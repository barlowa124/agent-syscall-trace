//! AF_PACKET flow capture inside a user+net namespace we own.
//!
//! The orchestrator unshares CLONE_NEWUSER once (uid 0 inside), then
//! each side unshares CLONE_NEWNET. Both new net namespaces are owned by
//! the same user namespace, so this process holds CAP_NET_ADMIN over
//! both and can move the veth peer across. A TCP sink on the B side
//! makes flows real; AF_PACKET on the A-side veth records 5-tuple
//! metadata only — never payload.

use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::process::{Command, Stdio};

use crate::events::now_ns;

#[derive(Clone, Debug, Default)]
pub struct Flow {
    pub key: String,
    pub src: String,
    pub dst: String,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub packets: u64,
    pub bytes: u64,
    pub first_ns: u128,
    pub last_ns: u128,
}

pub struct FlowTable {
    pub flows: HashMap<String, Flow>,
    pub packets_seen: u64,
}

impl FlowTable {
    pub fn new() -> Self { Self { flows: HashMap::new(), packets_seen: 0 } }

    pub fn feed(&mut self, frame: &[u8]) {
        self.packets_seen += 1;
        if frame.len() < 14 { return; }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != 0x0800 { return; } // IPv4 only for flow records
        let ip = &frame[14..];
        if ip.len() < 20 { return; }
        let ihl = ((ip[0] & 0x0f) * 4) as usize;
        if ip.len() < ihl + 4 { return; }
        let proto = ip[9];
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
        let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
        let l4 = &ip[ihl..];
        let (sport, dport) = if (proto == 6 || proto == 17) && l4.len() >= 4 {
            (u16::from_be_bytes([l4[0], l4[1]]),
             u16::from_be_bytes([l4[2], l4[3]]))
        } else { (0, 0) };
        let proto_name = match proto { 6 => "tcp", 17 => "udp", _ => "ip" };
        let key = format!("{dst}:{dport}/{proto_name}");
        let f = self.flows.entry(key.clone()).or_insert_with(|| Flow {
            key, src: src.clone(), dst, proto, sport, dport,
            packets: 0, bytes: 0, first_ns: now_ns(), last_ns: 0 });
        f.packets += 1;
        f.bytes += total as u64;
        f.last_ns = now_ns();
    }

    pub fn records(&self) -> Vec<serde_json::Value> {
        let mut v: Vec<_> = self.flows.values().collect();
        v.sort_by(|a, b| a.key.cmp(&b.key));
        v.iter().map(|f| serde_json::json!({
            "flow": f.key, "src": f.src, "dst": f.dst,
            "proto": f.proto, "sport": f.sport, "dport": f.dport,
            "packets": f.packets, "bytes": f.bytes,
            "first_ns": f.first_ns, "last_ns": f.last_ns,
        })).collect()
    }
}

/// Open a bound AF_PACKET raw socket on `iface`. Caller must be in the
/// owning netns (CAP_NET_RAW there, which our userns grant covers).
pub fn open_packet(iface: &str) -> io::Result<RawFd> {
    unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW,
                              (libc::ETH_P_ALL as u16).to_be() as i32);
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let ifindex = libc::if_nametoindex(
            std::ffi::CString::new(iface).unwrap().as_ptr());
        if ifindex == 0 {
            libc::close(fd);
            return Err(io::Error::new(io::ErrorKind::NotFound, iface));
        }
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0, sll_pkttype: 0, sll_halen: 0,
            sll_addr: [0; 8],
        };
        if libc::bind(fd, &sll as *const _ as *const libc::sockaddr,
                      std::mem::size_of::<libc::sockaddr_ll>() as u32) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

/// Capture frames until `stop` is set or `deadline`/`max_packets` hit.
pub fn capture(fd: RawFd, deadline: std::time::Duration, max_packets: u64,
               stop: &std::sync::atomic::AtomicBool)
               -> io::Result<FlowTable> {
    use std::sync::atomic::Ordering;
    let mut table = FlowTable::new();
    let start = std::time::Instant::now();
    let mut buf = vec![0u8; 65536];
    let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO,
                         &tv as *const _ as *const libc::c_void,
                         std::mem::size_of::<libc::timeval>() as u32);
    }
    while !stop.load(Ordering::Relaxed) {
        if start.elapsed() > deadline || table.packets_seen >= max_packets {
            break;
        }
        let n = unsafe {
            libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void,
                       buf.len(), 0)
        };
        if n > 0 { table.feed(&buf[..n as usize]); }
    }
    Ok(table)
}

/// Enter the owning user namespace then a fresh net namespace.
/// Call once before any netns work; must be followed by map writes.
pub fn enter_userns() -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    unsafe {
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    Ok(())
}

pub fn enter_netns() -> io::Result<()> {
    unsafe {
        if libc::unshare(libc::CLONE_NEWNET) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn ip(args: &[&str]) -> io::Result<()> {
    let st = Command::new("ip").args(args)
        .stdout(Stdio::null()).stderr(Stdio::inherit()).status()?;
    if st.success() { Ok(()) } else {
        Err(io::Error::new(io::ErrorKind::Other,
                           format!("ip {args:?} -> {st}")))
    }
}
