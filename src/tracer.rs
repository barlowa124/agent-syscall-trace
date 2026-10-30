//! ptrace supervisor: spawns the workload, follows the whole process
//! tree, and normalizes the syscalls we care about.
//!
//! Coverage:
//!   execve, fork/vfork/clone/clone3 (as PTRACE_EVENTs)
//!   openat/openat2 (path read from tracee memory)
//!   socket/connect (sockaddr decoded)
//!   io_uring_setup/enter (flagged as an unmonitored channel)
//!   exit
//!
//! On syscall-enter-stop the policy runs. Block rewrites orig_rax to -1
//! so the kernel returns -ENOSYS; flag allows and records.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;

use crate::events::{Decision, Event, EventKind, now_ns};
use crate::manifest::Policy;
use crate::policy::evaluate;

mod nr {
    pub const OPEN: u64 = 2;
    pub const SOCKET: u64 = 41;
    pub const CONNECT: u64 = 42;
    pub const CLONE: u64 = 56;
    pub const FORK: u64 = 57;
    pub const VFORK: u64 = 58;
    // execve is observed via PTRACE_EVENT_EXEC, not a syscall nr
    pub const OPENAT: u64 = 257;
    pub const IO_URING_SETUP: u64 = 425;
    pub const IO_URING_ENTER: u64 = 426;
    pub const CLONE3: u64 = 435;
    pub const OPENAT2: u64 = 437;
}

#[repr(C)]
#[derive(Default)]
struct Regs {
    r15: u64, r14: u64, r13: u64, r12: u64, rbp: u64, rbx: u64,
    r11: u64, r10: u64, r9: u64, r8: u64, rax: u64, rcx: u64,
    rdx: u64, rsi: u64, rdi: u64, orig_rax: u64, rip: u64,
    cs: u64, eflags: u64, rsp: u64, ss: u64,
    fs_base: u64, gs_base: u64, ds: u64, es: u64, fs: u64, gs: u64,
}

#[derive(Default)]
struct Pending {
    in_syscall: bool,
    nr: u64,
    path: String,
    target: String,
    dirfd: i64,
    flags: u64,
}

unsafe fn ptrace(req: libc::c_uint, pid: i32,
                 addr: *mut libc::c_void, data: *mut libc::c_void) -> i64 {
    libc::ptrace(req, pid, addr, data)
}

fn getregs(pid: i32) -> io::Result<Regs> {
    unsafe {
        let mut r = Regs::default();
        let mut iov = libc::iovec {
            iov_base: &mut r as *mut _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<Regs>(),
        };
        let e = ptrace(libc::PTRACE_GETREGSET, pid,
                       1 as *mut libc::c_void, // NT_PRSTATUS
                       &mut iov as *mut _ as *mut libc::c_void);
        if e == -1 { return Err(io::Error::last_os_error()); }
        Ok(r)
    }
}

fn setregs(pid: i32, r: &Regs) -> io::Result<()> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: r as *const _ as *mut libc::c_void,
            iov_len: std::mem::size_of::<Regs>(),
        };
        let e = ptrace(libc::PTRACE_SETREGSET, pid,
                       1 as *mut libc::c_void,
                       &mut iov as *mut _ as *mut libc::c_void);
        if e == -1 { return Err(io::Error::last_os_error()); }
        Ok(())
    }
}

fn read_str(pid: i32, addr: u64, max: usize) -> String {
    let mut out = Vec::new();
    let mut off = 0u64;
    while out.len() < max {
        let mut local = [0u8; 256];
        let liov = libc::iovec {
            iov_base: local.as_mut_ptr() as *mut libc::c_void,
            iov_len: local.len(),
        };
        let riov = libc::iovec {
            iov_base: (addr + off) as *mut libc::c_void,
            iov_len: local.len(),
        };
        let n = unsafe {
            libc::process_vm_readv(pid, &liov, 1, &riov, 1, 0)
        };
        if n <= 0 { break; }
        let chunk = &local[..n as usize];
        if let Some(z) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..z]);
            break;
        }
        out.extend_from_slice(chunk);
        off += n as u64;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_mem(pid: i32, addr: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let liov = libc::iovec {
        iov_base: out.as_mut_ptr() as *mut libc::c_void, iov_len: len };
    let riov = libc::iovec {
        iov_base: addr as *mut libc::c_void, iov_len: len };
    let n = unsafe { libc::process_vm_readv(pid, &liov, 1, &riov, 1, 0) };
    if n <= 0 { return Vec::new(); }
    out.truncate(n as usize);
    out
}

fn decode_sockaddr(pid: i32, addr: u64, len: u64) -> String {
    let sa = read_mem(pid, addr, len.min(128) as usize);
    if sa.len() < 2 { return format!("family:?") }
    let fam = u16::from_ne_bytes([sa[0], sa[1]]);
    match fam {
        f if f == libc::AF_INET as u16 && sa.len() >= 8 => {
            let port = u16::from_be_bytes([sa[2], sa[3]]);
            format!("{}.{}.{}.{}:{}", sa[4], sa[5], sa[6], sa[7], port)
        }
        f if f == libc::AF_INET6 as u16 && sa.len() >= 28 => {
            let port = u16::from_be_bytes([sa[2], sa[3]]);
            let mut g = Vec::new();
            for i in 0..8 {
                g.push(u16::from_be_bytes([sa[8 + 2 * i], sa[9 + 2 * i]]));
            }
            let s = g.iter().map(|x| format!("{:x}", x))
                .collect::<Vec<_>>().join(":");
            format!("[{s}]:{port}")
        }
        f if f == libc::AF_UNIX as u16 => {
            let path = CStr::from_bytes_until_nul(&sa[2..])
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "@abstract".into());
            format!("unix:{path}")
        }
        f => format!("family:{f}"),
    }
}

pub fn spawn(cmd: &[String]) -> io::Result<i32> {
    let argv: Vec<CString> = cmd.iter()
        .map(|s| CString::new(s.as_str()).unwrap()).collect();
    let mut argv_p: Vec<*const i8> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    unsafe {
        match libc::fork() {
            -1 => Err(io::Error::last_os_error()),
            0 => {
                libc::ptrace(libc::PTRACE_TRACEME, 0,
                             std::ptr::null_mut::<libc::c_void>(),
                             std::ptr::null_mut::<libc::c_void>());
                libc::raise(libc::SIGSTOP);
                libc::execvp(argv[0].as_ptr(), argv_p.as_ptr());
                libc::_exit(127);
            }
            pid => Ok(pid),
        }
    }
}

pub struct TraceOpts<'a> {
    pub policy: Policy,
    pub root_pid: i32,
    pub on_event: Box<dyn FnMut(&Event) + 'a>,
}

pub fn run(opts: &mut TraceOpts) -> io::Result<i32> {
    let root = opts.root_pid;
    let mut status = 0;
    libc_waitpid(root, &mut status)?;
    unsafe {
        ptrace(libc::PTRACE_SETOPTIONS, root, std::ptr::null_mut(),
               (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEVFORK | libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEEXIT
                | libc::PTRACE_O_EXITKILL) as *mut libc::c_void);
        ptrace(libc::PTRACE_SYSCALL, root, std::ptr::null_mut(),
               std::ptr::null_mut());
    }
    let mut pending: HashMap<i32, Pending> = HashMap::new();
    let mut seq = 0u64;
    let mut root_status = -1i32;

    let mut emit = |seq: &mut u64, pid: i32, ppid: i32,
                    kind: EventKind, detail: serde_json::Value| {
        *seq += 1;
        let decision = evaluate(&opts.policy, kind, &detail);
        (opts.on_event)(&Event {
            seq: *seq, ts_ns: now_ns(), pid: pid as u32,
            ppid: ppid as u32, kind, detail, decision });
    };

    loop {
        let mut st = 0;
        let pid = libc_waitpid(-1, &mut st)?;
        if pid == -1 {
            if pending.is_empty() { break; } else { continue; }
        }
        let ppid = read_ppid(pid);
        if libc::WIFEXITED(st) {
            emit(&mut seq, pid, ppid, EventKind::Exit,
                 serde_json::json!({"how": "exit", "code": libc::WEXITSTATUS(st)}));
            pending.remove(&pid);
            if pid == root { root_status = libc::WEXITSTATUS(st); }
            if pending.is_empty() && pid == root { break; }
            continue;
        }
        if libc::WIFSIGNALED(st) {
            emit(&mut seq, pid, ppid, EventKind::Exit,
                 serde_json::json!({"how": "signal", "sig": libc::WTERMSIG(st)}));
            pending.remove(&pid);
            if pid == root { root_status = 128 + libc::WTERMSIG(st); }
            if pending.is_empty() { break; }
            continue;
        }
        if !libc::WIFSTOPPED(st) { continue; }

        let sig = libc::WSTOPSIG(st);
        let event = st >> 16;

        match event {
            x if x == libc::PTRACE_EVENT_FORK as i32
                || x == libc::PTRACE_EVENT_VFORK as i32
                || x == libc::PTRACE_EVENT_CLONE as i32 => {
                let child = eventmsg(pid);
                pending.insert(child, Pending::default());
                emit(&mut seq, pid, ppid, EventKind::Fork,
                     serde_json::json!({"child": child,
                         "how": match x {
                             e if e == libc::PTRACE_EVENT_FORK as i32 => "fork",
                             e if e == libc::PTRACE_EVENT_VFORK as i32 => "vfork",
                             _ => "clone" }}));
                resume_syscall(pid, 0);
                resume_syscall(child, 0);
                continue;
            }
            x if x == libc::PTRACE_EVENT_EXEC as i32 => {
                let exe = read_exe(pid);
                let argv = read_cmdline(pid);
                emit(&mut seq, pid, ppid, EventKind::Exec,
                     serde_json::json!({"exe": exe, "argv": argv}));
                resume_syscall(pid, 0);
                continue;
            }
            x if x == libc::PTRACE_EVENT_EXIT as i32 => {
                resume_syscall(pid, 0);
                continue;
            }
            _ => {}
        }

        if sig == (libc::SIGTRAP | 0x80) {
            // syscall-stop: alternate enter/exit per pid
            let regs = getregs(pid).unwrap_or_default();
            let p = pending.entry(pid).or_default();
            if !p.in_syscall {
                p.in_syscall = true;
                p.nr = regs.orig_rax;
                let mut blocked = false;
                match regs.orig_rax {
                    nr::OPEN | nr::OPENAT | nr::OPENAT2 => {
                        // open: rdi=path. openat: rdi=dirfd rsi=path
                        // rdx=flags. openat2: dirfd, path, open_how*
                        // whose first field is flags.
                        if regs.orig_rax == nr::OPEN {
                            p.path = read_str(pid, regs.rdi, 4096);
                            p.dirfd = -100; // AT_FDCWD
                            p.flags = regs.rsi;
                        } else {
                            p.path = read_str(pid, regs.rsi, 4096);
                            p.dirfd = regs.rdi as i64;
                            p.flags = if regs.orig_rax == nr::OPENAT2 {
                                let how = read_mem(pid, regs.rdx, 8);
                                if how.len() == 8 {
                                    u64::from_ne_bytes(how.try_into().unwrap())
                                } else { 0 }
                            } else { regs.rdx };
                        }
                        let detail = serde_json::json!({
                            "nr": regs.orig_rax, "dirfd": p.dirfd,
                            "path": p.path, "flags": p.flags });
                        let d = evaluate(&opts.policy, EventKind::OpenAt, &detail);
                        if d == Decision::Block {
                            blocked = true;
                            emit(&mut seq, pid, ppid, EventKind::OpenAt,
                                 serde_json::json!({
                                     "dirfd": p.dirfd, "path": p.path,
                                     "flags": p.flags, "blocked": true}));
                        }
                    }
                    nr::SOCKET => {
                        emit(&mut seq, pid, ppid, EventKind::Socket,
                             serde_json::json!({
                                 "domain": regs.rdi, "type": regs.rsi,
                                 "protocol": regs.rdx }));
                    }
                    nr::CONNECT => {
                        p.target = decode_sockaddr(pid, regs.rsi, regs.rdx);
                        let detail = serde_json::json!({
                            "fd": regs.rdi, "target": p.target });
                        let d = evaluate(&opts.policy, EventKind::Connect, &detail);
                        if d == Decision::Block {
                            blocked = true;
                            emit(&mut seq, pid, ppid, EventKind::Connect,
                                 serde_json::json!({
                                     "fd": regs.rdi, "target": p.target,
                                     "blocked": true}));
                        }
                    }
                    nr::IO_URING_SETUP | nr::IO_URING_ENTER => {
                        emit(&mut seq, pid, ppid, EventKind::IoUring,
                             serde_json::json!({
                                 "nr": regs.orig_rax,
                                 "note": "async channel not per-op traced"}));
                    }
                    _ => {}
                }
                if blocked {
                    let mut r = regs;
                    r.orig_rax = u64::MAX;
                    let _ = setregs(pid, &r);
                }
            } else {
                p.in_syscall = false;
                let retval = regs.rax as i64;
                match p.nr {
                    nr::OPEN | nr::OPENAT | nr::OPENAT2 => {
                        emit(&mut seq, pid, ppid, EventKind::OpenAt,
                             serde_json::json!({
                                 "dirfd": p.dirfd, "path": p.path,
                                 "flags": p.flags, "ret": retval }));
                    }
                    nr::CONNECT => {
                        emit(&mut seq, pid, ppid, EventKind::Connect,
                             serde_json::json!({
                                 "target": p.target, "ret": retval }));
                    }
                    nr::CLONE | nr::FORK | nr::VFORK | nr::CLONE3 => {}
                    _ => {}
                }
            }
            resume_syscall(pid, 0);
        } else {
            // signal-delivery or group stop: forward
            let fwd = if sig == libc::SIGSTOP || sig == libc::SIGTRAP
                         || sig == libc::SIGTSTP || sig == libc::SIGTTIN
                         || sig == libc::SIGTTOU { 0 } else { sig };
            resume_syscall(pid, fwd);
        }
    }
    Ok(root_status)
}

fn resume_syscall(pid: i32, sig: i32) {
    unsafe {
        ptrace(libc::PTRACE_SYSCALL, pid, std::ptr::null_mut(),
               sig as *mut libc::c_void);
    }
}

fn eventmsg(pid: i32) -> i32 {
    unsafe {
        let mut msg: libc::c_ulong = 0;
        ptrace(libc::PTRACE_GETEVENTMSG, pid, std::ptr::null_mut(),
               &mut msg as *mut _ as *mut libc::c_void);
        msg as i32
    }
}

fn read_exe(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_cmdline(pid: i32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| b.split(|&c| c == 0)
             .filter(|s| !s.is_empty())
             .map(|s| String::from_utf8_lossy(s).into_owned())
             .collect())
        .unwrap_or_default()
}

fn read_ppid(pid: i32) -> i32 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("PPid:"))
            .and_then(|l| l[5..].trim().parse().ok()))
        .unwrap_or(0)
}

fn libc_waitpid(pid: i32, status: &mut i32) -> io::Result<i32> {
    unsafe {
        let r = libc::waitpid(pid, status, libc::__WALL);
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ECHILD) { return Ok(-1); }
            return Err(e);
        }
        Ok(r)
    }
}
