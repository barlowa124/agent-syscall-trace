//! Overhead benchmarks: per-syscall-stop cost under ptrace, and flow
//! hashing throughput on synthetic frames.

use std::io;
use std::process::Command;
use std::time::Instant;

use crate::netcap::FlowTable;

/// Time `cmd` untraced and return wall time.
pub fn untraced(cmd: &[String]) -> io::Result<std::time::Duration> {
    let t = Instant::now();
    let st = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    if !st.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "workload failed"));
    }
    Ok(t.elapsed())
}

/// Parse flow-table throughput: feed synthetic IPv4/TCP frames.
pub fn flow_hash_rate(frames: usize) -> (usize, std::time::Duration) {
    let mut table = FlowTable::new();
    // 14B eth + 20B ip + 20B tcp
    let mut frame = vec![0u8; 54];
    frame[12] = 0x08; // IPv4
    frame[14] = 0x45;
    frame[14 + 2] = 0;
    frame[14 + 3] = 40;
    frame[14 + 9] = 6;
    frame[14 + 12..14 + 16].copy_from_slice(&[10, 9, 9, 1]);
    frame[14 + 16..14 + 20].copy_from_slice(&[10, 9, 9, 2]);
    let t = Instant::now();
    for i in 0..frames {
        frame[14 + 34..14 + 36].copy_from_slice(&(i as u16).to_be_bytes());
        frame[14 + 36..14 + 38].copy_from_slice(&9999u16.to_be_bytes());
        table.feed(&frame);
    }
    (table.packets_seen as usize, t.elapsed())
}
