//! TCP sink for the netns demo: accepts and discards. Runs inside the
//! second net namespace on the B end of the veth pair.

use std::io::{Read, Write};
use std::net::TcpListener;

pub fn run_sink(addr: &str, max_conns: usize) -> std::io::Result<()> {
    let l = TcpListener::bind(addr)?;
    let mut n = 0;
    for stream in l.incoming() {
        match stream {
            Ok(mut s) => {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"ok\n");
            }
            Err(_) => break,
        }
        n += 1;
        if n >= max_conns { break; }
    }
    Ok(())
}
