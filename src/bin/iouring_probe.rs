//! Adversarial fixture: performs one io_uring_setup + io_uring_enter,
//! an async channel ptrace syscall-stop tracing cannot see into.

fn main() {
    unsafe {
        // io_uring_params is 128 bytes in the kernel ABI
        let mut p = [0u8; 128];
        let fd = libc::syscall(libc::SYS_io_uring_setup, 8u32, p.as_mut_ptr());
        if fd < 0 {
            eprintln!("io_uring_setup: {}", std::io::Error::last_os_error());
            std::process::exit(0); // restricted environment: still emitted setup try
        }
        // submit a NOP through the enter path
        let ring_fd = fd as i32;
        let sqes = [0u8; 64];
        libc::syscall(libc::SYS_io_uring_enter, ring_fd, 0u32, 0u32,
                      0u32, std::ptr::null::<u8>(), sqes.len());
        libc::close(ring_fd);
    }
}
