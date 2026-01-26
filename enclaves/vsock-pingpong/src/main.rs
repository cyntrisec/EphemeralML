use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, RawFd};
use std::process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Basic,
    Vsock,
}

fn parse_mode() -> Mode {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--mode" {
            if let Some(v) = args.next() {
                return match v.as_str() {
                    "basic" => Mode::Basic,
                    "vsock" => Mode::Vsock,
                    _ => Mode::Vsock,
                };
            }
        }
        if a == "basic" {
            return Mode::Basic;
        }
        if a == "vsock" {
            return Mode::Vsock;
        }
    }
    Mode::Vsock
}

// AF_VSOCK server: listen on port 5000; reply "pong" when receiving "ping".
// Parent connects to CID 16 / port 5000.

const PORT: u32 = 5000;

// Linux sockaddr_vm (from <linux/vm_sockets.h>)
#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: libc::c_ushort,
    svm_port: libc::c_uint,
    svm_cid: libc::c_uint,
    svm_zero: [libc::c_uchar; 4],
}

fn die(msg: &str) -> ! {
    // In Nitro Enclaves, failures can be hard to diagnose if the process exits instantly
    // (the enclave disappears before we can attach `nitro-cli console`).
    // So we log the error and then sleep forever to keep the enclave alive for debugging.
    let e = std::io::Error::last_os_error();
    eprintln!("{}: {}", msg, e);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn cvt(ret: libc::c_int, msg: &str) -> libc::c_int {
    if ret < 0 {
        die(msg);
    }
    ret
}

fn make_listener(port: u32) -> RawFd {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        die("socket(AF_VSOCK)");
    }

    // Allow fast restart.
    let optval: libc::c_int = 1;
    unsafe {
        cvt(
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const c_void,
                mem::size_of_val(&optval) as libc::socklen_t,
            ),
            "setsockopt(SO_REUSEADDR)",
        );
    }

    let addr = SockAddrVm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        // Bind to any CID inside the enclave.
        svm_cid: libc::VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    unsafe {
        cvt(
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<SockAddrVm>() as libc::socklen_t,
            ),
            "bind(vsock)",
        );
        cvt(libc::listen(fd, 16), "listen");
    }

    fd
}

fn run(mode: Mode) {
    match mode {
        Mode::Basic => {
            eprintln!("[enclave] basic mode: alive; sleeping forever");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        Mode::Vsock => {
            eprintln!("[enclave] vsock mode: starting vsock server on port {}", PORT);

            let listen_fd = make_listener(PORT);

            loop {
                let client_fd = unsafe {
                    libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut())
                };
                if client_fd < 0 {
                    die("accept");
                }

                // Wrap the client fd in a File for plain read/write.
                let mut stream = unsafe { std::fs::File::from_raw_fd(client_fd) };

                let mut buf = [0u8; 16];
                let n = match stream.read(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[enclave] read error: {e}");
                        continue;
                    }
                };

                let msg = &buf[..n];
                eprintln!(
                    "[enclave] received: {:?}",
                    std::str::from_utf8(msg).unwrap_or("<non-utf8>")
                );

                let reply: &[u8] = if msg == b"ping" { b"pong" } else { b"unknown" };

                if let Err(e) = stream.write_all(reply) {
                    eprintln!("[enclave] write error: {e}");
                }
                // drop(stream) closes the connection
            }
        }
    }
}

fn main() {
    let mode = parse_mode();
    eprintln!("[enclave] mode={mode:?}");

    // If the enclave panics and exits immediately, we lose all visibility.
    // Catch panics, log them, then sleep forever so `nitro-cli console` (or attach-console) can inspect.
    let res = std::panic::catch_unwind(|| run(mode));
    if let Err(_) = res {
        eprintln!("[enclave] PANIC: caught unwind; sleeping forever for debugging");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}
