//! Patcher server — services target memory read/write requests from the
//! injected SO via `/proc/<pid>/mem` pwrite/pread.
//!
//! Runs as a background thread in the zymbiote (root) process.
//! Protocol (all native endian):
//!   Request:  [opcode:u8][addr:u64][len:u32]  (WRITE: followed by `len` bytes)
//!   Response: [status:u8][len:u32]             (READ OK: followed by `len` bytes)
//!   opcode: 1=READ, 2=WRITE

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::thread;

const PATCH_OP_READ: u8 = 1;
const PATCH_OP_WRITE: u8 = 2;
const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

/// Start the patcher server.
///
/// Binds socket and opens `/proc/<pid>/mem` **synchronously** (so the socket
/// is ready before the SO tries to connect), then spawns a background thread
/// for accept + service loop.
pub fn start_patcher(target_pid: i32) -> Result<thread::JoinHandle<()>, String> {
    // Bind socket NOW so it's listening before inject_memfd / SO init
    let listener = bind_abstract("xiam_patcher")?;
    eprintln!("[patcher] listening on @xiam_patcher for pid {}", target_pid);

    // Open /proc/<pid>/mem
    let mem_path = format!("/proc/{}/mem\0", target_pid);
    let mem_fd = unsafe {
        libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDWR)
    };
    if mem_fd < 0 {
        return Err(format!("open /proc/{}/mem failed (errno={})", target_pid,
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)));
    }
    eprintln!("[patcher] opened /proc/{}/mem fd={}", target_pid, mem_fd);

    Ok(thread::spawn(move || {
        if let Err(e) = service_loop(listener, mem_fd) {
            eprintln!("[patcher] error: {}", e);
        }
        unsafe { libc::close(mem_fd) };
    }))
}

fn service_loop(listener: UnixListener, mem_fd: i32) -> Result<(), String> {
    // Accept one client
    let (mut client, _) = listener.accept()
        .map_err(|e| format!("accept: {}", e))?;
    eprintln!("[patcher] client connected");

    // Service loop
    let mut hdr_buf = [0u8; 13]; // opcode(1) + addr(8) + len(4)
    let mut data_buf = vec![0u8; 4096];

    loop {
        // Read request header
        if let Err(_) = client.read_exact(&mut hdr_buf) {
            eprintln!("[patcher] client disconnected");
            break;
        }

        let opcode = hdr_buf[0];
        let addr = u64::from_ne_bytes(hdr_buf[1..9].try_into().unwrap());
        let len = u32::from_ne_bytes(hdr_buf[9..13].try_into().unwrap()) as usize;

        match opcode {
            PATCH_OP_READ => {
                // Resize buffer if needed
                if data_buf.len() < len {
                    data_buf.resize(len, 0);
                }

                let n = unsafe {
                    libc::pread(mem_fd, data_buf.as_mut_ptr() as *mut libc::c_void,
                                len, addr as libc::off_t)
                };

                if n == len as isize {
                    // Send OK response + data
                    let resp = make_resp(STATUS_OK, len as u32);
                    let _ = client.write_all(&resp);
                    let _ = client.write_all(&data_buf[..len]);
                } else {
                    eprintln!("[patcher] pread 0x{:x} len={} failed (ret={})", addr, len, n);
                    let resp = make_resp(STATUS_ERR, 0);
                    let _ = client.write_all(&resp);
                }
            }
            PATCH_OP_WRITE => {
                // Read data from client
                if data_buf.len() < len {
                    data_buf.resize(len, 0);
                }
                if let Err(_) = client.read_exact(&mut data_buf[..len]) {
                    eprintln!("[patcher] failed to read write data");
                    break;
                }

                let n = unsafe {
                    libc::pwrite(mem_fd, data_buf.as_ptr() as *const libc::c_void,
                                 len, addr as libc::off_t)
                };

                if n == len as isize {
                    eprintln!("[patcher] pwrite 0x{:x} len={} OK", addr, len);
                    let resp = make_resp(STATUS_OK, 0);
                    let _ = client.write_all(&resp);
                } else {
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    eprintln!("[patcher] pwrite 0x{:x} len={} FAILED (ret={} errno={})",
                              addr, len, n, err);
                    let resp = make_resp(STATUS_ERR, 0);
                    let _ = client.write_all(&resp);
                }
            }
            _ => {
                eprintln!("[patcher] unknown opcode {}", opcode);
                break;
            }
        }
    }

    Ok(())
}

/// Build a response header: [status:u8][len:u32] = 5 bytes
fn make_resp(status: u8, len: u32) -> [u8; 5] {
    let mut buf = [0u8; 5];
    buf[0] = status;
    buf[1..5].copy_from_slice(&len.to_ne_bytes());
    buf
}

/// Bind an abstract unix socket (Linux-specific).
fn bind_abstract(name: &str) -> Result<UnixListener, String> {
    unsafe {
        let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if sock < 0 {
            return Err("socket() failed".into());
        }

        let mut sa: libc::sockaddr_un = std::mem::zeroed();
        sa.sun_family = libc::AF_UNIX as u16;

        // Abstract: sun_path[0] = '\0', then name
        let abstract_name = format!("\0{}", name);
        let name_bytes = abstract_name.as_bytes();
        if name_bytes.len() > sa.sun_path.len() {
            libc::close(sock);
            return Err("socket name too long".into());
        }
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            sa.sun_path.as_mut_ptr() as *mut u8,
            name_bytes.len(),
        );

        let sa_len = (memoffset_sun_path() + name_bytes.len()) as libc::socklen_t;

        if libc::bind(sock, &sa as *const _ as *const libc::sockaddr, sa_len) < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            libc::close(sock);
            return Err(format!("bind @{} failed (errno={})", name, err));
        }

        if libc::listen(sock, 1) < 0 {
            libc::close(sock);
            return Err("listen() failed".into());
        }

        Ok(UnixListener::from_raw_fd(sock))
    }
}

/// Offset of sun_path in sockaddr_un (avoids unstable offset_of on older Rust).
fn memoffset_sun_path() -> usize {
    // sockaddr_un = { sun_family: u16, sun_path: [i8; 108] }
    // On Linux aarch64, sun_family is 2 bytes, so offset = 2
    2
}
