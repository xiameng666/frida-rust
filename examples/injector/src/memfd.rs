//! memfd creation and abstract Unix socket fd-passing.

use libc::{
    c_void, close, sockaddr_un, AF_UNIX, MFD_CLOEXEC, SOCK_STREAM,
};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use std::ffi::CString;
use std::io::{IoSlice, Read};
use std::mem::{size_of_val, zeroed};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread::{self, JoinHandle};

/// Global memfd that the socket listener sends to the loader.
static AGENT_MEMFD: AtomicI32 = AtomicI32::new(-1);

/// Create an anonymous memfd filled with `data`.
pub fn create_memfd_with_data(name: &str, data: &[u8]) -> Result<RawFd, String> {
    let cname = CString::new(name).unwrap();
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    let mut written = 0usize;
    while written < data.len() {
        let ret = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const c_void,
                data.len() - written,
            )
        };
        if ret < 0 {
            unsafe { close(fd) };
            return Err(format!("memfd write: {}", std::io::Error::last_os_error()));
        }
        written += ret as usize;
    }
    Ok(fd)
}

/// Send a file descriptor to the peer via SCM_RIGHTS.
fn send_fd(stream: &UnixStream, fd_to_send: RawFd) -> Result<(), String> {
    let data = b"AGENT_SO";
    let iov = [IoSlice::new(data)];
    let fds = [fd_to_send];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| format!("sendmsg: {e}"))?;
    Ok(())
}

/// Handle a single incoming connection on the abstract socket.
fn handle_connection(mut stream: UnixStream) {
    let mut buf = [0u8; 1024];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        }
        if let Ok(msg) = std::str::from_utf8(&buf[..n]) {
            let trimmed = msg.trim();
            if trimmed == "HELLO_LOADER" {
                eprintln!("[*] loader connected, sending memfd");
                let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
                if memfd >= 0 {
                    if let Err(e) = send_fd(&stream, memfd) {
                        eprintln!("[!] send memfd failed: {e}");
                    }
                } else {
                    eprintln!("[!] memfd not set");
                }
            } else {
                eprintln!("[loader] {trimmed}");
            }
        }
    }
}

/// Start an abstract Unix socket listener named `socket_name`.
///
/// The listener stores `agent_memfd` in a global and sends it to any client
/// that sends `"HELLO_LOADER"`.
pub fn start_socket_listener(
    socket_name: &str,
    agent_memfd: RawFd,
) -> Result<JoinHandle<()>, String> {
    AGENT_MEMFD.store(agent_memfd, Ordering::SeqCst);

    let fd = unsafe { libc::socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }

    // Build abstract sockaddr_un: sun_path[0]=0, name follows.
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    let name = socket_name.as_bytes();
    let len = name.len().min(107);
    // addr.sun_path[0] is already 0 (abstract)
    // Copy name bytes into sun_path[1..=len].
    for (i, &b) in name[..len].iter().enumerate() {
        addr.sun_path[i + 1] = b;
    }
    let addr_len = (size_of_val(&addr.sun_family) + 1 + len) as u32;

    let rc = unsafe {
        libc::bind(fd, &addr as *const _ as *const _, addr_len)
    };
    if rc < 0 {
        return Err(format!("bind: {}", std::io::Error::last_os_error()));
    }

    let rc = unsafe { libc::listen(fd, 4) };
    if rc < 0 {
        return Err(format!("listen: {}", std::io::Error::last_os_error()));
    }

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    thread::spawn(move || handle_connection(s));
                }
                Err(e) => eprintln!("[!] accept: {e}"),
            }
        }
    });
    Ok(handle)
}
