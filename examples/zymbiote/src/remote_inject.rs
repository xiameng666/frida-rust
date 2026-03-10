//! Memfd injection via pure ptrace remote function calls.
//!
//! No loader shellcode, no SCM_RIGHTS, no extra sockets.
//!
//! Flow:
//!   1. ptrace attach
//!   2. remote memfd_create("xiam", MFD_CLOEXEC)
//!   3. write agent SO to /proc/<pid>/fd/<memfd> from injector side (root)
//!   4. remote dlopen("/proc/self/fd/<memfd>", RTLD_NOW)
//!   5. remote dlsym(handle, "hello_entry")
//!   6. remote pthread_create(entry)
//!   7. ptrace detach
//!
//! NOTE: memfd is intentionally NOT closed — the linker retains the
//! path "/proc/self/fd/<N>" in its soinfo and may re-access it
//! during subsequent dlopen calls from other threads.

use crate::ptrace;
use crate::remote::{get_dl_base, get_libc_base, write_bytes};
use std::fs;
use std::io::Write;

/// Inject `agent_so` into process `pid` using memfd + ptrace remote calls.
pub fn inject_memfd(pid: i32, agent_so: &[u8]) -> Result<(), String> {
    // ---- 1. Resolve function addresses ----
    let self_libc = get_libc_base(None)?;
    let target_libc = get_libc_base(Some(pid))?;
    let self_dl = get_dl_base(None)?;
    let target_dl = get_dl_base(Some(pid))?;

    eprintln!("[*] self  libc=0x{self_libc:x}  dl=0x{self_dl:x}");
    eprintln!("[*] target libc=0x{target_libc:x}  dl=0x{target_dl:x}");

    macro_rules! resolve_libc {
        ($sym:ident) => {{
            let addr = libc::$sym as *const () as usize;
            assert!(addr >= self_libc, "symbol below self libc base");
            target_libc + (addr - self_libc)
        }};
    }
    macro_rules! resolve_dl {
        ($sym:ident) => {{
            let addr = libc::$sym as *const () as usize;
            assert!(addr >= self_dl, "symbol below self dl base");
            target_dl + (addr - self_dl)
        }};
    }

    let fn_malloc = resolve_libc!(malloc);
    let fn_free = resolve_libc!(free);
    let fn_memfd_create = resolve_libc!(memfd_create);
    let fn_pthread_create = resolve_libc!(pthread_create);
    let fn_pthread_detach = resolve_libc!(pthread_detach);
    let fn_dlopen = resolve_dl!(dlopen);
    let fn_dlsym = resolve_dl!(dlsym);

    eprintln!("[*] memfd_create=0x{fn_memfd_create:x} dlopen=0x{fn_dlopen:x}");

    // ---- 2. ptrace attach ----
    ptrace::attach(pid)?;
    eprintln!("[+] attached to pid {pid}");

    // Helper: allocate + write a string in target, returns address.
    let write_str = |s: &[u8]| -> Result<usize, String> {
        let addr = ptrace::call_remote_function(pid, fn_malloc, &[s.len()])?;
        write_bytes(pid, addr, s)?;
        Ok(addr)
    };

    // ---- 3. remote memfd_create("xiam", MFD_CLOEXEC) ----
    let name = b"xiam\0";
    let name_addr = write_str(name)?;
    let memfd = ptrace::call_remote_function(
        pid,
        fn_memfd_create,
        &[name_addr, libc::MFD_CLOEXEC as usize],
    )?;
    ptrace::call_remote_function(pid, fn_free, &[name_addr])?;

    if (memfd as isize) < 0 {
        ptrace::detach(pid)?;
        return Err(format!("remote memfd_create failed: {}", memfd as isize));
    }
    eprintln!("[+] remote memfd fd={memfd}");

    // ---- 4. Write agent SO from injector side ----
    // As root we can open /proc/<pid>/fd/<memfd> directly.
    let proc_fd_path = format!("/proc/{}/fd/{}", pid, memfd);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(&proc_fd_path)
        .map_err(|e| format!("open {proc_fd_path}: {e}"))?;
    f.write_all(agent_so)
        .map_err(|e| format!("write agent SO: {e}"))?;
    drop(f);
    eprintln!("[+] wrote {} bytes to {proc_fd_path}", agent_so.len());

    // ---- 5. remote dlopen("/proc/self/fd/<N>", RTLD_NOW) ----
    let path = format!("/proc/self/fd/{}\0", memfd);
    let path_addr = write_str(path.as_bytes())?;
    let handle = ptrace::call_remote_function(
        pid,
        fn_dlopen,
        &[path_addr, libc::RTLD_NOW as usize],
    )?;
    ptrace::call_remote_function(pid, fn_free, &[path_addr])?;

    if handle == 0 {
        ptrace::detach(pid)?;
        return Err("remote dlopen returned NULL".into());
    }
    eprintln!("[+] dlopen handle=0x{handle:x}");

    // NOTE: memfd fd is intentionally kept open — closing it causes the
    // linker's soinfo path to become stale, which can SIGILL when other
    // threads call dlopen() and the linker walks its namespace.

    // ---- 6. remote dlsym(handle, "hello_entry") ----
    let sym_name = b"hello_entry\0";
    let sym_addr = write_str(sym_name)?;
    let entry = ptrace::call_remote_function(pid, fn_dlsym, &[handle, sym_addr])?;
    ptrace::call_remote_function(pid, fn_free, &[sym_addr])?;

    if entry == 0 {
        ptrace::detach(pid)?;
        return Err("remote dlsym(hello_entry) returned NULL".into());
    }
    eprintln!("[+] hello_entry=0x{entry:x}");

    // ---- 8. remote pthread_create(&tid, NULL, entry, NULL) ----
    let tid_addr = ptrace::call_remote_function(pid, fn_malloc, &[8])?;
    let rc = ptrace::call_remote_function(
        pid,
        fn_pthread_create,
        &[tid_addr, 0, entry, 0],
    )?;

    if rc != 0 {
        ptrace::call_remote_function(pid, fn_free, &[tid_addr])?;
        ptrace::detach(pid)?;
        return Err(format!("remote pthread_create failed: {rc}"));
    }

    // Read tid value and detach the thread so it doesn't become a zombie.
    // tid is at tid_addr (8 bytes on aarch64, but pthread_t may vary).
    // For simplicity, just detach using the address directly.
    // Actually, pthread_detach takes pthread_t (the value, not pointer).
    // We need to read the value — use PTRACE_PEEKTEXT.
    let tid_val = ptrace::peek_remote(pid, tid_addr)?;
    ptrace::call_remote_function(pid, fn_pthread_detach, &[tid_val])?;
    ptrace::call_remote_function(pid, fn_free, &[tid_addr])?;
    eprintln!("[+] agent thread started and detached");

    // ---- 9. ptrace detach ----
    ptrace::detach(pid)?;
    eprintln!("[+] ptrace detached from pid {pid}");

    Ok(())
}
