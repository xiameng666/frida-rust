//! ptrace utilities for remote process control.

use libc::{c_int, c_void, iovec, pid_t, PTRACE_CONT, PTRACE_GETREGSET, PTRACE_SETREGSET};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::mem::size_of;

/// ARM64 user-space register set.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct UserRegs {
    pub regs: [u64; 31], // X0–X30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// Attach to a process via ptrace and wait for it to stop.
pub fn attach(pid: i32) -> Result<(), String> {
    let target = Pid::from_raw(pid);
    ptrace::attach(target).map_err(|e| format!("ptrace attach failed: {e}"))?;
    match waitpid(target, None) {
        Ok(WaitStatus::Stopped(_, _)) => Ok(()),
        other => Err(format!("unexpected waitpid status after attach: {other:?}")),
    }
}

/// Detach from a process.
pub fn detach(pid: i32) -> Result<(), String> {
    ptrace::detach(Pid::from_raw(pid), None).map_err(|e| format!("ptrace detach: {e}"))
}

/// Read all general-purpose registers.
pub fn get_registers(pid: i32) -> Result<UserRegs, String> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let rc =
        unsafe { libc::ptrace(PTRACE_GETREGSET, pid as pid_t, 1, &mut iov as *mut _ as *mut c_void) };
    if rc == -1 {
        return Err(format!("PTRACE_GETREGSET failed: {}", std::io::Error::last_os_error()));
    }
    Ok(regs)
}

/// Write all general-purpose registers.
pub fn set_registers(pid: i32, regs: &UserRegs) -> Result<(), String> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let rc =
        unsafe { libc::ptrace(PTRACE_SETREGSET, pid as pid_t, 1, &mut iov as *mut _ as *mut c_void) };
    if rc == -1 {
        return Err(format!("PTRACE_SETREGSET failed: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Read a single usize from remote process memory via PTRACE_PEEKTEXT.
pub fn peek_remote(pid: i32, addr: usize) -> Result<usize, String> {
    let val = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid as pid_t,
            addr as *mut c_void,
            std::ptr::null_mut::<c_void>(),
        )
    };
    // PEEKTEXT returns the value directly; error is indicated by -1 + errno.
    // Since -1 could be a valid value, we check errno.
    if val == -1 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() != Some(0) {
            return Err(format!("PTRACE_PEEKTEXT @0x{addr:x}: {errno}"));
        }
    }
    Ok(val as usize)
}

/// Call a function in the remote process and return its result (X0).
///
/// Sets X0–X7 from `args`, PC to `func_addr`, LR to a sentinel (0x340),
/// then continues.  When the function returns, execution hits the
/// invalid LR and the kernel delivers SIGSEGV, which we catch.
pub fn call_remote_function(pid: i32, func_addr: usize, args: &[usize]) -> Result<usize, String> {
    let orig_regs = get_registers(pid)?;
    let mut new_regs = orig_regs;

    // Pass up to 8 arguments via X0–X7.
    for (i, &arg) in args.iter().enumerate().take(8) {
        new_regs.regs[i] = arg as u64;
    }
    new_regs.regs[30] = 0x340; // LR = sentinel
    new_regs.pc = func_addr as u64;
    set_registers(pid, &new_regs)?;

    // Resume execution.
    let rc = unsafe { libc::ptrace(PTRACE_CONT as c_int, pid as pid_t, 0, 0) };
    if rc == -1 {
        return Err(format!("PTRACE_CONT failed: {}", std::io::Error::last_os_error()));
    }

    // Wait for SIGSEGV at LR sentinel.
    let target = Pid::from_raw(pid);
    match waitpid(target, None).map_err(|e| format!("waitpid: {e}"))? {
        WaitStatus::Stopped(_, Signal::SIGSEGV) => {
            let regs = get_registers(pid)?;
            if regs.pc == 0x340 {
                let ret = regs.regs[0] as usize;
                set_registers(pid, &orig_regs)?;
                Ok(ret)
            } else {
                Err(format!("unexpected PC after call: 0x{:x}", regs.pc))
            }
        }
        status => Err(format!("unexpected wait status: {status:?}")),
    }
}
