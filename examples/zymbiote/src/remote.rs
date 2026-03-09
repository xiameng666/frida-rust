//! Remote process memory helpers.

use libc::{c_void, pid_t};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::size_of;
use std::path::Path;

/// Write raw bytes to a remote process via PTRACE_POKETEXT (8 bytes at a time).
pub fn write_remote_mem(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let chunk = remaining.min(8);

        let mut word: u64 = 0;
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr().add(offset),
                &mut word as *mut u64 as *mut u8,
                chunk,
            );
        }

        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_POKETEXT,
                pid as pid_t,
                (addr + offset) as *mut c_void,
                word as usize as *mut c_void,
            )
        };
        if rc == -1 {
            return Err(format!(
                "PTRACE_POKETEXT @0x{:x}+{offset}: {}",
                addr,
                std::io::Error::last_os_error()
            ));
        }
        offset += chunk;
    }
    Ok(())
}

/// Write a typed value to remote memory.
pub fn write_memory<T>(pid: i32, addr: usize, data: &T) -> Result<(), String> {
    let ptr = data as *const T as *const u8;
    let bytes = unsafe { std::slice::from_raw_parts(ptr, size_of::<T>()) };
    write_remote_mem(pid, addr, bytes)
}

/// Write a byte slice to remote memory (alias kept for clarity).
pub fn write_bytes(pid: i32, addr: usize, data: &[u8]) -> Result<(), String> {
    write_remote_mem(pid, addr, data)
}

/// Search `/proc/<pid>/maps` for the first region whose path contains `lib_name`
/// and return its start address.
fn find_lib_base(pid: Option<i32>, lib_name: &str) -> Result<usize, String> {
    let maps = match pid {
        Some(p) => format!("/proc/{p}/maps"),
        None => "/proc/self/maps".into(),
    };
    if !Path::new(&maps).exists() {
        return Err(format!("maps not found: {maps}"));
    }
    let reader = BufReader::new(
        File::open(&maps).map_err(|e| format!("open {maps}: {e}"))?,
    );
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read {maps}: {e}"))?;
        if line.contains(lib_name) {
            if let Some(start) = line.split_whitespace().next().and_then(|r| r.split('-').next()) {
                return usize::from_str_radix(start, 16)
                    .map_err(|e| format!("parse addr: {e}"));
            }
        }
    }
    Err(format!("{lib_name} not found in {maps}"))
}

/// Get the base address of `libc.so` in the given process.
pub fn get_libc_base(pid: Option<i32>) -> Result<usize, String> {
    find_lib_base(pid, "libc.so")
}

/// Get the base address of `libdl.so` in the given process.
pub fn get_dl_base(pid: Option<i32>) -> Result<usize, String> {
    find_lib_base(pid, "libdl.so")
}
