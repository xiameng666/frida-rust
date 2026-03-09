//! Injection logic: offset calculation, string table, and orchestration.

use crate::ptrace;
use crate::remote::{get_dl_base, get_libc_base, write_bytes, write_memory};
use std::mem::size_of;

// ---------------------------------------------------------------------------
// Structs that MUST match loader.c layout exactly
// ---------------------------------------------------------------------------

/// Resolved libc function addresses in the target process.
/// Order must match `LibcOffsets` in loader.c.
#[repr(C)]
#[derive(Debug, Default)]
pub struct LibcOffsets {
    pub malloc: usize,
    pub free: usize,
    pub socket: usize,
    pub connect: usize,
    pub write: usize,
    pub close: usize,
    pub mprotect: usize,
    pub mmap: usize,
    pub munmap: usize,
    pub recvmsg: usize,
    pub pthread_create: usize,
    pub pthread_detach: usize,
    pub snprintf: usize,
    pub memcpy: usize,
    pub strlen: usize,
}

/// Resolved libdl function addresses in the target process.
#[repr(C)]
#[derive(Debug, Default)]
pub struct DlOffsets {
    pub dlopen: usize,
    pub dlsym: usize,
    pub dlerror: usize,
}

/// String table passed to the shellcode.
/// Each entry is (remote_ptr: u64, len_with_null: u32).
/// Order must match `StringTable` in loader.c.
#[repr(C)]
pub struct StringTable {
    pub socket_name: u64,
    pub socket_name_len: u32,
    pub hello_msg: u64,
    pub hello_msg_len: u32,
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub pthread_err: u64,
    pub pthread_err_len: u32,
    pub dlsym_err: u64,
    pub dlsym_err_len: u32,
    pub proc_path: u64,
    pub proc_path_len: u32,
    pub cmdline: u64,
    pub cmdline_len: u32,
    pub output_path: u64,
    pub output_path_len: u32,
}

// ---------------------------------------------------------------------------
// Offset calculation helpers
// ---------------------------------------------------------------------------

macro_rules! resolve {
    ($self_base:expr, $target_base:expr, $sym:ident) => {{
        let addr = libc::$sym as *const () as usize;
        assert!(addr >= $self_base, "symbol below self base");
        $target_base + (addr - $self_base)
    }};
}

impl LibcOffsets {
    /// Compute target-process function addresses from our own libc symbols.
    pub fn calculate(self_base: usize, target_base: usize) -> Self {
        Self {
            malloc: resolve!(self_base, target_base, malloc),
            free: resolve!(self_base, target_base, free),
            socket: resolve!(self_base, target_base, socket),
            connect: resolve!(self_base, target_base, connect),
            write: resolve!(self_base, target_base, write),
            close: resolve!(self_base, target_base, close),
            mprotect: resolve!(self_base, target_base, mprotect),
            mmap: resolve!(self_base, target_base, mmap),
            munmap: resolve!(self_base, target_base, munmap),
            recvmsg: resolve!(self_base, target_base, recvmsg),
            pthread_create: resolve!(self_base, target_base, pthread_create),
            pthread_detach: resolve!(self_base, target_base, pthread_detach),
            snprintf: resolve!(self_base, target_base, snprintf),
            memcpy: resolve!(self_base, target_base, memcpy),
            strlen: resolve!(self_base, target_base, strlen),
        }
    }

    pub fn print(&self) {
        eprintln!("[*] libc offsets:");
        eprintln!("    malloc      = 0x{:x}", self.malloc);
        eprintln!("    mmap        = 0x{:x}", self.mmap);
        eprintln!("    dlopen(via) = (see DlOffsets)");
    }
}

impl DlOffsets {
    pub fn calculate(self_base: usize, target_base: usize) -> Self {
        Self {
            dlopen: resolve!(self_base, target_base, dlopen),
            dlsym: resolve!(self_base, target_base, dlsym),
            dlerror: resolve!(self_base, target_base, dlerror),
        }
    }

    pub fn print(&self) {
        eprintln!("[*] dl offsets:");
        eprintln!("    dlopen  = 0x{:x}", self.dlopen);
        eprintln!("    dlsym   = 0x{:x}", self.dlsym);
        eprintln!("    dlerror = 0x{:x}", self.dlerror);
    }
}

// ---------------------------------------------------------------------------
// String table builder
// ---------------------------------------------------------------------------

/// Default string values (matching rustFrida, but socket_name → "xiam_socket").
struct Strings {
    socket_name: Vec<u8>,
    hello_msg: Vec<u8>,
    sym_name: Vec<u8>,
    pthread_err: Vec<u8>,
    dlsym_err: Vec<u8>,
    proc_path: Vec<u8>,
    cmdline: Vec<u8>,
    output_path: Vec<u8>,
}

impl Default for Strings {
    fn default() -> Self {
        Self {
            socket_name: b"xiam_socket\0".to_vec(),
            hello_msg: b"HELLO_LOADER\0".to_vec(),
            sym_name: b"hello_entry\0".to_vec(),
            pthread_err: b"pthreadded\0".to_vec(),
            dlsym_err: b"dlsymFail\0".to_vec(),
            proc_path: b"/proc/self/fd/\0".to_vec(),
            cmdline: b"novalue\0".to_vec(),
            output_path: b"novalue\0".to_vec(),
        }
    }
}

/// Allocate a StringTable in the remote process and write all strings.
#[allow(unused_assignments)]
fn write_string_table(pid: i32, malloc_addr: usize) -> Result<usize, String> {
    let s = Strings::default();

    let strings: [&[u8]; 8] = [
        &s.socket_name,
        &s.hello_msg,
        &s.sym_name,
        &s.pthread_err,
        &s.dlsym_err,
        &s.proc_path,
        &s.cmdline,
        &s.output_path,
    ];

    let table_size = size_of::<StringTable>();
    let strings_len: usize = strings.iter().map(|s| s.len()).sum();
    let total = table_size + strings_len;

    // Allocate in target process.
    let table_addr = ptrace::call_remote_function(pid, malloc_addr, &[total])?;
    let mut cur = table_addr + table_size;

    // Build table entries.
    macro_rules! entry {
        ($field:expr, $field_len:expr, $data:expr) => {{
            $field = cur as u64;
            $field_len = $data.len() as u32;
            write_bytes(pid, cur, $data)?;
            cur += $data.len();
        }};
    }

    #[allow(invalid_value)]
    let mut table: StringTable = unsafe { std::mem::zeroed() };
    entry!(table.socket_name, table.socket_name_len, &s.socket_name);
    entry!(table.hello_msg, table.hello_msg_len, &s.hello_msg);
    entry!(table.sym_name, table.sym_name_len, &s.sym_name);
    entry!(table.pthread_err, table.pthread_err_len, &s.pthread_err);
    entry!(table.dlsym_err, table.dlsym_err_len, &s.dlsym_err);
    entry!(table.proc_path, table.proc_path_len, &s.proc_path);
    entry!(table.cmdline, table.cmdline_len, &s.cmdline);
    entry!(table.output_path, table.output_path_len, &s.output_path);

    write_memory(pid, table_addr, &table)?;
    Ok(table_addr)
}

// ---------------------------------------------------------------------------
// Main injection entry point
// ---------------------------------------------------------------------------

/// Inject the shellcode + agent into the target process.
///
/// `shellcode` is the pre-compiled loader.bin.
pub fn inject_to_process(pid: i32, shellcode: &[u8]) -> Result<(), String> {
    // 1. Resolve bases.
    let self_libc = get_libc_base(None)?;
    let target_libc = get_libc_base(Some(pid))?;
    let self_dl = get_dl_base(None)?;
    let target_dl = get_dl_base(Some(pid))?;

    eprintln!("[*] self  libc=0x{self_libc:x}  dl=0x{self_dl:x}");
    eprintln!("[*] target libc=0x{target_libc:x}  dl=0x{target_dl:x}");

    let offsets = LibcOffsets::calculate(self_libc, target_libc);
    let dl_offsets = DlOffsets::calculate(self_dl, target_dl);
    offsets.print();
    dl_offsets.print();

    // 2. Attach.
    ptrace::attach(pid)?;
    eprintln!("[+] attached to pid {pid}");

    // 3. mmap RWX for shellcode.
    let page = 4096usize;
    let sc_len = ((shellcode.len() + page - 1) / page) * page;
    let prot = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as usize;
    let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize;
    let sc_addr = ptrace::call_remote_function(
        pid,
        offsets.mmap,
        &[0, sc_len, prot, flags, !0usize, 0],
    )?;
    eprintln!("[+] shellcode mmap @ 0x{sc_addr:x} ({sc_len} bytes)");

    // 4. Write shellcode.
    write_bytes(pid, sc_addr, shellcode)?;
    eprintln!("[+] shellcode written");

    // 5. Allocate + write LibcOffsets.
    let offsets_addr =
        ptrace::call_remote_function(pid, offsets.malloc, &[size_of::<LibcOffsets>()])?;
    write_memory(pid, offsets_addr, &offsets)?;
    eprintln!("[+] LibcOffsets @ 0x{offsets_addr:x}");

    // 6. Allocate + write DlOffsets.
    let dl_addr =
        ptrace::call_remote_function(pid, offsets.malloc, &[size_of::<DlOffsets>()])?;
    write_memory(pid, dl_addr, &dl_offsets)?;
    eprintln!("[+] DlOffsets @ 0x{dl_addr:x}");

    // 7. Write string table.
    let str_addr = write_string_table(pid, offsets.malloc)?;
    eprintln!("[+] StringTable @ 0x{str_addr:x}");

    // 8. Call shellcode(offsets, dl, strings).
    match ptrace::call_remote_function(pid, sc_addr, &[offsets_addr, dl_addr, str_addr]) {
        Ok(ret) => {
            eprintln!("[+] shellcode returned 0x{:x}", ret as isize);

            // Cleanup: munmap shellcode.
            let _ = ptrace::call_remote_function(pid, offsets.munmap, &[sc_addr, sc_len]);
            eprintln!("[+] shellcode unmapped");

            // Detach.
            ptrace::detach(pid)?;
            eprintln!("[+] detached from pid {pid}");
            Ok(())
        }
        Err(e) => {
            eprintln!("[!] shellcode exec failed: {e}");
            // Try to detach anyway.
            let _ = ptrace::detach(pid);
            Err(e)
        }
    }
}
