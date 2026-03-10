//! Core injector: Zymbiote injection via /proc/<pid>/mem.
//!
//! Route A: the stub only notifies us via socket; we do the real
//! injection with ptrace + memfd remote calls.

use crate::elf;
use crate::mem;
use crate::payload::{self, StubParams, PAYLOAD};
use crate::proc::{self, MemRegion};
use crate::remote_inject;
use crate::state::InjectState;
use std::io;
use std::io::{Read, Write};
use std::mem::zeroed;
use std::os::unix::io::FromRawFd;
use std::thread::{self, JoinHandle};

/// Write to stderr without panicking (safe for use inside Drop).
fn log_safe(msg: &str) {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
    let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");
}

/// The JNI mangled name of `android.os.Process.setArgV0Native()`.
/// Every Android app calls this during startup to set its process name.
const SET_ARGV0_SYM: &str =
    "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring";

/// Minimum heap region size to consider when searching for ArtMethod.
const MIN_HEAP_SIZE: usize = 0x10000;

/// Delay between force-stop and launch (microseconds).
const LAUNCH_DELAY_US: u32 = 300_000;

/// Abstract socket name for stub → injector notification.
const NOTIFY_SOCKET: &str = "xiam_zymbiote";

pub struct Injector {
    pkg: String,
    agent_so: &'static [u8],

    zpid: u32,
    uid: u32,
    fd: i32, // /proc/<zpid>/mem

    // Addresses found during analysis
    shell: usize,            // payload destination (libstagefright last page)
    func: usize,             // setArgV0Native runtime address
    slot: usize,             // ArtMethod entry_point field address
    heaps: Vec<MemRegion>,   // candidate boot heap regions
    all_rw: Vec<MemRegion>,  // all rw regions (fallback search)

    // Backup for restore
    orig_slot: [u8; 8],
    orig_code: Vec<u8>,

    // Notification listener
    listener_fd: i32,                    // dup'd fd for shutdown
    listener_handle: Option<JoinHandle<()>>,

    stopped: bool,
    need_restore: bool,
}

impl Injector {
    pub fn new(pkg: &str, agent_so: &'static [u8]) -> Self {
        Self {
            pkg: pkg.to_string(),
            agent_so,
            zpid: 0,
            uid: 0,
            fd: -1,
            shell: 0,
            func: 0,
            slot: 0,
            heaps: Vec::new(),
            all_rw: Vec::new(),
            orig_slot: [0u8; 8],
            orig_code: Vec::new(),
            listener_fd: -1,
            listener_handle: None,
            stopped: false,
            need_restore: false,
        }
    }

    /// Execute the full injection flow.
    pub fn run(&mut self) -> io::Result<()> {
        // Step 1: Find Zygote64
        eprintln!("[1] Finding Zygote64...");
        self.zpid = proc::find_zygote()?;
        eprintln!("  [+] Zygote PID: {}", self.zpid);

        // Step 2: Resolve target UID
        eprintln!("[2] Resolving UID for {}...", self.pkg);
        self.uid = proc::get_uid(&self.pkg)?;
        eprintln!("  [+] Target UID: {}", self.uid);

        // Step 3: Freeze Zygote
        eprintln!("[3] Freezing Zygote...");
        unsafe { libc::kill(self.zpid as i32, libc::SIGSTOP) };
        self.stopped = true;
        eprintln!("  [+] Zygote frozen");

        // Open /proc/<zpid>/mem
        let mem_path = format!("/proc/{}/mem\0", self.zpid);
        self.fd = unsafe { libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        if self.fd < 0 {
            self.resume();
            return Err(io::Error::last_os_error());
        }

        // Step 4: Locate key addresses
        eprintln!("[4] Scanning memory maps...");
        if let Err(e) = self.find_addr() {
            self.resume();
            return Err(e);
        }

        // Step 5: Search ArtMethod slot
        eprintln!("[5] Searching ArtMethod slot...");
        if let Err(e) = self.find_slot() {
            self.resume();
            return Err(e);
        }

        // Step 6: Start notification listener
        eprintln!("[6] Starting notify listener...");
        let (lfd, lhandle) = start_notify_listener(self.agent_so)?;
        self.listener_fd = lfd;
        self.listener_handle = Some(lhandle);
        eprintln!("  [+] Listening on @{}", NOTIFY_SOCKET);

        // Step 7: Install hook
        eprintln!("[7] Installing hook...");
        if let Err(e) = self.hook() {
            self.resume();
            return Err(e);
        }

        // Step 8: Launch app
        eprintln!("[8] Launching {}...", self.pkg);
        self.resume();
        self.launch();

        eprintln!("[+] Hook installed! Waiting for app to trigger...");
        Ok(())
    }

    /// Snapshot current injection state for persistence.
    pub fn to_state(&self) -> InjectState {
        InjectState {
            daemon_pid: std::process::id(),
            zpid: self.zpid,
            slot: self.slot,
            shell: self.shell,
            orig_slot: self.orig_slot,
            orig_code: self.orig_code.clone(),
            pkg: self.pkg.clone(),
        }
    }

    /// Restore Zygote to its original state.
    /// NOTE: this is called from Drop — must never panic (no eprintln!).
    pub fn restore(&mut self) {
        if !self.need_restore {
            return;
        }

        log_safe("[*] Restoring Zygote...");
        unsafe {
            libc::kill(self.zpid as i32, libc::SIGSTOP);

            // Restore original ArtMethod entry_point
            libc::pwrite(
                self.fd,
                self.orig_slot.as_ptr() as *const libc::c_void,
                8,
                self.slot as libc::off_t,
            );

            // Restore original code page
            libc::pwrite(
                self.fd,
                self.orig_code.as_ptr() as *const libc::c_void,
                self.orig_code.len(),
                self.shell as libc::off_t,
            );

            libc::kill(self.zpid as i32, libc::SIGCONT);
        }

        self.need_restore = false;
        log_safe("[+] Zygote restored");
    }

    // -----------------------------------------------------------------------
    // Internal steps
    // -----------------------------------------------------------------------

    /// Single-pass scan of /proc/<zpid>/maps to collect:
    /// - shellcode destination (libstagefright.so last executable page)
    /// - libandroid_runtime.so path (to resolve setArgV0Native)
    /// - Boot heap regions (to search for ArtMethod)
    fn find_addr(&mut self) -> io::Result<()> {
        let regions = proc::parse_maps(self.zpid)?;
        let mut rt_path = String::new();
        let mut sf_path = String::new();
        let mut sf_base: usize = 0;
        let mut sf_end: usize = 0;

        for m in &regions {
            // Use the FIRST r-xp mapping of libstagefright.so (the main text segment).
            // Using the last mapping would be incorrect if there are multiple r-xp
            // regions (e.g. separate .plt trampoline pages).
            if sf_path.is_empty() && m.x() && m.path.contains("libstagefright.so") {
                sf_path = m.path.clone();
                sf_base = m.start;
                sf_end = m.end;
            }

            // Find libandroid_runtime.so path
            if rt_path.is_empty() && m.path.contains("libandroid_runtime.so") {
                rt_path = m.path.clone();
            }

            // Collect rw regions for ArtMethod search
            if m.rw() {
                let is_heap = m.path.contains("boot.art")
                    || m.path.contains("boot-framework.art")
                    || m.path.contains(".art")
                    || m.path.contains("dalvik-")
                    || m.path.contains("LinearAlloc")
                    || (m.path.is_empty() && m.size() > MIN_HEAP_SIZE);

                if is_heap {
                    self.heaps.push(m.clone());
                }
                self.all_rw.push(m.clone());
            }
        }

        if sf_path.is_empty() || rt_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "libstagefright.so or libandroid_runtime.so not found in Zygote maps",
            ));
        }

        // ---- Determine shellcode placement ----
        // Prefer ELF padding (trailing NULs at end of executable segment) so we
        // don't overwrite real code that other threads might execute.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let payload_len = PAYLOAD.len();

        self.shell = match elf::exec_load_info(&sf_path) {
            Ok(info) => {
                let code_end = sf_base + info.exec_filesz as usize;
                let aligned = (code_end + 15) & !15; // 16-byte align for ARM64
                let padding = sf_end.saturating_sub(aligned);
                if padding >= payload_len {
                    eprintln!("  [+] Using ELF padding ({padding} bytes free)");
                    aligned
                } else {
                    eprintln!(
                        "  [!] ELF padding too small ({padding} B, need {payload_len}), using last page"
                    );
                    sf_end - page_size
                }
            }
            Err(e) => {
                eprintln!("  [!] ELF parse failed ({e}), using last page");
                sf_end - page_size
            }
        };

        // Resolve setArgV0Native address
        let base = proc::base_addr(self.zpid, &rt_path)?;
        let off = elf::sym_offset(&rt_path, SET_ARGV0_SYM)?;
        self.func = base + off;

        eprintln!("  [+] setArgV0: 0x{:x}", self.func);
        eprintln!("  [+] Shellcode dest: 0x{:x}", self.shell);
        eprintln!("  [+] Heap regions: {}", self.heaps.len());
        Ok(())
    }

    /// Search for the ArtMethod entry that contains the setArgV0Native address.
    /// Tries boot heap regions first, then falls back to all rw regions.
    fn find_slot(&mut self) -> io::Result<()> {
        // Fast path: boot heap regions
        for h in &self.heaps {
            if let Some(addr) = mem::search(self.fd, h, self.func) {
                self.slot = addr;
                eprintln!("  [+] ArtMethod slot: 0x{:x}", self.slot);
                return Ok(());
            }
        }

        // Fallback: search ALL rw regions (covers newer Android where
        // ArtMethod lives in [anon:*] tagged regions not matching boot heap filters)
        eprintln!("  [*] Not in boot heap ({} regions), searching all rw ({} regions)...",
            self.heaps.len(), self.all_rw.len());

        for m in &self.all_rw {
            // Skip regions already searched
            if self.heaps.iter().any(|h| h.start == m.start) {
                continue;
            }
            if let Some(addr) = mem::search(self.fd, m, self.func) {
                self.slot = addr;
                eprintln!("  [+] ArtMethod slot: 0x{:x} (in {:?})", self.slot,
                    if m.path.is_empty() { "<anon>" } else { &m.path });
                return Ok(());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ArtMethod slot not found in any rw region",
        ))
    }

    /// Install the hook: backup originals, fill payload, pwrite to Zygote.
    fn hook(&mut self) -> io::Result<()> {
        let payload_len = PAYLOAD.len();

        // Backup original data
        self.orig_code = vec![0u8; payload_len];
        let n = unsafe {
            libc::pread(
                self.fd,
                self.orig_code.as_mut_ptr() as *mut libc::c_void,
                payload_len,
                self.shell as libc::off_t,
            )
        };
        if n != payload_len as isize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to backup shellcode page",
            ));
        }

        let n = unsafe {
            libc::pread(
                self.fd,
                self.orig_slot.as_mut_ptr() as *mut libc::c_void,
                8,
                self.slot as libc::off_t,
            )
        };
        if n != 8 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to backup ArtMethod slot",
            ));
        }

        // Fill payload with runtime parameters
        let filled = payload::fill_payload(&StubParams {
            original_func: self.func,
            slot_addr: self.slot,
            uid: self.uid,
            socket_name: NOTIFY_SOCKET.to_string(),
        })
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Write payload to libstagefright last page
        let n = unsafe {
            libc::pwrite(
                self.fd,
                filled.as_ptr() as *const libc::c_void,
                filled.len(),
                self.shell as libc::off_t,
            )
        };
        if n != filled.len() as isize {
            return Err(io::Error::new(io::ErrorKind::Other, "pwrite payload failed"));
        }

        // Overwrite ArtMethod entry_point with shellcode address
        let shell_addr = self.shell.to_le_bytes();
        let n = unsafe {
            libc::pwrite(
                self.fd,
                shell_addr.as_ptr() as *const libc::c_void,
                8,
                self.slot as libc::off_t,
            )
        };
        if n != 8 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "pwrite slot failed",
            ));
        }

        self.need_restore = true;
        eprintln!("  [+] Hook installed");
        Ok(())
    }

    /// Resume Zygote (SIGCONT).
    fn resume(&mut self) {
        if self.stopped {
            unsafe { libc::kill(self.zpid as i32, libc::SIGCONT) };
            self.stopped = false;
        }
    }

    /// Force-stop then launch the target app.
    fn launch(&self) {
        let stop_cmd = format!("am force-stop {} 2>/dev/null\0", self.pkg);
        unsafe {
            libc::system(stop_cmd.as_ptr() as *const libc::c_char);
            libc::usleep(LAUNCH_DELAY_US);
        }

        let start_cmd = format!(
            "am start $(cmd package resolve-activity --brief '{}' | tail -n 1) 2>/dev/null\0",
            self.pkg
        );
        unsafe {
            libc::system(start_cmd.as_ptr() as *const libc::c_char);
        }

        eprintln!("  [+] App launched");
    }
}

/// Standalone restore from a persisted state — works without an Injector instance.
/// Opens `/proc/<zpid>/mem` itself, so the original fd is not required.
pub fn restore_from_state(state: &InjectState) -> io::Result<()> {
    eprintln!("[*] Restoring Zygote (pid {}) from state...", state.zpid);

    let mem_path = format!("/proc/{}/mem\0", state.zpid);
    let fd = unsafe { libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        libc::kill(state.zpid as i32, libc::SIGSTOP);

        libc::pwrite(
            fd,
            state.orig_slot.as_ptr() as *const libc::c_void,
            8,
            state.slot as libc::off_t,
        );

        if !state.orig_code.is_empty() {
            libc::pwrite(
                fd,
                state.orig_code.as_ptr() as *const libc::c_void,
                state.orig_code.len(),
                state.shell as libc::off_t,
            );
        }

        libc::kill(state.zpid as i32, libc::SIGCONT);
        libc::close(fd);
    }

    eprintln!("[+] Zygote restored");
    Ok(())
}

impl Drop for Injector {
    fn drop(&mut self) {
        self.restore();

        // Shut down the listener socket so the accept-loop thread exits.
        if self.listener_fd >= 0 {
            unsafe {
                libc::shutdown(self.listener_fd, libc::SHUT_RDWR);
                libc::close(self.listener_fd);
            }
            self.listener_fd = -1;
        }
        if let Some(handle) = self.listener_handle.take() {
            let _ = handle.join();
        }

        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

// ---------------------------------------------------------------------------
// Notification listener — accepts PID from stub, runs ptrace+memfd injection
// ---------------------------------------------------------------------------

/// Start an abstract Unix socket listener for stub notifications.
///
/// When a forked child's stub connects and sends its PID, this thread:
///   1. ptrace attaches to the child
///   2. Injects the agent via memfd remote calls
///   3. Signals the stub to continue
/// Returns `(shutdown_fd, join_handle)`.  The caller keeps `shutdown_fd`
/// and calls `shutdown()` + `close()` on it to terminate the thread.
fn start_notify_listener(agent_so: &'static [u8]) -> io::Result<(i32, JoinHandle<()>)> {
    // Create the listener socket before spawning the thread.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_un = unsafe { zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    // Abstract socket: sun_path[0] = 0, name follows.
    let name = NOTIFY_SOCKET.as_bytes();
    let len = name.len().min(107);
    for (i, &b) in name[..len].iter().enumerate() {
        addr.sun_path[i + 1] = b as libc::c_char;
    }
    let addr_len = (std::mem::size_of_val(&addr.sun_family) + 1 + len) as u32;

    let rc = unsafe { libc::bind(fd, &addr as *const _ as *const _, addr_len) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let rc = unsafe { libc::listen(fd, 4) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // dup fd so the caller can shutdown() it independently.
    let shutdown_fd = unsafe { libc::dup(fd) };
    if shutdown_fd < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };

    let handle = thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    // Read 4-byte PID from stub.
                    let mut pid_buf = [0u8; 4];
                    if stream.read_exact(&mut pid_buf).is_err() {
                        eprintln!("[!] failed to read PID from stub");
                        continue;
                    }
                    let pid = i32::from_le_bytes(pid_buf);
                    eprintln!("[*] stub notification: pid={pid}");

                    // Start patcher BEFORE injection so @xiam_patcher
                    // is already listening when the SO tries to connect.
                    let _patcher = match crate::patcher::start_patcher(pid) {
                        Ok(h) => {
                            eprintln!("[+] patcher server started for pid {pid}");
                            Some(h)
                        }
                        Err(e) => {
                            eprintln!("[!] patcher start failed: {e}");
                            None
                        }
                    };

                    // Perform ptrace + memfd injection.
                    match remote_inject::inject_memfd(pid, agent_so) {
                        Ok(()) => {
                            eprintln!("[+] injection into pid {pid} succeeded");
                        }
                        Err(e) => {
                            eprintln!("[!] injection into pid {pid} failed: {e}");
                        }
                    }

                    // Signal stub to continue (write 1 byte).
                    let _ = stream.write_all(&[0x01]);
                }
                // Listener error (e.g. shutdown from Drop) → exit thread.
                Err(_) => break,
            }
        }
    });

    Ok((shutdown_fd, handle))
}
