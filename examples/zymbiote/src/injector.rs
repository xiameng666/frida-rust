//! Core injector: Zymbiote injection via /proc/<pid>/mem.

use crate::elf;
use crate::mem;
use crate::payload::{self, StubParams, PAYLOAD};
use crate::proc::{self, MemRegion};
use crate::state::InjectState;
use std::io;

/// The JNI mangled name of `android.os.Process.setArgV0Native()`.
/// Every Android app calls this during startup to set its process name.
const SET_ARGV0_SYM: &str =
    "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring";

/// Minimum heap region size to consider when searching for ArtMethod.
const MIN_HEAP_SIZE: usize = 0x10000;

/// Delay between force-stop and launch (microseconds).
const LAUNCH_DELAY_US: u32 = 300_000;

pub struct Injector {
    pkg: String,
    so_path: String,

    zpid: u32,
    uid: u32,
    fd: i32, // /proc/<zpid>/mem

    // Addresses found during analysis
    shell: usize,            // payload destination (libstagefright last page)
    func: usize,             // setArgV0Native runtime address
    slot: usize,             // ArtMethod entry_point field address
    heaps: Vec<MemRegion>,   // candidate boot heap regions

    // Backup for restore
    orig_slot: [u8; 8],
    orig_code: Vec<u8>,

    // Remote SO path (in target app's cache dir)
    remote_so: String,

    stopped: bool,
    need_restore: bool,
}

impl Injector {
    pub fn new(pkg: &str, so_path: &str) -> Self {
        Self {
            pkg: pkg.to_string(),
            so_path: so_path.to_string(),
            zpid: 0,
            uid: 0,
            fd: -1,
            shell: 0,
            func: 0,
            slot: 0,
            heaps: Vec::new(),
            orig_slot: [0u8; 8],
            orig_code: Vec::new(),
            remote_so: String::new(),
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

        // Step 6: Prepare SO file
        eprintln!("[6] Preparing SO...");
        self.prep_so()?;

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

        eprintln!("[+] Injection complete! Press Ctrl+C to restore and exit.");
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
    pub fn restore(&mut self) {
        if !self.need_restore {
            return;
        }

        eprintln!("[*] Restoring Zygote...");
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
        eprintln!("[+] Zygote restored");
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

        for m in &regions {
            // Find shellcode location: last executable page of libstagefright.so
            if self.shell == 0 && m.x() && m.path.contains("libstagefright.so") {
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
                self.shell = m.end - page_size;
            }

            // Find libandroid_runtime.so path
            if rt_path.is_empty() && m.path.contains("libandroid_runtime.so") {
                rt_path = m.path.clone();
            }

            // Collect boot heap candidate regions
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
            }
        }

        if self.shell == 0 || rt_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "libstagefright.so or libandroid_runtime.so not found in Zygote maps",
            ));
        }

        // Resolve setArgV0Native address
        let base = proc::base_addr(self.zpid, &rt_path)?;
        let off = elf::sym_offset(&rt_path, SET_ARGV0_SYM)?;
        self.func = base + off;

        eprintln!("  [+] setArgV0: 0x{:x}", self.func);
        eprintln!("  [+] Shellcode dest: 0x{:x}", self.shell);
        eprintln!("  [+] Heap regions: {}", self.heaps.len());
        Ok(())
    }

    /// Search boot heap regions for the ArtMethod entry_point slot
    /// that contains the setArgV0Native address.
    fn find_slot(&mut self) -> io::Result<()> {
        for h in &self.heaps {
            if let Some(addr) = mem::search(self.fd, h, self.func) {
                self.slot = addr;
                eprintln!("  [+] ArtMethod slot: 0x{:x}", self.slot);
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ArtMethod slot not found in boot heap",
        ))
    }

    /// Copy SO to the target app's cache directory so dlopen can load it.
    fn prep_so(&mut self) -> io::Result<()> {
        self.remote_so = format!("/data/data/{}/cache/libXiaM_{}.so", self.pkg, self.uid);

        let cmd = format!(
            "cp '{}' '{}' && chown {}:{} '{}' && chmod 755 '{}'\0",
            self.so_path, self.remote_so, self.uid, self.uid, self.remote_so, self.remote_so
        );
        unsafe {
            libc::system(cmd.as_ptr() as *const libc::c_char);
        }

        eprintln!("  [+] SO: {}", self.remote_so);
        Ok(())
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

        // Resolve remote function addresses in Zygote's address space
        let fn_getuid = elf::remote_sym(self.zpid, "libc.so", "getuid")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("getuid: {e}")))?;
        let fn_dlopen = elf::remote_sym(self.zpid, "libdl.so", "dlopen")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("dlopen: {e}")))?;
        let fn_log = elf::remote_sym(self.zpid, "liblog.so", "__android_log_print")
            .unwrap_or(0); // log is optional

        eprintln!("  [+] getuid: 0x{:x}", fn_getuid);
        eprintln!("  [+] dlopen: 0x{:x}", fn_dlopen);
        eprintln!("  [+] log: 0x{:x}", fn_log);

        // Fill payload with runtime parameters
        let filled = payload::fill_payload(&StubParams {
            original_func: self.func,
            slot_addr: self.slot,
            uid: self.uid,
            so_path: self.remote_so.clone(),
            fn_getuid,
            fn_dlopen,
            fn_log,
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
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}
