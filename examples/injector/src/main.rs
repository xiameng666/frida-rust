//! XiaM Zymbiote Injector — ptrace-free spawn injection for Android.
//!
//! Subcommands:
//!   start <pkg> [so]  — inject + save state + keep running as daemon
//!   stop              — kill daemon + restore Zygote from state file
//!   status            — show current injection state
//!   restore           — force-restore Zygote from state file (even if daemon is dead)

mod elf;
mod injector;
mod mem;
mod payload;
mod proc;
mod state;

use injector::restore_from_state;
use state::InjectState;
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

const DEFAULT_SO: &str = "/data/local/tmp/libXiaM.so";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match cmd {
        "start" => cmd_start(&args),
        "stop" => cmd_stop(),
        "status" => cmd_status(),
        "restore" => cmd_restore(),
        _ => usage(&args),
    }
}

fn usage(args: &[String]) {
    let bin = args.first().map(|s| s.as_str()).unwrap_or("xiam-inject");
    eprintln!("XiaM Zymbiote Injector v0.2.0");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  {} start <pkg> [so]   Inject and keep running", bin);
    eprintln!("  {} stop               Kill daemon and restore", bin);
    eprintln!("  {} status             Show injection state", bin);
    eprintln!("  {} restore            Force-restore from state file", bin);
    eprintln!();
    eprintln!("Default SO: {}", DEFAULT_SO);
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

fn cmd_start(args: &[String]) {
    require_root();

    let pkg = match args.get(2) {
        Some(p) => p.as_str(),
        None => {
            eprintln!("[!] Missing package name");
            std::process::exit(1);
        }
    };
    let so_path = args.get(3).map(|s| s.as_str()).unwrap_or(DEFAULT_SO);

    // Verify SO exists
    let so_c = format!("{}\0", so_path);
    if unsafe { libc::access(so_c.as_ptr() as *const libc::c_char, libc::R_OK) } != 0 {
        eprintln!("[!] SO not found: {}", so_path);
        std::process::exit(1);
    }

    // If there is already an active injection, warn
    if InjectState::exists() {
        eprintln!("[!] State file already exists — run `stop` or `restore` first");
        std::process::exit(1);
    }

    // Install signal handler
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }

    let mut inj = injector::Injector::new(pkg, so_path);

    if let Err(e) = inj.run() {
        eprintln!("[!] Injection failed: {}", e);
        std::process::exit(1);
    }

    // Save state + disarm Drop so hook stays active
    let st = inj.to_state();
    if let Err(e) = st.save() {
        eprintln!("[!] Failed to save state: {}", e);
        // Still injected — keep running so Drop restores on exit
    } else {
        inj.disarm(); // Drop won't restore; stop/restore will
    }

    eprintln!("[+] Daemon PID {} — waiting for signal...", std::process::id());

    // Wait until Ctrl+C / SIGTERM
    while RUNNING.load(Ordering::Relaxed) {
        unsafe { libc::sleep(1) };
    }

    eprintln!();
    // Re-arm and restore
    inj.restore();
    InjectState::remove();
    eprintln!("[+] Done");
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

fn cmd_stop() {
    require_root();

    let st = match InjectState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] No active injection ({})", e);
            std::process::exit(1);
        }
    };

    // Kill daemon if alive
    if st.daemon_pid != 0 {
        let ret = unsafe { libc::kill(st.daemon_pid as i32, libc::SIGTERM) };
        if ret == 0 {
            eprintln!("[*] Sent SIGTERM to daemon pid {}", st.daemon_pid);
            // Give it a moment to self-restore
            unsafe { libc::usleep(500_000) };
        }
    }

    // Restore regardless (daemon may have died without restoring)
    if let Err(e) = restore_from_state(&st) {
        eprintln!("[!] Restore failed: {}", e);
        std::process::exit(1);
    }

    InjectState::remove();
    eprintln!("[+] Stopped");
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status() {
    if !InjectState::exists() {
        eprintln!("No active injection");
        return;
    }

    let st = match InjectState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] State file corrupt ({})", e);
            return;
        }
    };

    let daemon_alive = st.daemon_pid != 0
        && unsafe { libc::kill(st.daemon_pid as i32, 0) } == 0;

    eprintln!("Package   : {}", st.pkg);
    eprintln!("Daemon PID: {} {}", st.daemon_pid,
        if daemon_alive { "(alive)" } else { "(dead)" });
    eprintln!("Zygote PID: {}", st.zpid);
    eprintln!("Slot      : 0x{:x}", st.slot);
    eprintln!("Shell     : 0x{:x}", st.shell);
    eprintln!("Backup    : {} bytes code, 8 bytes slot", st.orig_code.len());
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

fn cmd_restore() {
    require_root();

    let st = match InjectState::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] No state file ({})", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = restore_from_state(&st) {
        eprintln!("[!] Restore failed: {}", e);
        std::process::exit(1);
    }

    InjectState::remove();
    eprintln!("[+] Restored");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn require_root() {
    if unsafe { libc::getuid() } != 0 {
        eprintln!("[!] Root required");
        std::process::exit(1);
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}
