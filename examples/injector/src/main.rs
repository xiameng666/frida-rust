//! XiaM Zymbiote Injector — ptrace-free spawn injection for Android.
//!
//! Usage: xiam-inject <package_name> [so_path]
//!
//! Injects libXiaM.so into a target Android app via the Zymbiote technique:
//! patches Zygote's setArgV0Native ArtMethod entry point so that newly-forked
//! processes with the target UID automatically dlopen the agent SO.

mod elf;
mod injector;
mod mem;
mod payload;
mod proc;

use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

const DEFAULT_SO: &str = "/data/local/tmp/libXiaM.so";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        eprintln!("XiaM Zymbiote Injector v0.1.0");
        eprintln!();
        eprintln!("Usage: {} <package_name> [so_path]", args[0]);
        eprintln!();
        eprintln!("  package_name    Target app package (e.g. com.example.app)");
        eprintln!(
            "  so_path         Path to agent SO (default: {})",
            DEFAULT_SO
        );
        eprintln!();
        eprintln!("Requires root. Press Ctrl+C to restore Zygote and exit.");
        std::process::exit(1);
    }

    // Check root
    if unsafe { libc::getuid() } != 0 {
        eprintln!("[!] Root required");
        std::process::exit(1);
    }

    let pkg = &args[1];
    let so_path = args.get(2).map(|s| s.as_str()).unwrap_or(DEFAULT_SO);

    // Verify SO exists
    let so_c = format!("{}\0", so_path);
    if unsafe { libc::access(so_c.as_ptr() as *const libc::c_char, libc::R_OK) } != 0 {
        eprintln!("[!] SO not found: {}", so_path);
        std::process::exit(1);
    }

    // Install signal handler for SIGINT/SIGTERM
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }

    let mut inj = injector::Injector::new(pkg, so_path);

    if let Err(e) = inj.run() {
        eprintln!("[!] Injection failed: {}", e);
        std::process::exit(1);
    }

    // Wait until Ctrl+C
    while RUNNING.load(Ordering::Relaxed) {
        unsafe { libc::sleep(1) };
    }

    // Drop triggers restore
    eprintln!();
    inj.restore();
    eprintln!("[+] Done");
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}
