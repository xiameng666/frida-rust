//! XiaM Zymbiote Injector — interactive REPL.
//!
//! Run `./xiam-inject`, then type commands:
//!   start <pkg> [so]  — inject into Zygote
//!   stop              — restore Zygote and clear state
//!   status            — show current injection info
//!   exit / quit       — restore (if active) and exit

mod elf;
mod injector;
mod mem;
mod payload;
mod proc;
mod state;

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

const DEFAULT_SO: &str = "/data/local/tmp/libXiaM.so";

fn main() {
    // Check root
    if unsafe { libc::getuid() } != 0 {
        eprintln!("[!] Root required");
        std::process::exit(1);
    }

    // Ctrl+C sets RUNNING=false so the REPL exits gracefully
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
    }

    eprintln!("XiaM Zymbiote Injector v0.2.0");
    eprintln!("Type \"help\" for commands.\n");

    let mut inj: Option<injector::Injector> = None;
    let stdin = io::stdin();

    loop {
        if !RUNNING.load(Ordering::Relaxed) {
            eprintln!();
            break;
        }

        // Print prompt
        eprint!("xiam> ");
        let _ = io::stderr().flush();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Err(_) => break,
            _ => {}
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "start" => cmd_start(&parts, &mut inj),
            "stop" => cmd_stop(&mut inj),
            "status" => cmd_status(&inj),
            "help" => cmd_help(),
            "exit" | "quit" => break,
            other => eprintln!("[!] Unknown command: {}", other),
        }
    }

    // Cleanup on exit
    if let Some(ref mut i) = inj {
        i.restore();
        state::InjectState::remove();
        eprintln!("[+] Zygote restored");
    }
    eprintln!("[+] Bye");
}

// ---------------------------------------------------------------------------
// start <pkg> [so]
// ---------------------------------------------------------------------------

fn cmd_start(args: &[&str], inj: &mut Option<injector::Injector>) {
    if inj.is_some() {
        eprintln!("[!] Already injected — run `stop` first");
        return;
    }

    let pkg = match args.get(1) {
        Some(p) => *p,
        None => {
            eprintln!("Usage: start <pkg> [so_path]");
            return;
        }
    };
    let so_path = args.get(2).copied().unwrap_or(DEFAULT_SO);

    // Verify SO exists
    let so_c = format!("{}\0", so_path);
    if unsafe { libc::access(so_c.as_ptr() as *const libc::c_char, libc::R_OK) } != 0 {
        eprintln!("[!] SO not found: {}", so_path);
        return;
    }

    let mut i = injector::Injector::new(pkg, so_path);

    if let Err(e) = i.run() {
        eprintln!("[!] Injection failed: {}", e);
        return;
    }

    // Save state to disk as safety net
    let st = i.to_state();
    if let Err(e) = st.save() {
        eprintln!("[!] Failed to save state: {}", e);
    }

    *inj = Some(i);
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

fn cmd_stop(inj: &mut Option<injector::Injector>) {
    match inj.take() {
        Some(mut i) => {
            i.restore();
            state::InjectState::remove();
            eprintln!("[+] Stopped");
        }
        None => {
            // Try restoring from state file (previous crash)
            if let Ok(st) = state::InjectState::load() {
                if let Err(e) = injector::restore_from_state(&st) {
                    eprintln!("[!] Restore failed: {}", e);
                    return;
                }
                state::InjectState::remove();
                eprintln!("[+] Restored from state file");
            } else {
                eprintln!("[!] Nothing to stop");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status(inj: &Option<injector::Injector>) {
    match inj {
        Some(i) => {
            let st = i.to_state();
            eprintln!("State     : ACTIVE");
            eprintln!("Package   : {}", st.pkg);
            eprintln!("Zygote PID: {}", st.zpid);
            eprintln!("Slot      : 0x{:x}", st.slot);
            eprintln!("Shell     : 0x{:x}", st.shell);
        }
        None => {
            if let Ok(st) = state::InjectState::load() {
                eprintln!("State     : ORPHANED (daemon dead, state file exists)");
                eprintln!("Package   : {}", st.pkg);
                eprintln!("Zygote PID: {}", st.zpid);
                eprintln!("Run `stop` to restore.");
            } else {
                eprintln!("State     : IDLE");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

fn cmd_help() {
    eprintln!("Commands:");
    eprintln!("  start <pkg> [so]   Inject (default SO: {})", DEFAULT_SO);
    eprintln!("  stop               Restore Zygote");
    eprintln!("  status             Show injection state");
    eprintln!("  exit / quit        Restore and exit");
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}
