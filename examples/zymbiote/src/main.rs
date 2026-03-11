//! XiaM Zymbiote Injector — interactive REPL.
//!
//! Run `./xiam-zymbiote`, then type commands:
//!   start <pkg>       — inject into Zygote
//!   stop              — restore Zygote and clear state
//!   status            — show current injection info
//!   exit / quit       — restore (if active) and exit

mod elf;
mod injector;
mod mem;
mod patcher;
mod payload;
mod proc;
mod ptrace;
mod remote;
mod remote_inject;
mod state;
mod wx;

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

/// Agent SO embedded at compile time.
static AGENT_SO: &[u8] = include_bytes!("../../../target/aarch64-linux-android/release/libXiaM.so");

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
    let mut wx_pid: u32 = 0;
    let stdin = io::stdin();

    loop {
        if !RUNNING.load(Ordering::Relaxed) {
            let _ = writeln!(io::stderr());
            break;
        }

        // Print prompt
        let _ = write!(io::stderr(), "xiam> ");
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
            "target" => cmd_target(&parts, &mut wx_pid),
            "wx" => cmd_wx(&parts, wx_pid),
            "wx-del" => cmd_wx_del(&parts, wx_pid),
            "help" => cmd_help(),
            "exit" | "quit" => break,
            other => eprintln!("[!] Unknown command: {}", other),
        }
    }

    // Cleanup on exit — use write! (not eprintln!) because stderr
    // may be a broken pipe if the adb session died.
    if let Some(ref mut i) = inj {
        i.restore();
        state::InjectState::remove();
        let _ = writeln!(io::stderr(), "[+] Zygote restored");
    }
    let _ = writeln!(io::stderr(), "[+] Bye");
}

// ---------------------------------------------------------------------------
// start <pkg>
// ---------------------------------------------------------------------------

fn cmd_start(args: &[&str], inj: &mut Option<injector::Injector>) {
    if inj.is_some() {
        eprintln!("[!] Already injected — run `stop` first");
        return;
    }

    let pkg = match args.get(1) {
        Some(p) => *p,
        None => {
            eprintln!("Usage: start <pkg>");
            return;
        }
    };

    let mut i = injector::Injector::new(pkg, AGENT_SO);

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
    eprintln!("  start <pkg>        Inject (agent SO embedded)");
    eprintln!("  stop               Restore Zygote");
    eprintln!("  status             Show injection state");
    eprintln!();
    eprintln!("wxshadow (requires KPM loaded):");
    eprintln!("  target <pid>       Set target PID for wx commands");
    eprintln!("  wx <addr>          Hidden breakpoint (log only)");
    eprintln!("  wx <addr> arg<N> <val>   BP + modify argument");
    eprintln!("  wx <addr> ret <val>      BP + modify return value");
    eprintln!("  wx <addr> x<N> <val> ... BP + modify registers");
    eprintln!("  wx-del <addr>      Remove hidden breakpoint");
    eprintln!();
    eprintln!("  exit / quit        Restore and exit");
}

// ---------------------------------------------------------------------------
// target <pid>
// ---------------------------------------------------------------------------

fn cmd_target(args: &[&str], wx_pid: &mut u32) {
    match args.get(1) {
        Some(s) => match parse_int(s) {
            Some(pid) => {
                *wx_pid = pid as u32;
                eprintln!("[+] Target PID: {}", *wx_pid);
            }
            None => eprintln!("Usage: target <pid>"),
        },
        None => {
            if *wx_pid > 0 {
                eprintln!("Current target: {}", *wx_pid);
            } else {
                eprintln!("No target set. Usage: target <pid>");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// wx <addr> [action] [args...]
// ---------------------------------------------------------------------------

fn cmd_wx(args: &[&str], pid: u32) {
    if pid == 0 {
        eprintln!("[!] No target. Run: target <pid>");
        return;
    }

    let addr = match args.get(1).and_then(|s| parse_int(s)) {
        Some(a) => a as u64,
        None => {
            eprintln!("Usage: wx <addr> [log | arg<N> <val> | ret <val> | x<N> <val> ...]");
            return;
        }
    };

    let action = if args.len() <= 2 || args[2] == "log" {
        // wx <addr>  OR  wx <addr> log
        wx::WxAction::Log
    } else if let Some(idx) = args[2].strip_prefix("arg") {
        // wx <addr> arg0 <val>
        let idx: u8 = match idx.parse() {
            Ok(i) if i <= 7 => i,
            _ => {
                eprintln!("[!] arg index must be 0-7");
                return;
            }
        };
        let val = args.get(3).and_then(|s| parse_int(s)).unwrap_or(0) as u64;
        wx::WxAction::Arg(idx, val)
    } else if args[2] == "ret" {
        // wx <addr> ret <val>
        let val = args.get(3).and_then(|s| parse_int(s)).unwrap_or(0) as u64;
        wx::WxAction::Ret(val)
    } else {
        // wx <addr> x3 0xdead x5 0xbeef
        let mut mods = Vec::new();
        let mut i = 2;
        while i + 1 < args.len() {
            if let Some(reg_str) = args[i].strip_prefix('x') {
                if let (Ok(reg), Some(val)) = (reg_str.parse::<u8>(), parse_int(args[i + 1])) {
                    mods.push((reg, val as u64));
                    i += 2;
                    continue;
                }
            }
            eprintln!("[!] Bad register pair: {} {}", args[i], args.get(i + 1).unwrap_or(&""));
            return;
        }
        if mods.is_empty() {
            eprintln!("Usage: wx <addr> x<N> <val> ...");
            return;
        }
        wx::WxAction::Regs(mods)
    };

    match wx::wx_hook(pid, addr, action.clone()) {
        Ok(()) => eprintln!("[+] wx bp 0x{:x} {:?}", addr, action),
        Err(e) => eprintln!("[!] {}", e),
    }
}

// ---------------------------------------------------------------------------
// wx-del <addr>
// ---------------------------------------------------------------------------

fn cmd_wx_del(args: &[&str], pid: u32) {
    if pid == 0 {
        eprintln!("[!] No target. Run: target <pid>");
        return;
    }
    let addr = match args.get(1).and_then(|s| parse_int(s)) {
        Some(a) => a as u64,
        None => {
            eprintln!("Usage: wx-del <addr>");
            return;
        }
    };
    match wx::wx_unhook(pid, addr) {
        Ok(()) => eprintln!("[+] wx bp removed 0x{:x}", addr),
        Err(e) => eprintln!("[!] {}", e),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse decimal or hex (0x...) integer.
fn parse_int(s: &str) -> Option<usize> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::Relaxed);
}
