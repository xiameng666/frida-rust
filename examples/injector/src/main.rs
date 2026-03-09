//! XiaM ptrace+memfd injector.
//!
//! Usage: xiam-inject --pid <PID>
//!
//! Flow:
//!   1. Create memfd with the agent SO.
//!   2. Start abstract Unix socket listener ("xiam_socket").
//!   3. ptrace-attach to target, write shellcode + structs, call shellcode.
//!   4. Shellcode connects back, receives memfd via SCM_RIGHTS, dlopen's it.
//!   5. Agent init_array fires → XiaM agent starts.

#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod inject;
mod memfd;
mod ptrace;
mod remote;

use std::env;
use std::process;

/// Pre-compiled loader shellcode (loader.bin).
const SHELLCODE: &[u8] = include_bytes!("../loader/loader.bin");

/// The agent shared library, embedded at compile time.
const AGENT_SO: &[u8] = include_bytes!("../../../target/aarch64-linux-android/release/libXiaM.so");

const SOCKET_NAME: &str = "xiam_socket";

fn usage() -> ! {
    eprintln!("usage: xiam-inject --pid <PID>");
    process::exit(1);
}

fn main() {
    // Minimal arg parsing (no clap dependency).
    let args: Vec<String> = env::args().collect();
    let pid = match args.iter().position(|a| a == "--pid" || a == "-p") {
        Some(i) => args
            .get(i + 1)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or_else(|| usage()),
        None => usage(),
    };

    eprintln!("[*] XiaM injector — target pid {pid}");
    eprintln!("[*] shellcode {} bytes, agent {} bytes", SHELLCODE.len(), AGENT_SO.len());

    // 1. Create memfd with agent SO.
    let agent_memfd = memfd::create_memfd_with_data("xiam", AGENT_SO)
        .unwrap_or_else(|e| {
            eprintln!("[!] memfd: {e}");
            process::exit(1);
        });
    eprintln!("[+] agent memfd = {agent_memfd}");

    // 2. Start abstract socket listener.
    let _listener = memfd::start_socket_listener(SOCKET_NAME, agent_memfd)
        .unwrap_or_else(|e| {
            eprintln!("[!] socket listener: {e}");
            process::exit(1);
        });
    eprintln!("[+] socket listener started on @{SOCKET_NAME}");

    // 3. Inject.
    if let Err(e) = inject::inject_to_process(pid, SHELLCODE) {
        eprintln!("[!] injection failed: {e}");
        process::exit(1);
    }

    eprintln!("[+] injection complete, agent should be running");

    // Keep process alive so the socket stays open for the loader handshake.
    // The agent will eventually establish its own TCP channel to the host.
    std::thread::sleep(std::time::Duration::from_secs(10));
    eprintln!("[*] exiting");
}
