# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. 写代码时请使用中文注释

## Project Overview

This is **frida-rust**, official Rust bindings for [Frida](https://frida.re), a dynamic instrumentation toolkit. The project provides safe Rust wrappers around Frida's C APIs for runtime code injection, hooking, and tracing.

## Workspace Structure

The repository is a Cargo workspace with these crates:

| Crate | Purpose |
|-------|---------|
| `frida` | High-level bindings for frida-core (device management, process injection, RPC scripts) |
| `frida-sys` | Raw FFI bindings for frida-core (generated via bindgen) |
| `frida-gum` | High-level bindings for Frida Gum (local instrumentation: interceptor, stalker, module APIs) |
| `frida-gum-sys` | Raw FFI bindings for frida-gum (generated via bindgen) |
| `frida-build` | Build helper for auto-downloading Frida devkits |

## Build Commands

```bash
# Build all default workspace members
cargo build

# Build with auto-download feature (downloads Frida devkits automatically)
cargo build --features auto-download

# Build frida-gum with JavaScript scripting support
cargo build --features frida-gum/script

# Build for Android (requires NDK toolchain)
cargo build --target aarch64-linux-android
```

### Prerequisites

Without `auto-download` feature, you must manually place Frida devkits:
- `frida-gum.h` and `libfrida-gum.a` → `/usr/local/include` and `/usr/local/lib`
- `frida-core.h` and `libfrida-core.a` → same locations

## Running Examples

Examples are split into two categories:

```bash
# Core examples (frida-core: device management, injection)
cargo run -p hello           # Basic Frida initialization
cargo run -p usb-device      # USB device enumeration
cargo run -p get-processes   # List processes on device
cargo run -p inject-lib-file # Inject library into process

# Gum examples (local instrumentation)
cargo run -p hook-open       # Function hooking (builds cdylib, inject with LD_PRELOAD)
cargo run -p process-check   # Process enumeration
cargo run -p stalker         # Code tracing with Stalker
cargo run -p debug-symbol    # Symbol resolution

# Agent examples (custom instrumentation framework)
# Agent SO - minimal Android SO with Unix socket communication
cargo build -p agent --target aarch64-linux-android --release
# Output: target/aarch64-linux-android/release/libagent.so

# Agent Host - Unix socket host tool (Linux/macOS only)
cargo run -p agent-host      # Interactive command shell for agent
```

## Key Architecture Concepts

### Two API Surfaces

1. **frida crate (frida-core)**: Remote instrumentation
   - `DeviceManager` → `Device` → `Session` → `Script`
   - Used for attaching to remote processes, injecting code, RPC communication
   - Requires Frida server running on target

2. **frida-gum crate**: Local in-process instrumentation
   - `Gum` singleton for initialization
   - `Interceptor` for function hooking (replace/attach)
   - `Stalker` for code tracing (follow/unfollow threads)
   - `Module` for symbol resolution and memory operations
   - `instruction_writer` for JIT code generation

### Gum Feature Flags

| Feature | Purpose |
|---------|---------|
| `script` | JavaScript scripting via GumJS |
| `event-sink` | Stalker event callbacks |
| `invocation-listener` | Interceptor invocation callbacks |
| `stalker-observer` | Stalker block observation |
| `stalker-params` | Custom Stalker parameters |
| `backtrace` | Backtrace support |
| `memory-access-monitor` | Memory watchpoints |
| `std` | Standard library support (default for most targets) |

### no_std Support

`frida-gum` supports `no_std` environments (useful for embedded/firmware):
- Disable `std` feature
- Requires `alloc` crate
- See `examples/gum/linux_no_std/` for reference

## Development Patterns

### Gum Initialization

```rust
use frida_gum::Gum;
// Singleton pattern - Gum::obtain() can be called multiple times
let gum = Gum::obtain();
```

### Function Hooking Pattern

```rust
use frida_gum::{interceptor::Interceptor, Gum, Module, NativePointer};

let gum = Gum::obtain();
let module = Module::load(&gum, "libc.so.6");
let mut interceptor = Interceptor::obtain(&gum);
let func_ptr = module.find_export_by_name("target_func").unwrap();

// Replace function
interceptor.replace(func_ptr, NativePointer(detour_fn as *mut c_void), NativePointer(std::ptr::null_mut())).unwrap();
```

### Stalker Tracing Pattern

```rust
use frida_gum::stalker::{Stalker, Transformer};

let mut stalker = Stalker::new(&gum);
let transformer = Transformer::from_callback(&gum, |block, output| {
    for instr in block {
        instr.keep();  // Pass through instruction
    }
});
stalker.follow_me(&transformer);
// ... code to trace ...
stalker.unfollow_me();
```

## Learning Resources

The file `rustfrida-7day-tutorial.md` contains a detailed tutorial for building a custom Frida-like tool, covering:
- Direct syscalls (bypassing libc hooks)
- ARM64 instruction relocation
- Hardware breakpoint hooking via KPM kernel modules
- ART Java method hooking
- Code tracing with Stalker

## Agent Module (Custom Instrumentation Framework)

The `agent` and `agent-host` examples implement a minimal custom instrumentation framework for learning purposes, as described in `rustfrida-7day-tutorial.md` Day 1.

### Architecture

```
┌─────────────────┐                    ┌─────────────────────┐
│   agent-host    │                    │   libagent.so       │
│   (PC/Linux)    │◄── Unix Socket ───►│   (Android ARM64)   │
│                 │   (abstract)       │                     │
│   Commands:     │                    │   Commands:         │
│   - ping        │                    │   - hello_entry()   │
│   - echo        │                    │   - constructor     │
│   - exit        │                    │                     │
└─────────────────┘                    └─────────────────────┘
```

### Usage on Android

1. **Build the agent SO:**
   ```bash
   # Requires Android NDK and target: aarch64-linux-android
   cargo build -p agent --target aarch64-linux-android --release
   ```

2. **Push to device and inject:**
   ```bash
   adb push libagent.so /data/local/tmp/
   # Use Zygisk, frida-inject, or other injection methods
   ```

3. **Communicate from Windows:**
   - Use ADB port forwarding (requires TCP version or socat)
   - Or run `agent-host` in WSL

### Abstract Unix Socket

The agent uses abstract Unix socket namespace (`\0my_agent_socket`):
- No file system entry (more stealthy)
- Linux-specific feature
- Not accessible across namespace boundaries

## Related Projects

- `C:\Users\24151\Documents\GitHub\rustFrida` - Reference implementation being studied
- `C:\Users\24151\Documents\GitHub\xiaojia-hide` - KPM kernel module for stealth hooks
- `C:\Users\24151\Documents\GitHub\zygisk_gadget` - Zygisk injection tool for Android
