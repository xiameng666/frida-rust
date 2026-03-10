//! quickjs-hook - QuickJS JavaScript engine with inline hook support for ARM64 Android
//!
//! This crate provides:
//! - QuickJS JavaScript engine bindings
//! - ARM64 inline hook engine
//! - Frida-style JavaScript API for hooking
//!
//! # Example
//!
//! ```rust,ignore
//! use quickjs_hook::{JSEngine, init_hook_engine};
//!
//! // Initialize hook engine with executable memory
//! init_hook_engine(exec_mem, size).unwrap();
//!
//! // Create JS engine and run script
//! let engine = JSEngine::new().unwrap();
//! engine.eval(r#"
//!     console.log("Hello from QuickJS!");
//!     hook(ptr("0x12345678"), function(ctx) {
//!         console.log("Hooked! x0=" + ctx.x0);
//!     });
//! "#).unwrap();
//! ```

#![allow(clippy::missing_safety_doc)]

pub mod ffi;
pub mod runtime;
pub mod context;
pub mod value;
pub mod jsapi;

pub use context::JSContext;
pub use runtime::JSRuntime;
pub use value::JSValue;
pub use jsapi::console::set_console_callback;
pub use jsapi::hook_api::cleanup_hooks;
pub use jsapi::interceptor::cleanup_interceptor_hooks;
pub use jsapi::send::{drain_send_messages, set_send_callback};

use std::sync::Mutex;

/// Global JS engine instance (protected by Mutex)
static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);

/// Initialize the hook engine with executable memory
///
/// # Arguments
/// * `exec_mem` - Pointer to executable memory region (must be RWX)
/// * `size` - Size of the memory region in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` on failure
pub fn init_hook_engine(exec_mem: *mut u8, rw_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe {
        ffi::hook::hook_engine_init(
            exec_mem as *mut _,
            rw_mem as *mut _,
            size,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
}

/// Connect to patcher server via abstract unix socket and set the fd.
/// Returns the connected fd, or -1 on failure.
#[cfg(target_os = "android")]
fn connect_patcher_server() -> i32 {
    // std UnixStream doesn't support abstract sockets directly, use raw syscall
    let fd = unsafe {
        let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if sock < 0 {
            eprintln!("[XiaM-hook] patcher: socket() failed");
            return -1;
        }

        // Build sockaddr_un with abstract name
        let mut sa: libc::sockaddr_un = std::mem::zeroed();
        sa.sun_family = libc::AF_UNIX as u16;
        // Abstract: sun_path[0] = '\0', then name bytes
        let name = b"\0xiam_patcher";
        if name.len() > sa.sun_path.len() {
            libc::close(sock);
            return -1;
        }
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            sa.sun_path.as_mut_ptr() as *mut u8,
            name.len(),
        );

        let sa_len = (std::mem::offset_of!(libc::sockaddr_un, sun_path) + name.len()) as libc::socklen_t;
        let ret = libc::connect(sock, &sa as *const _ as *const libc::sockaddr, sa_len);
        if ret < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            eprintln!("[XiaM-hook] patcher: connect failed (errno={})", err);
            libc::close(sock);
            return -1;
        }
        sock
    };

    unsafe { ffi::hook::hook_engine_set_server(fd) };
    eprintln!("[XiaM-hook] patcher: connected fd={}", fd);
    fd
}

/// Hide our SO from linker data structures (soinfo, link_map, ELF header).
#[cfg(target_os = "android")]
fn hide_so(server_fd: i32) {
    if server_fd < 0 {
        eprintln!("[XiaM-hide] no server fd, skip SO hiding");
        return;
    }

    let rc = unsafe { ffi::hook::so_hide_init(server_fd) };
    if rc != 0 {
        eprintln!("[XiaM-hide] so_hide_init failed ({})", rc);
        return;
    }

    // Run test: logs before/after enumeration via logcat
    let name = b"memfd\0";
    unsafe { ffi::hook::so_hide_test(name.as_ptr() as *const _) };
}

/// Cleanup the hook engine
pub fn cleanup_hook_engine() {
    unsafe {
        ffi::hook::hook_engine_cleanup();
    }
}

/// High-level JS engine wrapper
/// Note: Field order matters for drop order - context must be dropped before runtime
pub struct JSEngine {
    context: JSContext,
    runtime: JSRuntime,
}

impl JSEngine {
    /// Create a new JS engine with all APIs registered
    pub fn new() -> Option<Self> {
        let runtime = JSRuntime::new()?;
        let context = runtime.new_context()?;

        // Register all JavaScript APIs
        jsapi::register_all_apis(&context);

        Some(JSEngine { runtime, context })
    }

    /// Evaluate a JavaScript script
    pub fn eval(&self, script: &str) -> Result<JSValue, String> {
        self.context.eval(script, "<eval>")
    }

    /// Evaluate a script with a specific filename
    pub fn eval_file(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        self.context.eval(script, filename)
    }

    /// Get the JS context
    pub fn context(&self) -> &JSContext {
        &self.context
    }

    /// Get the JS runtime
    pub fn runtime(&self) -> &JSRuntime {
        &self.runtime
    }

    /// Execute pending jobs (for promises)
    pub fn run_pending_jobs(&self) {
        while self.context.execute_pending_job() {}
    }
}

impl Drop for JSEngine {
    fn drop(&mut self) {
        // 清理所有 hook（低级 API + Interceptor）
        cleanup_hooks();
        cleanup_interceptor_hooks();
    }
}

// Safety: JSEngine is protected by Mutex, ensuring single-threaded access
unsafe impl Send for JSEngine {}
unsafe impl Sync for JSEngine {}

/// Try to set up a dual-mapped pool via memfd_create.
/// Returns true on success (hook engine initialized), false on failure.
#[cfg(target_os = "android")]
fn try_dual_mapping(size: usize) -> bool {
    // memfd_create("xm-jit-cache", MFD_CLOEXEC)
    let fd = unsafe {
        libc::syscall(libc::SYS_memfd_create, b"xm-jit-cache\0".as_ptr(), 1u32 /* MFD_CLOEXEC */)
    } as i32;
    if fd < 0 {
        eprintln!("[XiaM-hook] memfd_create failed (errno={}), falling back",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        return false;
    }

    if unsafe { libc::ftruncate(fd, size as libc::off_t) } != 0 {
        unsafe { libc::close(fd) };
        return false;
    }

    let rw = unsafe {
        libc::mmap(
            std::ptr::null_mut(), size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED, fd, 0,
        )
    };
    let rx = unsafe {
        libc::mmap(
            std::ptr::null_mut(), size,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED, fd, 0,
        )
    };

    unsafe { libc::close(fd) }; // fd no longer needed after both mappings

    if rw == libc::MAP_FAILED || rx == libc::MAP_FAILED {
        if rw != libc::MAP_FAILED { unsafe { libc::munmap(rw, size) }; }
        if rx != libc::MAP_FAILED { unsafe { libc::munmap(rx, size) }; }
        eprintln!("[XiaM-hook] dual-mapping mmap failed, falling back");
        return false;
    }

    let _ = init_hook_engine(rx as *mut u8, rw as *mut u8, size);
    eprintln!("[XiaM-hook] pool: dual-map rx={:?} rw={:?} ({} KB) — zero RWX",
        rx, rw, size / 1024);
    true
}

/// Get or initialize the global JS engine
pub fn get_or_init_engine() -> Result<(), String> {
    // 确保 hook 引擎已初始化（仅 Android）
    #[cfg(target_os = "android")]
    {
        static HOOK_INIT: std::sync::Once = std::sync::Once::new();
        HOOK_INIT.call_once(|| {
            const POOL_SIZE: usize = 1024 * 1024; // 1 MB

            // Strategy 1: dual-mapping via memfd (zero RWX, zero mprotect)
            if try_dual_mapping(POOL_SIZE) {
                let sfd = connect_patcher_server();
                hide_so(sfd);
                return;
            }

            // Strategy 2: single mapping with mprotect toggle / proc_mem
            // Try RWX mmap first (proves kernel allows toggle).
            let mem = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    POOL_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mem != libc::MAP_FAILED {
                let _ = init_hook_engine(mem as *mut u8, std::ptr::null_mut(), POOL_SIZE);
                unsafe { libc::mprotect(mem, POOL_SIZE, libc::PROT_READ | libc::PROT_EXEC); }
                let sfd = connect_patcher_server();
                hide_so(sfd);
                eprintln!("[XiaM-hook] pool: {:?} ({} KB) single-map R-X", mem, POOL_SIZE / 1024);
            } else {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                let mem = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        POOL_SIZE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if mem != libc::MAP_FAILED {
                    let _ = init_hook_engine(mem as *mut u8, std::ptr::null_mut(), POOL_SIZE);
                    unsafe { libc::mprotect(mem, POOL_SIZE, libc::PROT_READ | libc::PROT_EXEC); }
                    let sfd = connect_patcher_server();
                    hide_so(sfd);
                    eprintln!("[XiaM-hook] pool: {:?} ({} KB) single-map R-X (RWX denied, errno={})",
                        mem, POOL_SIZE / 1024, errno);
                } else {
                    eprintln!("[XiaM-hook] pool: mmap failed — hook engine disabled!");
                }
            }
        });
    }

    let mut engine = JS_ENGINE.lock().map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    Ok(())
}

/// Load and execute a JavaScript script using the global engine
pub fn load_script(script: &str) -> Result<(), String> {
    let mut engine = JS_ENGINE.lock().map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    let engine = engine.as_ref().ok_or("JS engine not initialized")?;
    engine.eval(script)?;
    engine.run_pending_jobs();
    Ok(())
}

/// Cleanup the global JS engine
pub fn cleanup_engine() {
    if let Ok(mut engine) = JS_ENGINE.lock() {
        *engine = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        // This test may fail if QuickJS is not built
        // It's mainly for development verification
    }
}
