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
pub fn init_hook_engine(exec_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe {
        ffi::hook::hook_engine_init(exec_mem as *mut _, size)
    };

    if result == 0 {
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
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

/// Get or initialize the global JS engine
pub fn get_or_init_engine() -> Result<(), String> {
    // 确保 hook 引擎已初始化（仅 Android）
    #[cfg(target_os = "android")]
    {
        static HOOK_INIT: std::sync::Once = std::sync::Once::new();
        HOOK_INIT.call_once(|| {
            const POOL_SIZE: usize = 1024 * 1024; // 1 MB
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
                let _ = init_hook_engine(mem as *mut u8, POOL_SIZE);
                // Tighten to R-X: hook engine writes to pool via /proc/self/mem
                unsafe {
                    libc::mprotect(
                        mem,
                        POOL_SIZE,
                        libc::PROT_READ | libc::PROT_EXEC,
                    );
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
