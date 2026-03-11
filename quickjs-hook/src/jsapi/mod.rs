//! JavaScript API implementations

pub mod console;
pub mod hook_api;
pub mod interceptor;
pub mod memory;
pub mod module_api;
pub mod process;
pub mod ptr;
pub mod send;
pub mod wxshadow;

pub use console::register_console;
pub use hook_api::register_hook_api;
pub use interceptor::register_interceptor;
pub use memory::register_memory_api;
pub use module_api::register_module_api;
pub use process::register_process;
pub use ptr::register_ptr;
pub use send::register_send;
pub use wxshadow::register_wxshadow;

use crate::context::JSContext;

/// 注册所有 JavaScript API
pub fn register_all_apis(ctx: &JSContext) {
    register_console(ctx);
    register_ptr(ctx);
    register_hook_api(ctx);
    register_memory_api(ctx);
    register_interceptor(ctx);
    register_module_api(ctx);
    register_process(ctx);
    register_send(ctx);
    register_wxshadow(ctx);
}
