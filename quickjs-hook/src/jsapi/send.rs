//! Frida 风格 send() API
//!
//! ```js
//! send({type: "ready", payload: "hooked"});
//! send("simple string message");
//! ```

use crate::context::JSContext;
use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;
use std::sync::Mutex;

/// send() 实时回调类型
pub type SendCallback = Box<dyn Fn(&str) + Send + 'static>;

/// 全局消息缓冲区
static SEND_BUFFER: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 全局 send 回调（实时推送）
static SEND_CALLBACK: Mutex<Option<SendCallback>> = Mutex::new(None);

/// 设置 send() 实时回调
pub fn set_send_callback<F>(callback: F)
where
    F: Fn(&str) + Send + 'static,
{
    let mut guard = SEND_CALLBACK.lock().unwrap();
    *guard = Some(Box::new(callback));
}

/// 提取并清空消息缓冲区（供 agent 在 loadjs/reloadjs 后调用）
pub fn drain_send_messages() -> Vec<String> {
    match SEND_BUFFER.lock() {
        Ok(mut buf) => std::mem::take(&mut *buf),
        Err(_) => Vec::new(),
    }
}

/// JS: send(message) — 将 message JSON 序列化后推入缓冲区
unsafe extern "C" fn js_send(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"send() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let arg = JSValue(*argv);

    // 使用 JSON.stringify 序列化
    let global = ffi::JS_GetGlobalObject(ctx);
    let json_obj = JSValue(global).get_property(ctx, "JSON");
    let stringify = json_obj.get_property(ctx, "stringify");

    let json_str = if stringify.is_function(ctx) {
        let result = ffi::JS_Call(ctx, stringify.raw(), json_obj.raw(), 1, argv);
        let result_val = JSValue(result);
        let s = result_val.to_string(ctx).unwrap_or_else(|| "null".to_string());
        result_val.free(ctx);
        s
    } else {
        // 降级：直接 toString
        arg.to_string(ctx).unwrap_or_else(|| "null".to_string())
    };

    stringify.free(ctx);
    json_obj.free(ctx);
    ffi::qjs_free_value(ctx, global);

    if let Ok(mut buf) = SEND_BUFFER.lock() {
        buf.push(json_str.clone());
    }

    // 实时回调
    if let Ok(guard) = SEND_CALLBACK.lock() {
        if let Some(callback) = guard.as_ref() {
            callback(&json_str);
        }
    }

    JSValue::undefined().raw()
}

/// 注册 send() 全局函数
pub fn register_send(ctx: &JSContext) {
    let cname = CString::new("send").unwrap();
    unsafe {
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_send), cname.as_ptr(), 1);
        let global = ctx.global_object();
        global.set_property(ctx.as_ptr(), "send", JSValue(func_val));
        global.free(ctx.as_ptr());
    }
}
