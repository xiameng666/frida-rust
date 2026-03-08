//! Frida 风格 Interceptor API
//!
//! 用法:
//! ```js
//! Interceptor.attach(ptr("0x1234"), {
//!     onEnter: function(args) {
//!         console.log("arg0 = " + args[0]);
//!     },
//!     onLeave: function(retval) {
//!         console.log("ret = " + retval);
//!     }
//! });
//! Interceptor.detachAll();
//! ```

use crate::context::JSContext;
use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

// hook_engine 错误码
const HOOK_OK: i32 = 0;

/// 存储 Interceptor hook 的回调数据
struct InterceptorHook {
    ctx: usize, // *mut ffi::JSContext as usize
    on_enter_bytes: [u8; 16],
    on_leave_bytes: [u8; 16],
    has_on_enter: bool,
    has_on_leave: bool,
}

unsafe impl Send for InterceptorHook {}
unsafe impl Sync for InterceptorHook {}

/// 全局 Interceptor hook 注册表
static INTERCEPTOR_REGISTRY: Mutex<Option<HashMap<u64, InterceptorHook>>> = Mutex::new(None);

fn init_registry() {
    let mut guard = INTERCEPTOR_REGISTRY.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// on_enter C 回调：构造 args 数组（NativePointer），调用 JS onEnter(args)，回读修改
unsafe extern "C" fn on_enter_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let target_addr = user_data as u64;

    let guard = INTERCEPTOR_REGISTRY.lock().unwrap();
    let registry = match guard.as_ref() {
        Some(r) => r,
        None => return,
    };
    let hook = match registry.get(&target_addr) {
        Some(h) if h.has_on_enter => h,
        _ => return,
    };

    let ctx = hook.ctx as *mut ffi::JSContext;
    let on_enter: ffi::JSValue =
        std::ptr::read(hook.on_enter_bytes.as_ptr() as *const ffi::JSValue);
    let hook_ctx = &*ctx_ptr;

    // 构造 args 数组：args[0..7] = NativePointer(x0..x7)
    let args_array = ffi::JS_NewArray(ctx);
    for i in 0..8u32 {
        let np = create_native_pointer(ctx, hook_ctx.x[i as usize]);
        ffi::JS_SetPropertyUint32(ctx, args_array, i, np.raw());
    }

    // 调用 onEnter(args)
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, on_enter, global, 1, &args_array as *const _ as *mut _);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);

    // 回读 args[0..7]，如果 JS 修改了则写回 HookContext
    for i in 0..8u32 {
        let val = ffi::JS_GetPropertyUint32(ctx, args_array, i);
        let js_val = JSValue(val);
        if let Some(addr) = get_native_pointer_addr(ctx, js_val) {
            (*ctx_ptr).x[i as usize] = addr;
        } else if let Some(n) = js_val.to_u64(ctx) {
            (*ctx_ptr).x[i as usize] = n;
        }
        js_val.free(ctx);
    }

    ffi::qjs_free_value(ctx, args_array);
}

/// on_leave C 回调：构造 retval = NativePointer(x0)，调用 JS onLeave(retval)，回读修改
unsafe extern "C" fn on_leave_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let target_addr = user_data as u64;

    let guard = INTERCEPTOR_REGISTRY.lock().unwrap();
    let registry = match guard.as_ref() {
        Some(r) => r,
        None => return,
    };
    let hook = match registry.get(&target_addr) {
        Some(h) if h.has_on_leave => h,
        _ => return,
    };

    let ctx = hook.ctx as *mut ffi::JSContext;
    let on_leave: ffi::JSValue =
        std::ptr::read(hook.on_leave_bytes.as_ptr() as *const ffi::JSValue);
    let hook_ctx = &*ctx_ptr;

    // retval = NativePointer(x0)
    let retval = create_native_pointer(ctx, hook_ctx.x[0]);

    // 调用 onLeave(retval)
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, on_leave, global, 1, &retval.raw() as *const _ as *mut _);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);

    // 回读 retval —— 如果 JS 通过 retval.replace(newVal) 修改了，NativePointer 的 opaque 会变
    if let Some(addr) = get_native_pointer_addr(ctx, retval) {
        (*ctx_ptr).x[0] = addr;
    }

    retval.free(ctx);
}

/// JS: Interceptor.attach(target, { onEnter, onLeave })
unsafe extern "C" fn js_interceptor_attach(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Interceptor.attach() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let callbacks_arg = JSValue(*argv.add(1));

    // 获取目标地址
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => match ptr_arg.to_u64(ctx) {
            Some(a) => a,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"first argument must be a NativePointer\0".as_ptr() as *const _,
                )
            }
        },
    };

    // 检查第二个参数是对象
    if !callbacks_arg.is_object() {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"second argument must be {onEnter, onLeave}\0".as_ptr() as *const _,
        );
    }

    // 提取 onEnter / onLeave
    let on_enter_val = callbacks_arg.get_property(ctx, "onEnter");
    let on_leave_val = callbacks_arg.get_property(ctx, "onLeave");

    let has_on_enter = on_enter_val.is_function(ctx);
    let has_on_leave = on_leave_val.is_function(ctx);

    if !has_on_enter && !has_on_leave {
        on_enter_val.free(ctx);
        on_leave_val.free(ctx);
        return ffi::JS_ThrowTypeError(
            ctx,
            b"at least one of onEnter/onLeave must be a function\0".as_ptr() as *const _,
        );
    }

    init_registry();

    // dup 回调防止 GC
    let on_enter_dup = if has_on_enter {
        ffi::qjs_dup_value(ctx, on_enter_val.raw())
    } else {
        JSValue::undefined().raw()
    };
    let on_leave_dup = if has_on_leave {
        ffi::qjs_dup_value(ctx, on_leave_val.raw())
    } else {
        JSValue::undefined().raw()
    };

    on_enter_val.free(ctx);
    on_leave_val.free(ctx);

    // 序列化 JSValue 为 bytes
    let mut on_enter_bytes = [0u8; 16];
    let mut on_leave_bytes = [0u8; 16];
    std::ptr::copy_nonoverlapping(
        &on_enter_dup as *const ffi::JSValue as *const u8,
        on_enter_bytes.as_mut_ptr(),
        16,
    );
    std::ptr::copy_nonoverlapping(
        &on_leave_dup as *const ffi::JSValue as *const u8,
        on_leave_bytes.as_mut_ptr(),
        16,
    );

    {
        let mut guard = INTERCEPTOR_REGISTRY.lock().unwrap();
        let registry = guard.as_mut().unwrap();
        registry.insert(
            addr,
            InterceptorHook {
                ctx: ctx as usize,
                on_enter_bytes,
                on_leave_bytes,
                has_on_enter,
                has_on_leave,
            },
        );
    }

    // 安装 hook — HookCallback = Option<unsafe extern "C" fn(...)>
    let c_on_enter: hook_ffi::HookCallback = if has_on_enter {
        Some(on_enter_wrapper as unsafe extern "C" fn(*mut hook_ffi::HookContext, *mut std::ffi::c_void))
    } else {
        None
    };
    let c_on_leave: hook_ffi::HookCallback = if has_on_leave {
        Some(on_leave_wrapper as unsafe extern "C" fn(*mut hook_ffi::HookContext, *mut std::ffi::c_void))
    } else {
        None
    };

    let result = hook_ffi::hook_attach(
        addr as *mut std::ffi::c_void,
        c_on_enter,
        c_on_leave,
        addr as *mut std::ffi::c_void, // user_data = target addr
        0, // 不使用 stealth
    );

    if result != HOOK_OK {
        // 失败清理
        let mut guard = INTERCEPTOR_REGISTRY.lock().unwrap();
        if let Some(registry) = guard.as_mut() {
            if let Some(hook) = registry.remove(&addr) {
                if hook.has_on_enter {
                    let cb: ffi::JSValue =
                        std::ptr::read(hook.on_enter_bytes.as_ptr() as *const ffi::JSValue);
                    ffi::qjs_free_value(ctx, cb);
                }
                if hook.has_on_leave {
                    let cb: ffi::JSValue =
                        std::ptr::read(hook.on_leave_bytes.as_ptr() as *const ffi::JSValue);
                    ffi::qjs_free_value(ctx, cb);
                }
            }
        }
        return ffi::JS_ThrowInternalError(
            ctx,
            b"Interceptor.attach failed\0".as_ptr() as *const _,
        );
    }

    JSValue::undefined().raw()
}

/// JS: Interceptor.detachAll()
unsafe extern "C" fn js_interceptor_detach_all(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    cleanup_interceptor_hooks();
    let _ = ctx;
    JSValue::undefined().raw()
}

/// 清理所有 Interceptor hook（供 hot reload 调用）
pub fn cleanup_interceptor_hooks() {
    let mut guard = INTERCEPTOR_REGISTRY.lock().unwrap();
    if let Some(registry) = guard.take() {
        for (addr, hook) in registry {
            unsafe {
                hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
                let ctx = hook.ctx as *mut ffi::JSContext;
                if hook.has_on_enter {
                    let cb: ffi::JSValue =
                        std::ptr::read(hook.on_enter_bytes.as_ptr() as *const ffi::JSValue);
                    ffi::qjs_free_value(ctx, cb);
                }
                if hook.has_on_leave {
                    let cb: ffi::JSValue =
                        std::ptr::read(hook.on_leave_bytes.as_ptr() as *const ffi::JSValue);
                    ffi::qjs_free_value(ctx, cb);
                }
            }
        }
    }
}

/// 注册 Interceptor 对象
pub fn register_interceptor(ctx: &JSContext) {
    let global = ctx.global_object();
    let interceptor = ctx.new_object();

    unsafe {
        // Interceptor.attach(target, callbacks)
        let cname = CString::new("attach").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_interceptor_attach), cname.as_ptr(), 2);
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), interceptor.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);

        // Interceptor.detachAll()
        let cname = CString::new("detachAll").unwrap();
        let func_val = ffi::qjs_new_cfunction(
            ctx.as_ptr(),
            Some(js_interceptor_detach_all),
            cname.as_ptr(),
            0,
        );
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), interceptor.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);
    }

    global.set_property(ctx.as_ptr(), "Interceptor", interceptor);
    global.free(ctx.as_ptr());
}
