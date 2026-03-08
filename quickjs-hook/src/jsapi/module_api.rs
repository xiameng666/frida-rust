//! Frida 风格 Module API
//!
//! ```js
//! var addr = Module.findExportByName("libc.so", "open");
//! var base = Module.getBaseAddress("libc.so");
//! ```

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;
use std::ffi::CString;

// ---------------------------------------------------------------------------
// 平台辅助函数（仅 Linux/Android）
// ---------------------------------------------------------------------------

/// 通过 dlopen(RTLD_NOLOAD) + dlsym 查找导出符号地址
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn find_export_by_name(module_name: Option<&str>, export_name: &str) -> Option<u64> {
    let handle = if let Some(name) = module_name {
        let cname = CString::new(name).ok()?;
        // RTLD_NOLOAD: 不加载新库，仅查找已加载的
        let h = libc::dlopen(cname.as_ptr(), libc::RTLD_NOLOAD | libc::RTLD_NOW);
        if h.is_null() {
            return None;
        }
        h
    } else {
        // RTLD_DEFAULT: 在所有已加载库中搜索
        libc::RTLD_DEFAULT
    };

    let cexport = CString::new(export_name).ok()?;
    let sym = libc::dlsym(handle, cexport.as_ptr());

    // 如果是 dlopen 返回的 handle，需要 dlclose
    if module_name.is_some() && handle != libc::RTLD_DEFAULT {
        libc::dlclose(handle);
    }

    if sym.is_null() {
        None
    } else {
        Some(sym as u64)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
unsafe fn find_export_by_name(_module_name: Option<&str>, _export_name: &str) -> Option<u64> {
    None
}

/// 解析 /proc/self/maps 获取模块基址
#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_base_address(module_name: &str) -> Option<u64> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        // 行格式: 7f1234000-7f1235000 r-xp 00000000 fd:01 12345 /path/to/lib.so
        if line.contains(module_name) {
            let addr_str = line.split('-').next()?;
            return u64::from_str_radix(addr_str.trim(), 16).ok();
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn get_base_address(_module_name: &str) -> Option<u64> {
    None
}

// ---------------------------------------------------------------------------
// JS 绑定
// ---------------------------------------------------------------------------

/// Module.findExportByName(moduleName, exportName)
unsafe extern "C" fn js_find_export_by_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findExportByName() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let module_arg = JSValue(*argv);
    let export_arg = JSValue(*argv.add(1));

    // moduleName 可以是 null（搜索所有已加载模块）
    let module_name = if module_arg.is_null() || module_arg.is_undefined() {
        None
    } else {
        module_arg.to_string(ctx)
    };

    let export_name = match export_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"exportName must be a string\0".as_ptr() as *const _,
            )
        }
    };

    match find_export_by_name(module_name.as_deref(), &export_name) {
        Some(addr) => create_native_pointer(ctx, addr).raw(),
        None => JSValue::null().raw(),
    }
}

/// Module.getBaseAddress(moduleName)
unsafe extern "C" fn js_get_base_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.getBaseAddress() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let name_arg = JSValue(*argv);
    let module_name = match name_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"moduleName must be a string\0".as_ptr() as *const _,
            )
        }
    };

    match get_base_address(&module_name) {
        Some(addr) => create_native_pointer(ctx, addr).raw(),
        None => JSValue::null().raw(),
    }
}

/// 注册 Module 对象（扩展已有的 Memory 对象之外的独立对象）
pub fn register_module_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let module_obj = ctx.new_object();

    unsafe {
        let cname = CString::new("findExportByName").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_find_export_by_name), cname.as_ptr(), 2);
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), module_obj.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);

        let cname = CString::new("getBaseAddress").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_get_base_address), cname.as_ptr(), 1);
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), module_obj.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);
    }

    global.set_property(ctx.as_ptr(), "Module", module_obj);
    global.free(ctx.as_ptr());
}
