//! Frida 风格 Process API
//!
//! ```js
//! var mods = Process.enumerateModules();
//! console.log("pid=" + Process.id + " arch=" + Process.arch);
//! ```

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::value::JSValue;
use std::ffi::CString;

// ---------------------------------------------------------------------------
// /proc/self/maps 解析
// ---------------------------------------------------------------------------

struct ModuleInfo {
    name: String,
    path: String,
    base: u64,
    end: u64,
}

/// 解析 /proc/self/maps，合并同路径连续区域
#[cfg(any(target_os = "linux", target_os = "android"))]
fn enumerate_modules() -> Vec<ModuleInfo> {
    let maps = match std::fs::read_to_string("/proc/self/maps") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut modules: Vec<ModuleInfo> = Vec::new();

    for line in maps.lines() {
        // 格式: 7f1234000-7f1235000 r-xp 00000000 fd:01 12345 /path/to/lib.so
        let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if parts.len() < 6 {
            continue;
        }
        let path = parts[5].trim();
        if path.is_empty() || path.starts_with('[') {
            continue; // 跳过 [stack], [heap], [vdso] 等
        }

        let addr_range = parts[0];
        let mut range_parts = addr_range.split('-');
        let start = match range_parts
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        {
            Some(v) => v,
            None => continue,
        };
        let end = match range_parts
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        {
            Some(v) => v,
            None => continue,
        };

        // 提取文件名
        let name = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_string();

        // 合并同路径模块
        if let Some(last) = modules.last_mut() {
            if last.path == path {
                if end > last.end {
                    last.end = end;
                }
                continue;
            }
        }

        modules.push(ModuleInfo {
            name,
            path: path.to_string(),
            base: start,
            end,
        });
    }

    modules
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn enumerate_modules() -> Vec<ModuleInfo> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// JS 绑定
// ---------------------------------------------------------------------------

/// Process.enumerateModules() -> [{name, base, size, path}, ...]
unsafe extern "C" fn js_enumerate_modules(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let modules = enumerate_modules();
    let arr = ffi::JS_NewArray(ctx);

    for (i, m) in modules.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);

        // name
        let name_val = JSValue::string(ctx, &m.name);
        let cname = CString::new("name").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
        ffi::qjs_set_property(ctx, obj, atom, name_val.raw());
        ffi::JS_FreeAtom(ctx, atom);

        // base (NativePointer)
        let base_val = create_native_pointer(ctx, m.base);
        let cname = CString::new("base").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
        ffi::qjs_set_property(ctx, obj, atom, base_val.raw());
        ffi::JS_FreeAtom(ctx, atom);

        // size
        let size_val = ffi::JS_NewBigUint64(ctx, m.end - m.base);
        let cname = CString::new("size").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
        ffi::qjs_set_property(ctx, obj, atom, size_val);
        ffi::JS_FreeAtom(ctx, atom);

        // path
        let path_val = JSValue::string(ctx, &m.path);
        let cname = CString::new("path").unwrap();
        let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
        ffi::qjs_set_property(ctx, obj, atom, path_val.raw());
        ffi::JS_FreeAtom(ctx, atom);

        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, obj);
    }

    arr
}

/// Process.id getter
unsafe extern "C" fn js_process_id(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let pid = std::process::id();
    JSValue::int(pid as i32).raw()
}

/// Process.arch getter
unsafe extern "C" fn js_process_arch(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    #[cfg(target_arch = "aarch64")]
    let arch = "arm64";
    #[cfg(target_arch = "x86_64")]
    let arch = "x64";
    #[cfg(target_arch = "x86")]
    let arch = "ia32";
    #[cfg(target_arch = "arm")]
    let arch = "arm";
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "arm"
    )))]
    let arch = "unknown";

    JSValue::string(ctx, arch).raw()
}

/// 注册 Process 对象
pub fn register_process(ctx: &JSContext) {
    let global = ctx.global_object();
    let process = ctx.new_object();

    unsafe {
        // Process.enumerateModules()
        let cname = CString::new("enumerateModules").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_enumerate_modules), cname.as_ptr(), 0);
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), process.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);

        // Process.getId() — 用函数模拟属性
        let cname = CString::new("getId").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_process_id), cname.as_ptr(), 0);
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), process.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);

        // Process.getArch()
        let cname = CString::new("getArch").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_process_arch), cname.as_ptr(), 0);
        let atom = ffi::JS_NewAtom(ctx.as_ptr(), cname.as_ptr());
        ffi::qjs_set_property(ctx.as_ptr(), process.raw(), atom, func_val);
        ffi::JS_FreeAtom(ctx.as_ptr(), atom);

        // 直接设置 Process.id 和 Process.arch 为常量值（兼容 Frida 风格的属性访问）
        let pid_val = JSValue::int(std::process::id() as i32);
        process.set_property(ctx.as_ptr(), "id", pid_val);

        #[cfg(target_arch = "aarch64")]
        let arch_str = "arm64";
        #[cfg(not(target_arch = "aarch64"))]
        let arch_str = "unknown";
        let arch_val = JSValue::string(ctx.as_ptr(), arch_str);
        process.set_property(ctx.as_ptr(), "arch", arch_val);
    }

    global.set_property(ctx.as_ptr(), "Process", process);
    global.free(ctx.as_ptr());
}
