//! WxShadow JS API — 内核级隐藏断点
//!
//! 通过 prctl 调用 wxshadow KPM 模块，在目标地址设置 BRK #7 断点。
//! 断点对 CRC32 校验完全不可见（W^X 影子页机制）。
//!
//! JS 用法:
//! ```js
//! // 观测断点 — 命中时在 logcat 打印寄存器
//! WxShadow.brk(ptr("0x7abc1234"));
//!
//! // 断点 + 修改寄存器（每次命中自动应用）
//! WxShadow.brk(ptr("0x7abc1234"), { x0: 1, x1: ptr("0xdead") });
//!
//! // 删除断点
//! WxShadow.unbrk(ptr("0x7abc1234"));
//!
//! // 实战: hook android_dlopen_ext（对CRC校验不可见）
//! var dlopen = Module.findExportByName("libdl.so", "android_dlopen_ext");
//! WxShadow.brk(dlopen);  // logcat 会打印 x0(SO路径) x1(caller)
//! ```

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::value::JSValue;
use std::ffi::CString;

/// wxshadow prctl option codes
const WX_SET_BP: libc::c_int = 0x57585801;
const WX_SET_REG: libc::c_int = 0x57585802;
const WX_DEL_BP: libc::c_int = 0x57585803;

/// JS: WxShadow.brk(addr)
/// JS: WxShadow.brk(addr, { x0: val, x1: val, ... })
///
/// Sets a wxshadow BRK #7 breakpoint at the given address.
/// pid=0 means current process (agent runs inside target).
unsafe extern "C" fn js_wx_brk(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"WxShadow.brk() requires at least 1 argument\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);

    // 获取地址
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => match ptr_arg.to_u64(ctx) {
            Some(a) => a,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"WxShadow.brk() first argument must be a pointer\0".as_ptr() as *const _,
                )
            }
        },
    };

    // 设置断点 (pid=0 = 当前进程)
    let ret = libc::prctl(WX_SET_BP, 0usize, addr as usize, 0usize, 0usize);
    if ret < 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"WxShadow.brk() SET_BP failed (is wxshadow KPM loaded?)\0".as_ptr() as *const _,
        );
    }

    // 如果第二个参数是对象 { x0: val, x1: val, ... }，设置寄存器修改
    if argc >= 2 {
        let mods_arg = JSValue(*argv.add(1));
        if mods_arg.is_object() {
            // 遍历 x0-x30, sp
            for reg in 0..=31u8 {
                let prop_name = if reg <= 30 {
                    format!("x{}", reg)
                } else {
                    "sp".to_string()
                };

                let val = mods_arg.get_property(ctx, &prop_name);
                if !val.is_undefined() {
                    if let Some(v) = val.to_u64(ctx) {
                        let ret = libc::prctl(
                            WX_SET_REG,
                            0usize,
                            addr as usize,
                            reg as usize,
                            v as usize,
                        );
                        if ret < 0 {
                            val.free(ctx);
                            let msg = format!("WxShadow.brk() SET_REG x{}=0x{:x} failed\0", reg, v);
                            return ffi::JS_ThrowInternalError(
                                ctx,
                                msg.as_ptr() as *const _,
                            );
                        }
                    } else if let Some(np_addr) = get_native_pointer_addr(ctx, val) {
                        // 支持 NativePointer 作为值: { x0: ptr("0x1234") }
                        let ret = libc::prctl(
                            WX_SET_REG,
                            0usize,
                            addr as usize,
                            reg as usize,
                            np_addr as usize,
                        );
                        if ret < 0 {
                            val.free(ctx);
                            return ffi::JS_ThrowInternalError(
                                ctx,
                                b"WxShadow.brk() SET_REG failed\0".as_ptr() as *const _,
                            );
                        }
                    }
                }
                val.free(ctx);
            }
        }
    }

    JSValue::bool(true).raw()
}

/// JS: WxShadow.unbrk(addr)
///
/// Removes a wxshadow breakpoint.
unsafe extern "C" fn js_wx_unbrk(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"WxShadow.unbrk() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let addr = match get_native_pointer_addr(ctx, ptr_arg) {
        Some(a) => a,
        None => match ptr_arg.to_u64(ctx) {
            Some(a) => a,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"WxShadow.unbrk() argument must be a pointer\0".as_ptr() as *const _,
                )
            }
        },
    };

    let ret = libc::prctl(WX_DEL_BP, 0usize, addr as usize, 0usize, 0usize);
    if ret < 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"WxShadow.unbrk() DEL_BP failed\0".as_ptr() as *const _,
        );
    }

    JSValue::bool(true).raw()
}

/// Register the WxShadow API on the global object.
pub fn register_wxshadow(ctx: &JSContext) {
    let global = ctx.global_object();
    let wx_obj = ctx.new_object();

    unsafe {
        // WxShadow.brk(addr, mods?)
        let cname = CString::new("brk").unwrap();
        let func = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_wx_brk), cname.as_ptr(), 2);
        wx_obj.set_property(ctx.as_ptr(), "brk", JSValue(func));

        // WxShadow.unbrk(addr)
        let cname = CString::new("unbrk").unwrap();
        let func = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_wx_unbrk), cname.as_ptr(), 1);
        wx_obj.set_property(ctx.as_ptr(), "unbrk", JSValue(func));
    }

    global.set_property(ctx.as_ptr(), "WxShadow", wx_obj);
    global.free(ctx.as_ptr());
}
