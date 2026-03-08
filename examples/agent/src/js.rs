//! JS 引擎集成模块
//!
//! 在 Android 平台上通过 quickjs-hook 提供 JS 脚本执行能力，
//! 在其他平台上返回 NotImplemented（保持测试兼容）。

use agent_protocol::{ErrorCode, Request, Response};
#[cfg(target_os = "android")]
use serde_json::json;

// ---------------------------------------------------------------------------
// Android 实现：使用 quickjs-hook
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod inner {
    use super::*;
    use std::sync::Mutex;

    /// console 输出缓冲区
    static CONSOLE_OUTPUT: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// 设置 console 回调，将 JS 的 console.log / warn / error 输出捕获到缓冲区
    fn setup_console_callback() {
        quickjs_hook::set_console_callback(|msg: &str| {
            if let Ok(mut buf) = CONSOLE_OUTPUT.lock() {
                buf.push(msg.to_string());
            }
        });
    }

    /// 提取并清空 console 输出缓冲区
    fn drain_console_output() -> Vec<String> {
        match CONSOLE_OUTPUT.lock() {
            Ok(mut buf) => std::mem::take(&mut *buf),
            Err(_) => Vec::new(),
        }
    }

    /// 处理 jsinit 命令：初始化 QuickJS 引擎
    pub fn handle_jsinit(req: &Request) -> Response {
        // 先设置 console 回调，确保引擎初始化后日志可捕获
        setup_console_callback();

        match quickjs_hook::get_or_init_engine() {
            Ok(()) => Response::ok(
                &req.id,
                json!({
                    "engine": "quickjs",
                    "status": "initialized",
                }),
            ),
            Err(e) => Response::error(
                &req.id,
                ErrorCode::Internal,
                format!("JS 引擎初始化失败: {}", e),
            ),
        }
    }

    /// 处理 loadjs 命令：执行 JS 脚本，返回 console 输出和 send() 消息
    pub fn handle_loadjs(req: &Request) -> Response {
        let script = match req.args.get("script").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Response::error(
                    &req.id,
                    ErrorCode::InvalidArgs,
                    "loadjs 需要 'script' 参数",
                );
            }
        };

        // 清空之前的缓冲
        drain_console_output();
        quickjs_hook::drain_send_messages();

        match quickjs_hook::load_script(script) {
            Ok(()) => {
                let output = drain_console_output();
                let messages = quickjs_hook::drain_send_messages();
                Response::ok(&req.id, json!({
                    "output": output,
                    "messages": messages,
                }))
            }
            Err(e) => {
                let output = drain_console_output();
                let messages = quickjs_hook::drain_send_messages();
                let mut msg = format!("JS 执行错误: {}", e);
                if !output.is_empty() {
                    msg.push_str(&format!("\nconsole 输出:\n{}", output.join("\n")));
                }
                if !messages.is_empty() {
                    msg.push_str(&format!("\nsend 消息:\n{}", messages.join("\n")));
                }
                Response::error(&req.id, ErrorCode::Internal, msg)
            }
        }
    }

    /// 处理 reloadjs 命令：清理所有 hook → 重建引擎 → 加载新脚本
    pub fn handle_reloadjs(req: &Request) -> Response {
        let script = match req.args.get("script").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return Response::error(
                    &req.id,
                    ErrorCode::InvalidArgs,
                    "reloadjs 需要 'script' 参数",
                );
            }
        };

        // 清理旧引擎和所有 hook
        quickjs_hook::cleanup_engine();

        // 重新初始化
        setup_console_callback();
        if let Err(e) = quickjs_hook::get_or_init_engine() {
            return Response::error(
                &req.id,
                ErrorCode::Internal,
                format!("热加载失败 - 引擎重建错误: {}", e),
            );
        }

        // 加载新脚本
        drain_console_output();
        quickjs_hook::drain_send_messages();

        match quickjs_hook::load_script(script) {
            Ok(()) => {
                let output = drain_console_output();
                let messages = quickjs_hook::drain_send_messages();
                Response::ok(&req.id, json!({
                    "reloaded": true,
                    "output": output,
                    "messages": messages,
                }))
            }
            Err(e) => {
                let output = drain_console_output();
                let mut msg = format!("热加载失败 - JS 执行错误: {}", e);
                if !output.is_empty() {
                    msg.push_str(&format!("\nconsole 输出:\n{}", output.join("\n")));
                }
                Response::error(&req.id, ErrorCode::Internal, msg)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 非 Android 平台 stub
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "android"))]
mod inner {
    use super::*;

    pub fn handle_jsinit(req: &Request) -> Response {
        Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "jsinit not yet implemented",
        )
    }

    pub fn handle_loadjs(req: &Request) -> Response {
        Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "loadjs not yet implemented",
        )
    }

    pub fn handle_reloadjs(req: &Request) -> Response {
        Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "reloadjs not yet implemented",
        )
    }
}

pub use inner::{handle_jsinit, handle_loadjs, handle_reloadjs};
