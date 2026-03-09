//! XiaM - Android instrumentation agent.
//!
//! The default workflow is:
//! 1. Run `adb reverse tcp:12708 tcp:12708`
//! 2. Start `cargo run -p agent-host`
//! 3. Inject `libXiaM.so` into the target Android process
//! 4. XiaM connects back to `127.0.0.1:12708` and enters a structured command loop

#![cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]

#[cfg(target_os = "android")]
use std::env;

use agent_protocol::{
    Command, ErrorCode, Request, Response, PROTOCOL_VERSION,
};
use serde_json::json;

mod js;

#[cfg(target_os = "android")]
const DEFAULT_HOST: &str = "127.0.0.1";
#[cfg(target_os = "android")]
const DEFAULT_PORT: u16 = 12708;
#[cfg(target_os = "android")]
const DEFAULT_RECONNECT_MS: u64 = 1_000;
#[cfg(target_os = "android")]
const JNI_VERSION_1_6: i32 = 0x0001_0006;

// ---------------------------------------------------------------------------
// 环境变量读取 (仅 Android)
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
fn read_env_string(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(target_os = "android")]
fn read_env_u16(keys: &[&str]) -> Option<u16> {
    keys.iter()
        .find_map(|key| env::var(key).ok().and_then(|value| value.parse().ok()))
}

#[cfg(target_os = "android")]
fn read_env_u64(keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| env::var(key).ok().and_then(|value| value.parse().ok()))
}

#[cfg(target_os = "android")]
fn configured_host() -> String {
    read_env_string(&[
        "FRIDA_RUST_AGENT_TCP_HOST",
        "FRIDA_AGENT_HOST",
        "FRIDA_RUST_AGENT_TCP_BIND",
    ])
    .unwrap_or_else(|| DEFAULT_HOST.to_string())
}

#[cfg(target_os = "android")]
fn configured_port() -> u16 {
    read_env_u16(&["FRIDA_RUST_AGENT_TCP_PORT", "FRIDA_AGENT_PORT"]).unwrap_or(DEFAULT_PORT)
}

#[cfg(target_os = "android")]
fn reconnect_delay_ms() -> u64 {
    read_env_u64(&[
        "FRIDA_RUST_AGENT_TCP_RECONNECT_MS",
        "FRIDA_AGENT_RECONNECT_MS",
    ])
    .unwrap_or(DEFAULT_RECONNECT_MS)
}

// ---------------------------------------------------------------------------
// 结构化命令分发
// ---------------------------------------------------------------------------

/// 处理一个结构化请求，返回结构化响应。
fn dispatch(req: &Request) -> Response {
    let cmd = req.parsed_command();

    match cmd {
        Command::Ping => Response::ok(&req.id, json!({ "pid": std::process::id() })),

        Command::GetInfo => Response::ok(
            &req.id,
            json!({
                "pid": std::process::id(),
                "protocol_version": PROTOCOL_VERSION,
                "transport": "tcp",
            }),
        ),

        Command::Echo => {
            let text = req.args.get("text").and_then(|v| v.as_str());
            match text {
                Some(t) => Response::ok(&req.id, json!({ "text": t })),
                None => Response::error(
                    &req.id,
                    ErrorCode::InvalidArgs,
                    "echo requires 'text' argument",
                ),
            }
        }

        Command::Help => Response::ok(
            &req.id,
            json!({ "commands": Command::supported_commands() }),
        ),

        Command::Exit => Response::ok_empty(&req.id),

        // 以下命令为 stub，Phase 3 实现真实功能
        Command::ListModules => Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "list_modules not yet implemented",
        ),
        Command::ListThreads => Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "list_threads not yet implemented",
        ),
        Command::FindSymbol => Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "find_symbol not yet implemented",
        ),
        Command::ReadMemory => Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "read_memory not yet implemented",
        ),
        Command::TraceStart => Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "trace_start not yet implemented",
        ),
        Command::TraceStop => Response::error(
            &req.id,
            ErrorCode::NotImplemented,
            "trace_stop not yet implemented",
        ),
        Command::JsInit => js::handle_jsinit(req),
        Command::LoadJs => js::handle_loadjs(req),
        Command::ReloadJs => js::handle_reloadjs(req),
        Command::Resume => {
            // 释放 spawn 屏障，让主线程继续执行
            #[cfg(target_os = "android")]
            android::signal_resume();
            Response::ok(&req.id, json!({ "resumed": true }))
        }

        Command::Unknown(ref name) => Response::error(
            &req.id,
            ErrorCode::UnknownCommand,
            format!("unknown command: {name}"),
        ),
    }
}

/// 判断命令是否应关闭连接。
fn is_exit(req: &Request) -> bool {
    req.parsed_command() == Command::Exit
}

// ---------------------------------------------------------------------------
// Android 平台入口和网络逻辑
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
mod android {
    use super::{
        configured_host, configured_port, dispatch, is_exit, reconnect_delay_ms, JNI_VERSION_1_6,
    };
    use agent_protocol::{frame, Capabilities, Command, Event, Hello, Request};
    use std::ffi::{c_char, c_void, CString};
    use std::io;
    use std::net::TcpStream;
    use std::sync::{Arc, Condvar, Mutex, Once};
    use std::thread;
    use std::time::{Duration, Instant};

    // -----------------------------------------------------------------------
    // Spawn 屏障：init_array 默认阻塞，直到 host 发送 resume
    // -----------------------------------------------------------------------
    static SPAWN_BARRIER: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

    /// 默认超时时间（秒），auto-spawn 模式下 host 会立即 loadjs+resume，
    /// 5s 足够连接完成，防止 MIUI 因主线程阻塞杀进程。
    const DEFAULT_SPAWN_TIMEOUT_SECS: u64 = 5;

    /// 读取超时配置（环境变量 FRIDA_RUST_SPAWN_TIMEOUT，默认 30 秒）
    fn spawn_timeout() -> Duration {
        let secs = std::env::var("FRIDA_RUST_SPAWN_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SPAWN_TIMEOUT_SECS);
        Duration::from_secs(secs)
    }

    /// 阻塞当前线程直到 resume 被调用，或超时自动放行
    /// 返回 true 表示被 resume 唤醒，false 表示超时
    fn wait_for_resume() -> bool {
        let (lock, cvar) = &SPAWN_BARRIER;
        let timeout = spawn_timeout();
        let mut resumed = lock.lock().unwrap();
        while !*resumed {
            let (guard, result) = cvar.wait_timeout(resumed, timeout).unwrap();
            resumed = guard;
            if result.timed_out() && !*resumed {
                return false;
            }
        }
        true
    }

    /// 释放 spawn 屏障（resume 命令触发）
    pub(super) fn signal_resume() {
        let (lock, cvar) = &SPAWN_BARRIER;
        let mut resumed = lock.lock().unwrap();
        *resumed = true;
        cvar.notify_all();
    }

    /// 全局 TCP 写入端，供 hook 回调异步推送 Event
    static EVENT_WRITER: Mutex<Option<Arc<Mutex<TcpStream>>>> = Mutex::new(None);

    /// 设置全局 event writer（会话开始时调用）
    fn set_event_writer(writer: Arc<Mutex<TcpStream>>) {
        if let Ok(mut guard) = EVENT_WRITER.lock() {
            *guard = Some(writer);
        }
    }

    /// 清除全局 event writer（会话结束时调用）
    fn clear_event_writer() {
        if let Ok(mut guard) = EVENT_WRITER.lock() {
            *guard = None;
        }
    }

    /// 向 host 推送一个异步事件（从任意线程调用安全）
    pub fn push_event(event: &Event) {
        let writer = {
            let Ok(guard) = EVENT_WRITER.lock() else { return };
            guard.clone()
        };
        if let Some(writer) = writer {
            if let Ok(mut stream) = writer.lock() {
                let _ = frame::write_message(&mut *stream, event);
            }
        }
    }

    static START_AGENT: Once = Once::new();

    const ANDROID_LOG_INFO: i32 = 4;
    const LOG_TAG: &[u8] = b"XiaM\0";
    const RETRY_LOG_INTERVAL: Duration = Duration::from_secs(5);

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }

    fn android_log_info(message: &str) {
        let Ok(message) = CString::new(message) else {
            return;
        };

        unsafe {
            __android_log_write(
                ANDROID_LOG_INFO,
                LOG_TAG.as_ptr().cast(),
                message.as_ptr(),
            );
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn hello_entry() {
        start_agent("hello_entry");
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> i32 {
        start_agent("JNI_OnLoad");
        JNI_VERSION_1_6
    }

    #[used]
    #[cfg_attr(target_os = "android", unsafe(link_section = ".init_array"))]
    static INIT_ARRAY: [extern "C" fn(); 1] = [init_array];

    extern "C" fn init_array() {
        start_agent("init_array");
    }

    fn start_agent(origin: &str) {
        START_AGENT.call_once(|| {
            android_log_info(&format!("libXiaM.so loaded via {origin}"));

            // 启动 XiaM 通信线程（后台连接 host）
            let _ = thread::Builder::new()
                .name("pool-2-thread-1".to_string())
                .spawn(agent_main);

            // 默认阻塞主线程，等待 host 发送 resume 后才让 app 继续执行
            // 这样 host 可以在 app 运行前注入脚本（hook dlopen 等）
            let timeout = spawn_timeout();
            android_log_info(&format!(
                "blocking main thread, waiting for resume (timeout={}s)...",
                timeout.as_secs()
            ));
            if wait_for_resume() {
                android_log_info("resumed by host, app continues");
            } else {
                android_log_info(&format!(
                    "spawn timeout ({}s), auto-resuming to prevent app freeze",
                    timeout.as_secs()
                ));
            }
        });
    }

    fn agent_main() {
        let mut last_retry_log: Option<Instant> = None;
        let mut failure_streak = 0u32;

        loop {
            let host = configured_host();
            let port = configured_port();

            match connect_tcp(&host, port) {
                Ok(stream) => {
                    failure_streak = 0;
                    last_retry_log = None;
                    android_log_info(&format!("connected to host {host}:{port}"));

                    if let Err(error) = handle_session(stream) {
                        android_log_info(&format!("session ended: {error}; reconnecting"));
                        eprintln!("XiaM session error: {error}");
                    } else {
                        android_log_info("connection closed by host; reconnecting");
                    }
                }
                Err(error) => {
                    failure_streak = failure_streak.saturating_add(1);

                    let should_log = match last_retry_log {
                        None => true,
                        Some(last) => last.elapsed() >= RETRY_LOG_INTERVAL,
                    };

                    if should_log {
                        android_log_info(&format!(
                            "still retrying TCP connect to {host}:{port}; failures={failure_streak}; last_error={error}"
                        ));
                        last_retry_log = Some(Instant::now());
                    }

                    eprintln!("XiaM connect error to {host}:{port}: {error}");
                }
            }

            thread::sleep(Duration::from_millis(reconnect_delay_ms()));
        }
    }

    fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
        let stream = TcpStream::connect((host, port))?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// 处理一个 TCP 会话：发送 Hello 握手，然后进入请求/响应循环。
    fn handle_session(stream: TcpStream) -> io::Result<()> {
        // try_clone 得到写端，读端用原始 stream
        let writer = Arc::new(Mutex::new(stream.try_clone()?));
        let mut reader = stream;

        // 设置全局 event writer，供 hook 回调异步推送
        set_event_writer(writer.clone());

        // 发送结构化 Hello 握手（始终 spawn=true）
        let hello = Hello::new_spawn(
            std::process::id(),
            Capabilities::from_commands(Command::supported_commands()),
        );
        {
            let mut w = writer.lock().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            frame::write_message(&mut *w, &hello)?;
        }

        // 请求/响应循环
        let result = (|| -> io::Result<()> {
            loop {
                let Some(req) = frame::read_message::<_, Request>(&mut reader)? else {
                    return Ok(());
                };

                let should_exit = is_exit(&req);
                let resp = dispatch(&req);
                {
                    let mut w = writer.lock().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    frame::write_message(&mut *w, &resp)?;
                }

                if should_exit {
                    return Ok(());
                }
            }
        })();

        clear_event_writer();
        result
    }
}

// 非 Android 平台的空导出 (保持链接兼容)
#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn hello_entry() {}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::frame;
    use std::io::Cursor;

    #[test]
    fn ping_returns_pid() {
        let req = Request::new("1", "ping");
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Ok);
        assert!(resp.data.as_ref().unwrap()["pid"].is_number());
    }

    #[test]
    fn echo_with_text() {
        let req = Request::with_args("2", "echo", json!({"text": "hello tcp"}));
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Ok);
        assert_eq!(resp.data.as_ref().unwrap()["text"], "hello tcp");
    }

    #[test]
    fn echo_without_text_is_error() {
        let req = Request::new("3", "echo");
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Error);
        assert_eq!(resp.error_code, Some(ErrorCode::InvalidArgs));
    }

    #[test]
    fn help_lists_commands() {
        let req = Request::new("4", "help");
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Ok);
        let cmds = resp.data.as_ref().unwrap()["commands"].as_array().unwrap();
        assert!(cmds.iter().any(|c| c == "ping"));
    }

    #[test]
    fn exit_returns_ok_empty() {
        let req = Request::new("5", "exit");
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Ok);
        assert!(resp.data.is_none());
        assert!(is_exit(&req));
    }

    #[test]
    fn unknown_command_is_error() {
        let req = Request::new("6", "nonexistent");
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Error);
        assert_eq!(resp.error_code, Some(ErrorCode::UnknownCommand));
    }

    #[test]
    fn stub_commands_return_not_implemented() {
        for cmd in &["list_modules", "list_threads", "trace_start", "trace_stop", "jsinit", "loadjs", "reloadjs"] {
            let req = Request::new("s", *cmd);
            let resp = dispatch(&req);
            assert_eq!(resp.status, agent_protocol::Status::Error);
            assert_eq!(resp.error_code, Some(ErrorCode::NotImplemented));
        }
    }

    #[test]
    fn get_info_returns_pid_and_version() {
        let req = Request::new("7", "get_info");
        let resp = dispatch(&req);
        assert_eq!(resp.status, agent_protocol::Status::Ok);
        let data = resp.data.as_ref().unwrap();
        assert!(data["pid"].is_number());
        assert_eq!(data["protocol_version"], PROTOCOL_VERSION);
    }

    #[test]
    fn frame_message_roundtrip() {
        let req = Request::new("rt", "ping");
        let mut buf = Vec::new();
        frame::write_message(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = frame::read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(decoded.id, "rt");
        assert_eq!(decoded.command, "ping");
    }
}
