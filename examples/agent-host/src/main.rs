//! XiaM Host - communicates with the injected XiaM agent over TCP.
//!
//! The intended setup for USB-attached devices is:
//! `adb reverse tcp:12708 tcp:12708`

use std::env;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use agent_protocol::{
    frame, Event, Hello, HostMode, Request, Response, Status,
};
use serde_json::{json, Value};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 12708;

/// 全局请求 ID 计数器。
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> String {
    REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

#[derive(Debug, Clone)]
struct Config {
    host: String,
    port: u16,
    mode: HostMode,
    /// Spawn 模式：连接后自动发送 jsinit + loadjs + resume，再进入 REPL
    spawn_script: Option<String>,
}

fn main() {
    let program = env::args()
        .next()
        .unwrap_or_else(|| "XiaM-host".to_string());

    if env::args()
        .skip(1)
        .any(|arg| arg == "-h" || arg == "--help")
    {
        print_usage(&program);
        return;
    }

    let config = match parse_args(env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}\n");
            print_usage(&program);
            std::process::exit(2);
        }
    };

    if let Err(error) = run(config) {
        eprintln!("XiaM-host error: {error}");
        std::process::exit(1);
    }
}

fn run(config: Config) -> io::Result<()> {
    // MCP 模式预留，暂不实现
    if config.mode == HostMode::Mcp {
        eprintln!("[!] MCP mode is reserved but not yet implemented.");
        eprintln!("[!] Use --mode cli (default) for now.");
        std::process::exit(1);
    }

    println!("[*] XiaM Host v0.2.0");
    println!("[*] Mode: {}", match &config.mode {
        HostMode::Cli => "CLI (interactive REPL)",
        HostMode::Once(_) => "one-shot",
        HostMode::Mcp => unreachable!(),
    });
    println!("[*] Listening on {}:{}", config.host, config.port);
    println!(
        "[*] For USB debugging, run: adb reverse tcp:{0} tcp:{0}",
        config.port
    );

    let listener = TcpListener::bind((config.host.as_str(), config.port))?;
    let (mut stream, addr) = listener.accept()?;
    stream.set_nodelay(true)?;

    println!("[+] XiaM connected from {addr}");

    // 读取 Hello 握手
    let hello: Hello = frame::read_message(&mut stream)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "XiaM disconnected before hello")
    })?;

    println!("[+] XiaM hello: pid={}, version={}, transport={}", hello.pid, hello.version, hello.transport);
    println!("[+] Capabilities: {:?}", hello.capabilities.commands);
    if hello.spawn {
        println!("[+] XiaM SPAWN mode (main thread blocked, waiting for resume)");
    }

    // 拆分 TCP 流：reader 给后台线程，writer 给主线程发送请求
    let reader = stream.try_clone()?;
    let writer = Arc::new(Mutex::new(stream));

    // 通道：后台线程读到 Response 后发给主线程
    let (resp_tx, resp_rx) = mpsc::channel::<Response>();

    // 后台读取线程：分发 Event（直接打印）和 Response（通过 channel）
    thread::spawn(move || {
        reader_thread(reader, resp_tx);
    });

    // Spawn 模式：自动注入脚本并恢复
    if let Some(ref script_path) = config.spawn_script {
        spawn_sequence(&writer, &resp_rx, script_path)?;
    }

    match config.mode {
        HostMode::Once(ref command) => {
            let keep_running = send_command(&writer, &resp_rx, command)?;
            if !keep_running {
                println!("[*] Session closed by command");
            }
        }
        HostMode::Cli => {
            print_repl_help();
            repl_loop(&writer, &resp_rx)?;
        }
        HostMode::Mcp => unreachable!(),
    }

    Ok(())
}

/// Spawn 模式自动化序列：loadjs → resumeï¼引擎自动初始化ï¼
fn spawn_sequence(
    writer: &Arc<Mutex<TcpStream>>,
    resp_rx: &mpsc::Receiver<Response>,
    script_path: &str,
) -> io::Result<()> {
    println!("[*] Spawn mode: loadjs + resume...");

    // 1. loadjs <script> (引擎自动初始化)
    println!("[*] Step 1/2: loadjs {script_path}");
    let load_cmd = format!("loadjs {script_path}");
    if !send_command(writer, resp_rx, &load_cmd)? {
        return Err(io::Error::new(io::ErrorKind::Other, "loadjs failed"));
    }

    // 2. resume
    println!("[*] Step 2/2: resume");
    if !send_command(writer, resp_rx, "resume")? {
        return Err(io::Error::new(io::ErrorKind::Other, "resume failed"));
    }

    println!("[+] Spawn complete — app resumed");
    Ok(())
}

/// 后台读取线程：持续读取帧，区分 Event 和 Response
fn reader_thread(mut reader: TcpStream, resp_tx: mpsc::Sender<Response>) {
    loop {
        let payload = match frame::read_frame(&mut reader) {
            Ok(Some(p)) => p,
            Ok(None) => {
                eprintln!("\n[*] XiaM disconnected");
                break;
            }
            Err(e) => {
                eprintln!("\n[!] Read error: {e}");
                break;
            }
        };

        // 尝试解析 JSON
        let json: Value = match serde_json::from_slice(&payload) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[!] Invalid JSON frame: {e}");
                continue;
            }
        };

        // 通过 "event" 字段区分 Event 和 Response
        if json.get("event").is_some() {
            if let Ok(event) = serde_json::from_value::<Event>(json) {
                display_event(&event);
            }
        } else {
            if let Ok(resp) = serde_json::from_value::<Response>(json) {
                let _ = resp_tx.send(resp);
            }
        }
    }
}

/// 交互式 REPL 循环。
fn repl_loop(
    writer: &Arc<Mutex<TcpStream>>,
    resp_rx: &mpsc::Receiver<Response>,
) -> io::Result<()> {
    let stdin = io::stdin();
    loop {
        print!("XiaM> ");
        io::stdout().flush()?;

        let mut input = String::new();
        if stdin.read_line(&mut input)? == 0 {
            println!();
            return Ok(());
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        // 本地 help 直接显示
        if input == "help" {
            print_repl_help();
            continue;
        }

        if !send_command(writer, resp_rx, input)? {
            return Ok(());
        }
    }
}

/// 解析用户输入为结构化请求，发送并等待响应。
/// 返回 false 表示会话应结束。
fn send_command(
    writer: &Arc<Mutex<TcpStream>>,
    resp_rx: &mpsc::Receiver<Response>,
    input: &str,
) -> io::Result<bool> {
    let req = parse_user_input(input);
    let is_exit = req.command == "exit";

    {
        let mut w = writer.lock().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
        frame::write_message(&mut *w, &req)?;
    }

    // 等待后台线程转发的 Response
    let resp = resp_rx.recv().map_err(|_| {
        io::Error::new(io::ErrorKind::UnexpectedEof, "XiaM disconnected")
    })?;

    display_response(&resp);

    Ok(!is_exit)
}

/// 将用户 REPL 输入转换为结构化 Request。
/// 支持简写: "echo hello" -> {command:"echo", args:{"text":"hello"}}
fn parse_user_input(input: &str) -> Request {
    let id = next_request_id();
    let (verb, rest) = split_first_word(input);

    // quit 映射到 exit
    let verb = if verb == "quit" { "exit" } else { verb };

    match verb {
        "echo" if !rest.is_empty() => {
            Request::with_args(id, verb, json!({ "text": rest }))
        }
        "loadjs" | "reloadjs" if !rest.is_empty() => {
            // 如果参数是 .js 文件路径，读取文件内容
            let script = if rest.ends_with(".js") {
                match std::fs::read_to_string(rest) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("[!] 无法读取文件 {rest}: {e}");
                        return Request::new(id, verb);
                    }
                }
            } else {
                rest.to_string()
            };
            Request::with_args(id, verb, json!({ "script": script }))
        }
        "find_symbol" if !rest.is_empty() => {
            Request::with_args(id, verb, json!({ "name": rest }))
        }
        "read_memory" if !rest.is_empty() => {
            // 简单格式: read_memory <address> [size]
            let parts: Vec<&str> = rest.splitn(2, char::is_whitespace).collect();
            let mut args = json!({ "address": parts[0] });
            if let Some(size) = parts.get(1) {
                args["size"] = json!(size.trim());
            }
            Request::with_args(id, verb, args)
        }
        _ => {
            if rest.is_empty() {
                Request::new(id, verb)
            } else {
                // 通用: 剩余部分作为 "args" 字符串
                Request::with_args(id, verb, json!({ "raw": rest }))
            }
        }
    }
}

/// 显示异步事件（hook 回调的 console/send 输出）
fn display_event(event: &Event) {
    let prefix = match event.event_type.as_str() {
        "console" => "[console]",
        "send" => "[send]",
        _ => "[event]",
    };
    match &event.payload {
        Value::String(s) => println!("{prefix} {s}"),
        other => println!("{prefix} {other}"),
    }
    // 刷新输出，确保 Event 在 prompt 之前可见
    let _ = io::stdout().flush();
}

/// 以人类友好的方式显示响应。
fn display_response(resp: &Response) {
    match resp.status {
        Status::Ok => {
            if let Some(ref data) = resp.data {
                // 紧凑显示小对象，美化显示大对象
                let json_str = serde_json::to_string(data).unwrap_or_default();
                if json_str.len() < 120 {
                    println!("[ok] {json_str}");
                } else {
                    let pretty = serde_json::to_string_pretty(data).unwrap_or(json_str);
                    println!("[ok]\n{pretty}");
                }
            } else {
                println!("[ok]");
            }
        }
        Status::Error => {
            let code = resp
                .error_code
                .as_ref()
                .map(|c| format!("{c:?}"))
                .unwrap_or_else(|| "unknown".to_string());
            let msg = resp
                .error_message
                .as_deref()
                .unwrap_or("no details");
            println!("[err] [{code}] {msg}");
        }
    }
}

fn split_first_word(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

// ---------------------------------------------------------------------------
// 参数解析
// ---------------------------------------------------------------------------

fn parse_args<I>(args: I) -> Result<Config, String>
where
    I: IntoIterator<Item = String>,
{
    let mut host = env::var("FRIDA_RUST_AGENT_TCP_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_HOST.to_string());
    let mut port = env::var("FRIDA_RUST_AGENT_TCP_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let mut mode = HostMode::Cli;
    let mut spawn_script: Option<String> = None;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--host" => host = take_value("--host", &mut iter)?,
            "--port" => {
                let value = take_value("--port", &mut iter)?;
                port = value
                    .parse()
                    .map_err(|_| format!("invalid port: {value}"))?;
            }
            "--once" => {
                mode = HostMode::Once(take_value("--once", &mut iter)?);
            }
            "--spawn" => {
                spawn_script = Some(take_value("--spawn", &mut iter)?);
            }
            "--mode" => {
                let value = take_value("--mode", &mut iter)?;
                mode = match value.as_str() {
                    "cli" => HostMode::Cli,
                    "mcp" => HostMode::Mcp,
                    _ => return Err(format!("unknown mode: {value} (supported: cli, mcp)")),
                };
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Config { host, port, mode, spawn_script })
}

fn take_value<I>(flag: &str, iter: &mut I) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn print_repl_help() {
    println!("[*] Commands:");
    println!("    ping              - 检查连通性");
    println!("    get_info          - 获取 XiaM 信息");
    println!("    echo <text>       - 回显文本");
    println!("    list_modules      - 枚举模块 (stub)");
    println!("    list_threads      - 枚举线程 (stub)");
    println!("    find_symbol <name> - 查找符号 (stub)");
    println!("    read_memory <addr> [size] - 读取内存 (stub)");
    println!("    trace_start       - 开始跟踪 (stub)");
    println!("    trace_stop        - 停止跟踪 (stub)");
    println!("    jsinit            - 初始化 JS 引擎 (Android)");
    println!("    loadjs <script>   - 执行 JS 脚本 (Android)");
    println!("    reloadjs <script> - 热加载 JS 脚本 (Android)");
    println!("    resume            - 恢复 spawn 模式阻塞的主线程");
    println!("    help              - 显示此帮助");
    println!("    quit / exit       - 断开连接");
}

fn print_usage(program: &str) {
    println!("Usage: {program} [OPTIONS]");
    println!();
    println!("Options:");
    println!("    --host HOST       Listen address (default: {DEFAULT_HOST})");
    println!("    --port PORT       Listen port (default: {DEFAULT_PORT})");
    println!("    --once COMMAND    Send one command and exit");
    println!("    --spawn SCRIPT    Spawn mode: auto jsinit + loadjs SCRIPT + resume, then REPL");
    println!("    --mode cli|mcp    Run mode (default: cli; mcp is reserved)");
    println!();
    println!("Examples:");
    println!("  adb reverse tcp:{0} tcp:{0}", DEFAULT_PORT);
    println!("  cargo run -p agent-host");
    println!("  cargo run -p agent-host -- --once ping");
    println!("  cargo run -p agent-host -- --spawn test.js  # spawn mode: auto jsinit+loadjs+resume");
    println!("  cargo run -p agent-host -- --mode mcp  # reserved, not yet implemented");
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agent_protocol::frame;
    use std::io::Cursor;

    #[test]
    fn parse_defaults() {
        let config = parse_args(Vec::<String>::new()).unwrap();
        assert_eq!(config.host, DEFAULT_HOST);
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.mode, HostMode::Cli);
        assert!(config.spawn_script.is_none());
    }

    #[test]
    fn parse_overrides() {
        let config = parse_args(vec![
            "--host".to_string(),
            "0.0.0.0".to_string(),
            "--port".to_string(),
            "31337".to_string(),
            "--once".to_string(),
            "ping".to_string(),
        ])
        .unwrap();

        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 31337);
        assert!(matches!(config.mode, HostMode::Once(ref cmd) if cmd == "ping"));
    }

    #[test]
    fn parse_mode_mcp() {
        let config = parse_args(vec!["--mode".to_string(), "mcp".to_string()]).unwrap();
        assert_eq!(config.mode, HostMode::Mcp);
    }

    #[test]
    fn parse_spawn_flag() {
        let config = parse_args(vec!["--spawn".to_string(), "hook.js".to_string()]).unwrap();
        assert_eq!(config.spawn_script.as_deref(), Some("hook.js"));
        assert_eq!(config.mode, HostMode::Cli);
    }

    #[test]
    fn parse_user_input_simple() {
        let req = parse_user_input("ping");
        assert_eq!(req.command, "ping");
        assert_eq!(req.args, json!({}));
    }

    #[test]
    fn parse_user_input_echo() {
        let req = parse_user_input("echo hello world");
        assert_eq!(req.command, "echo");
        assert_eq!(req.args["text"], "hello world");
    }

    #[test]
    fn parse_user_input_quit_maps_to_exit() {
        let req = parse_user_input("quit");
        assert_eq!(req.command, "exit");
    }

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        frame::write_frame(&mut buf, b"ping").unwrap();

        let mut cursor = Cursor::new(buf);
        let payload = frame::read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(payload, b"ping");
    }
}
