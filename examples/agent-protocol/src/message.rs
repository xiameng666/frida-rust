//! 结构化消息定义。
//!
//! 所有消息通过 JSON 序列化后放入长度前缀帧传输。

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 协议版本号。
pub const PROTOCOL_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Hello 握手 (agent -> host，连接建立后的第一条消息)
// ---------------------------------------------------------------------------

/// Agent 连接后发送的握手消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// 协议版本
    pub version: String,
    /// Agent 进程 PID
    pub pid: u32,
    /// 传输方式 ("tcp")
    pub transport: String,
    /// Agent 支持的能力列表
    pub capabilities: Capabilities,
}

impl Hello {
    /// 创建一个默认的 Hello 消息 (TCP 传输)。
    pub fn new(pid: u32, capabilities: Capabilities) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            pid,
            transport: "tcp".to_string(),
            capabilities,
        }
    }
}

/// Agent 能力声明。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// 支持的命令列表
    pub commands: Vec<String>,
}

impl Capabilities {
    /// 从命令列表创建。
    pub fn from_commands(commands: &[&str]) -> Self {
        Self {
            commands: commands.iter().map(|s| s.to_string()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// 命令枚举 (已知命令的类型安全表示)
// ---------------------------------------------------------------------------

/// 已知命令枚举，用于类型安全的命令分发。
/// 未知命令通过 `Unknown(String)` 保持前向兼容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ping,
    GetInfo,
    ListModules,
    ListThreads,
    FindSymbol,
    ReadMemory,
    TraceStart,
    TraceStop,
    JsInit,
    LoadJs,
    ReloadJs,
    Echo,
    Exit,
    Help,
    /// 未知命令 (前向兼容)
    Unknown(String),
}

impl Command {
    /// 从字符串解析命令。
    pub fn parse(s: &str) -> Self {
        match s {
            "ping" => Self::Ping,
            "get_info" => Self::GetInfo,
            "list_modules" => Self::ListModules,
            "list_threads" => Self::ListThreads,
            "find_symbol" => Self::FindSymbol,
            "read_memory" => Self::ReadMemory,
            "trace_start" => Self::TraceStart,
            "trace_stop" => Self::TraceStop,
            "jsinit" => Self::JsInit,
            "loadjs" => Self::LoadJs,
            "reloadjs" => Self::ReloadJs,
            "echo" => Self::Echo,
            "exit" | "quit" => Self::Exit,
            "help" => Self::Help,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// 转为协议字符串。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ping => "ping",
            Self::GetInfo => "get_info",
            Self::ListModules => "list_modules",
            Self::ListThreads => "list_threads",
            Self::FindSymbol => "find_symbol",
            Self::ReadMemory => "read_memory",
            Self::TraceStart => "trace_start",
            Self::TraceStop => "trace_stop",
            Self::JsInit => "jsinit",
            Self::LoadJs => "loadjs",
            Self::ReloadJs => "reloadjs",
            Self::Echo => "echo",
            Self::Exit => "exit",
            Self::Help => "help",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// 当前 stub 实现支持的命令列表。
    pub fn supported_commands() -> &'static [&'static str] {
        &[
            "ping",
            "get_info",
            "echo",
            "help",
            "exit",
            // 以下为 stub，后续 Phase 3 实现
            "list_modules",
            "list_threads",
            "find_symbol",
            "read_memory",
            "trace_start",
            "trace_stop",
            "jsinit",
            "loadjs",
            "reloadjs",
        ]
    }
}

// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------

/// 结构化请求消息 (host -> agent)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// 请求 ID，用于关联请求和响应
    pub id: String,
    /// 命令名称
    pub command: String,
    /// 命令参数 (JSON object)
    #[serde(default = "default_args")]
    pub args: Value,
}

fn default_args() -> Value {
    Value::Object(serde_json::Map::new())
}

impl Request {
    /// 创建无参数请求。
    pub fn new(id: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            command: command.into(),
            args: default_args(),
        }
    }

    /// 创建带参数请求。
    pub fn with_args(id: impl Into<String>, command: impl Into<String>, args: Value) -> Self {
        Self {
            id: id.into(),
            command: command.into(),
            args,
        }
    }

    /// 解析命令为类型安全的枚举。
    pub fn parsed_command(&self) -> Command {
        Command::parse(&self.command)
    }
}

/// 响应状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Error,
}

/// 错误码枚举。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 未知命令
    UnknownCommand,
    /// 参数缺失或无效
    InvalidArgs,
    /// 功能未实现 (stub)
    NotImplemented,
    /// 内部错误
    Internal,
}

/// 结构化响应消息 (agent -> host)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// 对应请求的 ID
    pub id: String,
    /// 状态
    pub status: Status,
    /// 成功时的数据
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// 错误码
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
    /// 错误描述
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl Response {
    /// 创建成功响应。
    pub fn ok(id: impl Into<String>, data: Value) -> Self {
        Self {
            id: id.into(),
            status: Status::Ok,
            data: Some(data),
            error_code: None,
            error_message: None,
        }
    }

    /// 创建无数据的成功响应。
    pub fn ok_empty(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: Status::Ok,
            data: None,
            error_code: None,
            error_message: None,
        }
    }

    /// 创建错误响应。
    pub fn error(
        id: impl Into<String>,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status: Status::Error,
            data: None,
            error_code: Some(code),
            error_message: Some(message.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Host 运行模式 (预留 MCP 接口)
// ---------------------------------------------------------------------------

/// Host 运行模式。
/// MCP 模式预留接口，暂不实现。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMode {
    /// 交互式 REPL 模式
    Cli,
    /// 一次性命令模式
    Once(String),
    /// MCP stdio 模式 (预留，暂未实现)
    Mcp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serialize_roundtrip() {
        let req = Request::new("1", "ping");
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, "1");
        assert_eq!(decoded.command, "ping");
    }

    #[test]
    fn request_with_args() {
        let req = Request::with_args("2", "echo", json!({"text": "hello"}));
        let decoded: Request = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(decoded.args["text"], "hello");
    }

    #[test]
    fn response_ok_serialization() {
        let resp = Response::ok("1", json!({"pid": 123}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""status":"ok"#));
        assert!(!json.contains("error_code"));
    }

    #[test]
    fn response_error_serialization() {
        let resp = Response::error("2", ErrorCode::UnknownCommand, "no such command: foo");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""status":"error"#));
        assert!(json.contains("unknown_command"));
    }

    #[test]
    fn hello_message() {
        let hello = Hello::new(1234, Capabilities::from_commands(&["ping", "echo"]));
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("0.1.0"));
        assert!(json.contains("1234"));
        assert!(json.contains("ping"));
    }

    #[test]
    fn command_parse() {
        assert_eq!(Command::parse("ping"), Command::Ping);
        assert_eq!(Command::parse("quit"), Command::Exit);
        assert_eq!(Command::parse("exit"), Command::Exit);
        assert_eq!(
            Command::parse("unknown_cmd"),
            Command::Unknown("unknown_cmd".to_string())
        );
    }

    #[test]
    fn command_roundtrip() {
        for cmd_str in Command::supported_commands() {
            let cmd = Command::parse(cmd_str);
            assert_eq!(cmd.as_str(), *cmd_str);
        }
    }
}
