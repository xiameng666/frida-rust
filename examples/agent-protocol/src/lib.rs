//! agent-protocol: agent 和 agent-host 之间的共享通信协议。
//!
//! 提供:
//! - 长度前缀帧传输 (4字节 LE + payload)
//! - 结构化 JSON 请求/响应消息
//! - Hello 握手协议
//! - 命令枚举和能力声明

pub mod frame;
pub mod message;

pub use frame::{read_frame, write_frame};
pub use message::{
    Capabilities, Command, ErrorCode, Event, Hello, HostMode, Request, Response, Status,
    PROTOCOL_VERSION,
};
