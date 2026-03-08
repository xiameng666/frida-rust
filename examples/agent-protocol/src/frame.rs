//! 长度前缀帧传输层。
//!
//! 帧格式: [4字节 LE 长度][payload]
//! 最大帧长度: 1 MiB

use std::io::{self, Read, Write};

/// 单帧最大长度 (1 MiB)。
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// 将 payload 写入一个长度前缀帧。
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload is larger than u32::MAX",
        )
    })?;

    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// 从流中读取一个长度前缀帧，返回 None 表示 EOF。
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// 将结构化消息序列化为 JSON 并写入帧。
pub fn write_message<W: Write, T: serde::Serialize>(writer: &mut W, msg: &T) -> io::Result<()> {
    let json = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(writer, &json)
}

/// 从帧中读取并反序列化结构化消息，返回 None 表示 EOF。
pub fn read_message<R: Read, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> io::Result<Option<T>> {
    match read_frame(reader)? {
        Some(payload) => {
            let msg = serde_json::from_slice(&payload)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(msg))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"ping").unwrap();

        let mut cursor = Cursor::new(buf);
        let payload = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn empty_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").unwrap();

        let mut cursor = Cursor::new(buf);
        let payload = read_frame(&mut cursor).unwrap().unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn eof_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn frame_too_large() {
        // 构造一个声称长度超过 MAX_FRAME_LEN 的帧头
        let len = (MAX_FRAME_LEN as u32 + 1).to_le_bytes();
        let mut cursor = Cursor::new(len.to_vec());
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn message_roundtrip() {
        use crate::message::{Request, Response, Status};
        use serde_json::json;

        let req = Request {
            id: "1".to_string(),
            command: "ping".to_string(),
            args: json!({}),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &req).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Request = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(decoded.id, "1");
        assert_eq!(decoded.command, "ping");

        // 测试 Response 序列化
        let resp = Response::ok("1", json!({"pid": 123}));
        let mut buf2 = Vec::new();
        write_message(&mut buf2, &resp).unwrap();

        let mut cursor2 = Cursor::new(buf2);
        let decoded_resp: Response = read_message(&mut cursor2).unwrap().unwrap();
        assert_eq!(decoded_resp.status, Status::Ok);
    }
}
