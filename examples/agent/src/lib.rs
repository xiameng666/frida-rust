//! Minimal TCP control agent for Android injection.
//!
//! The default workflow is:
//! 1. Run `adb reverse tcp:12708 tcp:12708`
//! 2. Start `cargo run -p agent-host`
//! 3. Inject `libagent.so` into the target Android process
//! 4. The agent connects back to `127.0.0.1:12708` and enters a framed command loop

#![cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]

#[cfg(target_os = "android")]
use std::env;
use std::io::{self, Read, Write};

#[cfg(target_os = "android")]
const DEFAULT_HOST: &str = "127.0.0.1";
#[cfg(target_os = "android")]
const DEFAULT_PORT: u16 = 12708;
#[cfg(target_os = "android")]
const DEFAULT_RECONNECT_MS: u64 = 1_000;
#[cfg(target_os = "android")]
const JNI_VERSION_1_6: i32 = 0x0001_0006;
const MAX_FRAME_LEN: usize = 1024 * 1024;

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

fn trim_line(line: &str) -> &str {
    line.trim_end_matches(|ch| ch == '\r' || ch == '\n')
}

fn split_command(command: &str) -> (&str, &str) {
    match command.find(char::is_whitespace) {
        Some(index) => (&command[..index], command[index..].trim_start()),
        None => (command, ""),
    }
}

fn should_close(command: &str) -> bool {
    matches!(split_command(trim_line(command)).0, "quit" | "exit")
}

fn execute_command(command: &str) -> String {
    let command = trim_line(command).trim();
    let (verb, rest) = split_command(command);

    match verb {
        "" => "ERR empty command".to_string(),
        "help" => {
            "OK commands: help, ping, pid, echo <text>, hello_entry, trace <arg>, jhook, jsinit, loadjs <script>, quit".to_string()
        }
        "ping" => format!("PONG pid={}", std::process::id()),
        "pid" => format!("OK pid={}", std::process::id()),
        "echo" if rest.is_empty() => "ERR echo requires text".to_string(),
        "echo" => rest.to_string(),
        "hello_entry" => "OK hello_entry stub".to_string(),
        "trace" if rest.is_empty() => "OK trace stub".to_string(),
        "trace" => format!("OK trace stub: {rest}"),
        "jhook" if rest.is_empty() => "OK jhook stub".to_string(),
        "jhook" => format!("OK jhook stub: {rest}"),
        "jsinit" => "OK jsinit stub".to_string(),
        "loadjs" if rest.is_empty() => "ERR loadjs requires script".to_string(),
        "loadjs" => format!("OK loadjs stub: {rest}"),
        "quit" | "exit" => "BYE".to_string(),
        _ => format!("ERR unknown command: {command}"),
    }
}

fn write_frame<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: Write,
{
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

fn read_frame<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: Read,
{
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

#[cfg(target_os = "android")]
mod android {
    use super::{
        configured_host, configured_port, execute_command, reconnect_delay_ms, should_close,
        JNI_VERSION_1_6,
    };
    use std::ffi::{c_char, c_void, CString};
    use std::io;
    use std::net::TcpStream;
    use std::sync::Once;
    use std::thread;
    use std::time::{Duration, Instant};

    static START_AGENT: Once = Once::new();

    const ANDROID_LOG_INFO: i32 = 4;
    const LOG_TAG: &[u8] = b"frida-rust-agent\0";
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
            android_log_info(&format!("libagent.so loaded via {origin}"));
            let _ = thread::Builder::new()
                .name("frida-rust-agent".to_string())
                .spawn(agent_main);
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
                        eprintln!("agent session error: {error}");
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

                    eprintln!(
                        "agent connect error to {host}:{port}: {error}"
                    );
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

    fn handle_session(mut stream: TcpStream) -> io::Result<()> {
        let greeting = format!(
            "HELLO_AGENT pid={} transport=tcp target={}:{}\n",
            std::process::id(),
            configured_host(),
            configured_port()
        );

        super::write_frame(&mut stream, greeting.as_bytes())?;

        loop {
            let Some(frame) = super::read_frame(&mut stream)? else {
                return Ok(());
            };

            let command = String::from_utf8_lossy(&frame).into_owned();

            let response = execute_command(&command);
            super::write_frame(&mut stream, response.as_bytes())?;

            if should_close(&command) {
                return Ok(());
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
#[unsafe(no_mangle)]
pub extern "C" fn hello_entry() {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{execute_command, read_frame, should_close, write_frame};

    #[test]
    fn ping_returns_process_info() {
        assert!(execute_command("ping").starts_with("PONG pid="));
    }

    #[test]
    fn echo_returns_payload() {
        assert_eq!(execute_command("echo hello tcp"), "hello tcp");
    }

    #[test]
    fn help_lists_supported_commands() {
        assert!(execute_command("help").contains("echo <text>"));
    }

    #[test]
    fn quit_is_terminal() {
        assert!(should_close("quit\n"));
        assert!(should_close("exit"));
        assert!(!should_close("ping"));
    }

    #[test]
    fn frame_roundtrip() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"ping").unwrap();

        let mut cursor = Cursor::new(buffer);
        let frame = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(frame, b"ping");
    }
}
