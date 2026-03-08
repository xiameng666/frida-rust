//! Host tool for communicating with the injected Android agent over TCP.
//!
//! The intended setup for USB-attached devices is:
//! `adb reverse tcp:12708 tcp:12708`

use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 12708;
const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    host: String,
    port: u16,
    once: Option<String>,
}

fn main() {
    let program = env::args()
        .next()
        .unwrap_or_else(|| "agent-host".to_string());

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
        eprintln!("agent-host error: {error}");
        std::process::exit(1);
    }
}

fn run(config: Config) -> io::Result<()> {
    println!("[*] Agent Host Tool v0.1.0");
    println!("[*] Mode: TCP");
    println!("[*] Listening on {}:{}", config.host, config.port);
    println!(
        "[*] For USB debugging, run: adb reverse tcp:{0} tcp:{0}",
        config.port
    );

    let listener = TcpListener::bind((config.host.as_str(), config.port))?;
    let (mut stream, addr) = listener.accept()?;
    stream.set_nodelay(true)?;

    println!("[+] Agent connected from {addr}");

    let greeting = read_response(&mut stream)?;
    println!("[<] {greeting}");

    if let Some(command) = config.once.as_deref() {
        let keep_running = send_command(&mut stream, command)?;
        if !keep_running {
            println!("[*] Session closed by command");
        }
        return Ok(());
    }

    print_repl_help();

    let stdin = io::stdin();
    loop {
        print!("agent> ");
        io::stdout().flush()?;

        let mut input = String::new();
        if stdin.read_line(&mut input)? == 0 {
            println!();
            return Ok(());
        }

        let command = input.trim();
        if command.is_empty() {
            continue;
        }

        if command == "help" {
            print_repl_help();
            continue;
        }

        if !send_command(&mut stream, command)? {
            return Ok(());
        }
    }
}

fn send_command(stream: &mut TcpStream, command: &str) -> io::Result<bool> {
    let wire_command = if command.eq_ignore_ascii_case("quit") {
        "exit"
    } else {
        command
    };

    write_frame(stream, wire_command.as_bytes())?;

    let response = read_response(stream)?;
    println!("[<] {response}");

    Ok(!wire_command.eq_ignore_ascii_case("exit"))
}

fn read_response(stream: &mut TcpStream) -> io::Result<String> {
    match read_frame(stream)? {
        Some(frame) => Ok(String::from_utf8_lossy(&frame).into_owned()),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "agent disconnected",
        )),
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
    let mut once = None;

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
            "--once" => once = Some(take_value("--once", &mut iter)?),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(Config { host, port, once })
}

fn take_value<I>(flag: &str, iter: &mut I) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn print_repl_help() {
    println!(
        "[*] Commands: ping, pid, echo <text>, hello_entry, trace <arg>, jhook, jsinit, loadjs <script>, quit"
    );
}

fn print_usage(program: &str) {
    println!("Usage: {program} [--host HOST] [--port PORT] [--once COMMAND]");
    println!();
    println!("Examples:");
    println!("  adb reverse tcp:{0} tcp:{0}", DEFAULT_PORT);
    println!("  cargo run -p agent-host");
    println!("  cargo run -p agent-host -- --once ping");
}

#[cfg(test)]
mod tests {
    use super::{parse_args, read_frame, write_frame, Config, DEFAULT_HOST, DEFAULT_PORT};
    use std::io::Cursor;

    #[test]
    fn parse_defaults() {
        let config = parse_args(Vec::<String>::new()).unwrap();
        assert_eq!(
            config,
            Config {
                host: DEFAULT_HOST.to_string(),
                port: DEFAULT_PORT,
                once: None,
            }
        );
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

        assert_eq!(
            config,
            Config {
                host: "0.0.0.0".to_string(),
                port: 31337,
                once: Some("ping".to_string()),
            }
        );
    }

    #[test]
    fn frame_roundtrip() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"ping").unwrap();

        let mut cursor = Cursor::new(buffer);
        let payload = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(payload, b"ping");
    }
}
