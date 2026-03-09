//! Injection state persistence — save/load to a file so that
//! `restore` and `stop` work even if the daemon crashed.
//!
//! Format: simple `key:hex_value` lines, easy to debug.

use std::fs;
use std::io;

pub const STATE_PATH: &str = "/data/local/tmp/.xiam-state";

#[derive(Debug)]
pub struct InjectState {
    pub daemon_pid: u32,
    pub zpid: u32,
    pub slot: usize,
    pub shell: usize,
    pub orig_slot: [u8; 8],
    pub orig_code: Vec<u8>,
    pub pkg: String,
}

impl InjectState {
    /// Save state to file.
    pub fn save(&self) -> io::Result<()> {
        let mut lines = Vec::new();
        lines.push(format!("daemon_pid:{:x}", self.daemon_pid));
        lines.push(format!("zpid:{:x}", self.zpid));
        lines.push(format!("slot:{:x}", self.slot));
        lines.push(format!("shell:{:x}", self.shell));
        lines.push(format!("orig_slot:{}", hex_encode(&self.orig_slot)));
        lines.push(format!("orig_code:{}", hex_encode(&self.orig_code)));
        lines.push(format!("pkg:{}", self.pkg));
        fs::write(STATE_PATH, lines.join("\n"))
    }

    /// Load state from file.
    pub fn load() -> io::Result<Self> {
        let data = fs::read_to_string(STATE_PATH)?;
        let mut daemon_pid = 0u32;
        let mut zpid = 0u32;
        let mut slot = 0usize;
        let mut shell = 0usize;
        let mut orig_slot = [0u8; 8];
        let mut orig_code = Vec::new();
        let mut pkg = String::new();

        for line in data.lines() {
            let Some((key, val)) = line.split_once(':') else {
                continue;
            };
            match key {
                "daemon_pid" => daemon_pid = u32::from_str_radix(val, 16).unwrap_or(0),
                "zpid" => zpid = u32::from_str_radix(val, 16).unwrap_or(0),
                "slot" => slot = usize::from_str_radix(val, 16).unwrap_or(0),
                "shell" => shell = usize::from_str_radix(val, 16).unwrap_or(0),
                "orig_slot" => {
                    let bytes = hex_decode(val);
                    if bytes.len() == 8 {
                        orig_slot.copy_from_slice(&bytes);
                    }
                }
                "orig_code" => orig_code = hex_decode(val),
                "pkg" => pkg = val.to_string(),
                _ => {}
            }
        }

        if zpid == 0 || slot == 0 || shell == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete state file",
            ));
        }

        Ok(Self {
            daemon_pid,
            zpid,
            slot,
            shell,
            orig_slot,
            orig_code,
            pkg,
        })
    }

    /// Remove state file.
    pub fn remove() {
        let _ = fs::remove_file(STATE_PATH);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| {
            s.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}
