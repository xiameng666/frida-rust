//! /proc filesystem utilities: find Zygote, resolve UID, parse maps.

use std::fs;
use std::io::{self, BufRead, BufReader};

/// A parsed memory region from /proc/<pid>/maps.
#[derive(Debug, Clone)]
pub struct MemRegion {
    pub start: usize,
    pub end: usize,
    pub perms: u8,
    pub offset: usize,
    pub path: String,
}

impl MemRegion {
    pub const PERM_R: u8 = 1;
    pub const PERM_W: u8 = 2;
    pub const PERM_X: u8 = 4;

    pub fn r(&self) -> bool {
        self.perms & Self::PERM_R != 0
    }
    pub fn w(&self) -> bool {
        self.perms & Self::PERM_W != 0
    }
    pub fn x(&self) -> bool {
        self.perms & Self::PERM_X != 0
    }
    pub fn rw(&self) -> bool {
        self.r() && self.w()
    }
    pub fn size(&self) -> usize {
        self.end - self.start
    }
}

/// Find the PID of a process by cmdline substring (e.g. "zygote64").
pub fn find_process(name: &str) -> io::Result<u32> {
    let proc_dir = fs::read_dir("/proc")?;
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let fname = file_name.to_string_lossy();
        // Skip non-numeric directories
        if !fname.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            continue;
        }

        let cmdline_path = format!("/proc/{}/cmdline", fname);
        if let Ok(data) = fs::read(&cmdline_path) {
            // cmdline is NUL-separated; check the first component
            let cmdline = String::from_utf8_lossy(&data);
            if cmdline.contains(name) {
                if let Ok(pid) = fname.parse::<u32>() {
                    return Ok(pid);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("process '{}' not found", name),
    ))
}

/// Find Zygote64 PID.
pub fn find_zygote() -> io::Result<u32> {
    find_process("zygote64")
}

/// Resolve UID for a package name from /data/system/packages.list.
pub fn get_uid(pkg: &str) -> io::Result<u32> {
    let data = fs::read_to_string("/data/system/packages.list")?;
    for line in data.lines() {
        // Format: <pkg> <uid> ...
        if let Some(rest) = line.strip_prefix(pkg) {
            if rest.starts_with(' ') {
                let uid_str = rest.trim_start().split_whitespace().next().unwrap_or("");
                if let Ok(uid) = uid_str.parse::<u32>() {
                    return Ok(uid);
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("package '{}' not found in packages.list", pkg),
    ))
}

/// Parse a single line from /proc/<pid>/maps into a MemRegion.
fn parse_maps_line(line: &str) -> Option<MemRegion> {
    // Format: start-end perms offset dev inode [path]
    let mut parts = line.splitn(6, char::is_whitespace);
    let range = parts.next()?;
    let perms_str = parts.next()?;
    let offset_str = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    // path may be missing or have leading spaces
    let path = parts.next().unwrap_or("").trim().to_string();

    let (start_s, end_s) = range.split_once('-')?;
    let start = usize::from_str_radix(start_s, 16).ok()?;
    let end = usize::from_str_radix(end_s, 16).ok()?;
    let offset = usize::from_str_radix(offset_str, 16).ok()?;

    let mut perms: u8 = 0;
    let pb = perms_str.as_bytes();
    if pb.len() >= 3 {
        if pb[0] == b'r' {
            perms |= MemRegion::PERM_R;
        }
        if pb[1] == b'w' {
            perms |= MemRegion::PERM_W;
        }
        if pb[2] == b'x' {
            perms |= MemRegion::PERM_X;
        }
    }

    Some(MemRegion {
        start,
        end,
        perms,
        offset,
        path,
    })
}

/// Parse all regions from /proc/<pid>/maps.
pub fn parse_maps(pid: u32) -> io::Result<Vec<MemRegion>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = fs::File::open(&maps_path)?;
    let reader = BufReader::new(file);
    let mut regions = Vec::with_capacity(256);
    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }
    Ok(regions)
}

/// Find the base address (first mapping with offset=0) of a module in a process.
pub fn base_addr(pid: u32, module: &str) -> io::Result<usize> {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = fs::File::open(&maps_path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            if region.offset == 0 && region.path.contains(module) {
                return Ok(region.start);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("module '{}' not found in pid {}", module, pid),
    ))
}

/// Find the full filesystem path of a module in a process's maps.
pub fn module_path(pid: u32, module: &str) -> io::Result<String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = fs::File::open(&maps_path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            if region.path.contains(module) && !region.path.is_empty() {
                return Ok(region.path);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("module '{}' not found in pid {}", module, pid),
    ))
}
