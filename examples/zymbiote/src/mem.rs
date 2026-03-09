//! Memory search via /proc/<pid>/mem — scan for 8-byte values in memory regions.

use crate::proc::MemRegion;

const MAX_REGION_SIZE: usize = 64 * 1024 * 1024; // 512 MB
const CHUNK_SIZE: usize = 256 * 1024; // 256 KB

/// Search a memory region (via an open /proc/<pid>/mem fd) for an 8-byte needle.
/// Returns the virtual address where the needle was found, or None.
pub fn search(fd: i32, region: &MemRegion, needle: usize) -> Option<usize> {
    let size = region.size();
    if size < 8 {
        return None;
    }
    if size > MAX_REGION_SIZE {
        eprintln!("  [!] skipping oversized region 0x{:x}-0x{:x} ({} MB) {}",
            region.start, region.end, size / (1024*1024), region.path);
        return None;
    }

    let needle_bytes = needle.to_ne_bytes();

    // For small regions, read all at once
    if size <= CHUNK_SIZE {
        let mut buf = vec![0u8; size];
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                size,
                region.start as libc::off_t,
            )
        };
        if n != size as isize {
            return None;
        }
        return find_bytes(&buf, &needle_bytes).map(|off| region.start + off);
    }

    // Large regions: read in chunks with overlap
    let overlap = 7; // sizeof(usize) - 1
    let mut buf = vec![0u8; CHUNK_SIZE + overlap];
    let mut pos = 0usize;

    while pos < size {
        let to_read = (CHUNK_SIZE + overlap).min(size - pos);
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                to_read,
                (region.start + pos) as libc::off_t,
            )
        };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        if let Some(off) = find_bytes(&buf[..n], &needle_bytes) {
            return Some(region.start + pos + off);
        }
        pos += CHUNK_SIZE;
    }

    None
}

/// Find the first occurrence of `needle` in `haystack` (simple byte search).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
