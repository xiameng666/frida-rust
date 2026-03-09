//! ARM64 notification stub and StubData layout.
//!
//! The stub is position-independent ARM64 code that:
//! 1. Calls getuid() and compares with the target UID
//! 2. If matched: restores ArtMethod entry_point, notifies injector via socket
//! 3. Blocks until injector completes memfd injection
//! 4. Calls the original setArgV0Native function
//!
//! The data section is appended after the code, located by a marker string.

/// Marker string used to locate StubData within the payload binary.
pub const MARKER: &[u8] = b"/alone12345678";

/// Pre-compiled ARM64 stub (from stub.S via NDK).
/// Build with: `make -C examples/zymbiote/stub`
///
/// NOTE: rebuild stub.bin after modifying stub.S.
pub static PAYLOAD: &[u8] = include_bytes!("../stub/stub.bin");

/// StubData field offsets from the marker position.
///
/// Layout (matching stub.S):
/// ```text
/// +0x00: mark[16]         "/alone12345678\0\0"
/// +0x10: original_func    (u64, setArgV0Native address)
/// +0x18: slot_addr         (u64, ArtMethod entry_point field address)
/// +0x20: uid               (u32, target UID)
/// +0x24: socket_name[108]  (null-terminated abstract socket name)
/// ```
mod offsets {
    pub const ORIGINAL_FUNC: usize = 0x10;
    pub const SLOT_ADDR: usize = 0x18;
    pub const UID: usize = 0x20;
    pub const SOCKET_NAME: usize = 0x24;
    pub const SOCKET_NAME_LEN: usize = 32;
    /// Total struct size.
    pub const STRUCT_SIZE: usize = 0x24 + 32; // 0x44
}

/// Parameters for filling the stub data section.
pub struct StubParams {
    pub original_func: usize,
    pub slot_addr: usize,
    pub uid: u32,
    pub socket_name: String,
}

/// Copy the payload into a mutable buffer and fill in the StubData fields.
pub fn fill_payload(params: &StubParams) -> Result<Vec<u8>, &'static str> {
    let mut buf = PAYLOAD.to_vec();

    let m = find_marker(&buf).ok_or("marker not found in payload")?;

    if m + offsets::STRUCT_SIZE > buf.len() {
        return Err("payload too small for StubData");
    }

    // Write fields at fixed offsets (little-endian, aarch64)
    write_u64(&mut buf, m + offsets::ORIGINAL_FUNC, params.original_func as u64);
    write_u64(&mut buf, m + offsets::SLOT_ADDR, params.slot_addr as u64);
    write_u32(&mut buf, m + offsets::UID, params.uid);

    // Write socket name (NUL-terminated)
    let name_bytes = params.socket_name.as_bytes();
    let max_len = offsets::SOCKET_NAME_LEN - 1;
    let copy_len = name_bytes.len().min(max_len);
    let dst = m + offsets::SOCKET_NAME;
    // Clear the socket_name region first
    for b in &mut buf[dst..dst + offsets::SOCKET_NAME_LEN] {
        *b = 0;
    }
    buf[dst..dst + copy_len].copy_from_slice(&name_bytes[..copy_len]);

    Ok(buf)
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Find the marker position in a byte buffer.
fn find_marker(buf: &[u8]) -> Option<usize> {
    buf.windows(MARKER.len())
        .position(|w| w == MARKER)
}
