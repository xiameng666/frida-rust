//! Minimal ELF64 parser — resolve symbol file offset from DYNSYM.

use std::fs;
use std::io;

// ELF64 constants
const ELFMAG: &[u8; 4] = b"\x7fELF";
const SHT_DYNSYM: u32 = 11;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;

/// ELF64 header (only the fields we need).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 section header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// ELF64 symbol entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

/// ELF64 program header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// Information about the executable PT_LOAD segment.
pub struct ExecLoadInfo {
    /// p_vaddr of the first PT_LOAD (base vaddr for offset calculations).
    pub first_load_vaddr: u64,
    /// p_filesz of the executable PT_LOAD (where real code ends).
    pub exec_filesz: u64,
}

/// Parse the ELF at `path` and return info about the executable PT_LOAD segment.
///
/// This is used to find the padding area at the end of the text segment:
/// `code_end = runtime_base + (exec_vaddr - first_load_vaddr) + exec_filesz`.
/// Bytes from `code_end` to the next page boundary are NUL padding —
/// safe to overwrite without clobbering real code.
pub fn exec_load_info(path: &str) -> io::Result<ExecLoadInfo> {
    let data = fs::read(path)?;

    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
    }
    let ehdr = unsafe { &*(data.as_ptr() as *const Elf64Ehdr) };
    if &ehdr.e_ident[..4] != ELFMAG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ELF file"));
    }

    let phdr_base = ehdr.e_phoff as usize;
    let phdr_size = std::mem::size_of::<Elf64Phdr>();

    let mut first_load_vaddr: Option<u64> = None;
    let mut exec_filesz: Option<u64> = None;

    for i in 0..ehdr.e_phnum as usize {
        let off = phdr_base + i * phdr_size;
        if off + phdr_size > data.len() {
            break;
        }
        let phdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Phdr) };
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if first_load_vaddr.is_none() {
            first_load_vaddr = Some(phdr.p_vaddr);
        }
        if (phdr.p_flags & PF_X) != 0 && exec_filesz.is_none() {
            exec_filesz = Some(phdr.p_filesz);
        }
    }

    match (first_load_vaddr, exec_filesz) {
        (Some(fv), Some(ef)) => Ok(ExecLoadInfo {
            first_load_vaddr: fv,
            exec_filesz: ef,
        }),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no executable PT_LOAD segment found",
        )),
    }
}

/// Get the file offset of a symbol in an ELF64 shared library.
///
/// This parses DYNSYM, finds the symbol by name, gets its virtual address,
/// then subtracts the first PT_LOAD vaddr to get a file-relative offset
/// suitable for computing `base + offset = runtime address`.
pub fn sym_offset(path: &str, sym_name: &str) -> io::Result<usize> {
    let data = fs::read(path)?;

    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too small"));
    }

    let ehdr = unsafe { &*(data.as_ptr() as *const Elf64Ehdr) };
    if &ehdr.e_ident[..4] != ELFMAG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ELF file"));
    }

    let shdr_base = ehdr.e_shoff as usize;
    let shdr_size = std::mem::size_of::<Elf64Shdr>();

    // Find DYNSYM section, resolve symbol
    let mut sym_vaddr: u64 = 0;
    for i in 0..ehdr.e_shnum as usize {
        let off = shdr_base + i * shdr_size;
        if off + shdr_size > data.len() {
            break;
        }
        let shdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Shdr) };
        if shdr.sh_type != SHT_DYNSYM {
            continue;
        }

        // Get string table for this symbol table
        let strtab_idx = shdr.sh_link as usize;
        let strtab_off = {
            let so = shdr_base + strtab_idx * shdr_size;
            if so + shdr_size > data.len() {
                continue;
            }
            let strtab_shdr = unsafe { &*(data.as_ptr().add(so) as *const Elf64Shdr) };
            strtab_shdr.sh_offset as usize
        };

        let sym_count = shdr.sh_size as usize / std::mem::size_of::<Elf64Sym>();
        let syms_off = shdr.sh_offset as usize;

        for j in 0..sym_count {
            let so = syms_off + j * std::mem::size_of::<Elf64Sym>();
            if so + std::mem::size_of::<Elf64Sym>() > data.len() {
                break;
            }
            let sym = unsafe { &*(data.as_ptr().add(so) as *const Elf64Sym) };
            let name_off = strtab_off + sym.st_name as usize;
            if name_off >= data.len() {
                continue;
            }

            // Read NUL-terminated symbol name
            let name_bytes = &data[name_off..];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");

            if name == sym_name {
                sym_vaddr = sym.st_value;
                break;
            }
        }

        if sym_vaddr != 0 {
            break;
        }
    }

    if sym_vaddr == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("symbol '{}' not found in {}", sym_name, path),
        ));
    }

    // Subtract first PT_LOAD vaddr to get file-relative offset
    let phdr_base = ehdr.e_phoff as usize;
    let phdr_size = std::mem::size_of::<Elf64Phdr>();
    for i in 0..ehdr.e_phnum as usize {
        let off = phdr_base + i * phdr_size;
        if off + phdr_size > data.len() {
            break;
        }
        let phdr = unsafe { &*(data.as_ptr().add(off) as *const Elf64Phdr) };
        if phdr.p_type == PT_LOAD {
            sym_vaddr -= phdr.p_vaddr;
            break;
        }
    }

    Ok(sym_vaddr as usize)
}

/// Resolve the runtime address of a symbol in a remote process.
/// = base address of lib in target + file offset of symbol.
pub fn remote_sym(pid: u32, lib: &str, sym_name: &str) -> io::Result<usize> {
    let lib_path = crate::proc::module_path(pid, lib)?;
    let base = crate::proc::base_addr(pid, lib)?;
    let off = sym_offset(&lib_path, sym_name)?;
    Ok(base + off)
}
