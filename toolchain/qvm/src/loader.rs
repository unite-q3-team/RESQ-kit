//! QVM file loader.
//!
//! Spec from ioq3 `code/qcommon/qfiles.h`, `vm.c` (VM_LoadQVM), `vm_interpreted.c`.
//! Header v1: 8 x int32, little-endian, magic 0x12721444.
//! Header v2 (VER2): 9 x int32, magic 0x12721445 (+jtrgLength).
//!
//! Data layout on disk (from dataOffset):
//!   [dataLength bytes: int32 big-endian, byteswapped on load]
//!   [litLength bytes: literals (strings/structs), NOT swapped]
//!   [jtrgLength bytes: jump table targets, VER2 only]
//! bss (bssLength bytes) is zero-filled, appended to data in memory.
//!
//! data_mask = pow2(dataLength+litLength+bssLength) - 1.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

pub const VM_MAGIC: u32 = 0x12721444;
pub const VM_MAGIC_VER2: u32 = 0x12721445;

pub const V1_HEADER_INTS: usize = 8;
pub const V2_HEADER_INTS: usize = 9;

#[derive(Debug)]
pub enum QvmError {
    Io(std::io::Error),
    TooSmall(String),
    BadMagic(u32),
    BadLength(String),
    OutOfBounds(String),
}

impl fmt::Display for QvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QvmError::Io(e) => write!(f, "io error: {e}"),
            QvmError::TooSmall(s) => write!(f, "{s}"),
            QvmError::BadMagic(m) => write!(f, "unrecognized magic 0x{m:08X}"),
            QvmError::BadLength(s) => write!(f, "{s}"),
            QvmError::OutOfBounds(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for QvmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            QvmError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for QvmError {
    fn from(e: std::io::Error) -> Self {
        QvmError::Io(e)
    }
}

/// A parsed QVM file.
#[derive(Debug, Clone)]
pub struct Qvm {
    pub path: String,
    pub vm_magic: u32,
    pub instruction_count: i32,
    pub code_offset: i32,
    pub code_length: i32,
    pub data_offset: i32,
    pub data_length: i32,
    pub lit_length: i32,
    pub bss_length: i32,
    pub jtrg_length: i32, // VER2 only

    /// Which VM module this is (drives the syscall/trap name table).
    pub module: crate::traps::Module,

    /// Code segment (opcode bytes), raw.
    pub code: Vec<u8>,
    /// Data segment, int32 words byteswapped to little-endian.
    pub data: Vec<u8>,
    /// Literals (strings/structs), NOT byteswapped.
    pub lit: Vec<u8>,
    /// Jump-table targets (VER2 only), byteswapped.
    pub jump_table_targets: Vec<u8>,

    /// Symbol names keyed by function *entry instruction index*
    /// (the index a `CALL` pushes; `cfg.entry` for the matching function).
    /// Empty unless the caller attaches a name map (e.g. from a `.names` file).
    pub names: HashMap<usize, String>,
}

impl Qvm {
    pub fn is_ver2(&self) -> bool {
        self.vm_magic == VM_MAGIC_VER2
    }

    /// Mask used for all data-base accesses (VM_LoadQVM):
    /// next power of two of (dataLength + litLength + bssLength), minus one.
    pub fn data_mask(&self) -> u32 {
        let total = self.data_length as u64 + self.lit_length as u64 + self.bss_length as u64;
        let mut mask: u64 = 1;
        while total > mask {
            mask <<= 1;
        }
        (mask - 1) as u32
    }

    /// The initialized data segment as int32 words (little-endian after swap).
    pub fn data_int32(&self) -> Vec<i32> {
        as_int32(&self.data)
    }

    /// Resolve a data-space address to a printable C string literal, if it
    /// points into the literal segment (where lcc puts string constants).
    pub fn string_at(&self, addr: i32) -> Option<String> {
        if addr < self.data_length || addr >= self.data_length + self.lit_length {
            return None;
        }
        let off = (addr - self.data_length) as usize;
        let rest = &self.lit[off..];
        let end = rest.iter().position(|&b| b == 0)?;
        let s = &rest[..end];
        if s.is_empty()
            || !s
                .iter()
                .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        {
            return None;
        }
        Some(String::from_utf8_lossy(s).into_owned())
    }

    /// Look up a symbol name for a function entry instruction index.
    pub fn name_for_fn(&self, entry: usize) -> Option<&str> {
        self.names.get(&entry).map(String::as_str)
    }
}

impl fmt::Display for Qvm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QVM {} [{}] magic=0x{:08X} instr={} code={} data={} lit={} bss={}",
            self.path,
            self.module.label(),
            self.vm_magic,
            self.instruction_count,
            self.code_length,
            self.data_length,
            self.lit_length,
            self.bss_length
        )
    }
}

/// Decode a little-endian int32 buffer as a list of ints.
pub fn as_int32(buf: &[u8]) -> Vec<i32> {
    buf.chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Parse a QVM file from raw bytes.
pub fn parse(bytes: &[u8]) -> Result<Qvm, QvmError> {
    if bytes.len() < V1_HEADER_INTS * 4 {
        return Err(QvmError::TooSmall("file too small for header".into()));
    }

    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let nints = match magic {
        VM_MAGIC => V1_HEADER_INTS,
        VM_MAGIC_VER2 => V2_HEADER_INTS,
        m => return Err(QvmError::BadMagic(m)),
    };

    let rd32 = |off: usize| {
        i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };

    let mut q = Qvm {
        path: String::new(),
        vm_magic: magic,
        instruction_count: rd32(4),
        code_offset: rd32(8),
        code_length: rd32(12),
        data_offset: rd32(16),
        data_length: rd32(20),
        lit_length: rd32(24),
        bss_length: rd32(28),
        jtrg_length: if nints == V2_HEADER_INTS { rd32(32) } else { 0 },
        module: crate::traps::Module::Game,
        code: Vec::new(),
        data: Vec::new(),
        lit: Vec::new(),
        jump_table_targets: Vec::new(),
        names: HashMap::new(),
    };

    if q.bss_length < 0 || q.data_length < 0 || q.lit_length < 0 || q.code_length <= 0 {
        return Err(QvmError::BadLength("negative/zero section length".into()));
    }
    if nints == V2_HEADER_INTS && q.jtrg_length < 0 {
        return Err(QvmError::BadLength("negative jtrgLength".into()));
    }

    // code segment
    let (co, cl) = (q.code_offset as usize, q.code_length as usize);
    let end = co
        .checked_add(cl)
        .ok_or_else(|| QvmError::OutOfBounds("code overflow".into()))?;
    if end > bytes.len() {
        return Err(QvmError::OutOfBounds(
            "code segment out of file bounds".into(),
        ));
    }
    q.code = bytes[co..end].to_vec();

    // data + lit + (VER2) jtrg
    let (doff, dl) = (q.data_offset as usize, q.data_length as usize);
    let lit = q.lit_length as usize;
    let d_end = doff
        .checked_add(dl)
        .ok_or_else(|| QvmError::OutOfBounds("data overflow".into()))?;
    let l_end = d_end
        .checked_add(lit)
        .ok_or_else(|| QvmError::OutOfBounds("lit overflow".into()))?;
    if l_end > bytes.len() {
        return Err(QvmError::OutOfBounds(
            "data segment out of file bounds".into(),
        ));
    }
    q.data = bytes[doff..d_end].to_vec();
    q.lit = bytes[d_end..l_end].to_vec();

    if nints == V2_HEADER_INTS {
        let jtrg = q.jtrg_length as usize;
        let j_end = l_end
            .checked_add(jtrg)
            .ok_or_else(|| QvmError::OutOfBounds("jtrg overflow".into()))?;
        if j_end > bytes.len() {
            return Err(QvmError::OutOfBounds(
                "jump table out of file bounds".into(),
            ));
        }
        q.jump_table_targets = bytes[l_end..j_end].to_vec();
    }

    Ok(q)
}

/// Load a QVM file from disk, auto-detecting the VM module from the name.
pub fn load(path: impl AsRef<Path>) -> Result<Qvm, QvmError> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    let mut q = parse(&bytes)?;
    q.path = path.display().to_string();
    q.module = crate::traps::Module::detect(&q.path);
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: [u8; 4] = [0x44, 0x14, 0x72, 0x12];

    fn v1_header(instr: i32, code_len: i32, data_len: i32, lit_len: i32, bss_len: i32) -> Vec<u8> {
        let mut h = Vec::new();
        for v in [
            0x12721444u32,
            instr as u32,
            32u32,
            code_len as u32,
            32 + code_len as u32,
            data_len as u32,
            lit_len as u32,
            bss_len as u32,
        ] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h
    }

    #[test]
    fn parse_v1_segments() {
        let code = vec![0x03, 0x00, 0x00, 0x00]; // ENTER 0
        let data = vec![0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]; // little-endian 1,2
        let lit = b"hello\0".to_vec();
        let mut f = Vec::new();
        f.extend_from_slice(&v1_header(
            1,
            code.len() as i32,
            data.len() as i32,
            lit.len() as i32,
            8,
        ));
        f.extend_from_slice(&code);
        f.extend_from_slice(&data);
        f.extend_from_slice(&lit);

        let q = parse(&f).unwrap();
        assert!(!q.is_ver2());
        assert_eq!(q.instruction_count, 1);
        assert_eq!(q.code, code);
        // data stays in host (little-endian) order, matching ioq3 LittleLong on LE hosts
        assert_eq!(q.data, data);
        assert_eq!(q.lit, lit);
        assert_eq!(q.data_int32(), vec![1, 2]);
        // dataLength=8 + lit=6 + bss=8 = 22 -> mask 0x1F
        assert_eq!(q.data_mask(), 0x1F);
    }

    #[test]
    fn parse_ver2_jtrg() {
        let code = vec![0x00];
        let data = vec![0x00, 0x00, 0x00, 0x05];
        let lit: Vec<u8> = vec![];
        let jtrg = vec![0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00]; // little-endian 7,9

        let mut h = Vec::new();
        let hdr = 36u32;
        for v in [
            0x12721445u32,
            1u32,
            hdr,
            code.len() as u32,
            hdr + code.len() as u32,
            data.len() as u32,
            lit.len() as u32,
            8u32,
            jtrg.len() as u32,
        ] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        let mut f = h;
        f.extend_from_slice(&code);
        f.extend_from_slice(&data);
        f.extend_from_slice(&lit);
        f.extend_from_slice(&jtrg);

        let q = parse(&f).unwrap();
        assert!(q.is_ver2());
        assert_eq!(q.jtrg_length, 8);
        assert_eq!(q.jump_table_targets, vec![7, 0, 0, 0, 9, 0, 0, 0]);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut f = v1_header(0, 4, 0, 0, 0);
        f[0] = 0x99;
        assert!(matches!(parse(&f), Err(QvmError::BadMagic(_))));
    }

    #[test]
    fn magic_bytes() {
        assert_eq!(VM_MAGIC.to_le_bytes(), MAGIC);
    }
}
