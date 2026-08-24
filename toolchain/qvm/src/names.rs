//! Symbol-name support: parse q3asm `.map` files.
//!
//! `q3asm -m` writes a map file whose lines are:
//!
//! ```text
//! <seg> <addr-hex> <name>
//! ```
//!
//! Traps are listed with a negative instruction address (`0xfffffdbf` for
//! trap 576 => index `-1-num`); functions have a positive instruction index
//! (verified: `G_InitGame` at `0x51c` = insn 1308 = the entry of fn[9] in the
//! decompiled baseq3a game). Names may carry a `^N` uniqueness suffix
//! (`G_InitGame^0`).

use std::collections::HashMap;
use std::io::Read;

/// Parse map text into `(insn_start, name)` for function symbols only
/// (positive addresses). The `^N` suffix is stripped. Duplicate starts keep
/// the first entry.
pub fn parse_map(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(seg), Some(addr), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if seg != "0" {
            continue;
        }
        let Ok(v) = u64::from_str_radix(addr, 16) else {
            continue;
        };
        if v > 0x1_0000_0000 {
            continue; // trap / negative sentinel
        }
        let name = name.split('^').next().unwrap_or(name).to_string();
        out.push((v as usize, name));
    }
    out.sort_by_key(|(a, _)| *a);
    out.dedup_by_key(|(a, _)| *a);
    out
}

/// Load and parse a `.map` file.
pub fn load_map(path: &str) -> std::io::Result<Vec<(usize, String)>> {
    let mut buf = String::new();
    std::fs::File::open(path)?.read_to_string(&mut buf)?;
    Ok(parse_map(&buf))
}

/// Index by start address for O(1) lookup.
pub fn index(map: &[(usize, String)]) -> HashMap<usize, &str> {
    map.iter().map(|(a, n)| (*a, n.as_str())).collect()
}
