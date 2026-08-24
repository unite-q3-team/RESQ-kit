//! probe_datacmp: compare the data+lit bytes of an original QVM against the
//! data segment of a rebuilt QVM (identity-mapped blob).
//!
//! Usage: probe_datacmp <orig.qvm> <rebuilt.qvm>

use std::env;
use std::process::exit;

use qvm::loader::load;

fn main() {
    let a: Vec<String> = env::args().collect();
    let (orig, reb) = (&a[1], &a[2]);
    let o = load(orig).expect("load orig");
    let r = load(reb).expect("load rebuilt");

    let o_mem: Vec<u8> = {
        let mut m = o.data.clone();
        m.extend_from_slice(&o.lit);
        m
    };
    let r_data = &r.data;

    let n = o_mem.len().min(r_data.len());
    let mut diffs = 0usize;
    let mut first: Vec<(usize, u8, u8)> = Vec::new();
    for i in 0..n {
        if o_mem[i] != r_data[i] {
            diffs += 1;
            if first.len() < 20 {
                first.push((i, o_mem[i], r_data[i]));
            }
        }
    }
    println!(
        "orig data+lit = {} bytes, rebuilt data = {} bytes; common = {}; byte diffs = {}",
        o_mem.len(),
        r_data.len(),
        n,
        diffs
    );
    for (i, x, y) in &first {
        println!(
            "  diff at 0x{i:06X} (orig mem): orig=0x{x:02X} rebuilt=0x{y:02X}"
        );
    }
    if diffs == 0 {
        println!("MATCH: rebuilt data segment reproduces orig data+lit at all offsets");
    } else {
        // group by 4-byte word to find meaningful mismatches
        let mut word_diffs = 0usize;
        let mut w_first: Vec<(usize, u32, u32)> = Vec::new();
        for i in (0..n).step_by(4) {
            let o4 = u32::from_le_bytes([o_mem[i], o_mem[i + 1], o_mem[i + 2], o_mem[i + 3]]);
            let r4 = u32::from_le_bytes([r_data[i], r_data[i + 1], r_data[i + 2], r_data[i + 3]]);
            if o4 != r4 {
                word_diffs += 1;
                if w_first.len() < 25 {
                    w_first.push((i, o4, r4));
                }
            }
        }
        println!("word diffs = {word_diffs}");
        for (i, x, y) in &w_first {
            println!(
                "  word diff at 0x{i:06X}: orig=0x{x:08X} rebuilt=0x{y:08X}"
            );
        }
        exit(1);
    }
}
