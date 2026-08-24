//! Probe: dump data words (and strings / f32 at those words) around a byte offset.
//! Usage: probe_data <path.qvm> <start_byte> <n_words>
//!
//! CONST color pointers are often ±4 and not 16-byte aligned. A dword that
//! looks like 1.0 may be the alpha of the previous vec4 — use dump.py color.

use qvm::{disassemble, load};

fn looks_like_channel(f: f32) -> bool {
    f.is_finite() && (-0.05..=1.05).contains(&f)
}

fn fmt_f(bits: i32) -> String {
    let f = f32::from_bits(bits as u32);
    if !f.is_finite() {
        return String::new();
    }
    format!("  f={f}")
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let q = load(&a[0]).expect("load qvm");
    let _d = disassemble(&q).expect("disasm");
    let start: usize = a[1].trim_start_matches("0x").parse().unwrap_or(0);
    let n: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(32);
    let data = q.data_int32();
    for i in 0..n {
        let off = start + 4 * i;
        let idx = off / 4;
        if idx >= data.len() {
            break;
        }
        let v = data[idx];
        let s = q.string_at(off as i32).unwrap_or_default();
        let mut extra = if s.is_empty() {
            fmt_f(v)
        } else {
            format!("  string: {s:?}")
        };
        if s.is_empty() && idx + 3 < data.len() {
            let rgba: [f32; 4] = std::array::from_fn(|k| f32::from_bits(data[idx + k] as u32));
            if rgba.iter().copied().all(looks_like_channel) && rgba[3] >= 0.2 {
                extra.push_str(&format!(
                    "  vec4({}, {}, {}, {})",
                    rgba[0], rgba[1], rgba[2], rgba[3]
                ));
            }
        }
        println!("data[0x{off:06x}] = {v:>12} (0x{v:08x}){extra}");
    }
}
