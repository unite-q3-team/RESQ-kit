//! Probe: resolve string_at() for a list of data/lit offsets (handles both
//! the data segment and the lit segment, unlike probe_data which only covers
//! data_int32()).
//! Usage: probe_strat <path.qvm> <off1> [<off2> ...]

use qvm::load;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let q = load(&a[0]).expect("load qvm");
    for off_s in &a[1..] {
        let off: i32 = off_s.trim_start_matches("0x").parse().unwrap_or(0);
        match q.string_at(off) {
            Some(s) => println!("off={off}: {s:?}"),
            None => println!("off={off}: <no string>"),
        }
    }
}
