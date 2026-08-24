//! Check the identity mapping of the rebuilt data image: dump raw data bytes
//! around a few offsets so we can tell whether rebuilt array[k] == blob[k]
//! (identity) or blob[k+4] (shifted by the q3asm 4-byte reservation).
//! Usage: probe_shift <orig.qvm> <offsets...>

use qvm::load;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_shift <orig.qvm> <off...>");
        std::process::exit(2);
    }
    let q = load(&a[0]).expect("load");
    let data = &q.data;
    let offs: Vec<usize> = a[1..].iter().map(|s| s.parse().unwrap()).collect();
    for &o in &offs {
        let mut bytes = Vec::new();
        for k in o..o + 24 {
            let b = if k < data.len() { data[k] } else { 0 };
            bytes.push(b);
        }
        let printable: String = bytes
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        println!("off {o}: {bytes:02x?}  '{printable}'");
    }
}
