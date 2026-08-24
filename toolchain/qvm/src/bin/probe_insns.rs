use qvm::{disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() {
        eprintln!("usage: probe_insns <qvm>");
        std::process::exit(2);
    }
    let q = load(&a[0]).expect("load");
    let _d = disassemble(&q).expect("disasm");
    let data = q.data_int32();
    let base = 7080usize;
    println!("table @ data+{base} (data_len={}):", data.len() * 4);
    for k in 0..20 {
        let off = base / 4 + k;
        if off < data.len() {
            println!("  [{}] offset={} value={}", k, off * 4, data[off]);
        }
    }
}
