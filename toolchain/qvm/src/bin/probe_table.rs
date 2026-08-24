fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() {
        eprintln!("usage: probe_table <qvm>");
        std::process::exit(2);
    }
    let q = qvm::load(&a[0]).unwrap();
    let d = qvm::disassemble(&q).unwrap();
    let cfgs = qvm::build_all(&d, &q);
    let cfg = &cfgs[307];
    println!("fn[307] range {}..{}", cfg.start, cfg.end);
    let data = q.data_int32();
    for k in 0..12 {
        let t = data[13048 / 4 + k];
        println!("[{}]={}", k, t);
    }
}
