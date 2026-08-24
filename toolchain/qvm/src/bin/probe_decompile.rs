use qvm::{build_all, decompile_function, disassemble, fmt_function, load};

fn main() {
    let path = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("usage: probe_decompile <fn_index> <qvm>");
        std::process::exit(2);
    });
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");

    let cfgs = build_all(&d, &q);
    println!("functions: {}", cfgs.len());

    let which: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Some(cfg) = cfgs.get(which) {
        let frame = d.insns[cfg.entry].operand.unwrap_or(0);
        let data = q.data_int32();
        let f = decompile_function(&d, cfg, frame, &data);
        println!("{}", fmt_function(&f, &q));
    } else {
        for (i, cfg) in cfgs.iter().take(5).enumerate() {
            println!("[{i}] entry={} blocks={}", cfg.entry, cfg.blocks.len());
        }
    }
}
