use qvm::{build_all, disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() { eprintln!("usage: probe_blocks <qvm>"); std::process::exit(2); }
    let q = load(&a[0]).expect("load");
    let d = disassemble(&q).expect("disasm");
    let cfgs = build_all(&d, &q);
    let which: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let cfg = &cfgs[which];
    println!("fn[{}] insns {}..{}  blocks={}", which, cfg.start, cfg.end, cfg.blocks.len());
    for (bi, b) in cfg.blocks.iter().enumerate() {
        println!("B{bi} [{}..{}) pred={:?} succ={:?}", b.start, b.end, b.pred, b.succ);
        for i in b.start..b.end {
            println!("   {i}: {:?}", d.insns[i]);
        }
    }
}
