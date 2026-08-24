use qvm::{build_all, decompile_function, disassemble, fmt_function, load};

fn main() {
    let path = std::env::args().nth(1).expect("path");
    let which: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    println!(
        "{}: magic={:#x} instrs={} code={} data={} lit={} bss={}",
        path,
        q.vm_magic,
        q.instruction_count,
        q.code_length,
        q.data_length,
        q.lit_length,
        q.bss_length
    );
    let cfgs = build_all(&d, &q);
    println!("functions: {}", cfgs.len());
    if let Some(cfg) = cfgs.get(which) {
        let frame = d.insns[cfg.entry].operand.unwrap_or(0);
        let data = q.data_int32();
        let f = decompile_function(&d, cfg, frame, &data);
        println!("{}", fmt_function(&f, &q));
    }
}
