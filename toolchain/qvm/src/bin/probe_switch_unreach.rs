use qvm::{build_all, decompile_function, disassemble, load, Terminator};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: probe_switch_unreach <qvm>");
        std::process::exit(2);
    });
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let cfgs = build_all(&d, &q);
    let data = q.data_int32();

    for (fi, cfg) in cfgs.iter().enumerate() {
        let frame = d.insns[cfg.entry].operand.unwrap_or(0);
        let f = decompile_function(&d, cfg, frame, &data);
        for (bi, b) in f.blocks.iter().enumerate() {
            if let Terminator::Switch { cases, .. } = &b.term {
                println!("fn[{fi}] block {bi} @{} cases={}", b.start, cases.len());
            }
        }
    }
}
