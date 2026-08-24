use qvm::{build_all, decompile_function, disassemble, load, Terminator};

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: probe_switch <qvm>");
        std::process::exit(2);
    });
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let cfgs = build_all(&d, &q);
    let data = q.data_int32();

    let mut total_switches = 0usize;
    let mut bad = 0usize;
    let mut switch_fns = 0usize;
    let mut max_cases = 0usize;
    for (fi, cfg) in cfgs.iter().enumerate() {
        let frame = d.insns[cfg.entry].operand.unwrap_or(0);
        let f = decompile_function(&d, cfg, frame, &data);
        let n = f
            .blocks
            .iter()
            .filter(|b| matches!(b.term, Terminator::Switch { .. }))
            .count();
        if n > 0 {
            switch_fns += 1;
            total_switches += n;
        }
        for b in &f.blocks {
            if let Terminator::Switch { sel, cases, default } = &b.term {
                max_cases = max_cases.max(cases.len());
                for (_, t) in cases {
                    if *t < cfg.start || *t >= cfg.end {
                        bad += 1;
                        println!("BAD fn[{fi}] block@{} case target {t} outside [{}, {})", b.start, cfg.start, cfg.end);
                    }
                }
                if let Some(dflt) = default {
                    if *dflt < cfg.start || *dflt >= cfg.end {
                        bad += 1;
                        println!("BAD fn[{fi}] block@{} default target {dflt} outside [{}, {})", b.start, cfg.start, cfg.end);
                    }
                }
                let _ = sel;
            }
        }
    }
    println!(
        "functions={} switch_fns={} total_switches={} max_cases={} bad_targets={}",
        cfgs.len(),
        switch_fns,
        total_switches,
        max_cases,
        bad
    );
}
