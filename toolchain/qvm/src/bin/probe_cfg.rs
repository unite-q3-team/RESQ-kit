use qvm::cfg::{build_cfg, build_functions};
use qvm::loader::{load, Qvm};
use qvm::{disassemble, Opcode};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() {
        eprintln!("usage: probe_cfg <qvm>");
        std::process::exit(2);
    }
    let q: Qvm = load(&a[0]).expect("load");
    let d = disassemble(&q).expect("disasm");

    let ranges = build_functions(&d);
    println!("functions = {}", ranges.len());

    let data = q.data_int32();
    let mut block_total = 0usize;
    let mut max_blocks = (0usize, 0usize); // (blocks, fn_start)
    let mut cfgs = Vec::new();
    for r in &ranges {
        if let Some(cfg) = build_cfg(&d, *r, &data) {
            block_total += cfg.blocks.len();
            if cfg.blocks.len() > max_blocks.0 {
                max_blocks = (cfg.blocks.len(), cfg.start);
            }
            cfgs.push(cfg);
        }
    }
    println!("cfgs = {}", cfgs.len());
    println!("total blocks = {block_total}");
    println!("max blocks in fn#{} = {}", max_blocks.1, max_blocks.0);

    // verify against Python: 1144 functions, ENTER=1144, no UNDEF
    let enter = d.insns.iter().filter(|i| i.op == Opcode::Enter).count();
    let undef = d.insns.iter().filter(|i| i.op == Opcode::Undef).count();
    println!("ENTER = {enter}, UNDEF = {undef}");

    // count resolved indirect jumps via pattern A (CONST JUMP) = returns
    let mut ret_jumps = 0;
    for r in &ranges {
        let (s, e) = *r;
        for i in s..e {
            if d.insns[i].op == Opcode::Jump && i > s && d.insns[i - 1].op == Opcode::Const {
                ret_jumps += 1;
            }
        }
    }
    println!("JUMP preceded by CONST (returns/const-jumps) = {ret_jumps}");

    // show the first function CFG
    let first = build_cfg(&d, ranges[0], &data).unwrap();
    println!("--- first function: {} blocks ---", first.blocks.len());
    for (bi, b) in first.blocks.iter().enumerate() {
        let last = &d.insns[b.end - 1];
        println!(
            "B#{} [{:#x}..{:#x}] last={} succ={:?}",
            bi, b.start, b.end, last, b.succ
        );
    }
    let _ = Opcode::Enter; // silence unused import warning if path unused
}
