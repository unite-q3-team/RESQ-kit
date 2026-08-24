use qvm::{build_cfg, build_functions, disassemble, load};

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let fnidx: usize = std::env::args()
        .nth(2)
        .unwrap_or("0".into())
        .parse()
        .unwrap();
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let (start, end) = ranges[fnidx];
    let cfg = build_cfg(&d, (start, end), &q.data_int32()).expect("cfg");
    println!("fn[{fnidx}] start={start} end={end}");
    for b in &cfg.blocks {
        println!("-- block start insn {} --", b.start);
        for ins in b.insns(&d) {
            println!("  {:>6}: {:?}", ins.addr, ins);
        }
    }
}
