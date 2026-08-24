use qvm::loader::{load, Qvm};
use qvm::{disassemble, Opcode};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() {
        eprintln!("usage: probe_load <qvm>");
        std::process::exit(2);
    }
    let q: Qvm = load(&a[0]).expect("load");
    let d = disassemble(&q).expect("disasm");
    println!("insns = {}", d.insns.len());
    println!("expected = {}", q.instruction_count);

    // opcode histogram
    use std::collections::BTreeMap;
    let mut hist: BTreeMap<Opcode, usize> = BTreeMap::new();
    for ins in &d.insns {
        *hist.entry(ins.op).or_insert(0) += 1;
    }
    for (op, c) in &hist {
        println!("{:<12} {:>8}", op.name(), c);
    }

    // show the first function (until first LEAVE-close pattern is skipped):
    // just print first 40 insns
    println!("--- first 40 ---");
    for ins in d.insns.iter().take(40) {
        println!("{ins}");
    }
}
