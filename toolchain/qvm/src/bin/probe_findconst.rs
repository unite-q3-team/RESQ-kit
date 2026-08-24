//! Probe: find all CONST <value> instructions in the code and show the
//! following opcode (how the constant is used).
//! Usage: probe_findconst <path.qvm> <value> [limit]

use qvm::{disassemble, load};
use qvm::Opcode;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let q = load(&a[0]).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let v: i32 = a[1].parse().expect("value");
    let limit: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
    let mut n = 0;
    for (i, ins) in d.insns.iter().enumerate() {
        if ins.op == Opcode::Const && ins.operand == Some(v) {
            let nxt = if i + 1 < d.insns.len() {
                format!("{:?}", d.insns[i + 1].op)
            } else {
                "<end>".into()
            };
            println!("insn {:6} (addr 0x{:x})  CONST {v} -> next {}", i, ins.addr, nxt);
            n += 1;
            if n >= limit {
                println!("... (limit {limit})");
                return;
            }
        }
    }
    println!("total CONST {v}: {n}");
}
