//! Scan a QVM for stores to a given address (via CONST <addr>; ...; STORE4)
//! to find bytecode stores the decompiler dropped.

use qvm::{build_functions, disassemble, load, Opcode};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_findstore <qvm> <addr>");
        std::process::exit(2);
    }
    let addr: i32 = a[1].parse().unwrap();
    let q = load(&a[0]).expect("load");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);

    let mut fn_of = vec![usize::MAX; d.insns.len()];
    for (fi, &(s, e)) in ranges.iter().enumerate() {
        for i in s..e {
            fn_of[i] = fi;
        }
    }

    let mut hits = 0;
    let mut i = 0;
    let n = d.insns.len();
    while i < n {
        let insn = &d.insns[i];
        if insn.op == Opcode::Const && insn.operand == Some(addr) {
            // look ahead for STORE4 within a few instructions (address pushed
            // as r1 under the value); value must be pushed after it.
            let mut j = i + 1;
            while j < n && j < i + 12 {
                let c = &d.insns[j];
                if c.op == Opcode::Store4 {
                    hits += 1;
                    println!(
                        "store to {addr} at insn {j} (fn[{}], insns {:?}); const pushed at {i}",
                        fn_of[j],
                        ranges.get(fn_of[j])
                    );
                    // print the nearby instructions
                    let lo = i.saturating_sub(2);
                    for k in lo..=j {
                        println!("    [{k}] {:?}", d.insns[k]);
                    }
                    break;
                }
                j += 1;
            }
            if j >= i + 12 {
                println!(
                    "const {addr} at insn {i} (fn[{}]) with no STORE4 nearby",
                    fn_of[i]
                );
            }
        }
        i += 1;
    }
    println!("total hits: {hits}");
}
