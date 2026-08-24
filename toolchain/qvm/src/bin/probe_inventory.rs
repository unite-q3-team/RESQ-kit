//! Probe: inventory a .qvm — for every function collect the syscalls it
//! performs (CONST <neg>; CALL pattern) and the string literals it
//! references (CONST pointing into the literal segment).
//!
//! Usage: probe_inventory <path.qvm> [min_insns] [--strings N] [--traps]
//!   min_insns : only list functions with at least this many instructions
//!               (default 0)
//!   --strings N : print up to N strings per function (default 3)
//!   --traps    : print the trap-name histogram at the end

use std::collections::HashMap;

use qvm::{build_functions, disassemble, load, trap_name, Opcode};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = &args[0];
    let min_insns: usize = args.iter().find_map(|a| a.parse().ok()).unwrap_or(0);
    let max_strings: usize = args
        .iter()
        .position(|a| a == "--strings")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let want_traps = args.iter().any(|a| a == "--traps");

    let q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    println!("{}", q);
    println!("functions: {}", ranges.len());

    let mut trap_hist: HashMap<u32, usize> = HashMap::new();

    for (fi, &(start, end)) in ranges.iter().enumerate() {
        let len = end - start;
        if len < min_insns {
            continue;
        }
        let insns = &d.insns[start..end];

        let mut strings: Vec<String> = Vec::new();
        let mut traps: Vec<u32> = Vec::new();

        for (i, ins) in insns.iter().enumerate() {
            if let Some(opd) = ins.operand {
                if ins.op == Opcode::Const {
                    if let Some(s) = q.string_at(opd) {
                        if !strings.contains(&s) {
                            strings.push(s);
                        }
                    }
                    // CONST <neg>; CALL  => syscall
                    if let Some(next) = insns.get(i + 1) {
                        if next.op == Opcode::Call && opd < 0 {
                            let num = (-1 - opd) as u32;
                            traps.push(num);
                            *trap_hist.entry(num).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        if !strings.is_empty() || !traps.is_empty() {
            print!("fn[{fi}] insns {start}..{end} ({len})");
            if !traps.is_empty() {
                let ts: Vec<String> = traps
                    .iter()
                    .map(|&t| {
                        let n = trap_name(q.module, t).unwrap_or("?");
                        format!("{t}:{n}")
                    })
                    .collect();
                print!("  traps[{}] {}", ts.len(), ts.join(" "));
            }
            println!();
            for s in strings.iter().take(max_strings) {
                println!("    str {s:?}");
            }
        }
    }

    if want_traps {
        println!("\n== trap histogram (all functions) ==");
        let mut v: Vec<_> = trap_hist.iter().collect();
        v.sort_by_key(|(k, _)| **k);
        for (num, count) in v {
            let n = trap_name(q.module, *num).unwrap_or("?");
            println!("  trap {num} {n}: {count} uses");
        }
    }
}
