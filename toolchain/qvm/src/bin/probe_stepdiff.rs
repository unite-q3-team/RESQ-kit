//! Step-level differential diagnosis of the DISCONNECT mismatch: run the same
//! persistent command sequence in an original and a rebuilt QVM (budget rule
//! identical to probe_seqdiff: only the rebuilt side is capped, and only at the
//! DISCONNECT command), capture the DISCONNECT pc stream on both sides and:
//!   - print per-command result/steps/traps (must reproduce the seqdiff picture);
//!   - dump the instruction tail after the LAST trap of DISCONNECT on both
//!     sides (seqdiff shows traps match 12/12, so divergence is post-trap);
//!   - if the rebuilt side never returns, find the runaway cycle: the first pc
//!     that occurs 3+ times in the post-last-trap tail.
//!
//! Usage: probe_stepdiff <orig.qvm> <rebuilt.qvm> [names]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use qvm::probe_common::{TrapLog, make_handler};
use qvm::{Emu, build_functions, disassemble, load};

const SEQ: &[(i32, i32, i32, i32)] = &[
    (0, 100, 123, 0),   // GAME_INIT
    (2, 0, 1, 0),       // GAME_CLIENT_CONNECT
    (3, 0, 0, 0),       // GAME_CLIENT_BEGIN
    (4, 0, 0, 0),       // GAME_CLIENT_USERINFO_CHANGED
    (7, 0, 0, 0),       // GAME_CLIENT_THINK
    (8, 1000, 0, 0),    // GAME_RUN_FRAME
    (8, 1100, 0, 0),    // GAME_RUN_FRAME
    (5, 0, 0, 0),       // GAME_CLIENT_DISCONNECT  <-- focus
    (1, 0, 0, 0),       // GAME_SHUTDOWN
];

fn fn_of(ranges: &[(usize, usize)], idx: usize) -> usize {
    let mut lo = 0;
    let mut hi = ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if ranges[mid].1 <= idx {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_stepdiff <orig.qvm> <rebuilt.qvm> [names] [map]");
        std::process::exit(2);
    }
    let names_path = a.get(2);
    let map_path = a.get(3);

    let mut q1 = load(&a[0]).expect("load orig");
    let mut q2 = load(&a[1]).expect("load rebuilt");
    let d1 = Box::leak(Box::new(disassemble(&q1).expect("disasm orig")));
    let d2 = Box::leak(Box::new(disassemble(&q2).expect("disasm rebuilt")));

    let ranges1 = build_functions(&d1);
    let ranges2 = build_functions(&d2);
    let (start1, start2) = (ranges1[0].0, ranges2[0].0);

    // attach names from `fn[<idx>] <name>` lines by entry insn of each function
    // (the `.names` file and `build_functions` share the same linear order).
    let mut names: Vec<String> = Vec::new();
    if let Some(np) = names_path {
        for line in std::fs::read_to_string(np).expect("read names").lines() {
            let mut it = line.split_whitespace();
            let (Some(idx), Some(name)) = (it.next(), it.next()) else {
                continue;
            };
            if let Ok(i) = idx.trim_start_matches("fn[").trim_end_matches(']').parse::<usize>() {
                if names.len() <= i {
                    names.resize(i + 1, String::new());
                }
                names[i] = name.to_string();
            }
        }
        for (i, n) in names.iter().enumerate() {
            if !n.is_empty() {
                if let Some(&entry) = ranges1.get(i).map(|r| &r.0) {
                    q1.names.insert(entry, n.clone());
                }
            }
        }
    }

    // For the REBUILT module the fn indices do not match the orig `.names`
    // file (q3asm drops unreferenced functions), so resolve names from the
    // q3asm `.map` (lines `insn name`, in address order = build_functions order).
    if let Some(mp) = map_path {
        let mut mapped = 0;
        for line in std::fs::read_to_string(mp).expect("read map").lines() {
            let mut it = line.split_whitespace();
            let (Some(a0), Some(a1), Some(name)) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let Ok(insn) = usize::from_str_radix(a1, 16) else { continue };
            if a0 != "0" {
                continue;
            }
            if let Some(&entry) = ranges2.iter().find(|r| r.0 == insn).map(|r| &r.0) {
                q2.names.insert(entry, name.to_string());
                mapped += 1;
            }
        }
        eprintln!("stepdiff: mapped {mapped}/{} rebuilt functions from {mp}", ranges2.len());
    }

    fn name_of(q: &qvm::Qvm, ranges: &[(usize, usize)], idx: usize) -> String {
        let (s, _) = ranges[idx];
        q.name_for_fn(s).map(|n| n.to_string()).unwrap_or_else(|| format!("fn[{idx}]"))
    }

    let logs1: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let logs2: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let pcs1: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
    let pcs2: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
    let mut e1 = Emu::new(&d1.insns, &q1).with_syscall(make_handler(q1.module, 0, logs1.clone()));
    let mut e2 = Emu::new(&d2.insns, &q2).with_syscall(make_handler(q2.module, 0, logs2.clone()));
    e1.step_pcs = Some(pcs1.clone());
    e2.step_pcs = Some(pcs2.clone());

    let mut dis1: Vec<usize> = Vec::new();
    let mut dis2: Vec<usize> = Vec::new();
    let mut t1: Vec<usize> = Vec::new();
    let mut t2: Vec<usize> = Vec::new();

    for (i, cmd) in SEQ.iter().enumerate() {
        if cmd.0 == 5 {
            pcs1.borrow_mut().clear();
            pcs2.borrow_mut().clear();
        }
        // seqdiff budget rule: rebuilt is capped only at DISCONNECT, window =
        // cumulative steps before it + 50k; everything else runs uncapped.
        if cmd.0 == 5 {
            e2.set_max_steps(e2.stats.steps + 50_000);
        }
        let r1 = e1.call(start1, &[cmd.0, cmd.1, cmd.2, cmd.3]);
        let r2 = e2.call(start2, &[cmd.0, cmd.1, cmd.2, cmd.3]);
        let r1v = match &r1 {
            Ok(v) => format!("Some({v})"),
            Err(e) => format!("Err({e})"),
        };
        let r2v = match &r2 {
            Ok(v) => format!("Some({v})"),
            Err(e) => format!("Err({e})"),
        };
        println!(
            "cmd[{}] msg={} orig {r1v:>14} steps={} traps={} || rebld {r2v:>14} steps={} traps={}",
            i,
            cmd.0,
            e1.stats.steps,
            logs1.borrow().len(),
            e2.stats.steps,
            logs2.borrow().len(),
        );
        if cmd.0 == 5 {
            dis1 = pcs1.borrow().clone();
            dis2 = pcs2.borrow().clone();
            t1 = e1.trap_insns.clone();
            t2 = e2.trap_insns.clone();
        }
    }

    println!("\nDISCONNECT: orig {} steps / {} traps || rebld {} steps / {} traps", dis1.len(), t1.len(), dis2.len(), t2.len());

    // ---- dump the tail after the LAST trap of DISCONNECT on both sides ----
    // (traps match per seqdiff, so the divergence is in the return path)
    let dump_tail = |pcs: &[usize], d: &qvm::disasm::Disassembly, ranges: &[(usize, usize)], q: &qvm::Qvm, traps: &[usize], label: &str| {
        if traps.is_empty() {
            println!("\n{label}: no traps; showing first 60 steps:");
            let n = pcs.len().min(60);
            for (j, &x) in pcs.iter().enumerate().take(n) {
                let f = fn_of(ranges, x);
                println!("  step {j:>6} fn[{f}]{:<18} {}", name_of(q, ranges, f), d.insns[x]);
            }
            return;
        }
        let last_trap = traps[traps.len() - 1];
        let pos = pcs.iter().position(|&x| x == last_trap).unwrap_or(0);
        println!("\n{label}: after last trap (step {pos}/{}, trap insn #{last_trap}):", pcs.len());
        for (j, &x) in pcs.iter().enumerate().skip(pos).take(80) {
            let f = fn_of(ranges, x);
            println!("  step {j:>6} fn[{f}]{:<18} {}", name_of(q, ranges, f), d.insns[x]);
        }
    };
    dump_tail(&dis1, &d1, &ranges1, &q1, &t1, "orig ");
    dump_tail(&dis2, &d2, &ranges2, &q2, &t2, "rebld");

    // ---- runaway cycle in the rebuilt post-last-trap tail ----
    if !t2.is_empty() {
        let last_trap = t2[t2.len() - 1];
        let pos = dis2.iter().position(|&x| x == last_trap).unwrap_or(0);
        let tail = &dis2[pos..];
        let mut first_seen: HashMap<usize, usize> = HashMap::new();
        let mut second: HashMap<usize, usize> = HashMap::new();
        let mut cycle = None;
        for (k, &pc) in tail.iter().enumerate() {
            if let Some(&k1) = first_seen.get(&pc) {
                if let Some(&k2) = second.get(&pc) {
                    cycle = Some((k, k2, k1, pc));
                    break;
                }
                second.insert(pc, k);
            } else {
                first_seen.insert(pc, k);
            }
        }
        match cycle {
            Some((k3, k2, k1, pc)) => {
                let f = fn_of(&ranges2, pc);
                println!("\nrebld RUNAWAY: pc #{pc} at tail steps {k1}, {k2}, {k3} (period {}) in fn[{}]={}", k2 - k1, f, name_of(&q2, &ranges2, f));
                let mut body: Vec<usize> = tail[k1..k2].to_vec();
                body.sort_unstable();
                body.dedup();
                for &c in &body {
                    println!("    {}{}", if c == pc { "*" } else { " " }, d2.insns[c]);
                }
            }
            None => println!("\nno pc repeats 3x in rebuilt DISCONNECT tail (runaway unlikely)"),
        }
    }
}
