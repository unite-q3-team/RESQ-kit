//! Differential verification: run the same function in two QVMs (original vs
//! rebuilt) with identical args and compare the trap call sequences, final
//! result, and step counts.
//!
//! Usage: probe_diff <orig.qvm> <orig_fn> <rebuilt.qvm> <rebuilt_fn> [args...]
//!   args may contain a `|` to split per-module: `<orig args> | <rebuilt args>`.
//!   (Call args are VM addresses in each module's own space; both modules map
//!   the original image identity, so a blob address `c` is `c` in both.)
//!
//! Trap args are string-resolved from VM memory on both sides so that stack
//! buffer addresses (which differ between modules) compare by content, while
//! `qvm_mem + off` pointers resolve to identical strings/addresses. Int args are
//! only compared when they are blob addresses (below the stack region); stack
//! addresses that don't hold printable text render as `_`.
//!
//! q3asm reserves the first 4 bytes of the data segment (image[0..4] = 0 so
//! NULL pointers work). probe_emit skips the blob's own 0-sentinel word and
//! emits the rest starting at image[4], so blob byte b sits at image offset b:
//! absolute addresses are identity-mapped between modules and no arg
//! normalization is needed (base = 0 for both).

use qvm::probe_common::{run_once, TrapLog};
use qvm::{build_functions, disassemble, load};

fn run(
    path: &str,
    fnidx: usize,
    base: u32,
    call_args: &[i32],
) -> (Vec<TrapLog>, i32, usize, usize, bool) {
    let _ = base;
    let q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let (start, end) = ranges[fnidx];
    // lcc compiles `return;` for a void function as `PUSH; LEAVE`; the PUSH
    // only re-copies the current op-stack top, so the value left at the
    // terminal LEAVE is undefined garbage and MUST NOT be compared.
    let is_void = end >= 2
        && d.insns[end - 2].op == qvm::Opcode::Push
        && d.insns[end - 1].op == qvm::Opcode::Leave;
    eprintln!("  {path} fn[{fnidx}] insns {start}..{end} args={call_args:?}");
    let (logs, result, steps, syscalls) = run_once(&d.insns, &q, start, call_args, usize::MAX);
    (logs, result, steps, syscalls, is_void)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        eprintln!("usage: probe_diff <orig.qvm> <orig_fn> <rebuilt.qvm> <rebuilt_fn> [args...]");
        eprintln!(
            "       rebuilt_fn may be `auto` to locate the matching function by trap sequence"
        );
        std::process::exit(2);
    }
    let (orig_path, orig_fn) = (&a[0], a[1].parse::<usize>().expect("orig fn"));
    let reb_path = &a[2];
    let reb_fn = if a[3] == "auto" {
        usize::MAX
    } else {
        a[3].parse::<usize>().expect("rebuilt fn")
    };
    let argstr = a[4..].join(" ");
    let (args1, args2) = match argstr.split_once('|') {
        Some((x, y)) => (
            x.split_whitespace().map(|s| s.parse().unwrap()).collect(),
            y.split_whitespace().map(|s| s.parse().unwrap()).collect(),
        ),
        None => {
            let v: Vec<i32> = argstr
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            (v.clone(), v)
        }
    };

    let (l1, r1, s1, c1, v1) = run(orig_path, orig_fn, 0, &args1);

    let mut reb_fn = reb_fn;
    if reb_fn == usize::MAX {
        // locate the rebuilt function whose trap sequence matches the original
        let q = load(reb_path).expect("load rebuilt qvm");
        let d = disassemble(&q).expect("disasm rebuilt");
        let ranges = build_functions(&d);
        let mut cands = Vec::new();
        for k in 0..ranges.len() {
            let (l2, _r2, s2, c2, _v2) = run(reb_path, k, 0, &args2);
            if l2 == l1 {
                let score = ((s2 == s1) as usize * 2) + (c2 == c1) as usize;
                cands.push((score, k, s2, c2));
            }
        }
        cands.sort_by_key(|c| std::cmp::Reverse(c.0));
        if cands.is_empty() {
            eprintln!("--find: no rebuilt function matches the trap sequence of fn[{orig_fn}]");
            std::process::exit(3);
        }
        reb_fn = cands[0].1;
        eprintln!(
            "--find: fn[{orig_fn}] -> rebuilt fn[{reb_fn}] ({} candidates)",
            cands.len()
        );
    }

    let (l2, r2, s2, c2, v2) = run(reb_path, reb_fn, 0, &args2);

    println!(
        "orig  fn[{orig_fn}] result={r1} steps={s1} syscalls={c1} traps={}",
        l1.len()
    );
    println!(
        "rebld fn[{reb_fn}] result={r2} steps={s2} syscalls={c2} traps={}",
        l2.len()
    );
    let max = l1.len().max(l2.len());
    let mut diffs = 0;
    for i in 0..max {
        let (x, y) = (l1.get(i), l2.get(i));
        if x != y {
            diffs += 1;
            println!(
                "  DIFF trap #{i}: orig {:?} vs rebuilt {:?}",
                x.map(|t| (t.name.clone(), t.args.clone())),
                y.map(|t| (t.name.clone(), t.args.clone()))
            );
            if std::env::var("QVM_DIFF_DEBUG").is_ok() {
                println!(
                    "      orig raw   = {:?}\n      rebuilt raw = {:?}",
                    x.map(|t| &t.raw),
                    y.map(|t| &t.raw)
                );
            }
        }
    }
    if r1 != r2 {
        if v1 && v2 {
            // void epilogue (PUSH; LEAVE): the "result" is undefined garbage.
            println!(
                "  NOTE result: orig {r1} vs rebuilt {r2} (void fn: leftover op-stack, ignored)"
            );
        } else {
            diffs += 1;
            println!("  DIFF result: orig {r1} vs rebuilt {r2}");
        }
    }
    if diffs == 0 && r1 == r2 && l1.len() == l2.len() && s1 == s2 && c1 == c2 {
        println!("MATCH (identical: traps, result, steps, syscalls)");
    } else {
        println!("mismatches: {diffs} (traps+result; steps/syscalls may differ)");
    }
}
