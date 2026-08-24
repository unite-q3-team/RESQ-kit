//! Targeted console-command dispatch check: run CG_Init then CG_ConsoleCommand
//! with a real command string (from argv[0] via QVM_ARGV0-style modeling) in the
//! original vs the rebuilt cgame, and compare trap sequences + result.
//!
//! Usage: probe_cgcmd <orig.qvm> <rebuilt.qvm> <cmd> [cmd...]
//!
//! The command table (data 3084, 66 {name, handler} pairs) is reached through an
//! INDIRECT call `(*(int*)(base + idx*8))()`; handlers that live below
//! blob_len were historically not blob-relocated, so rebuilt dispatch jumped
//! into the middle of unrelated functions. This probe verifies each command
//! dispatches identically on both sides.

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{make_handler, TrapLog};
use qvm::{build_functions, disassemble, load, Emu};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        eprintln!("usage: probe_cgcmd <orig.qvm> <rebuilt.qvm> <cmd> [cmd...]");
        std::process::exit(2);
    }
    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));
    let (start1, start2) = (build_functions(d1)[0].0, build_functions(d2)[0].0);

    struct Side<'a> {
        emu: Emu<'a>,
        logs: Rc<RefCell<Vec<TrapLog>>>,
        start: usize,
    }
    fn make_side<'a>(
        insns: &'a [qvm::Insn],
        q: &'a qvm::Qvm,
        start: usize,
        label: &'static str,
    ) -> Side<'a> {
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let h = make_handler(q.module, 0, logs.clone());
        let mut emu = Emu::new(insns, q).with_syscall(h).with_watch_label(label);
        emu.set_max_steps(20_000_000);
        Side { emu, logs, start }
    }

    let mut s1 = make_side(&d1.insns, q1, start1, "orig");
    let mut s2 = make_side(&d2.insns, q2, start2, "rebld");
    // CG_INIT(100, 123, 0) first so cg state exists.
    for s in [&mut s1, &mut s2] {
        let r = match s.emu.call(s.start, &[0, 100, 123, 0]) {
            Ok(v) => v.to_string(),
            Err(e) => format!("error: {e}"),
        };
        println!("CG_INIT -> {r}");
        s.logs.borrow_mut().clear();
        s.emu.trap_insns.clear();
    }

    let fns1 = build_functions(d1);
    let fns2 = build_functions(d2);
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

    let mut total = 0usize;
    for cmd in &a[2..] {
        std::env::set_var("QVM_ARGV0", cmd);
        let (r1, e1) = match s1.emu.call(s1.start, &[2, 0, 0, 0]) {
            Ok(v) => (v, None),
            Err(e) => (i32::MIN, Some(format!("{e}"))),
        };
        let (r2, e2) = match s2.emu.call(s2.start, &[2, 0, 0, 0]) {
            Ok(v) => (v, None),
            Err(e) => (i32::MIN, Some(format!("{e}"))),
        };
        let logs1 = s1.logs.borrow().clone();
        let logs2 = s2.logs.borrow().clone();
        let t1 = s1.emu.trap_insns.clone();
        let t2 = s2.emu.trap_insns.clone();
        s1.logs.borrow_mut().clear();
        s2.logs.borrow_mut().clear();
        s1.emu.trap_insns.clear();
        s2.emu.trap_insns.clear();

        let mut diffs = 0usize;
        let mut lines = Vec::new();
        for j in 0..logs1.len().max(logs2.len()) {
            let (x, y) = (logs1.get(j), logs2.get(j));
            if x != y {
                diffs += 1;
                let xi = t1
                    .get(j)
                    .map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns1, i)));
                let yi = t2
                    .get(j)
                    .map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns2, i)));
                lines.push(format!(
                    "        #{j}: orig {:?} {} vs rebuilt {:?} {}",
                    x.map(|t| (t.name.clone(), t.args.clone())),
                    xi.unwrap_or_default(),
                    y.map(|t| (t.name.clone(), t.args.clone())),
                    yi.unwrap_or_default()
                ));
            }
        }
        let err = match (&e1, &e2) {
            (None, None) => String::new(),
            (e1, e2) => format!("  ERR orig={:?} rebld={:?}", e1, e2),
        };
        if r1 != r2 {
            diffs += 1;
            lines.push(format!("        result: orig {r1} vs rebuilt {r2}"));
        }
        total += diffs;
        let status = if diffs == 0 && e1.is_none() && e2.is_none() {
            "OK"
        } else {
            "MISMATCH"
        };
        println!(
            "  {cmd:>18}: traps {:>3} vs {:>3}  result {:>6} vs {:>6}  steps {:>7} vs {:>7}  {status}{err}",
            logs1.len(),
            logs2.len(),
            r1,
            r2,
            s1.emu.stats.steps,
            s2.emu.stats.steps
        );
        for l in lines {
            println!("{l}");
        }
    }
    println!("total mismatches: {total}");
}
