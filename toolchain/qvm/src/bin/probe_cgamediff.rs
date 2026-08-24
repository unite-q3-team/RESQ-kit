//! Sequence differential verification for the cgame module: run the same
//! multi-command vmMain sequence in two QVMs (original vs rebuilt) on
//! PERSISTENT VMs and compare the trap call sequences per command.
//!
//! Usage: probe_cgamediff <orig.qvm> <rebuilt.qvm>
//!
//! The sequence models the reference cgame vmMain dispatch (see _emit_cgame/cgame.c
//! vmMain and baseq3a code/cgame/cg_main.c): CG_Init -> 2x DrawActiveFrame ->
//! KeyEvent -> MouseEvent -> EventHandling -> CrosshairPlayer -> LastAttacker
//! -> ConsoleCommand -> Shutdown.
//!
//! Trap modeling comes from probe_common::make_handler (deterministic, so both
//! sides take the same branches even though their frame/BSS layout differs).

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{TrapLog, make_handler};
use qvm::{Emu, build_functions, disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_cgamediff <orig.qvm> <rebuilt.qvm>");
        std::process::exit(2);
    }

    // cgame vmMain commands as (msg, p1, p2, p3) — see _emit_cgame/cgame.c:
    //   msg 0 -> CG_Init(serverMessageNum, serverCommandSequence, clientNum)
    //   msg 1 -> CG_Shutdown
    //   msg 2 -> CG_ConsoleCommand
    //   msg 3 -> CG_DrawActiveFrame(serverTime, stereoView, first)
    //   msg 4 -> CG_CrosshairPlayer
    //   msg 5 -> CG_LastAttacker
    //   msg 6 -> CG_KeyEvent(key, down)
    //   msg 7 -> CG_MouseEvent(dx, dy)
    //   msg 8 -> CG_EventHandling(type)
    let seq: &[(i32, i32, i32, i32)] = &[
        (0, 100, 123, 0), // CG_INIT
        (3, 1000, 0, 0),  // CG_DRAW_ACTIVE_FRAME
        (3, 1100, 0, 0),  // CG_DRAW_ACTIVE_FRAME
        (6, 0, 0, 0),     // CG_KEY_EVENT
        (7, 0, 0, 0),     // CG_MOUSE_EVENT
        (8, 0, 0, 0),     // CG_EVENT_HANDLING
        (4, 0, 0, 0),     // CG_CROSSHAIR_PLAYER
        (5, 0, 0, 0),     // CG_LAST_ATTACKER
        (2, 0, 0, 0),     // CG_CONSOLE_COMMAND
        (1, 0, 0, 0),     // CG_SHUTDOWN
    ];
    let names = [
        "CG_INIT",
        "CG_DRAW_ACTIVE_FRAME",
        "CG_DRAW_ACTIVE_FRAME",
        "CG_KEY_EVENT",
        "CG_MOUSE_EVENT",
        "CG_EVENT_HANDLING",
        "CG_CROSSHAIR_PLAYER",
        "CG_LAST_ATTACKER",
        "CG_CONSOLE_COMMAND",
        "CG_SHUTDOWN",
    ];

    struct Side<'a> {
        emu: Emu<'a>,
        logs: Rc<RefCell<Vec<TrapLog>>>,
        bounds: Vec<usize>,
        results: Vec<i32>,
        step_marks: Vec<usize>,
        errors: Vec<Option<String>>,
        trap_marks: Vec<usize>,
        trap_insns: Vec<usize>,
    }

    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));

    let (start1, start2) = (build_functions(d1)[0].0, build_functions(d2)[0].0);

    fn make_side<'a>(insns: &'a [qvm::Insn], q: &'a qvm::Qvm, label: &'static str) -> Side<'a> {
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let h = make_handler(q.module, 0, logs.clone());
        let mut emu = Emu::new(insns, q).with_syscall(h).with_watch_label(label);
        emu.set_max_steps(5_000_000);
        Side {
            emu,
            logs,
            bounds: vec![0],
            results: Vec::new(),
            step_marks: vec![0],
            errors: Vec::new(),
            trap_marks: vec![0],
            trap_insns: Vec::new(),
        }
    }

    let mut s1 = make_side(&d1.insns, q1, "orig");
    let mut s2 = make_side(&d2.insns, q2, "rebld");

    if std::env::var("QVM_SEQ_MEMDIFF").is_ok() {
        let (d1, d2) = (&s1.emu.mem.data, &s2.emu.mem.data);
        let n = d1.len().min(d2.len());
        let mut count = 0usize;
        for off in (0..n).step_by(4) {
            let a = i32::from_le_bytes([d1[off], d1[off + 1], d1[off + 2], d1[off + 3]]);
            let b = i32::from_le_bytes([d2[off], d2[off + 1], d2[off + 2], d2[off + 3]]);
            if a != b {
                count += 1;
                if count <= 12 {
                    println!(
                        "      INIT mem[0x{off:x}] orig {a:>10} ({a:#010x}) vs rebld {b:>10} ({b:#010x})"
                    );
                }
            }
        }
        println!(
            "      INITIAL: {count} differing words (masks {:#x}/{:#x})",
            s1.emu.mem.data_mask, s2.emu.mem.data_mask
        );
    }

    for (ci, cmd) in seq.iter().copied().enumerate() {
        if cmd.0 == 0 {
            if let Ok(v) = std::env::var("QVM_WATCH") {
                let w = i32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
                s1.emu.watch_store = Some(w);
                s2.emu.watch_store = Some(w);
            }
        }
        let (r1, e1) = match s1.emu.call(start1, &[cmd.0, cmd.1, cmd.2, cmd.3]) {
            Ok(v) => (v, None),
            Err(e) => (i32::MIN, Some(format!("{e}"))),
        };
        s1.results.push(r1);
        s1.errors.push(e1);
        s1.bounds.push(s1.logs.borrow().len());
        s1.step_marks.push(s1.emu.stats.steps);
        let m1 = s1.trap_marks.last().copied().unwrap_or(0) + s1.emu.trap_insns.len();
        s1.trap_marks.push(m1);
        s1.trap_insns.extend_from_slice(&s1.emu.trap_insns);

        let (r2, e2) = match s2.emu.call(start2, &[cmd.0, cmd.1, cmd.2, cmd.3]) {
            Ok(v) => (v, None),
            Err(e) => (i32::MIN, Some(format!("{e}"))),
        };
        s2.results.push(r2);
        s2.errors.push(e2);
        s2.bounds.push(s2.logs.borrow().len());
        s2.step_marks.push(s2.emu.stats.steps);
        let m2 = s2.trap_marks.last().copied().unwrap_or(0) + s2.emu.trap_insns.len();
        s2.trap_marks.push(m2);
        s2.trap_insns.extend_from_slice(&s2.emu.trap_insns);

        if std::env::var("QVM_SEQ_MEMDIFF").is_ok() {
            let (d1, d2) = (&s1.emu.mem.data, &s2.emu.mem.data);
            let n = d1.len().min(d2.len());
            let mut shown = 0usize;
            let mut first = None;
            for off in (0..n).step_by(4) {
                let a = i32::from_le_bytes([d1[off], d1[off + 1], d1[off + 2], d1[off + 3]]);
                let b = i32::from_le_bytes([d2[off], d2[off + 1], d2[off + 2], d2[off + 3]]);
                if a != b && first.is_none() {
                    first = Some(off);
                }
                if a != b && shown < 16 {
                    println!(
                        "      mem[0x{off:x}] orig {a:>10} ({a:#010x}) vs rebld {b:>10} ({b:#010x})"
                    );
                    shown += 1;
                }
            }
            match first {
                Some(off) => println!(
                    "      first memory divergence at 0x{off:x} ({} words differ, {} shown)",
                    n / 4,
                    shown
                ),
                None => println!("      memory identical ({} bytes)", n),
            }
        }
    }

    let logs1 = s1.logs.borrow();
    let logs2 = s2.logs.borrow();

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

    let mut total_diffs = 0usize;
    for (i, name) in names.iter().enumerate().take(s1.bounds.len() - 1) {
        let l1 = &logs1[s1.bounds[i]..s1.bounds[i + 1]];
        let l2 = &logs2[s2.bounds[i]..s2.bounds[i + 1]];
        let t1 = &s1.trap_insns[s1.trap_marks[i]..s1.trap_marks[i + 1]];
        let t2 = &s2.trap_insns[s2.trap_marks[i]..s2.trap_marks[i + 1]];
        let steps1 = s1.step_marks[i + 1] - s1.step_marks[i];
        let steps2 = s2.step_marks[i + 1] - s2.step_marks[i];
        let mut diffs = 0usize;
        let mut diff_lines = Vec::new();
        for j in 0..l1.len().max(l2.len()) {
            let (x, y) = (l1.get(j), l2.get(j));
            if x != y {
                diffs += 1;
                let xi = t1.get(j).map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns1, i)));
                let yi = t2.get(j).map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns2, i)));
                diff_lines.push(format!(
                    "      #{j}: orig {:?} {} vs rebuilt {:?} {}",
                    x.map(|t| (t.name.clone(), t.args.clone())),
                    xi.unwrap_or_default(),
                    y.map(|t| (t.name.clone(), t.args.clone())),
                    yi.unwrap_or_default()
                ));
            }
        }
        let r1 = s1.results[i];
        let r2 = s2.results[i];
        if r1 != r2 {
            diffs += 1;
            diff_lines.push(format!("      result: orig {r1} vs rebuilt {r2}"));
        }
        total_diffs += diffs;
        let status = if diffs == 0 { "OK" } else { "MISMATCH" };
        println!(
            "{name:>24}: traps {:>3} vs {:>3}  result {:>6} vs {:>6}  steps {:>7} vs {:>7}  {status}",
            l1.len(),
            l2.len(),
            r1,
            r2,
            steps1,
            steps2
        );
        for dl in diff_lines {
            println!("{dl}");
        }
        if diffs != 0 && std::env::var("QVM_SEQ_VERBOSE").is_ok() {
            for (j, t) in l1.iter().enumerate() {
                let ti = t1
                    .get(j)
                    .map(|&i| format!(" insn {i}, fn[{}]", fn_of(&fns1, i)))
                    .unwrap_or_default();
                println!("      orig #{j}: {}({:?}){ti}", t.name, t.args);
            }
            for (j, t) in l2.iter().enumerate() {
                let ti = t2
                    .get(j)
                    .map(|&i| format!(" insn {i}, fn[{}]", fn_of(&fns2, i)))
                    .unwrap_or_default();
                println!("      rebld #{j}: {}({:?}){ti}", t.name, t.args);
            }
        }
        if let (Some(e1), Some(e2)) = (&s1.errors[i], &s2.errors[i]) {
            println!("      orig error: {e1}  rebuilt error: {e2}");
        } else if let Some(e2) = &s2.errors[i] {
            println!("      rebuilt error: {e2}");
        } else if let Some(e1) = &s1.errors[i] {
            println!("      orig error: {e1}");
        }
    }
    println!("total mismatches: {total_diffs}");
}
