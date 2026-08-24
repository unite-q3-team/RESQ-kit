//! Diagnostic: run the exact UI_KEY_SYS_UP crash-repro sequence against the
//! rebuilt ui.qvm only, with a step hook that prints the calling PC/function
//! whenever execution lands on a specific target instruction index (used to
//! find who indirectly calls into fn[129], the ArenaServers-style init that
//! should never fire from a System->Network tab Up-arrow key event).
//!
//! Usage: probe_whocalls <rebuilt.qvm> <target_pc>

use qvm::probe_common::make_handler;
use qvm::{build_functions, disassemble, load, Emu};
use std::cell::RefCell;
use std::rc::Rc;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let path = &a[0];
    let target: usize = a[1].parse().unwrap();

    let q = Box::leak(Box::new(load(path).expect("load")));
    let d = Box::leak(Box::new(disassemble(q).expect("disasm")));
    let fns = build_functions(d);
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

    let logs = Rc::new(RefCell::new(Vec::new()));
    let h = make_handler(q.module, 0, logs.clone());
    let start = fns[0].0;

    let prev_pc = Rc::new(RefCell::new(usize::MAX));
    let prev_pc2 = prev_pc.clone();
    let fns2 = fns.clone();
    let hit = Rc::new(RefCell::new(0usize));
    let hit2 = hit.clone();
    let step_idx = Rc::new(RefCell::new(0usize));
    let step_idx2 = step_idx.clone();

    let mut emu = Emu::new(&d.insns, q).with_syscall(h).with_step_hook(Box::new(move |e, pc| {
        if pc == target {
            let pp = *prev_pc2.borrow();
            let f_here = fn_of(&fns2, pc);
            let f_prev = if pp != usize::MAX { fn_of(&fns2, pp) } else { usize::MAX };
            println!(
                "HIT target pc={pc} step={} (fn[{f_here}] range {:?}) prev_pc={pp} (fn[{f_prev}] range {:?})",
                *step_idx2.borrow(),
                fns2.get(f_here),
                fns2.get(f_prev)
            );
            *hit2.borrow_mut() += 1;
        }
        if pc == 6266 {
            let ps = e.program_stack();
            let v = e.mem().load4(ps + 52);
            println!("fn51 switch value at pc=6266 step={}: {v}", *step_idx2.borrow());
        }
        *prev_pc2.borrow_mut() = pc;
    }));
    emu.set_max_steps(20_000_000);

    // seq up to and including the Network tab + Up-arrow key event, matching
    // probe_uidiff.rs's UI_KEY_SYS_UP repro path.
    let seq: &[(i32, i32, i32, i32)] = &[
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (7, 1, 0, 0),
        (5, 0, 0, 0),
        (3, 13, 1, 0),
        (3, 133, 1, 0),
        (3, 97, 1, 0),
        (7, 1, 0, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (7, 2, 0, 0),
        (5, 0, 0, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (7, 1, 0, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (7, 1, 0, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 132, 1, 0),
        (3, 135, 1, 0),
        (3, 135, 1, 0),
        (3, 135, 1, 0),
        (5, 0, 0, 0),
        (7, 1, 0, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (3, 133, 1, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 133, 1, 0),
        (3, 13, 1, 0),
        (5, 0, 0, 0),
        (3, 132, 1, 0), // Up: the crash step
    ];

    for (ci, cmd) in seq.iter().enumerate() {
        *step_idx.borrow_mut() = ci;
        println!("--- step {ci}: {:?} ---", cmd);
        match emu.call(start, &[cmd.0, cmd.1, cmd.2, cmd.3]) {
            Ok(v) => println!("cmd {:?} -> {v}", cmd),
            Err(e) => {
                println!("cmd {:?} -> ERROR: {e}", cmd);
                break;
            }
        }
    }
    println!("total hits on target: {}", *hit.borrow());
}
