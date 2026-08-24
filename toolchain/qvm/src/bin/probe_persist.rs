//! Debug: two sequential vmMain calls on a persistent VM with make_handler.
//! Isolates whether CG_Init corrupts the arg slots for the next call.

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::make_handler;
use qvm::{Emu, build_functions, disassemble, load};

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let q = Box::leak(Box::new(load(&path).expect("load")));
    let d = Box::leak(Box::new(disassemble(q).expect("disasm")));
    let (start, _) = build_functions(d)[0];

    let logs: Rc<RefCell<Vec<qvm::probe_common::TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let mut emu = Emu::new(&d.insns, q)
        .with_syscall(make_handler(q.module, 0, logs.clone()))
        .with_watch_label("orig");
    emu.set_max_steps(5_000_000);

    // Bare run: same 2 calls, but NO syscall handler at all.
    let mut bare = Emu::new(&d.insns, q);
    bare.set_max_steps(5_000_000);
    let r0 = bare.call(start, &[0, 100, 123, 0]);
    let mut tab = Vec::new();
    for a in (8..32).step_by(4) {
        tab.push(bare.mem.read_i32_raw(a).unwrap());
    }
    println!("BARE call(0,..) result={r0:?} tab={tab:?}");

    let ps0 = q.data_mask() as i32 + 1 - (8 + 4 * qvm::emu::MAX_VMMAIN_ARGS as i32);
    println!("data_mask={:#x} ps0={ps0:#x} ps0+8={:#x}", q.data_mask(), (ps0 + 8));
    let mut tab = Vec::new();
    for a in (8..32).step_by(4) {
        tab.push(emu.mem.read_i32_raw(a).unwrap());
    }
    println!("dispatch table data[8..32] = {tab:?}");

    let cmds: &[(i32, i32, i32, i32)] = &[(0, 100, 123, 0), (3, 1000, 0, 0), (1, 0, 0, 0)];
    for (ci, c) in cmds.iter().copied().enumerate() {
        logs.borrow_mut().clear();
        emu.trap_insns.clear();
        emu.trace = ci == 1;
        let before = emu.stats.steps;
        let r = emu.call(start, &[c.0, c.1, c.2, c.3]);
        emu.trace = false;
        let steps = emu.stats.steps - before;
        let mut tab = Vec::new();
        for a in (8..32).step_by(4) {
            tab.push(emu.mem.read_i32_raw(a).unwrap());
        }
        println!(
            "call[{ci}] cmd=({}) result={r:?} steps={steps} traps={} tab={tab:?}",
            c.0,
            logs.borrow().len()
        );
        let last = logs.borrow().last().cloned();
        if let Some(l) = last {
            println!("   last trap: {} args={:?}", l.name, l.args);
        }
        if ci == 0 {
            use std::collections::HashMap;
            let mut cnt: HashMap<String, usize> = HashMap::new();
            for l in logs.borrow().iter() {
                *cnt.entry(l.name.clone()).or_insert(0) += 1;
            }
            let mut v: Vec<_> = cnt.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            println!("   trap profile: {v:?}");
            for (ti, l) in logs.borrow().iter().enumerate() {
                if l.num >= 100 {
                    println!("   [{ti}] {} num={} raw={:?}", l.name, l.num, l.raw);
                }
            }
        }
        for off in [ps0 + 8, ps0 + 12, ps0 + 16, ps0 + 20] {
            let w = emu.mem.read_i32_raw(off).unwrap();
            println!("   mem[{off:#x}] = {w}");
        }
    }
}
