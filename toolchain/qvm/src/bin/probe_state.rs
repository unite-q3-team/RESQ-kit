//! Dump selected memory words at each step of the persistent command sequence
//! for both an original and a rebuilt QVM, to find where their VM state
//! diverges.
//!
//! Usage: probe_state <orig.qvm> <rebuilt.qvm>

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{TrapLog, make_handler};
use qvm::{Emu, build_functions, disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_state <orig.qvm> <rebuilt.qvm>");
        std::process::exit(2);
    }
    let seq: &[(i32, i32, i32, i32)] = &[
        (0, 100, 123, 0),
        (2, 0, 1, 0),
        (3, 0, 0, 0),
        (4, 0, 0, 0),
        (7, 0, 0, 0),
        (8, 1000, 0, 0),
        (8, 1100, 0, 0),
    ];
    let names = [
        "GAME_INIT",
        "CLIENT_CONNECT",
        "CLIENT_BEGIN",
        "USERINFO_CHANGED",
        "CLIENT_THINK",
        "RUN_FRAME(1000)",
        "RUN_FRAME(1100)",
    ];

    // addresses of interest
    let watch: [(i32, &str); 11] = [
        (0x103c68, "level.time"),
        (0x103c6c, "level.last"),
        (0x107448, "cvar_next (0x107448)"),
        (0x103c8c, "gate1 (0x103c8c)"),
        (0x17ae7c, "gate2 (0x17ae7c)"),
        (0x17d6bc, "gate3 (0x17d6bc)"),
        (0x103c54, "num_entities"),
        (0x103c60, "num_clients"),
        (0x107458, "0x107458 (CheckExitRules t0)"),
        (0x103c90, "0x103c90 (CheckExitRules t1)"),
        (0x17d29c, "default_change.integer"),
    ];

    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));
    let (start1, start2) = (build_functions(d1)[0].0, build_functions(d2)[0].0);

    let logs1: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let logs2: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let mut e1 = Emu::new(&d1.insns, q1).with_syscall(make_handler(q1.module, 0, logs1.clone()));
    let mut e2 = Emu::new(&d2.insns, q2).with_syscall(make_handler(q2.module, 0, logs2.clone()));

    for (i, cmd) in seq.iter().enumerate() {
        e1.call(start1, &[cmd.0, cmd.1, cmd.2, cmd.3]).ok();
        e2.call(start2, &[cmd.0, cmd.1, cmd.2, cmd.3]).ok();
        let m1 = e1.mem();
        let m2 = e2.mem();
        let mut diffs = 0;
        let mut line = String::new();
        for &(addr, name) in &watch {
            let v1 = m1.load4(addr);
            let v2 = m2.load4(addr);
            let mark = if v1 != v2 { "*" } else { " " };
            if v1 != v2 {
                diffs += 1;
            }
            line.push_str(&format!(" {mark}{name}={v1}/{v2}"));
        }
        println!(
            "{:>18} traps {} vs {}  steps {} vs {}{}",
            names[i],
            logs1.borrow().len(),
            logs2.borrow().len(),
            e1.stats.steps,
            e2.stats.steps,
            line
        );
        if diffs == 0 {
            println!("{:>18}   (no watched-word diffs)", "");
        }
    }
}
