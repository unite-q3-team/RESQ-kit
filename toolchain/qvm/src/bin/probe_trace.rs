//! Temporary trace probe: run one function with args and dump every executed
//! instruction (using the built-in `trace`), stopping at a step cap.
//!
//! Usage: probe_trace <qvm> <fn> <arg0> <arg1> ... [--cap N]

use qvm::{Emu, build_functions, disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_trace <qvm> <fn> [args...] [--cap N]");
        std::process::exit(2);
    }
    let path = &a[0];
    let fnidx: usize = a[1].parse().unwrap();
    let mut args: Vec<i32> = Vec::new();
    let mut cap = 5000usize;
    let mut i = 2;
    while i < a.len() {
        match a[i].as_str() {
            "--cap" => { cap = a[i + 1].parse().unwrap(); i += 2; }
            s => { args.push(s.parse().unwrap()); i += 1; }
        }
    }

    let q = load(path).expect("load");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let (start, end) = ranges[fnidx];
    eprintln!("fn[{fnidx}] insns {start}..{end} args={args:?}");

    let mut emu = Emu::new(&d.insns, &q);
    emu.set_max_steps(cap);
    emu.trace = true;
    match emu.call(start, &args) {
        Ok(v) => println!("RESULT {v}  steps={} syscalls={}", emu.stats.steps, emu.stats.syscalls),
        Err(e) => println!("ERROR: {e}  steps={}", emu.stats.steps),
    }
}
