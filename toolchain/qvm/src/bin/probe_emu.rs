//! Probe: run the emulator over a real .qvm function.
//!
//! Usage: probe_emu <path.qvm> [fn_index] [arg0 arg1 arg2 arg3]
//! Emulates the function at the given index (default 0 = vmMain) with the
//! given args (default none). Prints the result and interpreter stats.

use qvm::{build_functions, disassemble, load, Emu};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let path = &a[0];
    let fnidx: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let args: Vec<i32> = a[2..]
        .iter()
        .take(4)
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    let q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let (start, _end) = ranges[fnidx];
    println!("{}", q);
    println!("fn[{fnidx}] start insn {start}");

    let mut emu = Emu::new(&d.insns, &q);
    let result = emu.call(start, &args);
    match result {
        Ok(v) => println!("result: {v} (0x{v:X})"),
        Err(e) => println!("error: {e}"),
    }
    println!(
        "stats: steps={} syscalls={}",
        emu.stats.steps, emu.stats.syscalls
    );
    let mut v: Vec<_> = emu.stats.syscall_counts.iter().collect();
    v.sort_by_key(|(k, _)| **k);
    for (num, count) in v {
        println!("  trap {num}: {count}x");
    }
}
