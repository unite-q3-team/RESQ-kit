//! Probe: emulate a .qvm function and log every trap call, printing string
//! arguments resolved from the VM memory.
//!
//! Usage: probe_verify <path.qvm> <fn_index> [arg0] [arg1] ...
//! E.g. probe_verify vm/game/game.qvm 10 0   (G_ShutdownGame restart=0)

use qvm::{Emu, build_functions, disassemble, load, trap_name};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: probe_verify <qvm> <fn> [args...]");
    let fnidx: usize = args.next().expect("fn index").parse().unwrap();
    let call_args: Vec<i32> = args.map(|a| a.parse().unwrap()).collect();

    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let (start, end) = ranges[fnidx];
    println!("{}", q);
    println!("fn[{fnidx}] insns {start}..{end} args={call_args:?}");

    let name = q.module;
    let mut emu = Emu::new(&d.insns, &q).with_syscall(Box::new(move |mem, num, a| {
        let n = trap_name(name, num as u32).unwrap_or("?");
        print!("  trap {num} {n}(");
        for (i, v) in a.iter().enumerate().take(8) {
            if i > 0 {
                print!(", ");
            }
            if i > 0 && i < 4 && *v >= 0 {
                // candidate string pointer: resolve first few non-zero args
                if let Some(s) = q_string(mem, *v) {
                    print!("{s:?}");
                    continue;
                }
            }
            print!("{v}");
        }
        println!(")");
        0
    }));

    match emu.call(start, &call_args) {
        Ok(v) => println!("result: {v} (0x{v:X})"),
        Err(e) => println!("error: {e}"),
    }
    println!("stats: steps={} syscalls={}", emu.stats.steps, emu.stats.syscalls);
}

fn q_string(mem: &qvm::Memory, addr: i32) -> Option<String> {
    let a = (addr as u32 & mem.data_mask) as usize;
    let rest = mem.data.get(a..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    let s = &rest[..end];
    if s.is_empty() || !s.iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7f)) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}
