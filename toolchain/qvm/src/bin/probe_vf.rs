//! Probe: exercise Q_vsprintf end-to-end in the emulator with a float format.
//!
//! Usage: probe_vf <path.qvm> [entry_insn] [fmt] [value]
//! Defaults: entry=31013 (Q_vsprintf in _emit_u3), fmt="%5.2f", value=4.0f.
//! Writes fmt + float bits into bss, calls Q_vsprintf(buffer, fmt, &bits),
//! prints the produced buffer. Exits nonzero if output != expected " 4.00".

use qvm::{disassemble, load, Emu};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let path = &a[0];
    let entry: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(31013);
    let fmt = a.get(2).map(|s| s.as_str()).unwrap_or("%5.2f");
    let fval: f32 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(4.0);

    let q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    println!("{}", q);
    println!("entry insn {entry} (Q_vsprintf)");

    let mut emu = Emu::new(&d.insns, &q);

    let buf = 1800000i32;
    let fmt_a = 1800100i32;
    let argptr = 1800200i32;
    let bits = fval.to_bits() as i32;

    for (i, b) in fmt.bytes().enumerate() {
        emu.mem_mut().store1(fmt_a + i as i32, b as i32);
    }
    emu.mem_mut().store1(fmt_a + fmt.len() as i32, 0);
    emu.mem_mut().store4(argptr, bits);

    let result = emu.call(entry, &[buf, fmt_a, argptr]);
    match result {
        Ok(v) => println!("Q_vsprintf returned: {v}"),
        Err(e) => {
            println!("error: {e}");
            std::process::exit(2);
        }
    }

    let mut out = String::new();
    let mut p = buf;
    loop {
        let c = emu.mem().load1(p);
        if c == 0 {
            break;
        }
        out.push(c as u8 as char);
        p += 1;
    }
    println!("buffer=[{out}]");
    println!(
        "stats: steps={} syscalls={}",
        emu.stats.steps, emu.stats.syscalls
    );

    let expected = " 4.00";
    if out == expected {
        println!("PASS: va(\"%5.2f\", 4.0) -> [{out}]");
    } else {
        println!("FAIL: expected [{expected}]");
        std::process::exit(1);
    }
}
