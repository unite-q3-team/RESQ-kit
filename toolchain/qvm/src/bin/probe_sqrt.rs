//! Debug probe: run the seqdiff session on ONE side and dump VM memory at the
//! moment EVERY sqrt (game trap 106) syscall fires, so we can see the
//! velocity values PM_Footsteps/VectorLength actually read, and compare
//! orig vs rebld side by side per trap index.

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{make_handler_ctrl, TrapLog};
use qvm::{build_functions, disassemble, load, Memory};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (orig_path, reb_path) = (&a[0], &a[1]);
    let side = a.get(2).map(|s| s.as_str()).unwrap_or("rebld");

    let seq: &[(i32, i32, i32, i32)] = &[
        (0, 100, 123, 0),
        (2, 0, 1, 0),
        (3, 0, 0, 0),
        (4, 0, 0, 0),
        (7, 0, 0, 0),
        (7, 0, 0, 0),
        (7, 0, 0, 0),
        (8, 1000, 0, 0),
        (8, 1100, 0, 0),
        (5, 0, 0, 0),
        (1, 0, 0, 0),
    ];

    let q = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d = Box::leak(Box::new(disassemble(q).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));

    let (start1, start2) = (build_functions(d)[0].0, build_functions(d2)[0].0);

    fn dump(label: &str, m: &Memory, insn: usize) {
        let pm = m.load4(0x107590);
        let ps = m.load4(pm);
        let v1 = m.load4(ps.wrapping_add(32));
        let v2 = m.load4(ps.wrapping_add(36));
        println!(
            "  [{label}] sqrt@insn={insn} pm=0x{pm:x} ps=0x{ps:x} v1=0x{v1:x}({v1}) v2=0x{v2:x}({v2}) f1={} f2={}",
            f32::from_bits(v1 as u32),
            f32::from_bits(v2 as u32)
        );
        // velocity = ps+28 (vec3) -> v[0]=ps+28 v[1]=ps+32 v[2]=ps+36
        println!(
            "    ps+16..44: {} {} {} {} {} {} {}",
            f32::from_bits(m.load4(ps + 16) as u32),
            f32::from_bits(m.load4(ps + 20) as u32),
            f32::from_bits(m.load4(ps + 24) as u32),
            f32::from_bits(m.load4(ps + 28) as u32),
            f32::from_bits(m.load4(ps + 32) as u32),
            f32::from_bits(m.load4(ps + 36) as u32),
            f32::from_bits(m.load4(ps + 40) as u32),
        );
        println!("    data[0..40]={:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}", 
            m.load4(0) as u32, m.load4(4) as u32, m.load4(8) as u32, m.load4(12) as u32,
            m.load4(16) as u32, m.load4(20) as u32, m.load4(24) as u32, m.load4(28) as u32,
            m.load4(32) as u32, m.load4(36) as u32);
        // pml globals: frametime@0x107528, movetime@0x10752c, fwd/right/up vecs @0x107500..0x10750c
        let ft = m.load4(0x107528);
        let mv = m.load4(0x10752c);
        let f: Vec<String> = (0..3)
            .map(|i| format!("{}", f32::from_bits(m.load4(0x107500 + 4 * i) as u32)))
            .collect();
        println!(
            "    frametime@0x107528={} ({:#x}) movetime={} fwd=[{}]",
            f32::from_bits(ft as u32),
            ft,
            f32::from_bits(mv as u32),
            f.join(" ")
        );
    }

    for (label, qv, dv, start) in [
        ("orig", q, d, start1),
        ("rebld", q2, d2, start2),
    ] {
        if label != side && side != "both" {
            continue;
        }
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let hc = make_handler_ctrl(qv.module, 0, logs.clone());
        let mut inner = hc.syscall;
        let dumped = Rc::new(RefCell::new(0usize));
        let n = dumped.clone();
        let emu = qvm::Emu::new(&dv.insns, qv).with_syscall(Box::new(move |m: &mut Memory, num, args| {
            if num == 106 {
                let got = *n.borrow();
                *n.borrow_mut() += 1;
                let arg = args[1];
                println!(
                    "[{label}] TRAP sqrt #{got} arg={arg} ({arg:#010x}) f={}",
                    f32::from_bits(arg as u32)
                );
                dump(label, m, 0);
            }
            inner(m, num, args)
        }));
        println!("=== {label} session ===");
        let mut emu = emu;
        for (ci, cmd) in seq.iter().copied().enumerate() {
            if cmd.0 == 0 {
                hc.entity_tokens.borrow_mut().reset();
            }
            let r = emu.call(start, &[cmd.0, cmd.1, cmd.2, cmd.3]);
            println!("  cmd {ci} msg {} -> {:?}", cmd.0, r);
        }
    }
}
