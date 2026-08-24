//! Diagnose cgame console-command runaways: replay the full 66-command sweep on
//! both sides, dump decal/dynamic-memory words after each command, and when the
//! rebuilt side exceeds N steps print the recent-pc ring so the infinite loop is
//! identifiable.
//!
//! Usage: probe_cgdecal <orig.qvm> <rebuilt.qvm>

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{TrapLog, make_handler};
use qvm::{Emu, build_functions, disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_cgdecal <orig.qvm> <rebuilt.qvm>");
        std::process::exit(2);
    }
    let cmds = [
        "hudstyle", "hudnext", "hudprev", "addstr", "+vstr", "-vstr", "+fire", "-fire",
        "clientversion", "credits", "motd", "myname", "testgun", "testmodel", "nextframe",
        "prevframe", "nextskin", "prevskin", "viewpos", "+scores", "-scores", "+wstats",
        "-wstats", "+zoom", "-zoom", "sizeup", "sizedown", "weapnext", "weapprev", "weapon",
        "tell_target", "tell_attacker", "tcmd", "startOrbit", "loaddeferred", "currenttime",
        "+modif1", "+modif2", "+modif3", "+modif4", "+modif5", "-modif1", "-modif2", "-modif3",
        "-modif4", "-modif5", "+action", "-action", "menuleft", "menuright", "menu",
        "cg_dynamicmem", "addpos", "decaladd", "decaldec", "decaldisable", "decaldump",
        "decaledit", "decalenable", "decalgfxnext", "decalgfxprev", "decalinc", "decalnext",
        "decalprev", "decalrotclock", "decalrotcounter",
    ];

    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));
    let (start1, start2) = (build_functions(d1)[0].0, build_functions(d2)[0].0);

    let watch: &[(i32, &str)] = &[
        (14396, "decalPosCount"),
        (1141724, "decalEnabled"),
        (1141728, "decalIndex"),
        (1141744, "decalSlot0"),
        (988764, "voiceEn"),
        (24736, "dynA"),
        (24740, "dynB"),
        (24768, "dynC"),
        (24788, "dynD"),
    ];
    let fns = build_functions(d2);
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

    let mut s1 = Emu::new(
        &d1.insns,
        q1,
    )
    .with_syscall(make_handler(q1.module, 0, Rc::new(RefCell::new(Vec::new()))));
    let mut s2 = Emu::new(
        &d2.insns,
        q2,
    )
    .with_syscall(make_handler(q2.module, 0, Rc::new(RefCell::new(Vec::new()))));
    for (label, s, start) in [("orig", &mut s1, start1), ("rebld", &mut s2, start2)] {
        s.set_max_steps(20_000_000);
        let r = s.call(start, &[0, 100, 123, 0]);
        println!("{label} CG_INIT -> {r:?}");
    }
    println!("after CG_INIT:");
    {
        let m1 = s1.mem();
        let m2 = s2.mem();
        for &(addr, name) in watch {
            let v1 = m1.load4(addr);
            let v2 = m2.load4(addr);
            println!(
                "  {name:>14}: orig 0x{v1:08x} rebld 0x{v2:08x}{}",
                if v1 != v2 { "  <-- DIFF" } else { "" }
            );
        }
    }

    let ring: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
    let cnt: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
    {
        let ring = ring.clone();
        let cnt = cnt.clone();
        s2.step_hook = Some(Box::new(move |_e, pc| {
            let mut c = cnt.borrow_mut();
            *c += 1;
            let c = *c;
            if c > 500000 {
                let mut r = ring.borrow_mut();
                r.push(pc);
                if r.len() > 30 {
                    r.remove(0);
                }
            }
        }));
    }

    for cmd in &cmds {
        std::env::set_var("QVM_ARGV0", cmd);
        *cnt.borrow_mut() = 0;
        ring.borrow_mut().clear();
        let r1 = s1.call(start1, &[2, 0, 0, 0]);
        let r2 = s2.call(start2, &[2, 0, 0, 0]);
        let runaway = *cnt.borrow() > 500000;
        let m1 = s1.mem();
        let m2 = s2.mem();
        let mut wdiff = Vec::new();
        for &(addr, name) in watch {
            let v1 = m1.load4(addr);
            let v2 = m2.load4(addr);
            if v1 != v2 {
                wdiff.push(format!("{name}:0x{v1:08x}->0x{v2:08x}"));
            }
        }
        let extra = if wdiff.is_empty() {
            String::new()
        } else {
            format!("  [{}]", wdiff.join(" "))
        };
        println!(
            "{cmd:>18}: orig {r1:?} rebld {r2:?} steps {} vs {}{extra}{}",
            s1.stats.steps,
            s2.stats.steps,
            if runaway { "  ** RUNAWAY **" } else { "" }
        );
        if runaway {
            let r = ring.borrow();
            let pcs = r
                .iter()
                .map(|&p| format!("{p}(fn{})", fn_of(&fns, p)))
                .collect::<Vec<_>>()
                .join(" ");
            println!("  last 30 pcs (rebld): {pcs}");
            break;
        }
    }
}
