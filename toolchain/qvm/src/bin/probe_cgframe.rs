//! Frame-level differential harness for the cgame entity-rendering collapse:
//! serve realistic evolving snapshots (`probe_common::make_handler_snap`) and
//! compare per-frame trap counts between orig and rebuilt.
//!
//! Usage: probe_cgframe <orig.qvm> <rebuilt.qvm> [frames]
//!
//! Each DrawActiveFrame gets a fresh snapshot (snapNum++, serverTime+50) with
//! `SNAP_ENTITIES` synthetic parse entities. The per-entity signal is trap 32
//! (`S_UpdateEntityPosition`): `CG_AddPacketEntities` -> `CG_AddCEntity` ->
//! `CG_SetEntitySoundPosition` emits exactly one trap 32 per entity. If the
//! rebuilt stops looping (numEntities read <= 0), its trap-32 count collapses
//! to the player-only 1 while orig keeps ~158.

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{make_handler_snap, TrapLog};
use qvm::{build_functions, disassemble, load, Emu};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_cgframe <orig.qvm> <rebuilt.qvm> [frames]");
        std::process::exit(2);
    }
    let frames = a.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(24);

    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));
    let funcs1 = build_functions(d1);
    let funcs2 = build_functions(d2);
    let (start1, start2) = (funcs1[0].0, funcs2[0].0);

    struct Side<'a> {
        emu: Emu<'a>,
        logs: Rc<RefCell<Vec<TrapLog>>>,
        state: Rc<RefCell<qvm::probe_common::SnapState>>,
        fired: Rc<RefCell<bool>>,
        pc_cnt: Rc<RefCell<Vec<usize>>>,
    }
    fn make_side<'a>(insns: &'a [qvm::Insn], q: &'a qvm::Qvm) -> Side<'a> {
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let hs = make_handler_snap(q.module, 0, logs.clone());
        // Ring of the last ~400 executed pc's, dumped at the first trap_Error of
        // each call, so the caller that CALLs the bad target (vmMain re-entry) is
        // identifiable instead of just seeing the CG_Error count.
        let ring: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
        let ring_hook = ring.clone();
        let fired = Rc::new(RefCell::new(false));
        let fired_1 = fired.clone();
        let mut inner = hs.syscall;
        let wrapped: qvm::SyscallHandler = Box::new(move |mem, num, a| {
            if num == 1 && !*fired_1.borrow() {
                *fired_1.borrow_mut() = true;
                let r = ring_hook.borrow();
                let s = r
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                eprintln!(
                    "    [orig] last {} pcs before first trap_Error: {s}",
                    r.len()
                );
            }
            inner(mem, num, a)
        });
        let mut emu = Emu::new(insns, q).with_syscall(wrapped);
        let ring_hook2 = ring.clone();
        let last_pc = Rc::new(RefCell::new(0usize));
        let last_pc_h = last_pc.clone();
        let pc_cnt: Rc<RefCell<Vec<usize>>> = Rc::new(RefCell::new(Vec::new()));
        let pc_cnt_h = pc_cnt.clone();
        emu = emu.with_step_hook(Box::new(move |e, pc| {
            let prev = *last_pc_h.borrow();
            if pc == 0 && prev != 0 {
                // Re-entry into vmMain from somewhere (CALL/JUMP/LEAVE to insn 0).
                // Dump the branching site + frame pointer + return stack top.
                let ret = e.mem().read_i32_raw(e.program_stack()).unwrap_or(i32::MIN);
                eprintln!(
                    "    [orig] re-enter vmMain from insn {} (ps={}, ret=[{}]={})",
                    prev,
                    e.program_stack(),
                    e.program_stack(),
                    ret
                );
            }
            *last_pc_h.borrow_mut() = pc;
            pc_cnt_h.borrow_mut().push(pc);
            let mut r = ring_hook2.borrow_mut();
            r.push(pc);
            if r.len() > 400 {
                r.remove(0);
            }
        }));
        emu.set_max_steps(20_000_000);
        Side {
            emu,
            logs,
            state: hs.state,
            fired,
            pc_cnt,
        }
    }

    let mut s1 = make_side(&d1.insns, q1);
    let mut s2 = make_side(&d2.insns, q2);

    let r1 = s1.emu.call(start1, &[0, 100, 123, 0]).unwrap_or(i32::MIN); // CG_Init
    let r2 = s2.emu.call(start2, &[0, 100, 123, 0]).unwrap_or(i32::MIN);
    println!(
        "CG_Init: result orig {r1} vs rebuilt {r2}  steps {} vs {}",
        s1.emu.stats.steps, s2.emu.stats.steps
    );

    fn cells(m: &qvm::Memory, tag: &str) {
        let c = |a: i32| m.load4(a);
        println!(
            "  [{tag}] latestSnapNum(863664)={} snapTime(863668)={} cg.snap(863672)={} nextSnap(863676)={} serverCmdSeq(1020496)={} processed(1020500)={} f971264={} f971268={}",
            c(863664), c(863668), c(863672), c(863676), c(1020496), c(1020500), c(971264), c(971268)
        );
    }
    // Dump the active local-entity (temp entity) list, as CG_AddLocalEntities
    // walks it: head at sentinel 1146028's next field? No - walker reads
    // *(0x117cac)==1146028 then le = *(le+0) until le==1146028. The head cell
    // 1146028 holds the first entity, entities link via +0, sentinel is the
    // terminator value.
    fn dump_les(m: &qvm::Memory, tag: &str) {
        const SENT: i32 = 1146028;
        println!(
            "  [{tag}] le-cells [1146024]={:#x} [1146028]={:#x} [1146032]={:#x} [1146036]={:#x}",
            m.load4(1146024),
            m.load4(1146028),
            m.load4(1146032),
            m.load4(1146036)
        );
        let mut out: Vec<String> = Vec::new();
        let mut le = m.load4(SENT);
        let mut guard = 0;
        while le != SENT && le != 0 && guard < 4096 {
            let le_t = m.load4(le + 8);
            let st = m.load4(le + 16);
            let end = m.load4(le + 20);
            let f0 = m.load4(le);
            let f4 = m.load4(le + 4);
            out.push(format!(
                "{le:#x}:T{le_t},st{st},end{end},f0={f0:#x},f4={f4:#x}"
            ));
            le = m.load4(le);
            guard += 1;
        }
        println!("  [{tag}] localEntities[{}]: {}", out.len(), out.join(" "));
        let free = m.load4(1146024);
        if free != 0 {
            println!(
                "  [{tag}] free-list head {free:#x}: f0={:#x}, f4={:#x}",
                m.load4(free),
                m.load4(free + 4)
            );
        }
    }
    println!("after CG_Init:");
    cells(s1.emu.mem(), "orig");
    cells(s2.emu.mem(), "rebld");
    // CG_Init stores its serverMessageNum arg into bytecode 1020500, which is the
    // cell CG_ReadNextSnapshot uses as processedSnapshotNum (`while (processed <
    // latest)`). With arg 100 it sits above latestSnapshotNum forever, so neither
    // module ever fetches a snapshot (trap 52 == 0). Reset it to a fresh-map 0 so
    // the snapshot path is exercised on both sides.
    s1.emu.mem_mut().store4(1020500, 0);
    s2.emu.mem_mut().store4(1020500, 0);
    println!("  [fix] zeroed processedSnapshotNum(1020500) in both images");

    fn frame_stats(logs: &[TrapLog]) -> (usize, usize, i32, usize) {
        let n52 = logs.iter().filter(|t| t.num == 52).count();
        let n32 = logs.iter().filter(|t| t.num == 32).count();
        let n51 = logs.iter().filter(|t| t.num == 51).count();
        let max_ent = logs
            .iter()
            .filter(|t| t.num == 32)
            .filter_map(|t| t.raw.get(1).copied())
            .max()
            .unwrap_or(-1);
        let _ = n51;
        (n52, n32, max_ent, logs.len())
    }

    fn hist(logs: &[TrapLog]) -> Vec<(u32, usize)> {
        let mut h: Vec<(u32, usize)> = Vec::new();
        for t in logs {
            match h.iter_mut().find(|x| x.0 == t.num) {
                Some(x) => x.1 += 1,
                None => h.push((t.num, 1)),
            }
        }
        h.sort();
        h
    }

    let mut b1 = s1.logs.borrow().len();
    let mut b2 = s2.logs.borrow().len();
    let mut diverged = 0usize;
    for f in 0..frames {
        let time = 1000 + 50 * (f as i32);
        {
            let mut st = s1.state.borrow_mut();
            st.snap_num = 2 + f as i32;
            st.snap_time = time;
        }
        {
            let mut st = s2.state.borrow_mut();
            st.snap_num = 2 + f as i32;
            st.snap_time = time;
        }
        *s1.fired.borrow_mut() = false;
        *s2.fired.borrow_mut() = false;
        let pcb1 = s1.pc_cnt.borrow().len();
        let pcb2 = s2.pc_cnt.borrow().len();
        let r1 = s1.emu.call(start1, &[3, time, 0, 0]).unwrap_or(i32::MIN);
        let r2 = s2.emu.call(start2, &[3, time, 0, 0]).unwrap_or(i32::MIN);
        let pc_delta = |c: &[usize], b: usize, what: &[usize]| {
            let seg = &c[b..];
            what.iter()
                .map(|w| seg.iter().filter(|p| **p == *w).count())
                .collect::<Vec<_>>()
        };
        let sites = [67749usize, 31281, 30321, 30264, 32949];
        let d1 = pc_delta(&s1.pc_cnt.borrow(), pcb1, &sites);
        let d2 = pc_delta(&s2.pc_cnt.borrow(), pcb2, &sites);
        println!(
            "  [pcc] orig alloc67749={} render31281={} allocTmp30321={} free30264={} walk32949={} | rebld {} {} {} {} {}",
            d1[0], d1[1], d1[2], d1[3], d1[4], d2[0], d2[1], d2[2], d2[3], d2[4]
        );
        let len1 = s1.logs.borrow().len();
        let len2 = s2.logs.borrow().len();
        cells(s1.emu.mem(), "orig");
        cells(s2.emu.mem(), "rebld");
        dump_les(s1.emu.mem(), "orig");
        dump_les(s2.emu.mem(), "rebld");
        let (s52_1, s32_1, max1, tot1) = frame_stats(&s1.logs.borrow()[b1..len1]);
        let (s52_2, s32_2, max2, tot2) = frame_stats(&s2.logs.borrow()[b2..len2]);
        let h1 = hist(&s1.logs.borrow()[b1..len1]);
        let h2 = hist(&s2.logs.borrow()[b2..len2]);
        let fmt_h = |h: &[(u32, usize)]| -> String {
            h.iter()
                .map(|(n, c)| format!("{n}x{c}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        if h1 != h2 {
            eprintln!("  [hist] orig: {}", fmt_h(&h1));
            eprintln!("  [hist] rebld: {}", fmt_h(&h2));
            let dump41 = |logs: &[TrapLog],
                          pcs: &[usize],
                          funcs: &[(usize, usize)],
                          mem: &qvm::emu::Memory|
             -> String {
                logs.iter()
                    .zip(pcs)
                    .filter(|(t, _)| t.num == 41)
                    .map(|(t, pc)| {
                        let fi = funcs.iter().position(|(s, e)| *s <= *pc && *pc < *e);
                        let idx = match fi {
                            Some(i) => format!("{i}"),
                            None => format!("?{pc}"),
                        };
                        let re = t.raw.get(1).copied().unwrap_or(0);
                        let cent = re - 152;
                        let le = mem.read_i32_raw(mem.masked(cent) as i32 + 8).unwrap_or(-1);
                        format!("{idx}(re{re:#x},le{le})")
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            };
            eprintln!(
                "  [t41] orig: fn[{}]",
                dump41(
                    &s1.logs.borrow()[b1..len1],
                    &s1.emu.trap_insns,
                    &funcs1,
                    s1.emu.mem()
                )
            );
            eprintln!(
                "  [t41] rebld: fn[{}]",
                dump41(
                    &s2.logs.borrow()[b2..len2],
                    &s2.emu.trap_insns,
                    &funcs2,
                    s2.emu.mem()
                )
            );
        }
        // Diagnose the orig CG_Error spin: show the distinct trap_Error / trap_Print
        // messages (and how often each repeats) for this frame, plus the CALL pc
        // (`emu.trap_insns` aligns 1:1 with the trap logs of this call).
        for (tag, seg) in [
            ("orig", &s1.logs.borrow()[b1..len1]),
            ("rebld", &s2.logs.borrow()[b2..len2]),
        ] {
            let mut msgs: Vec<(String, usize)> = Vec::new();
            for t in seg.iter().filter(|t| t.num == 0 || t.num == 1) {
                let m = t.args.get(1).cloned().unwrap_or_default();
                match msgs.iter_mut().find(|(s, _)| *s == m) {
                    Some((_, c)) => *c += 1,
                    None => msgs.push((m, 1)),
                }
            }
            if !msgs.is_empty() {
                let joined = msgs
                    .iter()
                    .map(|(s, c)| format!("{s}x{c}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                eprintln!("  [{tag}] trap0/1 msgs: {joined}");
            }
            let pcs = if tag == "orig" {
                &s1.emu.trap_insns
            } else {
                &s2.emu.trap_insns
            };
            if pcs.len() == seg.len() {
                let mut sites: Vec<(usize, usize)> = Vec::new();
                for (t, pc) in seg.iter().zip(pcs) {
                    if t.num == 1 {
                        match sites.iter_mut().find(|(p, _)| *p == *pc) {
                            Some((_, c)) => *c += 1,
                            None => sites.push((*pc, 1)),
                        }
                    }
                }
                if !sites.is_empty() {
                    let joined = sites
                        .iter()
                        .map(|(p, c)| format!("insn{p}x{c}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("  [{tag}] trap_Error call sites: {joined}");
                    // chronological context: first/last few traps of this frame
                    if tag == "orig" && seg.len() > 20 {
                        let head = seg
                            .iter()
                            .take(18)
                            .map(|t| format!("{}", t.num))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let tail = seg
                            .iter()
                            .rev()
                            .take(12)
                            .map(|t| format!("{}", t.num))
                            .collect::<Vec<_>>()
                            .join(" ");
                        eprintln!("    orig seq ... {head} ... {tail} ...");
                    }
                }
            }
        }
        b1 = len1;
        b2 = len2;
        let status = if s32_1 != s32_2 || max1 != max2 || h1 != h2 {
            diverged += 1;
            "DIVERGE"
        } else {
            "ok"
        };
        println!(
            "frame {f:>2} (t={time:>5}) r {r1:>2}/{r2:>2}: orig s52={s52_1} ent32={s32_1:>3} maxEnt={max1:>3} traps={tot1:>5} | rebld s52={s52_2} ent32={s32_2:>3} maxEnt={max2:>3} traps={tot2:>5}  {status}"
        );
        if h1 == h2 && !h1.is_empty() {
            eprintln!("  [hist] {}", fmt_h(&h1));
        }
    }
    println!("diverged frames: {diverged}/{frames}");
}
