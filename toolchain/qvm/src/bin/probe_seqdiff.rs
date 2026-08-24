//! Sequence differential verification: run the same multi-command vmMain
//! sequence in two QVMs (original vs rebuilt) on PERSISTENT VMs — data memory
//! carries between commands like a real game session — and compare the trap
//! call sequences per command.
//!
//! Usage: probe_seqdiff <orig.qvm> <rebuilt.qvm>
//!
//! The sequence models a short game session (vmMain dispatch as seen in the
//! original qagame bytecode): GAME_INIT -> CLIENT_CONNECT -> CLIENT_BEGIN ->
//! USERINFO_CHANGED -> CLIENT_THINK -> 2x RUN_FRAME -> CLIENT_DISCONNECT ->
//! SHUTDOWN.
//!
//! Deterministic trap modeling in `probe_common::make_handler` (GetUserinfo
//! returns a fixed player userinfo, GetUsercmd a zeroed cmd, traces hit
//! nothing, FS reads fail) keeps both sides on the same branches even though
//! their frame memory differs. The per-command diff of the concatenated trap
//! logs reports where the rebuilt module diverges from the original.

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{make_handler_ctrl, TrapLog};
use qvm::{build_functions, disassemble, load, Emu};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_seqdiff <orig.qvm> <rebuilt.qvm>");
        std::process::exit(2);
    }

    // vmMain commands as (msg, p1, p2, p3) — see _emit_full/qagame.c vmMain:
    //   msg 0 -> G_InitGame(p1=levelTime, p2=randomSeed, p3=restart)
    //   msg 2 -> G_ClientConnect(p1=clientNum, p2=firstTime, p3=isBot)
    //   msg 3 -> G_ClientBegin(p1=clientNum)
    //   msg 4 -> G_ClientUserinfoChanged(p1=clientNum)
    //   msg 5 -> G_ClientDisconnect(p1=clientNum)
    //   msg 7 -> ClientThink(p1=clientNum)
    //   msg 8 -> G_RunFrame(p1=levelTime)
    //   msg 1 -> G_ShutdownGame(p1=restart)
    let seq: &[(i32, i32, i32, i32)] = &[
        (0, 100, 123, 0), // GAME_INIT
        (2, 0, 1, 0),     // GAME_CLIENT_CONNECT (client 0, first time, not a bot)
        (3, 0, 0, 0),     // GAME_CLIENT_BEGIN
        (4, 0, 0, 0),     // GAME_CLIENT_USERINFO_CHANGED
        (7, 0, 0, 0),     // GAME_CLIENT_THINK (pmove; attack button fires EV_FIRE_WEAPON)
        (7, 0, 0, 0),     // GAME_CLIENT_THINK (ClientEvents -> FireWeapon, projectile spawn)
        (7, 0, 0, 0),     // GAME_CLIENT_THINK
        (8, 1000, 0, 0),  // GAME_RUN_FRAME
        (8, 1100, 0, 0),  // GAME_RUN_FRAME
        (5, 0, 0, 0),     // GAME_CLIENT_DISCONNECT
        (1, 0, 0, 0),     // GAME_SHUTDOWN
    ];
    let names = [
        "GAME_INIT",
        "GAME_CLIENT_CONNECT",
        "GAME_CLIENT_BEGIN",
        "GAME_CLIENT_USERINFO_CHANGED",
        "GAME_CLIENT_THINK",
        "GAME_CLIENT_THINK",
        "GAME_CLIENT_THINK",
        "GAME_RUN_FRAME",
        "GAME_RUN_FRAME",
        "GAME_CLIENT_DISCONNECT",
        "GAME_SHUTDOWN",
    ];

    struct Side<'a> {
        emu: Emu<'a>,
        logs: Rc<RefCell<Vec<TrapLog>>>,
        tokens: Rc<RefCell<qvm::probe_common::EntityTokens>>,
        bounds: Vec<usize>,
        results: Vec<i32>,
        step_marks: Vec<usize>,
        errors: Vec<Option<String>>,
        trap_marks: Vec<usize>,
        trap_insns: Vec<usize>,
    }

    // Leak the QVM/disasm so the Emu may borrow them for the whole run (this
    // is a short-lived probe tool).
    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));

    let (start1, start2) = (build_functions(d1)[0].0, build_functions(d2)[0].0);

    fn make_side<'a>(insns: &'a [qvm::Insn], q: &'a qvm::Qvm, label: &'static str) -> Side<'a> {
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let hc = make_handler_ctrl(q.module, 0, logs.clone());
        let tokens = hc.entity_tokens.clone();
        Side {
            emu: Emu::new(insns, q)
                .with_syscall(hc.syscall)
                .with_watch_label(label),
            logs,
            tokens,
            bounds: vec![0],
            results: Vec::new(),
            step_marks: vec![0],
            errors: Vec::new(),
            trap_marks: vec![0],
            trap_insns: Vec::new(),
        }
    }

    let mut s1 = make_side(&d1.insns, q1, "orig");
    let mut s2 = make_side(&d2.insns, q2, "rebld");

    // QVM_DUMP_SQRT: fire a step hook at every sqrt call site (CALL -107 =
    // trap 106) and dump the caller frame: arg0 (vec3 pointer) at sp+60, the
    // three vec components cached in locals sp+24/28/32, and the dot product
    // written to the arg slot sp+8 by ARG 8. This attributes the sqrt input on
    // each side to a memory location (stack frame vs data/bss global) and shows
    // which component carries the divergence.
    if std::env::var("QVM_DUMP_SQRT").is_ok() {
        // The syscall target (-107 -> trap 106 = sqrt) is pushed by `CONST -107`
        // right before the `CALL`; the CALL itself has no operand. Fire on the
        // CONST so the frame (program_stack) is still the caller's.
        let sqrt_pcs1: Vec<usize> = d1
            .insns
            .iter()
            .filter(|i| matches!(i.op, qvm::Opcode::Const) && i.operand == Some(-107))
            .map(|i| i.idx)
            .collect();
        let sqrt_pcs2: Vec<usize> = d2
            .insns
            .iter()
            .filter(|i| matches!(i.op, qvm::Opcode::Const) && i.operand == Some(-107))
            .map(|i| i.idx)
            .collect();
        // The return address of the CALL that entered the current function was
        // written at the *caller's* sp (before ENTER moved sp down), i.e. it
        // sits at sp + frame_size. Find each function's ENTER (frame size).
        let frame_of = |insns: &[qvm::Insn], pc: usize| -> i32 {
            insns[..=pc]
                .iter()
                .rev()
                .find(|i| matches!(i.op, qvm::Opcode::Enter))
                .map(|i| i.operand.unwrap_or(0))
                .unwrap_or(0)
        };
        let dump = |emu: &mut Emu, pc: usize, enter: i32, caller_enter: i32| {
            let sp = emu.program_stack();
            // The callee reads arg0 (the vec3 pointer) at sp+enter+8 (caller
            // wrote it at caller_sp+8). The dot is written by `ARG 8` at sp+8.
            let ptr = emu.mem().load4(sp + enter + 8);
            let c0 = f32::from_bits(emu.mem().load4(ptr) as u32);
            let c1 = f32::from_bits(emu.mem().load4(ptr + 4) as u32);
            let c2 = f32::from_bits(emu.mem().load4(ptr + 8) as u32);
            let dot = f32::from_bits(emu.mem().load4(sp + 8) as u32);
            let ret = emu.mem().load4(sp + enter);
            let mask = emu.mem().data_mask;
            let region = if (ptr as u32) >= mask + 1 - 65536 {
                "stack"
            } else if (ptr as u32) < mask {
                "data"
            } else {
                "?"
            };
            // Caller frame = sp + enter (the caller of the sqrt caller, i.e.
            // SpotWouldTelefrag, whose locals sit at caller_sp+0..). Dump its
            // first locals as raw ints so the loop var / clientEnt / spot can be
            // decoded: orig layout (caller ENTER 52) local[12]=clientEnt,
            // local[28]=loop, spot at caller_sp+60; rebuilt (ENTER 76) local[24],
            // local[40], spot at caller_sp+84.
            let csp = sp + enter;
            let mut raws = String::new();
            for k in (0..24).step_by(4) {
                raws.push_str(&format!(" {:10}", emu.mem().load4(csp + k)));
            }
            let client_a = emu.mem().load4(csp + 12);
            let client_b = emu.mem().load4(csp + 24);
            let spot_a = emu.mem().load4(csp + 60);
            let spot_b = emu.mem().load4(csp + 84);
            println!("SQRT insn {pc} frame=0x{sp:x} vec@0x{ptr:x} ({region}) v=({c0}, {c1}, {c2}) dot={dot} ret={ret}");
            println!("   CFRAME 0x{csp:x} l[0..20]={raws}");
            println!(
                "   spotA(60)=0x{spot_a:x} spotB(84)=0x{spot_b:x} clientA(l12)=0x{client_a:x} clientB(l24)=0x{client_b:x}"
            );
            // Return address of the CALL into the *caller* of VectorLength (i.e.
            // SpotWouldTelefrag): written at its sp + its frame size.
            let spotret = emu.mem().load4(sp + enter + caller_enter);
            println!("   CALLER ret (into SpotWouldTelefrag) = {spotret}");
            for (tag, ce) in [("A", client_a), ("B", client_b)] {
                if (ce as u32) < mask {
                    let p672 = emu.mem().load4(ce + 672);
                    let p672p488 = if (p672 as u32) < mask {
                        emu.mem().load4(p672 + 488)
                    } else {
                        -1
                    };
                    println!("   client{tag} 0x{ce:x} *(ce+672)=0x{p672:x} *(*(ce+672)+488)=0x{p672p488:x} (0x{p672p488:x} = {}f)", p672p488 as u32 as f32);
                }
            }
            // Dump the spot struct memory (origin at +24..+36) so both sides'
            // bytes can be compared at the same address.
            for spt in [spot_a, spot_b].into_iter().filter(|&s| (s as u32) < mask) {
                let mut words = String::new();
                for k in (0..48).step_by(4) {
                    words.push_str(&format!(" {:10}", emu.mem().load4(spt + k)));
                }
                println!("   SPOT 0x{spt:x} [0..48)={words}");
                let o0 = f32::from_bits(emu.mem().load4(spt + 24) as u32);
                let o1 = f32::from_bits(emu.mem().load4(spt + 28) as u32);
                let o2 = f32::from_bits(emu.mem().load4(spt + 32) as u32);
                println!("   SPOT origin(+24..36)=({o0}, {o1}, {o2})");
                let mut w92 = String::new();
                for k in (80..112).step_by(4) {
                    w92.push_str(&format!(" {:10}", emu.mem().load4(spt + k)));
                }
                println!("   SPOT [80..112)={w92}");
                let n0 = f32::from_bits(emu.mem().load4(spt + 92) as u32);
                let n1 = f32::from_bits(emu.mem().load4(spt + 96) as u32);
                let n2 = f32::from_bits(emu.mem().load4(spt + 100) as u32);
                let m0 = f32::from_bits(emu.mem().load4(spt + 488) as u32);
                let m1 = f32::from_bits(emu.mem().load4(spt + 492) as u32);
                let m2 = f32::from_bits(emu.mem().load4(spt + 496) as u32);
                println!(
                    "   SPOT origin2? +92..104=({n0}, {n1}, {n2})  +488..500=({m0}, {m1}, {m2})"
                );
            }
            // Branch A reads the client at *(ent+516) (g_entities[0] -> world).
            for (tag, ce) in [("A", client_a), ("B", client_b)] {
                if (ce as u32) < mask {
                    let cl = emu.mem().load4(ce + 516);
                    let o0 = if (cl as u32) < mask {
                        f32::from_bits(emu.mem().load4(cl + 20) as u32)
                    } else {
                        f32::NAN
                    };
                    let o1 = if (cl as u32) < mask {
                        f32::from_bits(emu.mem().load4(cl + 24) as u32)
                    } else {
                        f32::NAN
                    };
                    let o2 = if (cl as u32) < mask {
                        f32::from_bits(emu.mem().load4(cl + 28) as u32)
                    } else {
                        f32::NAN
                    };
                    let d0 = f32::from_bits(emu.mem().load4(20) as u32);
                    let d1 = f32::from_bits(emu.mem().load4(24) as u32);
                    let d2 = f32::from_bits(emu.mem().load4(28) as u32);
                    println!("   client{tag} *(ce+516)=0x{cl:x} ps.origin=({o0}, {o1}, {o2}) data[20..32]=({d0}, {d1}, {d2})");
                }
            }
        };
        let insns1: &[qvm::Insn] = &d1.insns;
        let insns2: &[qvm::Insn] = &d2.insns;
        s1.emu.step_hook = Some(Box::new(move |emu: &mut Emu, pc: usize| {
            if sqrt_pcs1.binary_search(&pc).is_ok() {
                dump(emu, pc, frame_of(insns1, pc), 52);
            }
        }));
        s2.emu.step_hook = Some(Box::new(move |emu: &mut Emu, pc: usize| {
            if sqrt_pcs2.binary_search(&pc).is_ok() {
                dump(emu, pc, frame_of(insns2, pc), 76);
            }
        }));
    }

    // QVM_SCANF: dump the Q_sscanf call args (p0=input, p1=format, p2-p4=output
    // ptrs) at the known G_SpawnVector case-4 call sites (orig 164211 / rebuilt
    // 195463) to check whether the "origin" spawnvar string reaches the parser
    // intact. Fires on the CALL so program_stack is still the caller's frame.
    if std::env::var("QVM_SCANF").is_ok() {
        let dump_scanf = |emu: &mut Emu, pc: usize| {
            let sp = emu.program_stack();
            let p0 = emu.mem().load4(sp + 8);
            let p1 = emu.mem().load4(sp + 12);
            let p2 = emu.mem().load4(sp + 16);
            let p3 = emu.mem().load4(sp + 20);
            let p4 = emu.mem().load4(sp + 24);
            let mask = emu.mem().data_mask as i32;
            let s = |addr: i32| -> String {
                let mut v = String::new();
                let mut a = addr;
                for _ in 0..48 {
                    if a < 0 || a > mask {
                        break;
                    }
                    let c = emu.mem().load1(a) as u8;
                    if c == 0 {
                        break;
                    }
                    v.push(c as char);
                    a += 1;
                }
                v
            };
            println!(
                "SCANF insn {pc} sp=0x{sp:x} p0=0x{p0:x} '{}' p1=0x{p1:x} '{}' p2=0x{p2:x} p3=0x{p3:x} p4=0x{p4:x}",
                s(p0),
                s(p1)
            );
        };
        // Also dump the parsed output slots right after the CALL returns
        // (orig return = 164212 POP, rebuilt return = 195464 POP).
        let hook_out = |emu: &mut Emu, pc: usize, ret_insn: usize, sp: i32| {
            if pc == ret_insn {
                let p2 = emu.mem().load4(sp + 16);
                let p3 = emu.mem().load4(sp + 20);
                let p4 = emu.mem().load4(sp + 24);
                println!(
                    "SCANFOUT insn {pc} p2=0x{p2:x}=0x{:x} p3=0x{p3:x}=0x{:x} p4=0x{p4:x}=0x{:x}",
                    emu.mem().load4(p2),
                    emu.mem().load4(p3),
                    emu.mem().load4(p4)
                );
            }
        };
        {
            let mut sp_at_call = 0i32;
            let mut ret_seen = false;
            s1.emu.step_hook = Some(Box::new(move |emu: &mut Emu, pc: usize| {
                if pc == 164211 {
                    sp_at_call = emu.program_stack();
                    dump_scanf(emu, pc);
                    ret_seen = true;
                } else if ret_seen && pc == 164212 {
                    hook_out(emu, pc, 164212, sp_at_call);
                    ret_seen = false;
                }
            }));
        }
        {
            let mut sp_at_call = 0i32;
            let mut ret_seen = false;
            s2.emu.step_hook = Some(Box::new(move |emu: &mut Emu, pc: usize| {
                if pc == 195463 {
                    sp_at_call = emu.program_stack();
                    dump_scanf(emu, pc);
                    ret_seen = true;
                } else if ret_seen && pc == 195464 {
                    hook_out(emu, pc, 195464, sp_at_call);
                    ret_seen = false;
                }
            }));
        }
    }

    // Env QVM_TRACE_SCANF=1: trace every rebuilt Q_sscanf body insn so we can
    // see exactly which format branch executes (does %f -> 31886 fire?).
    if std::env::var("QVM_TRACE_SCANF").is_ok() {
        s2.emu.step_hook = Some(Box::new(move |emu: &mut Emu, pc: usize| {
            if (31714..=32156).contains(&pc) {
                if pc == 31890 {
                    let p0 = emu.mem().load4(emu.program_stack() + 128);
                    let mask = emu.mem().data_mask as i32;
                    let mut s = String::new();
                    let mut a = p0;
                    for _ in 0..32 {
                        if a < 0 || a > mask {
                            break;
                        }
                        let c = emu.mem().load1(a) as u8;
                        if c == 0 {
                            break;
                        }
                        s.push(c as char);
                        a += 1;
                    }
                    println!("TRACE-CPF p0='{s}'");
                }
                if pc == 31901 {
                    let cur = emu.mem().load4(emu.program_stack() + 40);
                    let target = emu.mem().load4(cur);
                    let val = emu.mem().load4(emu.program_stack() + 80);
                    println!(
                        "TRACE-FWRITE target=0x{target:x} val=0x{val:x} ({})",
                        f32::from_bits(val as u32)
                    );
                }
                println!("TRACE {}", emu.insn(pc));
            }
        }));
    }

    // Env QVM_SEQ_TRACE_CMDS="3,7": emit full instruction traces for the
    // given vmMain command indices (in addition to the always-traced DISCONNECT).
    let trace_cmds: Vec<i32> = std::env::var("QVM_SEQ_TRACE_CMDS")
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_default();

    if std::env::var("QVM_SEQ_MEMDIFF").is_ok() {
        let (d1, d2) = (&s1.emu.mem.data, &s2.emu.mem.data);
        let n = d1.len().min(d2.len());
        let mut count = 0usize;
        for off in (0..n).step_by(4) {
            let a = i32::from_le_bytes([d1[off], d1[off + 1], d1[off + 2], d1[off + 3]]);
            let b = i32::from_le_bytes([d2[off], d2[off + 1], d2[off + 2], d2[off + 3]]);
            if a != b {
                count += 1;
                if count <= 12 {
                    println!(
                        "      INIT mem[0x{off:x}] orig {a:>10} ({a:#010x}) vs rebld {b:>10} ({b:#010x})"
                    );
                }
            }
        }
        println!(
            "      INITIAL: {count} differing words (masks {:#x}/{:#x})",
            s1.emu.mem.data_mask, s2.emu.mem.data_mask
        );
    }

    for cmd in seq.iter().copied() {
        if cmd.0 == 0 {
            // GAME_INIT = level load: the engine re-points sv.entityParsePoint
            // at SV_SpawnServer; mirror that so a restart re-parses entities.
            s1.tokens.borrow_mut().reset();
            s2.tokens.borrow_mut().reset();
            if let Ok(v) = std::env::var("QVM_WATCH") {
                let w = i32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0);
                s1.emu.watch_store = Some(w);
                s2.emu.watch_store = Some(w);
            }
        } else if cmd.0 == 5 || trace_cmds.contains(&cmd.0) {
            s1.emu.trace = true;
            s2.emu.trace = true;
            if cmd.0 == 5 {
                let budget = s2.step_marks.last().copied().unwrap_or(0) + 50_000;
                s2.emu.set_max_steps(budget);
            }
        }
        qvm::probe_common::zero_stack(&mut s1.emu.mem);
        qvm::probe_common::zero_stack(&mut s2.emu.mem);
        let (r1, e1) = match s1.emu.call(start1, &[cmd.0, cmd.1, cmd.2, cmd.3]) {
            Ok(v) => (v, None),
            Err(e) => (i32::MIN, Some(format!("{e}"))),
        };
        s1.results.push(r1);
        s1.errors.push(e1);
        s1.bounds.push(s1.logs.borrow().len());
        s1.step_marks.push(s1.emu.stats.steps);
        let m1 = s1.trap_marks.last().copied().unwrap_or(0) + s1.emu.trap_insns.len();
        s1.trap_marks.push(m1);
        s1.trap_insns.extend_from_slice(&s1.emu.trap_insns);

        let (r2, e2) = match s2.emu.call(start2, &[cmd.0, cmd.1, cmd.2, cmd.3]) {
            Ok(v) => (v, None),
            Err(e) => (i32::MIN, Some(format!("{e}"))),
        };
        s2.results.push(r2);
        s2.errors.push(e2);
        s2.bounds.push(s2.logs.borrow().len());
        s2.step_marks.push(s2.emu.stats.steps);
        let m2 = s2.trap_marks.last().copied().unwrap_or(0) + s2.emu.trap_insns.len();
        s2.trap_marks.push(m2);
        s2.trap_insns.extend_from_slice(&s2.emu.trap_insns);

        if std::env::var("QVM_SEQ_MEMDIFF").is_ok() {
            let (d1, d2) = (&s1.emu.mem.data, &s2.emu.mem.data);
            if cmd.0 == 0 {
                for (d, label) in [(d1, "orig"), (d2, "rebld")] {
                    let mut hx = String::new();
                    for off in (0x26c0..0x27a0).step_by(4) {
                        let w = i32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]]);
                        hx.push_str(&format!(" {w:08x}"));
                    }
                    println!("      {label} mem[26c0..27a0] =[{hx}]");
                }
            }
            let n = d1.len().min(d2.len());
            let mut shown = 0usize;
            let mut first = None;
            for off in (0..n).step_by(4) {
                let a = i32::from_le_bytes([d1[off], d1[off + 1], d1[off + 2], d1[off + 3]]);
                let b = i32::from_le_bytes([d2[off], d2[off + 1], d2[off + 2], d2[off + 3]]);
                if a != b && first.is_none() {
                    first = Some(off);
                }
                if a != b && shown < 16 {
                    println!(
                        "      mem[0x{off:x}] orig {a:>10} ({a:#010x}) vs rebld {b:>10} ({b:#010x})"
                    );
                    shown += 1;
                }
            }
            match first {
                Some(off) => println!(
                    "      first memory divergence at 0x{off:x} ({} words differ, {} shown)",
                    n / 4,
                    shown
                ),
                None => println!("      memory identical ({} bytes)", n),
            }
        }
    }

    let logs1 = s1.logs.borrow();
    let logs2 = s2.logs.borrow();

    let fns1 = build_functions(d1);
    let fns2 = build_functions(d2);
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

    let mut total_diffs = 0usize;
    // Only the commands actually run (the loop breaks early at `ci == 6` to
    // bound the frame-2 trace) have per-command boundaries.
    for (i, name) in names.iter().enumerate().take(s1.bounds.len() - 1) {
        let l1 = &logs1[s1.bounds[i]..s1.bounds[i + 1]];
        let l2 = &logs2[s2.bounds[i]..s2.bounds[i + 1]];
        let t1 = &s1.trap_insns[s1.trap_marks[i]..s1.trap_marks[i + 1]];
        let t2 = &s2.trap_insns[s2.trap_marks[i]..s2.trap_marks[i + 1]];
        let steps1 = s1.step_marks[i + 1] - s1.step_marks[i];
        let steps2 = s2.step_marks[i + 1] - s2.step_marks[i];
        let mut diffs = 0usize;
        let mut diff_lines = Vec::new();
        for j in 0..l1.len().max(l2.len()) {
            let (x, y) = (l1.get(j), l2.get(j));
            if x != y {
                diffs += 1;
                let xi = t1
                    .get(j)
                    .map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns1, i)));
                let yi = t2
                    .get(j)
                    .map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns2, i)));
                diff_lines.push(format!(
                    "      #{j}: orig {:?} {} vs rebuilt {:?} {}\n          raw orig {:?}\n          raw rebld {:?}",
                    x.map(|t| (t.name.clone(), t.args.clone())),
                    xi.unwrap_or_default(),
                    y.map(|t| (t.name.clone(), t.args.clone())),
                    yi.unwrap_or_default(),
                    x.map(|t| t.raw.clone()),
                    y.map(|t| t.raw.clone())
                ));
            }
        }
        let r1 = s1.results[i];
        let r2 = s2.results[i];
        if r1 != r2 {
            diffs += 1;
            diff_lines.push(format!("      result: orig {r1} vs rebuilt {r2}"));
        }
        total_diffs += diffs;
        let status = if diffs == 0 { "OK" } else { "MISMATCH" };
        println!(
            "{name:>24}: traps {:>3} vs {:>3}  result {:>6} vs {:>6}  steps {:>7} vs {:>7}  {status}",
            l1.len(),
            l2.len(),
            r1,
            r2,
            steps1,
            steps2
        );
        for dl in diff_lines {
            println!("{dl}");
        }
        if diffs != 0 && std::env::var("QVM_SEQ_VERBOSE").is_ok() {
            for (j, t) in l1.iter().enumerate() {
                let ti = t1
                    .get(j)
                    .map(|&i| format!(" insn {i}, fn[{}]", fn_of(&fns1, i)))
                    .unwrap_or_default();
                println!("      orig #{j}: {}({:?}){ti}", t.name, t.args);
            }
            for (j, t) in l2.iter().enumerate() {
                let ti = t2
                    .get(j)
                    .map(|&i| format!(" insn {i}, fn[{}]", fn_of(&fns2, i)))
                    .unwrap_or_default();
                println!("      rebld #{j}: {}({:?}){ti}", t.name, t.args);
            }
        }
        if let (Some(e1), Some(e2)) = (&s1.errors[i], &s2.errors[i]) {
            println!("      orig error: {e1}  rebuilt error: {e2}");
        } else if let Some(e2) = &s2.errors[i] {
            println!("      rebuilt error: {e2}");
        } else if let Some(e1) = &s1.errors[i] {
            println!("      orig error: {e1}");
        }
    }
    println!("total mismatches: {total_diffs}");
}
