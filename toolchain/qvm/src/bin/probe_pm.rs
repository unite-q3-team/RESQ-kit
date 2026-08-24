//! Debug probe: run the seqdiff session on ONE side and, at the PM_Accelerate
//! velocity-writer instructions (orig 20897 / rebuilt-u3 32667), dump the whole
//! call frame: p0=wishdir ptr, p1=wishspeed, p2=accel, the wishdir vec3
//! contents, the addspeed/dot locals, and the ps velocity triple.
//!
//! Usage: probe_pm <orig.qvm> <rebld.qvm> [orig|rebld|both]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use qvm::probe_common::{make_handler_ctrl, TrapLog};
use qvm::{build_functions, disassemble, load, Emu};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
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

    // writer insn -> (fn_entry, label) for both sides; entry needed to find
    // the ENTER operand v so args (at sp+v+8+4k) can be read from the frame.
    let cfg1 = build_functions(&disassemble(&load(&a[0]).expect("load orig")).expect("disasm"));
    let cfg2 = build_functions(&disassemble(&load(&a[1]).expect("load rebld")).expect("disasm"));

    // find the (start, end) function range containing `insn`
    fn fn_of(cfg: &[(usize, usize)], insn: usize) -> (usize, usize) {
        for i in 0..cfg.len() {
            let (s, e) = (cfg[i].0, cfg[i].1);
            if s <= insn && insn < e {
                return (s, e);
            }
        }
        (cfg[0].0, cfg[0].1)
    }

    fn frame_dump(label: &str, e: &mut Emu, d: &[qvm::Insn], entry: usize, insn: usize, why: &str) {
        let m = e.mem();
        let sp = e.program_stack();
        // ENTER operand v is at the function's first insn
        let v = d.get(entry).and_then(|i| i.operand).unwrap_or(0);
        // Step hooks run *before* ENTER executes, so program_stack still is
        // the caller's stack pointer and the ARG slots begin at sp+8. Adding
        // the callee frame size here fabricated host-looking pointers and a
        // false PM corruption signal.
        let a0 = m.load4(sp + 8);
        let a1 = m.load4(sp + 12);
        let a2 = m.load4(sp + 16);
        let ps = m.load4(0x107590);
        let ps_v = m.load4(ps);
        let ft = m.load4(0x107528);
        println!(
            "[{label}] insn={insn} ({why}) entry={entry} ENTER v={v} pre-enter sp=0x{sp:x} ps=0x{ps_v:x} frametime={}",
            f32::from_bits(ft as u32)
        );
        println!(
            "    args: p0=wishdir@0x{a0:x} p1=wishspeed={} p2=accel={}",
            f32::from_bits(a1 as u32),
            f32::from_bits(a2 as u32)
        );
        let wd_raw: Vec<u32> = (0..3)
            .map(|i| m.load4(a0.wrapping_add(4 * i)) as u32)
            .collect();
        println!(
            "    wishdir=[{} {} {}] (0x{:08x} 0x{:08x} 0x{:08x})",
            wd_raw[0], wd_raw[1], wd_raw[2], wd_raw[0], wd_raw[1], wd_raw[2]
        );
        // caller frame: p0 = loc_0 + 48 (wishdir), so loc_0 = p0-48.
        // wishvel = loc_0+32..44, wishspeed = loc_0[44]
        let base = a0.wrapping_sub(48);
        let wv: Vec<u32> = (0..3).map(|i| m.load4(base + 32 + 4 * i) as u32).collect();
        let ws = m.load4(base + 44);
        let wc = m.load4(base + 52);
        println!(
            "    caller loc_0@{base:#x}: wishvel=[{} {} {}] wishspeed={} walkSpeed={}",
            f32::from_bits(wv[0]),
            f32::from_bits(wv[1]),
            f32::from_bits(wv[2]),
            f32::from_bits(ws as u32),
            f32::from_bits(wc as u32)
        );
        println!(
            "    pm+208(gameType?)= {}  ps+52={}  10036={} 10040={}",
            m.load4(ps_v + 208),
            f32::from_bits(m.load4(ps_v + 52) as u32),
            f32::from_bits(m.load4(10036) as u32),
            f32::from_bits(m.load4(10040) as u32)
        );
        println!(
            "    velocity=[{} {} {}] (ps+28..40)",
            f32::from_bits(m.load4(ps_v + 28) as u32),
            f32::from_bits(m.load4(ps_v + 32) as u32),
            f32::from_bits(m.load4(ps_v + 36) as u32)
        );
        // frame locals around the addSpeed/dot slots (LOCAL 12/16/20, 36)
        println!(
            "    locals 8/12/16/20/32/36/44: {} {} {} {} {} {} {}",
            f32::from_bits(m.load4(sp + 8) as u32),
            f32::from_bits(m.load4(sp + 12) as u32),
            f32::from_bits(m.load4(sp + 16) as u32),
            f32::from_bits(m.load4(sp + 20) as u32),
            f32::from_bits(m.load4(sp + 32) as u32),
            f32::from_bits(m.load4(sp + 36) as u32),
            f32::from_bits(m.load4(sp + 44) as u32)
        );
    }

    for (label, path, cfg, writer, call_tgt, _vn_tgt, _cms_tgt) in [
        // Capture both sides at the ENTER instruction, before the callee
        // adjusts program_stack. The former 20897 watchpoint was an internal
        // STORE and mixed caller/callee frame layouts.
        (
            "orig", &a[0], &cfg1, 20786usize, 20786usize, 36686usize, 20910usize,
        ),
        // These are q3asm instruction entries from _emit_u3/qagame.map, not
        // source labels from an earlier u2 emission.
        (
            "rebld", &a[1], &cfg2, 32588usize, 32588usize, 0usize, 32714usize,
        ),
    ] {
        if label != side && side != "both" {
            continue;
        }
        let q = Box::leak(Box::new(load(path).expect("load")));
        // attach names for readable call tracing (orig: qagame.names, rebld: q3asm .map)
        if label == "orig" {
            if let Ok(txt) = std::fs::read_to_string("qagame.names") {
                for line in txt.lines() {
                    let mut it = line.split_whitespace();
                    let (Some(idx), Some(name)) = (it.next(), it.next()) else {
                        continue;
                    };
                    if let Ok(i) = idx
                        .trim_start_matches("fn[")
                        .trim_end_matches(']')
                        .parse::<usize>()
                    {
                        if let Some(entry) = cfg.get(i).map(|r| r.0) {
                            q.names.insert(entry, name.to_string());
                        }
                    }
                }
            }
        } else if let Ok(txt) = std::fs::read_to_string("qagame.map") {
            for line in txt.lines() {
                let mut it = line.split_whitespace();
                let (Some(a0), Some(a1), Some(name)) = (it.next(), it.next(), it.next()) else {
                    continue;
                };
                if a0 != "0" {
                    continue;
                }
                if let Ok(insn) = usize::from_str_radix(a1, 16) {
                    if let Some(entry) = cfg.iter().find(|r| r.0 == insn).map(|r| r.0) {
                        q.names.insert(entry, name.to_string());
                    }
                }
            }
        }
        let d = Box::leak(Box::new(disassemble(q).expect("disasm")));
        let insns: &'static [qvm::Insn] = &d.insns;
        let cfgs: &'static [(usize, usize)] = Box::leak(Box::new(cfg.to_vec()));
        let (fn_entry, _fn_end) = fn_of(cfg, writer);
        let start = cfg[0].0;
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let hc = make_handler_ctrl(q.module, 0, logs.clone());
        let why = "PM_Accelerate STORE";
        let mut inner_syscall = hc.syscall;
        let trace_serial = Rc::new(Cell::new(0usize));
        let trace_serial_h = trace_serial.clone();
        let last_trace_dst = Rc::new(Cell::new(0i32));
        let last_trace_dst_syscall = last_trace_dst.clone();
        let last_call_pc = Rc::new(Cell::new(usize::MAX));
        let last_call_pc_syscall = last_call_pc.clone();
        let trace_syscall: qvm::SyscallHandler = Box::new(move |mem, num, a| {
            let result = inner_syscall(mem, num, a);
            // Game syscall 24 is G_TRACE (encoded as QVM CALL target -25).
            // Capture the trace_t after the shared handler fills it so the first
            // ground-contact divergence can be aligned without guessing from
            // function entries.
            if num == 24 {
                let n = trace_serial_h.get();
                trace_serial_h.set(n + 1);
                let dst = a.get(1).copied().unwrap_or(0);
                last_trace_dst_syscall.set(dst);
                let start = a.get(2).copied().unwrap_or(0);
                let end = a.get(5).copied().unwrap_or(0);
                let f = |addr| f32::from_bits(mem.load4(addr) as u32);
                println!(
                    "[{label}] trace#{n} start=[{:.3},{:.3},{:.3}] end=[{:.3},{:.3},{:.3}] \
                     frac={:.6} endz={:.3} normalz={:.3} ent={} mask=0x{:x} call_pc={}",
                    f(start),
                    f(start + 4),
                    f(start + 8),
                    f(end),
                    f(end + 4),
                    f(end + 8),
                    f(dst + 8),
                    f(dst + 20),
                    f(dst + 32),
                    mem.load4(dst + 48),
                    a.get(7).copied().unwrap_or(0),
                    last_call_pc_syscall.get(),
                );
            }
            result
        });
        let mut last_const: Option<i32> = None;
        let mut last_const_pc: usize = 0;
        let stage: Rc<Cell<usize>> = Rc::new(Cell::new(0));
        let stage_hook = stage.clone();
        let last_call_pc_hook = last_call_pc.clone();
        let last_trace_dst_hook = last_trace_dst.clone();
        let steps1: Rc<Cell<usize>> = Rc::new(Cell::new(0));
        let _steps1_hook = steps1.clone();
        let mut emu = Emu::new(&d.insns, q)
            .with_syscall(trace_syscall)
            .with_step_hook(Box::new(move |e: &mut Emu, pc: usize| {
                let insn = &insns[pc];
                let ci = stage_hook.get();
                if ci == 1 {
                    let n = steps1.get();
                    if n < 8 {
                        println!("[{label}] cmd1 step#{n} pc={pc} {:?}", insn.op);
                    }
                    steps1.set(n + 1);
                }
                if insn.op == qvm::Opcode::Call {
                    last_call_pc_hook.set(pc);
                    if let Some(t) = last_const {
                        if t < 0 {
                            println!("[{label}] ci={ci} CALL syscall#{} at pc={pc}", -1 - t);
                            if -1 - t == 106 {
                                let sp = e.program_stack();
                                let m = e.mem();
                                let arg0 = m.load4(sp + 8);
                                let (fe, fe_end) = fn_of(cfgs, pc);
                                println!(
                                    "  [{label}] trap106 at pc={pc} (fn {fe}..{fe_end}) arg0={} ({:#010x})",
                                    f32::from_bits(arg0 as u32),
                                    arg0 as u32
                                );
                            }
                        } else {
                            let f = cfgs.iter().position(|r| r.0 <= t as usize && (t as usize) < r.1);
                            let n = f.and_then(|i| q.name_for_fn(cfgs[i].0)).unwrap_or("?");
                            println!("[{label}] ci={ci} CALL {n} (tgt={t}) at pc={pc}");
                        }
                    }
                }
                // Immediately after PM_GroundTrace's indirect trace returns,
                // before its trace_t is copied/branched on, expose the two
                // control fields. A nonzero allsolid here explains a
                // PM_CorrectAllSolid retry; fraction==1 explains a miss.
                let after_ground_trace = (label == "orig" && pc == 24580)
                    || (label == "rebld" && pc == 36824);
                if after_ground_trace {
                    let sp = e.program_stack();
                    let m = e.mem();
                    println!(
                        "[{label}] PM_GroundTrace return pc={pc} sp=0x{sp:x} trace@0x{:x} allsolid={} fraction={:.6}",
                        last_trace_dst_hook.get(),
                        m.load4(last_trace_dst_hook.get()),
                        f32::from_bits(m.load4(last_trace_dst_hook.get() + 8) as u32),
                    );
                }
                if insn.op == qvm::Opcode::Const {
                    last_const = insn.operand;
                    last_const_pc = pc;
                }
                // Start host math after entity setup, when Pmove begins its
                // AngleVectors calls. This keeps spawn behavior on the legacy
                // deterministic model while giving PM real sin/cos/sqrt.
                let pm_math_start = (label == "orig"
                    && matches!(pc, 37841 | 37852 | 37870 | 37881 | 37901 | 37912))
                    || (label == "rebld"
                    && matches!(pc, 47195 | 47210 | 47232 | 47247 | 47271 | 47286));
                if pm_math_start {
                    std::env::set_var("QVM_MODEL_MATH", "1");
                }
                // PM_AirMove's rebuilt-u3 path. These points bracket the
                // VectorNormalize return, its float-bitcast helper, and the
                // PM_Accelerate call that first receives NaN.
                if label == "rebld" && matches!(pc, 34576 | 34582 | 34593) {
                    let sp = e.program_stack();
                    let m = e.mem();
                    let word = |off| m.load4(sp + off) as u32;
                    println!(
                        "[rebld] PM_AirMove pc={pc} sp=0x{sp:x} slots 84/92/120/128/152/156 = \
                         {:08x}/{:08x}/{:08x}/{:08x}/{:08x}/{:08x}",
                        word(84), word(92), word(120), word(128), word(152), word(156),
                    );
                }
                if insn.op == qvm::Opcode::Call
                    && last_const == Some(call_tgt as i32)
                    && pc == last_const_pc + 1
                {
                    let sp = e.program_stack();
                    let m = e.mem();
                    let p0 = m.load4(sp + 8);
                    let p1 = m.load4(sp + 12);
                    let p2 = m.load4(sp + 16);
                    println!(
                        "[{label}] CONST+{call_tgt} CALL at pc={pc} sp=0x{sp:x} p0=0x{p0:x} p1={} p2={}",
                        f32::from_bits(p1 as u32),
                        f32::from_bits(p2 as u32)
                    );
                }
                if pc == writer {
                    frame_dump(label, e, insns, fn_entry, pc, why);
                }
            }));
        std::env::remove_var("QVM_MODEL_MATH");
        println!("=== {label} session ===");
        for (ci, cmd) in seq.iter().copied().enumerate() {
            stage.set(ci);
            if cmd.0 == 0 {
                hc.entity_tokens.borrow_mut().reset();
            }
            let r = emu.call(start, &[cmd.0, cmd.1, cmd.2, cmd.3]);
            println!(
                "  cmd {ci} msg {} -> {:?} steps={}",
                cmd.0, r, emu.stats.steps
            );
            let m = emu.mem();
            let ent0 = 220232i32;
            let cl = m.load4(ent0 + 516);
            println!(
                "    client=0x{cl:x} connected={} pm_type={} pm_flags=0x{:x} ent0+424(svFlags)=0x{:x} 0x33d84={} 0x103c48(level.clients)=0x{:x}",
                m.load4(cl + 468),
                m.load4(cl + 4),
                m.load4(cl + 104),
                m.load4(ent0 + 424),
                m.load4(0x33d84),
                m.load4(0x103c48)
            );
        }
    }
    std::env::remove_var("QVM_MODEL_MATH");
}
