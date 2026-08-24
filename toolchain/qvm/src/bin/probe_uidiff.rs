//! Sequence differential verification for the ui module: run the same
//! multi-command vmMain sequence in two QVMs (original vs rebuilt) on
//! PERSISTENT VMs and compare the trap call sequences per command.
//!
//! Usage: probe_uidiff <orig.qvm> <rebuilt.qvm>
//!
//! The sequence models the reference ui vmMain dispatch (see _emit_ui/ui.c vmMain
//! and baseq3a code/ui/ui_main.c): UI_GETAPIVERSION -> UI_INIT ->
//! UI_SET_ACTIVE_MENU(UIMENU_MAIN) -> UI_REFRESH -> real UI_KEY_EVENT inputs
//! -> UI_CONSOLE_COMMAND -> UI_SHUTDOWN.
//!
//! Trap modeling comes from probe_common::make_handler (deterministic, so both
//! sides take the same branches even though their frame/BSS layout differs).

use std::cell::RefCell;
use std::rc::Rc;

use qvm::probe_common::{TrapLog, make_handler};
use qvm::{Emu, build_functions, disassemble, load};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_uidiff <orig.qvm> <rebuilt.qvm>");
        std::process::exit(2);
    }

    // ui vmMain commands as (msg, p1, p2, p3) — see _emit_ui/ui.c vmMain:
    //   msg 0 -> return 4 (UI_GETAPIVERSION)
    //   msg 1 -> fn_5609()  (UI_INIT)
    //   msg 5 -> fn_6121(p1) (UI_REFRESH)
    //   msg 3 -> fn_4976(p1, p2) (UI_KEY_EVENT)
    //   msg 8 -> fn_5428(p1) (UI_CONSOLE_COMMAND)
    //   msg 2 -> fn_5606()  (UI_SHUTDOWN)
    let seq: &[(i32, i32, i32, i32)] = &[
        (0, 0, 0, 0),    // UI_GETAPIVERSION
        (1, 0, 0, 0),    // UI_INIT
        (7, 1, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_MAIN
        (5, 0, 0, 0),    // UI_REFRESH
        (3, 13, 1, 0),   // UI_KEY_EVENT: Enter down
        (3, 133, 1, 0),  // UI_KEY_EVENT: K_DOWNARROW down
        (3, 97, 1, 0),   // UI_KEY_EVENT: ASCII 'a' down
        // Exercise the historic main-menu crash path: select Exit, move from
        // the default "Yes" to "No", then confirm. A corrupt callback used to
        // send this indirect call into unrelated UI code.
        (7, 1, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_MAIN
        (3, 133, 1, 0),  // Down: Multiplayer
        (3, 133, 1, 0),  // Down: Setup
        (3, 133, 1, 0),  // Down: Demos
        (3, 133, 1, 0),  // Down: Exit
        (3, 13, 1, 0),   // Enter: open exit confirmation
        (3, 133, 1, 0),  // Down: select No
        (3, 13, 1, 0),   // Enter: dismiss confirmation
        // Team menu initializes the JOIN RED/JOIN BLUE string and callback
        // fields that previously suffered entry-index/string collisions.
        (7, 2, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_TEAM
        (5, 0, 0, 0),    // UI_REFRESH: team menu
        (3, 133, 1, 0),  // Down: move team-menu cursor
        (3, 13, 1, 0),   // Enter: activate focused team item
        // Follow the main-menu Setup path, the parent of the System/Sound UI.
        (7, 1, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_MAIN
        (3, 133, 1, 0),  // Down: Multiplayer
        (3, 133, 1, 0),  // Down: Setup
        (3, 13, 1, 0),   // Enter: open Setup
        (5, 0, 0, 0),    // UI_REFRESH: setup menu
        // Player Setup -> models list (reported live crash: navigating into
        // the model list from Setup->Player).
        (7, 1, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_MAIN
        (3, 133, 1, 0),  // Down: Multiplayer
        (3, 133, 1, 0),  // Down: Setup
        (3, 13, 1, 0),   // Enter: open Setup (lands on Player, item 0)
        (5, 0, 0, 0),    // UI_REFRESH: setup menu
        (3, 13, 1, 0),   // Enter: open Player Setup
        (5, 0, 0, 0),    // UI_REFRESH: player setup menu
        (3, 133, 1, 0),  // Down 1 in Player Setup
        (3, 133, 1, 0),  // Down 2
        (3, 133, 1, 0),  // Down 3
        (3, 133, 1, 0),  // Down 4 (models list widget, guess)
        (3, 13, 1, 0),   // Enter: open/select on models widget
        (5, 0, 0, 0),    // UI_REFRESH
        (3, 132, 1, 0),  // K_UPARROW: cycle model list (if it's a spin control)
        (3, 135, 1, 0),  // K_RIGHTARROW: cycle model list right
        (3, 135, 1, 0),
        (3, 135, 1, 0),
        (5, 0, 0, 0),    // UI_REFRESH

        // Exact live-crash repro from the user: Setup -> System(Graphics) ->
        // Display -> Sound -> Network -> back to Sound (Up+Enter). Reported
        // to crash with "Menu_Init: unknown type 0" / bounds-overflow.
        (7, 1, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_MAIN
        (3, 133, 1, 0),  // Down
        (3, 133, 1, 0),  // Down: Setup
        (3, 13, 1, 0),   // Enter: open Setup (Player)
        (3, 133, 1, 0),  // Down: Controls
        (3, 133, 1, 0),  // Down: System
        (3, 13, 1, 0),   // Enter: open System (Graphics tab)
        (5, 0, 0, 0),    // UI_REFRESH
        (3, 133, 1, 0),  // Down
        (3, 13, 1, 0),   // Enter: Display tab
        (5, 0, 0, 0),    // UI_REFRESH
        (3, 133, 1, 0),  // Down
        (3, 13, 1, 0),   // Enter: Sound tab
        (5, 0, 0, 0),    // UI_REFRESH
        (3, 133, 1, 0),  // Down
        (3, 13, 1, 0),   // Enter: Network tab
        (5, 0, 0, 0),    // UI_REFRESH
        (3, 132, 1, 0),  // Up
        (3, 13, 1, 0),   // Enter: back to Sound tab -- reported crash here
        (5, 0, 0, 0),    // UI_REFRESH

        // Setup -> Game Options (crosshair ownerdraw preview).
        // Setup order: Player, Controls, System, Game Options, CD Key.
        (7, 1, 0, 0),    // UI_SET_ACTIVE_MENU: UIMENU_MAIN
        (3, 133, 1, 0),  // Down: Multiplayer
        (3, 133, 1, 0),  // Down: Setup
        (3, 13, 1, 0),   // Enter: Setup (Player)
        (3, 133, 1, 0),  // Down: Controls
        (3, 133, 1, 0),  // Down: System
        (3, 133, 1, 0),  // Down: Game Options
        (3, 13, 1, 0),   // Enter: open Game Options
        (5, 0, 0, 0),    // UI_REFRESH: Game Options (RegisterShader + DrawStretchPic)

        (8, 0, 0, 0),    // UI_CONSOLE_COMMAND
        (2, 0, 0, 0),    // UI_SHUTDOWN
    ];
    let names = [
        "UI_GETAPIVERSION",
        "UI_INIT",
        "UI_SET_ACTIVE_MENU_MAIN",
        "UI_REFRESH",
        "UI_KEY_EVENT_ENTER",
        "UI_KEY_EVENT_DOWN",
        "UI_KEY_EVENT_A",
        "UI_SET_ACTIVE_MENU_EXIT",
        "UI_KEY_EXIT_DOWN_MULTIPLAYER",
        "UI_KEY_EXIT_DOWN_SETUP",
        "UI_KEY_EXIT_DOWN_DEMOS",
        "UI_KEY_EXIT_DOWN_EXIT",
        "UI_KEY_EXIT_ENTER",
        "UI_KEY_EXIT_SELECT_NO",
        "UI_KEY_EXIT_CONFIRM_NO",
        "UI_SET_ACTIVE_MENU_TEAM",
        "UI_REFRESH_TEAM",
        "UI_KEY_TEAM_DOWN",
        "UI_KEY_TEAM_ENTER",
        "UI_SET_ACTIVE_MENU_SETUP",
        "UI_KEY_SETUP_DOWN_MULTIPLAYER",
        "UI_KEY_SETUP_DOWN_SETUP",
        "UI_KEY_SETUP_ENTER",
        "UI_REFRESH_SETUP",
        "UI_SET_ACTIVE_MENU_MAIN2",
        "UI_KEY_DOWN_MULTIPLAYER2",
        "UI_KEY_DOWN_SETUP2",
        "UI_KEY_OPEN_SETUP2",
        "UI_REFRESH_SETUP2",
        "UI_KEY_OPEN_PLAYERSETUP",
        "UI_REFRESH_PLAYERSETUP",
        "UI_KEY_PS_DOWN1",
        "UI_KEY_PS_DOWN2",
        "UI_KEY_PS_DOWN3",
        "UI_KEY_PS_DOWN4_MODELS",
        "UI_KEY_PS_ENTER_MODELS",
        "UI_REFRESH_PS2",
        "UI_KEY_PS_UP",
        "UI_KEY_PS_RIGHT1",
        "UI_KEY_PS_RIGHT2",
        "UI_KEY_PS_RIGHT3",
        "UI_REFRESH_PS3",
        "UI_SET_ACTIVE_MENU_MAIN3",
        "UI_KEY_DOWN_MULTIPLAYER3",
        "UI_KEY_DOWN_SETUP3",
        "UI_KEY_OPEN_SETUP3",
        "UI_KEY_DOWN_CONTROLS",
        "UI_KEY_DOWN_SYSTEM",
        "UI_KEY_OPEN_SYSTEM",
        "UI_REFRESH_SYSTEM",
        "UI_KEY_SYS_DOWN1",
        "UI_KEY_SYS_ENTER_DISPLAY",
        "UI_REFRESH_DISPLAY",
        "UI_KEY_SYS_DOWN2",
        "UI_KEY_SYS_ENTER_SOUND",
        "UI_REFRESH_SOUND",
        "UI_KEY_SYS_DOWN3",
        "UI_KEY_SYS_ENTER_NETWORK",
        "UI_REFRESH_NETWORK",
        "UI_KEY_SYS_UP",
        "UI_KEY_SYS_ENTER_BACK_TO_SOUND",
        "UI_REFRESH_BACK_TO_SOUND",
        "UI_SET_ACTIVE_MENU_MAIN_GO",
        "UI_KEY_GO_DOWN_MP",
        "UI_KEY_GO_DOWN_SETUP",
        "UI_KEY_GO_ENTER_SETUP",
        "UI_KEY_GO_DOWN_CONTROLS",
        "UI_KEY_GO_DOWN_SYSTEM",
        "UI_KEY_GO_DOWN_GAMEOPTIONS",
        "UI_KEY_GO_ENTER_GAMEOPTIONS",
        "UI_REFRESH_GAMEOPTIONS",
        "UI_CONSOLE_COMMAND",
        "UI_SHUTDOWN",
    ];

    struct Side<'a> {
        emu: Emu<'a>,
        logs: Rc<RefCell<Vec<TrapLog>>>,
        bounds: Vec<usize>,
        results: Vec<i32>,
        step_marks: Vec<usize>,
        errors: Vec<Option<String>>,
        trap_marks: Vec<usize>,
        trap_insns: Vec<usize>,
    }

    let q1 = Box::leak(Box::new(load(&a[0]).expect("load orig")));
    let d1 = Box::leak(Box::new(disassemble(q1).expect("disasm orig")));
    let q2 = Box::leak(Box::new(load(&a[1]).expect("load rebuilt")));
    let d2 = Box::leak(Box::new(disassemble(q2).expect("disasm rebuilt")));

    let (start1, start2) = (build_functions(d1)[0].0, build_functions(d2)[0].0);

    fn make_side<'a>(insns: &'a [qvm::Insn], q: &'a qvm::Qvm, label: &'static str) -> Side<'a> {
        let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
        let h = make_handler(q.module, 0, logs.clone());
        let mut emu = Emu::new(insns, q).with_syscall(h).with_watch_label(label);
        emu.set_max_steps(20_000_000);
        Side {
            emu,
            logs,
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

    let trace_cur_step: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
    if let Ok(targets_s) = std::env::var("QVM_TRACE_CALLS") {
        let targets: Vec<usize> = targets_s.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        let cur_step2 = trace_cur_step.clone();
        let prev_pc = Rc::new(RefCell::new(usize::MAX));
        let mut tmp = Emu::new(&d2.insns, q2);
        std::mem::swap(&mut tmp, &mut s2.emu);
        let trace_step_filter: Option<usize> = std::env::var("QVM_TRACE_STEP").ok().and_then(|s| s.parse().ok());
        let insns2 = d2.insns.clone();
        s2.emu = tmp.with_step_hook(Box::new(move |e, pc| {
            if targets.contains(&pc) {
                println!("TRACE step={} pc={pc} prev_pc={}", *cur_step2.borrow(), *prev_pc.borrow());
            }
            if trace_step_filter == Some(*cur_step2.borrow()) {
                use qvm::opcodes::Opcode;
                let insn = &insns2[pc];
                if matches!(insn.op, Opcode::Enter | Opcode::Leave | Opcode::Call) {
                    println!(
                        "  DEPTH step={} pc={pc} op={:?} operand={:?} ps_before={}",
                        *cur_step2.borrow(),
                        insn.op,
                        insn.operand,
                        e.program_stack()
                    );
                }
            }
            *prev_pc.borrow_mut() = pc;
        }));
        // re-attach the syscall handler that was lost by the fresh Emu::new above.
        let h = make_handler(q2.module, 0, s2.logs.clone());
        s2.emu = s2.emu.with_syscall(h).with_watch_label("rebld");
        s2.emu.set_max_steps(20_000_000);
    }

    for (_ci, cmd) in seq.iter().copied().enumerate() {
        *trace_cur_step.borrow_mut() = _ci;
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
                let xi = t1.get(j).map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns1, i)));
                let yi = t2.get(j).map(|&i| format!("(insn {i}, fn[{}])", fn_of(&fns2, i)));
                diff_lines.push(format!(
                    "      #{j}: orig {:?} {} vs rebuilt {:?} {}",
                    x.map(|t| (t.name.clone(), t.args.clone())),
                    xi.unwrap_or_default(),
                    y.map(|t| (t.name.clone(), t.args.clone())),
                    yi.unwrap_or_default()
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
        if (*name == "UI_KEY_GO_ENTER_GAMEOPTIONS" || *name == "UI_REFRESH_GAMEOPTIONS")
            && std::env::var("QVM_UI_CROSSHAIR_MODEL").as_deref() == Ok("1")
        {
            let dump = |label: &str, logs: &[TrapLog]| {
                println!("      [{label}] shader/draw traps on {name}:");
                for (j, t) in logs.iter().enumerate() {
                    if t.name.contains("RegisterShader") || t.name.contains("DrawStretch") {
                        println!("        #{j}: {}({:?})", t.name, t.args);
                    }
                }
            };
            dump("orig", l1);
            dump("rebld", l2);
            println!(
                "      curvalue@259228: orig={} rebld={}",
                s1.emu.mem.load4(259228),
                s2.emu.mem.load4(259228)
            );
            print!("      shaders@260028: orig=[");
            for i in 0..10 {
                print!("{}{}", s1.emu.mem.load4(260028 + i * 4), if i < 9 { "," } else { "" });
            }
            println!("]");
            print!("      shaders@260028: rebld=[");
            for i in 0..10 {
                print!("{}{}", s2.emu.mem.load4(260028 + i * 4), if i < 9 { "," } else { "" });
            }
            println!("]");
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
