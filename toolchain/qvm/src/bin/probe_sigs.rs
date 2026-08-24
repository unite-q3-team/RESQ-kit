//! Probe: derive function signatures from the QVM bytecode (stage C2).
//!
//! For every function reports:
//!   - frame (ENTER operand),
//!   - arity  = max(callee arg reads, caller ARG counts),
//!   - return class: void | int | float,
//!   - per-arg best-guess type: ptr | float | int | unknown.
//!
//! Usage: probe_sigs <qvm> [out.sigs] [--names qagame.names] [--only N,M]
//!
//! Ground truth for aligned functions comes later from baseq3a prototypes.

use std::collections::{HashMap, HashSet};

use qvm::opcodes::Opcode;
use qvm::{build_functions, disassemble, load};

fn is_float_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Negf | Opcode::AddF | Opcode::SubF | Opcode::DivF | Opcode::MulF | Opcode::Cvif
    )
}

fn is_float_cmp(op: Opcode) -> bool {
    matches!(op, Opcode::Eqf | Opcode::Nef | Opcode::Ltf | Opcode::Lef | Opcode::Gtf | Opcode::Gef)
}

fn is_int_binop(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Negi | Opcode::Add | Opcode::Sub | Opcode::Divi | Opcode::Divu | Opcode::Modi
            | Opcode::Modu | Opcode::Muli | Opcode::Mulu | Opcode::Band | Opcode::Bor
            | Opcode::Bxor | Opcode::Bcom | Opcode::Lsh | Opcode::Rshi | Opcode::Rshu
    )
}

fn is_int_cmp(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Eq | Opcode::Ne | Opcode::Lti | Opcode::Lei | Opcode::Gti | Opcode::Gei
            | Opcode::Ltu | Opcode::Leu | Opcode::Gtu | Opcode::Geu
    )
}

fn is_noop(op: Opcode) -> bool {
    matches!(op, Opcode::Ignore | Opcode::Break | Opcode::Undef)
}

/// Producer kind of the opstack top at a `Leave` (scan backward from the
/// terminator through the block body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Producer {
    Dummy,
    Int,
    Float,
    IntMaybeFloat,
    CrossBlock,
}

/// Kind of the value that is on top of the opstack when a block reaches its
/// final `Leave`. `block_end` indexes the instruction AFTER the block; the
/// block's last instruction (the Leave) is at `block_end - 1`.
fn producer_at_leave(
    insns: &[qvm::disasm::Insn],
    block_start: usize,
    block_end: usize,
) -> Producer {
    // net stack delta of each opcode (+push / -pop / 0)
    fn push_n(op: Opcode) -> i8 {
        match op {
            Opcode::Const | Opcode::Local | Opcode::Push => 1,
            Opcode::Pop | Opcode::Arg | Opcode::Jump => -1,
            Opcode::Load1 | Opcode::Load2 | Opcode::Load4 => 0,
            Opcode::Store1 | Opcode::Store2 | Opcode::Store4 | Opcode::BlockCopy => -2,
            Opcode::Call => 0,
            Opcode::Cvif | Opcode::Cvfi => 0,
            o if is_int_binop(o) => -1,
            o if is_float_op(o) => -1,
            o if is_int_cmp(o) => -2,
            o if is_float_cmp(o) => -2,
            _ => 0,
        }
    }

    let mut k: i32 = 0; // final-stack index (0 = top) of the value we look for
    let mut i = block_end as i64 - 2; // skip trailing Leave
    while i >= block_start as i64 {
        let ins = &insns[i as usize];
        let op = ins.op;
        if is_noop(op) || op == Opcode::Enter {
            i -= 1;
            continue;
        }
        let kind = match op {
            Opcode::Const | Opcode::Local => Producer::Int,
            Opcode::Push => Producer::Dummy,
            Opcode::Load1 | Opcode::Load2 | Opcode::Load4 | Opcode::Call => Producer::IntMaybeFloat,
            Opcode::Cvif => Producer::Float,
            Opcode::Cvfi => Producer::Int,
            o if is_float_op(o) => Producer::Float,
            o if is_int_binop(o) => Producer::Int,
            _ => Producer::Int,
        };
        let p = push_n(op);
        if p > 0 {
            if k == 0 {
                return kind;
            }
            k -= 1;
        } else if p < 0 {
            k += (-p) as i32;
        } else {
            // net zero: replace/pop the top (load, call, unary) or pop-2/push-1
            if k == 0 {
                return kind;
            }
            if is_int_cmp(op) || is_float_cmp(op) {
                k += 2;
            } else if is_int_binop(op) || is_float_op(op) {
                k -= 1;
            }
        }
        i -= 1;
    }
    Producer::CrossBlock
}

#[derive(Default)]
struct ArgEv {
    ptr: u32,
    float: u32,
    int: u32,
}

impl ArgEv {
    fn guess(&self) -> &'static str {
        if self.ptr > 0 && self.ptr >= self.float && self.ptr >= self.int {
            "ptr"
        } else if self.float > 0 && self.float >= self.int {
            "float"
        } else if self.int > 0 {
            "int"
        } else {
            "unknown"
        }
    }
}

fn arg_index(frame: i32, off: usize) -> Option<usize> {
    let f = frame as usize;
    if off >= f + 8 && (off - f - 8) % 4 == 0 {
        Some((off - f - 8) / 4)
    } else {
        None
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = &args[0];
    let out_path: Option<String> = args
        .iter()
        .find(|a| a.ends_with(".sigs"))
        .map(|s| s.to_string());
    let only: Option<HashSet<usize>> = args.iter().position(|a| a == "--only").and_then(|i| {
        args.get(i + 1).map(|s| {
            s.split(',').map(|t| t.trim().parse::<usize>().unwrap()).collect()
        })
    });

    let mut q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);

    if let Some(nf) = args.iter().find(|a| a.ends_with(".names")) {
        if let Ok(text) = std::fs::read_to_string(nf) {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                if let (Some(f), Some(n)) = (it.next(), it.next()) {
                    if let Some(rest) = f.strip_prefix("fn[") {
                        if let Some(idx) = rest.strip_suffix(']').and_then(|x| x.parse::<usize>().ok()) {
                            if let Some(&(s, _e)) = ranges.get(idx) {
                                q.names.insert(s, n.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut entry_to_fn: Vec<Option<usize>> = vec![None; d.insns.len()];
    for (fi, &(start, _)) in ranges.iter().enumerate() {
        entry_to_fn[start] = Some(fi);
    }

    let n = ranges.len();
    let mut arg_ev_all: Vec<HashMap<usize, ArgEv>> = Vec::with_capacity(n);
    let mut callee_max_k_all: Vec<Option<usize>> = Vec::with_capacity(n);
    let mut frame_all: Vec<i32> = Vec::with_capacity(n);
    let mut caller_max_args: Vec<usize> = vec![0; n];
    let mut caller_ret_use: Vec<(bool, bool)> = vec![(false, false); n]; // (used, float)

    for &(start, end) in ranges.iter() {
        let frame = d.insns[start].operand.unwrap_or(0);
        frame_all.push(frame);
        let mut arg_ev: HashMap<usize, ArgEv> = HashMap::new();
        let mut callee_max_k: Option<usize> = None;
        let mut argset: HashSet<usize> = HashSet::new();

        let mut i = start;
        while i < end {
            let ins = &d.insns[i];
            match ins.op {
                Opcode::Local => {
                    let off = ins.operand.unwrap_or(0) as usize;
                    if let Some(k) = arg_index(frame, off) {
                        callee_max_k = Some(callee_max_k.map_or(k, |m| m.max(k)));
                        let nxt = d.insns.get(i + 1).map(|x| x.op);
                        let ev = arg_ev.entry(k).or_default();
                        match nxt {
                            Some(Opcode::Load1) | Some(Opcode::Load2) | Some(Opcode::Load4) => {
                                let nn = d.insns.get(i + 2).map(|x| x.op);
                                match nn {
                                    Some(o) if is_float_op(o) || is_float_cmp(o) => ev.float += 1,
                                    Some(o) if is_int_binop(o) || is_int_cmp(o) => ev.int += 1,
                                    _ => ev.ptr += 1,
                                }
                            }
                            Some(Opcode::Arg) => ev.ptr += 1,
                            Some(Opcode::Store1) | Some(Opcode::Store2) | Some(Opcode::Store4) => {
                                ev.ptr += 1
                            }
                            _ => {
                                // possibly a Store-target address a few insns later
                                let mut j = i + 1;
                                let mut val_pending = 0usize;
                                while j < end && j < i + 6 {
                                    let oj = d.insns[j].op;
                                    if matches!(oj, Opcode::Store1 | Opcode::Store2 | Opcode::Store4)
                                        && val_pending >= 1
                                    {
                                        ev.ptr += 1;
                                        break;
                                    }
                                    match oj {
                                        Opcode::Const | Opcode::Local | Opcode::Push | Opcode::Call
                                        | Opcode::Load1 | Opcode::Load2 | Opcode::Load4 => {
                                            val_pending += 1
                                        }
                                        Opcode::Pop | Opcode::Arg | Opcode::Jump => {
                                            val_pending = val_pending.saturating_sub(1)
                                        }
                                        Opcode::Store1 | Opcode::Store2 | Opcode::Store4
                                        | Opcode::BlockCopy => {
                                            val_pending = val_pending.saturating_sub(2)
                                        }
                                        _ => {}
                                    }
                                    j += 1;
                                }
                            }
                        }
                    }
                }
                Opcode::Arg => {
                    argset.insert(ins.operand.unwrap_or(0) as usize);
                }
                Opcode::Call => {
                    let target = d.insns.get(i.saturating_sub(1)).and_then(|p| {
                        if p.op == Opcode::Const {
                            p.operand
                        } else {
                            None
                        }
                    });
                    let mut tf = None;
                    if let Some(t) = target {
                        if t >= 0 {
                            tf = entry_to_fn[t as usize];
                        }
                    }
                    let count = argset.len();
                    argset.clear();
                    if let Some(tf) = tf {
                        if count > caller_max_args[tf] {
                            caller_max_args[tf] = count;
                        }
                        let nu = d.insns.get(i + 1).map(|x| x.op);
                        let (used, f) = match nu {
                            Some(Opcode::Pop) => (false, false),
                            Some(o) if is_float_op(o) || is_float_cmp(o) => (true, true),
                            _ => (true, false),
                        };
                        let e = caller_ret_use.get_mut(tf).unwrap();
                        e.0 |= used;
                        e.1 |= f;
                    }
                }
                Opcode::Leave | Opcode::Jump => {
                    argset.clear();
                }
                _ => {}
            }
            i += 1;
        }
        arg_ev_all.push(arg_ev);
        callee_max_k_all.push(callee_max_k);
    }

    // ---- returns: void vs value + float hint ----
    let data = q.data_int32();
    let mut lines: Vec<String> = Vec::new();
    lines.push("# probe_sigs: signatures derived from bytecode (stage C2)".into());
    lines.push("# format: fn[N] <name> frame=<enter> args=<arity> ret=<void|int|float>".into());
    lines.push("# arg types are best-guess from callee usage (ptr/float/int/unknown)".into());
    lines.push("# ' float?' = caller/return path uses the value in a float context".into());

    for (fi, &(start, end)) in ranges.iter().enumerate() {
        if only.as_ref().is_some_and(|s| !s.contains(&fi)) {
            continue;
        }
        let frame = frame_all[fi];
        let ret = match qvm::build_cfg(&d, (start, end), &data) {
            Some(cfg) => {
                let f = qvm::decompile_function(&d, &cfg, frame, &data);
                let reach = qvm::reachable_blocks(&f);
                let assigned: HashSet<usize> = f
                    .blocks
                    .iter()
                    .enumerate()
                    .filter(|(bi, _)| reach[*bi])
                    .flat_map(|(_, b)| b.body.iter())
                    .filter_map(|s| match s {
                        qvm::Stmt::Assign { slot, .. } => Some(*slot),
                        _ => None,
                    })
                    .collect();
                // float-ness inferred for SSA slots and memory locals
                let mut slot_float: HashSet<usize> = HashSet::new();
                let mut local_float: HashSet<usize> = HashSet::new();
                for _round in 0..3 {
                    for (bi, b) in f.blocks.iter().enumerate() {
                        if !reach[bi] {
                            continue;
                        }
                        for s in b.body.iter() {
                            match s {
                                qvm::Stmt::Assign { slot, value, .. } => {
                                    if float_or(slot_float.contains(slot), &local_float, value) {
                                        slot_float.insert(*slot);
                                    }
                                }
                                qvm::Stmt::Store { addr, value, .. } => {
                                    if let qvm::Expr::AddrLocal(off) = addr {
                                        if float_or(
                                            slot_float.contains(off),
                                            &local_float,
                                            value,
                                        ) {
                                            local_float.insert(*off);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                let mut any_value = false;
                let mut any_float = false;
                let mut any_void = false;
                for (bi, b) in f.blocks.iter().enumerate() {
                    if !reach[bi] {
                        continue;
                    }
                    match &b.term {
                        qvm::Terminator::Return(None) => any_void = true,
                        qvm::Terminator::Return(Some(v)) => {
                            let dummy = matches!(v, qvm::Expr::Slot(s) if !assigned.contains(s));
                            if dummy {
                                any_void = true;
                            } else {
                                any_value = true;
                                if is_float_expr(v)
                                    || matches!(
                                        v,
                                        qvm::Expr::Slot(s) if slot_float.contains(s)
                                    )
                                    || matches!(
                                        v,
                                        qvm::Expr::Local { off, .. } if local_float.contains(off)
                                    )
                                {
                                    any_float = true;
                                }
                                // float hint from the producer scan of the epilogue
                                let bi0 = cfg.blocks[bi].start;
                                let bi1 = cfg.blocks[bi].end;
                                if producer_at_leave(&d.insns, bi0, bi1) == Producer::Float {
                                    any_float = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if !any_value && any_void {
                    "void".to_string()
                } else if any_float {
                    "float".to_string()
                } else if any_value {
                    "int".to_string()
                } else {
                    // no reachable Leave (infinite loop / no return) -> int
                    "int".to_string()
                }
            }
            None => "unknown".to_string(),
        };

        let name = q.name_for_fn(start).unwrap_or(&format!("fn_{start}")).to_string();
        let maxk = callee_max_k_all[fi];
        let arity = maxk.map_or(0, |m| m + 1).max(caller_max_args[fi]);
        let (used, caller_float) = caller_ret_use[fi];
        let fmark = ret == "float" || (used && caller_float);
        lines.push(format!(
            "fn[{fi}] {name} frame={frame} args={arity} ret={ret}{}",
            if fmark && ret != "float" { " float?" } else { "" }
        ));
        if let Some(mk) = maxk {
            let mut argline = Vec::new();
            for k in 0..=mk {
                let t = arg_ev_all[fi].get(&k).map(|e| e.guess()).unwrap_or("unknown");
                argline.push(format!("arg{k}={t}"));
            }
            lines.push(format!("    {}", argline.join(" ")));
        }
    }

    match out_path {
        Some(p) => std::fs::write(&p, lines.join("\n") + "\n").expect("write sigs"),
        None => print!("{}\n", lines.join("\n")),
    }
}

fn is_float_expr(e: &qvm::Expr) -> bool {
    match e {
        qvm::Expr::FConst(_) => true,
        // game: sin/cos/atan2/sqrt 103-106, floor/ceil 110/111; cgame/ui: 107/108
        qvm::Expr::Trap(n, _) => matches!(n, 103..=106 | 107 | 108 | 110 | 111),
        qvm::Expr::Unop(op, a) => *op == "(float)" || is_float_expr(a),
        qvm::Expr::Binop(_, a, b) => is_float_expr(a) || is_float_expr(b),
        _ => false,
    }
}

/// Float-ness of a value, extended by slot/local inference sets.
fn float_or(slotf: bool, localf: &HashSet<usize>, e: &qvm::Expr) -> bool {
    match e {
        qvm::Expr::Slot(s) => slotf || is_float_expr(e),
        qvm::Expr::Local { off, .. } => localf.contains(off) || is_float_expr(e),
        // Float-ness comes from Float() markers (float ops as_float operands),
        // not from recursing into operands/addresses and checking inferred
        // slot types (slot-reuse contamination, see decompile::float_or).
        qvm::Expr::Unop(..) | qvm::Expr::Binop(..) | qvm::Expr::MemRef(..) => is_float_expr(e),
        _ => is_float_expr(e),
    }
}
