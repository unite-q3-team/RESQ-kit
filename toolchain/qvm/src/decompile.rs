//! Decompiler: stack machine -> C-like statements.
//!
//! Strategy (v1): model the opstack as a set of virtual slot variables
//! `s0..sN`. Straight-line code is reconstructed as expression trees over the
//! slots; control-flow joins where a slot's value differs between
//! predecessors are resolved by materializing slot assignments (phi).
//!
//! Block terminators are emitted as `goto`/`if (cond) goto`/`return`.
//! Structured reconstruction (if/else/switch/loops) is a later refinement.

use std::collections::{HashMap, HashSet};

use crate::cfg::CFG;
use crate::disasm::Disassembly;
use crate::loader::Qvm;
use crate::opcodes::Opcode;

/// Load/store width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoadSize {
    I1,
    I2,
    I4,
}

impl LoadSize {
    pub fn ty(self) -> &'static str {
        match self {
            LoadSize::I1 => "uchar",
            LoadSize::I2 => "ushort",
            LoadSize::I4 => "int",
        }
    }
}

/// Value expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Const(i32),
    /// Float constant (bits reinterpreted).
    FConst(f32),
    /// Unknown value / phi placeholder: the runtime value of stack slot `i`.
    Slot(usize),
    /// Value of a stack local at `off` (result of `LOCAL off` + `LOAD`).
    Local {
        off: usize,
        size: LoadSize,
    },
    /// Address of a stack local (`LOCAL off`).
    AddrLocal(usize),
    /// Reference into the data/lit segment at byte `addr`.
    GlobalRef {
        addr: usize,
        size: LoadSize,
    },
    /// Dereference of an arbitrary address.
    MemRef(Box<Expr>, LoadSize),
    /// Unary operator.
    Unop(&'static str, Box<Expr>),
    /// Binary operator.
    Binop(&'static str, Box<Expr>, Box<Expr>),
    /// Function call; target is an instruction index (Const >= 0).
    Call(Box<Expr>, Vec<Expr>),
    /// System call (CALL with negative target).
    Trap(u32, Vec<Expr>),
    /// Float context marker: the wrapped value holds float bits (bit-reinterpreted
    /// IEEE-754), regardless of its C-ish sub-expression type. Applied by `as_float`
    /// to float-op operands so float-ness survives in the tree (int and float
    /// operations use the same `+ - * /` op strings).
    Float(Box<Expr>),
}

impl Expr {
    #[allow(dead_code)]
    fn contains_slot(&self, slot: usize) -> bool {
        match self {
            Expr::Slot(s) => *s == slot,
            Expr::Unop(_, a) => a.contains_slot(slot),
            Expr::Binop(_, a, b) => a.contains_slot(slot) || b.contains_slot(slot),
            Expr::MemRef(a, _) => a.contains_slot(slot),
            Expr::Call(t, args) => {
                t.contains_slot(slot) || args.iter().any(|a| a.contains_slot(slot))
            }
            Expr::Trap(_, args) => args.iter().any(|a| a.contains_slot(slot)),
            Expr::Float(a) => a.contains_slot(slot),
            _ => false,
        }
    }
}

/// A lowered statement inside a block body.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// `s<slot> = value` (kept only if the slot is read across blocks).
    Assign { slot: usize, value: Expr },
    /// `*addr = value`.
    Store {
        addr: Expr,
        value: Expr,
        size: LoadSize,
    },
    /// `memcpy(dest, src, count)`.
    BlockCopy { dest: Expr, src: Expr, count: i32 },
}

/// Block terminator.
#[derive(Debug, Clone)]
pub enum Terminator {
    Return(Option<Expr>),
    Goto(usize),
    IfGoto {
        cond: Expr,
        target: usize,
    },
    /// Resolved jump table: `switch (sel) { case k: goto target_insn; }`.
    /// `default` is the bounds-check default target (both LTI/GTI checks jump
    /// there), as an instruction index.
    Switch {
        sel: Box<Expr>,
        cases: Vec<(i32, usize)>,
        default: Option<usize>,
    },
    /// Indirect jump we could not resolve statically.
    Unresolved(Expr),
    Fallthrough,
}

/// A lowered basic block.
#[derive(Debug, Clone)]
pub struct LoweredBlock {
    pub start: usize,
    pub body: Vec<Stmt>,
    pub term: Terminator,
}

/// A decompiled function.
#[derive(Debug, Clone)]
pub struct Function {
    pub start: usize,
    pub end: usize,
    /// ENTER operand: stack frame size.
    pub frame: i32,
    pub blocks: Vec<LoweredBlock>,
    /// Slots read across blocks (used to decide which slot assigns to keep).
    pub read_slots: std::collections::BTreeSet<usize>,
    /// Argument count inferred from ARG marshaling instructions.
    pub arity: usize,
    /// True when at least one block returns a value.
    pub returns: bool,
}

/// Net opstack effect of an opcode (items pushed minus popped).
pub fn net_stack_effect(op: Opcode) -> i32 {
    use Opcode::*;
    match op {
        Const | Local | Push => 1,
        Pop | Arg | Jump => -1,
        Store1 | Store2 | Store4 | BlockCopy => -2,
        Eq | Ne | Lti | Lei | Gti | Gei | Ltu | Leu | Gtu | Geu | Eqf | Nef | Ltf | Lef | Gtf
        | Gef => -2,
        Add | Sub | Divi | Divu | Modi | Modu | Muli | Mulu | Band | Bor | Bxor | Lsh | Rshi
        | Rshu | AddF | SubF | DivF | MulF => -1,
        _ => 0, // Call, Load*, Enter, Leave, unary, Undef, Ignore, Break
    }
}

fn is_control(op: Opcode) -> bool {
    op == Opcode::Leave || op == Opcode::Jump || op.is_branch_idx()
}

/// Compute the opstack height before every instruction, propagated through the CFG.
pub fn compute_heights(d: &Disassembly, cfg: &CFG) -> Vec<i32> {
    let nblocks = cfg.blocks.len();
    let mut entry_h: Vec<Option<i32>> = vec![None; nblocks];
    let mut h_at: Vec<i32> = vec![0; d.insns.len()];
    let mut in_q = vec![false; nblocks];
    let mut queue: Vec<usize> = vec![cfg.entry];
    entry_h[cfg.entry] = Some(0);
    in_q[cfg.entry] = true;
    while let Some(bi) = queue.pop() {
        in_q[bi] = false;
        let h0 = entry_h[bi].unwrap();
        let mut h = h0;
        let b = &cfg.blocks[bi];
        for i in b.start..b.end {
            h_at[i] = h;
            h += net_stack_effect(d.insns[i].op);
        }
        for &s in &b.succ {
            let new = h;
            match entry_h[s] {
                None => {
                    entry_h[s] = Some(new);
                    if !in_q[s] {
                        in_q[s] = true;
                        queue.push(s);
                    }
                }
                Some(old) if old != new => {
                    let m = old.max(new);
                    if m != old {
                        entry_h[s] = Some(m);
                        if !in_q[s] {
                            in_q[s] = true;
                            queue.push(s);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    h_at
}

// ---- pass 1: value tracking (known/unknown per slot) ----

type ValStack = Vec<Option<Expr>>;

fn track_step(op: Opcode, operand: i32, st: &mut ValStack) {
    use Opcode::*;
    match op {
        Const => st.push(Some(Expr::Const(operand))),
        Local => st.push(Some(Expr::AddrLocal(operand as usize))),
        Push => st.push(None),
        Pop | Arg | Jump => {
            st.pop();
        }
        Call => {
            st.pop();
            st.push(None);
        }
        Load1 | Load2 | Load4 => {
            let size = load_size(op);
            let a = st.pop().unwrap_or(None);
            st.push(a.map(|e| simplify(Expr::MemRef(Box::new(e), size))));
        }
        Store1 | Store2 | Store4 | BlockCopy => {
            st.pop();
            st.pop();
        }
        Eq | Ne | Lti | Lei | Gti | Gei | Ltu | Leu | Gtu | Geu | Eqf | Nef | Ltf | Lef | Gtf
        | Gef => {
            st.pop();
            st.pop();
        }
        Add | Sub | Divi | Divu | Modi | Modu | Muli | Mulu | Band | Bor | Bxor | Lsh | Rshi
        | Rshu => {
            let b = st.pop().flatten();
            let a = st.pop().flatten();
            let e = match (a, b) {
                (Some(x), Some(y)) => {
                    Some(simplify(Expr::Binop(int_op(op), Box::new(x), Box::new(y))))
                }
                _ => None,
            };
            st.push(e);
        }
        AddF | SubF | DivF | MulF => {
            let b = st.pop().flatten();
            let a = st.pop().flatten();
            let e = match (a, b) {
                (Some(x), Some(y)) => Some(simplify(Expr::Binop(
                    float_op(op),
                    Box::new(as_float(x)),
                    Box::new(as_float(y)),
                ))),
                _ => None,
            };
            st.push(e);
        }
        Negi | Bcom => {
            if let Some(x) = st.last_mut() {
                *x = x
                    .clone()
                    .map(|e| simplify(Expr::Unop(un_op(op), Box::new(e))));
            }
        }
        Negf => {
            if let Some(x) = st.last_mut() {
                *x = x
                    .clone()
                    .map(|e| simplify(Expr::Unop("-", Box::new(as_float(e)))));
            }
        }
        Sex8 | Sex16 => {
            // sign-extend the low byte/word: mark the value with a signed-cast
            // marker so it is rendered as a signed load (lcc re-emits SEX8/SEX16).
            if let Some(x) = st.last_mut() {
                let marker = if matches!(op, Sex8) {
                    "(signed char)"
                } else {
                    "(signed short)"
                };
                *x = x.clone().map(|e| Expr::Unop(marker, Box::new(e)));
            }
        }
        Cvif => {
            if let Some(x) = st.last_mut() {
                *x = x.clone().map(cvif_expr);
            }
        }
        Cvfi => {
            if let Some(x) = st.last_mut() {
                *x = x.clone().map(cvfi_expr);
            }
        }
        Enter | Leave | Undef | Ignore | Break => {}
    }
}

// ---- pass 2: lowering to statements ----

/// One virtual opstack cell: a known value (optionally), and a stable slot id.
#[derive(Debug, Clone)]
struct Cell {
    value: Option<Expr>,
    id: usize,
}

type Track = Vec<Cell>;

/// True if evaluating `e` again is safe (no side effects).
fn is_pure(e: &Expr) -> bool {
    match e {
        Expr::Call(..) | Expr::Trap(..) => false,
        Expr::MemRef(a, _) => is_pure(a),
        Expr::Float(a) => is_pure(a),
        Expr::Unop(_, a) => is_pure(a),
        Expr::Binop(_, a, b) => is_pure(a) && is_pure(b),
        _ => true,
    }
}

struct Lower<'a> {
    d: &'a Disassembly,
    cfg: &'a CFG,
    /// Initialized data segment as little-endian int32 (for jump-table resolution).
    data: &'a [i32],
    reads: std::collections::BTreeSet<usize>,
    /// Best-effort constant propagation for stack locals written with a
    /// constant and never re-stored: local offset -> const value.
    local_consts: HashMap<usize, i32>,
    /// Blocks whose terminator is a switch bounds-check; their conditions are
    /// absorbed into `switch ... default:` and replaced with `Fallthrough`.
    absorb_blocks: Vec<usize>,
}

impl<'a> Lower<'a> {
    fn read_cell(&mut self, st: &mut Vec<Cell>, from_top: usize, next_id: &mut usize) -> Expr {
        let depth = st.len().saturating_sub(from_top);
        while st.len() <= depth {
            let id = *next_id;
            *next_id += 1;
            st.push(Cell { value: None, id });
        }
        let c = &st[depth];
        match &c.value {
            Some(v) if is_pure(v) => v.clone(),
            _ => {
                self.reads.insert(c.id);
                Expr::Slot(c.id)
            }
        }
    }

    fn write_cell(
        &mut self,
        st: &mut Track,
        depth: usize,
        val: Expr,
        body: &mut Vec<Stmt>,
        next_id: &mut usize,
    ) {
        while st.len() <= depth {
            let id = *next_id;
            *next_id += 1;
            st.push(Cell { value: None, id });
        }
        let id = *next_id;
        *next_id += 1;
        st[depth] = Cell {
            value: Some(val.clone()),
            id,
        };
        body.push(Stmt::Assign {
            slot: id,
            value: val,
        });
    }
}

fn load_size(op: Opcode) -> LoadSize {
    match op {
        Opcode::Load1 | Opcode::Store1 => LoadSize::I1,
        Opcode::Load2 | Opcode::Store2 => LoadSize::I2,
        _ => LoadSize::I4,
    }
}

fn int_op(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Add => "+",
        Sub => "-",
        Divi => "/",
        Divu => "/u",
        Modi => "%",
        Modu => "%u",
        Muli => "*",
        Mulu => "*u",
        Band => "&",
        Bor => "|",
        Bxor => "^",
        Lsh => "<<",
        Rshi => ">>",
        Rshu => ">>u",
        _ => "?",
    }
}

fn float_op(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        AddF => "+",
        SubF => "-",
        DivF => "/",
        MulF => "*",
        _ => "?",
    }
}

fn un_op(op: Opcode) -> &'static str {
    match op {
        Opcode::Negi => "-",
        Opcode::Bcom => "~",
        _ => "?",
    }
}

fn as_float(e: Expr) -> Expr {
    match e {
        Expr::Const(c) => Expr::FConst(f32::from_bits(c as u32)),
        Expr::FConst(_) | Expr::Float(_) => e,
        e => Expr::Float(Box::new(e)),
    }
}

/// CVIF: int→float conversion (lcc `(float)expr`). Unlike `as_float` (which
/// REINTERPRETS bits already holding a float), this CONVERTS an int value:
/// `Const(10)` becomes `FConst(10.0f)` (not `f32::from_bits(10)`), and any
/// non-constant int expression becomes an explicit `(float)` cast so the
/// emitter renders a conversion rather than a bit reinterpret.
fn cvif_expr(e: Expr) -> Expr {
    match e {
        Expr::FConst(_) | Expr::Float(_) => e,
        Expr::Const(c) => Expr::FConst(c as f32),
        e => Expr::Unop("(float)", Box::new(e)),
    }
}

/// CVFI: float→int conversion. The operand holds IEEE-754 bits; a value read
/// from memory (`MemRef`/`Local`/`GlobalRef`) must therefore be re-rendered
/// as a float deref so the emitter produces `*(float*)` and lcc re-emits the
/// CVFI. Reading the word as `*(int*)` feeds the raw bit pattern (e.g. 5.0f =
/// 0x40A00000) into int arithmetic/bounds checks (CG_PlayerAngles `dir>7`
/// crash on the rebuilt cgame). Pure int expressions (slots, constants,
/// arithmetic) keep the plain `(int)` cast.
fn cvfi_expr(e: Expr) -> Expr {
    match e {
        Expr::FConst(f) => Expr::Const(f as i32),
        Expr::Float(a) => Expr::Unop("(int)", a),
        Expr::MemRef(a, size) => Expr::Unop(
            "(int)",
            Box::new(Expr::Float(Box::new(Expr::MemRef(a, size)))),
        ),
        Expr::Local { off, size } => Expr::Unop(
            "(int)",
            Box::new(Expr::Float(Box::new(Expr::Local { off, size }))),
        ),
        Expr::GlobalRef { addr, size } => Expr::Unop(
            "(int)",
            Box::new(Expr::Float(Box::new(Expr::GlobalRef { addr, size }))),
        ),
        e => Expr::Unop("(int)", Box::new(e)),
    }
}

/// True if `e` is a float-typed value: a float constant, a float-context marker,
/// a float-returning trap, or an expression derived from one.
///
/// Float trap numbers (game: sin/cos/atan2/sqrt 103-106, floor/ceil 110/111;
/// cgame/ui: 107/108) are listed here because a `Trap` used as a float operand
/// carries no other float mark.
pub fn is_float_expr(e: &Expr) -> bool {
    match e {
        Expr::FConst(_) | Expr::Float(_) => true,
        Expr::Trap(n, _) => matches!(n, 103..=106 | 107 | 108 | 110 | 111),
        Expr::Unop(op, a) => match *op {
            // Cvfi converts float -> int; the result is not float.
            "(int)" => false,
            // Cvif converts int -> float; the result is float.
            "(float)" => true,
            _ => is_float_expr(a),
        },
        // int ops never float-mark their operands, so a Float operand means
        // this whole binop is a float operation.
        Expr::Binop(_, a, b) => is_float_expr(a) || is_float_expr(b),
        _ => false,
    }
}

/// Float-ness of a value, extended by the slot/local float-inference sets:
/// a `Slot(s)` is float when the slot ever holds float data, and a
/// `Local{off}` when the stack local does.
pub fn float_or(slotf: bool, localf: &HashSet<usize>, e: &Expr) -> bool {
    match e {
        Expr::Slot(_) => slotf || is_float_expr(e),
        Expr::Local { off, .. } => localf.contains(off) || is_float_expr(e),
        // Float(x) means "x's bits are a float" (as_float wraps every operand
        // of a float op). It is unconditionally float: recursing into x made
        // float stores of memory loads (e.g. AnglesToAxis `axis[1] = vec3_origin
        // - right`) render `*(int*)` and lcc inserted a spurious CVFI.
        Expr::Float(_) => true,
        // Operators/loads decide float-ness from the Float() markers already
        // in the IR (every float op as_float's its operands) — never by
        // recursing into operands/addresses and checking inferred slot types.
        // Recursing let a slot reused as both an int pointer temp and a float
        // value (COM_ParseFloat: `*(signed char*)ptr` and `ptr + 1` next to a
        // `0.1f` scale) be contaminated into float, emitting `*(float*)`
        // loads, `qvm_fbits` compares, and spurious CVIF/CVFI round-trips.
        Expr::Unop(..) | Expr::Binop(..) | Expr::MemRef(..) => is_float_expr(e),
        _ => is_float_expr(e),
    }
}

fn cmp_op(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Eq => "==",
        Ne => "!=",
        Lti => "<",
        Lei => "<=",
        Gti => ">",
        Gei => ">=",
        Ltu => "<u",
        Leu => "<=u",
        Gtu => ">u",
        Geu => ">=u",
        Ltf => "<",
        Lef => "<=",
        Gtf => ">",
        Gef => ">=",
        Eqf => "==",
        Nef => "!=",
        _ => "?",
    }
}

/// Constant folding + memory simplification.
pub fn simplify(e: Expr) -> Expr {
    match e {
        Expr::MemRef(addr, size) => match *addr {
            Expr::AddrLocal(off) => Expr::Local { off, size },
            Expr::Const(c) => Expr::GlobalRef {
                addr: c as usize,
                size,
            },
            a => Expr::MemRef(Box::new(a), size),
        },
        Expr::Binop(op, a, b) => {
            let (a, b) = (*a, *b);
            if let (Expr::Const(x), Expr::Const(y)) = (&a, &b) {
                let fold = match op {
                    "+" => x.checked_add(*y),
                    "-" => x.checked_sub(*y),
                    "*" => x.checked_mul(*y),
                    "&" => Some(x & y),
                    "|" => Some(x | y),
                    "^" => Some(x ^ y),
                    "<<" => Some(x.wrapping_shl(*y as u32)),
                    ">>" => Some(x >> *y),
                    "/" if *y != 0 => Some(x.wrapping_div(*y)),
                    "%" if *y != 0 => Some(x.wrapping_rem(*y)),
                    _ => None,
                };
                if let Some(v) = fold {
                    return Expr::Const(v);
                }
            }
            // x op 0 / 0 op x identities (avoid infinite recursion on x+0)
            if op == "+" && b == Expr::Const(0) {
                return a;
            }
            if op == "+" && a == Expr::Const(0) {
                return b;
            }
            if op == "*" && b == Expr::Const(1) {
                return a;
            }
            if op == "*" && a == Expr::Const(1) {
                return b;
            }
            Expr::Binop(op, Box::new(a), Box::new(b))
        }
        Expr::Unop("-", a) => match *a {
            Expr::Const(c) => Expr::Const(c.wrapping_neg()),
            a => Expr::Unop("-", Box::new(a)),
        },
        Expr::Unop("~", a) => match *a {
            Expr::Const(c) => Expr::Const(!c),
            a => Expr::Unop("~", Box::new(a)),
        },
        Expr::Float(a) => Expr::Float(Box::new(simplify(*a))),
        e => e,
    }
}

/// Decompile one function.
pub fn decompile_function(d: &Disassembly, cfg: &CFG, frame: i32, data: &[i32]) -> Function {
    let mut f = decompile_function_raw(d, cfg, frame, data);
    inline_single_use_slots(&mut f);
    f
}

fn decompile_function_raw(d: &Disassembly, cfg: &CFG, frame: i32, data: &[i32]) -> Function {
    let heights = compute_heights(d, cfg);
    let nblocks = cfg.blocks.len();

    // ---- pass 1: known-value propagation ----
    let mut entry_known: Vec<ValStack> = vec![Vec::new(); nblocks];
    let mut in_q = vec![false; nblocks];
    let mut queue: Vec<usize> = vec![cfg.entry];
    in_q[cfg.entry] = true;
    while let Some(bi) = queue.pop() {
        in_q[bi] = false;
        let eh = heights[cfg.blocks[bi].start] as usize;
        let mut st: ValStack = entry_known[bi].clone();
        while st.len() < eh {
            st.push(None);
        }
        let b = &cfg.blocks[bi];
        for i in b.start..b.end {
            if i == b.end - 1 && is_control(d.insns[i].op) {
                break;
            }
            let ins = &d.insns[i];
            track_step(ins.op, ins.operand.unwrap_or(0), &mut st);
        }
        let ex = st;
        for &s in &b.succ {
            let mut changed = false;
            while entry_known[s].len() < ex.len() {
                entry_known[s].push(None);
                changed = true;
            }
            for (dd, mine) in ex.iter().enumerate() {
                let their = &entry_known[s][dd];
                match (mine, their) {
                    (Some(a), Some(b2)) if a == b2 => {}
                    (Some(_), Some(_)) => {
                        entry_known[s][dd] = None;
                        changed = true;
                    }
                    (None, Some(_)) => {
                        entry_known[s][dd] = None;
                        changed = true;
                    }
                    (_, None) => {}
                }
            }
            if changed && !in_q[s] {
                in_q[s] = true;
                queue.push(s);
            }
        }
    }

    // ---- pass 2: lowering ----
    let mut lower = Lower {
        d,
        cfg,
        data,
        reads: std::collections::BTreeSet::new(),
        local_consts: HashMap::new(),
        absorb_blocks: Vec::new(),
    };
    let mut next_id = 0usize;
    let mut post: Vec<Option<Track>> = vec![None; nblocks];
    let mut post_lc: Vec<Option<HashMap<usize, i32>>> = vec![None; nblocks];
    // Pending call args (`ARG off` writes) carried across blocks: a call's
    // args can be split by a branch (ARG 8/12 before the branch, ARG 16/20
    // plus the CALL in the merge block), so a block-local map would lose the
    // earlier args.  Mirrors `post` so the driver can inherit/merge them.
    let mut post_args: Vec<Option<HashMap<usize, Expr>>> = vec![None; nblocks];
    let mut blocks_out: Vec<LoweredBlock> = Vec::with_capacity(nblocks);
    for bi in 0..nblocks {
        let entry = entry_track(cfg, &post, &entry_known, bi, &heights, &mut next_id);
        let args_in = block_entry_args(cfg, &post_args, bi);
        // input const map: flow-sensitive. Single pred -> reuse its exit map;
        // otherwise intersect the exit maps of all known preds (a local is only
        // treated as a known constant if every reaching definition is the same
        // constant).
        let preds = &cfg.blocks[bi].pred;
        let lc_in = if preds.len() == 1 {
            post_lc[preds[0]].clone().unwrap_or_default()
        } else {
            let mut all_known = true;
            let mut merge: HashMap<usize, i32> = HashMap::new();
            let mut first = true;
            for &p in preds {
                match &post_lc[p] {
                    Some(m) => {
                        if first {
                            merge = m.clone();
                            first = false;
                        } else {
                            merge.retain(|k, v| m.get(k).copied() == Some(*v));
                        }
                    }
                    None => all_known = false,
                }
            }
            if all_known && !first {
                merge
            } else {
                HashMap::new()
            }
        };
        lower.local_consts = lc_in;
        let (blk, exit, exit_args) = lower_block(&mut lower, bi, entry, args_in, &mut next_id);
        post[bi] = Some(exit);
        post_args[bi] = Some(exit_args);
        post_lc[bi] = Some(lower.local_consts.clone());
        blocks_out.push(blk);
    }

    // Absorb switch bounds-checks: their conditional terminator is now
    // represented by `switch ... default:`, so the checks become fallthrough
    // blocks. Their comparison operands were consumed via the stack and leave
    // no statements, but the block may also hold real side effects (typically
    // the `sel = p0` store of the dispatch value before the bounds) — keep
    // everything except dead pure slot writes.
    if !lower.absorb_blocks.is_empty() {
        for blk in blocks_out.iter_mut() {
            if lower.absorb_blocks.contains(&blk.start) {
                blk.term = Terminator::Fallthrough;
                blk.body.retain(|st| match st {
                    Stmt::Assign { slot, value } => lower.reads.contains(slot) || !is_pure(value),
                    _ => true,
                });
            }
        }
    }

    // Signature inference: arity from ARG marshaling (offsets are 4, 8, ...),
    // return type from presence of value-returning terminators.
    let arity = (cfg.start..cfg.end)
        .filter_map(|i| d.at(i))
        .filter(|ins| ins.op == Opcode::Arg)
        .filter_map(|ins| ins.operand)
        .max()
        .map_or(0, |m| m as usize / 4 + 1);
    let returns = blocks_out
        .iter()
        .any(|b| matches!(b.term, Terminator::Return(Some(_))));

    Function {
        start: cfg.start,
        end: cfg.end,
        frame,
        blocks: blocks_out,
        read_slots: lower.reads,
        arity,
        returns,
    }
}

/// Replace `Expr::Slot(s)` with the value in `subst`, recursively.
fn subst_slots(e: &Expr, subst: &HashMap<usize, Expr>) -> Expr {
    match e {
        Expr::Slot(s) => subst.get(s).cloned().unwrap_or_else(|| e.clone()),
        Expr::Unop(op, a) => Expr::Unop(op, Box::new(subst_slots(a, subst))),
        Expr::Binop(op, a, b) => Expr::Binop(
            op,
            Box::new(subst_slots(a, subst)),
            Box::new(subst_slots(b, subst)),
        ),
        Expr::MemRef(a, size) => Expr::MemRef(Box::new(subst_slots(a, subst)), *size),
        Expr::Call(t, args) => Expr::Call(
            Box::new(subst_slots(t, subst)),
            args.iter().map(|a| subst_slots(a, subst)).collect(),
        ),
        Expr::Trap(n, args) => Expr::Trap(*n, args.iter().map(|a| subst_slots(a, subst)).collect()),
        Expr::Float(a) => Expr::Float(Box::new(subst_slots(a, subst))),
        other => other.clone(),
    }
}

/// Record every `Expr::Slot` reachable from `e` as a use at statement `si`
/// of block `bi`. The terminator is `si = usize::MAX`.
fn collect_slot_uses(
    e: &Expr,
    uses: &mut HashMap<usize, Vec<(usize, usize)>>,
    bi: usize,
    si: usize,
) {
    match e {
        Expr::Slot(s) => uses.entry(*s).or_default().push((bi, si)),
        Expr::Unop(_, a) => collect_slot_uses(a, uses, bi, si),
        Expr::Binop(_, a, b) => {
            collect_slot_uses(a, uses, bi, si);
            collect_slot_uses(b, uses, bi, si);
        }
        Expr::MemRef(a, _) => collect_slot_uses(a, uses, bi, si),
        Expr::Call(t, args) => {
            collect_slot_uses(t, uses, bi, si);
            for a in args {
                collect_slot_uses(a, uses, bi, si);
            }
        }
        Expr::Trap(_, args) => {
            for a in args {
                collect_slot_uses(a, uses, bi, si);
            }
        }
        Expr::Float(a) => collect_slot_uses(a, uses, bi, si),
        _ => {}
    }
}

/// Copy-propagate slots that have exactly one use into that use, then drop
/// the defining `Assign`. A slot is only inlined when its single use sits in
/// the same block, strictly after the definition (or in the terminator), so
/// impure values (call/trap results) are still evaluated exactly once and in
/// order. Cross-block and multi-use slots keep their `Assign`.
fn inline_single_use_slots(f: &mut Function) {
    let mut uses: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    for (bi, b) in f.blocks.iter().enumerate() {
        for (si, st) in b.body.iter().enumerate() {
            match st {
                Stmt::Assign { value, .. } => collect_slot_uses(value, &mut uses, bi, si),
                Stmt::Store { addr, value, .. } => {
                    collect_slot_uses(addr, &mut uses, bi, si);
                    collect_slot_uses(value, &mut uses, bi, si);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    collect_slot_uses(dest, &mut uses, bi, si);
                    collect_slot_uses(src, &mut uses, bi, si);
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => collect_slot_uses(v, &mut uses, bi, usize::MAX),
            Terminator::IfGoto { cond, .. } => collect_slot_uses(cond, &mut uses, bi, usize::MAX),
            Terminator::Switch { sel, .. } => collect_slot_uses(sel, &mut uses, bi, usize::MAX),
            Terminator::Unresolved(a) => collect_slot_uses(a, &mut uses, bi, usize::MAX),
            _ => {}
        }
    }

    for (bi, b) in f.blocks.iter_mut().enumerate() {
        let mut subst: HashMap<usize, Expr> = HashMap::new();
        let mut keep = vec![true; b.body.len()];
        for si in 0..b.body.len() {
            // substitute earlier single-use slots into this statement
            match &mut b.body[si] {
                Stmt::Assign { value, .. } => *value = subst_slots(value, &subst),
                Stmt::Store { addr, value, .. } => {
                    *addr = subst_slots(addr, &subst);
                    *value = subst_slots(value, &subst);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    *dest = subst_slots(dest, &subst);
                    *src = subst_slots(src, &subst);
                }
            }
            if let Stmt::Assign { slot, value } = &b.body[si] {
                let u = uses.get(slot).map(|v| v.as_slice()).unwrap_or(&[]);
                let single_later = u.len() == 1 && u[0].0 == bi && u[0].1 > si;
                if single_later {
                    let value = value.clone();
                    subst.insert(*slot, value);
                    keep[si] = false;
                }
            }
        }
        match &mut b.term {
            Terminator::Return(Some(v)) => *v = subst_slots(v, &subst),
            Terminator::IfGoto { cond, .. } => *cond = subst_slots(cond, &subst),
            Terminator::Switch { sel, .. } => **sel = subst_slots(sel, &subst),
            Terminator::Unresolved(a) => *a = subst_slots(a, &subst),
            _ => {}
        }
        let mut new_body = Vec::with_capacity(b.body.len());
        for (st, k) in b.body.drain(..).zip(&keep) {
            if *k {
                new_body.push(st);
            }
        }
        b.body = new_body;
    }
}

/// Build the entry stack of a block.
///
/// - Single predecessor with a known exit state -> reuse its cells exactly
///   (straight-line value flow; preserves slot ids so impure values like call
///   results are materialized once in the predecessor).
/// - Otherwise -> phi cells: known-equal pure values are inlined, everything
///   else becomes an unknown slot.
fn entry_track(
    cfg: &CFG,
    post: &[Option<Track>],
    entry_known: &[ValStack],
    bi: usize,
    heights: &[i32],
    next_id: &mut usize,
) -> Track {
    let preds = &cfg.blocks[bi].pred;
    if preds.len() == 1 {
        if let Some(t) = &post[preds[0]] {
            return t.clone();
        }
    }
    let eh = heights[cfg.blocks[bi].start].max(0) as usize;
    let mut t = Vec::with_capacity(eh);
    for i in 0..eh {
        let v = entry_known[bi].get(i).cloned().flatten();
        let value = match v {
            Some(v) if is_pure(&v) => Some(v),
            _ => None,
        };
        let id = *next_id;
        *next_id += 1;
        t.push(Cell { value, id });
    }
    t
}

/// Entry pending call-args of a block (from `ARG off` writes in predecessors).
///
/// - Single predecessor -> reuse its exit args (straight-line flow).
/// - Multiple predecessors -> keep only args written identically by every
///   known predecessor (a call reached on several paths must agree).
/// - Unknown predecessor (back edge not yet lowered) -> empty.
fn block_entry_args(
    cfg: &CFG,
    post_args: &[Option<HashMap<usize, Expr>>],
    bi: usize,
) -> HashMap<usize, Expr> {
    let preds = &cfg.blocks[bi].pred;
    if preds.is_empty() {
        return HashMap::new();
    }
    if preds.len() == 1 {
        return post_args[preds[0]].clone().unwrap_or_default();
    }
    let mut all_known = true;
    let mut merge: HashMap<usize, Expr> = HashMap::new();
    let mut first = true;
    for &p in preds {
        match &post_args[p] {
            Some(a) => {
                if first {
                    merge = a.clone();
                    first = false;
                } else {
                    merge.retain(|k, v| a.get(k) == Some(v));
                }
            }
            None => all_known = false,
        }
    }
    if all_known && !first {
        merge
    } else {
        HashMap::new()
    }
}

/// Resolve an indirect jump through a data jump table.
///
/// Recognizes the lcc switch-dispatch shape
/// `*(int*)((sel << 2) + base)` and reads the table at data offset
/// `base`, one `i32` per case (entry k -> instruction index of case k).
/// A table ends at the first entry outside the current function's
/// instruction range `[cfg.start, cfg.end)`, so adjacent tables in the
/// same data segment do not bleed into each other.
/// Find [lo, hi] of an lcc switch dispatch from the bounds checks that
/// precede it in the CFG.  Pattern:
///   CONST lo; LTI  default      (sel < lo  -> default)   lo = const
///   CONST hi; GTI  default      (sel > hi  -> default)   hi = const
/// The bound constant may also be loaded from a constant local
/// (`LOCAL off; LOAD4`), resolved through `local_consts`.
/// Walk the unique-predecessor chain of the dispatch block, reading the
/// comparison + const immediately preceding each comparison.
/// Returns (lo, hi, default target insn, starts of the absorbed bound blocks).
fn switch_bounds(
    cfg: &CFG,
    d: &Disassembly,
    bi: usize,
    local_consts: &HashMap<usize, i32>,
) -> Option<(i32, i32, usize, Vec<usize>)> {
    use Opcode::{Const, Gei, Gti, Lei, Load4, Local, Lti};
    let mut cur = bi;
    let mut lo: Option<(i32, usize)> = None; // (const, default target)
    let mut hi: Option<(i32, usize)> = None;
    let mut absorb: Vec<usize> = Vec::new();
    for _ in 0..16 {
        if lo.is_some() && hi.is_some() {
            break;
        }
        let preds = &cfg.blocks[cur].pred;
        if preds.len() != 1 {
            break;
        }
        let p = preds[0];
        if p >= cur {
            break;
        }
        let blk = &cfg.blocks[p];
        if blk.end - blk.start >= 2 {
            let last = &d.insns[blk.end - 1];
            let prev = &d.insns[blk.end - 2];
            let bound = match (prev.op, prev.operand) {
                (Const, Some(c)) => Some(c),
                (Load4, _) if blk.end - blk.start >= 3 => {
                    let local = &d.insns[blk.end - 3];
                    match (local.op, local.operand) {
                        (Local, Some(off)) => local_consts.get(&(off as usize)).copied(),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(c) = bound {
                let default_t = last.target.unwrap_or(0);
                match last.op {
                    Lti if lo.is_none() => {
                        lo = Some((c, default_t));
                        absorb.push(blk.start);
                    }
                    Lei if lo.is_none() => {
                        lo = Some((c + 1, default_t));
                        absorb.push(blk.start);
                    }
                    Gti if hi.is_none() => {
                        hi = Some((c, default_t));
                        absorb.push(blk.start);
                    }
                    Gei if hi.is_none() => {
                        hi = Some((c - 1, default_t));
                        absorb.push(blk.start);
                    }
                    _ => {}
                }
            }
        }
        cur = p;
    }
    match (lo, hi) {
        (Some((l, _)), Some((h, _))) if l <= h => {
            let dlo = lo.unwrap().1;
            let dhi = hi.unwrap().1;
            if dlo == dhi && dlo != 0 {
                Some((l, h, dlo, absorb))
            } else if dlo != 0 {
                // The two bound checks target different blocks (a nested/dual
                // dispatch, e.g. Q_vsprintf where `<lo` enters a second switch
                // and `>hi` a separate handler). No single `default` exists, so
                // keep the bounds as explicit if/else (no absorption); the
                // default resolves to None in resolve_switch.
                Some((l, h, dlo, Vec::new()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Collect the switch cases `(case_value, target_insn)` for an lcc dispatch.
/// Resolved jump table: selector expression, `(case value, target insn)` pairs
/// sorted as emitted, optional default target, and the bound-check blocks the
/// switch absorbed.
type SwitchLayout = (Expr, Vec<(i32, usize)>, Option<usize>, Vec<usize>);

/// Indexing is `sel << 2 + base`, so the case window is given by the bounds
/// checks [lo, hi] (or, as a fallback, by scanning from entry 0).
/// Returns `(sel, cases, default_insn, absorbed_bound_blocks)`.
fn resolve_switch(
    addr: &Expr,
    d: &Disassembly,
    cfg: &CFG,
    data: &[i32],
    bi: usize,
    local_consts: &HashMap<usize, i32>,
) -> Option<SwitchLayout> {
    let Expr::MemRef(inner, size) = addr else {
        return None;
    };
    if *size != LoadSize::I4 {
        return None;
    }
    let Expr::Binop("+", a, b) = inner.as_ref() else {
        return None;
    };
    let (sel, shift) = match (a.as_ref(), b.as_ref()) {
        (Expr::Binop("<<", s, sh), Expr::Const(_)) | (Expr::Const(_), Expr::Binop("<<", s, sh)) => {
            match (s.as_ref(), sh.as_ref()) {
                (sel_expr, Expr::Const(shc)) => (sel_expr.clone(), *shc),
                _ => return None,
            }
        }
        _ => return None,
    };
    let base = match (a.as_ref(), b.as_ref()) {
        (Expr::Binop("<<", _, _), Expr::Const(ba)) => *ba,
        (Expr::Const(ba), Expr::Binop("<<", _, _)) => *ba,
        _ => return None,
    };
    if shift != 2 {
        return None; // only 4-byte index tables for now
    }
    let base = base as usize;
    if !base.is_multiple_of(4) || base / 4 >= data.len() {
        return None;
    }

    let collect = |lo: i32, hi: i32| -> Option<Vec<(i32, usize)>> {
        let mut cases = Vec::new();
        for k in lo..=hi {
            let i = match (base / 4).checked_add_signed(k as isize) {
                Some(i) => i,
                None => continue,
            };
            if i >= data.len() {
                break;
            }
            let t = data[i] as usize;
            if t == 0 {
                continue; // unused hole slot in a sparse table
            }
            if t < cfg.start || t >= cfg.end {
                return None; // entry is not an instruction in this function
            }
            cases.push((k, t));
        }
        if cases.is_empty() {
            None
        } else {
            Some(cases)
        }
    };

    let (cases, bound) = match switch_bounds(cfg, d, bi, local_consts) {
        Some((lo, hi, dflt, absorb)) => (collect(lo, hi), Some((dflt, absorb))),
        None => {
            // fallback: scan from entry 0 for a run of valid targets
            let mut cases = Vec::new();
            for k in 0..1024usize {
                let i = base / 4 + k;
                if i >= data.len() {
                    break;
                }
                let t = data[i] as usize;
                if t == 0 || t < cfg.start || t >= cfg.end {
                    break;
                }
                cases.push((k as i32, t));
            }
            if cases.is_empty() {
                (None, None)
            } else {
                (Some(cases), None)
            }
        }
    };
    let cases = cases?;
    let sel = simplify(sel);
    // Only surface the bounds default when every predecessor of the default
    // block is one of the absorbed bound checks (otherwise other edges to it
    // would dangle after the checks are turned into the switch's default).
    let default = bound
        .as_ref()
        .filter(|(dflt, absorb)| {
            let Some(dbi) = cfg.blocks.iter().position(|b| b.start == *dflt) else {
                return false;
            };
            let preds = &cfg.blocks[dbi].pred;
            !preds.is_empty() && preds.iter().all(|p| absorb.contains(&cfg.blocks[*p].start))
        })
        .map(|(dflt, _)| *dflt);
    let absorb = bound.map(|(_, absorb)| absorb).unwrap_or_default();
    Some((sel, cases, default, absorb))
}

fn lower_block(
    lower: &mut Lower,
    bi: usize,
    entry: Track,
    mut args: HashMap<usize, Expr>,
    next_id: &mut usize,
) -> (LoweredBlock, Track, HashMap<usize, Expr>) {
    let d = lower.d;
    let cfg = lower.cfg;
    let b = &cfg.blocks[bi];

    let mut st = entry;

    let mut body: Vec<Stmt> = Vec::new();

    for i in b.start..b.end {
        let last = i == b.end - 1 && is_control(d.insns[i].op);
        if last {
            break;
        }
        let ins = &d.insns[i];
        let op = ins.op;
        let operand = ins.operand.unwrap_or(0);
        use Opcode::*;
        match op {
            Const => {
                let depth = st.len();
                lower.write_cell(&mut st, depth, Expr::Const(operand), &mut body, next_id);
            }
            Local => {
                let depth = st.len();
                lower.write_cell(
                    &mut st,
                    depth,
                    Expr::AddrLocal(operand as usize),
                    &mut body,
                    next_id,
                );
            }
            Push => {
                let id = *next_id;
                *next_id += 1;
                st.push(Cell { value: None, id });
            }
            Pop => {
                st.pop();
            }
            Arg => {
                let off = operand as usize;
                let v = lower.read_cell(&mut st, 1, next_id);
                st.pop();
                args.insert(off, v);
            }
            Jump => {
                st.pop();
            }
            Call => {
                let target = lower.read_cell(&mut st, 1, next_id);
                st.pop();
                // collect args sorted by offset
                let mut keys: Vec<usize> = args.keys().copied().collect();
                keys.sort_unstable();
                let call_args: Vec<Expr> = keys.iter().map(|k| args[k].clone()).collect();
                args.clear();
                // A callee may write memory through its pointer arguments, so a
                // constant local cached before the call is stale afterwards.
                // Without this, `LOCAL off; CONST c; STORE4; CALL f(&off);
                // LOCAL off; LOAD4` folds the post-call load back to `c`.
                lower.local_consts.clear();
                let result = match target {
                    Expr::Const(c) if c < 0 => Expr::Trap((-1 - c) as u32, call_args),
                    Expr::Const(c) => Expr::Call(Box::new(Expr::Const(c)), call_args),
                    t => Expr::Call(Box::new(t), call_args),
                };
                let depth = st.len();
                lower.write_cell(&mut st, depth, result, &mut body, next_id);
            }
            Load1 | Load2 | Load4 => {
                let size = load_size(op);
                let addr = lower.read_cell(&mut st, 1, next_id);
                st.pop();
                let v = match (&addr, size) {
                    (Expr::AddrLocal(off), LoadSize::I4) => match lower.local_consts.get(off) {
                        Some(c) => Expr::Const(*c),
                        None => simplify(Expr::MemRef(Box::new(addr), size)),
                    },
                    _ => simplify(Expr::MemRef(Box::new(addr), size)),
                };
                let depth = st.len();
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Store1 | Store2 | Store4 => {
                let size = load_size(op);
                let addr = lower.read_cell(&mut st, 2, next_id);
                let value = lower.read_cell(&mut st, 1, next_id);
                st.pop();
                st.pop();
                let addr = simplify(addr);
                // Track constant locals for switch-shift resolution. Only a
                // write INTO a local slot (`LOCAL off; CONST c; STORE4` ->
                // `AddrLocal(off)`) defines a known-constant local. A write
                // THROUGH a local's value (`LOCAL off; LOAD4; CONST c;
                // STORE4` -> `Local { off }`, i.e. `*(p) = c`) must NOT
                // poison the map: the local still holds a pointer.
                let off = match &addr {
                    Expr::AddrLocal(off) => Some(*off),
                    _ => None,
                };
                if let Some(off) = off {
                    match (&value, size) {
                        (Expr::Const(c), LoadSize::I4) => {
                            lower.local_consts.insert(off, *c);
                        }
                        _ => {
                            lower.local_consts.remove(&off);
                        }
                    }
                }
                body.push(Stmt::Store { addr, value, size });
            }
            BlockCopy => {
                let dest = simplify(lower.read_cell(&mut st, 2, next_id));
                let src = lower.read_cell(&mut st, 1, next_id);
                st.pop();
                st.pop();
                // A block copy INTO a local region overwrites those bytes, so
                // any constant cached for a local slot overlapping the
                // destination range is now stale and must be invalidated --
                // exactly like a scalar Store does. Without this, a later
                // `LOCAL off; LOAD4` inside the copied range folds back to the
                // pre-copy constant. This is the PM_StepSlideMove bug: after
                // `VectorSet(up,0,0,1)` caches up[2]=1.0, `VectorCopy(start_o,up)`
                // (a BLOCK_COPY) refreshes up[2], but the cached 1.0 survived
                // and `up[2] += STEPSIZE` folded to `1.0 + 18` = 19, collapsing
                // the player's Z (fall-through / broken step-up).
                if let Expr::AddrLocal(off) = dest {
                    let lo = off as i64;
                    let hi = lo + operand as i64;
                    // keep only cached consts whose 4-byte span does not overlap
                    lower.local_consts.retain(|&k, _| {
                        let ks = k as i64;
                        ks + 4 <= lo || ks >= hi
                    });
                }
                body.push(Stmt::BlockCopy {
                    dest,
                    src,
                    count: operand,
                });
            }
            Eq | Ne | Lti | Lei | Gti | Gei | Ltu | Leu | Gtu | Geu | Eqf | Nef | Ltf | Lef
            | Gtf | Gef => {
                let r1 = lower.read_cell(&mut st, 2, next_id);
                let r0 = lower.read_cell(&mut st, 1, next_id);
                st.pop();
                st.pop();
                // cond computed in terminator; nothing to emit here
                let _ = (r1, r0);
            }
            Add | Sub | Divi | Divu | Modi | Modu | Muli | Mulu | Band | Bor | Bxor | Lsh
            | Rshi | Rshu => {
                let b = lower.read_cell(&mut st, 1, next_id);
                let a = lower.read_cell(&mut st, 2, next_id);
                st.pop();
                st.pop();
                let v = simplify(Expr::Binop(int_op(op), Box::new(a), Box::new(b)));
                let depth = st.len();
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            AddF | SubF | DivF | MulF => {
                let b = as_float(lower.read_cell(&mut st, 1, next_id));
                let a = as_float(lower.read_cell(&mut st, 2, next_id));
                st.pop();
                st.pop();
                let v = simplify(Expr::Binop(float_op(op), Box::new(a), Box::new(b)));
                let depth = st.len();
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Negi | Bcom => {
                let a = lower.read_cell(&mut st, 1, next_id);
                let v = simplify(Expr::Unop(un_op(op), Box::new(a)));
                let depth = st.len().saturating_sub(1);
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Negf => {
                let a = as_float(lower.read_cell(&mut st, 1, next_id));
                let v = simplify(Expr::Unop("-", Box::new(a)));
                let depth = st.len().saturating_sub(1);
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Sex8 | Sex16 => {
                // LOAD1/LOAD2 zero-extend; SEX8/SEX16 sign-extend the low
                // byte/word. Render the operand under a signed-cast marker so
                // the emitter produces a signed load and lcc re-emits the
                // sign-extension (CVII4 -> OP_SEX8/SEX16). A bare `(int)` cast
                // on the unsigned load would compile to CVUI4 -> IGNORE and
                // silently drop the sign extension.
                let a = lower.read_cell(&mut st, 1, next_id);
                let marker = if matches!(op, Sex8) {
                    "(signed char)"
                } else {
                    "(signed short)"
                };
                let v = simplify(Expr::Unop(marker, Box::new(a)));
                let depth = st.len().saturating_sub(1);
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Cvif => {
                let a = lower.read_cell(&mut st, 1, next_id);
                let v = cvif_expr(a);
                let depth = st.len().saturating_sub(1);
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Cvfi => {
                let a = lower.read_cell(&mut st, 1, next_id);
                let v = cvfi_expr(a);
                let depth = st.len().saturating_sub(1);
                lower.write_cell(&mut st, depth, v, &mut body, next_id);
            }
            Enter | Leave | Undef | Ignore | Break => {}
        }
    }

    // ---- terminator ----
    let last = &d.insns[b.end - 1];
    let term = match last.op {
        Opcode::Leave => {
            let val = match st.last() {
                Some(c) => match &c.value {
                    Some(v) if is_pure(v) => Some(v.clone()),
                    _ => {
                        lower.reads.insert(c.id);
                        Some(Expr::Slot(c.id))
                    }
                },
                None => None,
            };
            Terminator::Return(val)
        }
        Opcode::Jump => {
            // target resolved by CFG
            if let Some(&s) = b.succ.first() {
                Terminator::Goto(cfg.blocks[s].start)
            } else {
                let addr = match st.last() {
                    Some(c) => match &c.value {
                        Some(v) if is_pure(v) => v.clone(),
                        _ => {
                            lower.reads.insert(c.id);
                            Expr::Slot(c.id)
                        }
                    },
                    None => Expr::Slot(0),
                };
                // try to resolve an indirect jump through a data jump table (switch)
                if let Some((sel, cases, default, absorb)) =
                    resolve_switch(&addr, d, cfg, lower.data, bi, &lower.local_consts)
                {
                    // Absorbing a guard block (LTI/GTI bound check) replaces its
                    // conditional branch with plain fallthrough, relying on the
                    // switch's emitted `default:` to reproduce the "out of range"
                    // edge. If `default` failed to surface (e.g. the default
                    // block has other predecessors besides the absorbed guards,
                    // so `resolve_switch` couldn't safely claim it), absorbing
                    // anyway would silently delete the range check with no
                    // replacement. Only absorb when default is confirmed.
                    if default.is_some() {
                        lower.absorb_blocks.extend(absorb);
                    }
                    if cases.iter().all(|(_, t)| *t == cases[0].1)
                        && default.is_some_and(|dft| dft == cases[0].1)
                    {
                        // every table entry AND the out-of-range default all
                        // point to the same target: truly equivalent to a
                        // plain jump regardless of the selector value.
                        Terminator::Goto(cases[0].1)
                    } else {
                        // Even when every in-range case shares one target
                        // (e.g. 4 joystick buttons that all do the same
                        // thing), the bound checks absorbed above are load-
                        // bearing: an out-of-range selector must still reach
                        // `default`, not silently fall into that shared
                        // target. Keep it as a real Switch so the emitter
                        // preserves the range guard.
                        Terminator::Switch {
                            sel: Box::new(sel),
                            cases,
                            default,
                        }
                    }
                } else {
                    Terminator::Unresolved(addr)
                }
            }
        }
        op if op.is_branch_idx() => {
            let r1 = lower.read_cell(&mut st, 2, next_id);
            let r0 = lower.read_cell(&mut st, 1, next_id);
            st.pop();
            st.pop();
            let cond = if is_float_cmp(op) {
                simplify(Expr::Binop(
                    cmp_op(op),
                    Box::new(as_float(r1)),
                    Box::new(as_float(r0)),
                ))
            } else {
                simplify(Expr::Binop(cmp_op(op), Box::new(r1), Box::new(r0)))
            };
            Terminator::IfGoto {
                cond,
                target: last.target.unwrap_or(0),
            }
        }
        _ => Terminator::Fallthrough,
    };

    let exit = st;
    (
        LoweredBlock {
            start: b.start,
            body,
            term,
        },
        exit,
        args,
    )
}

fn is_float_cmp(op: Opcode) -> bool {
    use Opcode::*;
    matches!(op, Eqf | Nef | Ltf | Lef | Gtf | Gef)
}

/// Split an operator marker: `"/u"` → `("/", true)` (unsigned arith/compare),
/// plain ops stay unchanged. The trailing `u` marks unsigned semantics that the
/// emitter must render as `((unsigned)a) op ((unsigned)b)` so q3lcc re-emits
/// the unsigned opcodes (LEU/LTU/GEU/GTU, RSHU, DIVU, MODU, MULU).
pub fn split_uop(op: &str) -> (&str, bool) {
    match op {
        "/u" => ("/", true),
        "%u" => ("%", true),
        "*u" => ("*", true),
        ">>u" => (">>", true),
        "<u" => ("<", true),
        "<=u" => ("<=", true),
        ">u" => (">", true),
        ">=u" => (">=", true),
        _ => (op, false),
    }
}

// ---- C printer ----

/// Format an expression.
pub fn fmt_expr(q: &Qvm, frame: i32, e: &Expr) -> String {
    match e {
        Expr::Const(c) => fmt_const(q, *c),
        Expr::FConst(f) => format!("{f:?}f"),
        Expr::Slot(s) => format!("s{s}"),
        Expr::Local { off, size } => match size {
            LoadSize::I4 => stack_name(frame, *off),
            LoadSize::I1 => format!("(uchar){}", stack_name(frame, *off)),
            LoadSize::I2 => format!("(ushort){}", stack_name(frame, *off)),
        },
        Expr::AddrLocal(off) => format!("&{}", stack_name(frame, *off)),
        Expr::GlobalRef { addr, size } => mem_ref(q, *addr, *size),
        Expr::MemRef(a, size) => format!("*(<{}>*)({})", size.ty(), fmt_expr(q, frame, a)),
        Expr::Unop(op, a) => {
            if *op == "(int)" {
                format!("(int)({})", fmt_expr(q, frame, a))
            } else {
                format!("({op}{})", fmt_expr(q, frame, a))
            }
        }
        Expr::Binop(op, a, b) => {
            let (op, ucast) = split_uop(op);
            if ucast {
                format!(
                    "((unsigned)({})) {op} ((unsigned)({}))",
                    fmt_expr(q, frame, a),
                    fmt_expr(q, frame, b)
                )
            } else {
                format!(
                    "({}) {op} ({})",
                    fmt_expr(q, frame, a),
                    fmt_expr(q, frame, b)
                )
            }
        }
        Expr::Call(t, args) => {
            let f = match t.as_ref() {
                Expr::Const(c) => match q.name_for_fn(*c as usize) {
                    Some(name) => name.to_string(),
                    None => format!("fn_{c}"),
                },
                t => fmt_expr(q, frame, t),
            };
            let args: Vec<String> = args.iter().map(|a| fmt_expr(q, frame, a)).collect();
            format!("{f}({})", args.join(", "))
        }
        Expr::Trap(n, args) => {
            let args: Vec<String> = args.iter().map(|a| fmt_expr(q, frame, a)).collect();
            match crate::traps::trap_name(q.module, *n) {
                Some(name) => format!("{name}({})", args.join(", ")),
                None => format!("trap_{n}({})", args.join(", ")),
            }
        }
        Expr::Float(a) => fmt_expr(q, frame, a),
    }
}

/// Format an integer constant: render string-literal addresses as C strings.
fn fmt_const(q: &Qvm, c: i32) -> String {
    if let Some(s) = q.string_at(c) {
        let esc = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
            .replace('\r', "\\r");
        format!("\"{esc}\"")
    } else {
        c.to_string()
    }
}

/// Name for a stack offset: local or argument.
fn stack_name(frame: i32, off: usize) -> String {
    let f = frame as usize;
    if off < f {
        format!("loc_{off}")
    } else if off >= f + 8 && (off - f - 8).is_multiple_of(4) {
        format!("arg_{}", (off - f - 8) / 4)
    } else {
        format!("sp_{off}")
    }
}

fn mem_ref(q: &Qvm, addr: usize, size: LoadSize) -> String {
    let dl = q.data_length as usize;
    let ll = q.lit_length as usize;
    if addr < dl {
        match size {
            LoadSize::I4 if addr.is_multiple_of(4) => format!("data_i32[{}]", addr / 4),
            LoadSize::I2 if addr.is_multiple_of(2) => format!("data_i16[{}]", addr / 2),
            _ => format!("data_i8[{addr}]"),
        }
    } else if addr < dl + ll {
        format!("lit_i8[{}]", addr - dl)
    } else {
        format!("*(<{}>*)(0x{addr:x})", size.ty())
    }
}

/// Block indexes reachable from the entry, following terminator edges.
/// Switch case targets count as edges even though the CFG does not model
/// the jump table, and fall-through edges are the next block by address.
pub fn reachable_blocks(f: &Function) -> Vec<bool> {
    let mut by_start: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (bi, b) in f.blocks.iter().enumerate() {
        by_start.insert(b.start, bi);
    }
    let mut reach = vec![false; f.blocks.len()];
    let mut queue: Vec<usize> = vec![0];
    reach[0] = true;
    while let Some(bi) = queue.pop() {
        let b = &f.blocks[bi];
        let mark = |t: usize, reach: &mut Vec<bool>, queue: &mut Vec<usize>| {
            if let Some(&j) = by_start.get(&t) {
                if !reach[j] {
                    reach[j] = true;
                    queue.push(j);
                }
            }
        };
        match &b.term {
            Terminator::Goto(t) => mark(*t, &mut reach, &mut queue),
            Terminator::IfGoto { target, .. } => {
                mark(*target, &mut reach, &mut queue);
                // linear fall-through = next block by address
                if bi + 1 < f.blocks.len() {
                    reach[bi + 1] = true;
                    queue.push(bi + 1);
                }
            }
            Terminator::Switch { cases, default, .. } => {
                for (_, t) in cases {
                    mark(*t, &mut reach, &mut queue);
                }
                if let Some(t) = default {
                    mark(*t, &mut reach, &mut queue);
                }
            }
            Terminator::Fallthrough if bi + 1 < f.blocks.len() => {
                reach[bi + 1] = true;
                queue.push(bi + 1);
            }
            _ => {}
        }
    }
    reach
}

/// Render a decompiled function as C.
/// One formatted C line plus the instruction range it was produced from.
pub type FmtLine = (String, (usize, usize));

/// Formatted identity C with a per-line -> insn-range map (for GUI sync).
pub fn fmt_function_lines(f: &Function, q: &Qvm) -> Vec<FmtLine> {
    let reach = reachable_blocks(f);
    let mut assigned: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for b in &f.blocks {
        for st in &b.body {
            if let Stmt::Assign { slot, .. } = st {
                assigned.insert(*slot);
            }
        }
    }
    let whole = (f.start, f.end);
    let mut lines: Vec<FmtLine> = Vec::new();
    let mut out = |text: String, range: (usize, usize)| lines.push((text, range));
    out(
        format!(
            "// function @ insn {}..{} frame {}",
            f.start, f.end, f.frame
        ),
        whole,
    );
    // Signature: real name when known, arity from ARG marshaling. The QVM
    // ABI passes everything as 4-byte ints, so `int` args is the honest bet.
    let name = q
        .name_for_fn(f.start)
        .map_or_else(|| format!("fn_{}", f.start), |s| s.to_string());
    let args = if f.arity == 0 {
        "void".to_string()
    } else {
        (0..f.arity)
            .map(|i| format!("int a{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let ret = if f.returns { "int" } else { "void" };
    out(format!("{ret} {name}({args}) {{"), whole);
    for (bi, b) in f.blocks.iter().enumerate() {
        if !reach[bi] {
            continue;
        }
        let end = f
            .blocks
            .get(bi + 1)
            .map_or(f.end, |nb| nb.start)
            .max(b.start);
        let span = (b.start, end);
        out(format!("L{}:", b.start), (b.start, end));
        for st in &b.body {
            match st {
                Stmt::Assign { slot, value } => {
                    let rhs = fmt_expr(q, f.frame, value);
                    if !f.read_slots.contains(slot) {
                        match value {
                            Expr::Call(..) | Expr::Trap(..) => {
                                out(format!("  {rhs};"), span);
                            }
                            _ => continue, // pure, dead slot write
                        }
                    } else {
                        out(format!("  s{slot} = {rhs};"), span);
                    }
                }
                Stmt::Store { addr, value, size } => {
                    let v = fmt_expr(q, f.frame, value);
                    let store_lhs = store_lhs(q, f.frame, addr, *size);
                    out(format!("  {store_lhs} = {v};"), span);
                }
                Stmt::BlockCopy { dest, src, count } => {
                    out(
                        format!(
                            "  memcpy((void*)({}), (const void*)({}), {});",
                            fmt_expr(q, f.frame, dest),
                            fmt_expr(q, f.frame, src),
                            count
                        ),
                        span,
                    );
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => {
                // an unassigned slot is the PUSH dummy of a void return
                let is_dummy = matches!(v, Expr::Slot(s) if !assigned.contains(s));
                if is_dummy {
                    out("  return;".to_string(), span);
                } else {
                    out(format!("  return {};", fmt_expr(q, f.frame, v)), span);
                }
            }
            Terminator::Return(None) => out("  return;".to_string(), span),
            Terminator::Goto(t) => out(format!("  goto L{t};"), span),
            Terminator::IfGoto { cond, target } => {
                out(
                    format!("  if ({}) goto L{target};", fmt_expr(q, f.frame, cond)),
                    span,
                );
            }
            Terminator::Unresolved(a) => {
                out(
                    format!("  goto /* indirect */ ({});", fmt_expr(q, f.frame, a)),
                    span,
                );
            }
            Terminator::Switch {
                sel,
                cases,
                default,
            } => {
                let mut counts: HashMap<usize, usize> = HashMap::new();
                for (_, t) in cases {
                    *counts.entry(*t).or_insert(0) += 1;
                }
                let default_target = default.or_else(|| {
                    if cases.len() >= 2 {
                        counts
                            .iter()
                            .max_by_key(|(_, c)| *c)
                            .filter(|(_, c)| **c >= 2)
                            .map(|(t, _)| *t)
                    } else {
                        None
                    }
                });
                out(format!("  switch ({}) {{", fmt_expr(q, f.frame, sel)), span);
                for (v, t) in cases {
                    if default_target == Some(*t) {
                        continue;
                    }
                    out(format!("  case {v}: goto L{t};"), span);
                }
                if let Some(t) = default_target {
                    out(format!("  default: goto L{t};"), span);
                }
                out("  }".to_string(), span);
            }
            Terminator::Fallthrough => {}
        }
    }
    out("}\n".to_string(), whole);
    lines
}

pub fn fmt_function(f: &Function, q: &Qvm) -> String {
    fmt_function_lines(f, q)
        .into_iter()
        .map(|(text, _)| text + "\n")
        .collect()
}

/// Left-hand side of a store: `*addr` in the right width.
fn store_lhs(q: &Qvm, frame: i32, addr: &Expr, size: LoadSize) -> String {
    match addr {
        Expr::AddrLocal(off) => match size {
            LoadSize::I4 => stack_name(frame, *off),
            LoadSize::I1 => format!("(*(uchar*)&({}))", stack_name(frame, *off)),
            LoadSize::I2 => format!("(*(ushort*)&({}))", stack_name(frame, *off)),
        },
        Expr::GlobalRef { addr, .. } => {
            // A GlobalRef as a store address only ever arises from CONST;LOAD4
            // (the pointer value loaded from a fixed cell), so the store must
            // go *through* that loaded value, not to the cell itself.
            format!("*(<{}>*)({})", size.ty(), mem_ref(q, *addr, LoadSize::I4))
        }
        Expr::MemRef(a, _) => format!("*(<{}>*)({})", size.ty(), fmt_expr(q, frame, a)),
        _ => format!("*(<{}>*)({})", size.ty(), fmt_expr(q, frame, addr)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::build_cfg;
    use crate::disasm::disassemble;
    use crate::loader::parse;

    fn qvm_from_parts(code: &[u8], data: &[u8], instr_count: i32) -> crate::loader::Qvm {
        let mut f = Vec::new();
        for v in [
            0x12721444u32,
            instr_count as u32,
            32u32,
            code.len() as u32,
            32 + code.len() as u32,
            data.len() as u32,
            0u32,
            0u32,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(code);
        f.extend_from_slice(data);
        parse(&f).unwrap()
    }

    #[test]
    fn switch_dispatch_resolved() {
        // data words: [0, 9, 10] little-endian (table at data+4)
        // #0 ENTER 0; #1 LOCAL 36; #2 LOAD4 (sel=arg0); #3 CONST 2; #4 LSH;
        // #5 CONST 4; #6 ADD; #7 LOAD4; #8 JUMP; #9 LEAVE 0; #10 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x08, 2, 0, 0, 0, 0x32, 0x08, 4, 0, 0, 0,
            0x26, 0x1d, 0x0a, 0x04, 0, 0, 0, 0, 0x04, 0, 0, 0, 0,
        ];
        let data = [0u8, 0, 0, 0, 9, 0, 0, 0, 10, 0, 0, 0];
        let q = qvm_from_parts(&code, &data, 11);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 11), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let dispatch = f
            .blocks
            .iter()
            .find(|b| matches!(b.term, Terminator::Switch { .. }))
            .expect("switch");
        match &dispatch.term {
            Terminator::Switch {
                sel,
                cases,
                default,
            } => {
                assert_eq!(cases, &vec![(0, 9), (1, 10)]);
                assert_eq!(*default, None, "no bounds checks -> no default");
                // sel must not be folded to a constant (it is the argument)
                assert!(!matches!(sel.as_ref(), Expr::Const(_)));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn switch_bounds_via_const_local() {
        // bounds checks load the constant from a local (LOCAL 12; LOAD4),
        // and the table has junk at entries 0..1 so scan-from-0 must not fire.
        // #0 ENTER 0
        // #1 LOCAL 12; #2 CONST 2; #3 STORE4            loc_12 = 2
        // #4 LOCAL 36; #5 LOAD4; #6 LOCAL 12; #7 LOAD4; #8 LTI 24   if sel<2  -> default 24
        // #9 LOCAL 36; #10 LOAD4; #11 CONST 3; #12 GTI 24           if sel>3  -> default 24
        // #13 LOCAL 36; #14 LOAD4; #15 CONST 2; #16 LSH; #17 CONST 8; #18 ADD; #19 LOAD4; #20 JUMP
        // #21 LEAVE 0       case 2
        // #22 LEAVE 0       case 3
        // #23 LEAVE 0       dead
        // #24 LEAVE 0       default
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 12, 0, 0, 0, 0x08, 2, 0, 0, 0, 0x20, 0x09, 36, 0, 0, 0, 0x1d,
            0x09, 12, 0, 0, 0, 0x1d, 0x0d, 24, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x08, 3, 0, 0, 0,
            0x0f, 24, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x08, 2, 0, 0, 0, 0x32, 0x08, 8, 0, 0, 0,
            0x26, 0x1d, 0x0a, 0x04, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0x04, 0, 0, 0,
            0,
        ];
        // table at data offset 8 = word 2: words[2]=junk, [3]=0 sentinel,
        // [4]=21 (sel 2), [5]=22 (sel 3)
        let data = [
            0x0f, 0x27, 0, 0, 0, 0, 0, 0, 0x0f, 0x27, 0, 0, 0, 0, 0, 0, 0x15, 0, 0, 0, 0x16, 0, 0,
            0,
        ];
        let q = qvm_from_parts(&code, &data, 25);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 25), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let dispatch = f
            .blocks
            .iter()
            .find(|b| matches!(b.term, Terminator::Switch { .. }))
            .expect("switch resolved through constant-local bounds");
        match &dispatch.term {
            Terminator::Switch { cases, default, .. } => {
                assert_eq!(cases, &vec![(2, 21), (3, 22)]);
                assert_eq!(*default, Some(24), "bounds default attached");
            }
            _ => unreachable!(),
        }
        // the bounds-check blocks are absorbed: no `if (...<...)` remains,
        // the dispatch renders as a switch with a default
        let out = fmt_function(&f, &q);
        assert!(out.contains("default:"), "default in output: {out}");
        assert!(
            !out.contains("indirect"),
            "dispatch resolved, no indirect: {out}"
        );
    }

    #[test]
    fn unresolved_jump_stays() {
        // indirect jump through a stack slot, no table:
        // #0 ENTER 0; #1 LOCAL 36; #2 LOAD4; #3 JUMP; #4 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x0a, 0x04, 0, 0, 0, 0,
        ];
        let q = qvm_from_parts(&code, &[], 5);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 5), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        assert!(f
            .blocks
            .iter()
            .any(|b| matches!(b.term, Terminator::Unresolved(_))));
    }

    #[test]
    fn single_use_slot_inlined() {
        // ret = fn_100(arg_0); return ret;
        // #0 ENTER 12
        // #1 LOCAL 20; #2 LOAD4; #3 ARG 8           arg0
        // #4 LOCAL 4; #5 CONST 100; #6 CALL; #7 STORE4   loc_4 = fn_100(arg_0)
        // #8 LOCAL 4; #9 LOAD4; #10 LEAVE 12        return loc_4
        let code = [
            0x03, 12, 0, 0, 0, 0x09, 20, 0, 0, 0, 0x1d, 0x21, 8, 0x09, 4, 0, 0, 0, 0x08, 100, 0, 0,
            0, 0x05, 0x20, 0x09, 4, 0, 0, 0, 0x1d, 0x04, 12, 0, 0, 0,
        ];
        let q = qvm_from_parts(&code, &[], 11);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 11), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 12, &data_words);
        let out = fmt_function(&f, &q);
        assert!(
            out.contains("loc_4 = fn_100(arg_0);"),
            "slot inlined into store: {out}"
        );
        assert!(out.contains("return loc_4;"), "return kept: {out}");
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("s")),
            "no sN assigns: {out}"
        );
    }

    #[test]
    fn const_local_invalidated_across_call() {
        // A constant local stored BEFORE a call must not be folded into a
        // LOAD4 AFTER the call: the callee can write through a pointer arg
        // (e.g. UI_AdjustFrom640(&w) scales w/h). Folded, the rebuilt C emits
        // `(int)(1142947840)` (float 640.0f bit pattern) into refdef.width —
        // the rebuilt-ui main-menu 3D background rendered 1142947840-wide.
        // #0 ENTER 0
        // #1 LOCAL 12; #2 CONST 1142947840; #3 STORE4   w = 640.0f bits
        // #4 LOCAL 12; #5 ARG 8; #6 CONST 100; #7 CALL; #8 POP
        //                                              UI_AdjustFrom640(&w)
        // #9 LOCAL 36; #10 LOCAL 12; #11 LOAD4; #12 STORE4  refdef.width = w
        // #13 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 12, 0, 0, 0, 0x08, 0x00, 0x00, 0x20, 0x44, 0x20, 0x09, 12, 0,
            0, 0, 0x21, 8, 0x08, 100, 0, 0, 0, 0x05, 0x07, 0x09, 36, 0, 0, 0, 0x09, 12, 0, 0, 0,
            0x1d, 0x20, 0x04, 0, 0, 0, 0,
        ];
        let q = qvm_from_parts(&code, &[], 14);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 14), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let out = fmt_function(&f, &q);
        assert!(
            out.contains("fn_100(&arg_1);"),
            "call present before load: {out}"
        );
        // the post-call load must NOT fold back to the stored constant:
        // `refdef.width = w` keeps the local read (arg_7 = arg_1)
        assert!(
            out.contains("arg_7 = arg_1;"),
            "post-call load folded to stale const: {out}"
        );
        assert!(
            !out.contains("(int)(1142947840)"),
            "stale const folded across call: {out}"
        );
    }

    #[test]
    fn call_args_across_blocks() {
        // lcc emits a call whose ARG writes are split by a branch: ARG 8/12 are
        // laid down before the conditional default-value store, ARG 16/20 and
        // the CALL sit in the merge block. A block-local arg map lost the
        // first two args (trap emitted with only default+flags).
        // #0  ENTER 0
        // #1..4   LOCAL 36; LOAD4; LOAD4; CONST 215608
        // #5      NE 34                     if (slot != 215608) goto leave
        // #6..9   LOCAL 36; LOAD4; LOAD4; ARG 8       arg0 = slot
        // #10..15 LOCAL 36; LOAD4; CONST 4; ADD; LOAD4; ARG 12   arg1 = name
        // #16..18 CONST 0; CONST 1; NE 22   if (0 != 1) goto merge
        // #19..21 LOCAL 76; CONST 25961; STORE4       loc_0[76] = default
        // #22..24 LOCAL 76; LOAD4; ARG 16            arg2 = default
        // #25..30 LOCAL 36; LOAD4; CONST 12; ADD; LOAD4; ARG 20  arg3 = flags
        // #31..33 CONST -4; CALL; POP        trap_Cvar_Register(...)
        // #34     LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x1d, 0x08, 0x38, 0xa4, 0x03, 0x00, 0x0c,
            34, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x1d, 0x21, 8, 0x09, 36, 0, 0, 0, 0x1d, 0x08, 4,
            0, 0, 0, 0x26, 0x1d, 0x21, 12, 0x08, 0, 0, 0, 0, 0x08, 1, 0, 0, 0, 0x0c, 22, 0, 0, 0,
            0x09, 76, 0, 0, 0, 0x08, 0x69, 0x65, 0, 0, 0x20, 0x09, 76, 0, 0, 0, 0x1d, 0x21, 16,
            0x09, 36, 0, 0, 0, 0x1d, 0x08, 12, 0, 0, 0, 0x26, 0x1d, 0x21, 20, 0x08, 0xfc, 0xff,
            0xff, 0xff, 0x05, 0x07, 0x04, 0, 0, 0, 0,
        ];
        let q = qvm_from_parts(&code, &[], 35);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 35), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let out = fmt_function(&f, &q);
        // all four args present, in lcc order (slot, name, default, flags)
        assert!(
            out.contains("trap_Cvar_Register(*(<int>*)(arg_7), *(<int>*)((arg_7) + (4)), arg_17, *(<int>*)((arg_7) + (12)))"),
            "args lost/misordered across blocks: {out}"
        );
    }

    #[test]
    fn cvfi_memref_renders_float_deref() {
        // CVFI over a LOAD4 from memory must keep the float interpretation so
        // the rebuilt C emits `(int)(*(float*)addr)` and lcc re-emits the CVFI.
        // Reading `*(int*)` would feed raw IEEE-754 bits (5.0f = 0x40A00000 =
        // 1084227584) into int checks — the rebuilt-cgame CG_PlayerAngles crash.
        // #0 ENTER 0
        // #1 LOCAL 84; #2 LOCAL 36; #3 LOAD4; #4 CONST 132; #5 ADD; #6 LOAD4;
        // #7 CVFI; #8 STORE4; #9 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 84, 0, 0, 0, 0x09, 36, 0, 0, 0, 0x1d, 0x08, 132, 0, 0, 0, 0x26,
            0x1d, 0x3b, 0x20, 0x04, 0, 0, 0, 0,
        ];
        let q = qvm_from_parts(&code, &[], 10);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 10), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let out = fmt_function(&f, &q);
        // the dump format is `*(<int>*)` for I4 regardless of float-ness, but
        // the expression tree must wrap the MemRef in Expr::Float so probe_emit
        // renders `*(float*)` (checked by emitter integration). Here we assert
        // the tree shape: cvfi_expr(Local/MemRef) -> (int)(Float(...)).
        let m = Expr::MemRef(Box::new(Expr::Const(4)), LoadSize::I4);
        match cvfi_expr(m) {
            Expr::Unop("(int)", a) => assert!(matches!(*a, Expr::Float(_))),
            other => panic!("cvfi_expr(MemRef) = {other:?}, expected (int)(Float(..))"),
        }
        let l = Expr::Local {
            off: 8,
            size: LoadSize::I4,
        };
        match cvfi_expr(l) {
            Expr::Unop("(int)", a) => assert!(matches!(*a, Expr::Float(_))),
            other => panic!("cvfi_expr(Local) = {other:?}, expected (int)(Float(..))"),
        }
        // plain int slot keeps a plain (int) cast
        match cvfi_expr(Expr::Slot(3)) {
            Expr::Unop("(int)", a) => assert!(matches!(*a, Expr::Slot(3))),
            other => panic!("cvfi_expr(Slot) = {other:?}, expected (int)(Slot)"),
        }
        // FConst converts directly (float constant value -> int)
        assert_eq!(cvfi_expr(Expr::FConst(5.0)), Expr::Const(5));
        // and the rendered function keeps the CVFI expression
        assert!(
            out.contains("(int)(*(<int>*)(("),
            "cvfi lost in output: {out}"
        );
    }

    #[test]
    fn sex8_marks_signed_byte_load() {
        // SEX8 after LOAD1 must sign-extend the byte, not zero-extend it. The
        // lowered expression must carry a `(signed char)` marker on the I1 load
        // so the emitter renders `*(signed char*)&loc_0[..]` and lcc re-emits
        // LOAD1; SEX8 (INDIRI1+CVII4). Rendering `(int)(*(unsigned char*)..)`
        // compiles to CVUI4 -> IGNORE and silently drops the sign extension —
        // the rebuilt qagame's PM_AirMove read usercmd forwardmove/rightmove as
        // unsigned, so back/left (0xFF) became forward/right.
        // #0 ENTER 0
        // #1 LOCAL 0; #2 LOCAL 4; #3 LOAD1; #4 SEX8; #5 CVIF; #6 STORE4; #7 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 0, 0, 0, 0, 0x09, 4, 0, 0, 0, 0x1b, 0x23, 0x3a, 0x20, 0x04, 0,
            0, 0, 0,
        ];
        let q = qvm_from_parts(&code, &[], 8);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 8), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let out = fmt_function(&f, &q);
        assert!(
            out.contains("(signed char)(uchar)sp_4"),
            "SEX8 lost its signed marker in output: {out}"
        );
    }

    #[test]
    fn sex16_marks_signed_word_load() {
        // SEX16 after LOAD2 likewise must keep a `(signed short)` marker.
        // #0 ENTER 0
        // #1 LOCAL 0; #2 LOCAL 4; #3 LOAD2; #4 SEX16; #5 STORE4; #6 LEAVE 0
        let code = [
            0x03, 0, 0, 0, 0, 0x09, 0, 0, 0, 0, 0x09, 4, 0, 0, 0, 0x1c, 0x24, 0x20, 0x04, 0, 0, 0,
            0,
        ];
        let q = qvm_from_parts(&code, &[], 7);
        let d = disassemble(&q).unwrap();
        let data_words = q.data_int32();
        let cfg = build_cfg(&d, (0, 7), &data_words).unwrap();
        let f = decompile_function(&d, &cfg, 0, &data_words);
        let out = fmt_function(&f, &q);
        assert!(
            out.contains("(signed short)(ushort)sp_4"),
            "SEX16 lost its signed marker in output: {out}"
        );
    }
}
