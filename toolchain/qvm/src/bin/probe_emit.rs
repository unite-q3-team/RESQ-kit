//! Probe: emit decompiled functions as real C89 source buildable with the
//! baseq3a q3lcc/q3asm toolchain, plus a syscalls.asm equ table.
//!
//! Key design decisions:
//! - The original data+lit segments are re-materialized as a flat byte blob
//!   `qvm_mem[]`; every static address in the decompiled AST is rendered as a
//!   pointer into it (`*(int*)(qvm_mem + addr)`). This is what makes absolute
//!   data-space offsets survive an lcc rebuild.
//! - Functions are emitted in raw-block form (labels + goto), not structured
//!   text: the lcc-produced block order/fallthrough matches the bytecode CFG.
//! - Stack locals live in one byte array `unsigned char loc_0[frame];` indexed
//!   by VM LOCAL offset (`*(int*)&loc_0[OFF]`, `((int)loc_0 + OFF)`). This
//!   preserves the frame's true byte extent so lcc reserves the full frame
//!   (a 1024-byte buffer must produce an ENTER ~1048, not 28). SSA slots are
//!   `int sN;`. Float contexts reinterpret words: `*(float*)&loc_0[OFF]`.
//! - Traps become `equ name -1-n` entries in the syscalls.asm file, and the C
//!   header declares int-returning traps with a generous arg list and the
//!   math traps (sin/cos/atan2/sqrt/floor/ceil) as `float`-returning.
//!
//! Usage:
//!   probe_emit <qvm> <out.c> <syscalls.asm> [--names f] [--sigs f]
//!              [--only a,b,c] [--lst stem] [--typed] [--no-typed]

use qvm::decompile::float_or;
use qvm::decompile::LoadSize;
use qvm::{
    Expr, Function, Opcode, Stmt, Terminator, build_cfg, build_functions, decompile_function,
    disassemble, load, reachable_blocks, trap_name,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

#[derive(Clone)]
struct Sig {
    frame: i32,
    args: usize,
    ret: String,
}

/// Upper bound on dispatch-table length (entries). Indirect-call cells are
/// recognized as words on the table's stride grid; without a range limit the
/// congruence test would also flag unrelated data far past the table (malloc
/// arenas, free lists) that merely happen to land on the same stride.
const MAX_TABLE_ENTRIES: usize = 1024;

fn blob_word(blob: &[u8], off: usize) -> Option<i32> {
    let w = blob.get(off..off + 4)?;
    Some(i32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// How many stride-aligned cells from `base` look like a dispatch table:
/// NULL or a function entry that is not also a lit-segment string. Stops at
/// the first data/string cell so a small command table (stride 8 at 0xf28)
/// is not stretched across `bg_itemlist.pickup_sound` 8 KB later just
/// because that string's address collides with an ENTER.
fn indir_table_len(
    blob: &[u8],
    q: &qvm::loader::Qvm,
    by_entry: &HashMap<usize, usize>,
    base: usize,
    stride: usize,
) -> usize {
    let mut n = 0usize;
    while n < MAX_TABLE_ENTRIES {
        let Some(w) = blob_word(blob, base + n * stride) else { break };
        if w == 0 {
            n += 1;
            continue;
        }
        let is_fn = w >= 0 && by_entry.contains_key(&(w as usize));
        if is_fn && q.string_at(w).is_none() {
            n += 1;
            continue;
        }
        break;
    }
    n
}

struct Emitter {
    q: qvm::loader::Qvm,
    d: qvm::disasm::Disassembly,
    data: Vec<i32>,
    ranges: Vec<(usize, usize)>,
    sigs: HashMap<usize, Sig>,
    cname: Vec<String>,
    /// entry instruction index -> function index
    by_entry: HashMap<usize, usize>,
    /// function entry constants proven to be used as function pointers
    addrtaken: HashSet<usize>,
    /// function ENTER constants proven to be STORED into memory (menu
    /// callbacks written to BSS structs outside the blob)
    stored_fnptrs: HashSet<i32>,
    /// blob addresses proven to be used as data pointers (ARG/STORE4 value)
    data_addrs: HashSet<i32>,
    /// constants proven to be used as integer operands (binop/compare args);
    /// such constants must render as plain numbers even if a printable string
    /// exists at that offset (e.g. va()'s buffer-stride multiplier 32000)
    intused: HashSet<i32>,
    /// per-function emitted parameter count (sigs args ∪ body refs ∪ caller args)
    params: HashMap<usize, usize>,
    /// per-trap maximum argument count (prototype arity + call padding)
    trap_arity: HashMap<u32, usize>,
    traps: BTreeSet<u32>,
    /// trap numbers whose name collides with an emitted function name; the
    /// value is the collision-free name used in the C and syscalls.asm
    /// (e.g. trap 101 "memcpy" vs the module's own local memcpy -> "memcpy_trap")
    trap_cname: HashMap<u32, String>,
    /// distinct BLOCK_COPY byte counts (emitted as byte-array struct typedefs
    /// so struct assignment compiles back to OP_BLOCK_COPY, not a trap call)
    block_sizes: BTreeSet<usize>,
    blob: Vec<u8>,
    /// Named overlay. `--no-typed` restores v0 spelling.
    typed: bool,
    overlay: qvm::types::OverlayMod,
}

fn sanitize(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if s.is_empty() || s.as_bytes()[0].is_ascii_digit() {
        s = format!("fn_{s}");
    }
    s
}

fn parse_names(path: &str) -> HashMap<usize, String> {
    let mut out = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if let (Some(f), Some(n)) = (it.next(), it.next()) {
                if let Some(rest) = f.strip_prefix("fn[") {
                    if let Some(idx) = rest.strip_suffix(']').and_then(|x| x.parse::<usize>().ok()) {
                        out.insert(idx, n.to_string());
                    }
                }
            }
        }
    }
    out
}

fn parse_sigs(path: &str) -> HashMap<usize, Sig> {
    let mut out = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("fn[") {
                continue;
            }
            let mut it = line.split_whitespace();
            let head = it.next().unwrap_or("");
            let Some(idx) = head.strip_prefix("fn[").and_then(|r| r.strip_suffix(']').and_then(|x| x.parse::<usize>().ok()))
            else { continue };
            let mut frame = 0;
            let mut args = 0usize;
            let mut ret = "int".to_string();
            for tok in it {
                if let Some(v) = tok.strip_prefix("frame=") {
                    frame = v.parse().unwrap_or(0);
                } else if let Some(v) = tok.strip_prefix("args=") {
                    args = v.parse().unwrap_or(0);
                } else if let Some(v) = tok.strip_prefix("ret=") {
                    ret = v.to_string();
                }
            }
            out.insert(idx, Sig { frame, args, ret });
        }
    }
    out
}

/// `(off - frame - 8) / 4` if `off` is an argument slot.
fn arg_index(frame: i32, off: usize) -> Option<usize> {
    let f = frame as usize;
    if off >= f + 8 && (off - f - 8) % 4 == 0 {
        Some((off - f - 8) / 4)
    } else {
        None
    }
}

/// `float_or` with a correction: an explicit `(int)` cast always yields an int
/// expression, regardless of the operand's float-ness (CVFI converts to int).
fn float_or_pe(slotf: bool, localf: &HashSet<usize>, e: &Expr) -> bool {
    match e {
        Expr::Unop("(int)", _) => false,
        Expr::Unop("(float)", _) => true,
        _ => float_or(slotf, localf, e),
    }
}

/// Parenthesize a binop operand only when it contains spaces (it is itself a
/// binop / unsigned cast). Atoms, `(ty*)p`, and `p->field` stay bare so the
/// emitted C is readable without changing lcc's AST.
fn wrap_opnd(s: &str) -> String {
    if s.as_bytes().contains(&b' ') {
        format!("({s})")
    } else {
        s.to_string()
    }
}

fn binop_fmt(op: &str, a: &str, b: &str) -> String {
    format!("{} {op} {}", wrap_opnd(a), wrap_opnd(b))
}

/// Operand of a C cast: identifiers stay bare, anything else is parenthesized.
fn wrap_cast_operand(s: &str) -> String {
    if s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        s.to_string()
    } else {
        format!("({s})")
    }
}

/// Probe: invert `if (c) goto then; goto else` in G_FindTeams only.
/// Tried 2026-08-14: not byte-identical (NE+jump vs EQ). Leave off.
const INVERT_FINDTEAMS: bool = false;
const USE_VA_Z: bool = true;
const USE_VN_SLOTS: bool = true;
const USE_PTR_VIEWS: bool = true;

fn ptr_view_ty(overlay: qvm::types::OverlayMod, kind: qvm::types::PtrKind) -> Option<&'static str> {
    use qvm::types::{OverlayMod, PtrKind};
    match (overlay, kind) {
        (OverlayMod::Game, PtrKind::Entity) => Some("gentity_t"),
        (OverlayMod::Game, PtrKind::Client) => Some("gclient_t"),
        (OverlayMod::CGame, PtrKind::Entity) => Some("centity_t"),
        (OverlayMod::Ui, PtrKind::Menu) => Some("menucommon_s"),
        _ => None,
    }
}

fn ptr_view_suffix(kind: qvm::types::PtrKind) -> &'static str {
    use qvm::types::PtrKind;
    match kind {
        PtrKind::Entity => "e",
        PtrKind::Client => "c",
        PtrKind::Menu => "m",
    }
}

fn emit_va_z_macros() -> String {
    let mut s = String::from(
        "/* trailing zero pads for wide prototypes (va / G_Printf); cpp-identical to 0,0,… */\n",
    );
    for n in 4..=59 {
        let zeros = vec!["0"; n].join(",");
        s.push_str(&format!("#define VA_Z{n} {zeros}\n"));
    }
    s.push('\n');
    s
}

fn looks_like_counter_loop(cond_s: &str) -> bool {
    let cmp = cond_s.contains(" < ")
        || cond_s.contains(" > ")
        || cond_s.contains(" <= ")
        || cond_s.contains(" >= ");
    if !cmp {
        return false;
    }
    cond_s.contains("level_num_entities")
        || cond_s.contains("level_maxclients")
        || cond_s.contains("GENTITIES")
        || cond_s.contains("MAX_CLIENTS")
}

fn collect_non_i4_locals(f: &Function, frame: i32) -> HashSet<usize> {
    let mut bad: HashSet<usize> = HashSet::new();
    let mark_addr = |bad: &mut HashSet<usize>, off: usize| {
        if arg_index(frame, off).is_none() {
            bad.insert(off);
        }
    };
    let mut walk = |e: &Expr, bad: &mut HashSet<usize>| {
        let mut st: Vec<&Expr> = vec![e];
        while let Some(x) = st.pop() {
            match x {
                Expr::AddrLocal(off) => mark_addr(bad, *off),
                Expr::Local { off, size } => {
                    if !matches!(size, LoadSize::I4) {
                        mark_addr(bad, *off);
                    }
                }
                Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                Expr::Binop(_, a, b) => {
                    st.push(a);
                    st.push(b);
                }
                Expr::Call(t, args) => {
                    st.push(t);
                    st.extend(args.iter());
                }
                Expr::Trap(_, args) => st.extend(args.iter()),
                _ => {}
            }
        }
    };
    for b in &f.blocks {
        for s in b.body.iter() {
            match s {
                Stmt::Assign { slot, value } => {
                    // Dead LOCAL→slot writes are not emitted; treating them as
                    // address-taken would ban vN on every I4 counter.
                    if f.read_slots.contains(slot) {
                        walk(value, &mut bad);
                    }
                }
                Stmt::Store { addr, value, size } => {
                    match addr {
                        Expr::AddrLocal(_off) if matches!(size, LoadSize::I4) => {}
                        Expr::AddrLocal(off) => mark_addr(&mut bad, *off),
                        other => walk(other, &mut bad),
                    }
                    walk(value, &mut bad);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    walk(dest, &mut bad);
                    walk(src, &mut bad);
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => walk(v, &mut bad),
            Terminator::IfGoto { cond, .. } => walk(cond, &mut bad),
            Terminator::Switch { sel, .. } => walk(sel, &mut bad),
            Terminator::Unresolved(a) => walk(a, &mut bad),
            _ => {}
        }
    }
    bad
}

fn collect_frame_locals(f: &Function, frame: i32) -> BTreeSet<usize> {
    let mut offs: BTreeSet<usize> = BTreeSet::new();
    let mut walk = |e: &Expr| {
        let mut st: Vec<&Expr> = vec![e];
        while let Some(x) = st.pop() {
            match x {
                Expr::Local { off, .. } | Expr::AddrLocal(off) => {
                    if arg_index(frame, *off).is_none() {
                        offs.insert(*off);
                    }
                }
                Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                Expr::Binop(_, a, b) => {
                    st.push(a);
                    st.push(b);
                }
                Expr::Call(t, args) => {
                    st.push(t);
                    st.extend(args.iter());
                }
                Expr::Trap(_, args) => st.extend(args.iter()),
                _ => {}
            }
        }
    };
    for b in &f.blocks {
        for s in b.body.iter() {
            match s {
                Stmt::Assign { value, .. } => walk(value),
                Stmt::Store { addr, value, .. } => {
                    walk(addr);
                    walk(value);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    walk(dest);
                    walk(src);
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => walk(v),
            Terminator::IfGoto { cond, .. } => walk(cond),
            Terminator::Switch { sel, .. } => walk(sel),
            Terminator::Unresolved(a) => walk(a),
            _ => {}
        }
    }
    offs
}

fn pad_trailing_va_z(args: &mut Vec<String>) {
    let mut z = 0usize;
    while args.last().map(|s| s.as_str()) == Some("0") {
        args.pop();
        z += 1;
    }
    if z >= 4 {
        args.push(format!("VA_Z{z}"));
    } else {
        for _ in 0..z {
            args.push("0".into());
        }
    }
}

fn is_emitted_empty(body: &[Stmt], read_slots: &BTreeSet<usize>) -> bool {
    body.iter().all(|s| match s {
        Stmt::Assign { slot, value } => {
            !read_slots.contains(slot) && !matches!(value, Expr::Call(..) | Expr::Trap(..))
        }
        _ => false,
    })
}

/// C comment body for a lit-segment string. Address stays `qvm_mem+N`.
fn c_string_comment(s: &str) -> String {
    let escaped: String = s
        .chars()
        .map(|c| match c {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            '"' => "\\\"".to_string(),
            _ => c.to_string(),
        })
        .collect();
    let mut chars = escaped.chars();
    let mut t: String = chars.by_ref().take(40).collect();
    if chars.next().is_some() {
        t.push_str("...");
    }
    t = t.replace("*/", "* /");
    format!("\"{t}\"")
}

impl Emitter {
    fn frame_of(&self, fi: usize) -> i32 {
        // ENTER operand is the source of truth. A stale .sigs row (wrong fn[N]
        // after CFG changes, or a smaller frame from another function) used to
        // shrink this; locals in a 20KB stack buffer then classified as p4965..
        // and q3lcc died on a 50KB prototype.
        let (start, end) = self.ranges[fi];
        if let Some(ins) = self.d.insns.get(start) {
            if ins.op == Opcode::Enter {
                return ins.operand.unwrap_or(0);
            }
        }
        for i in start..end {
            if self.d.insns[i].op == Opcode::Enter {
                return self.d.insns[i].operand.unwrap_or(0);
            }
        }
        self.sigs.get(&fi).map(|s| s.frame).unwrap_or(0)
    }

    fn ret_of(&self, fi: usize) -> &str {
        // Same class of bug as frame_of: a stale .sigs row (wrong fn[N]) can
        // mark a function `void` while callers assign the CALL result.
        // q3lcc then dies with `operands of = have illegal types int and void`.
        // Bytecode CALL always leaves a word; `int f() { return 0; }` is valid
        // C and a legal QVM leave. Keep `float` from sigs when present.
        match self.sigs.get(&fi).map(|s| s.ret.as_str()) {
            Some("float") => "float",
            _ => "int",
        }
    }

    fn name_of(&self, fi: usize) -> &str {
        &self.cname[fi]
    }

    /// Resolved trap name (collision-renamed when it clashes with an emitted
    /// function name), falling back to the traps table / trap_<n>.
    fn trap_name_c(&self, n: u32) -> String {
        if let Some(s) = self.trap_cname.get(&n) {
            return s.clone();
        }
        match trap_name(self.q.module, n) {
            Some(s) => s.to_string(),
            None => format!("trap_{n}"),
        }
    }

    /// Render an integer constant: blob address (string literal or data
    /// pointer), (address-taken) function pointer, or plain number.
    /// A function address is only rendered as its C name when a module-wide
    /// dataflow scan proved the constant is used as a function pointer
    /// (ARG/STORE4 value) and never as an integer operand. Blob addresses are
    /// rendered as `qvm_mem + (off - 4)` so traps receive the identity-mapped
    /// image offset `off` (identical values in the original and rebuilt
    /// bytecode).
    fn fmt_const(&self, c: i32) -> String {
        // CONST 0 is NULL / integer zero. Do not render it as `(int)vmMain`
        // just because vmMain is instruction index 0.
        if c == 0 {
            return "0".into();
        }
            if self.typed && self.overlay == qvm::types::OverlayMod::Game && self.intused.contains(&c)
            {
                use qvm::types::{GCLIENTS_BASE, GENTITIES_BASE};
                if c == GENTITIES_BASE as i32 {
                    return "GENTITIES_BASE".into();
                }
                if c == GCLIENTS_BASE as i32 {
                    return "GCLIENTS_BASE".into();
                }
            }
            if c >= 0 {
            // A function entry proven used as a function pointer (stored,
            // passed as an arg, or compared) always renders as the C name so
            // every use of the pointer agrees in the rebuilt module, where
            // function addresses differ from the original's insn indices. This
            // must win over `intused`: a think-pointer compare like
            // `ent->think == fn` makes the constant an integer operand too, but
            // store and compare must both be the rebuilt address.
            if self.addrtaken.contains(&(c as usize)) {
                if let Some(&fi) = self.by_entry.get(&(c as usize)) {
                    return format!("(int){}", self.name_of(fi));
                }
            }
            // A constant used as an integer operand stays a plain number even
            // when a printable string or data pointer exists at that offset
            // (e.g. va()'s buffer-stride multiplier 32000).
            if self.intused.contains(&c) {
                return c.to_string();
            }
            if self.q.string_at(c).is_some() || self.data_addrs.contains(&c) {
                // image offset c sits at qvm_mem + (c - 4); offsets below the
                // 4-byte q3asm reservation are the zero sentinel.
                return if c >= 4 {
                    let mut s = format!("(int)(qvm_mem + {})", c - 4);
                    if self.typed {
                        if let Some(lit) = self.q.string_at(c) {
                            s.push_str(&format!(" /* {} */", c_string_comment(&lit)));
                        } else if let Some(note) = qvm::types::comment(c as usize) {
                            s.push_str(&format!(" /* {note} */"));
                        }
                    }
                    s
                } else {
                    "0".to_string()
                };
            }
        }
        c.to_string()
    }

    /// Force a constant to render as a plain data/string address, bypassing
    /// the addrtaken/function-pointer classification entirely. Used only for
    /// a Store whose value is proven (locally, within one function) to be a
    /// sibling data field despite numerically colliding with a function
    /// entry index elsewhere in the program.
    fn fmt_data_const(&self, c: i32) -> String {
        if c >= 4 {
            format!("(int)(qvm_mem + {})", c - 4)
        } else {
            "0".to_string()
        }
    }

    /// Force a constant to render as the rebuilt function's C name, bypassing
    /// the module-wide addrtaken/fns classification entirely. Used only for a
    /// Store whose value is proven (locally, within one function's own AST)
    /// to be a genuine callback field of a struct-array element despite
    /// numerically colliding with a printable string elsewhere in the
    /// program (see `local_indexed_callback_rescue`).
    fn fmt_fn_const(&self, c: i32) -> String {
        match self.by_entry.get(&(c as usize)) {
            Some(&fi) => format!("(int){}", self.name_of(fi)),
            None => self.fmt_data_const(c),
        }
    }

    /// Trap arguments are VM data values. A constant can legitimately be both
    /// a callback entry and a string offset (for example UI's 19740), but a
    /// syscall must receive the original image offset, never the rebuilt C
    /// function address.
    fn fmt_trap_const(&self, c: i32) -> String {
        if c >= 0 && !self.intused.contains(&c)
            && (self.q.string_at(c).is_some() || self.data_addrs.contains(&c))
        {
            return if c >= 4 {
                format!("(int)(qvm_mem + {})", c - 4)
            } else {
                "0".to_string()
            };
        }
        self.fmt_const(c)
    }

    /// True if `e` should be rendered in a float context.
    fn fval(&self, body: &Body, e: &Expr) -> bool {
        match e {
            Expr::Float(_) | Expr::FConst(_) => return true,
            Expr::Trap(n, _) => return float_trap(*n),
            Expr::Call(t, _) => {
                return match t.as_ref() {
                    Expr::Const(c) if *c >= 0 => self
                        .by_entry
                        .get(&(*c as usize))
                        .and_then(|&fi| self.sigs.get(&fi))
                        .map(|s| s.ret == "float")
                        .unwrap_or(false),
                    _ => false,
                };
            }
            _ => {}
        }
        let slotf = match e {
            Expr::Slot(s) => body.slot_float.contains(s),
            _ => false,
        };
        float_or_pe(slotf, &body.local_float, e)
    }

    /// True if `e` renders as a C pointer expression.
    fn pval(&self, body: &Body, e: &Expr) -> bool {
        match e {
            Expr::AddrLocal(_) => true,
            Expr::Const(c) => self.q.string_at(*c).is_some(),
            _ => false,
        }
    }

    /// Render `e` as an int expression (cast pointers and floats at the
    /// boundary; float bit patterns are preserved).
    fn fmt_int(&mut self, body: &mut Body, e: &Expr) -> String {
        if self.pval(body, e) {
            let s = self.fmt(body, e, false);
            if s.starts_with("(int)") {
                s
            } else {
                format!("(int)({s})")
            }
        } else if self.fval(body, e) {
            format!("qvm_fbits_i({})", self.fmt(body, e, true))
        } else {
            self.fmt(body, e, false)
        }
    }

    /// Render `e` as a float expression (reinterpret int/pointer bits).
    fn fmt_float(&mut self, body: &mut Body, e: &Expr) -> String {
        if self.pval(body, e) {
            format!("qvm_fbits((int)({}))", self.fmt(body, e, false))
        } else if self.fval(body, e) {
            self.fmt(body, e, true)
        } else {
            format!("qvm_fbits({})", self.fmt(body, e, false))
        }
    }

    fn call_name(&mut self, body: &mut Body, t: &Expr, nargs: usize) -> String {
        if let Expr::Const(c) = t {
            if *c >= 0 {
                if let Some(&fi) = self.by_entry.get(&(*c as usize)) {
                    return self.name_of(fi).to_string();
                }
            }
        }
        let params = (0..nargs).map(|_| "int".to_string()).collect::<Vec<_>>().join(",");
        format!("((int (*)({params}))({}))", self.fmt(body, t, false))
    }

    /// Render an expression. `f` = float context.
    fn fmt(&mut self, body: &mut Body, e: &Expr, f: bool) -> String {
        match e {
            Expr::Const(c) => {
                if f {
                    format!("qvm_fbits({c})")
                } else if *c == 0 {
                    "0".into()
                } else {
                    self.fmt_const(*c)
                }
            }
            Expr::FConst(v) => format!("{v:?}f"),
            Expr::Slot(s) => {
                body.slots.insert(*s);
                if f {
                    format!("*(float*)&s{s}")
                } else {
                    format!("s{s}")
                }
            }
            Expr::Local { off, size } => self.local_ref(body, *off, *size, f),
            Expr::AddrLocal(off) => {
                if let Some(k) = arg_index(body.frame, *off) {
                    body.nparams = body.nparams.max(k + 1);
                    return format!("&p{k}");
                }
                body.locals.insert(*off);
                if let Some(n) = self.named_loc(body, *off) {
                    return format!("((int)&{n})");
                }
                format!("((int)loc_0 + {off})")
            }
            Expr::GlobalRef { addr, size } => self.global_ref(*addr, *size, f),
            Expr::MemRef(a, size) => {
                if let Expr::Const(c) = a.as_ref() {
                    if *c >= 4 {
                        let ty = match size {
                            LoadSize::I4 if f => "float",
                            LoadSize::I4 => "int",
                            LoadSize::I1 => "unsigned char",
                            LoadSize::I2 => "unsigned short",
                        };
                        if let Some(s) = self.typed_abs_cell(*c as usize, ty) {
                            return s;
                        }
                    }
                }
                if matches!(size, LoadSize::I4) {
                    if let Some(s) = self.fmt_overlay_field(body, a) {
                        return if f {
                            format!("*(float*)&{s}")
                        } else {
                            s
                        };
                    }
                }
                mem_ref(self.fmt(body, a, false), *size, f)
            }
            Expr::Unop(op, a) => {
                if *op == "(int)" {
                    format!("(int)({})", self.fmt(body, a, self.fval(body, a)))
                } else if *op == "(float)" {
                    // CVIF: convert the int value, not reinterpret its bits.
                    // The operand is BY DEFINITION an int (that's what CVIF
                    // converts) — always render it with f=false. Using
                    // `self.fval(body, a)` here was wrong: for a bare
                    // `Expr::Local`, fval falls back to
                    // `body.local_float.contains(off)`, a FUNCTION-WIDE set
                    // keyed only by stack offset. If that same offset is
                    // ALSO used to hold genuine float data elsewhere in the
                    // function (slot reuse across unrelated statements),
                    // this int-conversion's operand got misrendered as
                    // `*(float*)&loc_0[off]` (a bit-reinterpret) instead of
                    // `*(int*)&loc_0[off]` (a numeric read) — silently
                    // truncating the converted value to ~0 (e.g. a ui module's
                    // `originalWidth` in the text-centering helper, breaking
                    // ALL centered/right-aligned menu text: it always
                    // rendered flush against the anchor x instead of
                    // centered/right of it).
                    format!("(float)({})", self.fmt(body, a, false))
                } else if *op == "(signed char)" || *op == "(signed short)" {
                    // SEX8/SEX16: sign-extend the low byte/word. Render the
                    // underlying load as its signed type so lcc emits
                    // LOAD1+SEX8 / LOAD2+SEX16 (INDIRI+CVII4); the unsigned
                    // zero-extension (CVUI4 -> IGNORE) would drop the sign.
                    let ty = if *op == "(signed char)" { "signed char" } else { "signed short" };
                    match a.as_ref() {
                        Expr::Local { off, size } if matches!(size, LoadSize::I1 | LoadSize::I2) => {
                            if let Some(k) = arg_index(body.frame, *off) {
                                body.nparams = body.nparams.max(k + 1);
                                let mask = if *op == "(signed char)" { format!("(p{k} & 255)") } else { format!("(p{k} & 65535)") };
                                format!("({ty})({mask})")
                            } else {
                                body.locals.insert(*off);
                                if let Some(n) = self.named_loc(body, *off) {
                                    format!("*({ty}*)&{n}")
                                } else {
                                    format!("*({ty}*)&loc_0[{off}]")
                                }
                            }
                        }
                        Expr::MemRef(addr, size) if matches!(size, LoadSize::I1 | LoadSize::I2) => {
                            format!("*({ty}*)({})", self.fmt(body, addr, false))
                        }
                        Expr::GlobalRef { addr, size } if matches!(size, LoadSize::I1 | LoadSize::I2) => {
                            self.typed_load(*addr, ty)
                        }
                        _ => format!("({ty})({})", self.fmt(body, a, f)),
                    }
                } else {
                    format!("({op}{})", self.fmt(body, a, f))
                }
            }
            Expr::Binop(op, a, b) => {
                // always-int ops have no float form; lcc rejects `%` etc. on
                // floats, so render operands as ints (reinterpreting float bits).
                let (op, ucast) = qvm::decompile::split_uop(op);
                if ucast {
                    format!(
                        "((unsigned)({})) {op} ((unsigned)({}))",
                        self.fmt_int(body, a),
                        self.fmt_int(body, b)
                    )
                } else if matches!(op, "%" | "&" | "|" | "^" | "<<" | ">>") {
                    binop_fmt(op, &self.fmt_int(body, a), &self.fmt_int(body, b))
                } else if self.typed && op == "+" && !f {
                    if let Some(s) = self.fmt_typed_add(body, a, b) {
                        s
                    } else {
                        binop_fmt(op, &self.fmt(body, a, f), &self.fmt(body, b, f))
                    }
                } else if self.typed && op == "*" && !f && self.overlay == qvm::types::OverlayMod::Game {
                    match (a.as_ref(), b.as_ref()) {
                        (Expr::Const(n), x) | (x, Expr::Const(n)) => {
                            if let Some(m) = qvm::types::stride_macro(*n) {
                                format!("{m} * {}", wrap_opnd(&self.fmt(body, x, false)))
                            } else {
                                binop_fmt(op, &self.fmt(body, a, f), &self.fmt(body, b, f))
                            }
                        }
                        _ => binop_fmt(op, &self.fmt(body, a, f), &self.fmt(body, b, f)),
                    }
                } else {
                    binop_fmt(op, &self.fmt(body, a, f), &self.fmt(body, b, f))
                }
            }
            Expr::Call(t, args) => {
                let name = self.call_name(body, t, args.len());
                let mut a: Vec<String> = args.iter().map(|x| self.fmt_int(body, x)).collect();
                if let Expr::Const(c) = t.as_ref() {
                    if *c >= 0 {
                        if let Some(&fi) = self.by_entry.get(&(*c as usize)) {
                            let want = self.params.get(&fi).copied().unwrap_or(a.len());
                            while a.len() < want {
                                a.push("0".into());
                            }
                        }
                    }
                }
                if self.typed && USE_VA_Z {
                    pad_trailing_va_z(&mut a);
                }
                format!("{name}({})", a.join(", "))
            }
            Expr::Trap(n, args) => {
                self.traps.insert(*n);
                let name = self.trap_name_c(*n);
                let arity = self.trap_arity.get(n).copied().unwrap_or(args.len());
                let mut a: Vec<String> = if float_trap(*n) {
                    args.iter().map(|x| self.fmt_float(body, x)).collect()
                } else {
                    args.iter().map(|x| match x {
                        Expr::Const(c) => self.fmt_trap_const(*c),
                        _ => self.fmt_int(body, x),
                    }).collect()
                };
                while a.len() < arity {
                    a.push(if float_trap(*n) { "0.0f".into() } else { "0".into() });
                }
                format!("{name}({})", a.join(", "))
            }
            Expr::Float(a) => self.fmt(body, a, true),
        }
    }

    fn local_ref(&mut self, body: &mut Body, off: usize, size: LoadSize, f: bool) -> String {
        let fr = body.frame;
        if let Some(k) = arg_index(fr, off) {
            body.nparams = body.nparams.max(k + 1);
            return match size {
                LoadSize::I4 if f => format!("*(float*)&p{k}"),
                LoadSize::I4 => format!("p{k}"),
                // LOAD1/LOAD2 zero-extend the low byte/word; render as a mask
                // so lcc emits BAND, not a no-op conversion cast (which would
                // leave the high bits set) and not CVUU2 (unassembleable).
                LoadSize::I1 => format!("(p{k} & 255)"),
                LoadSize::I2 => format!("(p{k} & 65535)"),
            };
        }
        body.locals.insert(off);
        if let Some(n) = self.named_loc(body, off) {
            return match size {
                LoadSize::I4 if f => format!("*(float*)&{n}"),
                LoadSize::I4 => n.to_string(),
                LoadSize::I1 => format!("*(unsigned char*)&{n}"),
                LoadSize::I2 => format!("*(unsigned short*)&{n}"),
            };
        }
        match size {
            LoadSize::I4 if f => format!("*(float*)&loc_0[{off}]"),
            LoadSize::I4 => format!("*(int*)&loc_0[{off}]"),
            LoadSize::I1 => format!("*(unsigned char*)&loc_0[{off}]"),
            LoadSize::I2 => format!("*(unsigned short*)&loc_0[{off}]"),
        }
    }

    fn store_lhs(&mut self, body: &mut Body, addr: &Expr, size: LoadSize, f: bool) -> String {
        // 2-byte stores render as signed short so lcc emits CVII2/ASGNI2;
        // `unsigned short` stores emit the CVUU2 opcode that q3asm cannot
        // assemble (opstrings.h has CVUU4/CVUU1 but no CVUU2). STORE2 keeps
        // only the low 16 bits, so signedness of the stored value is moot.
        let i2 = matches!(size, LoadSize::I2) && !f;
        match addr {
            Expr::AddrLocal(off) => {
                if let Some(k) = arg_index(body.frame, *off) {
                    body.nparams = body.nparams.max(k + 1);
                    return match size {
                        LoadSize::I4 if f => format!("*(float*)&p{k}"),
                        LoadSize::I4 => format!("p{k}"),
                        LoadSize::I1 => format!("*(unsigned char*)&p{k}"),
                        LoadSize::I2 => format!("*(short*)&p{k}"),
                    };
                }
                body.locals.insert(*off);
                if let Some(n) = self.named_loc(body, *off) {
                    return match size {
                        LoadSize::I4 if f => format!("*(float*)&{n}"),
                        LoadSize::I4 => n.to_string(),
                        LoadSize::I1 => format!("*(unsigned char*)&{n}"),
                        LoadSize::I2 => format!("*(short*)&{n}"),
                    };
                }
                match size {
                    LoadSize::I4 if f => format!("*(float*)&loc_0[{off}]"),
                    LoadSize::I4 => format!("*(int*)&loc_0[{off}]"),
                    LoadSize::I1 => format!("*(unsigned char*)&loc_0[{off}]"),
                    LoadSize::I2 => format!("*(short*)&loc_0[{off}]"),
                }
            }
            Expr::GlobalRef { addr, .. } => {
                // Address came from CONST;LOAD4 (the pointer value stored at
                // a fixed cell), so store *through* that loaded value.
                let ptr = self.typed_load(*addr, "int");
                if i2 {
                    format!("*(short*)({ptr})")
                } else if f {
                    format!("*(float*)({ptr})")
                } else {
                    format!("*(int*)({ptr})")
                }
            }
            Expr::Const(c) if *c >= 4 => {
                let ty = if i2 {
                    "short"
                } else if f {
                    "float"
                } else {
                    match size {
                        LoadSize::I4 => "int",
                        LoadSize::I1 => "unsigned char",
                        LoadSize::I2 => "short",
                    }
                };
                if let Some(s) = self.typed_abs_cell(*c as usize, ty) {
                    return s;
                }
                let base = self.fmt(body, addr, false);
                if i2 {
                    format!("*(short*)({base})")
                } else {
                    mem_ref(base, size, f)
                }
            }
            a => {
                if matches!(size, LoadSize::I4) {
                    if let Some(s) = self.fmt_overlay_field(body, a) {
                        return if f {
                            format!("*(float*)&{s}")
                        } else {
                            s
                        };
                    }
                }
                let base = self.fmt(body, a, false);
                if i2 {
                    format!("*(short*)({base})")
                } else {
                    mem_ref(base, size, f)
                }
            }
        }
    }

    fn fmt_overlay_field(&mut self, body: &mut Body, addr: &Expr) -> Option<String> {
        if !self.typed {
            return None;
        }
        let (base, n) = match addr {
            Expr::Binop("+", a, b) => match (a.as_ref(), b.as_ref()) {
                (x, Expr::Const(n)) | (Expr::Const(n), x) => (x, *n),
                _ => return None,
            },
            _ => return None,
        };
        let kind = pointer_kind(base, body);
        let (ty, field) = qvm::types::overlay_ptr_field_for(self.overlay, kind, n)?;
        if let Some(view) = self.view_of_base(body, base) {
            return Some(format!("{view}->{field}"));
        }
        let base_s = self.fmt(body, base, false);
        Some(format!("(({ty}*){})->{field}", wrap_cast_operand(&base_s)))
    }

    fn fmt_typed_add(&mut self, body: &mut Body, a: &Expr, b: &Expr) -> Option<String> {
        let (base, n) = match (a, b) {
            (x, Expr::Const(n)) | (Expr::Const(n), x) => (x, *n),
            _ => return None,
        };
        if self.overlay == qvm::types::OverlayMod::Game {
            if let Some(m) = qvm::types::stride_macro(n) {
                return Some(format!("{} + {m}", wrap_opnd(&self.fmt(body, base, false))));
            }
        }
        let kind = pointer_kind(base, body);
        if let Some((ty, field)) = qvm::types::overlay_ptr_field_for(self.overlay, kind, n) {
            if let Some(view) = self.view_of_base(body, base) {
                return Some(format!("((int)&{view}->{field})"));
            }
            let base_s = self.fmt(body, base, false);
            return Some(format!("((int)&(({ty}*){})->{field})", wrap_cast_operand(&base_s)));
        }
        if self.overlay == qvm::types::OverlayMod::Game {
            if let Some(note) = qvm::types::field_addend_for(kind, n) {
                return Some(format!("({}) + ({n} /* {note} */)", self.fmt(body, base, false)));
            }
        }
        None
    }

    fn view_of_base(&self, body: &Body, base: &Expr) -> Option<String> {
        match base {
            Expr::Local { off, .. } => {
                if let Some(k) = arg_index(body.frame, *off) {
                    return body.arg_view.get(&k).cloned();
                }
                if body.ptr_view.contains(off) {
                    return body.local_names.get(off).cloned();
                }
                None
            }
            Expr::MemRef(addr, _) => {
                let (inner, n) = match addr.as_ref() {
                    Expr::Binop("+", a, b) => match (a.as_ref(), b.as_ref()) {
                        (x, Expr::Const(n)) | (Expr::Const(n), x) => (x, *n),
                        _ => return None,
                    },
                    _ => return None,
                };
                if n != 516 {
                    return None;
                }
                if let Expr::Local { off, .. } = inner {
                    if let Some(k) = arg_index(body.frame, *off) {
                        if body.gcl_from_arg == Some(k) {
                            return Some("gcl".into());
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn named_loc(&self, body: &Body, off: usize) -> Option<String> {
        if !self.typed {
            return None;
        }
        let name = body.local_names.get(&off)?;
        if body.ptr_view.contains(&off) {
            Some(format!("{name}_i"))
        } else {
            Some(name.clone())
        }
    }

    /// CONST n used as a cell address (STORE/LOAD), not `qvm_mem+(n-4)`.
    /// Scalar macros expand to the qvm_mem form (same CONST under identity
    /// mapping). Everything else keeps the raw address and adds a comment.
    fn typed_abs_cell(&self, vmoff: usize, ty: &str) -> Option<String> {
        if !self.typed || self.overlay != qvm::types::OverlayMod::Game || vmoff < 4 {
            return None;
        }
        if ty == "int" {
            if let Some(name) = qvm::types::scalar_macro(vmoff) {
                return Some(name.to_string());
            }
        }
        if let Some(note) = qvm::types::comment(vmoff) {
            return Some(format!("*({ty}*)({vmoff}) /* {note} */"));
        }
        None
    }

    fn typed_load(&self, addr: usize, ty: &str) -> String {
        let raw = if addr >= 4 {
            format!("*({ty}*)(qvm_mem + {})", addr - 4)
        } else {
            format!("*({ty}*)(0)")
        };
        if !self.typed || self.overlay != qvm::types::OverlayMod::Game {
            return raw;
        }
        if ty == "int" {
            if let Some(name) = qvm::types::scalar_macro(addr) {
                return name.to_string();
            }
        }
        if let Some(note) = qvm::types::comment(addr) {
            format!("{raw} /* {note} */")
        } else {
            raw
        }
    }

    fn global_ref(&self, addr: usize, size: LoadSize, f: bool) -> String {
        let ty = match size {
            LoadSize::I4 if f => "float",
            LoadSize::I4 => "int",
            LoadSize::I1 => "unsigned char",
            LoadSize::I2 => "unsigned short",
        };
        self.typed_load(addr, ty)
    }
}

fn pointer_kind(e: &Expr, body: &Body) -> Option<qvm::types::PtrKind> {
    use qvm::types::{PtrKind, OverlayMod, GCLIENTS_BASE, GCLIENTS_END, GENTITIES_BASE, GENTITIES_END, LEVEL_BASE};
    let game = body.overlay == OverlayMod::Game;
    match e {
        Expr::Local { off, .. } => body.ptr_kind.get(off).copied(),
        Expr::MemRef(addr, _) if game && add_const_eq(addr, 516) => Some(PtrKind::Client),
        Expr::GlobalRef { addr, .. } if game && *addr == LEVEL_BASE => Some(PtrKind::Entity),
        Expr::GlobalRef { addr, .. } if game && *addr == LEVEL_BASE + 4 => Some(PtrKind::Client),
        Expr::Const(n) if game => {
            let u = *n as usize;
            if u >= GENTITIES_BASE && u < GENTITIES_END {
                Some(PtrKind::Entity)
            } else if u >= GCLIENTS_BASE && u < GCLIENTS_END {
                Some(PtrKind::Client)
            } else {
                None
            }
        }
        Expr::Unop(_, a) => pointer_kind(a, body),
        Expr::Binop("+", a, b) => {
            if game && add_const_eq(e, 824) {
                return Some(PtrKind::Entity);
            }
            if game && add_const_eq(e, 1448) {
                return Some(PtrKind::Client);
            }
            if game && (mul_const_eq(a, 1448) || mul_const_eq(b, 1448)) {
                return Some(PtrKind::Client);
            }
            if game && (mul_const_eq(a, 824) || mul_const_eq(b, 824)) {
                return Some(PtrKind::Entity);
            }
            pointer_kind(a, body).or_else(|| pointer_kind(b, body))
        }
        Expr::MemRef(addr, _) => pointer_kind(addr, body),
        _ => None,
    }
}

fn add_const_eq(e: &Expr, want: i32) -> bool {
    match e {
        Expr::Binop("+", a, b) => {
            matches!(a.as_ref(), Expr::Const(n) if *n == want)
                || matches!(b.as_ref(), Expr::Const(n) if *n == want)
        }
        _ => false,
    }
}

fn mul_const_eq(e: &Expr, want: i32) -> bool {
    match e {
        Expr::Binop("*", a, b) => {
            matches!(a.as_ref(), Expr::Const(n) if *n == want)
                || matches!(b.as_ref(), Expr::Const(n) if *n == want)
        }
        _ => false,
    }
}

fn mem_ref(addr: String, size: LoadSize, f: bool) -> String {
    let ty = match size {
        LoadSize::I4 if f => "float",
        LoadSize::I4 => "int",
        LoadSize::I1 => "unsigned char",
        LoadSize::I2 => "unsigned short",
    };
    format!("*({ty}*)({addr})")
}

/// Per-function emission context.
struct Body {
    frame: i32,
    ret: String,
    slot_float: HashSet<usize>,
    local_float: HashSet<usize>,
    locals: BTreeSet<usize>,
    slots: BTreeSet<usize>,
    nparams: usize,
    fn_name: String,
    overlay: qvm::types::OverlayMod,
    local_names: HashMap<usize, String>,
    /// LOCAL offset → gentity* / gclient* when this function uses entity-unique
    /// field strides on that slot (p0+520, loc+GENTITY_SIZE, load of +516, …).
    ptr_kind: HashMap<usize, qvm::types::PtrKind>,
    /// Locals that get a pointer view macro (`ent_24` = `(gentity_t*)ent_24_i`).
    ptr_view: HashSet<usize>,
    /// Argument index → `p0_e` / `p0_c` / `p0_m`.
    arg_view: HashMap<usize, String>,
    /// `gcl` from `pN` (`#define gcl ((gclient_t*)(pN_e->client))`).
    gcl_from_arg: Option<usize>,
}

fn infer_floats(f: &Function, reach: &[bool]) -> (HashSet<usize>, HashSet<usize>) {
    let mut slot_float: HashSet<usize> = HashSet::new();
    let mut local_float: HashSet<usize> = HashSet::new();
    for _ in 0..3 {
        for (bi, b) in f.blocks.iter().enumerate() {
            if !reach[bi] {
                continue;
            }
            for s in b.body.iter() {
                match s {
                    Stmt::Assign { slot, value, .. } => {
                        if float_or_pe(slot_float.contains(slot), &local_float, value) {
                            slot_float.insert(*slot);
                        }
                    }
                    Stmt::Store { addr, value, .. } => {
                        if let Expr::AddrLocal(off) = addr {
                            if float_or_pe(slot_float.contains(off), &local_float, value) {
                                local_float.insert(*off);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    (slot_float, local_float)
}

/// Find the highest argument index referenced anywhere in a function body.
fn body_max_arg(f: &Function, frame: i32) -> Option<usize> {    let mut maxk: Option<usize> = None;
    let mut walk = |e: &Expr| {
        let mut st: Vec<&Expr> = vec![e];
        while let Some(x) = st.pop() {
            if let Expr::Local { off, .. } = x {
                if let Some(k) = arg_index(frame, *off) {
                    maxk = Some(maxk.map_or(k, |m| m.max(k)));
                }
            }
            if let Expr::AddrLocal(off) = x {
                if let Some(k) = arg_index(frame, *off) {
                    maxk = Some(maxk.map_or(k, |m| m.max(k)));
                }
            }
            match x {
                Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                Expr::Binop(_, a, b) => {
                    st.push(a);
                    st.push(b);
                }
                Expr::Call(t, args) => {
                    st.push(t);
                    st.extend(args.iter());
                }
                Expr::Trap(_, args) => st.extend(args.iter()),
                _ => {}
            }
        }
    };
    for b in &f.blocks {
        for s in b.body.iter() {
            match s {
                Stmt::Assign { value, .. } => walk(value),
                Stmt::Store { addr, value, .. } => {
                    walk(addr);
                    walk(value);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    walk(dest);
                    walk(src);
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => walk(v),
            Terminator::IfGoto { cond, .. } => walk(cond),
            Terminator::Switch { sel, .. } => walk(sel),
            Terminator::Unresolved(a) => walk(a),
            _ => {}
        }
    }
    maxk
}

fn infer_ptr_kinds(
    f: &Function,
    overlay: qvm::types::OverlayMod,
) -> HashMap<usize, qvm::types::PtrKind> {
    use qvm::types::{PtrKind, OverlayMod, GCLIENTS_BASE, GCLIENT_SIZE, GENTITIES_BASE, GENTITY_SIZE, LEVEL_BASE};

    let mut kind: HashMap<usize, PtrKind> = HashMap::new();
    let mark = |map: &mut HashMap<usize, PtrKind>, off: usize, k: PtrKind| {
        match (map.get(&off).copied(), k) {
            (Some(PtrKind::Client), PtrKind::Entity) => {}
            (Some(PtrKind::Menu), _) => {}
            _ => {
                map.insert(off, k);
            }
        }
    };
    let local_of = |e: &Expr| -> Option<usize> {
        match e {
            Expr::Local { off, .. } => Some(*off),
            _ => None,
        }
    };

    let mut walk = |e: &Expr, kind: &mut HashMap<usize, PtrKind>| {
        let mut st: Vec<&Expr> = vec![e];
        while let Some(x) = st.pop() {
            if let Expr::Binop("+", a, b) = x {
                let (base, n) = match (a.as_ref(), b.as_ref()) {
                    (e, Expr::Const(n)) | (Expr::Const(n), e) => (e, *n),
                    _ => {
                        st.push(a);
                        st.push(b);
                        continue;
                    }
                };
                if let Some(off) = local_of(base) {
                    let u = n as usize;
                    match overlay {
                        OverlayMod::Game => {
                            if n == GENTITY_SIZE as i32
                                || matches!(u, 424 | 520 | 524 | 528 | 532 | 536)
                            {
                                mark(kind, off, PtrKind::Entity);
                            } else if n == GCLIENT_SIZE as i32 || matches!(u, 468 | 944) {
                                mark(kind, off, PtrKind::Client);
                            } else if u == 516 {
                                mark(kind, off, PtrKind::Entity);
                            }
                        }
                        OverlayMod::CGame => {
                            if matches!(u, 208 | 416 | 420) {
                                mark(kind, off, PtrKind::Entity);
                            }
                        }
                        OverlayMod::Ui => {
                            if u == 44 {
                                mark(kind, off, PtrKind::Menu);
                            }
                        }
                    }
                }
                st.push(a);
                st.push(b);
                continue;
            }
            if let Expr::Binop(_, a, b) = x {
                st.push(a);
                st.push(b);
                continue;
            }
            match x {
                Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                Expr::Call(t, args) => {
                    // vtos(p+92) / similar 1-arg vec3 calls: +92 is s.origin on
                    // a gentity, but is a next-pointer on waypoints — only the
                    // call form is unique enough to mark (BotFreeWaypoints
                    // loads +92 and must stay unnamed).
                    if args.len() == 1 {
                        if let Expr::Binop("+", a, b) = &args[0] {
                            let (base, n) = match (a.as_ref(), b.as_ref()) {
                                (e, Expr::Const(n)) | (Expr::Const(n), e) => (e, *n),
                                _ => {
                                    st.push(t);
                                    st.extend(args.iter());
                                    continue;
                                }
                            };
                            if n == 92 && overlay != OverlayMod::Ui {
                                if let Some(off) = local_of(base) {
                                    mark(kind, off, PtrKind::Entity);
                                }
                            }
                        }
                    }
                    st.push(t);
                    st.extend(args.iter());
                }
                Expr::Trap(_, args) => st.extend(args.iter()),
                _ => {}
            }
        }
    };

    let walk_fn = |f: &Function, kind: &mut HashMap<usize, PtrKind>, walk: &mut dyn FnMut(&Expr, &mut HashMap<usize, PtrKind>)| {
        for b in &f.blocks {
            for s in &b.body {
                match s {
                    Stmt::Assign { value, .. } => walk(value, kind),
                    Stmt::Store { addr, value, .. } => {
                        if let Expr::AddrLocal(dst) = addr {
                            match value {
                                Expr::MemRef(inner, _)
                                    if overlay == OverlayMod::Game && add_const_eq(inner, 516) =>
                                {
                                    mark(kind, *dst, PtrKind::Client);
                                }
                                Expr::Binop("+", _, _)
                                    if overlay == OverlayMod::Game
                                        && add_const_eq(value, GENTITY_SIZE as i32) =>
                                {
                                    mark(kind, *dst, PtrKind::Entity);
                                }
                                Expr::Local { off, .. } => {
                                    if let Some(k) = kind.get(off).copied() {
                                        mark(kind, *dst, k);
                                    }
                                }
                                Expr::GlobalRef { addr, .. }
                                    if overlay == OverlayMod::Game && *addr == LEVEL_BASE =>
                                {
                                    mark(kind, *dst, PtrKind::Entity);
                                }
                                Expr::GlobalRef { addr, .. }
                                    if overlay == OverlayMod::Game && *addr == LEVEL_BASE + 4 =>
                                {
                                    mark(kind, *dst, PtrKind::Client);
                                }
                                Expr::Const(n)
                                    if overlay == OverlayMod::Game
                                        && *n == GENTITIES_BASE as i32 =>
                                {
                                    mark(kind, *dst, PtrKind::Entity);
                                }
                                Expr::Const(n)
                                    if overlay == OverlayMod::Game
                                        && *n == GCLIENTS_BASE as i32 =>
                                {
                                    mark(kind, *dst, PtrKind::Client);
                                }
                                _ => {}
                            }
                        }
                        walk(addr, kind);
                        walk(value, kind);
                    }
                    Stmt::BlockCopy { dest, src, .. } => {
                        walk(dest, kind);
                        walk(src, kind);
                    }
                }
            }
            match &b.term {
                Terminator::Return(Some(v)) => walk(v, kind),
                Terminator::IfGoto { cond, .. } => walk(cond, kind),
                Terminator::Switch { sel, .. } => walk(sel, kind),
                Terminator::Unresolved(a) => walk(a, kind),
                _ => {}
            }
        }
    };

    for _ in 0..3 {
        walk_fn(f, &mut kind, &mut walk);
    }
    kind
}

fn apply_known_ptr_kinds(fn_name: &str, kind: &mut HashMap<usize, qvm::types::PtrKind>) {
    use qvm::types::PtrKind;
    for &(off, name) in qvm::types::fn_local_slots(fn_name) {
        let k = match name {
            "spot" | "ent" => PtrKind::Entity,
            "gcl" | "targ_client" | "cl" => PtrKind::Client,
            _ => continue,
        };
        kind.insert(off, k);
    }
}

fn collect_local_names(
    fn_name: &str,
    frame: i32,
    ptr_kind: &HashMap<usize, qvm::types::PtrKind>,
    all_offs: &BTreeSet<usize>,
    skip_vn: &HashSet<usize>,
) -> HashMap<usize, String> {
    use qvm::types::PtrKind;
    let mut out: HashMap<usize, String> = HashMap::new();
    let mut taken: HashSet<String> = HashSet::new();
    for &(off, name) in qvm::types::fn_local_slots(fn_name) {
        out.insert(off, name.to_string());
        taken.insert(name.to_string());
    }
    let mut ents: Vec<usize> = ptr_kind
        .iter()
        .filter(|(off, k)| {
            **k == PtrKind::Entity && arg_index(frame, **off).is_none() && !out.contains_key(*off)
        })
        .map(|(off, _)| *off)
        .collect();
    ents.sort();
    for off in ents.iter().copied() {
        let name = if ents.len() == 1 && !taken.contains("ent") {
            "ent".into()
        } else {
            format!("ent_{off}")
        };
        taken.insert(name.clone());
        out.insert(off, name);
    }
    let mut cls: Vec<usize> = ptr_kind
        .iter()
        .filter(|(off, k)| {
            **k == PtrKind::Client && arg_index(frame, **off).is_none() && !out.contains_key(*off)
        })
        .map(|(off, _)| *off)
        .collect();
    cls.sort();
    for off in cls.iter().copied() {
        let name = if cls.len() == 1 && !taken.contains("cl") && !taken.contains("client") {
            "cl".into()
        } else {
            format!("cl_{off}")
        };
        taken.insert(name.clone());
        out.insert(off, name);
    }
    let mut menus: Vec<usize> = ptr_kind
        .iter()
        .filter(|(off, k)| {
            **k == PtrKind::Menu && arg_index(frame, **off).is_none() && !out.contains_key(*off)
        })
        .map(|(off, _)| *off)
        .collect();
    menus.sort();
    for off in menus.iter().copied() {
        let name = if menus.len() == 1 && !taken.contains("item") {
            "item".into()
        } else {
            format!("item_{off}")
        };
        taken.insert(name.clone());
        out.insert(off, name);
    }
    for off in all_offs {
        if !USE_VN_SLOTS {
            break;
        }
        if out.contains_key(off) || skip_vn.contains(off) {
            continue;
        }
        let name = format!("v{off}");
        if taken.contains(&name) {
            continue;
        }
        taken.insert(name.clone());
        out.insert(*off, name);
    }
    out
}

fn emit_function(em: &mut Emitter, out: &mut String, fi: usize) {
    let (_start, end) = em.ranges[fi];
    let frame = em.frame_of(fi);
    let ret = em.ret_of(fi).to_string();
    let cfg = build_cfg(&em.d, (_start, end), &em.data).expect("cfg");
    let f = decompile_function(&em.d, &cfg, frame, &em.data);
    let reach = reachable_blocks(&f);
    let (slot_float, local_float) = infer_floats(&f, &reach);
    let mut ptr_kind = infer_ptr_kinds(&f, em.overlay);
    apply_known_ptr_kinds(em.name_of(fi), &mut ptr_kind);
    let all_offs = collect_frame_locals(&f, frame);
    let mut skip_vn = collect_non_i4_locals(&f, frame);
    skip_vn.extend(local_float.iter().copied());
    let local_names = collect_local_names(em.name_of(fi), frame, &ptr_kind, &all_offs, &skip_vn);

    let nparams = em.params.get(&fi).copied().unwrap_or(0);

    let mut assigned: HashSet<usize> = HashSet::new();
    for b in &f.blocks {
        for st in &b.body {
            if let Stmt::Assign { slot, .. } = st {
                assigned.insert(*slot);
            }
        }
    }

    let mut ptr_view: HashSet<usize> = HashSet::new();
    let mut arg_view: HashMap<usize, String> = HashMap::new();
    let mut gcl_from_arg: Option<usize> = None;
    if em.typed && USE_PTR_VIEWS {
        for (off, k) in &ptr_kind {
            if ptr_view_ty(em.overlay, *k).is_some() {
                if let Some(ai) = arg_index(frame, *off) {
                    arg_view.insert(ai, format!("p{ai}_{}", ptr_view_suffix(*k)));
                } else if local_names.contains_key(off) {
                    ptr_view.insert(*off);
                }
            }
        }
        if em.overlay == qvm::types::OverlayMod::Game
            && !local_names.values().any(|n| n == "gcl")
        {
            let mut best: Option<usize> = None;
            for (off, k) in &ptr_kind {
                if *k == qvm::types::PtrKind::Entity {
                    if let Some(ai) = arg_index(frame, *off) {
                        best = Some(best.map_or(ai, |b| b.min(ai)));
                    }
                }
            }
            if let Some(ai) = best {
                if arg_view.contains_key(&ai) {
                    gcl_from_arg = Some(ai);
                }
            }
        }
    }

    let mut body = Body {
        frame,
        ret: ret.clone(),
        slot_float,
        local_float,
        locals: BTreeSet::new(),
        slots: BTreeSet::new(),
        nparams,
        fn_name: em.name_of(fi).to_string(),
        overlay: em.overlay,
        local_names,
        ptr_kind,
        ptr_view,
        arg_view,
        gcl_from_arg,
    };
    let mut blocks_text = String::new();

    // Bare-const cell inits (`CONST addr; CONST val; STORE4`) in THIS function
    // only — used to locally disambiguate a value that collides with a
    // function entry index but is stored as a sibling field of an otherwise
    // unambiguous data-only struct-array (e.g. a ui module's tab-bar text fields:
    // 215176/215248/215320 hold plain string addresses, 215392 holds the
    // SAME kind of value but numerically collides with entry 17229 — a real
    // function elsewhere in the program). Scoped to one function's own
    // stores (not the whole module) so it can never coincide with unrelated
    // code elsewhere in a >1MB data segment.
    let mut local_bare_stores: Vec<(i32, i32)> = Vec::new();
    for b in &f.blocks {
        for st in &b.body {
            if let Stmt::Store { addr: Expr::Const(a), value: Expr::Const(v), .. } = st {
                local_bare_stores.push((*a, *v));
            }
        }
    }
    // A value that collides with both a function entry and a string offset is
    // ambiguous per-site (see forced_data below), but if the SAME numeric
    // value is ALSO stored elsewhere in this function at a site that does
    // NOT look like a sibling text-field (e.g. a callback field repeated
    // across several otherwise-identical struct instances, like the sample's
    // tab-bar items sharing one event handler), that's strong evidence the
    // value is genuinely a function pointer throughout this function — don't
    // let the sibling-stride heuristic force ANY of its occurrences to data
    // (this fixed a real crash: NetworkOptionsMenu_Init's Sound-tab/Data-rate
    // callback fields were mis-rendered as qvm_mem+offset instead of the fn
    // pointer, because they happened to sit at the same stride as nearby
    // icon-texture string fields).
    let mut confirmed_fnptr_values: HashSet<i32> = HashSet::new();
    for &(a, v) in &local_bare_stores {
        if v < 0 || !em.addrtaken.contains(&(v as usize)) || em.q.string_at(v).is_none() {
            continue;
        }
        let pure_siblings: Vec<i32> = local_bare_stores
            .iter()
            .filter(|&&(oa, ov)| {
                oa != a
                    && (oa - a).abs() <= 256
                    && ov >= 0
                    && !em.addrtaken.contains(&(ov as usize))
                    && em.q.string_at(ov).is_some()
            })
            .map(|&(oa, _)| oa - a)
            .collect();
        let would_force = pure_siblings
            .iter()
            .any(|&d| d.abs() > 0 && pure_siblings.iter().any(|&d2| d2 == 2 * d || d2 == -2 * d));
        if !would_force {
            confirmed_fnptr_values.insert(v);
        }
    }

    // Array-of-structs analogue of `local_bare_stores`/`confirmed_fnptr_values`
    // above, for stores whose ADDRESS is computed (`(stride*i)+FIELD_OFF`,
    // e.g. a loop initializing `item[k].generic.x = ...`) rather than a bare
    // constant. Struct-array field stores in the same loop share the exact
    // same `stride*i` sub-expression, differing only in the trailing added
    // FIELD_OFF constant, so grouping by that sub-expression (structural
    // equality) scopes the sibling-field lookup to one array/loop, exactly
    // like `local_bare_stores` scopes to one function. Only the OFFSET+VALUE
    // pair is kept (the shared base sub-expression is implied by grouping),
    // so this can never coincide with an unrelated loop over a DIFFERENT
    // array elsewhere in the same function.
    fn split_indexed_addr(addr: &Expr) -> Option<(i32, &Expr)> {
        if let Expr::Binop("+", a, b) = addr {
            if let Expr::Const(k) = b.as_ref() {
                return Some((*k, a.as_ref()));
            }
            if let Expr::Const(k) = a.as_ref() {
                return Some((*k, b.as_ref()));
            }
        }
        None
    }
    let mut indexed_groups: Vec<(&Expr, Vec<(i32, i32)>)> = Vec::new();
    for b in &f.blocks {
        for st in &b.body {
            if let Stmt::Store { addr, value: Expr::Const(v), .. } = st {
                if let Some((k, base)) = split_indexed_addr(addr) {
                    match indexed_groups.iter_mut().find(|(gb, _)| *gb == base) {
                        Some((_, offs)) => offs.push((k, *v)),
                        None => indexed_groups.push((base, vec![(k, *v)])),
                    }
                }
            }
        }
    }
    // A function-entry constant that also collides with a printable string,
    // stored at offset K into a struct-array element, is a genuine callback
    // (not the string) when a SIBLING store into the SAME array element at
    // offset K-48 writes a small integer (1..=16) — the tell-tale shape of
    // `menucommon_s.type` (1..=16, an MTYPE_* enum) sitting 48 bytes before
    // `menucommon_s.callback`, repeated once per struct-array (e.g. a ui module's
    // PlayerModel_MenuInit `picbuttons[k].generic.callback` — entry 20990
    // numerically collides with a printable string, but 20990-48 always has
    // the sibling `type` write with value 6 in the SAME array).
    let mut local_indexed_fnptr_rescue: HashSet<(i32, i32)> = HashSet::new();
    for (_, offs) in &indexed_groups {
        for &(k, v) in offs {
            // Note: deliberately checking `by_entry` (every valid function
            // entry PC), NOT `em.addrtaken` (the module-wide CONFIRMED set) —
            // this rescue exists precisely FOR values the module-wide scan
            // could not confirm (excluded due to the string collision), so
            // requiring membership in that same set would always fail.
            if v < 0 || !em.by_entry.contains_key(&(v as usize)) || em.q.string_at(v).is_none() {
                continue;
            }
            let has_type_sibling = offs
                .iter()
                .any(|&(ok, ov)| ok == k - 48 && (1..=16).contains(&ov));
            if has_type_sibling {
                local_indexed_fnptr_rescue.insert((k, v));
            }
        }
    }

    let mut invert_else: HashMap<usize, usize> = HashMap::new();
    let mut skip_term: HashSet<usize> = HashSet::new();
    if INVERT_FINDTEAMS && em.typed && em.name_of(fi) == "G_FindTeams" {
        let mut targets = HashSet::new();
        for (bi, b) in f.blocks.iter().enumerate() {
            if !reach[bi] {
                continue;
            }
            match &b.term {
                Terminator::Goto(x) => {
                    targets.insert(*x);
                }
                Terminator::IfGoto { target, .. } => {
                    targets.insert(*target);
                }
                Terminator::Switch { cases, default, .. } => {
                    for (_, x) in cases {
                        targets.insert(*x);
                    }
                    if let Some(x) = default {
                        targets.insert(*x);
                    }
                }
                _ => {}
            }
        }
        for (bi, b) in f.blocks.iter().enumerate() {
            if !reach[bi] {
                continue;
            }
            if let Terminator::IfGoto { target, .. } = &b.term {
                let Some(next) = (bi + 1..f.blocks.len()).find(|&j| reach[j]) else {
                    eprintln!("G_FindTeams if L{}: no next reachable", b.start);
                    continue;
                };
                let nb = &f.blocks[next];
                if is_emitted_empty(&nb.body, &f.read_slots) {
                    if let Terminator::Goto(else_t) = nb.term {
                        if else_t != *target && !targets.contains(&nb.start) {
                            invert_else.insert(bi, else_t);
                            skip_term.insert(next);
                        }
                    }
                }
            }
        }
        eprintln!(
            "G_FindTeams invert: {} ifs, {} trampolines skipped",
            invert_else.len(),
            skip_term.len()
        );
    }

    for (bi, b) in f.blocks.iter().enumerate() {
        if !reach[bi] || skip_term.contains(&bi) {
            continue;
        }
        let mut text = String::new();
        for st in &b.body {
            match st {
                Stmt::Assign { slot, value } => {
                    let vf = em.fval(&body, value);
                    if !f.read_slots.contains(slot) {
                        match value {
                            Expr::Call(..) | Expr::Trap(..) => {
                                let cf = em.fval(&body, value);
                                let rhs = em.fmt(&mut body, value, cf);
                                text.push_str(&format!("  {rhs};\n"));
                            }
                            _ => {} // pure dead write
                        }
                    } else {
                        body.slots.insert(*slot);
                        if vf {
                            let rhs = em.fmt_float(&mut body, value);
                            text.push_str(&format!("  *(float*)&s{slot} = {rhs};\n"));
                        } else {
                            let rhs = em.fmt_int(&mut body, value);
                            text.push_str(&format!("  s{slot} = {rhs};\n"));
                        }
                    }
                }
                Stmt::Store { addr, value, size } => {
                    let vf = em.fval(&body, value);
                    let lhs = em.store_lhs(&mut body, addr, *size, vf);
                    // A bare-const cell init whose value collides with a
                    // function entry index AND a printable string is a
                    // sibling data field, not a callback, when it sits at a
                    // consistent repeating stride from >=2 OTHER bare-const
                    // stores in THIS function whose own values can never be
                    // a function (not address-taken at all) — the tell-tale
                    // shape of a struct-array of text fields (e.g. a ui module's
                    // tab-bar labels every 72 bytes). Requiring the SAME
                    // stride to repeat at least twice (not just one nearby
                    // store) rules out incidental neighbors from unrelated
                    // widgets earlier/later in a large sequential setup
                    // function. Global addrtaken/fns classification, and
                    // every other use of the same raw value elsewhere in the
                    // program, is left untouched.
                    let forced_data = match (addr, value) {
                        (Expr::Const(a), Expr::Const(v))
                            if *v >= 0
                                && em.addrtaken.contains(&(*v as usize))
                                && em.q.string_at(*v).is_some()
                                && !confirmed_fnptr_values.contains(v) =>
                        {
                            let pure_siblings: Vec<i32> = local_bare_stores
                                .iter()
                                .filter(|&&(oa, ov)| {
                                    oa != *a
                                        && (oa - a).abs() <= 256
                                        && ov >= 0
                                        && !em.addrtaken.contains(&(ov as usize))
                                        && em.q.string_at(ov).is_some()
                                })
                                .map(|&(oa, _)| oa - a)
                                .collect();
                            pure_siblings.iter().any(|&d| {
                                let stride = d.abs();
                                stride > 0
                                    && pure_siblings
                                        .iter()
                                        .any(|&d2| d2 == 2 * d || d2 == -2 * d)
                            })
                        }
                        _ => false,
                    };
                    // Opposite direction of `forced_data` above: a computed
                    // (array-indexed) store whose value is a function entry
                    // that also collides with a printable string, but has a
                    // confirmed sibling `type` field in the SAME array
                    // element (see `local_indexed_fnptr_rescue`), is rendered
                    // as the function's C name instead of the default data
                    // address — the module-wide addrtaken/fns classification
                    // never sees this value as a function pointer, so
                    // without this override the callback degrades to a
                    // garbage data address and the indirect call through it
                    // crashes (or, if it's never invoked immediately, the
                    // widget silently loses its `callback` handler).
                    let forced_fn = match (addr, value) {
                        (_, Expr::Const(v)) => split_indexed_addr(addr)
                            .is_some_and(|(k, _)| local_indexed_fnptr_rescue.contains(&(k, *v))),
                        _ => false,
                    }
                    // Absolute BSS store of a proven function-pointer value:
                    // `*(int*)(menuStruct + FIELD) = fn_entry` outside the
                    // blob. Guarded to constant addresses at/above the blob
                    // end so ordinary small-integer stores are untouched.
                    || match (addr, value) {
                        (Expr::Const(a), Expr::Const(v)) => {
                            *v > 0
                                && *a as usize >= em.blob.len()
                                && em.stored_fnptrs.contains(v)
                        }
                        (
                            Expr::GlobalRef { addr: a, .. },
                            Expr::Const(v),
                        ) => *v > 0 && *a >= em.blob.len() && em.stored_fnptrs.contains(v),
                        _ => false,
                    };
                    let rhs = if let (true, Expr::Const(v)) = (forced_data, value) {
                        em.fmt_data_const(*v)
                    } else if let (true, Expr::Const(v)) = (forced_fn, value) {
                        em.fmt_fn_const(*v)
                    } else if vf {
                        em.fmt_float(&mut body, value)
                    } else {
                        em.fmt_int(&mut body, value)
                    };
                    text.push_str(&format!("  {lhs} = {rhs};\n"));
                }
                Stmt::BlockCopy { dest, src, count } => {
                    // Original compiled this to OP_BLOCK_COPY (struct copy).
                    // A `memcpy(...)` call would compile to a trap-101 CALL,
                    // diverging the rebuilt's trap sequence. Emit a struct
                    // assignment over a byte-array typedef of the same size
                    // so lcc emits INDIRB/ASGNB -> OP_BLOCK_COPY.
                    let n = *count as usize;
                    em.block_sizes.insert(n);
                    let d = em.fmt(&mut body, dest, false);
                    let s = em.fmt(&mut body, src, false);
                    text.push_str(&format!("  *(blob_{n}*)({d}) = *(blob_{n}*)({s});\n"));
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => {
                let dummy = matches!(v, Expr::Slot(s) if !assigned.contains(s));
                match ret.as_str() {
                    "void" => text.push_str("  return;\n"),
                    "float" => {
                        if dummy {
                            text.push_str("  return 0.0f;\n");
                        } else {
                            text.push_str(&format!("  return {};\n", em.fmt_float(&mut body, v)));
                        }
                    }
                    _ => {
                        if dummy {
                            text.push_str("  return 0;\n");
                        } else {
                            text.push_str(&format!("  return {};\n", em.fmt_int(&mut body, v)));
                        }
                    }
                }
            }
            Terminator::Return(None) => match ret.as_str() {
                "void" => text.push_str("  return;\n"),
                "float" => text.push_str("  return 0.0f;\n"),
                _ => text.push_str("  return 0;\n"),
            },
            Terminator::Goto(t) => text.push_str(&format!("  goto L{t};\n")),
            Terminator::IfGoto { cond, target } => {
                let cf = em.fval(&body, cond);
                let cond_s = em.fmt(&mut body, cond, cf);
                if em.typed && looks_like_counter_loop(&cond_s) {
                    text.push_str("  /* for (...) */\n");
                }
                if let Some(&else_t) = invert_else.get(&bi) {
                    text.push_str(&format!("  if (!({cond_s})) goto L{else_t};\n"));
                } else {
                    text.push_str(&format!("  if ({cond_s}) goto L{target};\n"));
                }
            }
            Terminator::Unresolved(a) => {
                text.push_str(&format!("  /* UNRESOLVED JUMP: ({}) */\n", em.fmt(&mut body, a, false)));
            }
            Terminator::Switch { sel, cases, default } => {
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
                text.push_str(&format!("  switch ({}) {{\n", em.fmt(&mut body, sel, false)));
                for (v, t) in cases {
                    if default_target == Some(*t) {
                        continue;
                    }
                    text.push_str(&format!("  case {v}: goto L{t};\n"));
                }
                if let Some(t) = default_target {
                    text.push_str(&format!("  default: goto L{t};\n"));
                }
                text.push_str("  }\n");
            }
            Terminator::Fallthrough => {}
        }
        // label + body (labels must precede a statement in C89)
        if text.trim().is_empty() {
            blocks_text.push_str(&format!("L{}: ;\n", b.start));
        } else {
            blocks_text.push_str(&format!("L{}:\n", b.start));
            blocks_text.push_str(&text);
        }
    }

    // signature line (params)
    let mut head = String::new();
    if nparams == 0 {
        head.push_str(&format!("{ret} {}(void) {{\n", em.name_of(fi)));
    } else {
        let params: Vec<String> = (0..nparams).map(|k| format!("int p{k}")).collect();
        head.push_str(&format!("{ret} {}({}) {{\n", em.name_of(fi), params.join(", ")));
    }
    if body.locals.is_empty() && f.blocks.iter().all(|b| b.body.is_empty()) {
        head.push_str("  /* empty in orig QVM */\n");
    }

    // variable declarations (C89: must precede all statements)
    if em.typed {
        let mut arg_names: Vec<(usize, String)> = body.arg_view.iter().map(|(k, n)| (*k, n.clone())).collect();
        arg_names.sort_by_key(|(k, _)| *k);
        for (k, name) in &arg_names {
            let off = body.frame as usize + 8 + 4 * k;
            if let Some(kind) = body.ptr_kind.get(&off).copied() {
                if let Some(ty) = ptr_view_ty(em.overlay, kind) {
                    head.push_str(&format!("#define {name} (({ty}*)p{k})\n"));
                }
            }
        }
        if let Some(k) = body.gcl_from_arg {
            if let Some(view) = body.arg_view.get(&k) {
                head.push_str(&format!("#define gcl ((gclient_t*)({view}->client))\n"));
            }
        }
    }
    if !body.locals.is_empty() {
        let sz = body.frame.max(1) as usize;
        head.push_str(&format!("  unsigned char loc_0[{sz}];\n"));
        if em.typed {
            let mut names: Vec<(usize, String)> = body.local_names.iter().map(|(o, n)| (*o, n.clone())).collect();
            names.sort_by_key(|(o, _)| *o);
            for (off, name) in names {
                if !body.locals.contains(&off) {
                    continue;
                }
                if body.ptr_view.contains(&off) {
                    let ty = body
                        .ptr_kind
                        .get(&off)
                        .copied()
                        .and_then(|k| ptr_view_ty(em.overlay, k))
                        .unwrap_or("void");
                    head.push_str(&format!("#define {name}_i (*(int*)&loc_0[{off}])\n"));
                    head.push_str(&format!("#define {name} (({ty}*){name}_i)\n"));
                } else {
                    head.push_str(&format!("#define {name} (*(int*)&loc_0[{off}])\n"));
                }
            }
        }
    }
    for s in &body.slots {
        head.push_str(&format!("  int s{s};\n"));
    }

    out.push_str(&head);
    out.push_str(&blocks_text);
    if em.typed {
        let mut undefs: Vec<String> = Vec::new();
        if let Some(k) = body.gcl_from_arg {
            if body.arg_view.contains_key(&k) {
                undefs.push("gcl".into());
            }
        }
        for name in body.arg_view.values() {
            undefs.push(name.clone());
        }
        if !body.locals.is_empty() {
            for (off, name) in &body.local_names {
                if !body.locals.contains(off) {
                    continue;
                }
                if body.ptr_view.contains(off) {
                    undefs.push(format!("{name}_i"));
                }
                undefs.push(name.clone());
            }
        }
        undefs.sort();
        undefs.dedup();
        for name in undefs {
            out.push_str(&format!("#undef {name}\n"));
        }
    }
    out.push_str("}\n\n");
}

/// True if trap `n` returns a float in the game trap table (103..=106, 110, 111).
fn float_trap(n: u32) -> bool {
    matches!(n, 103..=106 | 110 | 111)
}

/// Collect every trap number appearing anywhere in a function's AST.
fn collect_traps(f: &Function, traps: &mut BTreeSet<u32>) {
    let mut walk = |e: &Expr| {
        let mut st: Vec<&Expr> = vec![e];
        while let Some(x) = st.pop() {
            if let Expr::Trap(n, args) = x {
                traps.insert(*n);
                st.extend(args.iter());
                continue;
            }
            match x {
                Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                Expr::Binop(_, a, b) => {
                    st.push(a);
                    st.push(b);
                }
                Expr::Call(t, args) => {
                    st.push(t);
                    st.extend(args.iter());
                }
                _ => {}
            }
        }
    };
    for b in &f.blocks {
        for s in b.body.iter() {
            match s {
                Stmt::Assign { value, .. } => walk(value),
                Stmt::Store { addr, value, .. } => {
                    walk(addr);
                    walk(value);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    walk(dest);
                    walk(src);
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => walk(v),
            Terminator::IfGoto { cond, .. } => walk(cond),
            Terminator::Switch { sel, .. } => walk(sel),
            Terminator::Unresolved(a) => walk(a),
            _ => {}
        }
    }
}

/// Collect every BLOCK_COPY byte count appearing in a function's AST.
fn collect_block_sizes(f: &Function, sizes: &mut BTreeSet<usize>) {
    for b in &f.blocks {
        for s in b.body.iter() {
            if let Stmt::BlockCopy { count, .. } = s {
                sizes.insert(*count as usize);
            }
        }
    }
}

/// If `addr` is a data-table address `base + idx * stride` (a large constant
/// leaf acting as the table base, with an optional `<< n`/`* m` scaling term),
/// return `(base, stride)` in BYTES. This recognises the data cells behind an
/// indirect call `(*(int*)(base + idx*stride))()`. Such cells hold FUNCTION
/// POINTERS and must be relocated even when their value numerically sits below
/// `blob.len()` — the generic guard treats sub-blob-length values as plain
/// data/string pointers, which is wrong for table-backed command dispatch
/// (e.g. cgame's console-command table at data 3084: handlers like `viewpos`
/// live at orig insn 6146, far below blob_len 61220).
fn table_cell_geoms(addr: &Expr) -> Option<(usize, usize)> {
    fn collect_consts(e: &Expr, out: &mut Vec<i64>) {
        match e {
            Expr::Const(c) => out.push(*c as i64),
            Expr::Unop(_, a) | Expr::Float(a) => collect_consts(a, out),
            Expr::Binop(_, a, b) => {
                collect_consts(a, out);
                collect_consts(b, out);
            }
            _ => {}
        }
    }
    fn find_scale(e: &Expr) -> Option<usize> {
        match e {
            Expr::Binop("<<", _, b) => match b.as_ref() {
                Expr::Const(sh) if *sh >= 0 && *sh < 16 => Some(1usize << *sh),
                _ => None,
            },
            Expr::Binop("*", a, b) => match (a.as_ref(), b.as_ref()) {
                (Expr::Const(m), _) if *m > 0 && *m <= 4096 => Some(*m as usize),
                (_, Expr::Const(m)) if *m > 0 && *m <= 4096 => Some(*m as usize),
                _ => None,
            },
            Expr::Binop("+", a, b) => find_scale(a).or_else(|| find_scale(b)),
            Expr::Unop(_, a) | Expr::Float(a) => find_scale(a),
            _ => None,
        }
    }
    let mut cs = Vec::new();
    collect_consts(addr, &mut cs);
    let base = cs.into_iter().max()?;
    // A table base must be a static data-space address (the identity-mapped
    // blob occupies 0..~0x400000; stack LOCALS live far above it).
    if !(0x100..=0x2000000).contains(&base) {
        return None;
    }
    let stride = find_scale(addr).unwrap_or(4).max(4);
    Some((base as usize, stride))
}

/// Classify constants by their consumer:
/// (1) function-entry constants genuinely used as function pointers (ARG/STORE4
///     value, never an int/float operand) -> returned as fn set;
/// (2) blob addresses used as data pointers (ARG/STORE4 value, never an
///     int/float operand, 4-aligned, >= 0x100) -> returned as data set.
/// True if `c` (a VM data-space address) holds a printable NUL-terminated
/// string — either in the literal segment (lcc string constants) or in the
/// data segment. Used to keep string/data addresses out of the function-pointer
/// classification even when the address numerically equals a function entry.
fn is_string_at(q: &qvm::Qvm, c: i32) -> bool {
    if c < 0 {
        return false;
    }
    if q.string_at(c).is_some() {
        return true;
    }
    let dlen = q.data_length as usize;
    if (c as usize) < dlen && (c as usize) < q.data.len() {
        let rest = &q.data[c as usize..];
        if let Some(end) = rest.iter().position(|&b| b == 0) {
            let s = &rest[..end];
            return !s.is_empty()
                && s.iter()
                    .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7f));
        }
    }
    false
}

fn scan_addrtaken(
    d: &qvm::disasm::Disassembly,
    by_entry: &HashMap<usize, usize>,
    blob_len: usize,
    strings: &HashSet<i32>,
    module: qvm::traps::Module,
) -> (HashSet<usize>, HashSet<i32>, HashSet<i32>, HashSet<i32>, HashSet<i32>) {
    use qvm::Opcode::*;
    // Stack value: a known constant, a LOCAL slot address, a value loaded from
    // a bare global cell (CellLoad), a value loaded from a LOCAL slot i.e. a
    // candidate incoming parameter (Param), a computed struct-field address
    // (base + constant offset, e.g. `ent + 4900`) whose offset is tracked
    // even though the base pointer itself is unknown (Field), a value loaded
    // from such a field (FieldLoad), or any other value.
    #[derive(Clone, Copy)]
    enum Se {
        C(i32),
        L(i32),
        CellLoad(i32),
        Param(i32),
        Field(i32),
        FieldLoad(i32),
        O,
    }
    // Struct-field offsets (e.g. 4900 for `ent->think`-style callback fields)
    // confirmed to hold function pointers because some function loads the
    // field from a computed per-instance base and immediately CALLs the
    // result (`base + 4900; LOAD4; CALL`). Analogous to `bare_call_cells`
    // but keyed by offset instead of absolute address, since these fields
    // are stored through many different entity/client base pointers, never
    // a single fixed global cell.
    let mut field_call_offsets: HashSet<i32> = HashSet::new();
    // (stored function-entry constant, field offset) for STOREs into a
    // computed `base + offset` address, deferred until the full scan is
    // done so they can be cross-checked against `field_call_offsets`.
    let mut field_stores: Vec<(i32, i32)> = Vec::new();
    let mut st: Vec<Se> = Vec::new();
    // Cells confirmed to hold function pointers because some function loads
    // them (from a bare constant address) and immediately CALLs the result —
    // e.g. a confirm-dialog's per-frame draw hook: `*(cell)` is invoked if
    // non-zero. This is the ONLY way to recognize a value as "must be a
    // function pointer" when it is merely PASSED AS AN ARGUMENT to a helper
    // (not itself directly called/stored-with-known-siblings), because the
    // helper stores its own parameter into this cell unmodified.
    let mut bare_call_cells: HashSet<i32> = HashSet::new();
    // (callee function entry, zero-based parameter index) -> cell the callee
    // forwards that parameter into verbatim. If that cell is in
    // `bare_call_cells`, every CALLER's argument at that position is a
    // function pointer even when its value numerically collides with a
    // printable string (the standard index-collision hazard).
    let mut param_forward: HashMap<(usize, i32), i32> = HashMap::new();
    // (callee entry, arg index, arg value) deferred until the full scan is done
    // so `param_forward` / `bare_call_cells` are complete. A single forward pass
    // misses every call site that appears BEFORE its callee in instruction
    // order — which is the common case for helpers like UI_ConfirmMenu (callers
    // at ~16k, body at ~17k). Without the deferral, action callbacks that
    // collide with printable strings (Exit/Restart Arena: 16458/"EMO",
    // 16477/"ts/banner/...") stay classified as data and the rebuilt QVM
    // stores a stale original insn index instead of the relocated fn address.
    let mut pending_param_args: Vec<(usize, i32, i32)> = Vec::new();
    let mut cur_fn_entry: usize = 0;
    let mut cur_frame_size: i32 = 0;
    let mut fns: HashSet<usize> = HashSet::new();
    let mut argstore: HashSet<i32> = HashSet::new();
    // Constants actually handed to a function call as arguments (resolved at the
    // non-trap CALL that closes the ARG sequence). They cannot establish that a
    // colliding string/entry value is a function pointer: strings are routinely
    // passed to ordinary calls.
    let mut arg_call: HashSet<i32> = HashSet::new();
    // Direct CALL targets are unambiguous function provenance. This matters for
    // globals such as cgame's CG_Trace callback: the VM offset 53366 is also
    // printable data, but a STORE4 of it into a callback cell must receive the
    // rebuilt function address.
    let mut call_targets: HashSet<i32> = HashSet::new();
    // (stored value, concrete destination when known, destination was a BARE
    // constant address rather than array-indexed). Keeping the destination
    // lets us identify menucommon_s.callback at item+48 even if the callback
    // entry numerically collides with a printable data string. The bare-ness
    // flag matters for `global_fnptr_store` below: an indexed array store's
    // trailing field offset is a much weaker signal (recurs across many
    // unrelated struct-array loops in the whole program, e.g. every menu
    // item's `.string` text field), so that heuristic must stay restricted to
    // truly concrete single-cell globals; only the narrower `callback_cell`
    // check (which cross-checks a sibling type field) is safe to extend to
    // indexed stores.
    let mut storevals: HashSet<(i32, Option<i32>, bool)> = HashSet::new();
    let mut concrete_stores: HashMap<i32, HashSet<i32>> = HashMap::new();
    let mut intused: HashSet<i32> = HashSet::new();
    // Constants ARG'd since the last call site. Resolved at the CALL/JUMP that
    // closes the call: a CALL whose target is negative is a syscall (trap), and
    // its arguments are data/string addresses or literals — NEVER function
    // pointers. A string address that numerically equals a function entry index
    // (e.g. a literal that collides with an insn index) must not be rendered
    // as the rebuilt function's C name, or the trap receives the function
    // address instead of the string offset.
    let mut pending: Vec<i32> = Vec::new();
    let mut traparg: HashSet<i32> = HashSet::new();
    // Constants used as operands of arithmetic / ordered-comparison / float
    // ops (i.e. ANY int operand EXCEPT EQ/NE). A think-pointer compare like
    // `ent->think == fn` is EQ/NE, so it must NOT disqualify a genuine
    // function pointer; but `count >= 200`, `p + 200`, `c * 200` prove the
    // value is a literal even when it collides with a function entry index.
    let mut arithused: HashSet<i32> = HashSet::new();
    for ins in &d.insns {
        match ins.op {
            Const => {
                if let Some(v) = ins.operand {
                    st.push(Se::C(v));
                } else {
                    st.push(Se::O);
                }
            }
            Local => st.push(Se::L(ins.operand.unwrap_or(0))),
            Push => st.push(Se::O),
            Load1 | Load2 | Load4 => {
                match st.pop() {
                    Some(Se::C(c)) => {
                        argstore.insert(c);
                        st.push(Se::CellLoad(c));
                    }
                    Some(Se::L(off)) => st.push(Se::Param(off)),
                    Some(Se::Field(off)) => st.push(Se::FieldLoad(off)),
                    _ => st.push(Se::O),
                }
            }
            Store1 | Store2 | Store4 => {
                // STORE4 pops (address, value) with value on top. A stored
                // constant is a genuine function pointer (ent->think = fn)
                // ONLY when the target address is NOT a plain LOCAL slot —
                // `LOCAL n; CONST 200; STORE4` writes a config literal that
                // merely collides with a function entry index. Local-slot
                // stores are excluded from storevals; computed-address stores
                // qualify. A BARE-const address (`CONST cell; CONST fn; STORE4`)
                // is NOT necessarily a data/string initializer: cgame stores
                // genuine function pointers into global cells this way (e.g.
                // CG_PointContents/CG_Trace addresses written into its cg
                // struct for the prediction path). When the value is a function
                // entry, hand it to the storevals pass and let the
                // arithused/strings+arg_call rules below decide fns vs literal.
                let val = st.pop();
                let addr = st.pop();
                if let (Some(Se::C(a)), Some(Se::C(c))) = (addr, val) {
                    concrete_stores.entry(a).or_default().insert(c);
                }
                // A callee that stores its own incoming parameter, unmodified,
                // into a bare global cell that is confirmed elsewhere to be
                // loaded-and-called is forwarding a callback parameter (e.g.
                // a confirm-dialog helper storing its 2nd/3rd argument
                // into the per-frame draw/accept hook cells). Record it so
                // every CALL SITE's argument at that position can be forced
                // to render as the rebuilt function pointer, even when the
                // value collides with a printable string.
                if let (Some(Se::C(cell)), Some(Se::Param(off))) = (addr, val) {
                    let param_idx = (off - cur_frame_size - 8) / 4;
                    if param_idx >= 0 {
                        param_forward.insert((cur_fn_entry, param_idx), cell);
                    }
                }
                if let Some(Se::C(c)) = val {
                    match addr {
                        Some(Se::L(_)) => {} // local-slot config literal
                        Some(Se::C(_)) => {
                            if by_entry.contains_key(&(c as usize)) {
                                storevals.insert((c, addr.and_then(|a| match a {
                                    Se::C(cell) => Some(cell),
                                    _ => None,
                                }), true));
                            }
                        } // bare-const cell init
                        Some(Se::Field(off)) => {
                            if by_entry.contains_key(&(c as usize)) {
                                field_stores.push((c, off));
                            }
                            storevals.insert((c, None, false));
                        } // computed per-instance struct-field store
                        _ => {
                            storevals.insert((c, None, false));
                        } // computed/loaded address
                    }
                }
                if let Some(Se::C(c)) = addr {
                    argstore.insert(c);
                }
            }
            Arg => {
                if let Some(Se::C(c)) = st.pop() {
                    pending.push(c);
                }
            }
            Call | Jump => {
                // Pop the call target: a negative CALL target is a syscall
                // (trap) whose ARG'd constants are data addresses/literals.
                let target = st.pop();
                if ins.op == Call {
                    if let Some(Se::C(t)) = target {
                        if t >= 0 {
                            call_targets.insert(t);
                        }
                    }
                    // `CONST cell; LOAD4; CALL` (possibly with an intervening
                    // null-check elsewhere in the function) invokes whatever
                    // function pointer is currently stored at `cell` — proof
                    // that cell genuinely holds a callback, independent of
                    // any particular value stored into it.
                    if let Some(Se::CellLoad(cell)) = target {
                        bare_call_cells.insert(cell);
                    }
                    // Record (callee, arg-index, arg-value) for post-scan
                    // resolution against `param_forward` × `bare_call_cells`.
                    // Must NOT resolve here: both maps are still incomplete
                    // for any call site that precedes its callee in the file.
                    if let Some(Se::C(t)) = target {
                        if t >= 0 {
                            for (i, &argval) in pending.iter().enumerate() {
                                pending_param_args.push((t as usize, i as i32, argval));
                            }
                        }
                    }
                    // `base + offset; LOAD4; CALL` invokes whatever function
                    // pointer is currently stored at that per-instance struct
                    // field (e.g. `ent->think()`) — proof the offset is a
                    // callback field, independent of which entity/base it
                    // was read through.
                    if let Some(Se::FieldLoad(off)) = target {
                        field_call_offsets.insert(off);
                    }
                }
                if ins.op == Call && matches!(target, Some(Se::C(t)) if t < 0) {
                    // memset/memcpy-shaped traps (dst, fill/src, byte-count):
                    // the trailing byte-count argument is ALWAYS a plain
                    // integer, never a pointer, even when its value happens
                    // to numerically collide with a valid data-segment offset
                    // (e.g. a small sizeof() constant like 444 that also
                    // looks like a printable-string address). Rendering it as
                    // `qvm_mem + c` turns a small memset into a multi-gigabyte
                    // one at runtime. Detected by trap name so it generalizes
                    // across modules/trap-number layouts.
                    if let Some(Se::C(t)) = target {
                        let is_bytecount_trap = matches!(
                            trap_name(module, (-t - 1) as u32),
                            Some("memset") | Some("memcpy")
                        );
                        if is_bytecount_trap {
                            if let Some(&last) = pending.last() {
                                intused.insert(last);
                            }
                        }
                    }
                    for c in pending.drain(..) {
                        traparg.insert(c);
                    }
                } else {
                    // Normal call (or branch jump): ARG'd constants may be
                    // function pointers (e.g. qsort cmp) and stay candidates.
                    let args: Vec<i32> = pending.drain(..).collect();
                    argstore.extend(args.iter().copied());
                    arg_call.extend(args);
                }
            }
            Add | Sub | Divi | Divu | Modi | Modu | Muli | Mulu | Band | Bor | Bxor | Lsh | Rshi
            | Rshu | AddF | SubF | DivF | MulF | Eq | Ne | Lti | Lei | Gti | Gei | Ltu | Leu
            | Gtu | Geu | Eqf | Nef | Ltf | Lef | Gtf | Gef => {
                let b = st.pop();
                let a = st.pop();
                let eq = matches!(ins.op, Eq | Ne);
                if let Some(Se::C(c)) = a {
                    intused.insert(c);
                    if !eq {
                        arithused.insert(c);
                    }
                }
                if let Some(Se::C(c)) = b {
                    intused.insert(c);
                    if !eq {
                        arithused.insert(c);
                    }
                }
                if !ins.op.is_branch_idx() {
                    // `base + offset` where base is a pointer-shaped value
                    // (param/local/loaded cell) and offset is a constant
                    // yields a computed struct-field address; keep tracking
                    // the offset so a later LOAD4+CALL or STORE4 through it
                    // can be recognized as a callback field (see
                    // `field_call_offsets`/`field_stores`).
                    let field = if ins.op == Add {
                        match (a, b) {
                            (Some(Se::Param(_) | Se::CellLoad(_) | Se::L(_)), Some(Se::C(off))) => {
                                Some(off)
                            }
                            (Some(Se::C(off)), Some(Se::Param(_) | Se::CellLoad(_) | Se::L(_))) => {
                                Some(off)
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    match field {
                        Some(off) => st.push(Se::Field(off)),
                        None => st.push(Se::O),
                    }
                }
            }
            Negi | Bcom | Sex8 | Sex16 | Negf | Cvif | Cvfi => {
                if let Some(Se::C(c)) = st.pop() {
                    intused.insert(c);
                    arithused.insert(c);
                }
                st.push(Se::O);
            }
            BlockCopy => {
                st.pop();
                st.pop();
                st.pop();
            }
            Leave => {
                st.clear();
                pending.clear();
            }
            Pop => {
                st.pop();
            }
            Enter => {
                cur_frame_size = ins.operand.unwrap_or(0);
                if by_entry.contains_key(&ins.idx) {
                    cur_fn_entry = ins.idx;
                }
            }
            Undef | Ignore | Break => {}
        }
    }
    let mut data = HashSet::new();
    for &c in &argstore {
        if intused.contains(&c) || c < 0 {
            continue;
        }
        // A constant used ONLY as a trap-call argument (never as a normal-call
        // arg) is a data/string address or literal, not a function pointer —
        // even when it collides with a function entry index. Same for any
        // constant that resolves to a printable string (a string literal whose
        // data address numerically equals a function entry index): a genuine
        // function pointer never points into a printable string region.
        if !traparg.contains(&c)
            && !strings.contains(&c)
            && by_entry.contains_key(&(c as usize))
        {
            fns.insert(c as usize);
        } else if c >= 0x100 && c % 4 == 0 && (c as usize) < blob_len {
            data.insert(c);
        }
    }
    // Store values that are function entries are function pointers even when
    // the constant also appears as an integer operand (a think-pointer compare
    // like `ent->think == fn`). The intused exclusion above exists to protect
    // data-pointer-shaped integers (va()'s buffer stride), not function entries.
    // BUT: a stored constant that is also used as an arithmetic/ordered-compare
    // operand is a literal that merely collides with a function entry index
    // (e.g. a literal numerically equal to a function entry) — rendering it as the
    // function's C name would write the REBUILT address, not the literal.
    for &(c, cell, is_bare) in &storevals {
        if c >= 0 && by_entry.contains_key(&(c as usize)) && !arithused.contains(&c) {
            // A printable string is normally data. Exceptions are direct-call
            // targets and menucommon_s.callback: menu items have their type at
            // base+0 and callback at base+48, so a concrete callback cell has
            // a known UI item type (1..=16) 48 bytes before it.
            let callback_cell = cell
                .and_then(|a| a.checked_sub(48))
                .and_then(|base| concrete_stores.get(&base))
                .is_some_and(|vals| vals.iter().any(|&v| (1..=16).contains(&v)));
            // A function-entry constant stored into a concrete GLOBAL cell that
            // is never used as a call argument (trap OR normal) and never as an
            // arithmetic/ordered-compare operand is a function pointer even when
            // its index numerically collides with a printable lit-segment string
            // (menuframework_s.draw = MainMenu_Draw: entry index 15744 also lands
            // inside a lit string). A genuine string initializer would show the
            // address as a call argument somewhere (it gets drawn/printed); a
            // callback that is only stored and later invoked indirectly does not.
            // Without this the pointer degrades to a data pointer (qvm_mem+off)
            // and the later `menu->draw()` indirect call jumps to garbage ->
            // "VM opStack overflow" on entering the menu.
            //
            // NOTE: this per-VALUE classification is fundamentally unable to
            // handle a value that is legitimately BOTH a real call target at
            // one instruction AND a string address at another (e.g. a ui module's
            // entry 17229 is both a directly-CALLed function AND the address
            // of the literal "NETWORK", stored as a widget's text field at
            // cell 215392 — the "NNING" text-corruption bug). Fixing that
            // requires per-instruction (not per-value) rendering in the
            // emitter, out of scope for this heuristic; see CONTEXT.md.
            let global_fnptr_store =
                is_bare && cell.is_some() && !traparg.contains(&c) && !arg_call.contains(&c);
            if !strings.contains(&c)
                || call_targets.contains(&c)
                || callback_cell
                || global_fnptr_store
            {
                fns.insert(c as usize);
            }
        }
    }
    // A function-entry constant stored into a computed per-instance
    // struct-field address (`ent->callback_field = SomeFunc`) is a genuine
    // function pointer when that same field offset is confirmed elsewhere
    // in the program to be loaded from a (different) instance and CALLed
    // indirectly (`ent->callback_field()`), even when the constant
    // numerically collides with a printable string. Without this, the
    // pointer degrades to a data address and the later indirect call jumps
    // into unrelated bytecode -> stack corruption (wild return address),
    // eventually surfacing as a spurious re-entrant GAME_INIT / "SpawnEntities:
    // no entities" many calls downstream. See CONTEXT.md addbot crash.
    for &(c, off) in &field_stores {
        if c >= 0 && by_entry.contains_key(&(c as usize)) && field_call_offsets.contains(&off) {
            fns.insert(c as usize);
        }
    }
    // Apply deferred param-forward rescues now that every callee body and
    // every LOAD4+CALL cell has been observed. See `pending_param_args`.
    for &(callee, arg_i, argval) in &pending_param_args {
        // NULL (0) is a legitimate "no callback" argument and must stay a
        // plain zero — never promote it to the rebuilt address of fn_0/vmMain
        // just because a callee forwards that parameter into a call-cell.
        if argval == 0 {
            continue;
        }
        if let Some(&cell) = param_forward.get(&(callee, arg_i)) {
            if bare_call_cells.contains(&cell) && by_entry.contains_key(&(argval as usize)) {
                fns.insert(argval as usize);
            }
        }
    }
    (fns, data, intused, arithused, traparg)
}

/// Collect the max argument count for every trap number in a function's AST.
fn collect_trap_arity(f: &Function, arity: &mut HashMap<u32, usize>) {
    let mut walk = |e: &Expr| {
        let mut st: Vec<&Expr> = vec![e];
        while let Some(x) = st.pop() {
            if let Expr::Trap(n, args) = x {
                let e = arity.entry(*n).or_insert(0);
                *e = (*e).max(args.len());
                st.extend(args.iter());
                continue;
            }
            match x {
                Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                Expr::Binop(_, a, b) => {
                    st.push(a);
                    st.push(b);
                }
                Expr::Call(t, args) => {
                    st.push(t);
                    st.extend(args.iter());
                }
                _ => {}
            }
        }
    };
    for b in &f.blocks {
        for s in b.body.iter() {
            match s {
                Stmt::Assign { value, .. } => walk(value),
                Stmt::Store { addr, value, .. } => {
                    walk(addr);
                    walk(value);
                }
                Stmt::BlockCopy { dest, src, .. } => {
                    walk(dest);
                    walk(src);
                }
            }
        }
        match &b.term {
            Terminator::Return(Some(v)) => walk(v),
            Terminator::IfGoto { cond, .. } => walk(cond),
            Terminator::Switch { sel, .. } => walk(sel),
            Terminator::Unresolved(a) => walk(a),
            _ => {}
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = &args[0];
    let out_c = &args[1];
    let out_asm = &args[2];
    let names_path = args.iter().find(|a| a.ends_with(".names")).map(|s| s.to_string());
    let sigs_path = args.iter().find(|a| a.ends_with(".sigs")).map(|s| s.to_string());
    let only: Option<HashSet<usize>> = args.iter().position(|a| a == "--only").and_then(|i| {
        args.get(i + 1).map(|s| s.split(',').filter_map(|t| t.trim().parse::<usize>().ok()).collect())
    });
    let lst_stem = args.iter().position(|a| a == "--lst").and_then(|i| args.get(i + 1).map(|s| s.to_string()));
    let wrapper = args.iter().any(|a| a == "--wrapper");
    let no_typed = args.iter().any(|a| a == "--no-typed");
    let want_typed = args.iter().any(|a| a == "--typed");

    let q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let mut em = Emitter {
        q,
        d,
        data: Vec::new(),
        ranges: Vec::new(),
        sigs: HashMap::new(),
        cname: Vec::new(),
        by_entry: HashMap::new(),
        addrtaken: HashSet::new(),
        stored_fnptrs: HashSet::new(),
        data_addrs: HashSet::new(),
        intused: HashSet::new(),
        params: HashMap::new(),
        trap_arity: HashMap::new(),
        traps: BTreeSet::new(),
        trap_cname: HashMap::new(),
        block_sizes: BTreeSet::new(),
        blob: Vec::new(),
        typed: false,
        overlay: qvm::types::OverlayMod::Game,
    };
    let d = &em.d;
    em.ranges = build_functions(d);
    em.data = em.q.data_int32();
    em.blob = em.q.data.clone();
    em.blob.extend_from_slice(&em.q.lit);
    // Generic kit: overlay is opt-in. `--no-typed` stays accepted for old scripts.
    em.typed = want_typed && !no_typed;
    em.overlay = match em.q.module {
        qvm::traps::Module::Game => qvm::types::OverlayMod::Game,
        qvm::traps::Module::CGame => qvm::types::OverlayMod::CGame,
        qvm::traps::Module::Ui => qvm::types::OverlayMod::Ui,
    };
    em.sigs = sigs_path.as_deref().map(parse_sigs).unwrap_or_default();

    // function names (fn index -> sanitized cname), de-duplicated
    let names = names_path.as_deref().map(parse_names).unwrap_or_default();
    let mut seen: HashSet<String> = HashSet::new();
    em.cname = (0..em.ranges.len())
        .map(|fi| {
            let base = match names.get(&fi) {
                Some(n) if !n.is_empty() => sanitize(n),
                _ => format!("fn_{}", em.ranges[fi].0),
            };
            let mut c = base.clone();
            let mut i = 2;
            while !seen.insert(c.clone()) {
                c = format!("{base}_{i}");
                i += 1;
            }
            c
        })
        .collect();
    for (fi, &(start, _)) in em.ranges.iter().enumerate() {
        em.by_entry.insert(start, fi);
    }
    // String/data addresses that numerically collide with a function entry
    // index must never be classified as function pointers (e.g. a ui menu
    // item text "JOIN RED" whose data address 24912 == an entry). Collect the
    // literal-segment (and data-segment printable) strings reachable from code.
    let mut string_addrs: HashSet<i32> = HashSet::new();
    for ins in &em.d.insns {
        if let qvm::Opcode::Const = ins.op {
            if let Some(v) = ins.operand {
                if v >= 0 && is_string_at(&em.q, v) {
                    string_addrs.insert(v);
                }
            }
        }
    }
    let (fns, data, intused, arithused, traparg) =
        scan_addrtaken(&em.d, &em.by_entry, em.blob.len(), &string_addrs, em.q.module);
    em.addrtaken = fns;
    em.data_addrs = data;
    em.intused = intused;
    eprintln!(
        "address-taken: {} functions, {} data addresses, {} intused",
        em.addrtaken.len(),
        em.data_addrs.len(),
        em.intused.len()
    );

    // selected functions = --only (if given) ∪ their call closure
    let mut selected: BTreeSet<usize> = BTreeSet::new();
    if let Some(set) = &only {
        let mut stack: Vec<usize> = set.iter().copied().collect();
        while let Some(fi) = stack.pop() {
            if !selected.insert(fi) {
                continue;
            }
            let (start, end) = em.ranges[fi];
            let frame = em.frame_of(fi);
            if let Some(cfg) = build_cfg(&em.d, (start, end), &em.data) {
                let f = decompile_function(&em.d, &cfg, frame, &em.data);
                let mut walk = |e: &Expr, stack: &mut Vec<usize>, by_entry: &HashMap<usize, usize>| {
                    let mut st: Vec<&Expr> = vec![e];
                    while let Some(x) = st.pop() {
                        if let Expr::Call(t, args) = x {
                            if let Expr::Const(c) = t.as_ref() {
                                if *c >= 0 {
                                    if let Some(&tf) = by_entry.get(&(*c as usize)) {
                                        stack.push(tf);
                                    }
                                }
                            }
                            st.push(t.as_ref());
                            st.extend(args.iter());
                            continue;
                        }
                        match x {
                            Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                            Expr::Binop(_, a, b) => {
                                st.push(a);
                                st.push(b);
                            }
                            Expr::Trap(_, args) => st.extend(args.iter()),
                            _ => {}
                        }
                    }
                };
                for b in &f.blocks {
                    for s in b.body.iter() {
                        match s {
                            Stmt::Assign { value, .. } => walk(value, &mut stack, &em.by_entry),
                            Stmt::Store { addr, value, .. } => {
                                walk(addr, &mut stack, &em.by_entry);
                                walk(value, &mut stack, &em.by_entry);
                            }
                            Stmt::BlockCopy { dest, src, .. } => {
                                walk(dest, &mut stack, &em.by_entry);
                                walk(src, &mut stack, &em.by_entry);
                            }
                        }
                    }
                    match &b.term {
                        Terminator::Return(Some(v)) => walk(v, &mut stack, &em.by_entry),
                        Terminator::IfGoto { cond, .. } => walk(cond, &mut stack, &em.by_entry),
                        Terminator::Switch { sel, .. } => walk(sel, &mut stack, &em.by_entry),
                        Terminator::Unresolved(a) => walk(a, &mut stack, &em.by_entry),
                        _ => {}
                    }
                }
            }
        }
    } else {
        selected = (0..em.ranges.len()).collect();
    }

    // Pre-pass: for each emitted function, compute the emitted parameter count
    // = max(sigs.args, args referenced in the body, args passed by any caller).
    // lcc rejects calls that pass more args than the callee declares, and the
    // bytecode's callers can push extra ARG words that the callee never reads.
    // Two passes: caller_args must be complete before params are computed.
    let mut caller_args: HashMap<usize, usize> = HashMap::new();
    // Indirect-call table cells: `(base, stride, nentries)` of data tables that
    // are dereferenced and CALLed (`(*(int*)(base + idx*stride))()`). Words at
    // these cells are function pointers and must be blob-relocated even when
    // their value is below blob.len() (command-dispatch tables: many handlers
    // sit at low instruction indices). `nentries` is the measured prefix, not
    // MAX_TABLE_ENTRIES — stretching the grid past the real table relocates
    // item/cvar data pointers whose values collide with function entries.
    let mut indir_cells: Vec<(usize, usize, usize)> = Vec::new();
    // Proven function-pointer VALUES: constants equal to a function ENTER that
    // code STORES into memory (menu callbacks: `item->callback = fn;`). UI
    // modules keep most functions BELOW the data+lit boundary, so those pointer
    // words look like "below-blob data" to the naive check and were never
    // relocated -- every indirect call then jumped to a stale ORIGINAL
    // instruction index inside the rebuilt module.
    let mut fptr_stored: std::collections::HashSet<i32> = std::collections::HashSet::new();
    let mut bc_ranges: Vec<(u32, u32)> = Vec::new();
    let mut fptr_slots: std::collections::HashMap<usize, i32> = std::collections::HashMap::new();
    for &fi in &selected {
        let frame = em.frame_of(fi);
        let (start, end) = em.ranges[fi];
        if let Some(cfg) = build_cfg(&em.d, (start, end), &em.data) {
            let f = decompile_function(&em.d, &cfg, frame, &em.data);
            let mut st: Vec<&Expr> = Vec::new();
            for b in &f.blocks {
                for s in &b.body {
                    match s {
                        Stmt::Assign { slot, value } => {
                            if let Expr::Const(c) = value {
                                if *c >= 0 && em.by_entry.contains_key(&(*c as usize)) {
                                    fptr_slots.insert(*slot, *c);
                                } else {
                                    fptr_slots.remove(slot);
                                }
                            } else {
                                fptr_slots.remove(slot);
                            }
                            st.push(value);
                        }
                        Stmt::Store { addr, value, .. } => {
                            st.push(addr);
                            st.push(value);
                            if let Expr::Const(c) = value {
                                if *c >= 0 && em.by_entry.contains_key(&(*c as usize)) {
                                    fptr_stored.insert(*c);
                                }
                            }
                            match value {
                                Expr::Local { off, .. } => {
                                    if let Some(&c) = fptr_slots.get(off) {
                                        fptr_stored.insert(c);
                                    }
                                }
                                Expr::Slot(sl) => {
                                    if let Some(&c) = fptr_slots.get(sl) {
                                        fptr_stored.insert(c);
                                    }
                                }
                                _ => {}
                            }
                        }
                        Stmt::BlockCopy { dest, src, count } => {
                            st.push(dest);
                            st.push(src);
                            if let (Expr::Const(a), l) = (src, count) {
                                if *a >= 0 && *l > 0 {
                                    bc_ranges.push((*a as u32, (*a + *l) as u32));
                                }
                            }
                        }
                    }
                }
                match &b.term {
                    Terminator::Return(Some(v)) => st.push(v),
                    Terminator::IfGoto { cond, .. } => st.push(cond),
                    Terminator::Switch { sel, .. } => st.push(sel),
                    Terminator::Unresolved(a) => st.push(a),
                    _ => {}
                }
            }
            while let Some(x) = st.pop() {
                if let Expr::Call(t, args) = x {
                    if let Expr::Const(c) = t.as_ref() {
                        if *c >= 0 {
                            if let Some(&tf) = em.by_entry.get(&(*c as usize)) {
                                let e = caller_args.entry(tf).or_insert(0);
                                *e = (*e).max(args.len());
                            }
                        }
                    } else {
                        // Indirect call through a data cell: the deref'd cell is
                        // a function pointer. Extract its (base, stride) so the
                        // blob words at those addresses get relocated too.
                        let mut tt = t.as_ref();
                        while let Expr::Float(inner) = tt {
                            tt = inner.as_ref();
                        }
                        if let Expr::MemRef(addr, LoadSize::I4) = tt {
                            if let Some(g) = table_cell_geoms(addr) {
                                // `table_cell_geoms` extracts (base, stride) from the
                                // address's constant sub-expressions, but it cannot
                                // tell a genuine fixed-base dispatch table from a
                                // per-struct-array FIELD OFFSET picked up because the
                                // real base is a runtime pointer (e.g.
                                // `item[i].generic.callback` -- the "268"-byte
                                // callback-field offset gets mistaken for an absolute
                                // table address). A real table's cells hold function
                                // pointers; a field-offset "table" mostly doesn't.
                                // Sample the blob at the (base, stride) geometry and
                                // require most sampled cells to be valid function
                                // entries before trusting the whole
                                // MAX_TABLE_ENTRIES-wide span for relocation.
                                let (base, stride) = g;
                                if stride % 4 == 0 && stride > 0 {
                                    let sample = 16usize;
                                    let mut hits = 0usize;
                                    let mut checked = 0usize;
                                    for k in 0..sample {
                                        let off = base + k * stride;
                                        if off + 4 > em.blob.len() {
                                            break;
                                        }
                                        let w = i32::from_le_bytes([
                                            em.blob[off],
                                            em.blob[off + 1],
                                            em.blob[off + 2],
                                            em.blob[off + 3],
                                        ]);
                                        checked += 1;
                                        if w >= 0 && em.by_entry.contains_key(&(w as usize)) {
                                            hits += 1;
                                        }
                                    }
                                    if checked > 0 && hits * 4 >= checked * 3 {
                                        let n = indir_table_len(
                                            &em.blob,
                                            &em.q,
                                            &em.by_entry,
                                            base,
                                            stride,
                                        );
                                        if n > 0 {
                                            eprintln!(
                                                "indir table base={base} stride={stride} entries={n}"
                                            );
                                            indir_cells.push((base, stride, n));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    st.push(t.as_ref());
                    st.extend(args.iter());
                    continue;
                }
                match x {
                    Expr::Unop(_, a) | Expr::MemRef(a, _) | Expr::Float(a) => st.push(a),
                    Expr::Binop(_, a, b) => {
                        st.push(a);
                        st.push(b);
                    }
                    Expr::Trap(_, args) => st.extend(args.iter()),
                    _ => {}
                }
            }
        }
    }
    for &fi in &selected {
        if let Some(cfg) = build_cfg(&em.d, em.ranges[fi], &em.data) {
            let frame = em.frame_of(fi);
            let f = decompile_function(&em.d, &cfg, frame, &em.data);
            let sig_raw = em.sigs.get(&fi).map(|s| s.args).unwrap_or(0);
            let body = body_max_arg(&f, frame).map_or(0, |k| k + 1);
            let call = caller_args.get(&fi).copied().unwrap_or(0);
            // Trust call-site arity. A huge `body` or stale `.sigs` count is a
            // leftover of mis-sized ENTER (stack buffer classified as pN).
            let sig = if sig_raw > 32 && sig_raw > call + 4 {
                eprintln!(
                    "arity ignore sig {} fn[{fi}]: sig={sig_raw} using call={call} (body={body} frame={frame})",
                    em.name_of(fi)
                );
                0
            } else {
                sig_raw
            };
            let mut n = sig.max(call);
            if body > 32 && body > n + 4 {
                eprintln!(
                    "arity ignore body {} fn[{fi}]: body={body} using {n} (sig={sig} call={call} frame={frame})",
                    em.name_of(fi)
                );
            } else {
                n = n.max(body);
            }
            em.params.insert(fi, n);
        }
    }

    // ---- emit C ----
    let mut c = String::new();
    c.push_str("/* generated by probe_emit -- DO NOT EDIT */\n");
    c.push_str("/* q3lcc -DQ3_VM -S <this file>; then q3asm with the matching syscalls.asm */\n\n");

    // function prototypes FIRST: the blob array below embeds bare function
    // names as function pointers, so every referenced symbol must be declared
    // before the array initializer.
    for &fi in &selected {
        let ret = em.ret_of(fi).to_string();
        let nparams = em.params.get(&fi).copied().unwrap_or(0);
        if nparams == 0 {
            c.push_str(&format!("{ret} {}(void);\n", em.name_of(fi)));
        } else {
            let params: Vec<String> = (0..nparams).map(|k| format!("int p{k}")).collect();
            c.push_str(&format!("{ret} {}({});\n", em.name_of(fi), params.join(", ")));
        }
    }
    c.push('\n');

    // Cover the real data+lit+bss span (plus the NULL sentinel word at VM
    // address 0), NOT the pow2 dataMask: the mask can double the array
    // (qagame 4.4 MB -> 8 MB image) and overflow q3asm's MAX_IMAGE. Memory
    // past the array is engine-zeroed BSS anyway, so semantics are unchanged.
    let span_bytes: usize = 4
        + em.q.data_length as usize
        + em.q.lit_length as usize
        + em.q.bss_length as usize;
    let blob_words_n = (span_bytes + 3) / 4;
    c.push_str("/* qvm_mem_words = original data+lit+bss, identity-mapped. Cannot become\n");
    c.push_str("   real C globals (BSS would shift and traps break). */\n");
    c.push_str(&format!("void *qvm_mem_words[{blob_words_n}] = {{\n"));
    if em.blob.len() >= 4
        && u32::from_le_bytes([em.blob[0], em.blob[1], em.blob[2], em.blob[3]]) != 0
    {
        eprintln!("WARNING: blob word 0 is non-zero; the identity mapping assumes it is the 0 NULL sentinel");
    }
    let blob_words: Vec<u32> = em
        .blob
        .chunks_exact(4)
        .skip(1)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .collect();
    // The blob stores ORIGINAL module data, and any FUNCTION POINTER inside it
    // (e.g. the G_CallSpawn spawn-func table, qsort comparators) holds an
    // ORIGINAL instruction index. Those indexes are NOT identity-mapped: the
    // rebuilt module's code layout differs, so the value must be re-resolved to
    // the rebuilt function via its C name (q3asm emits `address fn` = the new
    // insn index). Only relocate words that are provably function pointers:
    // the value is a function entry AND is never used as an int/arith operand
    // in code AND is never a trap argument. Blob literals that merely collide
    // with an entry (e.g. config value 200 == some entry) ARE used as operands
    // somewhere, so they stay raw.
    let mut blob_reloc: HashMap<u32, String> = HashMap::new();
    for (i, v) in blob_words.iter().enumerate() {
        let val = *v as i32;
        // Word's byte offset in the blob = its VM data address (blob is the
        // identity-mapped data+lit image, first 4 bytes are the NULL sentinel).
        let off = (i + 1) * 4;
        // A word is an indirect-call cell only if it sits INSIDE the dispatch
        // table's actual byte range ([base, base+stride*MAX_TABLE) -- congruence
        // mod stride alone is not enough: data far past the table (malloc arena,
        // free lists) can coincide with the stride grid and would be relocated
        // as bogus function pointers).
        let is_fptr_cell = indir_cells.iter().any(|&(base, stride, n)| {
            off >= base && off < base + stride * n && (off - base) % stride == 0
        });
        // A word whose value was proven to be stored as a function pointer
        // somewhere (menu callbacks etc.) is relocated even when the value is
        // below blob.len() -- UI modules keep most functions under the
        // data+lit boundary. Neighbor-string and arithused protections are
        // bypassed ONLY for this proven case; plain below-blob data that
        // merely collides with an entry stays untouched.
        let proven_fptr = fptr_stored.contains(&val)
            || bc_ranges.iter().any(|(a, b)| off >= *a as usize && off < *b as usize);
        let mut skip = "";
        if proven_fptr {
            // proven by a store site; skip all further exclusions
        } else if val < em.blob.len() as i32 && !is_fptr_cell {
            skip = "below-blob";
        } else if arithused.contains(&val) {
            skip = "arithused";
        } else if traparg.contains(&val) {
            skip = "traparg";
        }
        // vmCvar_t table: (bss_ptr, name_str, default_str, flags). The BSS
        // pointer can numerically equal a function ENTER (cg_debugevents @
        // 104524 == fn[464]); neighbors being lit strings prove it is data.
        // Spawn tables are (name_str, fptr, name_str, fptr) — the fptr's +8
        // is another fptr, not a string, so they still relocate.
        if skip.is_empty() && !is_fptr_cell && !proven_fptr {
            let n1 = blob_word(&em.blob, off + 4).and_then(|w| em.q.string_at(w));
            let n2 = blob_word(&em.blob, off + 8).and_then(|w| em.q.string_at(w));
            if n1.is_some() && n2.is_some() {
                skip = "string-neighbors";
            }
        }
        let fi_hit = em.by_entry.get(&(val as usize)).copied();
        if std::env::var("QVM_RELOC_DEBUG").ok().as_deref() == Some("2")
            && val >= em.blob.len() as i32
            && !is_fptr_cell
        {
            match fi_hit {
                None => eprintln!("RELOC-DBG off={off} val={val} NO-ENTRY skip={skip}"),
                Some(fi) if !selected.contains(&fi) => {
                    eprintln!("RELOC-DBG off={off} val={val} NOT-SELECTED fn[{fi}]")
                }
                _ => eprintln!("RELOC-DBG off={off} val={val} WOULD-RELOC skip={skip}"),
            }
        }
        if !skip.is_empty() {
            continue;
        }
        if let Some(fi) = fi_hit {
            if selected.contains(&fi) {
                // Key the relocation by the word OFFSET, not by its value:
                // two blob words can share a value (e.g. an entry index that is
                // also a data/string pointer) and a value-keyed map would
                // relocate every duplicate, corrupting unrelated data.
                blob_reloc.insert(off as u32, em.cname[fi].clone());
            }
        }
    }
    if !blob_reloc.is_empty() {
        eprintln!(
            "blob function-pointer relocations: {} distinct values ({} indirect-call cells)",
            blob_reloc.len(),
            indir_cells.len()
        );
    }
    for (i, v) in blob_words.iter().enumerate() {
        if i % 8 == 0 {
            c.push_str("  ");
        }
        match blob_reloc.get(&((i as u32 + 1) * 4)) {
            Some(name) => c.push_str(&format!("{name},")),
            None => c.push_str(&format!("(void*)0x{v:08x}u,")),
        }
        if i % 8 == 7 {
            c.push('\n');
        }
    }
    if blob_words.len() % 8 != 0 {
        c.push('\n');
    }
    c.push_str("};\n");
    c.push_str("#define qvm_mem ((unsigned char*)qvm_mem_words)\n\n");
    if em.typed {
        match em.overlay {
            qvm::types::OverlayMod::Game => {
                c.push_str(&qvm::types::emit_structs());
                c.push_str(&qvm::types::emit_macros());
                c.push_str(&emit_va_z_macros());
                eprintln!("typed overlay: qagame level/g_entities/g_clients");
            }
            qvm::types::OverlayMod::CGame => {
                c.push_str(&qvm::types::emit_cgame());
                c.push_str(&emit_va_z_macros());
                eprintln!("typed overlay: cgame centity_t prefix");
            }
            qvm::types::OverlayMod::Ui => {
                c.push_str(&qvm::types::emit_ui());
                c.push_str(&emit_va_z_macros());
                eprintln!("typed overlay: ui menucommon_s");
            }
        }
    }
    c.push_str("static float qvm_fbits(int x);\n");
    c.push_str("static int qvm_fbits_i(float f);\n\n");

    // trap prototypes
    c.push_str("/* syscall prototypes (symbols resolved by syscalls.asm equ entries) */\n");
    // (re)collect traps from selected functions first
    for &fi in &selected {
        let (start, end) = em.ranges[fi];
        let frame = em.frame_of(fi);
        if let Some(cfg) = build_cfg(&em.d, (start, end), &em.data) {
            let f = decompile_function(&em.d, &cfg, frame, &em.data);
            collect_traps(&f, &mut em.traps);
            collect_trap_arity(&f, &mut em.trap_arity);
            collect_block_sizes(&f, &mut em.block_sizes);
        }
    }
    // trap names must not collide with emitted function names (the module
    // ships its own memcpy/memset/qsort/etc.), so rename the trap side.
    let fn_names: HashSet<&String> = selected.iter().map(|&fi| &em.cname[fi]).collect();
    for &n in &em.traps {
        let base = match trap_name(em.q.module, n) {
            Some(s) => s.to_string(),
            None => format!("trap_{n}"),
        };
        if !fn_names.contains(&base) {
            continue;
        }
        let mut cand = format!("{base}_trap");
        let mut i = 2;
        while fn_names.contains(&cand) || em.trap_cname.values().any(|v| v == &cand) {
            cand = format!("{base}_trap{i}");
            i += 1;
        }
        eprintln!("trap {n} name {base} collides with a function; using {cand}");
        em.trap_cname.insert(n, cand);
    }
    for &n in &em.block_sizes {
        c.push_str(&format!("typedef struct {{ unsigned char b[{n}]; }} blob_{n};\n"));
    }
    if !em.block_sizes.is_empty() {
        c.push('\n');
    }
    for &n in &em.traps {
        let name = em.trap_name_c(n);
        let arity = em.trap_arity.get(&n).copied().unwrap_or(0);
        if float_trap(n) {
            let params = if arity == 0 {
                String::from("void")
            } else {
                (0..arity).map(|_| String::from("float")).collect::<Vec<_>>().join(", ")
            };
            c.push_str(&format!("float {name}({params});\n"));
        } else {
            let params = if arity == 0 {
                String::from("void")
            } else {
                (0..arity).map(|k| format!("int a{k}")).collect::<Vec<_>>().join(", ")
            };
            c.push_str(&format!("int {name}({params});\n"));
        }
    }
    c.push('\n');

    // optional vmMain wrapper referencing every emitted function, so q3asm's
    // entry-root pruning keeps the partial set (first proc in file == entry).
    if wrapper {
        c.push_str("int vmMain(int cmd, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11) {\n");
        for &fi in &selected {
            let name = em.name_of(fi).to_string();
            let nparams = em.params.get(&fi).copied().unwrap_or(0);
            if nparams == 0 {
                c.push_str(&format!("  {name}();\n"));
            } else {
                let args = (0..nparams).map(|_| "0").collect::<Vec<_>>().join(",");
                c.push_str(&format!("  {name}({args});\n"));
            }
        }
        c.push_str("  return 0;\n");
        c.push_str("}\n\n");
    }

    // ENTER-constants stored into memory (callbacks) → render as fn names.
    {
        let mut set: HashSet<i32> = HashSet::new();
        for &fi in &selected {
            let frame = em.frame_of(fi);
            let (start, end) = em.ranges[fi];
            if let Some(cfg) = build_cfg(&em.d, (start, end), &em.data) {
                let f = decompile_function(&em.d, &cfg, frame, &em.data);
                for b in &f.blocks {
                    for st in &b.body {
                        if let Stmt::Store { value: Expr::Const(cv), .. } = st {
                            if *cv >= 0
                                && em.by_entry.contains_key(&(*cv as usize))
                                && em.q.string_at(*cv).is_none()
                            {
                                set.insert(*cv);
                            }
                        }
                    }
                }
            }
        }
        em.stored_fnptrs = set;
    }

    for &fi in &selected {
        emit_function(&mut em, &mut c, fi);
    }
    c.push_str("static float qvm_fbits(int x) { union { int i; float f; } u; u.i = x; return u.f; }\n");
    c.push_str("static int qvm_fbits_i(float f) { union { int i; float f; } u; u.f = f; return u.i; }\n");

    // Compat (not a decompiler bug): a Driver Info menu Init strcpy's modern
    // GL_EXTENSIONS into a 1024-byte scratch (365972..366996) and overflows into
    // the extension-line pointer table → "read out of data segment". Original
    // The sample ui.qvm has the same unbounded strcpy. Replace with Q_strncpyz
    // (fn_76610) so rebuilt UI stays usable without engine-side truncation.
    let di_from = "fn_66367(365972, 190436)";
    let di_to = "fn_76610(365972, 190436, 1024)";
    let di_n = c.matches(di_from).count();
    if di_n > 0 {
        c = c.replace(di_from, di_to);
        eprintln!(
            "compat: DriverInfo strcpy -> Q_strncpyz(…, 1024) ×{di_n}"
        );
    }

    // Sample qagame: lcc left the spawn-spot pointer live across the
    // FL_NO_BOTS `continue` back-edge. The loop head then sees a non-NULL
    // spot and skips SelectSpawnPoint, retrying the same nobots pad forever.
    // Orig usually escapes because its first pick is bot-ok; rebuilt's rand
    // stream after GAME_INIT more often picks the nobots pad first. Clearing
    // the spot at the retry label restores the intended while(1) re-select.
    let (sp_from, sp_to) = if em.typed {
        if c.contains("L123403:\n  zero_tmp = 0;") && c.contains("#define spot_i ") {
            (
                "L123403:\n  zero_tmp = 0;",
                "L123403:\n  spot_i = 0;\n  zero_tmp = 0;",
            )
        } else {
            (
                "L123403:\n  zero_tmp = 0;",
                "L123403:\n  spot = 0;\n  zero_tmp = 0;",
            )
        }
    } else {
        (
            "L123403:\n  *(int*)&loc_0[2000] = 0;",
            "L123403:\n  *(int*)&loc_0[104] = 0;\n  *(int*)&loc_0[2000] = 0;",
        )
    };
    let sp_n = c.matches(sp_from).count();
    if sp_n > 0 {
        c = c.replace(sp_from, sp_to);
        eprintln!("compat: ClientSpawn clear spot on FL_NO_BOTS retry ×{sp_n}");
    }

    std::fs::write(out_c, c).expect("write out.c");
    eprintln!(
        "emitted {} functions to {out_c} ({} traps)",
        selected.len(),
        em.traps.len()
    );

    // ---- syscalls.asm ----
    let mut asm = String::from("code\n\n");
    for &n in &em.traps {
        let name = em.trap_name_c(n);
        asm.push_str(&format!("equ {name} {}\n", -1 - (n as i32)));
    }
    std::fs::write(out_asm, asm).expect("write syscalls.asm");
    eprintln!("wrote {out_asm}");

    if let Some(stem) = lst_stem {
        let stem = Path::new(&stem);
        let stem_name = stem.file_stem().and_then(|s| s.to_str()).unwrap_or("emit");
        let asm_name = Path::new(out_asm).file_name().and_then(|s| s.to_str()).unwrap_or("syscalls.asm").to_string();
        let c_name = Path::new(out_c).file_stem().and_then(|s| s.to_str()).unwrap_or("emit").to_string();
        let lst = format!("{asm_name}\n{c_name}.asm\n");
        let lst_path = stem.with_file_name(format!("{stem_name}.lst"));
        std::fs::write(&lst_path, lst).expect("write lst");
        eprintln!("wrote {}", lst_path.display());
    }
}
