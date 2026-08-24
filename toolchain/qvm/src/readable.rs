//! Structured C for port agents: `if`/`while` plus overlay field names.
//!
//! This is **not** q3lcc input. Identity emit stays in `probe_emit`.
//! Names follow [`crate::types`] — do not invent `pers.*` past `connected`,
//! fields in `_pad_812`, or a name for gentity word @552.

use std::collections::HashMap;

use crate::decompile::{Expr, Function, LoadSize, Stmt, Terminator};
use crate::loader::Qvm;
use crate::types::{
    OverlayMod, PtrKind, comment, overlay_ptr_field_for, scalar_macro, stride_macro,
    GCLIENTS_BASE, GCLIENTS_END, GCLIENT_SIZE, GENTITIES_BASE, GENTITIES_END, GENTITY_SIZE,
    LEVEL_BASE,
};

/// Proven gentity pointer fields (not ints). Used to print `NULL` / drop `(int)`.
const ENT_PTR_FIELDS: &[&str] = &[
    "client",
    "classname",
    "model",
    "nextTrain",
    "target",
    "team",
    "targetname",
    "targetShaderName",
    "targetShaderNewName",
    "target_ent",
    "think",
    "reached",
    "blocked",
    "touch",
    "use",
    "pain",
    "die",
    "chain",
    "enemy",
    "activator",
    "teamchain",
    "teammaster",
    "item",
];

/// Extra stack names for the first port candidate only (matches baseq3a `G_FindTeams`).
fn readable_fn_locals(fn_name: &str) -> &'static [(usize, &'static str)] {
    match fn_name {
        "G_FindTeams" => &[
            (20, "e2"),
            (24, "e"),
            (28, "j"),
            (32, "c2"),
            (36, "i"),
            (40, "c"),
        ],
        _ => &[],
    }
}

pub struct Ctx {
    overlay: OverlayMod,
    ptr_kind: HashMap<usize, PtrKind>,
    names: HashMap<usize, String>,
}

impl Ctx {
    pub fn new(f: &Function, q: &Qvm) -> Self {
        let overlay = OverlayMod::from_module(q.module);
        let mut ptr_kind = infer_ptr_kinds(f, overlay);
        let fn_name = q
            .name_for_fn(f.start)
            .map(|s| s.to_string())
            .unwrap_or_default();
        if !fn_name.is_empty() {
            crate_apply_known(&fn_name, &mut ptr_kind);
        }
        let names = local_names(&fn_name, &ptr_kind);
        Ctx {
            overlay,
            ptr_kind,
            names,
        }
    }

    pub fn fn_open(&self, f: &Function, q: &Qvm) -> String {
        let name = q
            .name_for_fn(f.start)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("fn_{}", f.start));
        format!("void {name}(void) {{\n")
    }

    pub fn expr(&self, f: &Function, q: &Qvm, e: &Expr) -> String {
        self.expr_prec(f, q, e, 0)
    }

    pub fn store_lhs(&self, f: &Function, q: &Qvm, addr: &Expr, size: LoadSize) -> String {
        if let Some(s) = self.field_access(f, q, addr, true) {
            return s;
        }
        match addr {
            Expr::AddrLocal(off) => match size {
                LoadSize::I4 => self.local_name(f.frame, *off),
                LoadSize::I1 => format!("(*(uchar*)&({}))", self.local_name(f.frame, *off)),
                LoadSize::I2 => format!("(*(ushort*)&({}))", self.local_name(f.frame, *off)),
            },
            _ => format!("*({}*)({})", size.ty(), self.expr(f, q, addr)),
        }
    }

    fn expr_prec(&self, f: &Function, q: &Qvm, e: &Expr, parent: i32) -> String {
        match e {
            Expr::Const(c) => self.fmt_const(q, *c),
            Expr::FConst(x) => format!("{x:?}f"),
            Expr::Slot(s) => format!("s{s}"),
            Expr::Local { off, size } => {
                let n = self.local_name(f.frame, *off);
                match size {
                    LoadSize::I4 => n,
                    LoadSize::I1 => format!("(uchar){n}"),
                    LoadSize::I2 => format!("(ushort){n}"),
                }
            }
            Expr::AddrLocal(off) => format!("&{}", self.local_name(f.frame, *off)),
            Expr::GlobalRef { addr, size } => self.mem_cell(q, *addr, *size),
            Expr::MemRef(a, size) => {
                if let Some(s) = self.field_access(f, q, a, false) {
                    return s;
                }
                format!("*({}*)({})", size.ty(), self.expr(f, q, a))
            }
            Expr::Unop(op, a) => {
                if *op == "(int)" {
                    format!("(int)({})", self.expr(f, q, a))
                } else {
                    format!("({op}{})", self.expr_prec(f, q, a, 13))
                }
            }
            Expr::Binop(op, a, b) => {
                let (op, ucast) = crate::decompile::split_uop(op);
                if ucast {
                    return format!(
                        "((unsigned)({})) {op} ((unsigned)({}))",
                        self.expr(f, q, a),
                        self.expr(f, q, b)
                    );
                }
                if let Some(s) = self.fmt_add(f, q, a, b) {
                    return s;
                }
                if let Some(s) = self.fmt_bit_flag(f, q, op, a, b) {
                    return s;
                }
                let prec = binop_prec(op);
                let s = format!(
                    "{} {op} {}",
                    self.expr_prec(f, q, a, prec),
                    self.expr_prec(f, q, b, prec + 1)
                );
                if prec < parent {
                    format!("({s})")
                } else {
                    s
                }
            }
            Expr::Call(t, args) => {
                let name = match t.as_ref() {
                    Expr::Const(c) => match q.name_for_fn(*c as usize) {
                        Some(n) => n.to_string(),
                        None => format!("fn_{c}"),
                    },
                    t => self.expr(f, q, t),
                };
                let args: Vec<String> = args.iter().map(|a| self.expr(f, q, a)).collect();
                format!("{name}({})", args.join(", "))
            }
            Expr::Trap(n, args) => {
                let args: Vec<String> = args.iter().map(|a| self.expr(f, q, a)).collect();
                match crate::traps::trap_name(q.module, *n) {
                    Some(name) => format!("{name}({})", args.join(", ")),
                    None => format!("trap_{n}({})", args.join(", ")),
                }
            }
            Expr::Float(a) => self.expr(f, q, a),
        }
    }

    fn fmt_add(&self, f: &Function, q: &Qvm, a: &Expr, b: &Expr) -> Option<String> {
        let (base, n) = match (a, b) {
            (Expr::Const(n), x) | (x, Expr::Const(n)) => (x, *n),
            _ => return None,
        };
        if let Some(m) = stride_macro(n) {
            if n == GENTITY_SIZE as i32 {
                if self.local_kind(base).is_some_and(|k| k == PtrKind::Entity) {
                    return Some(format!("{} + 1", self.expr(f, q, base)));
                }
            }
            return Some(format!("{} + {m}", self.expr(f, q, base)));
        }
        if let Some((_, field)) = self.field_of(base, n) {
            // address of a field: `(int)&e->team`
            return Some(format!("(int)&{}->{}", self.ptr_expr(f, q, base), field));
        }
        None
    }

    fn fmt_bit_flag(&self, f: &Function, q: &Qvm, op: &str, a: &Expr, b: &Expr) -> Option<String> {
        if op != "&" && op != "|" {
            return None;
        }
        let (field_e, n) = match (a, b) {
            (e, Expr::Const(n)) | (Expr::Const(n), e) => (e, *n),
            _ => return None,
        };
        let flag = flag_name(n)?;
        let lhs = if let Expr::MemRef(addr, _) = field_e {
            self.field_access(f, q, addr, false)
                .unwrap_or_else(|| self.expr(f, q, field_e))
        } else {
            self.expr(f, q, field_e)
        };
        Some(format!("({lhs} {op} {flag})"))
    }

    fn field_access(&self, f: &Function, q: &Qvm, addr: &Expr, _lhs: bool) -> Option<String> {
        match addr {
            Expr::Const(c) => Some(self.mem_cell(q, *c as usize, LoadSize::I4)),
            Expr::GlobalRef { addr, size } => Some(self.mem_cell(q, *addr, *size)),
            _ => {
                if let Some((base, n)) = split_add(addr) {
                    let (_, field) = self.field_of(base, n)?;
                    Some(format!("{}->{field}", self.ptr_expr(f, q, base)))
                } else {
                    None
                }
            }
        }
    }

    fn field_of(&self, base: &Expr, n: i32) -> Option<(&'static str, String)> {
        let kind = self.local_kind(base);
        overlay_ptr_field_for(self.overlay, kind, n)
    }

    fn local_kind(&self, e: &Expr) -> Option<PtrKind> {
        match e {
            Expr::Local { off, .. } | Expr::AddrLocal(off) => self.ptr_kind.get(off).copied(),
            _ => None,
        }
    }

    fn ptr_expr(&self, f: &Function, q: &Qvm, e: &Expr) -> String {
        match e {
            Expr::Local { off, .. } => self.local_name(f.frame, *off),
            _ => format!("((gentity_t*)({}))", self.expr(f, q, e)),
        }
    }

    fn local_name(&self, frame: i32, off: usize) -> String {
        if let Some(n) = self.names.get(&off) {
            return n.clone();
        }
        stack_name(frame, off)
    }

    fn fmt_const(&self, q: &Qvm, c: i32) -> String {
        if let Some(s) = q.string_at(c) {
            return quote_c(&s);
        }
        if let Some(m) = stride_macro(c) {
            return m.to_string();
        }
        if self.overlay == OverlayMod::Game {
            if let Some(s) = entity_addr(c) {
                return s;
            }
            if let Some(s) = client_addr(c) {
                return s;
            }
            if c == LEVEL_BASE as i32 {
                return "(int)&level".into();
            }
        }
        if let Some(name) = scalar_macro(c as usize) {
            return format!("(int)&{}", name.replacen('_', ".", 1));
        }
        if let Some(s) = comment(c as usize) {
            if s.starts_with("g_entities[") || s.starts_with("g_clients[") || s.starts_with("level.")
            {
                return format!("(int)&{s}");
            }
        }
        if let Some(f) = flag_name(c) {
            return f.to_string();
        }
        c.to_string()
    }

    fn mem_cell(&self, q: &Qvm, addr: usize, size: LoadSize) -> String {
        if let Some(name) = scalar_macro(addr) {
            return name.replacen('_', ".", 1);
        }
        if let Some(s) = comment(addr) {
            return s;
        }
        let dl = q.data_length as usize;
        let ll = q.lit_length as usize;
        if addr < dl {
            match size {
                LoadSize::I4 if addr % 4 == 0 => format!("data_i32[{}]", addr / 4),
                LoadSize::I2 if addr % 2 == 0 => format!("data_i16[{}]", addr / 2),
                _ => format!("data_i8[{addr}]"),
            }
        } else if addr < dl + ll {
            format!("lit_i8[{}]", addr - dl)
        } else {
            format!("*({}*)(0x{addr:x})", size.ty())
        }
    }
}

fn flag_name(n: i32) -> Option<&'static str> {
    match n {
        0x00000400 => Some("FL_TEAMSLAVE"),
        _ => None,
    }
}

fn entity_addr(c: i32) -> Option<String> {
    if c < 0 || GENTITY_SIZE == 0 {
        return None;
    }
    let u = c as usize;
    if u >= GENTITIES_BASE && u < GENTITIES_END && (u - GENTITIES_BASE) % GENTITY_SIZE == 0 {
        let i = (u - GENTITIES_BASE) / GENTITY_SIZE;
        return Some(format!("&g_entities[{i}]"));
    }
    None
}

fn client_addr(c: i32) -> Option<String> {
    if c < 0 || GCLIENT_SIZE == 0 {
        return None;
    }
    let u = c as usize;
    if u >= GCLIENTS_BASE && u < GCLIENTS_END && (u - GCLIENTS_BASE) % GCLIENT_SIZE == 0 {
        let i = (u - GCLIENTS_BASE) / GCLIENT_SIZE;
        return Some(format!("&g_clients[{i}]"));
    }
    None
}

fn split_add(e: &Expr) -> Option<(&Expr, i32)> {
    match e {
        Expr::Binop("+", a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Const(n), x) | (x, Expr::Const(n)) => Some((x, *n)),
            _ => None,
        },
        _ => None,
    }
}

fn binop_prec(op: &str) -> i32 {
    match op {
        "*" | "/" | "%" => 12,
        "+" | "-" => 11,
        "<<" | ">>" => 10,
        "<" | ">" | "<=" | ">=" => 9,
        "==" | "!=" => 8,
        "&" => 7,
        "^" => 6,
        "|" => 5,
        _ => 4,
    }
}

fn quote_c(s: &str) -> String {
    let esc = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('\r', "\\r");
    format!("\"{esc}\"")
}

fn stack_name(frame: i32, off: usize) -> String {
    let f = frame as usize;
    if off < f {
        format!("loc_{off}")
    } else if off >= f + 8 && (off - f - 8) % 4 == 0 {
        format!("arg_{}", (off - f - 8) / 4)
    } else {
        format!("sp_{off}")
    }
}

fn crate_apply_known(fn_name: &str, kind: &mut HashMap<usize, PtrKind>) {
    for &(off, name) in crate::types::fn_local_slots(fn_name) {
        let k = match name {
            "spot" | "ent" | "e" | "e2" => PtrKind::Entity,
            "gcl" | "targ_client" | "cl" => PtrKind::Client,
            _ => continue,
        };
        kind.insert(off, k);
    }
    for &(off, name) in readable_fn_locals(fn_name) {
        let k = match name {
            "e" | "e2" | "ent" => PtrKind::Entity,
            _ => continue,
        };
        kind.insert(off, k);
    }
}

fn local_names(
    fn_name: &str,
    ptr_kind: &HashMap<usize, PtrKind>,
) -> HashMap<usize, String> {
    let mut out: HashMap<usize, String> = HashMap::new();
    let mut taken: std::collections::HashSet<String> = std::collections::HashSet::new();
    for &(off, name) in crate::types::fn_local_slots(fn_name) {
        out.insert(off, name.to_string());
        taken.insert(name.to_string());
    }
    for &(off, name) in readable_fn_locals(fn_name) {
        out.insert(off, name.to_string());
        taken.insert(name.to_string());
    }
    let mut ents: Vec<usize> = ptr_kind
        .iter()
        .filter(|(off, k)| **k == PtrKind::Entity && !out.contains_key(*off))
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
        .filter(|(off, k)| **k == PtrKind::Client && !out.contains_key(*off))
        .map(|(off, _)| *off)
        .collect();
    cls.sort();
    for off in cls.iter().copied() {
        let name = if cls.len() == 1 && !taken.contains("cl") {
            "cl".into()
        } else {
            format!("cl_{off}")
        };
        taken.insert(name.clone());
        out.insert(off, name);
    }
    out
}

fn add_const_eq(e: &Expr, n: i32) -> bool {
    match e {
        Expr::Binop("+", a, b) => matches!(
            (a.as_ref(), b.as_ref()),
            (Expr::Const(c), _) | (_, Expr::Const(c)) if *c == n
        ),
        _ => false,
    }
}

fn infer_ptr_kinds(f: &Function, overlay: OverlayMod) -> HashMap<usize, PtrKind> {
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

    let walk = |e: &Expr, kind: &mut HashMap<usize, PtrKind>| {
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
                                || matches!(u, 424 | 516 | 520 | 524 | 528 | 532 | 536 | 656 | 660 | 780 | 784 | 808 | 820)
                            {
                                mark(kind, off, PtrKind::Entity);
                            } else if n == GCLIENT_SIZE as i32 || matches!(u, 468 | 944) {
                                mark(kind, off, PtrKind::Client);
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
                    st.push(t);
                    st.extend(args.iter());
                }
                Expr::Trap(_, args) => st.extend(args.iter()),
                _ => {}
            }
        }
    };

    for _ in 0..3 {
        for b in &f.blocks {
            for s in &b.body {
                match s {
                    Stmt::Assign { value, .. } => walk(value, &mut kind),
                    Stmt::Store { addr, value, .. } => {
                        if let Expr::AddrLocal(dst) = addr {
                            match value {
                                Expr::MemRef(inner, _)
                                    if overlay == OverlayMod::Game && add_const_eq(inner, 516) =>
                                {
                                    mark(&mut kind, *dst, PtrKind::Client);
                                }
                                Expr::Binop("+", _, _)
                                    if overlay == OverlayMod::Game
                                        && add_const_eq(value, GENTITY_SIZE as i32) =>
                                {
                                    mark(&mut kind, *dst, PtrKind::Entity);
                                }
                                Expr::Local { off, .. } => {
                                    if let Some(k) = kind.get(off).copied() {
                                        mark(&mut kind, *dst, k);
                                    }
                                }
                                Expr::GlobalRef { addr, .. }
                                    if overlay == OverlayMod::Game && *addr == LEVEL_BASE =>
                                {
                                    mark(&mut kind, *dst, PtrKind::Entity);
                                }
                                Expr::Const(n)
                                    if overlay == OverlayMod::Game
                                        && entity_addr(*n).is_some() =>
                                {
                                    mark(&mut kind, *dst, PtrKind::Entity);
                                }
                                Expr::Const(n)
                                    if overlay == OverlayMod::Game
                                        && *n == GCLIENTS_BASE as i32 =>
                                {
                                    mark(&mut kind, *dst, PtrKind::Client);
                                }
                                _ => {}
                            }
                        }
                        walk(addr, &mut kind);
                        walk(value, &mut kind);
                    }
                    Stmt::BlockCopy { dest, src, .. } => {
                        walk(dest, &mut kind);
                        walk(src, &mut kind);
                    }
                }
            }
            match &b.term {
                Terminator::Return(Some(v)) => walk(v, &mut kind),
                Terminator::IfGoto { cond, .. } => walk(cond, &mut kind),
                Terminator::Switch { sel, .. } => walk(sel, &mut kind),
                Terminator::Unresolved(a) => walk(a, &mut kind),
                _ => {}
            }
        }
    }
    kind
}

/// RHS of a store: pointer locals stay uncast; `0` on pointer fields becomes `NULL`.
pub fn store_rhs(ctx: &Ctx, f: &Function, q: &Qvm, addr: &Expr, value: &Expr) -> String {
    let field = ctx.field_access(f, q, addr, true);
    let ptr_field = field
        .as_ref()
        .and_then(|s| s.rsplit("->").next())
        .is_some_and(|f| ENT_PTR_FIELDS.contains(&f));
    match value {
        Expr::Const(0) if ptr_field => "NULL".into(),
        Expr::Local { off, .. } if ctx.ptr_kind.get(off).is_some() => {
            ctx.local_name(f.frame, *off)
        }
        Expr::Const(_) if ptr_field => ctx.expr(f, q, value),
        _ => ctx.expr(f, q, value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfilled_key_classifies_nothing() {
        // Template ships with an empty data-space key: array addresses stay
        // unnamed until types.rs is filled for the module under analysis.
        assert_eq!(entity_addr(221_056), None);
        assert_eq!(client_addr(116_952), None);
    }

    #[test]
    fn teamslave_flag() {
        assert_eq!(flag_name(1024), Some("FL_TEAMSLAVE"));
    }
}
