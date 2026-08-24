//! Structured control-flow reconstruction.
//!
//! The lowered function is a set of basic blocks whose terminators are
//! `goto` / `if (cond) goto` / `switch` / `return`. This module rebuilds the
//! original structured nesting (if / if-else / while / do-while) using
//! post-dominators (the merge point of a conditional) and dominators
//! (loop detection). `goto` remains only for the rare irreducible shapes.
//!
//! The algorithm is recursive: `structure(entry, stop)` emits the blocks
//! reachable from `entry` without crossing `stop`, recognizing at each step:
//!
//! - loop headers (a block with a back edge): the header test is emitted as
//!   `while`, or as `do { .. } while` when the test sits at the bottom;
//! - conditional blocks: the immediate post-dominator is the merge point, so
//!   the two successor regions become `if (cond) { .. } else { .. }`;
//! - `switch` terminators: case bodies are inlined, the default target is
//!   emitted right after the switch.
//!
//! Everything else is kept as a residual `goto`.

use std::collections::{HashMap, HashSet};

use crate::decompile::{Expr, Function, LoweredBlock, Stmt, Terminator};

/// Virtual function-exit node. Larger than any real block index.
const EXIT: usize = usize::MAX;

/// A structured statement.
#[derive(Debug, Clone)]
pub enum Elem {
    /// Straight-line block `idx` (its body statements).
    Block {
        idx: usize,
        body: Vec<Stmt>,
    },
    If {
        cond: Expr,
        then: Vec<Elem>,
        else_: Vec<Elem>,
    },
    While {
        cond: Expr,
        body: Vec<Elem>,
    },
    DoWhile {
        cond: Expr,
        body: Vec<Elem>,
    },
    Return(Option<Expr>),
    /// Residual unstructured jump.
    Goto(usize),
    /// Residual conditional jump.
    IfGoto {
        cond: Expr,
        target: usize,
    },
    /// Resolved jump table with per-case structured bodies.
    Switch {
        sel: Expr,
        /// Each entry: the case values sharing one target + what to emit.
        cases: Vec<(Vec<i32>, CaseKind)>,
        /// Default case body (from the bounds checks), when it can be inlined.
        /// `None` means "no default" or "default handled after the switch".
        default: Option<CaseKind>,
    },
    /// Indirect jump that could not be resolved statically.
    Unresolved(Expr),
}

/// What to emit for a group of switch cases.
#[derive(Debug, Clone)]
pub enum CaseKind {
    /// Structured body; `break_` says whether a trailing `break;` is needed.
    /// `also_default` merges the bounds-check default into this case's label
    /// (`case N: default:`) because the default target equals this target.
    Inline {
        body: Vec<Elem>,
        break_: bool,
        also_default: bool,
    },
    /// The target block could not be inlined; jump to its label.
    Goto(usize),
}

enum LoopKind {
    While {
        cond: Expr,
        body_entry: usize,
        exit: usize,
    },
    DoWhile {
        cond: Expr,
        test: usize,
    },
}

/// Structuring state: block graph, dominators, post-dominators.
pub struct Structure {
    n: usize,
    terms: Vec<Terminator>,
    bodies: Vec<Vec<Stmt>>,
    starts: Vec<usize>,
    by_start: HashMap<usize, usize>,
    pred: Vec<Vec<usize>>,
    dom: Vec<HashSet<usize>>,
    /// Post-dominator of each node; index `n` is the virtual exit.
    ipdom: Vec<usize>,
    emitted: Vec<bool>,
    /// Set while emitting a do-while body to keep its header from being
    /// re-detected as a loop header inside `structure(header, test)`.
    dowhile_guard: Option<usize>,
}

impl Structure {
    /// Build the graph, dominators and post-dominators for a lowered function.
    pub fn new(f: &Function) -> Structure {
        let n = f.blocks.len();
        let mut starts = Vec::with_capacity(n);
        let mut terms = Vec::with_capacity(n);
        let mut bodies = Vec::with_capacity(n);
        let mut by_start = HashMap::with_capacity(n);
        for (i, b) in f.blocks.iter().enumerate() {
            starts.push(b.start);
            by_start.insert(b.start, i);
            terms.push(b.term.clone());
            bodies.push(b.body.clone());
        }

        // ---- successors (index n = virtual exit) ----
        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
        for i in 0..n {
            let mut edge = |t: usize| {
                succ[i].push(t);
                pred[t].push(i);
            };
            match &terms[i] {
                Terminator::Return(_) | Terminator::Unresolved(_) => edge(n),
                Terminator::Goto(t) => {
                    if let Some(&d) = by_start.get(t) {
                        edge(d);
                    } else {
                        edge(n);
                    }
                }
                Terminator::IfGoto { target, .. } => {
                    if let Some(&d) = by_start.get(target) {
                        edge(d);
                    }
                    if i + 1 < n {
                        edge(i + 1);
                    } else {
                        edge(n);
                    }
                }
                Terminator::Switch { cases, .. } => {
                    let mut targets: HashSet<usize> = HashSet::new();
                    for (_, t) in cases {
                        if let Some(&d) = by_start.get(t) {
                            targets.insert(d);
                        }
                    }
                    if let Some(d) = switch_default_block(cases, &by_start) {
                        targets.insert(d);
                    }
                    if targets.is_empty() {
                        edge(n);
                    }
                    for d in targets {
                        edge(d);
                    }
                }
                Terminator::Fallthrough => {
                    if i + 1 < n {
                        edge(i + 1);
                    } else {
                        edge(n);
                    }
                }
            }
        }

        // ---- dominators ----
        let mut dom: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        if n > 0 {
            dom[0].insert(0);
            for i in 1..n {
                dom[i] = (0..n).collect();
            }
            let mut changed = true;
            while changed {
                changed = false;
                for i in 1..n {
                    if pred[i].is_empty() {
                        continue;
                    }
                    let mut new: HashSet<usize> = pred[i][0]
                        .checked_sub(0)
                        .map(|_| dom[pred[i][0]].clone())
                        .unwrap_or_default();
                    for &p in &pred[i][1..] {
                        new = new.intersection(&dom[p]).copied().collect();
                    }
                    new.insert(i);
                    if new != dom[i] {
                        dom[i] = new;
                        changed = true;
                    }
                }
            }
        }

        // ---- post-dominators (graph includes the virtual exit) ----
        let nn = n + 1;
        let mut pdom: Vec<HashSet<usize>> = vec![(0..nn).collect(); nn];
        pdom[n].clear();
        pdom[n].insert(n);
        let mut changed = true;
        while changed {
            changed = false;
            for b in 0..n {
                let mut new: HashSet<usize> = HashSet::new();
                if succ[b].is_empty() {
                    new.insert(b);
                    new.insert(n);
                } else {
                    let mut first = true;
                    for &s in &succ[b] {
                        if first {
                            new = pdom[s].clone();
                            first = false;
                        } else {
                            new = new.intersection(&pdom[s]).copied().collect();
                        }
                    }
                    new.insert(b);
                }
                if new != pdom[b] {
                    pdom[b] = new;
                    changed = true;
                }
            }
        }

        // ---- immediate post-dominator ----
        // The ipdom of `b` is the proper post-dominator with the largest
        // post-dom set (the nearest common post-dominator of all paths).
        let mut ipdom = vec![n; nn];
        for b in 0..n {
            // The ipdom of `b` is the proper post-dominator with the largest
            // post-dom set (the nearest common post-dominator of all paths).
            let mut best: Option<usize> = None;
            let mut best_size = 0;
            for &c in &pdom[b] {
                if c == b {
                    continue;
                }
                let sz = pdom[c].len();
                if best.is_none() || sz > best_size {
                    best = Some(c);
                    best_size = sz;
                }
            }
            if let Some(c) = best {
                ipdom[b] = c;
            } else {
                ipdom[b] = n;
            }
        }

        Structure {
            n,
            terms,
            bodies,
            starts,
            by_start,
            pred,
            dom,
            ipdom,
            emitted: vec![false; n],
            dowhile_guard: None,
        }
    }

    fn dominates(&self, a: usize, b: usize) -> bool {
        self.dom[b].contains(&a)
    }

    /// The natural loop set of loop header `h`.
    fn natural_loop(&self, h: usize) -> HashSet<usize> {
        let mut set = HashSet::from([h]);
        for &p in &self.pred[h] {
            if p >= self.n || !self.dominates(h, p) {
                continue;
            }
            let mut stack = vec![p];
            while let Some(w) = stack.pop() {
                if w != h && set.insert(w) {
                    for &pp in &self.pred[w] {
                        if pp != h && pp < self.n {
                            stack.push(pp);
                        }
                    }
                }
            }
        }
        set
    }

    fn loop_kind(&self, cur: usize) -> Option<LoopKind> {
        let is_header = self.pred[cur]
            .iter()
            .any(|&p| p < self.n && self.dominates(cur, p));
        if !is_header {
            return None;
        }
        match &self.terms[cur] {
            Terminator::IfGoto { cond, target } => {
                let t = self.by_start.get(target).copied()?;
                if cur + 1 >= self.n {
                    return None;
                }
                let f = cur + 1;
                let ls = self.natural_loop(cur);
                if ls.contains(&t) && !ls.contains(&f) {
                    Some(LoopKind::While {
                        cond: cond.clone(),
                        body_entry: t,
                        exit: f,
                    })
                } else if ls.contains(&f) && !ls.contains(&t) {
                    Some(LoopKind::While {
                        cond: negate_cond(cond),
                        body_entry: f,
                        exit: t,
                    })
                } else {
                    None
                }
            }
            _ => {
                if self.dowhile_guard == Some(cur) {
                    return None;
                }
                let ls = self.natural_loop(cur);
                for &p in &self.pred[cur] {
                    if p >= self.n || !self.dominates(cur, p) || !ls.contains(&p) {
                        continue;
                    }
                    if let Terminator::IfGoto { cond, target } = &self.terms[p] {
                        if self.by_start.get(target).copied() == Some(cur) {
                            return Some(LoopKind::DoWhile {
                                cond: cond.clone(),
                                test: p,
                            });
                        }
                    }
                }
                None
            }
        }
    }

    /// Recursively emit the structured statements for the region starting at
    /// `entry` and ending at `stop` (EXIT = function end).
    pub fn structure(&mut self, entry: usize, stop: usize) -> Vec<Elem> {
        let mut out = Vec::new();
        let mut cur = entry;
        while cur < self.n && cur != stop && !self.emitted[cur] {
            if let Some(lk) = self.loop_kind(cur) {
                match lk {
                    LoopKind::While {
                        cond,
                        body_entry,
                        exit,
                    } => {
                        let hdr = self.bodies[cur].clone();
                        self.emitted[cur] = true;
                        let body = self.structure(body_entry, cur);
                        if !hdr.is_empty() {
                            out.push(Elem::Block {
                                idx: cur,
                                body: hdr,
                            });
                        }
                        out.push(Elem::While { cond, body });
                        cur = exit;
                        continue;
                    }
                    LoopKind::DoWhile { cond, test } => {
                        let old = self.dowhile_guard;
                        self.dowhile_guard = Some(cur);
                        let body = self.structure(cur, test);
                        self.dowhile_guard = old;
                        self.emitted[cur] = true;
                        self.emitted[test] = true;
                        out.push(Elem::DoWhile { cond, body });
                        cur = if test + 1 < self.n { test + 1 } else { EXIT };
                        continue;
                    }
                }
            }
            if !self.bodies[cur].is_empty() {
                out.push(Elem::Block {
                    idx: cur,
                    body: self.bodies[cur].clone(),
                });
            }
            let term = self.terms[cur].clone();
            match term {
                Terminator::Return(v) => {
                    self.emitted[cur] = true;
                    out.push(Elem::Return(v));
                    break;
                }
                Terminator::Goto(t) => {
                    self.emitted[cur] = true;
                    let nb = self.by_start.get(&t).copied().unwrap_or(EXIT);
                    if nb == stop || nb == cur {
                        break;
                    }
                    cur = nb;
                    continue;
                }
                Terminator::IfGoto { cond, target } => {
                    let merge = if self.ipdom[cur] == self.n {
                        EXIT
                    } else {
                        self.ipdom[cur]
                    };
                    let then_entry = self.by_start.get(&target).copied().unwrap_or(EXIT);
                    let else_entry = cur + 1;
                    // Edges that would re-enter the enclosing region (loop
                    // header = `stop`, the block itself, or a block that
                    // already ran) must stay as residual conditional gotos.
                    let then_back = then_entry == cur || (then_entry == stop && stop != merge);
                    let else_back = else_entry == stop && stop != merge;
                    if then_back || else_back {
                        self.emitted[cur] = true;
                        out.push(Elem::IfGoto { cond, target });
                        if then_back && else_entry < self.n {
                            cur = else_entry;
                            continue;
                        }
                        break;
                    }
                    if then_entry < self.n && else_entry < self.n && merge != self.n {
                        self.emitted[cur] = true;
                        let then_src = self.structure(then_entry, merge);
                        let else_src = if else_entry == then_entry {
                            Vec::new()
                        } else {
                            self.structure(else_entry, merge)
                        };
                        if !(then_src.is_empty() && else_src.is_empty()) {
                            if else_src.is_empty() {
                                out.push(Elem::If {
                                    cond,
                                    then: then_src,
                                    else_: Vec::new(),
                                });
                            } else if then_src.is_empty() {
                                out.push(Elem::If {
                                    cond: negate_cond(&cond),
                                    then: else_src,
                                    else_: Vec::new(),
                                });
                            } else {
                                out.push(Elem::If {
                                    cond,
                                    then: then_src,
                                    else_: else_src,
                                });
                            }
                        }
                        cur = merge;
                        continue;
                    }
                    // degenerate shape: keep the conditional jump
                    self.emitted[cur] = true;
                    out.push(Elem::IfGoto { cond, target });
                    if else_entry < self.n {
                        cur = else_entry;
                        continue;
                    }
                    break;
                }
                Terminator::Switch {
                    sel,
                    cases,
                    default,
                } => {
                    let (sw, def) = self.emit_switch(cur, *sel, &cases, default);
                    self.emitted[cur] = true;
                    out.push(sw);
                    cur = def.unwrap_or(EXIT);
                    continue;
                }
                Terminator::Unresolved(a) => {
                    self.emitted[cur] = true;
                    out.push(Elem::Unresolved(a));
                    break;
                }
                Terminator::Fallthrough => {
                    self.emitted[cur] = true;
                    let nb = cur + 1;
                    if nb >= self.n || nb == stop {
                        break;
                    }
                    cur = nb;
                    continue;
                }
            }
        }
        out
    }

    fn emit_switch(
        &mut self,
        cur: usize,
        sel: Expr,
        cases: &[(i32, usize)],
        bounds_default: Option<usize>,
    ) -> (Elem, Option<usize>) {
        let default = switch_default_block(cases, &self.by_start);

        // Common exit of all case bodies: the single block every case target
        // jumps to. If all cases share one exit (a switch epilogue), each case
        // is structured with that block as its stop so it becomes `break;`,
        // and the epilogue is emitted after the switch instead of being
        // absorbed into the first case.
        let mut case_exits: Vec<usize> = Vec::new();
        for (_, t) in cases {
            if let Some(&b) = self.by_start.get(t) {
                if let Terminator::Goto(g) = &self.terms[b] {
                    if let Some(&gb) = self.by_start.get(g) {
                        case_exits.push(gb);
                    }
                }
            }
        }
        let merge = if !case_exits.is_empty() && case_exits.iter().all(|&x| x == case_exits[0]) {
            let m = case_exits[0];
            if default != Some(m) {
                Some(m)
            } else {
                None
            }
        } else {
            None
        };
        let stop = merge.or(bounds_default).unwrap_or(EXIT);

        // group consecutive cases that share a target
        let mut groups: Vec<(Vec<i32>, usize)> = Vec::new();
        for (v, t) in cases {
            match groups.last_mut() {
                Some((vs, gt)) if *gt == *t => vs.push(*v),
                _ => groups.push((vec![*v], *t)),
            }
        }

        let mut out_cases = Vec::new();
        let mut bound_group_inlined = false;
        for (vs, t) in groups {
            let b = self.by_start.get(&t).copied();
            match b {
                None => out_cases.push((vs, CaseKind::Goto(t))),
                Some(b) if default == Some(b) => {
                    // default body is emitted right after the switch
                    out_cases.push((vs, CaseKind::Goto(t)));
                }
                Some(b) if self.emitted[b] => out_cases.push((vs, CaseKind::Goto(t))),
                Some(b) => {
                    let body = self.structure(b, stop);
                    let needs_break = !matches!(
                        body.last(),
                        Some(Elem::Return(_))
                            | Some(Elem::Goto(_))
                            | Some(Elem::IfGoto { .. })
                            | Some(Elem::Switch { .. })
                            | Some(Elem::Unresolved(_))
                    );
                    let also_default = bounds_default == Some(t);
                    if also_default {
                        bound_group_inlined = true;
                    }
                    out_cases.push((
                        vs,
                        CaseKind::Inline {
                            body,
                            break_: needs_break,
                            also_default,
                        },
                    ));
                }
            }
        }

        // The bounds-default block (from the LTI/GTI checks) becomes an
        // inlined `default:` case, unless it already is the post-switch merge
        // or one of the case targets (then it is merged into that case).
        let mut continue_at = merge;
        let out_default = if bound_group_inlined {
            None
        } else {
            match bounds_default {
                None => None,
                Some(b) => match self.by_start.get(&b).copied() {
                    None => Some(CaseKind::Goto(b)),
                    Some(dbi) if self.emitted[dbi] => Some(CaseKind::Goto(b)),
                    Some(dbi) if merge == Some(dbi) => None,
                    Some(dbi) if default == Some(dbi) => None,
                    Some(dbi) => {
                        let body = self.structure(dbi, stop);
                        let needs_break = !matches!(
                            body.last(),
                            Some(Elem::Return(_))
                                | Some(Elem::Goto(_))
                                | Some(Elem::IfGoto { .. })
                                | Some(Elem::Switch { .. })
                                | Some(Elem::Unresolved(_))
                        );
                        continue_at = merge.or(bounds_default);
                        Some(CaseKind::Inline {
                            body,
                            break_: needs_break,
                            also_default: false,
                        })
                    }
                },
            }
        };
        let _ = cur;

        (
            Elem::Switch {
                sel,
                cases: out_cases,
                default: out_default,
            },
            continue_at,
        )
    }

    /// Blocks not emitted by the structuring recursion (dead after structure
    /// or fallback tails). Printed last, always labeled.
    pub fn leftover(&self) -> Vec<usize> {
        (0..self.n).filter(|&i| !self.emitted[i]).collect()
    }

    /// Block index for an instruction offset (`None` if not a block start).
    pub fn block_index(&self, start: usize) -> Option<usize> {
        self.by_start.get(&start).copied()
    }
}

/// The in-table default block of a switch: the target that occurs most often
/// (>= 2), the shared case body used by the `default:` path.
pub fn switch_default_block(
    cases: &[(i32, usize)],
    by_start: &HashMap<usize, usize>,
) -> Option<usize> {
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for (_, t) in cases {
        *counts.entry(*t).or_default() += 1;
    }
    counts
        .iter()
        .max_by_key(|(_, c)| **c)
        .filter(|(_, c)| **c >= 2)
        .and_then(|(t, _)| by_start.get(t).copied())
}

/// Negate a comparison condition, falling back to `!(..)`.
fn negate_cond(e: &Expr) -> Expr {
    if let Expr::Binop(op, a, b) = e {
        let inv = match *op {
            "==" => "!=",
            "!=" => "==",
            "<" => ">=",
            ">" => "<=",
            "<=" => ">",
            ">=" => "<",
            _ => "",
        };
        if !inv.is_empty() {
            return Expr::Binop(inv, a.clone(), b.clone());
        }
    }
    Expr::Unop("!", Box::new(e.clone()))
}

/// Walk `elems` and record every block index referenced by a residual jump.
fn collect_residual(
    elems: &[Elem],
    by_start: &HashMap<usize, usize>,
    residual: &mut HashSet<usize>,
) {
    for e in elems {
        match e {
            Elem::Goto(t) => {
                if let Some(&b) = by_start.get(t) {
                    residual.insert(b);
                }
            }
            Elem::IfGoto { target, .. } => {
                if let Some(&b) = by_start.get(target) {
                    residual.insert(b);
                }
            }
            Elem::Switch { cases, default, .. } => {
                for (_, kind) in cases {
                    if let CaseKind::Goto(t) = kind {
                        if let Some(&b) = by_start.get(t) {
                            residual.insert(b);
                        }
                    } else if let CaseKind::Inline { body, .. } = kind {
                        collect_residual(body, by_start, residual);
                    }
                }
                if let Some(CaseKind::Goto(t)) = default {
                    if let Some(&b) = by_start.get(t) {
                        residual.insert(b);
                    }
                } else if let Some(CaseKind::Inline { body, .. }) = default {
                    collect_residual(body, by_start, residual);
                }
            }
            Elem::If { then, else_, .. } => {
                collect_residual(then, by_start, residual);
                collect_residual(else_, by_start, residual);
            }
            Elem::While { body, .. } | Elem::DoWhile { body, .. } => {
                collect_residual(body, by_start, residual);
            }
            _ => {}
        }
    }
}

struct Emit<'a> {
    f: &'a Function,
    q: &'a crate::loader::Qvm,
    ctx: Option<&'a crate::readable::Ctx>,
}

impl Emit<'_> {
    fn expr(&self, e: &Expr) -> String {
        match self.ctx {
            Some(c) => c.expr(self.f, self.q, e),
            None => fmt_expr(self.q, self.f.frame, e),
        }
    }

    fn store_lhs(&self, addr: &Expr, size: crate::decompile::LoadSize) -> String {
        match self.ctx {
            Some(c) => c.store_lhs(self.f, self.q, addr, size),
            None => store_lhs(self.q, self.f.frame, addr, size),
        }
    }

    fn store_rhs(&self, addr: &Expr, value: &Expr) -> String {
        match self.ctx {
            Some(c) => crate::readable::store_rhs(c, self.f, self.q, addr, value),
            None => self.expr(value),
        }
    }

    fn fn_open(&self) -> String {
        match self.ctx {
            Some(c) => c.fn_open(self.f, self.q),
            None => "void fn() {\n".into(),
        }
    }
}

/// Render a fully structured function as C (raw loc_N / `*(<int>*)` spelling).
pub fn fmt_structured(f: &Function, q: &crate::loader::Qvm) -> String {
    emit_structured(f, q, None)
}

/// Structured C with overlay names (`e->inuse`, `while`, `level.num_entities`).
/// For port agents — not q3lcc input.
pub fn fmt_readable(f: &Function, q: &crate::loader::Qvm) -> String {
    let ctx = crate::readable::Ctx::new(f, q);
    emit_structured(f, q, Some(&ctx))
}

fn emit_structured(
    f: &Function,
    q: &crate::loader::Qvm,
    ctx: Option<&crate::readable::Ctx>,
) -> String {
    let em = Emit { f, q, ctx };
    let mut s = Structure::new(f);
    let main = s.structure(0, EXIT);
    let leftover = s.leftover();

    // slot ids assigned anywhere (used to detect the PUSH dummy return)
    let mut assigned: HashSet<usize> = HashSet::new();
    for b in &f.blocks {
        for st in &b.body {
            if let Stmt::Assign { slot, .. } = st {
                assigned.insert(*slot);
            }
        }
    }

    let mut residual: HashSet<usize> = HashSet::new();
    collect_residual(&main, &s.by_start, &mut residual);
    // Label targets only from leftover blocks that will actually be printed:
    // a dead stub's target must not keep the stub alive.
    for &bi in &leftover {
        let b = &f.blocks[bi];
        if is_dead_stub(b, f, &assigned) {
            continue;
        }
        match &b.term {
            Terminator::Goto(t) => {
                if let Some(&d) = s.by_start.get(t) {
                    residual.insert(d);
                }
            }
            Terminator::IfGoto { target, .. } => {
                if let Some(&d) = s.by_start.get(target) {
                    residual.insert(d);
                }
            }
            _ => {}
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "// function @ insn {}..{} frame {}\n",
        f.start, f.end, f.frame
    ));
    out.push_str(&em.fn_open());
    fmt_elems(&mut out, &main, &em, 1, &assigned, &s.starts, &mut residual);
    for &bi in &leftover {
        // `Lx: goto Ly;` and `Lx: return;` (PUSH-dummy void return) stubs that
        // nobody references are dead (default-path residue of resolved
        // switches): drop them.
        let b = &f.blocks[bi];
        if is_dead_stub(b, f, &assigned) && !residual.contains(&bi) {
            continue;
        }
        out.push_str(&format!("L{}:\n", b.start));
        fmt_block_tail(&mut out, &em, bi, 1, &assigned);
    }
    out.push_str("}\n");
    out
}

/// A leftover block whose whole body renders as nothing and whose terminator
/// is a jump or a dummy void return: dead residue, dropped unless referenced.
fn is_dead_stub(b: &LoweredBlock, f: &Function, assigned: &HashSet<usize>) -> bool {
    let invisible = b.body.iter().all(|st| match st {
        Stmt::Assign { slot, value } => {
            !f.read_slots.contains(slot) && !matches!(value, Expr::Call(..) | Expr::Trap(..))
        }
        _ => false,
    });
    invisible
        && (matches!(b.term, Terminator::Goto(_))
            || matches!(&b.term, Terminator::Return(Some(Expr::Slot(s))) if !assigned.contains(s)))
}

fn fmt_elems(
    out: &mut String,
    elems: &[Elem],
    em: &Emit,
    indent: usize,
    assigned: &HashSet<usize>,
    starts: &[usize],
    residual: &mut HashSet<usize>,
) {
    let pad = "  ".repeat(indent);
    for e in elems {
        match e {
            Elem::Block { idx, body } => {
                if residual.remove(idx) {
                    out.push_str(&format!("L{}:\n", starts[*idx]));
                }
                for st in body {
                    fmt_stmt(out, st, em, indent);
                }
            }
            Elem::If { cond, then, else_ } => {
                out.push_str(&format!("{pad}if ({}) {{\n", em.expr(cond)));
                fmt_elems(out, then, em, indent + 1, assigned, starts, residual);
                if !else_.is_empty() {
                    let mut else_s = String::new();
                    fmt_elems(
                        &mut else_s,
                        else_,
                        em,
                        indent + 1,
                        assigned,
                        starts,
                        residual,
                    );
                    if !else_s.trim().is_empty() {
                        out.push_str(&format!("{pad}}} else {{\n"));
                        out.push_str(&else_s);
                    }
                }
                out.push_str(&format!("{pad}}}\n"));
            }
            Elem::While { cond, body } => {
                out.push_str(&format!("{pad}while ({}) {{\n", em.expr(cond)));
                fmt_elems(out, body, em, indent + 1, assigned, starts, residual);
                out.push_str(&format!("{pad}}}\n"));
            }
            Elem::DoWhile { cond, body } => {
                out.push_str(&format!("{pad}do {{\n"));
                fmt_elems(out, body, em, indent + 1, assigned, starts, residual);
                out.push_str(&format!("{pad}}} while ({});\n", em.expr(cond)));
            }
            Elem::Return(v) => fmt_return(out, v, em, indent, assigned),
            Elem::Goto(t) => out.push_str(&format!("{pad}goto L{t};\n")),
            Elem::IfGoto { cond, target } => {
                out.push_str(&format!("{pad}if ({}) goto L{target};\n", em.expr(cond)));
            }
            Elem::Switch {
                sel,
                cases,
                default,
            } => {
                out.push_str(&format!("{pad}switch ({}) {{\n", em.expr(sel)));
                for (vs, kind) in cases {
                    for v in vs {
                        out.push_str(&format!("{pad}case {v}:\n"));
                    }
                    match kind {
                        CaseKind::Inline {
                            body,
                            break_,
                            also_default,
                        } => {
                            if *also_default {
                                out.push_str(&format!("{pad}default:\n"));
                            }
                            fmt_elems(out, body, em, indent + 1, assigned, starts, residual);
                            if *break_ {
                                out.push_str(&format!("{pad}  break;\n"));
                            }
                        }
                        CaseKind::Goto(t) => out.push_str(&format!("{pad}  goto L{t};\n")),
                    }
                }
                if let Some(kind) = default {
                    out.push_str(&format!("{pad}default:\n"));
                    match kind {
                        CaseKind::Inline { body, break_, .. } => {
                            fmt_elems(out, body, em, indent + 1, assigned, starts, residual);
                            if *break_ {
                                out.push_str(&format!("{pad}  break;\n"));
                            }
                        }
                        CaseKind::Goto(t) => {
                            out.push_str(&format!("{pad}  goto L{t};\n"));
                        }
                    }
                }
                out.push_str(&format!("{pad}}}\n"));
            }
            Elem::Unresolved(a) => {
                out.push_str(&format!("{pad}goto /* indirect */ ({});\n", em.expr(a)));
            }
        }
    }
}

/// Render a leftover (fallback) block: its body plus its raw terminator.
fn fmt_block_tail(
    out: &mut String,
    em: &Emit,
    bi: usize,
    indent: usize,
    assigned: &HashSet<usize>,
) {
    let pad = "  ".repeat(indent);
    for st in &em.f.blocks[bi].body {
        fmt_stmt(out, st, em, indent);
    }
    match &em.f.blocks[bi].term {
        Terminator::Return(Some(v)) => fmt_return(out, &Some(v.clone()), em, indent, assigned),
        Terminator::Return(None) => out.push_str(&format!("{pad}return;\n")),
        Terminator::Goto(t) => out.push_str(&format!("{pad}goto L{t};\n")),
        Terminator::IfGoto { cond, target } => {
            out.push_str(&format!("{pad}if ({}) goto L{target};\n", em.expr(cond)));
        }
        Terminator::Switch {
            sel,
            cases,
            default: _,
        } => {
            let mut counts: HashMap<usize, usize> = HashMap::new();
            for (_, t) in cases {
                *counts.entry(*t).or_default() += 1;
            }
            let default_target = if cases.len() >= 2 {
                counts
                    .iter()
                    .max_by_key(|(_, c)| **c)
                    .filter(|(_, c)| **c >= 2)
                    .map(|(t, _)| *t)
            } else {
                None
            };
            out.push_str(&format!("{pad}switch ({}) {{\n", em.expr(sel)));
            for (v, t) in cases {
                if default_target == Some(*t) {
                    continue;
                }
                out.push_str(&format!("{pad}case {v}: goto L{t};\n"));
            }
            if let Some(t) = default_target {
                out.push_str(&format!("{pad}default: goto L{t};\n"));
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Terminator::Unresolved(a) => {
            out.push_str(&format!("{pad}goto /* indirect */ ({});\n", em.expr(a)));
        }
        Terminator::Fallthrough => {}
    }
}

/// Render one statement.
fn fmt_stmt(out: &mut String, st: &Stmt, em: &Emit, indent: usize) {
    let pad = "  ".repeat(indent);
    match st {
        Stmt::Assign { slot, value } => {
            let rhs = em.expr(value);
            if !em.f.read_slots.contains(slot) {
                match value {
                    Expr::Call(..) | Expr::Trap(..) => {
                        out.push_str(&format!("{pad}{rhs};\n"));
                    }
                    _ => {} // pure, dead slot write
                }
            } else {
                out.push_str(&format!("{pad}s{slot} = {rhs};\n"));
            }
        }
        Stmt::Store { addr, value, size } => {
            let v = em.store_rhs(addr, value);
            let store_lhs = em.store_lhs(addr, *size);
            out.push_str(&format!("{pad}{store_lhs} = {v};\n"));
        }
        Stmt::BlockCopy { dest, src, count } => {
            out.push_str(&format!(
                "{pad}memcpy((void*)({}), (const void*)({}), {});\n",
                em.expr(dest),
                em.expr(src),
                count
            ));
        }
    }
}

/// Render a return; an unassigned slot is the PUSH dummy of a void return.
fn fmt_return(
    out: &mut String,
    v: &Option<Expr>,
    em: &Emit,
    indent: usize,
    assigned: &HashSet<usize>,
) {
    let pad = "  ".repeat(indent);
    match v {
        Some(Expr::Slot(s)) if !assigned.contains(s) => out.push_str(&format!("{pad}return;\n")),
        Some(v) => out.push_str(&format!("{pad}return {};\n", em.expr(v))),
        None => out.push_str(&format!("{pad}return;\n")),
    }
}

/// Left-hand side of a store: `*addr` in the right width.
fn store_lhs(
    q: &crate::loader::Qvm,
    frame: i32,
    addr: &Expr,
    size: crate::decompile::LoadSize,
) -> String {
    use crate::decompile::LoadSize;
    match addr {
        Expr::AddrLocal(off) => match size {
            LoadSize::I4 => stack_name(frame, *off),
            LoadSize::I1 => format!("(*(uchar*)&({}))", stack_name(frame, *off)),
            LoadSize::I2 => format!("(*(ushort*)&({}))", stack_name(frame, *off)),
        },
        Expr::GlobalRef { addr, .. } => mem_ref(q, *addr, size),
        Expr::MemRef(a, _) => format!("*(<{}>*)({})", size.ty(), fmt_expr(q, frame, a)),
        _ => format!("*(<{}>*)({})", size.ty(), fmt_expr(q, frame, addr)),
    }
}

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

fn mem_ref(q: &crate::loader::Qvm, addr: usize, size: crate::decompile::LoadSize) -> String {
    use crate::decompile::LoadSize;
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

fn fmt_expr(q: &crate::loader::Qvm, frame: i32, e: &Expr) -> String {
    crate::decompile::fmt_expr(q, frame, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::{LoadSize, LoweredBlock};

    fn mk_function(blocks: Vec<LoweredBlock>) -> Function {
        Function {
            start: 0,
            end: 0,
            frame: 4,
            blocks,
            read_slots: std::collections::BTreeSet::new(),
            arity: 0,
            returns: false,
        }
    }

    fn blk(start: usize, body: Vec<Stmt>, term: Terminator) -> LoweredBlock {
        LoweredBlock { start, body, term }
    }

    fn ret(v: Option<i32>) -> Terminator {
        Terminator::Return(v.map(Expr::Const))
    }

    fn const_e(x: i32) -> Expr {
        Expr::Const(x)
    }

    fn lt(a: Expr, b: Expr) -> Expr {
        Expr::Binop("<", Box::new(a), Box::new(b))
    }

    #[test]
    fn if_else_merge() {
        // b0: if (a < b) goto 30;  b1: <body> goto 40;  b2(30): <body> goto 40;  b3(40): return
        let body = vec![Stmt::Store {
            addr: Expr::AddrLocal(0),
            value: const_e(1),
            size: LoadSize::I4,
        }];
        let f = mk_function(vec![
            blk(
                0,
                vec![],
                Terminator::IfGoto {
                    cond: lt(const_e(1), const_e(2)),
                    target: 30,
                },
            ),
            blk(10, body.clone(), Terminator::Goto(40)),
            blk(30, body.clone(), Terminator::Goto(40)),
            blk(40, vec![], ret(None)),
        ]);
        let q = crate::loader::Qvm {
            path: String::new(),
            vm_magic: 0,
            instruction_count: 0,
            code_offset: 0,
            code_length: 0,
            data_offset: 0,
            data_length: 0,
            lit_length: 0,
            bss_length: 0,
            jtrg_length: 0,
            module: crate::traps::Module::Game,
            code: Vec::new(),
            data: Vec::new(),
            lit: Vec::new(),
            jump_table_targets: Vec::new(),
            names: std::collections::HashMap::new(),
        };
        let out = fmt_structured(&f, &q);
        assert!(out.contains("} else {"), "else emitted: {out}");
        assert!(!out.contains("goto"), "no goto: {out}");
    }

    #[test]
    fn while_loop() {
        // header b0: if (cond) goto exit(20); body b1: goto 0; b2(20): return
        let f = mk_function(vec![
            blk(
                0,
                vec![],
                Terminator::IfGoto {
                    cond: lt(const_e(1), const_e(2)),
                    target: 20,
                },
            ),
            blk(10, vec![], Terminator::Goto(0)),
            blk(20, vec![], ret(None)),
        ]);
        let q = crate::loader::Qvm {
            path: String::new(),
            vm_magic: 0,
            instruction_count: 0,
            code_offset: 0,
            code_length: 0,
            data_offset: 0,
            data_length: 0,
            lit_length: 0,
            bss_length: 0,
            jtrg_length: 0,
            module: crate::traps::Module::Game,
            code: Vec::new(),
            data: Vec::new(),
            lit: Vec::new(),
            jump_table_targets: Vec::new(),
            names: std::collections::HashMap::new(),
        };
        let out = fmt_structured(&f, &q);
        assert!(out.contains("while ("), "while emitted: {out}");
        assert!(!out.contains("goto"), "no goto: {out}");
    }

    #[test]
    fn consecutive_ifs() {
        // b0: if (a < b) goto 30; b1(10): S1 goto 40; b2(30): if (c < d) goto 50;
        // b3(40): S2 goto 50; b4(50): return
        let s1 = vec![Stmt::Store {
            addr: Expr::AddrLocal(0),
            value: const_e(1),
            size: LoadSize::I4,
        }];
        let s2 = vec![Stmt::Store {
            addr: Expr::AddrLocal(4),
            value: const_e(2),
            size: LoadSize::I4,
        }];
        let f = mk_function(vec![
            blk(
                0,
                vec![],
                Terminator::IfGoto {
                    cond: lt(const_e(1), const_e(2)),
                    target: 30,
                },
            ),
            blk(10, s1.clone(), Terminator::Goto(40)),
            blk(
                30,
                vec![],
                Terminator::IfGoto {
                    cond: lt(const_e(3), const_e(4)),
                    target: 50,
                },
            ),
            blk(40, s2.clone(), Terminator::Goto(50)),
            blk(50, vec![], ret(None)),
        ]);
        let q = crate::loader::Qvm {
            path: String::new(),
            vm_magic: 0,
            instruction_count: 0,
            code_offset: 0,
            code_length: 0,
            data_offset: 0,
            data_length: 0,
            lit_length: 0,
            bss_length: 0,
            jtrg_length: 0,
            module: crate::traps::Module::Game,
            code: Vec::new(),
            data: Vec::new(),
            lit: Vec::new(),
            jump_table_targets: Vec::new(),
            names: std::collections::HashMap::new(),
        };
        let out = fmt_structured(&f, &q);
        assert_eq!(out.matches("if (").count(), 2, "two ifs: {out}");
        assert!(!out.contains("goto"), "no goto: {out}");
    }

    #[test]
    fn do_while_loop() {
        // b0(0): body, falls to b1; b1(10): if (cond) goto 0; b2(20): return
        let f = mk_function(vec![
            blk(0, vec![], Terminator::Fallthrough),
            blk(
                10,
                vec![],
                Terminator::IfGoto {
                    cond: lt(const_e(1), const_e(2)),
                    target: 0,
                },
            ),
            blk(20, vec![], ret(None)),
        ]);
        let q = crate::loader::Qvm {
            path: String::new(),
            vm_magic: 0,
            instruction_count: 0,
            code_offset: 0,
            code_length: 0,
            data_offset: 0,
            data_length: 0,
            lit_length: 0,
            bss_length: 0,
            jtrg_length: 0,
            module: crate::traps::Module::Game,
            code: Vec::new(),
            data: Vec::new(),
            lit: Vec::new(),
            jump_table_targets: Vec::new(),
            names: std::collections::HashMap::new(),
        };
        let out = fmt_structured(&f, &q);
        assert!(out.contains("do {"), "do emitted: {out}");
        assert!(out.contains("} while ("), "do-while cond: {out}");
        assert!(!out.contains("goto"), "no goto: {out}");
    }

    #[test]
    fn switch_cases_inlined() {
        // b0: switch; b1(30): return 1; b2(40): return 2
        let f = mk_function(vec![
            blk(
                0,
                vec![],
                Terminator::Switch {
                    sel: Box::new(const_e(0)),
                    cases: vec![(0, 30), (1, 40)],
                    default: None,
                },
            ),
            blk(30, vec![], ret(Some(1))),
            blk(40, vec![], ret(Some(2))),
        ]);
        let q = crate::loader::Qvm {
            path: String::new(),
            vm_magic: 0,
            instruction_count: 0,
            code_offset: 0,
            code_length: 0,
            data_offset: 0,
            data_length: 0,
            lit_length: 0,
            bss_length: 0,
            jtrg_length: 0,
            module: crate::traps::Module::Game,
            code: Vec::new(),
            data: Vec::new(),
            lit: Vec::new(),
            jump_table_targets: Vec::new(),
            names: std::collections::HashMap::new(),
        };
        let out = fmt_structured(&f, &q);
        assert!(out.contains("case 0:"), "case 0: {out}");
        assert!(out.contains("return 1;"), "body inlined: {out}");
        assert!(!out.contains("goto"), "no case gotos: {out}");
    }
}
