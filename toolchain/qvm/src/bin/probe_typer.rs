// probe_typer — stage C1: collect every statically-known memory access across
// the whole QVM (loads, stores, block copies) and classify BSS/data addresses
// against the recovered layout (cvarTable slots, level, g_entities, g_clients,
// plus custom zones). Output: types.txt.
//
// Usage:
//   probe_typer <target.qvm> [types.txt] [--names <id>.names]
//
// The output is the raw material for stage C2 (struct-field matching). The
// acceptance metric is "every BSS address covered by a named region".

use std::collections::{BTreeMap, BTreeSet};

use qvm::decompile::{Expr, LoadSize, Stmt, Terminator};
use qvm::{build_all, decompile_function, disassemble, load};

// ---- BSS layout template ----
// The shipped layout is EMPTY: 0-sized ranges classify nothing. Recover the
// regions for YOUR module (see toolchain/qvm/src/types.rs for the guideline)
// and fill them in here or extend `ZONES` below. `level` / `g_entities` /
// `g_clients` are the classic qagame triple; everything else is a generic
// (base, end, label) row. Field-name tables further down follow stock id
// Tech 3 headers; verify every offset against your module before trusting.
const GCLIENTS_BASE: usize = 0; // FILL IN, e.g. 64 x <gclient size>
const GCLIENTS_END: usize = 0;
const GENTITIES_BASE: usize = 0; // FILL IN, e.g. 1024 x <gent size>
const GENTITIES_END: usize = 0;
const LEVEL_BASE: usize = 0; // FILL IN (globals block start)
const LEVEL_SIZE: usize = 0;

/// Extra named regions as `(base, end, label)`. FILL IN per module.
const ZONES: &[(usize, usize, &str)] = &[];

// cvarTable: base data word 1 (byte 4), stride 8 words (32 bytes),
// count at data word 1769. Record: +0 slot ptr, +4 name ptr, +8 default ptr, +12 flags.
const CVAR_TABLE_BASE_WORD: usize = 1;
const CVAR_TABLE_STRIDE_WORDS: usize = 8;
const CVAR_COUNT_WORD: usize = 1769;
const CVAR_SLOT_SIZE: usize = 272;

struct CvarSlot {
    addr: usize,
    name: String,
    default: String,
    flags: i32,
    index: usize,
}

fn parse_cvar_table(q: &qvm::Qvm) -> Vec<CvarSlot> {
    let d = q.data_int32();
    let count = d.get(CVAR_COUNT_WORD).copied().unwrap_or(0).max(0) as usize;
    let mut out = Vec::new();
    for k in 0..count {
        let w = CVAR_TABLE_BASE_WORD + k * CVAR_TABLE_STRIDE_WORDS;
        let (Some(&slot), Some(&name), Some(&def), Some(&flags)) =
            (d.get(w), d.get(w + 1), d.get(w + 2), d.get(w + 3))
        else {
            break;
        };
        let name_s = q
            .string_at(name)
            .unwrap_or_else(|| format!("<ptr 0x{:x}>", name));
        let def_s = q
            .string_at(def)
            .unwrap_or_else(|| format!("<ptr 0x{:x}>", def));
        out.push(CvarSlot {
            addr: slot.max(0) as usize,
            name: name_s,
            default: def_s,
            flags,
            index: k,
        });
    }
    out
}

/// Recursively visit every `Expr` (including nested traps) in `e`.
fn walk_expr_traps(e: &Expr, f: &mut impl FnMut(&Expr)) {
    f(e);
    match e {
        Expr::Unop(_, a) => walk_expr_traps(a, f),
        Expr::Binop(_, a, b) => {
            walk_expr_traps(a, f);
            walk_expr_traps(b, f);
        }
        Expr::MemRef(a, _) => walk_expr_traps(a, f),
        Expr::Call(t, args) => {
            walk_expr_traps(t, f);
            for a in args {
                walk_expr_traps(a, f);
            }
        }
        Expr::Trap(_, args) => {
            for a in args {
                walk_expr_traps(a, f);
            }
        }
        _ => {}
    }
}

/// Collect inline `trap_Cvar_Register(slot, name, default, flags)` registrations
/// where both the slot address and the name are compile-time constants (the
/// table-driven ones in G_RegisterCvars use a loop variable and are not found
/// here). Trap number 3 == trap_Cvar_Register.
fn collect_inline_cvars(
    q: &qvm::Qvm,
    d: &qvm::Disassembly,
    cfgs: &[qvm::CFG],
    data: &[i32],
) -> Vec<CvarSlot> {
    let mut out: Vec<CvarSlot> = Vec::new();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    for cfg in cfgs {
        let frame = d.insns[cfg.entry].operand.unwrap_or(0);
        let f = decompile_function(d, cfg, frame, data);
        let mut rec = |e: &Expr| {
            if let Expr::Trap(3, args) = e {
                if let Some(Expr::Const(slot)) = args.get(0) {
                    if *slot > 0 && seen.insert(*slot as usize) {
                        let name = match args.get(1) {
                            Some(Expr::Const(c)) => q
                                .string_at(*c)
                                .unwrap_or_else(|| format!("<ptr 0x{:x}>", c)),
                            _ => "<dynamic>".to_string(),
                        };
                        out.push(CvarSlot {
                            addr: *slot as usize,
                            name,
                            default: String::new(),
                            flags: 0,
                            index: usize::MAX,
                        });
                    }
                }
            }
        };
        for b in &f.blocks {
            for st in &b.body {
                match st {
                    Stmt::Assign { value, .. } => walk_expr_traps(value, &mut rec),
                    Stmt::Store { addr, value, .. } => {
                        walk_expr_traps(addr, &mut rec);
                        walk_expr_traps(value, &mut rec);
                    }
                    Stmt::BlockCopy { dest, src, .. } => {
                        walk_expr_traps(dest, &mut rec);
                        walk_expr_traps(src, &mut rec);
                    }
                }
            }
            match &b.term {
                Terminator::Return(Some(v)) => walk_expr_traps(v, &mut rec),
                Terminator::IfGoto { cond, .. } => walk_expr_traps(cond, &mut rec),
                Terminator::Switch { sel, .. } => walk_expr_traps(sel, &mut rec),
                Terminator::Unresolved(e) => walk_expr_traps(e, &mut rec),
                _ => {}
            }
        }
    }
    out
}

/// Find the cvar slot (by table addr) that contains `a`, if any.
fn cvar_containing(slots: &[CvarSlot], a: usize) -> Option<&CvarSlot> {
    slots
        .iter()
        .find(|s| a >= s.addr && a < s.addr + CVAR_SLOT_SIZE)
}

fn level_field(off: usize) -> Option<&'static str> {
    // Stock-style field names; the order of the first two words differs
    // between mods — verify against your module before trusting.
    Some(match off {
        0x00 => "gentities / clients",
        0x04 => "clients / gentities",
        0x08 => "gentitySize",
        0x0c => "num_entities",
        0x10 => "warmupTime",
        0x14 => "logFile",
        0x18 => "maxclients",
        0x1c => "framenum",
        0x20 => "time",
        0x24 => "previousTime",
        0x28 => "startTime",
        0x2c => "msec",
        0x30 => "teamScores[3]",
        0x3c => "lastTeamLocationTime",
        0x40 => "newSession",
        0x44 => "restarted",
        0x48 => "numConnectedClients",
        0x4c => "numNonSpectatorClients",
        0x50 => "numPlayingClients",
        0x54 => "sortedClients[64]",
        0x154 => "follow1",
        0x158 => "follow2",
        0x15c => "snd_fry",
        0x160 => "warmupModificationCount",
        0x164 => "voteString[256]",
        0x264 => "voteDisplayString[256]",
        0x364 => "voteTime",
        0x368 => "voteExecuteTime",
        0x36c => "voteYes",
        0x370 => "voteNo",
        0x374 => "numVotingClients",
        0x378 => "teamVoteString[2][1024]",
        0xb78 => "teamVoteTime[2]",
        0xb80 => "teamVoteYes[2]",
        0xb88 => "teamVoteNo[2]",
        0xb90 => "numteamVotingClients[3]",
        _ => return None,
    })
}

fn gentity_field(off: usize) -> Option<&'static str> {
    Some(match off {
        0x208 => "inuse",
        _ => return None,
    })
}

/// Classify a BSS address into a human label (region + offset).
fn classify_bss(slots: &[CvarSlot], a: usize) -> String {
    if let Some(s) = cvar_containing(slots, a) {
        let off = a - s.addr;
        return format!("cvar {} +0x{off:x}", s.name);
    }
    if a >= LEVEL_BASE && a < LEVEL_BASE + LEVEL_SIZE {
        let off = a - LEVEL_BASE;
        match level_field(off) {
            Some(f) => format!("level +0x{off:x} ({f})"),
            None => format!("level +0x{off:x}"),
        }
    } else if a >= GENTITIES_BASE && a < GENTITIES_END {
        let off = a - GENTITIES_BASE;
        match gentity_field(off) {
            Some(f) => format!("g_entities +0x{off:x} ({f})"),
            None => format!("g_entities +0x{off:x}"),
        }
    } else if GCLIENTS_END > GCLIENTS_BASE && a >= GCLIENTS_BASE && a < GCLIENTS_END {
        format!("g_clients +0x{:x}", a - GCLIENTS_BASE)
    } else if let Some((base, end, label)) = ZONES.iter().find(|(b, e, _)| a >= *b && a < *e) {
        format!("{label} +0x{:x}", a - base)
    } else {
        format!("bss-unknown 0x{a:06x}")
    }
}

#[derive(Default)]
struct Access {
    sizes: BTreeSet<LoadSize>,
    loads: u32,
    stores: u32,
    blkcopy: u32,
    funcs: BTreeSet<usize>,
}

impl Access {
    fn note(&mut self, size: LoadSize, is_load: bool, func: usize) {
        self.sizes.insert(size);
        if is_load {
            self.loads += 1;
        } else {
            self.stores += 1;
        }
        self.funcs.insert(func);
    }
    fn note_copy(&mut self, func: usize) {
        self.blkcopy += 1;
        self.funcs.insert(func);
    }
}

fn const_addr(e: &Expr) -> Option<usize> {
    match e {
        Expr::Const(c) if *c >= 0 => Some(*c as usize),
        Expr::Binop("+", a, b) => {
            let (a, b) = (const_addr(a)?, const_addr(b)?);
            Some(a.checked_add(b)?)
        }
        Expr::Binop("-", a, b) => {
            let (a, b) = (const_addr(a)?, const_addr(b)?);
            a.checked_sub(b)
        }
        _ => None,
    }
}

struct Collector<'a> {
    q: &'a qvm::Qvm,
    dl: usize,
    ll: usize,
    access: BTreeMap<usize, Access>,
    func: usize,
    unknown: u32,
}

impl<'a> Collector<'a> {
    fn new(q: &'a qvm::Qvm) -> Self {
        Collector {
            q,
            dl: q.data_length as usize,
            ll: q.lit_length as usize,
            access: BTreeMap::new(),
            func: 0,
            unknown: 0,
        }
    }

    fn in_mem(&self, a: usize) -> bool {
        a < self.q.data_mask() as usize + 1
    }

    fn note(&mut self, addr: usize, size: LoadSize, is_load: bool) {
        if !self.in_mem(addr) {
            self.unknown += 1;
            return;
        }
        self.access.entry(addr).or_default().note(size, is_load, self.func);
    }

    fn note_copy(&mut self, dest: usize, src: usize) {
        for a in [dest, src] {
            if self.in_mem(a) {
                self.access.entry(a).or_default().note_copy(self.func);
            } else {
                self.unknown += 1;
            }
        }
    }

    fn walk_expr(&mut self, e: &Expr) {
        match e {
            Expr::GlobalRef { addr, size } => self.note(*addr, *size, true),
            Expr::MemRef(inner, size) => {
                if let Some(a) = const_addr(inner) {
                    self.note(a, *size, true);
                } else {
                    self.walk_expr(inner);
                }
            }
            Expr::Unop(_, a) => self.walk_expr(a),
            Expr::Binop(_, a, b) => {
                self.walk_expr(a);
                self.walk_expr(b);
            }
            Expr::Call(t, args) => {
                self.walk_expr(t);
                for a in args {
                    self.walk_expr(a);
                }
            }
            Expr::Trap(_, args) => {
                for a in args {
                    self.walk_expr(a);
                }
            }
            _ => {}
        }
    }

    fn walk_stmt(&mut self, st: &Stmt) {
        match st {
            Stmt::Assign { value, .. } => self.walk_expr(value),
            Stmt::Store { addr, value, size } => {
                match const_addr(addr) {
                    Some(a) => self.note(a, *size, false),
                    None => self.walk_expr(addr),
                }
                self.walk_expr(value);
            }
            Stmt::BlockCopy { dest, src, .. } => {
                match (const_addr(dest), const_addr(src)) {
                    (Some(d), Some(s)) => self.note_copy(d, s),
                    (Some(d), None) => self.note_copy(d, 0),
                    (None, Some(s)) => self.note_copy(0, s),
                    (None, None) => {
                        self.walk_expr(dest);
                        self.walk_expr(src);
                    }
                }
            }
        }
    }

    fn walk_term(&mut self, t: &Terminator) {
        match t {
            Terminator::Return(Some(v)) => self.walk_expr(v),
            Terminator::IfGoto { cond, .. } => self.walk_expr(cond),
            Terminator::Switch { sel, .. } => self.walk_expr(sel),
            Terminator::Unresolved(addr) => {
                if let Some(a) = const_addr(addr) {
                    self.note(a, LoadSize::I4, true);
                } else {
                    self.walk_expr(addr);
                }
            }
            _ => {}
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: probe_typer <target.qvm> [types.txt] [--names <id>.names]");
        std::process::exit(2);
    }
    let path = args[1].clone();
    let out_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "types.txt".to_string());
    let mut names_path: Option<String> = None;
    let mut it = args.iter().skip(3);
    while let Some(a) = it.next() {
        if a == "--names" {
            if let Some(v) = it.next() {
                names_path = Some(v.clone());
            }
        }
    }

    let mut q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let cfgs = build_all(&d, &q);
    let data = q.data_int32();
    let starts: Vec<usize> = cfgs.iter().map(|c| c.start).collect();

    if let Some(np) = names_path {
        let mut by_index: BTreeMap<usize, String> = BTreeMap::new();
        for line in std::fs::read_to_string(&np).expect("read names").lines() {
            let mut sp = line.split_whitespace();
            let (Some(idx), Some(name)) = (sp.next(), sp.next()) else {
                continue;
            };
            let trimmed = idx.trim_start_matches("fn[").trim_end_matches(']');
            if let Ok(i) = trimmed.parse::<usize>() {
                by_index.insert(i, name.to_string());
            }
        }
        for (i, cfg) in cfgs.iter().enumerate() {
            if let Some(name) = by_index.get(&i) {
                q.names.insert(cfg.start, name.clone());
            }
        }
        eprintln!("names: {} attached", q.names.len());
    }

    let mut col = Collector::new(&q);
    for (i, cfg) in cfgs.iter().enumerate() {
        let frame = d.insns[cfg.entry].operand.unwrap_or(0);
        let f = decompile_function(&d, cfg, frame, &data);
        col.func = i;
        for b in &f.blocks {
            for st in &b.body {
                col.walk_stmt(st);
            }
            col.walk_term(&b.term);
        }
    }
    let dl = col.dl;
    let ll = col.ll;
    let dll = dl + ll;
    eprintln!(
        "collected {} distinct addresses (data<{}, lit<0x{:X}), unknown={}",
        col.access.len(),
        dl,
        dll,
        col.unknown
    );

    let mut cvars = parse_cvar_table(&q);
    let inline = collect_inline_cvars(&q, &d, &cfgs, &data);
    eprintln!("cvarTable: {} table entries + {} inline = {}", cvars.len(), inline.len(), cvars.len() + inline.len());
    let mut seen_slots: BTreeSet<usize> = cvars.iter().map(|c| c.addr).collect();
    for c in inline {
        if seen_slots.insert(c.addr) {
            cvars.push(c);
        }
    }
    cvars.sort_by_key(|c| c.addr);

    let data_addrs: BTreeSet<usize> = col.access.keys().copied().filter(|a| *a < dl).collect();
    let lit_addrs: BTreeSet<usize> = col
        .access
        .keys()
        .copied()
        .filter(|a| *a >= dl && *a < dll)
        .collect();
    let bss_addrs: BTreeSet<usize> = col.access.keys().copied().filter(|a| *a >= dll).collect();

    let mut out = String::new();
    out.push_str(&format!("// types.txt — data-segment typing (stage C1 collect)\n"));
    out.push_str(&format!("// qvm: {path}\n"));
    out.push_str(&format!(
        "// data_length={dl} lit_length={ll} data+lit=0x{dll:X}\n"
    ));
    out.push_str(&format!(
        "// distinct addresses: data={} lit={} bss={} total={}\n\n",
        data_addrs.len(),
        lit_addrs.len(),
        bss_addrs.len(),
        col.access.len()
    ));

    // ---- cvarTable dump ----
    out.push_str(&format!(
        "== cvarTable (count={}, base=word 1 / 0x4, stride 8 words / 0x20, slot=272 B) ==\n",
        cvars.len()
    ));
    for c in &cvars {
        let src = if c.index == usize::MAX {
            "inline".to_string()
        } else {
            format!("t{:03}", c.index)
        };
        out.push_str(&format!(
            "  [{src}] slot=0x{:06x} name={} default={} flags={}\n",
            c.addr, c.name, c.default, c.flags
        ));
    }
    out.push('\n');

    // ---- DATA region ----
    out.push_str("== DATA addresses (all, sorted) ==\n");
    for &a in &data_addrs {
        let acc = col.access.get(&a).unwrap();
        let in_table = a >= 4
            && (a - 4) % 32 < 16
            && (a - 4) / 32 + 1 < CVAR_COUNT_WORD
            && data.get(CVAR_COUNT_WORD).copied().unwrap_or(0).max(0) as usize > (a - 4) / 32;
        let tag = if in_table {
            format!("cvarTable[k={},+0x{:x}]", (a - 4) / 32, (a - 4) % 32)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "  data 0x{a:06x} {tag} sizes={} L={} S={} B={} funcs={}\n",
            sz(acc),
            acc.loads,
            acc.stores,
            acc.blkcopy,
            fmt_funcs(&q, &col, &starts, a)
        ));
    }
    out.push('\n');

    // ---- LIT ----
    out.push_str(&format!("== lit addresses ({}) ==\n", lit_addrs.len()));
    for a in &lit_addrs {
        let acc = col.access.get(a).unwrap();
        out.push_str(&format!(
            "  lit 0x{a:06x} sizes={} L={} S={} B={} funcs={}\n",
            sz(acc),
            acc.loads,
            acc.stores,
            acc.blkcopy,
            fmt_funcs(&q, &col, &starts, *a)
        ));
    }
    out.push('\n');

    // ---- BSS by region ----
    out.push_str("== BSS by region ==\n");
    // group addresses by classification label
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &a in &bss_addrs {
        let label = classify_bss(&cvars, a);
        groups.entry(label).or_default().push(a);
    }
    let mut region_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (label, addrs) in &groups {
        let region = label.split(' ').next().unwrap_or("bss-unknown");
        *region_counts.entry(region).or_insert(0) += addrs.len();
        out.push_str(&format!("  {} ({} addr):\n", label, addrs.len()));
        for &a in addrs {
            let acc = col.access.get(&a).unwrap();
            out.push_str(&format!(
                "      {a:06x} sizes={} L={} S={} B={} funcs={}\n",
                sz(acc),
                acc.loads,
                acc.stores,
                acc.blkcopy,
                fmt_funcs(&q, &col, &starts, a)
            ));
        }
    }
    out.push('\n');

    let total_bss = bss_addrs.len();
    out.push_str("== BSS coverage summary ==\n");
    for (r, n) in &region_counts {
        out.push_str(&format!("  {r:<12} {n:>4}  ({:.1}%)\n", 100.0 * *n as f64 / total_bss.max(1) as f64));
    }
    let unknown_n = groups
        .keys()
        .filter(|k| k.starts_with("bss-unknown"))
        .map(|k| groups[k].len())
        .sum::<usize>();
    out.push_str(&format!("  bss-unknown {unknown_n}  ({:.1}%)\n", 100.0 * unknown_n as f64 / total_bss.max(1) as f64));

    std::fs::write(&out_path, &out).expect("write");
    println!(
        "wrote {out_path}: data={} lit={} bss={} unknown={} cvars={}",
        data_addrs.len(),
        lit_addrs.len(),
        bss_addrs.len(),
        col.unknown,
        cvars.len()
    );
}

fn sz(a: &Access) -> String {
    a.sizes
        .iter()
        .map(|s| match s {
            LoadSize::I1 => "u8",
            LoadSize::I2 => "u16",
            LoadSize::I4 => "i32",
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn fmt_funcs(q: &qvm::Qvm, col: &Collector, starts: &[usize], addr: usize) -> String {
    let Some(a) = col.access.get(&addr) else {
        return String::new();
    };
    a.funcs
        .iter()
        .take(6)
        .map(|i| match starts.get(*i) {
            Some(s) => q
                .name_for_fn(*s)
                .map(|n| format!("fn[{i}]{n}"))
                .unwrap_or_else(|| format!("fn[{i}]")),
            None => format!("fn[{i}]"),
        })
        .collect::<Vec<_>>()
        .join(",")
}
