//! Loading + analysis state for the GUI. Pure `qvm` calls, no UI here, so it
//! stays unit-testable.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use qvm::{disassemble, load, load_map, trap_name, Disassembly, Insn, Opcode, Qvm};

/// Cached decompilation of one function.
#[derive(Clone, Debug, PartialEq)]
pub struct Decompiled {
    /// Identity C text (`\n`-separated lines, trailing newline).
    pub text: std::sync::Arc<str>,
    /// Per-C-line insn range covered by that line.
    pub ranges: std::sync::Arc<[(usize, usize)]>,
    /// Block label insn -> C line index (goto navigation targets).
    pub labels: std::sync::Arc<HashMap<usize, usize>>,
    /// Tracked `loc_N = ...` address initializations (for hover hints on
    /// `loc_N` tokens and `(loc_N) + (offset)` field accesses).
    pub locals: std::sync::Arc<HashMap<String, LocalDecl>>,
}

/// Tracked initialization of a `loc_N` local, e.g.
/// `loc_20 = ((arg_3) * (1568)) + (*(<int>*)(0xf0850));`
/// (in q3 terms: `cl = level.clients[clientNum]`).
#[derive(Clone, Debug, PartialEq)]
pub struct LocalDecl {
    /// Index expression name (`arg_3`) when the base is scaled.
    pub index: Option<String>,
    /// Scale of `index`.
    pub stride: Option<i32>,
    /// Absolute constant base (`loc = 218100` / `+ (149584)`).
    pub base_const: Option<i32>,
    /// Base loaded from a fixed address (`+ (*(<int>*)(0xf0850))`).
    pub base_deref: Option<i32>,
    /// Chained base: `loc = (loc_M) + (K)` — pointer derived from another
    /// local (resolved transitively by the struct census).
    pub base_loc: Option<(String, i32)>,
}

// ---------------------------------------------------------------------------
// Struct type database (`structs/*.json`, user-extensible; Ghidra-style
// "apply type" turns `(loc_20) + (704)` into `loc_20->pers`).
// ---------------------------------------------------------------------------

/// One named struct type: total size + field names by byte offset.
#[derive(Clone, Debug, Default)]
pub struct StructDef {
    pub size: i32,
    pub fields: BTreeMap<i32, String>,
}

/// All loaded struct types, keyed by type name.
#[derive(Clone, Debug, Default)]
pub struct StructDb {
    pub map: HashMap<String, StructDef>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct StructFileDef {
    #[serde(default)]
    size: Option<i32>,
    #[serde(default)]
    fields: HashMap<String, String>,
}

static STRUCT_DB: std::sync::RwLock<Option<std::sync::Arc<StructDb>>> =
    std::sync::RwLock::new(None);

/// Data folders scanned for `*.json` catalogs: next to the exe, then cwd.
fn data_dirs(sub: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            dirs.push(d.join(sub));
        }
    }
    dirs.push(PathBuf::from(sub));
    dirs
}

fn load_struct_db() -> StructDb {
    let mut db = StructDb::default();
    for dir in data_dirs("structs") {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<_> = rd.flatten().collect();
        paths.sort_by_key(|p| p.path());
        for p in paths {
            let fname = p.file_name();
            let Some(name) = fname.to_str() else {
                continue;
            };
            if !name.to_lowercase().ends_with(".json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(p.path()) else {
                continue;
            };
            let Ok(file) = serde_json::from_str::<HashMap<String, StructFileDef>>(&text) else {
                eprintln!("structs: skipping unparseable {}", p.path().display());
                continue;
            };
            for (ty, def) in file {
                let fields: BTreeMap<i32, String> = def
                    .fields
                    .into_iter()
                    .filter_map(|(k, v)| k.parse::<i32>().ok().map(|off| (off, v)))
                    .collect();
                db.map.insert(
                    ty,
                    StructDef {
                        size: def.size.unwrap_or(0),
                        fields,
                    },
                );
            }
        }
    }
    db
}

/// Load `structs/*.json` catalogs (exe dir + cwd, merged; same-name types
/// from later files win). Format:
/// `{ "gclient_t": { "size": 1568, "fields": { "704": "pers" } } }`.
pub fn struct_db() -> std::sync::Arc<StructDb> {
    if let Some(db) = STRUCT_DB.read().unwrap().clone() {
        return db;
    }
    let db = std::sync::Arc::new(load_struct_db());
    *STRUCT_DB.write().unwrap() = Some(db.clone());
    db
}

/// Rescan the structs/ directories (the scrape tool adds auto.json).
pub fn reload_struct_db() {
    *STRUCT_DB.write().unwrap() = Some(std::sync::Arc::new(load_struct_db()));
}

/// Parse `loc_N) + (K))` at the start of `s` (the tail of a struct-field
/// access); returns the loc name, the offset and the consumed length.
fn parse_loc_field(s: &str) -> Option<(String, i32, usize)> {
    let name_end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    let name = &s[..name_end];
    if !(name.len() > 4
        && name.starts_with("loc_")
        && name[4..].bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let rest = s[name_end..].strip_prefix(") + (")?;
    let num_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let off = rest[..num_end].parse::<i32>().ok()?;
    rest[num_end..].strip_prefix("))")?;
    Some((name.to_string(), off, name_end + 5 + num_end + 2))
}

fn field_of(types: &HashMap<String, String>, db: &StructDb, loc: &str, off: i32) -> Option<String> {
    let def = db.map.get(types.get(loc)?)?;
    def.fields.get(&off).cloned()
}

/// All `(loc_X) + (K)` field accesses on one line.
fn iter_field_accesses(line: &str) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(p) = line[i..].find("(loc_") {
        let start = i + p;
        // Name starts after "(loc_" — scan from there, not from the paren.
        let name_end = line[start + 5..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(line.len(), |x| start + 5 + x);
        let name = &line[start + 1..name_end];
        if let Some(rest) = line[name_end..].strip_prefix(") + (") {
            let num_end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if num_end > 0 && rest[num_end..].starts_with(')') {
                if let Ok(off) = rest[..num_end].parse::<i32>() {
                    out.push((name.to_string(), off));
                }
            }
        }
        i = name_end;
    }
    out
}

/// Census of struct-field accesses across the whole image: group the
/// `(loc_X) + (K)` offsets by loc_X's initialization base+stride and emit
/// struct skeletons `auto_<base>_<stride>_t` sized by the stride with
/// fields named `field_<off>`. The user renames fields in the JSON as
/// they identify them; re-running merges new offsets (existing names win).
pub fn scrape_struct_layouts(l: &Loaded) -> Vec<(String, StructDef)> {
    // base key -> (stride, offsets relative to base).
    let mut groups: HashMap<String, (Option<i32>, BTreeSet<i32>)> = HashMap::new();
    for f in &l.fns {
        let Ok(dec) = l.decompile(f.idx) else {
            continue;
        };
        if dec.locals.is_empty() {
            continue;
        }
        // loc -> (base key, stride, addend), chasing `loc = loc_M + K`.
        let resolved: HashMap<String, (String, Option<i32>, i32)> = dec
            .locals
            .keys()
            .filter_map(|n| resolve_base(&dec.locals, n, 0, 0).map(|r| (n.clone(), r)))
            .collect();
        if resolved.is_empty() {
            continue;
        }
        for line in dec.text.lines() {
            for (loc, off) in iter_field_accesses(line) {
                if let Some((base, stride, add)) = resolved.get(&loc) {
                    if base == "0x0" {
                        continue; // NULL-sentinel temps, not a struct base
                    }
                    groups
                        .entry(base.clone())
                        .and_modify(|(s, offs)| {
                            if s.is_none() {
                                *s = *stride;
                            }
                            offs.insert(add + off);
                        })
                        .or_insert_with(|| (*stride, BTreeSet::from([add + off])));
                }
            }
        }
    }
    let mut out: Vec<(String, StructDef)> = groups
        .into_iter()
        .map(|(base, (stride, offs))| {
            let max_off = offs.iter().copied().max().unwrap_or(0);
            let size = stride.unwrap_or((max_off + 4).max(4));
            let fields: BTreeMap<i32, String> = offs
                .into_iter()
                .filter(|o| stride.is_none_or(|s| *o < s))
                .map(|o| (o, format!("field_{o}")))
                .collect();
            let name = match stride {
                Some(s) => format!("auto_{base}_{s}_t"),
                None => format!("auto_{base}_t"),
            };
            (name, StructDef { size, fields })
        })
        .filter(|(_, d)| !d.fields.is_empty())
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Resolve a loc's base transitively (`loc = loc_M + K` chains): returns
/// (base key, stride, total addend).
fn resolve_base(
    decls: &HashMap<String, LocalDecl>,
    loc: &str,
    add: i32,
    depth: u8,
) -> Option<(String, Option<i32>, i32)> {
    if depth > 4 {
        return None;
    }
    let d = decls.get(loc)?;
    if let Some(v) = d.base_const {
        return Some((format!("{v:#x}"), d.stride, add));
    }
    if let Some(v) = d.base_deref {
        return Some((format!("{v:#x}"), d.stride, add));
    }
    let (bl, k) = d.base_loc.as_ref()?;
    resolve_base(decls, bl, add + k, depth + 1)
}

/// Merge scraped skeletons into an existing `auto.json` text (existing
/// field names win; new offsets and types are appended). Returns the JSON
/// to write.
pub fn merge_struct_json(
    existing: &str,
    scraped: &[(String, StructDef)],
) -> Result<String, String> {
    let mut file: HashMap<String, StructFileDef> =
        serde_json::from_str(existing).unwrap_or_default();
    for (name, def) in scraped {
        let entry = file.entry(name.clone()).or_default();
        if entry.size.is_none() {
            entry.size = Some(def.size);
        }
        for (off, fname) in &def.fields {
            entry
                .fields
                .entry(off.to_string())
                .or_insert_with(|| fname.clone());
        }
    }
    serde_json::to_string_pretty(&file).map_err(|e| e.to_string())
}

/// Ghidra-style struct typing on one identity-C line:
/// `*(<int>*)((loc_X) + (K))` -> `(loc_X->f)` and the bare address form
/// `((loc_X) + (K))` -> `(&loc_X->f)` when a struct type is applied to
/// loc_X and K is a known field offset. Unresolved shapes stay as-is.
fn rewrite_struct_fields(line: &str, types: &HashMap<String, String>, db: &StructDb) -> String {
    let mut out = String::with_capacity(line.len() + 32);

    // Pass 1: deref reads/writes.
    const DEREF: &str = "*(<int>*)((";
    let mut rest = line;
    loop {
        match rest.find(DEREF) {
            None => {
                out.push_str(rest);
                break;
            }
            Some(p) => {
                out.push_str(&rest[..p]);
                let after = &rest[p + DEREF.len()..];
                match parse_loc_field(after) {
                    Some((loc, off, consumed)) => match field_of(types, db, &loc, off) {
                        Some(f) => {
                            out.push_str(&format!("({loc}->{f})"));
                            rest = &after[consumed..];
                        }
                        None => {
                            out.push_str(DEREF);
                            out.push_str(&after[..consumed]);
                            rest = &after[consumed..];
                        }
                    },
                    None => {
                        out.push_str(DEREF);
                        rest = after;
                    }
                }
            }
        }
    }

    // Pass 2: bare address form (e.g. passed to a function).
    let mid = out;
    let mut out = String::with_capacity(mid.len() + 8);
    let mut rest = mid.as_str();
    const ADDR: &str = "((";
    loop {
        match rest.find(ADDR) {
            None => {
                out.push_str(rest);
                break;
            }
            Some(p) => {
                out.push_str(&rest[..p]);
                let after = &rest[p + ADDR.len()..];
                match parse_loc_field(after) {
                    Some((loc, off, consumed)) => match field_of(types, db, &loc, off) {
                        Some(f) => {
                            out.push_str(&format!("(&{loc}->{f})"));
                            rest = &after[consumed..];
                        }
                        None => {
                            out.push_str(ADDR);
                            out.push_str(&after[..consumed]);
                            rest = &after[consumed..];
                        }
                    },
                    None => {
                        out.push_str(ADDR);
                        rest = after;
                    }
                }
            }
        }
    }
    out
}

/// Parse a numeric literal: decimal or 0x-prefixed hex.
pub fn parse_num(t: &str) -> Option<i32> {
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i32::from_str_radix(h, 16).ok()
    } else {
        t.parse::<i32>().ok()
    }
}

/// Parse a `loc_N = ...;` line that builds an address: an optional
/// `index * stride` term plus a base that is a constant, a dereferenced
/// global, or another local (chained, e.g. `loc_20 = (loc_24) + (824);`).
/// Recognizes the identity-C shapes emitted by `fmt_function_lines`;
/// returns `None` for anything else (loads, copies, comparisons).
pub fn parse_local_decl(line: &str) -> Option<(String, LocalDecl)> {
    // Normalize: drop all whitespace and the trailing `;`.
    let t: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    let t = t.strip_suffix(';')?;
    let (name, rhs) = t.split_once('=')?;
    if !name.starts_with("loc_") || !name[4..].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut d = LocalDecl {
        index: None,
        stride: None,
        base_const: None,
        base_deref: None,
        base_loc: None,
    };

    // Base term: `218100` | `(218100)` | `*(<int>*(0xf0850))` | `loc_M` |
    // `(loc_M)`. Returns true when one of them was recognized.
    fn base_operand(s: &str, d: &mut LocalDecl) -> bool {
        let inner = s
            .strip_prefix('(')
            .and_then(|x| x.strip_suffix(')'))
            .unwrap_or(s);
        if let Some(h) = inner
            .strip_prefix("*(<int>*)(")
            .and_then(|x| x.strip_suffix(')'))
        {
            d.base_deref = parse_num(h);
            return d.base_deref.is_some();
        }
        let is_loc = |w: &str| {
            w.len() > 4 && w.starts_with("loc_") && w[4..].bytes().all(|b| b.is_ascii_digit())
        };
        if is_loc(inner) {
            d.base_loc = Some((inner.to_string(), 0));
            return true;
        }
        d.base_const = parse_num(inner);
        d.base_const.is_some()
    }

    if let Some(p) = rhs.find(")+(") {
        let l = rhs[..p + 1].to_string();
        let r = format!("({}", &rhs[p + 3..]);
        let inner = l
            .strip_prefix('(')
            .and_then(|x| x.strip_suffix(')'))
            .map(str::to_string)?;
        if inner.starts_with("loc_") {
            // `(loc_M) + (K)` — chained base with an addend.
            let mut dd = LocalDecl {
                index: None,
                stride: None,
                base_const: None,
                base_deref: None,
                base_loc: None,
            };
            if !base_operand(&l, &mut dd) || dd.base_loc.is_none() {
                return None;
            }
            let k = r
                .trim_start_matches('(')
                .trim_end_matches(')')
                .parse::<i32>()
                .ok()?;
            dd.base_loc.as_mut().unwrap().1 = k;
            d.base_loc = dd.base_loc;
        } else {
            // `((idx) * (S)) + (base)`
            let (a, b) = inner.split_once("*(")?;
            let idx = a.trim_start_matches('(').trim_end_matches(')');
            if idx.is_empty() || !idx.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            d.index = Some(idx.to_string());
            d.stride = b.trim_end_matches(')').parse().ok();
            d.stride?;
            if !base_operand(&r, &mut d) {
                return None;
            }
        }
    } else {
        // `(base)` / `base` only.
        if !base_operand(rhs, &mut d) {
            return None;
        }
    }
    Some((name.to_string(), d))
}

/// Raw bytecode bytes of one instruction, hex formatted (`0C FF FF FF FF`).
pub fn insn_bytes(ins: &Insn) -> String {
    let mut b = vec![ins.op as u8];
    if ins.op.has_int32_operand() {
        b.extend_from_slice(&ins.operand.unwrap_or(0).to_le_bytes());
    } else if ins.op.has_byte_operand() {
        b.push(ins.operand.unwrap_or(0) as u8);
    }
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Escape control characters so strings stay on one displayed line.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u8)),
            c => out.push(c),
        }
    }
    out
}

/// Short human-readable description of an opcode (for hover tooltips).
/// Per-opcode tooltip text. English comes from the built-in table (the
/// source-of-truth oracle text); other languages come from the translation
/// catalog (`opcode_help` section in `lang/*.json`), falling back to English.
pub fn opcode_help(op: Opcode, lang: crate::i18n::LangId) -> std::borrow::Cow<'static, str> {
    use crate::i18n::LangId;
    if lang == LangId::EN {
        return std::borrow::Cow::Borrowed(opcode_help_en(op));
    }
    match crate::i18n::opcode_help(lang, op.name()) {
        Some(s) => std::borrow::Cow::Owned(s),
        None => std::borrow::Cow::Borrowed(opcode_help_en(op)),
    }
}

fn opcode_help_en(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Undef => "undefined opcode",
        Ignore => "no-op, ignored by the interpreter",
        Break => "VM breakpoint (debugger trap)",
        Enter => "function prologue: allocate stack frame (operand = frame size)",
        Leave => "function epilogue: free frame and return to caller",
        Call => "call function: address popped from stack (syscall if negative)",
        Push => "push top of opstack onto the call stack",
        Pop => "discard the value popped from the call stack",
        Const => "push 32-bit constant (operand); often an address or syscall num",
        Local => "push address of a local: programStack + frame + operand",
        Jump => "indirect jump: target address popped from stack",
        Eq => "pop a, b; if a == b jump to target",
        Ne => "pop a, b; if a != b jump to target",
        Lti => "pop a, b; if a < b (signed) jump to target",
        Lei => "pop a, b; if a <= b (signed) jump to target",
        Gti => "pop a, b; if a > b (signed) jump to target",
        Gei => "pop a, b; if a >= b (signed) jump to target",
        Ltu => "pop a, b; if a < b (unsigned) jump to target",
        Leu => "pop a, b; if a <= b (unsigned) jump to target",
        Gtu => "pop a, b; if a > b (unsigned) jump to target",
        Geu => "pop a, b; if a >= b (unsigned) jump to target",
        Eqf => "pop float a, b; if a == b jump to target",
        Nef => "pop float a, b; if a != b jump to target",
        Ltf => "pop float a, b; if a < b jump to target",
        Lef => "pop float a, b; if a <= b jump to target",
        Gtf => "pop float a, b; if a > b jump to target",
        Gef => "pop float a, b; if a >= b jump to target",
        Load1 => "read 1 byte from memory at address on stack top",
        Load2 => "read 2 bytes (u16) from memory",
        Load4 => "read 4 bytes (i32) from memory",
        Store1 => "pop value, addr; write lowest byte to memory",
        Store2 => "pop value, addr; write 2 bytes to memory",
        Store4 => "pop value, addr; write 4 bytes to memory",
        Arg => "marshal argument: copy from opstack to call stack area (operand = offset)",
        BlockCopy => "pop count, src, dest; copy a block of memory",
        Sex8 => "sign-extend lowest byte to 32 bits",
        Sex16 => "sign-extend lowest 16 bits to 32 bits",
        Negi => "negate integer on stack top",
        Add => "pop a, b; push a + b",
        Sub => "pop a, b; push a - b",
        Divi => "pop a, b; push a / b (signed)",
        Divu => "pop a, b; push a / b (unsigned)",
        Modi => "pop a, b; push a % b (signed)",
        Modu => "pop a, b; push a % b (unsigned)",
        Muli => "pop a, b; push a * b",
        Mulu => "pop a, b; push a * b (unsigned low 32 bits)",
        Band => "pop a, b; push a & b",
        Bor => "pop a, b; push a | b",
        Bxor => "pop a, b; push a ^ b",
        Bcom => "bitwise NOT (~a) of stack top",
        Lsh => "pop a, b; push a << b",
        Rshi => "pop a, b; push a >> b (arithmetic)",
        Rshu => "pop a, b; push a >> b (logical)",
        Negf => "negate float on stack top",
        AddF => "pop float a, b; push a + b",
        SubF => "pop float a, b; push a - b",
        DivF => "pop float a, b; push a / b",
        MulF => "pop float a, b; push a * b",
        Cvif => "convert int to float",
        Cvfi => "convert float to int (truncating)",
    }
}

/// Per-function metadata collected at load time (mirrors `probe_inventory`).
pub struct FnInfo {
    pub idx: usize,
    pub entry: usize,
    pub end: usize,
    /// Editable display name; `None` = unnamed (`fn[idx]` shown instead).
    pub name: Option<String>,
    /// `(syscall num, resolved name or "?")` in program order.
    pub traps: Vec<(u32, String)>,
    /// Distinct literal strings referenced by this function.
    pub strings: Vec<String>,
    /// Lowercased blob for the filter box.
    pub search: String,
}

impl FnInfo {
    pub fn len(&self) -> usize {
        self.end - self.entry
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.entry
    }

    /// Display name; unnamed functions get the `fn_<idx>` placeholder
    /// (matches the identity-C call convention and the rename box).
    pub fn display_name(&self) -> std::borrow::Cow<'_, str> {
        match &self.name {
            Some(n) => std::borrow::Cow::Borrowed(n),
            None => std::borrow::Cow::Owned(format!("fn_{}", self.idx)),
        }
    }

    /// Rebuild the lowercased filter blob from current metadata.
    pub fn rebuild_search(&mut self) {
        let mut s = self
            .name
            .clone()
            .unwrap_or_else(|| format!("fn_{}", self.idx));
        s.push_str(&format!(" fn{} {} ", self.idx, self.entry));
        for (n, tn) in &self.traps {
            s.push_str(&format!("{n} {tn} "));
        }
        for st in &self.strings {
            s.push_str(st);
            s.push(' ');
        }
        self.search = s.to_lowercase();
    }
}

/// Whole-image call graph layout: layered columns by call depth.
pub struct CallGraph {
    /// Call depth (column index) per fn idx.
    pub depth: Vec<usize>,
    /// Row within the column, per fn idx.
    pub row: Vec<usize>,
    /// Functions nobody calls (entry points).
    pub roots: Vec<usize>,
    pub max_depth: usize,
    /// Column occupancy (rows per depth).
    pub col_len: Vec<usize>,
}

/// Everything the UI needs about an opened QVM.
pub struct Loaded {
    pub path: PathBuf,
    pub qvm: Qvm,
    pub d: Disassembly,
    /// One enriched text line per instruction (indexed by insn number):
    /// disasm plus `;` comments for strings, syscalls and call targets.
    pub lines: Vec<String>,
    pub fns: Vec<FnInfo>,
    /// Literal-segment strings: `(vm address, text)` in address order.
    pub lit_strings: Vec<(i32, String)>,
    /// String address -> functions referencing it.
    pub string_refs: BTreeMap<i32, Vec<usize>>,
    /// Syscall num -> functions performing it.
    pub trap_users: BTreeMap<u32, Vec<usize>>,
    /// Callee fn index -> caller fn indices (direct CONST+CALL xrefs).
    pub callers: BTreeMap<usize, Vec<usize>>,
    /// Caller fn index -> callee fn indices (direct CONST+CALL xrefs).
    pub callees: BTreeMap<usize, Vec<usize>>,
    /// Function entry insn -> fn index.
    pub entry_to_idx: HashMap<usize, usize>,
    /// Known function display name -> fn index.
    pub name_to_idx: HashMap<String, usize>,
    /// All syscall names seen in this module (for syntax highlighting).
    pub trap_names: HashSet<String>,
    /// Whole-image call graph layout.
    pub callgraph: CallGraph,
    /// `(entry, end)` per fn index, precomputed for pane tinting.
    pub fn_ranges: Vec<(usize, usize)>,
    /// BSS segment (globals): [start, end) in VM memory.
    pub bss_range: (i32, i32),
    /// BSS address referenced by CONST -> functions referencing it.
    pub bss_refs: BTreeMap<i32, Vec<usize>>,
    /// Any CONST memory operand (not a call target) -> functions
    /// referencing it. Backs the `mem_hint` tooltips and address xrefs.
    pub const_refs: BTreeMap<i32, Vec<usize>>,
    /// Applied struct types: fn entry insn -> (loc name -> type name).
    /// Persisted in a sidecar `<name>.types.json` next to the QVM.
    pub types: HashMap<usize, HashMap<String, String>>,
}

impl Loaded {
    /// Load a QVM and precompute everything the panes show.
    pub fn open(path: &Path) -> Result<Loaded, String> {
        let qvm = load(path).map_err(|e| format!("load: {e}"))?;
        let mut qvm = qvm;
        let map_sibling = path.with_extension("map");
        if map_sibling.is_file() {
            match load_map(map_sibling.to_str().unwrap_or_default()) {
                Ok(syms) => {
                    for (entry, name) in syms {
                        qvm.names.insert(entry, name);
                    }
                }
                Err(e) => return Err(format!("load {}: {e}", map_sibling.display())),
            }
        }

        // Applied struct types (sidecar next to the QVM); corrupt file = fresh.
        let mut types: HashMap<usize, HashMap<String, String>> = HashMap::new();
        let types_sidecar = path.with_extension("types.json");
        if types_sidecar.is_file() {
            if let Ok(text) = std::fs::read_to_string(&types_sidecar) {
                if let Ok(t) = serde_json::from_str(&text) {
                    types = t;
                }
            }
        }

        let d = disassemble(&qvm).map_err(|e| format!("disasm: {e}"))?;

        // Enriched disasm lines in one pass.
        let mut lines: Vec<String> = Vec::with_capacity(d.insns.len());
        for i in 0..d.insns.len() {
            let ins = &d.insns[i];
            let mut line = format!("{ins}");
            if ins.op == Opcode::Const {
                if let Some(opd) = ins.operand {
                    if let Some(s) = qvm.string_at(opd) {
                        line.push_str(&format!("  ; \"{}\"", escape(&s)));
                    }
                    if let Some(next) = d.insns.get(i + 1) {
                        if next.op == Opcode::Call && opd < 0 {
                            let num = (-1 - opd) as u32;
                            match trap_name(qvm.module, num) {
                                Some(n) => line.push_str(&format!("  ; syscall {num} {n}")),
                                None => line.push_str(&format!("  ; syscall {num}")),
                            }
                        } else if next.op == Opcode::Call && opd >= 0 {
                            let t = opd as usize;
                            match qvm.name_for_fn(t) {
                                Some(n) => line.push_str(&format!("  ; call {n}")),
                                None => line.push_str(&format!("  ; call fn@{t}")),
                            }
                        }
                    }
                }
            }
            lines.push(line);
        }

        let ranges = qvm::build_functions(&d);
        let mut fns = Vec::with_capacity(ranges.len());
        let mut string_refs: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
        let mut trap_users: BTreeMap<u32, Vec<usize>> = BTreeMap::new();

        for (idx, &(start, end)) in ranges.iter().enumerate() {
            let mut traps = Vec::new();
            let mut strings = Vec::new();
            for (k, ins) in d.insns[start..end].iter().enumerate() {
                let Some(opd) = ins.operand else { continue };
                if ins.op != Opcode::Const {
                    continue;
                }
                if let Some(s) = qvm.string_at(opd) {
                    if !strings.contains(&s) {
                        strings.push(s.clone());
                    }
                    string_refs.entry(opd).or_default().push(idx);
                }
                if opd < 0 {
                    if let Some(next) = d.insns[start..end].get(k + 1) {
                        if next.op == Opcode::Call {
                            let num = (-1 - opd) as u32;
                            let n = trap_name(qvm.module, num).unwrap_or("?").to_string();
                            if !traps.contains(&(num, n.clone())) {
                                traps.push((num, n));
                            }
                            trap_users.entry(num).or_default().push(idx);
                        }
                    }
                }
            }

            let name = qvm.name_for_fn(start).map(str::to_string);
            let mut info = FnInfo {
                idx,
                entry: start,
                end,
                name,
                traps,
                strings,
                search: String::new(),
            };
            info.rebuild_search();
            fns.push(info);
        }

        // Literal-segment string table (address order).
        let mut lit_strings = Vec::new();
        let base = qvm.data_length;
        let top = qvm.data_length + qvm.lit_length;
        let mut a = base;
        while a < top {
            match qvm.string_at(a) {
                Some(s) => {
                    let step = s.len() as i32 + 1;
                    lit_strings.push((a, s));
                    a += step;
                }
                None => a += 1,
            }
        }

        // Name/entry lookup tables for navigation and highlighting.
        let mut entry_to_idx: HashMap<usize, usize> = HashMap::new();
        let mut name_to_idx: HashMap<String, usize> = HashMap::new();
        let mut trap_names: HashSet<String> = HashSet::new();
        for f in &fns {
            entry_to_idx.entry(f.entry).or_insert(f.idx);
            if let Some(n) = &f.name {
                name_to_idx.insert(n.clone(), f.idx);
            }
            for (_, tn) in &f.traps {
                trap_names.insert(tn.clone());
            }
        }

        // Direct call graph: `CONST <entry>; CALL` pairs.
        let mut callers: BTreeMap<usize, std::collections::BTreeSet<usize>> = BTreeMap::new();
        let mut callees: BTreeMap<usize, std::collections::BTreeSet<usize>> = BTreeMap::new();
        for (idx, &(start, end)) in ranges.iter().enumerate() {
            for w in start..end.saturating_sub(1) {
                let ins = &d.insns[w];
                if ins.op != Opcode::Const {
                    continue;
                }
                let Some(opd) = ins.operand else { continue };
                if opd < 0 || d.insns[w + 1].op != Opcode::Call {
                    continue;
                }
                if let Some(&ti) = entry_to_idx.get(&(opd as usize)) {
                    if ti != idx {
                        callees.entry(idx).or_default().insert(ti);
                        callers.entry(ti).or_default().insert(idx);
                    }
                }
            }
        }
        let callers: BTreeMap<usize, Vec<usize>> = callers
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        let callees: BTreeMap<usize, Vec<usize>> = callees
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        // Whole-image call graph layout: BFS depth from the roots.
        let n = fns.len();
        let mut cg = CallGraph {
            depth: vec![0; n],
            row: vec![0; n],
            roots: Vec::new(),
            max_depth: 0,
            col_len: Vec::new(),
        };
        for i in 0..n {
            if callers.get(&i).is_none_or(|v| v.is_empty()) {
                cg.roots.push(i);
            }
        }
        let mut seen = vec![false; n];
        let mut queue = std::collections::VecDeque::new();
        for &r in &cg.roots {
            if !seen[r] {
                seen[r] = true;
                queue.push_back(r);
            }
        }
        if queue.is_empty() && n > 0 {
            // Everything inside a call cycle: start anywhere.
            seen[0] = true;
            queue.push_back(0);
        }
        while let Some(c) = queue.pop_front() {
            for t in callees.get(&c).into_iter().flatten() {
                if *t < n && !seen[*t] {
                    seen[*t] = true;
                    cg.depth[*t] = cg.depth[c] + 1;
                    queue.push_back(*t);
                }
            }
        }
        // Functions reachable only through cycles: one extra shared column.
        let park = cg.depth.iter().copied().max().unwrap_or(0) + 1;
        for (i, s) in seen.iter().enumerate() {
            if !s {
                cg.depth[i] = park;
            }
        }
        cg.max_depth = cg.depth.iter().copied().max().unwrap_or(0);
        let mut rows_by_col: Vec<usize> = vec![0; cg.max_depth + 1];
        for (i, d) in cg.depth.iter().enumerate() {
            cg.row[i] = rows_by_col[*d];
            rows_by_col[*d] += 1;
        }
        cg.col_len = rows_by_col;

        let fn_ranges: Vec<(usize, usize)> = fns.iter().map(|f| (f.entry, f.end)).collect();

        // BSS explorer: CONST operands pointing into the BSS segment.
        let bss_range = (
            qvm.data_length + qvm.lit_length,
            qvm.data_length + qvm.lit_length + qvm.bss_length,
        );
        let mut bss_refs: BTreeMap<i32, std::collections::BTreeSet<usize>> = BTreeMap::new();
        for (idx, &(start, end)) in ranges.iter().enumerate() {
            for ins in &d.insns[start..end] {
                if ins.op != Opcode::Const {
                    continue;
                }
                let Some(opd) = ins.operand else { continue };
                if opd >= bss_range.0 && opd < bss_range.1 {
                    bss_refs.entry(opd).or_default().insert(idx);
                }
            }
        }
        let bss_refs: BTreeMap<i32, Vec<usize>> = bss_refs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        // References to any memory address loaded via CONST (data / lit /
        // BSS globals). CONST immediately followed by CALL is a call target,
        // not memory.
        let mut const_refs: BTreeMap<i32, std::collections::BTreeSet<usize>> = BTreeMap::new();
        for (idx, &(start, end)) in ranges.iter().enumerate() {
            for (k, ins) in d.insns[start..end].iter().enumerate() {
                if ins.op != Opcode::Const {
                    continue;
                }
                let Some(opd) = ins.operand else { continue };
                if opd < 4 {
                    continue;
                }
                let calls_next = d
                    .insns
                    .get(start + k + 1)
                    .is_some_and(|n| n.op == Opcode::Call);
                if !calls_next {
                    const_refs.entry(opd).or_default().insert(idx);
                }
            }
        }
        let const_refs: BTreeMap<i32, Vec<usize>> = const_refs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();

        Ok(Loaded {
            path: path.to_path_buf(),
            qvm,
            d,
            lines,
            fns,
            lit_strings,
            string_refs,
            trap_users,
            callers,
            callees,
            entry_to_idx,
            name_to_idx,
            trap_names,
            callgraph: cg,
            fn_ranges,
            bss_range,
            bss_refs,
            const_refs,
            types,
        })
    }

    /// Struct type applied to a local of this function, if any.
    pub fn local_type(&self, fn_entry: usize, loc: &str) -> Option<&str> {
        self.types.get(&fn_entry)?.get(loc).map(String::as_str)
    }

    /// Heuristic auto-naming for a clean image:
    /// - the first function (the engine entry point) becomes `vmMain`;
    /// - small functions that only marshal arguments and issue exactly one
    ///   syscall become `trap_<Name>` thunks (unknown syscalls become
    ///   `syscall_<num>`).
    ///
    /// Already-named functions are skipped. Returns (named, thunks).
    pub fn auto_name_functions(&mut self) -> (usize, usize) {
        let mut named = 0usize;
        let mut thunks = 0usize;
        let mut used: HashSet<String> = self.fns.iter().filter_map(|f| f.name.clone()).collect();

        // vmMain: the engine calls the first function of the image.
        if let Some(f) = self.fns.first_mut() {
            if f.name.is_none() && !used.contains("vmMain") {
                f.name = Some("vmMain".into());
                f.rebuild_search();
                used.insert("vmMain".into());
                named += 1;
            }
        }

        // Syscall thunks.
        for f in &mut self.fns {
            if f.name.is_some() || f.idx == 0 || f.traps.len() != 1 || f.len() > 48 {
                continue;
            }
            // A thunk never calls other functions.
            if !self.callees.get(&f.idx).is_none_or(|v| v.is_empty()) {
                continue;
            }
            let (num, tname) = &f.traps[0];
            let base = if tname == "?" {
                format!("syscall_{num}")
            } else {
                tname.clone()
            };
            let mut cand = base.clone();
            let mut k = 2;
            while used.contains(&cand) {
                cand = format!("{base}_{k}");
                k += 1;
            }
            used.insert(cand.clone());
            f.name = Some(cand);
            f.rebuild_search();
            named += 1;
            thunks += 1;
        }
        (named, thunks)
    }

    /// Apply/clear a struct type on a local; persists to the sidecar file
    /// next to the QVM (`<name>.types.json`).
    pub fn set_local_type(
        &mut self,
        fn_entry: usize,
        loc: &str,
        ty: Option<&str>,
    ) -> Result<PathBuf, String> {
        let m = self.types.entry(fn_entry).or_default();
        match ty {
            Some(t) => {
                m.insert(loc.to_string(), t.to_string());
            }
            None => {
                m.remove(loc);
            }
        }
        if m.is_empty() {
            self.types.remove(&fn_entry);
        }
        let out = self.path.with_extension("types.json");
        let text = serde_json::to_string_pretty(&self.types).map_err(|e| e.to_string())?;
        std::fs::write(&out, text).map_err(|e| format!("write {}: {e}", out.display()))?;
        Ok(out)
    }

    /// CFG of one function.
    pub fn cfg(&self, idx: usize) -> Result<qvm::CFG, String> {
        let f = self.fns.get(idx).ok_or("bad fn index")?;
        let data = self.qvm.data_int32();
        qvm::build_cfg(&self.d, (f.entry, f.end), &data).ok_or_else(|| "degenerate CFG".into())
    }

    /// Index of the image entry function (`vmMain`), best effort.
    pub fn entry_fn(&self) -> usize {
        for f in &self.fns {
            if let Some(n) = &f.name {
                if n.eq_ignore_ascii_case("vmMain") || n.eq_ignore_ascii_case("vm_main") {
                    return f.idx;
                }
            }
        }
        self.callgraph.roots.first().copied().unwrap_or(0)
    }

    /// One byte of VM memory (data | lit | zeroed bss) at a masked address.
    pub fn mem_byte(&self, addr: i32) -> u8 {
        if addr < 0 {
            return 0;
        }
        let a = addr as usize;
        let dl = self.qvm.data_length as usize;
        if a < dl {
            self.qvm.data.get(a).copied().unwrap_or(0)
        } else if a < dl + self.qvm.lit_length as usize {
            self.qvm.lit.get(a - dl).copied().unwrap_or(0)
        } else {
            0 // bss
        }
    }

    fn mem_i32(&self, addr: i32) -> i32 {
        i32::from_le_bytes([
            self.mem_byte(addr),
            self.mem_byte(addr.wrapping_add(1)),
            self.mem_byte(addr.wrapping_add(2)),
            self.mem_byte(addr.wrapping_add(3)),
        ])
    }

    /// Human-readable hint for a VM memory address: which segment it falls
    /// into (data / lit / BSS), what currently lives there (C string, 32-bit
    /// value, pointer to a string, runtime global) and how many functions
    /// reference it. `None` for anything outside VM memory (call targets,
    /// syscalls, the NULL-sentinel word at 0..4). Phrases come from the
    /// translation catalog (`mem_hints` section), falling back to English.
    pub fn mem_hint(&self, addr: i32, lang: crate::i18n::LangId) -> Option<String> {
        use crate::i18n::mem_hint_phrase;
        if addr < 4 {
            return None;
        }
        let q = &self.qvm;
        let lit_end = q.data_length + q.lit_length;
        // Segment names per GLOSSARY (данные / литералы / BSS).
        let seg = if addr < q.data_length {
            mem_hint_phrase(lang, "seg.data").unwrap_or_else(|| "data".into())
        } else if addr < lit_end {
            mem_hint_phrase(lang, "seg.lit").unwrap_or_else(|| "lit".into())
        } else if addr < lit_end + q.bss_length {
            "BSS".to_string()
        } else {
            return None;
        };

        let quote = |s: &str| -> String {
            let mut shown: String = s.chars().take(48).collect();
            if s.chars().count() > 48 {
                shown.push('…');
            }
            format!("\"{}\"", escape(&shown))
        };

        let mut hint = format!("[{addr:#x}] {seg}");
        if let Some(s) = q.string_at(addr) {
            hint.push_str(&format!(" = {}", quote(&s)));
        } else if seg == "BSS" {
            hint.push_str(&format!(
                " = {}",
                mem_hint_phrase(lang, "hint.bss")
                    .unwrap_or_else(|| "runtime global (zero at load)".into())
            ));
        } else {
            let v = self.mem_i32(addr);
            if v > 4 {
                if let Some(s) = q.string_at(v) {
                    hint.push_str(&format!(
                        " = {} {}",
                        mem_hint_phrase(lang, "hint.ptr").unwrap_or_else(|| "ptr ->".into()),
                        quote(&s)
                    ));
                    return Some(hint);
                }
            }
            hint.push_str(&format!(" = {v} (0x{v:08x})"));
            // Data globals are often float constants (lcc does not 16-align
            // anything): show the f32 reading when the bits are sane.
            let f = f32::from_bits(v as u32);
            if f.is_finite() && f.abs() >= 1e-6 && f.abs() <= 1e9 {
                hint.push_str(&format!(" / {f} f32"));
            }
        }
        if let Some(r) = self.const_refs.get(&addr) {
            if !r.is_empty() {
                let refs = mem_hint_phrase(lang, "hint.refs")
                    .unwrap_or_else(|| "referenced by %N fn(s)".into())
                    .replace("%N", &r.len().to_string());
                hint.push('\n');
                hint.push_str(&refs);
            }
        }
        Some(hint)
    }

    /// Decompiled identity C for one function (uncached; the GUI caches).
    /// Returns the text, a per-line insn-range map for pane sync, and the
    /// label -> C-line index for goto navigation.
    pub fn decompile(&self, idx: usize) -> Result<Decompiled, String> {
        let f = self.fns.get(idx).ok_or("bad fn index")?;
        let data = self.qvm.data_int32();
        let cfg = qvm::build_cfg(&self.d, (f.entry, f.end), &data).ok_or("degenerate CFG")?;
        let frame = self.d.insns[cfg.entry].operand.unwrap_or(0);
        let fun = qvm::decompile_function(&self.d, &cfg, frame, &data);
        let lines = qvm::fmt_function_lines(&fun, &self.qvm);
        // Ghidra-style struct typing: applied types rewrite field accesses
        // (`*(<int>*)((loc_X) + (K))` -> `(loc_X->f)`) before caching.
        let fn_types = self.types.get(&f.entry).cloned().unwrap_or_default();
        let db = struct_db();
        let lines: Vec<(String, (usize, usize))> = lines
            .into_iter()
            .map(|(t, r)| (rewrite_struct_fields(&t, &fn_types, &db), r))
            .collect();
        let text: String = lines
            .iter()
            .map(|(t, _)| t.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let labels: HashMap<usize, usize> = lines
            .iter()
            .enumerate()
            .filter_map(|(i, (t, _))| {
                let t = t.trim();
                let n = t.strip_prefix('L')?.strip_suffix(':')?;
                n.parse::<usize>().ok().map(|n| (n, i))
            })
            .collect();
        let ranges: Vec<(usize, usize)> = lines.iter().map(|(_, r)| *r).collect();
        // Track `loc_N = ...` address initializations for hover hints.
        let mut locals: HashMap<String, LocalDecl> = HashMap::new();
        for (t, _) in &lines {
            if let Some((n, d)) = parse_local_decl(t) {
                locals.entry(n).or_insert(d);
            }
        }
        Ok(Decompiled {
            text: text.into(),
            ranges: ranges.into(),
            labels: labels.into(),
            locals: locals.into(),
        })
    }

    /// Disasm pane slice for one function (instruction-index range).
    pub fn fn_range(&self, idx: usize) -> Option<std::ops::Range<usize>> {
        let f = self.fns.get(idx)?;
        Some(f.entry..f.end)
    }

    /// Persist renames as a q3asm-compatible `.map` next to the QVM.
    /// The previous file is kept as `.map.bak` before overwriting.
    pub fn save_map(&self) -> Result<PathBuf, String> {
        let mut named: Vec<(usize, &str)> = self
            .fns
            .iter()
            .filter_map(|f| f.name.as_deref().map(|n| (f.entry, n)))
            .collect();
        named.sort_by_key(|&(e, _)| e);
        let out = self.path.with_extension("map");
        if out.is_file() {
            let bak = self.path.with_extension("map.bak");
            std::fs::copy(&out, &bak).map_err(|e| format!("backup {}: {e}", bak.display()))?;
        }
        let mut text = String::from("# resq-gui renames (q3asm -m compatible)\n");
        for (entry, name) in named {
            text.push_str(&format!("0 {entry:x} {name}\n"));
        }
        std::fs::write(&out, text).map_err(|e| format!("write {}: {e}", out.display()))?;
        Ok(out)
    }

    /// Apply a rename from the UI.
    pub fn rename(&mut self, idx: usize, new_name: &str) {
        let Some(f) = self.fns.get_mut(idx) else {
            return;
        };
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            f.name = None;
            self.qvm.names.remove(&f.entry);
        } else {
            f.name = Some(trimmed.to_string());
            self.qvm.names.insert(f.entry, trimmed.to_string());
        }
        f.rebuild_search();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::LangId;

    #[test]
    fn rebuild_search_covers_name_traps_strings() {
        let mut f = FnInfo {
            idx: 7,
            entry: 100,
            end: 200,
            name: Some("G_InitGame".into()),
            traps: vec![(5, "trap_SendServerCommand".into())],
            strings: vec!["mapchange".into()],
            search: String::new(),
        };
        f.rebuild_search();
        assert!(f.search.contains("g_initgame"));
        assert!(f.search.contains("sendservercommand"));
        assert!(f.search.contains("mapchange"));
        assert!(f.search.contains("fn7 100 "));

        f.name = None;
        f.rebuild_search();
        assert!(!f.search.contains("g_initgame"));
    }

    #[test]
    fn escape_keeps_control_chars_visible() {
        assert_eq!(escape("a\nb\"c\\d"), "a\\nb\\\"c\\\\d");
        assert_eq!(escape("\u{1}"), "\\x01");
        // Non-ASCII passes through untouched.
        assert_eq!(escape("привет"), "привет");
    }

    #[test]
    fn mem_hint_classifies_segments_and_rejects_non_memory() {
        // Smoke fixture: data/lit empty, BSS covers [0, 64).
        let dir = std::env::temp_dir().join(format!("resq_gui_hint_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("hint.qvm");
        let code = {
            let mut c = vec![3u8]; // ENTER 16
            c.extend_from_slice(&16i32.to_le_bytes());
            c.push(4); // LEAVE 16
            c.extend_from_slice(&16i32.to_le_bytes());
            c
        };
        let header: [i32; 8] = [
            qvm::loader::VM_MAGIC as i32,
            2,
            32,
            code.len() as i32,
            32 + code.len() as i32,
            0,  // dataLength
            0,  // litLength
            64, // bssLength
        ];
        let mut bytes = Vec::new();
        for v in header {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&code);
        std::fs::write(&path, &bytes).expect("write");

        let mut l = Loaded::open(&path).expect("open");
        // NULL sentinel and outside-of-memory addresses get no hint.
        assert_eq!(l.mem_hint(0, LangId::EN), None);
        assert_eq!(l.mem_hint(-1, LangId::EN), None);
        // Call target (inside code, beyond data+lit+bss) gets no hint.
        assert_eq!(l.mem_hint(10_000, LangId::EN), None);
        // BSS address: classified + zero-at-load note (EN).
        let h = l.mem_hint(0x24, LangId::EN).expect("bss hint");
        assert!(h.starts_with("[0x24] BSS"), "{h}");
        assert!(h.contains("zero at load"), "{h}");
        // Same address in Russian: segment names and phrases translated.
        let ru = LangId::from_code("ru").expect("embedded ru");
        let hr = l.mem_hint(0x24, ru).expect("bss hint ru");
        assert!(hr.starts_with("[0x24] BSS"), "{hr}");
        assert!(hr.contains("обнулён при загрузке"), "{hr}");
        // No CONST refs in the trivial fixture.
        assert!(l.const_refs.is_empty());

        // Opcode help: EN identity + RU translation from the catalog.
        assert_eq!(
            opcode_help(Opcode::Enter, LangId::EN),
            opcode_help_en(Opcode::Enter)
        );
        assert!(opcode_help(Opcode::Enter, ru).contains("пролог функции"));
        assert!(opcode_help(Opcode::Const, ru).contains("константу"));

        // Struct typing: apply -> sidecar written -> reload picks it up.
        let entry = l.fns[0].entry;
        assert_eq!(l.local_type(entry, "loc_0"), None);
        let sidecar = l
            .set_local_type(entry, "loc_0", Some("example_struct_t"))
            .expect("save sidecar");
        assert!(sidecar.is_file());
        assert_eq!(l.local_type(entry, "loc_0"), Some("example_struct_t"));
        {
            let l2 = Loaded::open(&path).expect("reopen");
            assert_eq!(l2.local_type(entry, "loc_0"), Some("example_struct_t"));
        }
        l.set_local_type(entry, "loc_0", None).expect("clear type");
        assert_eq!(l.local_type(entry, "loc_0"), None);
        std::fs::remove_file(&sidecar).ok();

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn parse_local_decl_tracks_base_shapes() {
        // index * stride + absolute const base
        let (n, d) = parse_local_decl("  loc_24 = ((arg_3) * (816)) + (149584);").expect("parse");
        assert_eq!(n, "loc_24");
        assert_eq!(d.index.as_deref(), Some("arg_3"));
        assert_eq!(d.stride, Some(816));
        assert_eq!(d.base_const, Some(149584));
        assert_eq!(d.base_deref, None);

        // index * stride + dereferenced global (hex, with spaces)
        let (n, d) = parse_local_decl("  loc_20 = ((arg_3) * (1568)) + (*(< int>*)( 0xf0850));")
            .expect("parse");
        assert_eq!(n, "loc_20");
        assert_eq!(d.index.as_deref(), Some("arg_3"));
        assert_eq!(d.stride, Some(1568));
        assert_eq!(d.base_deref, Some(0xf0850));
        assert_eq!(d.base_const, None);

        // plain const base
        let (_, d) = parse_local_decl("loc_4 = (45488);").expect("parse");
        assert_eq!(d.base_const, Some(45488));
        assert_eq!(d.index, None);

        // loads / copies / non-loc lines are rejected
        assert_eq!(
            parse_local_decl("loc_28 = *(<int>*)((loc_20) + (104));"),
            None
        );
        assert_eq!(
            parse_local_decl("loc_32 = (*(<int>*)(loc_20)) + (264);"),
            None
        );
        assert_eq!(
            parse_local_decl("if ((*(<int>*)(loc_24)) != (0)) goto L94017;"),
            None
        );
        assert_eq!(parse_local_decl("arg_3 = (5);"), None);
    }

    fn test_db() -> StructDb {
        let mut fields = BTreeMap::new();
        fields.insert(704, "pers".to_string());
        fields.insert(712, "ps".to_string());
        let mut map = HashMap::new();
        map.insert("gclient_t".to_string(), StructDef { size: 1568, fields });
        StructDb { map }
    }

    fn types1() -> HashMap<String, String> {
        HashMap::from([("loc_20".to_string(), "gclient_t".to_string())])
    }

    #[test]
    fn rewrite_struct_fields_names_known_offsets() {
        let db = test_db();
        let ty = types1();

        // deref write
        assert_eq!(
            rewrite_struct_fields("  *(<int>*)((loc_20) + (704)) = 0;", &ty, &db),
            "  (loc_20->pers) = 0;"
        );
        // deref read in a comparison
        assert_eq!(
            rewrite_struct_fields(
                "  if ((*(<int>*)((loc_20) + (712))) != (0)) goto L94017;",
                &ty,
                &db
            ),
            "  if (((loc_20->ps)) != (0)) goto L94017;"
        );
        // bare address form (outer parens are part of the match)
        assert_eq!(
            rewrite_struct_fields("  f((loc_20) + (704));", &ty, &db),
            "  f(&loc_20->pers);"
        );
        // unknown offset stays as-is
        assert_eq!(
            rewrite_struct_fields("  *(<int>*)((loc_20) + (708)) = 1;", &ty, &db),
            "  *(<int>*)((loc_20) + (708)) = 1;"
        );
        // no type applied -> untouched
        assert_eq!(
            rewrite_struct_fields("  *(<int>*)((loc_24) + (704)) = 0;", &HashMap::new(), &db),
            "  *(<int>*)((loc_24) + (704)) = 0;"
        );
        // arithmetic on a dereferenced value is NOT a field access
        assert_eq!(
            rewrite_struct_fields("  loc_32 = (*(<int>*)(loc_20)) + (264);", &ty, &db),
            "  loc_32 = (*(<int>*)(loc_20)) + (264);"
        );
        // several accesses on one line
        assert_eq!(
            rewrite_struct_fields(
                "  *(<int>*)((loc_20) + (704)) = *(<int>*)((loc_20) + (712));",
                &ty,
                &db
            ),
            "  (loc_20->pers) = (loc_20->ps);"
        );
    }

    #[test]
    fn display_name_placeholder_matches_fn_convention() {
        let mut f = FnInfo {
            idx: 12,
            entry: 300,
            end: 400,
            name: None,
            traps: vec![],
            strings: vec![],
            search: String::new(),
        };
        assert_eq!(f.display_name(), "fn_12");
        f.rebuild_search();
        assert!(f.search.contains("fn_12"), "{}", f.search);
        f.name = Some("G_Spawn".into());
        assert_eq!(f.display_name(), "G_Spawn");
    }

    #[test]
    fn auto_name_names_vmmain_and_skips_named() {
        // Minimal one-function image.
        let dir = std::env::temp_dir().join(format!("resq_gui_auto_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("auto.qvm");
        let code = {
            let mut c = vec![3u8]; // ENTER 16
            c.extend_from_slice(&16i32.to_le_bytes());
            c.push(4); // LEAVE 16
            c.extend_from_slice(&16i32.to_le_bytes());
            c
        };
        let header: [i32; 8] = [
            qvm::loader::VM_MAGIC as i32,
            2,
            32,
            code.len() as i32,
            32 + code.len() as i32,
            0,
            0,
            64,
        ];
        let mut bytes = Vec::new();
        for v in header {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes.extend_from_slice(&code);
        std::fs::write(&path, &bytes).expect("write");

        let mut l = Loaded::open(&path).expect("open");
        assert_eq!(l.fns[0].display_name(), "fn_0");

        // First run names the entry function vmMain.
        let (named, thunks) = l.auto_name_functions();
        assert_eq!((named, thunks), (1, 0));
        assert_eq!(l.fns[0].display_name(), "vmMain");

        // Second run: everything is already named -> no-op.
        let (named, thunks) = l.auto_name_functions();
        assert_eq!((named, thunks), (0, 0));
        assert_eq!(l.fns[0].display_name(), "vmMain");

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn iter_field_accesses_collects_all_offsets() {
        let hits =
            iter_field_accesses("  *(<int>*)((loc_20) + (704)) = *(<int>*)((loc_20) + (712));");
        assert_eq!(
            hits,
            vec![("loc_20".to_string(), 704), ("loc_20".to_string(), 712)]
        );
        // Arithmetic on a deref is not a field access.
        assert!(iter_field_accesses("  loc_32 = (*(<int>*)(loc_20)) + (264);").is_empty());
        // No closing paren after digits -> rejected.
        assert!(iter_field_accesses("  f((loc_20) + (704").is_empty());
    }

    #[test]
    fn merge_struct_json_keeps_existing_field_names() {
        let existing = r#"{"auto_t": {"size": 16, "fields": {"8": "renamed"}}}"#;
        let scraped = vec![(
            "auto_t".to_string(),
            StructDef {
                size: 32,
                fields: BTreeMap::from([(0, "field_0".into()), (8, "field_8".into())]),
            },
        )];
        let out = merge_struct_json(existing, &scraped).expect("merge");
        assert!(out.contains("\"renamed\""), "{out}");
        assert!(out.contains("field_0"), "{out}");
        assert!(!out.contains("field_8"), "{out}");
        // Size of an existing type is preserved.
        assert!(out.contains("\"size\": 16"), "{out}");
        // Broken existing text starts from scratch.
        let out2 = merge_struct_json("not json", &scraped).expect("merge fresh");
        assert!(out2.contains("field_8"), "{out2}");
    }
}
