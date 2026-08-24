//! Loading + analysis state for the GUI. Pure `qvm` calls, no UI here, so it
//! stays unit-testable.

use std::collections::{BTreeMap, HashMap, HashSet};
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
pub fn opcode_help(op: Opcode) -> &'static str {
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

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("unnamed")
    }

    /// Rebuild the lowercased filter blob from current metadata.
    pub fn rebuild_search(&mut self) {
        let mut s = self.name.clone().unwrap_or_default();
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
        })
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
        let ranges: Vec<(usize, usize)> = lines.into_iter().map(|(_, r)| r).collect();
        Ok(Decompiled {
            text: text.into(),
            ranges: ranges.into(),
            labels: labels.into(),
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
}
