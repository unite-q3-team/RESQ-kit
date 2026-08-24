//! Probe: align functions between two QVMs by bytecode fingerprint.
//!
//! Usage: probe_align <known.qvm> <known.map> <target.qvm> [--all]
//!
//! For every function in `target`, look for a function in `known` with an
//! identical instruction stream (opcode + operand sequence); if found, the
//! target function inherits the known function's `.map` name.
//!
//! Pass 1: exact (op, operand) match.
//! Pass 2: opcode-only match (operands ignored) for near-misses.
//! The report ends with a machine-readable target `.names` table.

use std::collections::HashMap;

use qvm::{Opcode, build_functions, disassemble, load, load_map};

fn fingerprint(d: &qvm::Disassembly, start: usize, end: usize) -> Vec<(u8, i64)> {
    d.insns[start..end]
        .iter()
        .map(|i| {
            let op = i.op as u8;
            let od = i.operand.map(|v| v as i64).unwrap_or(0);
            (op, od)
        })
        .collect()
}

fn opcode_only(d: &qvm::Disassembly, start: usize, end: usize) -> Vec<u8> {
    d.insns[start..end].iter().map(|i| i.op as u8).collect()
}

/// Semantic signature: the sorted set of string literals (by content) and
/// syscall trap numbers a function references. Stable across builds with
/// different layouts/compilers, as long as the source function is the same.
fn signature(q: &qvm::Qvm, d: &qvm::Disassembly, start: usize, end: usize) -> String {
    use qvm::Opcode;
    let insns = &d.insns[start..end];
    let mut sig: Vec<String> = Vec::new();
    for (i, ins) in insns.iter().enumerate() {
        if let Some(opd) = ins.operand {
            if ins.op == Opcode::Const {
                if let Some(s) = q.string_at(opd) {
                    sig.push(format!("S:{s}"));
                }
                if let Some(next) = insns.get(i + 1) {
                    if next.op == Opcode::Call && opd < 0 {
                        sig.push(format!("T:{}", -1 - opd));
                    }
                }
            }
        }
    }
    sig.sort();
    sig.dedup();
    sig.join("|")
}

/// Opcode-trigram Jaccard similarity, robust to small local edits.
fn trigrams(seq: &[u8]) -> std::collections::HashSet<u32> {
    let mut s = std::collections::HashSet::new();
    for w in seq.windows(3) {
        s.insert(((w[0] as u32) << 16) | ((w[1] as u32) << 8) | w[2] as u32);
    }
    s
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let known_qvm = &args[0];
    let known_map = &args[1];
    let target_qvm = &args[2];
    let all = args.iter().any(|a| a == "--all");
    let trig = args.iter().any(|a| a == "--trig");
    let overrides: Option<String> = args
        .iter()
        .position(|a| a == "--overrides")
        .and_then(|i| args.get(i + 1).cloned());

    // load overrides: fn[N] Name
    let mut ovr: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    if let Some(p) = &overrides {
        let text = std::fs::read_to_string(p).expect("read overrides");
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(idx), Some(name)) = (it.next(), it.next()) else { continue };
            let idx = idx.trim_start_matches("fn[").trim_end_matches(']');
            if let Ok(fi) = idx.parse::<usize>() {
                ovr.insert(fi, name.to_string());
            }
        }
        println!("overrides: {} entries", ovr.len());
    }

    let kq = load(known_qvm).expect("load known");
    let kd = disassemble(&kq).expect("disasm known");
    let kr = build_functions(&kd);
    let syms = load_map(known_map).expect("load map");
    let idx = qvm::index(&syms);

    let tq = load(target_qvm).expect("load target");
    let td = disassemble(&tq).expect("disasm target");
    let tr = build_functions(&td);
    println!("known {} ({} fn)  target {} ({} fn)", known_qvm, kr.len(), target_qvm, tr.len());

    let mut exact: HashMap<Vec<(u8, i64)>, (&str, usize)> = HashMap::new();
    for &(start, end) in kr.iter() {
        if let Some(name) = idx.get(&start) {
            exact.entry(fingerprint(&kd, start, end)).or_insert((name, start));
        }
    }
    let mut ops: HashMap<Vec<u8>, (&str, usize)> = HashMap::new();
    for &(start, end) in kr.iter() {
        if let Some(name) = idx.get(&start) {
            ops.entry(opcode_only(&kd, start, end)).or_insert((name, start));
        }
    }
    let mut sigs: HashMap<String, (&str, usize)> = HashMap::new();
    for &(start, end) in kr.iter() {
        if let Some(name) = idx.get(&start) {
            let s = signature(&kq, &kd, start, end);
            if !s.is_empty() {
                sigs.entry(s).or_insert((name, start));
            }
        }
    }

    // trigram pass: precompute known-side opcode sequences + trigram sets
    let known_ops: Vec<(usize, usize, Vec<u8>)> = kr
        .iter()
        .map(|&(s, e)| (s, e, opcode_only(&kd, s, e)))
        .collect();

    let mut named = 0usize;
    let mut named_by_ops = 0usize;
    let mut named_by_sig = 0usize;
    let mut named_by_trig = 0usize;
    let mut rows: Vec<(usize, usize, usize, String)> = Vec::new();
    for (fi, &(start, end)) in tr.iter().enumerate() {
        let len = end - start;
        let mut name: Option<&str> = None;
        if let Some((n, _)) = exact.get(&fingerprint(&td, start, end)) {
            name = Some(n);
            named += 1;
        } else if let Some((n, _)) = sigs.get(&signature(&tq, &td, start, end)) {
            name = Some(n);
            named_by_sig += 1;
        } else if let Some((n, _)) = ops.get(&opcode_only(&td, start, end)) {
            name = Some(n);
            named_by_ops += 1;
        } else {
            // trigram Jaccard: best + second-best among size-plausible known fns
            let tgt = trigrams(&opcode_only(&td, start, end));
            let mut best: Option<(f64, (&str, usize))> = None;
            let mut second: Option<f64> = None;
            for (ks, ke, kop) in &known_ops {
                let klen = ke - ks;
                if klen < len / 2 || klen > len * 2 {
                    continue;
                }
                let ksig = trigrams(kop);
                let inter = tgt.intersection(&ksig).count() as f64;
                let union = tgt.union(&ksig).count() as f64;
                if union == 0.0 {
                    continue;
                }
                let sim = inter / union;
                let key = (klen, kop[0]);
                let cand = (sim, (idx.get(ks).copied().unwrap_or(""), *ks));
                if let Some(b) = &best {
                    if cand.0 > b.0 {
                        second = Some(b.0);
                        best = Some(cand);
                    } else if second.is_none() || cand.0 > second.unwrap() {
                        second = Some(cand.0);
                    }
                } else {
                    best = Some(cand);
                }
                let _ = key;
            }
            if let Some((sim, (n, _))) = best {
                let margin = match second {
                    Some(s) => sim - s,
                    None => 1.0,
                };
                if sim >= 0.45 && margin >= 0.10 {
                    name = Some(n);
                    named_by_trig += 1;
                    if trig {
                        println!("    trig fn[{fi}] ~ {n} (sim {sim:.2} margin {margin:.2})");
                    }
                }
            }
        }
        // overrides win over alignment
        if let Some(n) = ovr.get(&fi) {
            name = Some(n);
        }
        if all || name.is_some() {
            println!(
                "fn[{fi}] insns {start}..{end} ({len}): {}",
                name.unwrap_or("<unique>")
            );
        }
        rows.push((fi, start, len, name.unwrap_or("").to_string()));
    }

    let total = tr.len();
    let total_named = rows.iter().filter(|(_, _, _, n)| !n.is_empty()).count();
    println!(
        "aligned: {named} exact + {named_by_ops} opcode-only + {named_by_sig} signature + {named_by_trig} trigram + {} override = {total_named} / {total} ({:.0}%)",
        ovr.len(),
        100.0 * total_named as f64 / total as f64
    );

    let out = format!("{}.names", std::path::Path::new(target_qvm).file_stem().unwrap().to_string_lossy());
    let mut w = String::new();
    for (fi, _start, _len, name) in &rows {
        if !name.is_empty() {
            w.push_str(&format!("fn[{fi}] {name}\n"));
        }
    }
    let n_rows = w.lines().count();
    std::fs::write(&out, &w).expect("write names");
    println!("wrote {out}  ({n_rows} named)");

    // curation aid: unnamed functions with their string/trap signature
    let mut cur = String::new();
    for (fi, start, len, name) in &rows {
        if !name.is_empty() {
            continue;
        }
        let s = signature(&tq, &td, *start, *start + len);
        let disp: String = s.split('|').take(6).collect::<Vec<_>>().join(" | ");
        cur.push_str(&format!("fn[{fi}] ({len} insns) {disp}\n"));
    }
    std::fs::write("qagame.unnamed.txt", &cur).expect("write unnamed");
    println!("wrote qagame.unnamed.txt ({} unnamed)", cur.lines().count());
}
