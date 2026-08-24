//! Probe: for each (optionally unnamed) function, list who calls it, plus its
//! string literals and syscall numbers -- context for naming.
//!
//! Usage: probe_callers <qvm> [--named] [--min N] [--only N,M,...]
//!   default: unnamed functions only

use qvm::opcodes::Opcode;
use qvm::{build_functions, disassemble, load};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = &args[0];
    let named = args.iter().any(|a| a == "--named");
    let min = args
        .iter()
        .position(|a| a == "--min")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(0);
    let only: Option<Vec<usize>> = args
        .iter()
        .position(|a| a == "--only")
        .and_then(|i| args.get(i + 1))
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().parse::<usize>().unwrap())
                .collect()
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
                        if let Some(idx) =
                            rest.strip_suffix(']').and_then(|x| x.parse::<usize>().ok())
                        {
                            if let Some(&(s, _e)) = ranges.get(idx) {
                                q.names.insert(s, n.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // index: entry-insn -> fn index
    let mut entry_to_fn: Vec<Option<usize>> = vec![None; d.insns.len()];
    for (fi, &(start, _end)) in ranges.iter().enumerate() {
        entry_to_fn[start] = Some(fi);
    }

    // gather strings/traps per function
    let mut strs: Vec<Vec<String>> = vec![Vec::new(); ranges.len()];
    let mut traps: Vec<Vec<i32>> = vec![Vec::new(); ranges.len()];
    for (fi, &(start, end)) in ranges.iter().enumerate() {
        for i in start..end {
            let ins = &d.insns[i];
            if ins.op == Opcode::Const {
                if let Some(off) = ins.operand {
                    let s = q.string_at(off).unwrap_or_default();
                    if !s.is_empty() && !strs[fi].contains(&s) {
                        strs[fi].push(s);
                    }
                }
            }
        }
    }

    // gather callers per function (lcc pattern: CONST <target>; CALL)
    let mut callers: Vec<Vec<usize>> = vec![Vec::new(); ranges.len()];
    for (fi, &(start, end)) in ranges.iter().enumerate() {
        let mut i = start;
        while i + 1 < end {
            let a = &d.insns[i];
            let b = &d.insns[i + 1];
            if a.op == Opcode::Const && b.op == Opcode::Call {
                if let Some(t) = a.operand {
                    if t >= 0 {
                        if let Some(target) = entry_to_fn[t as usize] {
                            if !callers[target].contains(&fi) {
                                callers[target].push(fi);
                            }
                        }
                    } else if !traps[fi].contains(&t) {
                        traps[fi].push(t);
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    let names = &q.names;
    for (fi, &(start, end)) in ranges.iter().enumerate() {
        let name = names.get(&start).map(|s| s.as_str());
        let is_named = name.is_some();
        if named == is_named || (named && is_named) || (!named && !is_named) {
            let keep = is_named == named;
            match &only {
                Some(set) => {
                    if !set.contains(&fi) {
                        continue;
                    }
                }
                None => {
                    if !keep {
                        continue;
                    }
                }
            }
            if (end - start) < min {
                continue;
            }
            let cs: Vec<String> = callers[fi]
                .iter()
                .map(|c| {
                    let (s2, _e2) = ranges[*c];
                    match names.get(&s2) {
                        Some(n) => n.to_string(),
                        None => format!("fn[{c}]"),
                    }
                })
                .collect();
            let st = strs[fi].join(" | ");
            let tr: Vec<String> = traps[fi].iter().map(|t| t.to_string()).collect();
            let tr = tr.join(",");
            println!(
                "fn[{fi}] insns {start}..{end} ({}): callers=[{}]{} {}",
                end - start,
                cs.join(", "),
                if st.is_empty() {
                    String::new()
                } else {
                    format!(" S:{st}")
                },
                if tr.is_empty() {
                    String::new()
                } else {
                    format!(" T:{tr}")
                }
            );
        }
    }
}
