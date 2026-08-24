//! Probe: disassemble one function of a .qvm and print every CALL with its
//! resolved target (symbol name if >0, trap name if <0) and every JUMP/
//! comparison branch with its target function name. Optionally take the
//! instruction range from a q3asm .map file to resolve names.
//!
//! Usage: probe_calls <path.qvm> <fn_entry_insn> [<map.txt>]

use qvm::{build_functions, disassemble, load, Opcode};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let path = &a[0];
    let entry_s = a[1].trim_start_matches("0x").trim_start_matches("0X");
    let entry: usize = if entry_s.contains(&['a', 'b', 'c', 'd', 'e', 'f'][..]) {
        usize::from_str_radix(entry_s, 16).expect("fn entry insn (hex)")
    } else {
        entry_s.parse().expect("fn entry insn")
    };
    let q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);

    let mut names: Vec<(usize, String)> = Vec::new();
    let mut traps: Vec<(i32, String)> = Vec::new();
    if let Some(map) = a.get(2) {
        if let Ok(txt) = std::fs::read_to_string(map) {
            for line in txt.lines() {
                let mut it = line.split_whitespace();
                let (_z, off, sym) = match (it.next(), it.next(), it.next()) {
                    (Some(z), Some(o), Some(s)) if z == "0" => (z, o, s),
                    _ => continue,
                };
                let v = i64::from_str_radix(off, 16).unwrap_or(0);
                if v < 0 {
                    traps.push((v as i32, sym.to_string()));
                } else {
                    names.push((v as usize, sym.to_string()));
                }
            }
        }
    }
    names.sort_by_key(|(n, _)| *n);
    let name_for = |idx: usize| -> String {
        match names.binary_search_by_key(&idx, |(n, _)| *n) {
            Ok(i) => names[i].1.clone(),
            Err(i) => {
                if i > 0 {
                    names[i - 1].1.clone() + ".."
                } else {
                    format!("fn_{idx}")
                }
            }
        }
    };
    let trap_for = |t: i32| -> String {
        if let Some((_, s)) = traps.iter().find(|(n, _)| *n == t) {
            s.clone()
        } else {
            format!("trap_{t}")
        }
    };

    let (start, end) = ranges
        .iter()
        .find(|(s, _)| *s == entry)
        .copied()
        .unwrap_or((entry, d.insns.len()));

    println!(
        "fn entry {entry} range {start}..{end} ({} insns)",
        end - start
    );
    for insn in &d.insns[start..end] {
        match insn.op {
            Opcode::Call => {
                let t = insn.operand.unwrap_or(0);
                if t < 0 {
                    println!("#{:>6}  CALL -> {}", insn.idx, trap_for(t));
                } else {
                    println!("#{:>6}  CALL -> {}", insn.idx, name_for(t as usize));
                }
            }
            Opcode::Jump => {
                if let Some(t) = insn.target {
                    println!("#{:>6}  JUMP -> {}", insn.idx, name_for(t));
                } else {
                    println!("#{:>6}  JUMP -> <indirect>", insn.idx);
                }
            }
            _ => {}
        }
    }
}
