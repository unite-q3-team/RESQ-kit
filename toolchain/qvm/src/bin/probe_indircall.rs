//! Probe: find indirect-call table geometries (same logic as probe_emit's
//! indir_cells collection) and print them per function.
//! Usage: probe_indircall <path.qvm> [<path.sigs>]

use std::collections::HashMap;
use qvm::{build_cfg, decompile_function, disassemble, load};
use qvm::decompile::{Expr, LoadSize, Stmt, Terminator};

#[derive(Default)]
struct Sig {
    frame: i32,
    args: usize,
    ret: String,
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
            let Some(idx) = head
                .strip_prefix("fn[")
                .and_then(|r| r.strip_suffix(']').and_then(|x| x.parse::<usize>().ok()))
            else {
                continue
            };
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

fn table_cell_geoms(addr: &Expr) -> Option<(usize, usize)> {
    let mut cs = Vec::new();
    collect_consts(addr, &mut cs);
    let base = cs.into_iter().max()?;
    if !(0x100..=0x2000000).contains(&base) {
        return None;
    }
    let stride = find_scale(addr).unwrap_or(4).max(4);
    Some((base as usize, stride))
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let q = load(&a[0]).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let sigs = a.get(1).map(|s| parse_sigs(s));
    let fns = qvm::cfg::build_functions(&d);
    let mut seen = std::collections::BTreeSet::new();
    for (fi, (start, end)) in fns.iter().enumerate() {
        let frame = sigs.as_ref().and_then(|m| m.get(&fi)).map(|s| s.frame)
            .unwrap_or_else(|| d.insns[*start].operand.unwrap_or(0));
        if let Some(cfg) = build_cfg(&d, (*start, *end), &q.data_int32()) {
            let f = decompile_function(&d, &cfg, frame, &q.data_int32());
            let mut st: Vec<&Expr> = Vec::new();
            for b in &f.blocks {
                for s in &b.body {
                    match s {
                        Stmt::Assign { value, .. } => st.push(value),
                        Stmt::Store { addr, value, .. } => {
                            st.push(addr);
                            st.push(value);
                        }
                        Stmt::BlockCopy { dest, src, .. } => {
                            st.push(dest);
                            st.push(src);
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
                if let Expr::Call(t, _) = x {
                    let mut tt = t.as_ref();
                    while let Expr::Float(inner) = tt {
                        tt = inner.as_ref();
                    }
                    if let Expr::MemRef(addr, LoadSize::I4) = tt {
                        let mut cs = Vec::new();
                        collect_consts(addr, &mut cs);
                        let maxc = cs.into_iter().max();
                        let geom = table_cell_geoms(addr);
                        let tag = match geom {
                            Some((base, stride)) => {
                                let tag = if seen.contains(&(base, stride)) { " (dup)" } else { "" };
                                println!(
                                    "fn[{fi}] ({start}..{end}) frame={frame} indir base=0x{base:x} stride={stride}{tag}",
                                );
                                seen.insert((base, stride));
                                String::new()
                            }
                            None => String::from(" NO-GEOM"),
                        };
                        if let Some(m) = maxc {
                            if (0x100..=0x2000000).contains(&m) {
                                println!("  fn[{fi}] memref-call maxconst=0x{m:x} off-range={maxc:?}{tag}");
                            }
                        }
                    }
                    st.push(t.as_ref());
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
    println!("total distinct indir tables: {}", seen.len());
    for (base, stride) in &seen {
        println!("  base=0x{base:x} stride={stride}");
    }
}
