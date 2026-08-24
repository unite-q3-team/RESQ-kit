use qvm::{
    build_all, decompile_function, disassemble, load, CaseKind, Elem, Structure, Terminator,
};
use std::collections::HashSet;

fn collect(elems: &[Elem], s: &Structure, residual: &mut HashSet<usize>) {
    for e in elems {
        match e {
            Elem::Goto(t) => {
                if let Some(b) = s.block_index(*t) {
                    residual.insert(b);
                }
            }
            Elem::IfGoto { target, .. } => {
                if let Some(b) = s.block_index(*target) {
                    residual.insert(b);
                }
            }
            Elem::Switch { cases, default, .. } => {
                for (_, kind) in cases {
                    match kind {
                        CaseKind::Goto(t) => {
                            if let Some(b) = s.block_index(*t) {
                                residual.insert(b);
                            }
                        }
                        CaseKind::Inline { body, .. } => collect(body, s, residual),
                    }
                }
                if let Some(CaseKind::Goto(t)) = default {
                    if let Some(b) = s.block_index(*t) {
                        residual.insert(b);
                    }
                } else if let Some(CaseKind::Inline { body, .. }) = default {
                    collect(body, s, residual);
                }
            }
            Elem::If { then, else_, .. } => {
                collect(then, s, residual);
                collect(else_, s, residual);
            }
            Elem::While { body, .. } | Elem::DoWhile { body, .. } => {
                collect(body, s, residual);
            }
            _ => {}
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: probe_stubs <qvm>");
        std::process::exit(2);
    });
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let cfgs = build_all(&d, &q);
    let cfg = &cfgs[0];
    let frame = d.insns[cfg.entry].operand.unwrap_or(0);
    let f = decompile_function(&d, cfg, frame, &q.data_int32());
    let mut s = Structure::new(&f);
    let main = s.structure(0, usize::MAX);
    let leftover = s.leftover();
    let mut residual: HashSet<usize> = HashSet::new();
    collect(&main, &s, &mut residual);
    for &bi in &leftover {
        match &f.blocks[bi].term {
            Terminator::Goto(t) => {
                if let Some(x) = s.block_index(*t) {
                    residual.insert(x);
                }
            }
            Terminator::IfGoto { target, .. } => {
                if let Some(x) = s.block_index(*target) {
                    residual.insert(x);
                }
            }
            _ => {}
        }
    }
    eprintln!("leftover: {:?}", leftover);
    eprintln!("residual: {:?}", residual.iter().collect::<Vec<_>>());
    for &bi in &leftover {
        let b = &f.blocks[bi];
        eprintln!(
            "  L{} term={:?} body={:?} in_residual={}",
            b.start,
            b.term,
            b.body,
            residual.contains(&bi)
        );
    }
}
