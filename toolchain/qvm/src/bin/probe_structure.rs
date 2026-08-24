use qvm::{
    build_cfg, build_functions, decompile_function, disassemble, load, CaseKind, Elem, Structure,
};

fn dump(elems: &[Elem], f: &qvm::Function, q: &qvm::Qvm, indent: usize) {
    let pad = "  ".repeat(indent);
    for e in elems {
        match e {
            Elem::Block { idx: b, body } => {
                let blk = &f.blocks[*b];
                let _ = body;
                println!(
                    "{pad}Block L{} term={:?} body={:?}",
                    blk.start, blk.term, blk.body
                );
            }
            Elem::If { cond, then, else_ } => {
                println!(
                    "{pad}If cond={}",
                    qvm::decompile::fmt_expr(q, f.frame, cond)
                );
                dump(then, f, q, indent + 1);
                if !else_.is_empty() {
                    println!("{pad}Else:");
                    dump(else_, f, q, indent + 1);
                }
            }
            Elem::While { cond, body } => {
                println!(
                    "{pad}While cond={}",
                    qvm::decompile::fmt_expr(q, f.frame, cond)
                );
                dump(body, f, q, indent + 1);
            }
            Elem::DoWhile { cond, body } => {
                println!(
                    "{pad}DoWhile cond={}",
                    qvm::decompile::fmt_expr(q, f.frame, cond)
                );
                dump(body, f, q, indent + 1);
            }
            Elem::Switch {
                sel,
                cases,
                default,
            } => {
                println!(
                    "{pad}Switch sel={}",
                    qvm::decompile::fmt_expr(q, f.frame, sel)
                );
                for (vals, kind) in cases {
                    match kind {
                        CaseKind::Goto(t) => println!("{pad}  case {:?}: Goto L{}", vals, t),
                        CaseKind::Inline { body, .. } => {
                            println!("{pad}  case {:?}: Inline", vals);
                            dump(body, f, q, indent + 2);
                        }
                    }
                }
                match default {
                    None => println!("{pad}  no default"),
                    Some(CaseKind::Goto(t)) => println!("{pad}  default: Goto L{}", t),
                    Some(CaseKind::Inline { body, .. }) => {
                        println!("{pad}  default: Inline");
                        dump(body, f, q, indent + 2);
                    }
                }
            }
            Elem::IfGoto { cond, target } => {
                println!(
                    "{pad}IfGoto cond={} target=L{}",
                    qvm::decompile::fmt_expr(q, f.frame, cond),
                    target
                );
            }
            Elem::Goto(t) => println!("{pad}Goto L{}", t),
            Elem::Return(..) => println!("{pad}Return"),
            Elem::Unresolved(_) => println!("{pad}Unresolved"),
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let fnidx: usize = std::env::args()
        .nth(2)
        .unwrap_or("0".into())
        .parse()
        .unwrap();
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let (start, end) = ranges[fnidx];
    let cfg = build_cfg(&d, (start, end), &q.data_int32()).expect("cfg");
    let frame = d.insns[start].operand.unwrap_or(0);
    let f = decompile_function(&d, &cfg, frame, &q.data_int32());
    let mut s = Structure::new(&f);
    let main = s.structure(0, usize::MAX);
    dump(&main, &f, &q, 0);
    let leftover = s.leftover();
    println!("leftover: {:?}", leftover);
    for &bi in &leftover {
        println!(
            "  L{} term={:?} body={:?}",
            f.blocks[bi].start, f.blocks[bi].term, f.blocks[bi].body
        );
    }
}
