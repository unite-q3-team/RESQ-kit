use qvm::{disassemble, load, Opcode};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = match args.get(1) {
        Some(p) => p.clone(),
        None => {
            eprintln!("usage: probe_ucmp <qvm>");
            std::process::exit(2);
        }
    };
    let q = load(&path).expect("load");
    let d = disassemble(&q).expect("disasm");
    let mut c = std::collections::HashMap::new();
    for ins in d.insns.iter() {
        let k = match ins.op {
            Opcode::Divi
            | Opcode::Divu
            | Opcode::Modi
            | Opcode::Modu
            | Opcode::Muli
            | Opcode::Mulu
            | Opcode::Rshi
            | Opcode::Rshu => format!("{:?}", ins.op),
            _ => continue,
        };
        *c.entry(k).or_insert(0usize) += 1;
    }
    let mut v: Vec<_> = c.into_iter().collect();
    v.sort();
    for (k, n) in v {
        println!("{k}: {n}");
    }
}
