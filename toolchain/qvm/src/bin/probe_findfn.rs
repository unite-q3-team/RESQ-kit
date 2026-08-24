use qvm::{build_functions, disassemble, load};

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let target: usize = std::env::args().nth(2).unwrap().parse().unwrap();
    let q = load(&path).expect("load");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    for (idx, (s, e)) in ranges.iter().enumerate() {
        if *s <= target && target < *e {
            println!("insn {target} is in fn[{idx}] ({s}..{e})");
            let end = *e.min(&(s + 2000));
            for i in *s..end {
                println!("{i}: {}", d.insns[i]);
            }
            break;
        }
    }
}
