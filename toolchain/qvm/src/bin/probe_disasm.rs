use qvm::{build_functions, disassemble, load};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: probe_disasm <qvm> [fn_index] [lo] [hi] [data_addr...]");
        eprintln!("  disassemble fn[fn_index], or an explicit insn range lo..hi.");
        eprintln!("  Extra numbers are treated as VM data addresses (data word dumps).");
        std::process::exit(2);
    }
    let path = &args[0];
    let which: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let q = load(path).expect("load");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    println!("functions: {}", ranges.len());
    let (start, end) = ranges[which];
    println!("fn[{which}] insns {start}..{end}");
    let lo = args
        .get(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(start);
    let hi = args
        .get(3)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(end.min(lo + 60));
    for i in lo..hi {
        println!("{i}: {}", d.insns[i]);
    }
    for a in args.iter().skip(4) {
        if let Ok(va) = a.parse::<usize>() {
            let word = q.data_word(va);
            println!("vm[0x{va:x}]={va} -> data_word={word} ({:#x})", word);
        }
    }
}

trait DataWord {
    fn data_word(&self, va: usize) -> i32;
}
impl DataWord for qvm::Qvm {
    fn data_word(&self, va: usize) -> i32 {
        if va + 4 > self.data.len() {
            return 0;
        }
        i32::from_le_bytes([
            self.data[va],
            self.data[va + 1],
            self.data[va + 2],
            self.data[va + 3],
        ])
    }
}
