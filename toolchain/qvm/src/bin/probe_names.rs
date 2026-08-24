//! Probe: coverage of q3asm `.map` names against the disassembled functions.
//!
//! Usage: probe_names <qvm> <map> [--all]
//!   --all : print every function, not just the named ones

use qvm::{build_functions, disassemble, load, load_map};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let qvm = &args[0];
    let map = &args[1];
    let all = args.iter().any(|a| a == "--all");

    let q = load(qvm).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let syms = load_map(map).expect("load map");
    let idx = qvm::index(&syms);
    println!("{}", q);
    println!("map symbols: {}  functions: {}", syms.len(), ranges.len());

    let mut named = 0;
    for (fi, &(start, end)) in ranges.iter().enumerate() {
        let name = idx.get(&start).copied();
        if name.is_some() {
            named += 1;
        }
        if all || name.is_some() {
            println!(
                "fn[{fi}] insns {start}..{end} ({}): {}",
                end - start,
                name.unwrap_or("<unnamed>")
            );
        }
    }
    println!(
        "coverage: {named}/{} functions named ({:.0}%)",
        ranges.len(),
        100.0 * named as f64 / ranges.len() as f64
    );

    // dump a machine-readable names table for later use
    let out = format!(
        "{}.names",
        std::path::Path::new(qvm)
            .file_stem()
            .unwrap()
            .to_string_lossy()
    );
    let mut w = String::new();
    for (fi, &(start, _end)) in ranges.iter().enumerate() {
        if let Some(name) = idx.get(&start) {
            w.push_str(&format!("fn[{fi}] {name}\n"));
        }
    }
    std::fs::write(&out, w).expect("write names");
    println!("wrote {out}");
}
