//! Probe: build a q3asm-style `.map` for a QVM without a map, from a
//! `fn[<idx>] <name>` names table + CFG function ranges.
//!
//! Usage: probe_origmap <qvm> <names> [<out.map>]
//!   Writes a .map with one line per named function:
//!     0 <hex-entry> <name>
//!   (entry = CFG start instruction index). Without <out.map>, prints to stdout.

use qvm::{build_functions, disassemble, load};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: probe_origmap <qvm> <names> [<out.map>]");
        std::process::exit(1);
    }
    let q = load(&args[0]).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);

    let names_text = std::fs::read_to_string(&args[1]).expect("read names");
    let mut idx_to_name: Vec<Option<String>> = vec![None; ranges.len()];
    let mut total = 0usize;
    for line in names_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("fn[") {
            let (idx_s, name_s) = rest.split_once(']').expect("names line");
            if let Ok(i) = idx_s.trim().parse::<usize>() {
                let name = name_s.trim();
                if i < ranges.len() {
                    idx_to_name[i] = Some(name.to_string());
                    total += 1;
                }
            }
        }
    }

    let mut out = String::new();
    for (fi, &(start, _end)) in ranges.iter().enumerate() {
        if let Some(name) = &idx_to_name[fi] {
            out.push_str(&format!("0 {:08x} {}\n", start, name));
        }
    }

    if args.len() >= 3 {
        std::fs::write(&args[2], &out).expect("write map");
        println!(
            "wrote {} ({} named of {} functions)",
            args[2],
            total,
            ranges.len()
        );
    } else {
        print!("{out}");
    }
}
