use std::collections::HashMap;

use qvm::{build_all, decompile_function, disassemble, fmt_readable, fmt_structured, load};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let raw = args.iter().any(|a| a == "--raw");
    args.retain(|a| a != "--raw");
    if args.is_empty() {
        eprintln!("usage: probe_dump_all <qvm> <out.struct.c> [names]");
        std::process::exit(2);
    }
    let path = args.first().cloned().unwrap();
    let out_path = args.get(1).cloned().unwrap_or_else(|| "out_all.c".to_string());
    let names_path = args.get(2).cloned();
    let handle = std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || run(&path, &out_path, names_path.as_deref(), raw))
        .expect("spawn");
    handle.join().expect("join");
}

fn run(path: &str, out_path: &str, names_path: Option<&str>, raw: bool) {
    let mut q = load(path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");

    let cfgs = build_all(&d, &q);
    let data = q.data_int32();

    // Attach symbol names: the `.names` file lists `fn[<cfg-index>] <name>`;
    // the decompiler formats calls as `fn_<entry-insn>`, so re-key by entry.
    if let Some(np) = names_path {
        let mut by_index: HashMap<usize, String> = HashMap::new();
        for line in std::fs::read_to_string(np).expect("read names").lines() {
            let mut it = line.split_whitespace();
            let (Some(idx), Some(name)) = (it.next(), it.next()) else {
                continue;
            };
            let trimmed = idx.trim_start_matches("fn[").trim_end_matches(']');
            if let Ok(i) = trimmed.parse::<usize>() {
                by_index.insert(i, name.to_string());
            } else {
                eprintln!("names: unparsable index {idx:?}");
            }
        }
        eprintln!("names: parsed {} lines from {np}", by_index.len());
        for (i, cfg) in cfgs.iter().enumerate() {
            if let Some(name) = by_index.get(&i) {
                q.names.insert(cfg.start, name.clone());
            }
        }
        eprintln!(
            "names: {} attached; fn0={:?} fn1={:?}",
            q.names.len(),
            q.name_for_fn(cfgs[0].start),
            q.name_for_fn(cfgs[1].start)
        );
    }

    let mut out = String::new();
    if raw {
        out.push_str("/* structured dump (--raw loc_N / *(<int>*)). NOT q3lcc input. */\n\n");
    } else {
        out.push_str(
            "/* structured + named overlay for port agents. NOT q3lcc input.\n\
             * Identity emit (goto / loc_0): sibling *.c from probe_emit.\n\
             * Do not invent pers.* past connected, _pad_812, or gentity word @552.\n\
             */\n\n",
        );
    }
    for (i, cfg) in cfgs.iter().enumerate() {
        eprintln!("fn[{i}]");
        // ENTER operand is the frame size; cfg.entry is the entry *block*
        // (always index 0) so the frame must come from the entry instruction.
        let frame = d.insns[cfg.start].operand.unwrap_or(0);
        let name = q
            .name_for_fn(cfg.start)
            .map(|n| format!(" = {n}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "/* ===== fn[{i}] insns {}..{} frame {}{name} ===== */\n",
            cfg.start, cfg.end, frame
        ));
        let dumped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let f = decompile_function(&d, cfg, frame, &data);
            if raw {
                fmt_structured(&f, &q)
            } else {
                fmt_readable(&f, &q)
            }
        }));
        match dumped {
            Ok(s) => out.push_str(&s),
            Err(_) => {
                eprintln!("fn[{i}] decompile panic — stub");
                out.push_str(&format!(
                    "/* fn[{i}] decompile panic; use sibling .c / identity emit */\nvoid fn_{}(void) {{}}\n",
                    cfg.start
                ));
            }
        }
        out.push('\n');
    }
    std::fs::write(&out_path, &out).expect("write");
    println!("wrote {out_path} ({} bytes, {} functions)", out.len(), cfgs.len());
}
