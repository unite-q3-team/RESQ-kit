//! Headless sanity check of the GUI state layer.
//! Usage: cargo run --release --example open -- <path.qvm>

fn main() {
    let path = std::env::args().nth(1).expect("usage: open <qvm>");
    let t0 = std::time::Instant::now();
    let l = resq_gui::state::Loaded::open(std::path::Path::new(&path)).expect("open");
    println!(
        "{} -> {} fns, {} insns, {} strings in {:?}",
        path,
        l.fns.len(),
        l.lines.len(),
        l.lit_strings.len(),
        t0.elapsed()
    );
    // decompile the largest function once
    let big = l
        .fns
        .iter()
        .enumerate()
        .max_by_key(|(_, f)| f.len())
        .map(|(i, _)| i)
        .unwrap();
    let t1 = std::time::Instant::now();
    let c = l.decompile(big).expect("decompile");
    println!(
        "fn[{big}] ({} insns) decompiled to {} lines in {:?}",
        l.fns[big].len(),
        c.text.lines().count(),
        t1.elapsed()
    );
    // Memory hints for the first CONST operands of that function.
    println!("mem hints:");
    let mut shown = 0;
    let range = l.fn_range(big).unwrap_or(0..0);
    for ins in &l.d.insns[range] {
        if shown >= 8 {
            break;
        }
        if ins.op != qvm::Opcode::Const {
            continue;
        }
        let Some(v) = ins.operand else { continue };
        if let Some(h) = l.mem_hint(v, resq_gui::i18n::LangId::EN) {
            println!("  {h}");
            shown += 1;
        }
    }

    // Heuristic auto-naming (vmMain + syscall thunks) and struct census.
    let mut l = l;
    let (named, thunks) = l.auto_name_functions();
    println!("auto-named {named} functions ({thunks} syscall thunks), e.g.:");
    for f in l.fns.iter().filter_map(|f| f.name.clone()).take(10) {
        println!("  {f}");
    }
    let scraped = resq_gui::state::scrape_struct_layouts(&l);
    println!("scraped {} struct layouts, e.g.:", scraped.len());
    for (name, def) in scraped.iter().take(6) {
        println!("  {name}: size {}, {} fields", def.size, def.fields.len());
    }
}
