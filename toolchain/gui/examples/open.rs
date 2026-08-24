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
}
