use qvm::{build_functions, disassemble, load};
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() { eprintln!("usage: probe_chk2 <qvm>"); std::process::exit(2); }
    let q = load(&a[0]).expect("load");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    for target in [17213i32,17233,17239,17247,17229,15744,215320,215392,210468,18636] {
        let is_entry = ranges.iter().any(|&(s,_)| s as i32 == target);
        println!("{target}: is_fn_entry={is_entry}");
    }
}
