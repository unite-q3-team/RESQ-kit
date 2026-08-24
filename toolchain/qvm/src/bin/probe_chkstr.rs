use qvm::load;
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() {
        eprintln!("usage: probe_chkstr <qvm>");
        std::process::exit(2);
    }
    let q = load(&a[0]).expect("load");
    println!("18636 string_at: {:?}", q.string_at(18636));
    println!("17229 string_at: {:?}", q.string_at(17229));
}
