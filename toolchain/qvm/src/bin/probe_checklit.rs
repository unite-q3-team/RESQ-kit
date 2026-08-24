use qvm::load;
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() { eprintln!("usage: probe_checklit <qvm>"); std::process::exit(2); }
    let q = load(&a[0]);
    match q {
        Ok(q) => println!("OK data={} lit={} code={}", q.data.len(), q.lit.len(), q.code.len()),
        Err(e) => println!("ERR {e:?}"),
    }
}
