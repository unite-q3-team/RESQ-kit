use qvm::load;
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let q = load(&a[0]).expect("load");
    println!("data_length={} lit_length={}", q.data.len(), q.lit.len());
    for needle in &a[1..] {
        let nb = needle.as_bytes();
        let mut i = 0;
        while i + nb.len() <= q.data.len() {
            if &q.data[i..i+nb.len()] == nb {
                println!("{needle}: data_off={i}");
            }
            i += 1;
        }
        i = 0;
        while i + nb.len() <= q.lit.len() {
            if &q.lit[i..i+nb.len()] == nb {
                println!("{needle}: lit_off={i} addr={}", q.data.len() as i32 + i as i32);
            }
            i += 1;
        }
    }
}
