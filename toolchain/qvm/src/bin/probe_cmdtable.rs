use qvm::{build_functions, disassemble, load};

fn main() {
    let path = std::env::args().nth(1).expect("path");
    let q = load(&path).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let fns = build_functions(&d);
    let mut entries: Vec<usize> = Vec::new();
    for &(start, _end) in fns.iter() {
        entries.push(start);
    }
    let data = q.data_int32();
    println!(
        "data_i32 len = {} (words), blob_len = {} bytes",
        data.len(),
        q.data_length + q.lit_length
    );
    let mut i = 0usize;
    while i < 132 {
        let name = data[771 + i] as usize;
        let func = data[771 + i + 1] as usize;
        let s = q.string_at(name as i32).unwrap_or_default();
        let is_entry = entries.contains(&func);
        let mut real = "      ".to_string();
        if entries.contains(&func) {
            let idx = entries.iter().position(|&e| e == func).unwrap();
            real = format!("#{}", idx);
        }
        println!(
            "{:3}: name={:6} ({:?}) func={:6} entry={} {}",
            i / 2,
            name,
            s,
            func,
            is_entry,
            real
        );
        i += 2;
    }
}
