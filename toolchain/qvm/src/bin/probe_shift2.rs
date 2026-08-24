//! Compare data-segment bytes of two QVMs at matching offsets to determine
//! whether the rebuilt image is identity-mapped (data[k]==blob[k]) or shifted
//! by 4 (data[k]==blob[k+4]).
//! Usage: probe_shift2 <orig.qvm> <rebuilt.qvm>

use qvm::load;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: probe_shift2 <orig.qvm> <rebuilt.qvm>");
        std::process::exit(2);
    }
    let o = load(&a[0]).expect("orig");
    let r = load(&a[1]).expect("rebuilt");
    let n = (o.data.len() + o.lit.len()).min(r.data.len() + r.lit.len());
    let data_end = o.data.len().min(r.data.len());
    let lit_end = data_end + o.lit.len().min(r.lit.len());
    let mut ident = 0usize;
    let mut shift4 = 0usize;
    let mut other = 0usize;
    let mut first_mismatch = usize::MAX;
    for k in 4..n.saturating_sub(4) {
        let a = if k < o.data.len() { o.data[k] } else { o.lit[k - o.data.len()] };
        let b = if k < r.data.len() { r.data[k] } else { r.lit[k - r.data.len()] };
        let b4 = if k - 4 < r.data.len() { r.data[k - 4] } else { r.lit[k - 4 - r.data.len()] };
        if a == b {
            ident += 1;
        }
        if a == b4 {
            shift4 += 1;
        }
        if a != b {
            other += 1;
            if first_mismatch == usize::MAX {
                first_mismatch = k;
            }
        }
    }
    println!("data+lit bytes compared: {n}  (data {data_end}, lit to {lit_end})");
    println!("identical (mem[k]==blob[k])   : {ident}");
    println!("shifted-4  (mem[k]==blob[k+4]): {shift4}");
    println!("other mismatches              : {other}");
    if first_mismatch != usize::MAX {
        let k = first_mismatch;
        let mut ob: Vec<u8> = Vec::new();
        let mut rb: Vec<u8> = Vec::new();
        for j in k..k + 24 {
            ob.push(if j < o.data.len() { o.data[j] } else { o.lit[j - o.data.len()] });
            rb.push(if j < r.data.len() { r.data[j] } else { r.lit[j - r.data.len()] });
        }
        println!("first mismatch at {k}: orig {ob:02x?}  rebuilt {rb:02x?}");
    }
}
