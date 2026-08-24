use qvm::{build_functions, disassemble, load};

fn main() {
    let path = std::env::args().nth(1).expect("path");
    let around: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(28752);
    let q = load(&path).expect("load");
    let d = disassemble(&q).expect("disasm");
    let ranges = build_functions(&d);
    let mut fi = 0;
    for (i, &(s, e)) in ranges.iter().enumerate() {
        if around >= s && around < e {
            fi = i;
            break;
        }
    }
    let (start, end) = ranges[fi];
    println!(
        "fn[{fi}] insns {start}..{end} (len {}) contains {around}",
        end - start
    );
    let lo = around.saturating_sub(12);
    let hi = (around + 60).min(d.insns.len());
    for i in lo..hi {
        println!("{i}: {}", d.insns[i]);
    }
}
