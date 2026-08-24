use qvm::{disassemble, load};

fn main() {
    let path = std::env::args().nth(1).unwrap();
    let addr: usize = std::env::args().nth(2).and_then(|s| {
        if s.starts_with("0x") { usize::from_str_radix(&s[2..], 16).ok() } else { s.parse().ok() }
    }).unwrap();
    let q = load(&path).expect("load");
    let d = disassemble(&q).expect("disasm");
    if let Some(idx) = d.insn_at.get(&addr) {
        println!("addr {:#x} ({}) -> insn idx {} : {}", addr, addr, idx, d.insns[*idx]);
    } else {
        println!("addr {:#x} ({}) not found", addr, addr);
    }
}
