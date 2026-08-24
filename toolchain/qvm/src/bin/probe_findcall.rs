//! Probe: find all CALL instructions with a given operand (trap number, e.g. -14
//! for trap_SendConsoleCommand) that are preceded (within a small window) by a
//! CONST matching a given data address. Useful when probe_findconst misses
//! addresses built via ADD/arithmetic - this scans raw operands directly.
//! Usage: probe_findcall <path.qvm> <call_operand> <nearby_const_value> [window]
use qvm::{disassemble, load};
use qvm::Opcode;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let q = load(&a[0]).expect("load qvm");
    let d = disassemble(&q).expect("disasm");
    let call_op: i32 = a[1].parse().expect("call_operand");
    let want_const: i32 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(i32::MIN);
    let window: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(12);
    let list_all = want_const == i32::MIN;
    if list_all {
        let mut i = 0usize;
        while i < d.insns.len() {
            let ins = &d.insns[i];
            if ins.op == Opcode::Call && i > 0 && d.insns[i-1].op == Opcode::Const && d.insns[i-1].operand == Some(call_op) {
                // find the preceding ARG's CONST (the string/int arg pushed just before this one)
                let mut consts = vec![];
                let lo = i.saturating_sub(30);
                for j in lo..i {
                    if d.insns[j].op == Opcode::Const {
                        consts.push(d.insns[j].operand.unwrap_or(0));
                    }
                }
                let raw_str = |addr: i32| -> Option<String> {
                    let a = addr as usize;
                    if a >= q.data.len() { return None; }
                    let rest = &q.data[a..];
                    let end = rest.iter().position(|&b| b == 0)?;
                    let s = &rest[..end.min(200)];
                    if s.len() < 2 || !s.iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7f)) {
                        return None;
                    }
                    Some(String::from_utf8_lossy(s).into_owned())
                };
                let strs: Vec<String> = consts.iter().rev()
                    .filter_map(|&v| q.string_at(v).or_else(|| raw_str(v)))
                    .collect();
                println!("insn {} (addr 0x{:x}): CALL {} consts={:?} strs={:?}", i, i*4, call_op, consts, strs);
            }
            i += ins.size as usize;
        }
        return;
    }
    let mut n = 0;
    let mut i = 0usize;
    while i < d.insns.len() {
        let ins = &d.insns[i];
        let is_target_call = ins.op == Opcode::Call
            && i > 0
            && d.insns[i - 1].op == Opcode::Const
            && d.insns[i - 1].operand == Some(call_op);
        if is_target_call {
            let lo = i.saturating_sub(window);
            let mut found = false;
            for j in lo..i {
                if d.insns[j].op == Opcode::Const && d.insns[j].operand == Some(want_const) {
                    found = true;
                    break;
                }
            }
            if found {
                println!("CALL {} at insn {} (addr 0x{:x}) with nearby CONST {} in window [{}..{})", call_op, i, i * 4, want_const, lo, i);
                for j in lo..=i {
                    println!("  {}: {}", j, d.insns[j]);
                }
                n += 1;
            }
        }
        i += ins.size as usize;
    }
    println!("total matches: {}", n);
}
