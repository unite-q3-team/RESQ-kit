//! probe_check: static validation of a QVM mirroring Quake3e VM_CheckInstructions
//! (vm.c:1239-1578) + VM_PrepareInterpreter2 opStack tracking (vm.c:1167-1211).
//!
//! The engine validates EVERY instruction at VM_Create time (both the JIT
//! VM_CompileX86 and interpreter2), so a bad constant store address crashes the
//! whole engine even if the executed path never reaches it. This probe replicates
//! that validation so we can find all errors in a rebuilt QVM before the user
//! boots the game.
//!
//! Usage: probe_check <qvm>

use std::env;
use std::process::exit;

use qvm::disasm::disassemble;
use qvm::loader::load;
use qvm::opcodes::Opcode;

fn stack_effect(op: Opcode) -> i32 {
    use Opcode::*;
    match op {
        Undef | Ignore | Break => 0,
        Enter => 0,
        Leave => -4,
        Call => 0,
        Push => 4,
        Pop => -4,
        Const | Local => 4,
        Jump => -4,
        Eq | Ne | Lti | Lei | Gti | Gei | Ltu | Leu | Gtu | Geu | Eqf | Nef | Ltf | Lef | Gtf
        | Gef => -8,
        Load1 | Load2 | Load4 => 0,
        Store1 | Store2 | Store4 => -8,
        Arg => -4,
        BlockCopy => -8,
        Sex8 | Sex16 => 0,
        Negi => 0,
        Add | Sub | Divi | Divu | Modi | Modu | Muli | Mulu | Band | Bor | Bxor | Lsh | Rshi
        | Rshu => -4,
        Bcom => 0,
        Negf => 0,
        AddF | SubF | DivF | MulF => -4,
        Cvif => 0,
        Cvfi => 0,
    }
}

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: probe_check <qvm>");
        exit(2);
    });
    let q = load(&path).expect("load");
    let dis = disassemble(&q).expect("disasm");
    let n = dis.insns.len();
    let data_len = q.data_mask() as i32 + 1;

    // pass 1: running opStack, stored per-instruction BEFORE its own effect
    let mut pre: Vec<i32> = vec![0; n];
    let mut errs: Vec<String> = Vec::new();
    {
        let mut os: i32 = 0;
        for i in 0..n {
            pre[i] = os;
            os += stack_effect(dis.insns[i].op);
            if os < 0 {
                errs.push(format!("opStack underflow at {i}"));
            }
            if os >= 30 * 4 {
                errs.push(format!("opStack overflow at {i}"));
            }
        }
    }

    // pass 2: VM_CheckInstructions
    let mut ptr: Vec<Option<usize>> = vec![None; 64];
    let mut os: i32 = 0;
    let mut op1 = Opcode::Undef;
    let mut proc: Option<usize> = None; // index of current ENTER
    let mut pstack: i32 = 0;
    let mut startp: usize = 0;
    let mut endp: usize = n - 1;
    let mut safe_stores = 0usize;
    let mut unsafe_stores = 0usize;

    for i in 0..n {
        let ci = &dis.insns[i];
        let op0 = ci.op;
        let m = stack_effect(op0);
        os += m;
        if m >= 0 {
            ptr[(os / 4) as usize] = Some(i);
        } else if m > -8 {
            ptr[(os / 4) as usize] = Some(i);
        }

        match op0 {
            Opcode::Enter => {
                if proc.is_some() {
                    errs.push(format!("missing proc end before {i}"));
                }
                if pre[i] != 0 {
                    errs.push(format!("bad entry opstack {} at {i}", pre[i]));
                }
                let v = ci.operand.unwrap_or(0);
                if v < 0 || v >= 0x10000 || v & 3 != 0 {
                    errs.push(format!("bad entry programStack {v} at {i}"));
                }
                pstack = v;
                let mut endp2 = 0usize;
                let mut j = i + 1;
                while j + 1 < n {
                    if dis.insns[j].op == Opcode::Push && dis.insns[j + 1].op == Opcode::Leave {
                        endp2 = j;
                        break;
                    }
                    j += 1;
                }
                if endp2 == 0 {
                    errs.push(format!("missing end proc for {i}"));
                } else {
                    endp = endp2;
                }
                startp = i + 1;
                proc = Some(i);
            }
            Opcode::Leave => {
                let v = ci.operand.unwrap_or(0);
                if pstack != v {
                    errs.push(format!("bad programStack {v} at {i}"));
                }
                if pre[i] != 4 {
                    errs.push(format!("bad opStack {} at {i}", pre[i]));
                }
                if v < 0 || v >= 0x10000 || v & 3 != 0 {
                    errs.push(format!("bad return programStack {v} at {i}"));
                }
                if op1 == Opcode::Push {
                    proc = None;
                    startp = i + 1;
                    endp = n - 1;
                }
            }
            op if op.is_branch_idx() => {
                let v = ci.operand.unwrap_or(0);
                if pre[i] < 8 {
                    errs.push(format!("bad jump opStack {} at {i}", pre[i]));
                }
                if v < startp as i32 || v > endp as i32 {
                    errs.push(format!("jump target {v} at {i} is out of range ({startp},{endp})"));
                } else if pre[v as usize] != pre[i] - 8 {
                    errs.push(format!(
                        "jump target {v} has bad opStack {}",
                        pre[v as usize]
                    ));
                }
            }
            Opcode::Jump => {
                if pre[i] < 4 {
                    errs.push(format!("bad jump opStack {} at {i}", pre[i]));
                }
                if op1 == Opcode::Const {
                    let v = dis.insns[i - 1].operand.unwrap_or(0);
                    if v < startp as i32 || v > endp as i32 {
                        errs.push(format!(
                            "jump target {v} at {} is out of range ({startp},{endp})",
                            i - 1
                        ));
                    } else {
                        let t = v as usize;
                        if pre[t] != pre[i] - 4 {
                            errs.push(format!(
                                "jump target {v} has bad opStack {}",
                                pre[t]
                            ));
                        }
                        if dis.insns[t].op == Opcode::Enter {
                            errs.push(format!("jump target {v} has bad opcode ENTER"));
                        }
                        if v == i as i32 - 1 {
                            errs.push(format!("self loop at {v}"));
                        }
                    }
                }
            }
            Opcode::Call => {
                if pre[i] < 4 {
                    errs.push(format!("bad call opStack at {i}"));
                }
                if op1 == Opcode::Const {
                    let v = dis.insns[i - 1].operand.unwrap_or(0);
                    if v >= 0 {
                        if v >= n as i32 {
                            errs.push(format!("call target {v} is out of range"));
                        } else if dis.insns[v as usize].op != Opcode::Enter {
                            errs.push(format!(
                                "call target {v} has bad opcode {}",
                                dis.insns[v as usize].op.name()
                            ));
                        } else if v == 0 {
                            errs.push(format!("explicit vmMain call inside VM at {i}"));
                        }
                    }
                }
            }
            Opcode::Arg => {
                let v = ci.operand.unwrap_or(0) & 255;
                if proc.is_none() {
                    errs.push(format!("missing proc frame for ARG {v} at {i}"));
                } else if v < 8 || v > pstack - 4 || v & 3 != 0 {
                    errs.push(format!("bad argument address {v} at {i}"));
                }
            }
            Opcode::Local => {
                let v = ci.operand.unwrap_or(0);
                if proc.is_none() {
                    errs.push(format!("missing proc frame for LOCAL {v} at {i}"));
                } else if i + 1 < n
                    && matches!(
                        dis.insns[i + 1].op,
                        Opcode::Load1 | Opcode::Load2 | Opcode::Load4
                    )
                {
                    let fsz = proc.map(|p| dis.insns[p].operand.unwrap_or(0)).unwrap_or(0);
                    if v < 8 || (proc.is_some() && v >= fsz + 256) {
                        errs.push(format!("bad LOCAL address {v} at {i}"));
                    }
                }
            }
            Opcode::Load1 | Opcode::Load2 | Opcode::Load4 => {
                if op1 == Opcode::Const {
                    let v = dis.insns[i - 1].operand.unwrap_or(0);
                    let size = match op0 {
                        Opcode::Load1 => 1,
                        Opcode::Load2 => 2,
                        _ => 4,
                    };
                    if v < 0 || v > data_len - size {
                        errs.push(format!("bad {} address {v} at {}", op0.name(), i - 1));
                    }
                }
            }
            Opcode::Store1 | Opcode::Store2 | Opcode::Store4 => {
                let slot = (os / 4 + 1) as usize;
                if let Some(xi) = ptr[slot] {
                    let xop = dis.insns[xi].op;
                    let xv = dis.insns[xi].operand.unwrap_or(0);
                    if xop == Opcode::Const || xop == Opcode::Local {
                        let ok = match xop {
                            Opcode::Const => xv >= 0 && xv < data_len,
                            Opcode::Local => {
                                let fsz = proc
                                    .map(|p| dis.insns[p].operand.unwrap_or(0))
                                    .unwrap_or(0);
                                xv >= 8 && (proc.is_none() || xv < fsz + 256)
                            }
                            _ => false,
                        };
                        if ok {
                            safe_stores += 1;
                        } else {
                            errs.push(format!("bad {} address {xv} at {xi}", op0.name()));
                        }
                        continue;
                    }
                }
                unsafe_stores += 1;
            }
            Opcode::BlockCopy => {
                let v = ci.operand.unwrap_or(0);
                if v >= data_len {
                    errs.push(format!("bad count {v} for block copy at {}", i.saturating_sub(1)));
                }
                for (label, rel) in [("src", 2usize), ("dst", 1usize)] {
                    let slot = (os / 4 + rel as i32) as usize;
                    if let Some(xi) = ptr[slot] {
                        let xop = dis.insns[xi].op;
                        let xv = dis.insns[xi].operand.unwrap_or(0);
                        if xop == Opcode::Const && !(xv >= 0 && xv < data_len) {
                            errs.push(format!("bad {label} for block copy at {xi}"));
                        } else if xop == Opcode::Local {
                            let fsz = proc
                                .map(|p| dis.insns[p].operand.unwrap_or(0))
                                .unwrap_or(0);
                            if !(xv >= 8 && (proc.is_none() || xv < fsz + 256)) {
                                errs.push(format!("bad {label} for block copy at {xi}"));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        op1 = op0;
    }

    if errs.is_empty() {
        println!(
            "{path}: OK ({} instructions, dataLength={data_len}, stores safe={safe_stores} unsafe={unsafe_stores})",
            n
        );
    } else {
        println!("{path}: {} ERRORS", errs.len());
        for e in errs.iter().take(60) {
            println!("  {e}");
        }
        exit(1);
    }
}
