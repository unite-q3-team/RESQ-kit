//! QVM disassembler.
//!
//! Decodes exactly `instructionCount` instructions (matching
//! VM_PrepareInterpreter). The interpreter does NOT walk the whole code
//! buffer — the trailing 3 pad bytes (0x00) are not decoded as instructions.
//!
//! Builds:
//! - `insns[i]`: the i-th instruction (index = instruction number)
//! - `insn_at[pc]`: index of instruction at byte offset `pc`

use std::collections::HashMap;
use std::fmt;

use crate::loader::Qvm;
use crate::opcodes::Opcode;

/// A single decoded instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    /// Instruction number (0-based).
    pub idx: usize,
    /// Byte offset in the code segment.
    pub addr: usize,
    /// Opcode.
    pub op: Opcode,
    /// Raw operand: int32 for CONST/LOCAL/ENTER/LEAVE/BLOCK_COPY and branch
    /// ops; byte value for ARG. `None` when the opcode has no operand.
    pub operand: Option<i32>,
    /// On-disk byte size.
    pub size: usize,
    /// For branch/comparison ops: the INSTRUCTION INDEX of the jump
    /// destination (JUMP is indirect — its target is popped from the stack,
    /// so it stays `None` unless resolved later).
    pub target: Option<usize>,
}

impl Insn {
    pub fn name(&self) -> &'static str {
        self.op.name()
    }
}

impl fmt::Display for Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{} @{:#06x} {}", self.idx, self.addr, self.name())?;
        if let Some(opd) = self.operand {
            write!(f, " {opd}")?;
        }
        if let Some(t) = self.target {
            write!(f, " ->#{t}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DisasmError {
    pub insn_idx: usize,
    pub n: usize,
    pub pc: usize,
    pub code_len: usize,
}

impl fmt::Display for DisasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "code exhausted at instruction {}/{} (pc={} len={})",
            self.insn_idx, self.n, self.pc, self.code_len
        )
    }
}

impl std::error::Error for DisasmError {}

/// Result of [`disassemble`].
#[derive(Debug)]
pub struct Disassembly {
    pub insns: Vec<Insn>,
    /// byte offset in code segment -> instruction index
    pub insn_at: HashMap<usize, usize>,
}

impl Disassembly {
    /// Look up the instruction that starts at byte offset `pc`.
    pub fn at(&self, pc: usize) -> Option<&Insn> {
        self.insn_at.get(&pc).map(|&i| &self.insns[i])
    }
}

/// Decode exactly `instructionCount` instructions from the code segment.
pub fn disassemble(qvm: &Qvm) -> Result<Disassembly, DisasmError> {
    let code = &qvm.code;
    let n = qvm.instruction_count as usize;
    let mut insns = Vec::with_capacity(n);
    let mut insn_at: HashMap<usize, usize> = HashMap::with_capacity(n);

    let mut pc = 0usize;
    for i in 0..n {
        if pc >= code.len() {
            return Err(DisasmError {
                insn_idx: i,
                n,
                pc,
                code_len: code.len(),
            });
        }
        let op = Opcode::from_u8(code[pc]).unwrap_or(Opcode::Undef);
        insn_at.insert(pc, i);

        let (operand, target, size) = if op.has_int32_operand() {
            let v = i32::from_le_bytes([code[pc + 1], code[pc + 2], code[pc + 3], code[pc + 4]]);
            let tgt = if op.is_branch_idx() {
                Some(v as usize)
            } else {
                None
            };
            (Some(v), tgt, 1 + 4)
        } else if op.has_byte_operand() {
            (Some(code[pc + 1] as i32), None, 1 + 1)
        } else {
            (None, None, 1)
        };

        insns.push(Insn {
            idx: i,
            addr: pc,
            op,
            operand,
            size,
            target,
        });
        pc += size;
    }

    Ok(Disassembly { insns, insn_at })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::parse;

    fn qvm_from_parts(code: &[u8], instr_count: i32) -> crate::loader::Qvm {
        let mut f = Vec::new();
        for v in [
            0x12721444u32,
            instr_count as u32,
            32u32,
            code.len() as u32,
            32 + code.len() as u32,
            0u32,
            0u32,
            0u32,
        ] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(code);
        parse(&f).unwrap()
    }

    #[test]
    fn decodes_typical_sequence() {
        // ENTER 36; LOCAL 44; LOAD4; CONST 5; ADD; ARG 8; CONST 1800; CALL; POP; LEAVE 36
        let code = [
            0x03, 36, 0, 0, 0, // ENTER 36
            0x09, 44, 0, 0, 0,    // LOCAL 44
            0x1d, // LOAD4
            0x08, 5, 0, 0, 0,    // CONST 5
            0x26, // ADD
            0x21, 8, // ARG 8
            0x08, 0x08, 0x07, 0, 0,    // CONST 1800
            0x05, // CALL
            0x07, // POP
            0x04, 36, 0, 0, 0, // LEAVE 36
        ];
        let q = qvm_from_parts(&code, 10);
        let d = disassemble(&q).unwrap();
        assert_eq!(d.insns.len(), 10);
        assert_eq!(d.insns[0].op, Opcode::Enter);
        assert_eq!(d.insns[0].operand, Some(36));
        assert_eq!(d.insns[3].op, Opcode::Const);
        assert_eq!(d.insns[4].op, Opcode::Add);
        assert_eq!(d.insns[5].op, Opcode::Arg);
        assert_eq!(d.insns[5].operand, Some(8));
        assert_eq!(d.insns[6].op, Opcode::Const);
        assert_eq!(d.insns[6].operand, Some(1800));
        assert_eq!(d.insns[7].op, Opcode::Call);
        assert_eq!(d.insns[8].op, Opcode::Pop);
        assert_eq!(d.insns[9].op, Opcode::Leave);
        // addresses are cumulative
        assert_eq!(d.insns[1].addr, 5);
        assert_eq!(d.insns[9].addr, 26);
        assert_eq!(d.insns[9].size, 5);
    }

    #[test]
    fn branch_target_is_insn_index() {
        // CONST 1; CONST 2; GTI #0; LEAVE 0
        let code = [
            0x08, 1, 0, 0, 0, 0x08, 2, 0, 0, 0, 0x0f, 0, 0, 0, 0, // GTI 0
            0x04, 0, 0, 0, 0,
        ];
        let q = qvm_from_parts(&code, 4);
        let d = disassemble(&q).unwrap();
        assert_eq!(d.insns[2].op, Opcode::Gti);
        assert_eq!(d.insns[2].target, Some(0));
        assert_eq!(d.insns[2].operand, Some(0));
    }

    #[test]
    fn decodes_exactly_instruction_count() {
        // 2 instructions + 3 pad bytes: interpreter stops at instructionCount
        let code = [0x03, 0, 0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0];
        let q = qvm_from_parts(&code, 2);
        let d = disassemble(&q).unwrap();
        assert_eq!(d.insns.len(), 2);
        assert_eq!(d.insns[1].op, Opcode::Leave);
        assert_eq!(d.insns[1].addr, 5);
    }

    #[test]
    fn code_exhaustion_detected() {
        let code = [0x03, 0, 0, 0, 0]; // 1 ENTER but claim 3 instructions
        let q = qvm_from_parts(&code, 3);
        assert!(disassemble(&q).is_err());
    }
}
