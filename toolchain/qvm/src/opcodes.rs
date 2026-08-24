//! QVM opcode table and instruction-length decoder.
//!
//! Encoding rules (from ioq3 VM_PrepareInterpreter in vm_interpreted.c):
//!
//! - Default: 1 byte (opcode only).
//! - opcode + 4-byte little-endian int32:
//!     OP_ENTER, OP_LEAVE, OP_CONST, OP_LOCAL, OP_BLOCK_COPY,
//!     and ALL comparison ops (OP_EQ..OP_GEF). The comparison operand is an
//!     INSTRUCTION INDEX, resolved via instructionPointers at load time.
//! - opcode + 1 byte: OP_ARG (offset from programStack).

/// QVM opcodes (enum opcode_t from ioq3 vm_local.h; numeric values are the
/// values in the bytecode stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opcode {
    Undef = 0,
    Ignore = 1,
    Break = 2,
    Enter = 3,
    Leave = 4,
    Call = 5,
    Push = 6,
    Pop = 7,
    Const = 8,
    Local = 9,
    Jump = 10,
    Eq = 11,
    Ne = 12,
    Lti = 13,
    Lei = 14,
    Gti = 15,
    Gei = 16,
    Ltu = 17,
    Leu = 18,
    Gtu = 19,
    Geu = 20,
    Eqf = 21,
    Nef = 22,
    Ltf = 23,
    Lef = 24,
    Gtf = 25,
    Gef = 26,
    Load1 = 27,
    Load2 = 28,
    Load4 = 29,
    Store1 = 30,
    Store2 = 31,
    Store4 = 32,
    Arg = 33,
    BlockCopy = 34,
    Sex8 = 35,
    Sex16 = 36,
    Negi = 37,
    Add = 38,
    Sub = 39,
    Divi = 40,
    Divu = 41,
    Modi = 42,
    Modu = 43,
    Muli = 44,
    Mulu = 45,
    Band = 46,
    Bor = 47,
    Bxor = 48,
    Bcom = 49,
    Lsh = 50,
    Rshi = 51,
    Rshu = 52,
    Negf = 53,
    AddF = 54,
    SubF = 55,
    DivF = 56,
    MulF = 57,
    Cvif = 58,
    Cvfi = 59,
}

impl Opcode {
    pub fn from_u8(op: u8) -> Option<Opcode> {
        Some(match op {
            0 => Opcode::Undef,
            1 => Opcode::Ignore,
            2 => Opcode::Break,
            3 => Opcode::Enter,
            4 => Opcode::Leave,
            5 => Opcode::Call,
            6 => Opcode::Push,
            7 => Opcode::Pop,
            8 => Opcode::Const,
            9 => Opcode::Local,
            10 => Opcode::Jump,
            11 => Opcode::Eq,
            12 => Opcode::Ne,
            13 => Opcode::Lti,
            14 => Opcode::Lei,
            15 => Opcode::Gti,
            16 => Opcode::Gei,
            17 => Opcode::Ltu,
            18 => Opcode::Leu,
            19 => Opcode::Gtu,
            20 => Opcode::Geu,
            21 => Opcode::Eqf,
            22 => Opcode::Nef,
            23 => Opcode::Ltf,
            24 => Opcode::Lef,
            25 => Opcode::Gtf,
            26 => Opcode::Gef,
            27 => Opcode::Load1,
            28 => Opcode::Load2,
            29 => Opcode::Load4,
            30 => Opcode::Store1,
            31 => Opcode::Store2,
            32 => Opcode::Store4,
            33 => Opcode::Arg,
            34 => Opcode::BlockCopy,
            35 => Opcode::Sex8,
            36 => Opcode::Sex16,
            37 => Opcode::Negi,
            38 => Opcode::Add,
            39 => Opcode::Sub,
            40 => Opcode::Divi,
            41 => Opcode::Divu,
            42 => Opcode::Modi,
            43 => Opcode::Modu,
            44 => Opcode::Muli,
            45 => Opcode::Mulu,
            46 => Opcode::Band,
            47 => Opcode::Bor,
            48 => Opcode::Bxor,
            49 => Opcode::Bcom,
            50 => Opcode::Lsh,
            51 => Opcode::Rshi,
            52 => Opcode::Rshu,
            53 => Opcode::Negf,
            54 => Opcode::AddF,
            55 => Opcode::SubF,
            56 => Opcode::DivF,
            57 => Opcode::MulF,
            58 => Opcode::Cvif,
            59 => Opcode::Cvfi,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Opcode::Undef => "UNDEF",
            Opcode::Ignore => "IGNORE",
            Opcode::Break => "BREAK",
            Opcode::Enter => "ENTER",
            Opcode::Leave => "LEAVE",
            Opcode::Call => "CALL",
            Opcode::Push => "PUSH",
            Opcode::Pop => "POP",
            Opcode::Const => "CONST",
            Opcode::Local => "LOCAL",
            Opcode::Jump => "JUMP",
            Opcode::Eq => "EQ",
            Opcode::Ne => "NE",
            Opcode::Lti => "LTI",
            Opcode::Lei => "LEI",
            Opcode::Gti => "GTI",
            Opcode::Gei => "GEI",
            Opcode::Ltu => "LTU",
            Opcode::Leu => "LEU",
            Opcode::Gtu => "GTU",
            Opcode::Geu => "GEU",
            Opcode::Eqf => "EQF",
            Opcode::Nef => "NEF",
            Opcode::Ltf => "LTF",
            Opcode::Lef => "LEF",
            Opcode::Gtf => "GTF",
            Opcode::Gef => "GEF",
            Opcode::Load1 => "LOAD1",
            Opcode::Load2 => "LOAD2",
            Opcode::Load4 => "LOAD4",
            Opcode::Store1 => "STORE1",
            Opcode::Store2 => "STORE2",
            Opcode::Store4 => "STORE4",
            Opcode::Arg => "ARG",
            Opcode::BlockCopy => "BLOCK_COPY",
            Opcode::Sex8 => "SEX8",
            Opcode::Sex16 => "SEX16",
            Opcode::Negi => "NEGI",
            Opcode::Add => "ADD",
            Opcode::Sub => "SUB",
            Opcode::Divi => "DIVI",
            Opcode::Divu => "DIVU",
            Opcode::Modi => "MODI",
            Opcode::Modu => "MODU",
            Opcode::Muli => "MULI",
            Opcode::Mulu => "MULU",
            Opcode::Band => "BAND",
            Opcode::Bor => "BOR",
            Opcode::Bxor => "BXOR",
            Opcode::Bcom => "BCOM",
            Opcode::Lsh => "LSH",
            Opcode::Rshi => "RSHI",
            Opcode::Rshu => "RSHU",
            Opcode::Negf => "NEGF",
            Opcode::AddF => "ADDF",
            Opcode::SubF => "SUBF",
            Opcode::DivF => "DIVF",
            Opcode::MulF => "MULF",
            Opcode::Cvif => "CVIF",
            Opcode::Cvfi => "CVFI",
        }
    }

    /// True if the opcode carries a 4-byte little-endian int32 operand.
    pub fn has_int32_operand(self) -> bool {
        use Opcode::*;
        matches!(
            self,
            Enter | Leave | Const | Local | BlockCopy
                | Eq | Ne | Lti | Lei | Gti | Gei
                | Ltu | Leu | Gtu | Geu | Eqf | Nef | Ltf | Lef | Gtf | Gef
        )
    }

    /// True if the opcode's int32 operand is an INSTRUCTION INDEX (branch target).
    pub fn is_branch_idx(self) -> bool {
        use Opcode::*;
        matches!(
            self,
            Eq | Ne | Lti | Lei | Gti | Gei | Ltu | Leu | Gtu | Geu | Eqf | Nef | Ltf | Lef | Gtf | Gef
        )
    }

    /// True if the opcode carries a 1-byte operand (ARG).
    pub fn has_byte_operand(self) -> bool {
        self == Opcode::Arg
    }

    /// Whether this instruction is a control-flow transfer.
    pub fn is_branch(self) -> bool {
        self.is_branch_idx() || self == Opcode::Jump
    }
}

/// On-disk byte length of an instruction given its opcode.
pub fn instr_length(op: Opcode) -> usize {
    if op.has_int32_operand() {
        1 + 4
    } else if op.has_byte_operand() {
        1 + 1
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_values_match_ioq3() {
        assert_eq!(Opcode::Undef as u8, 0);
        assert_eq!(Opcode::Enter as u8, 3);
        assert_eq!(Opcode::Jump as u8, 10);
        assert_eq!(Opcode::Load4 as u8, 29);
        assert_eq!(Opcode::Arg as u8, 33);
        assert_eq!(Opcode::Cvfi as u8, 59);
    }

    #[test]
    fn lengths() {
        assert_eq!(instr_length(Opcode::Add), 1);
        assert_eq!(instr_length(Opcode::Jump), 1);
        assert_eq!(instr_length(Opcode::Call), 1);
        assert_eq!(instr_length(Opcode::Enter), 5);
        assert_eq!(instr_length(Opcode::Eq), 5);
        assert_eq!(instr_length(Opcode::BlockCopy), 5);
        assert_eq!(instr_length(Opcode::Arg), 2);
    }

    #[test]
    fn branch_detection() {
        assert!(Opcode::Eq.is_branch());
        assert!(Opcode::Gef.is_branch_idx());
        assert!(Opcode::Jump.is_branch());
        assert!(!Opcode::Jump.is_branch_idx());
        assert!(!Opcode::Add.is_branch());
        assert!(!Opcode::Load4.is_branch());
    }

    #[test]
    fn from_u8_roundtrip() {
        for i in 0..60 {
            assert_eq!(Opcode::from_u8(i).unwrap() as u8, i);
        }
        assert!(Opcode::from_u8(60).is_none());
        assert!(Opcode::from_u8(255).is_none());
    }

    #[test]
    fn names() {
        assert_eq!(Opcode::Const.name(), "CONST");
        assert_eq!(Opcode::Muli.name(), "MULI");
        assert_eq!(Opcode::Undef.name(), "UNDEF");
    }
}
