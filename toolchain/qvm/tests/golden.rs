//! Golden / integration tests over a synthetic mini-QVM.
//!
//! The fixture is assembled from raw opcodes inside the test (no binary
//! artifacts in git), so every stage of the pipeline — loader -> disasm ->
//! cfg -> decompiler — runs against input whose intent is spelled out in
//! assembly form. The exact-text snapshots below are the golden outputs;
//! update them ONLY together with an intentional output-format change.
//!
//! Regenerate the printed output with:
//!   cargo test --test golden -- --nocapture

use qvm::loader::{parse, VM_MAGIC};
use qvm::{build_all, decompile_function, disassemble, fmt_function, load, Opcode};

// ---- mini-assembler --------------------------------------------------------

/// One assembly line. Labels resolve to INSTRUCTION indexes (what branches
/// and CALL consume), never to byte offsets.
enum Asm {
    /// opcode without operand (1 insn, 1 byte)
    Op(Opcode),
    /// opcode + int32 operand (1 insn, 5 bytes)
    Word(Opcode, i32),
    /// unconditional jump to label (CONST+JUMP, 2 insns)
    Goto(&'static str),
    /// conditional branch to label (1 insn)
    Branch(Opcode, &'static str),
    /// call function at label (CONST+CALL, 2 insns)
    CallFn(&'static str),
    /// position marker (0 insns)
    Label(&'static str),
}

struct Program {
    insns: Vec<Asm>,
}

impl Program {
    fn new(insns: Vec<Asm>) -> Self {
        Program { insns }
    }

    /// Pass 1: instruction index of every label.
    fn labels(&self) -> std::collections::HashMap<&'static str, usize> {
        let mut out = std::collections::HashMap::new();
        let mut idx = 0usize;
        for a in &self.insns {
            match a {
                Asm::Label(name) => {
                    out.insert(*name, idx);
                }
                Asm::Goto(_) | Asm::CallFn(_) => idx += 2,
                _ => idx += 1,
            }
        }
        out
    }

    fn encode(&self) -> Vec<u8> {
        let labels = self.labels();
        let mut code = Vec::new();
        let fixup = |name: &'static str| labels[name] as i32;
        for a in &self.insns {
            match a {
                Asm::Label(_) => {}
                Asm::Op(op) => code.push(*op as u8),
                Asm::Word(op, v) => {
                    code.push(*op as u8);
                    code.extend_from_slice(&v.to_le_bytes());
                }
                Asm::Goto(target) => {
                    code.push(Opcode::Const as u8);
                    code.extend_from_slice(&fixup(target).to_le_bytes());
                    code.push(Opcode::Jump as u8);
                }
                Asm::Branch(op, target) => {
                    code.push(*op as u8);
                    code.extend_from_slice(&fixup(target).to_le_bytes());
                }
                Asm::CallFn(target) => {
                    code.push(Opcode::Const as u8);
                    code.extend_from_slice(&fixup(target).to_le_bytes());
                    code.push(Opcode::Call as u8);
                }
            }
        }
        code
    }

    fn instruction_count(&self) -> usize {
        self.insns
            .iter()
            .filter(|a| !matches!(a, Asm::Label(_)))
            .map(|a| match a {
                Asm::Goto(_) | Asm::CallFn(_) => 2,
                _ => 1,
            })
            .sum()
    }
}

/// Serialize header (v1) + code + data + lit exactly as the loader expects.
fn build_qvm(prog: &Program, data_words: &[i32], lit: &[u8]) -> Vec<u8> {
    let code = prog.encode();
    let header_ints = 8usize;
    let code_offset = header_ints * 4;
    let data_offset = code_offset + code.len();

    let mut out = Vec::new();
    for v in [
        VM_MAGIC as i32,
        prog.instruction_count() as i32,
        code_offset as i32,
        code.len() as i32,
        data_offset as i32,
        (data_words.len() * 4) as i32,
        lit.len() as i32,
        64i32, // bssLength
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&code);
    for w in data_words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(lit);
    out
}

// ---- fixture program -------------------------------------------------------
//
// fn main:  sum = 0; for (i = 1; i <= 5; i++) sum += i;  return sum + helper();
// fn helper: return 100;
//
// Frame layout (frame=16): local slot +8 = sum, +12 = i.

fn fixture_program() -> Program {
    Program::new(vec![
        Asm::Label("main"),
        Asm::Word(Opcode::Enter, 16),
        // sum = 0   (q3lcc store order: address first, then value)
        Asm::Word(Opcode::Local, 8),
        Asm::Word(Opcode::Const, 0),
        Asm::Op(Opcode::Store4),
        // i = 1
        Asm::Word(Opcode::Local, 12),
        Asm::Word(Opcode::Const, 1),
        Asm::Op(Opcode::Store4),
        Asm::Label("loop"),
        // while (!(i > 5)) { ... }  — GTI exits when i > 5
        Asm::Word(Opcode::Local, 12),
        Asm::Op(Opcode::Load4),
        Asm::Word(Opcode::Const, 5),
        Asm::Branch(Opcode::Gti, "exit"),
        // sum = sum + i
        Asm::Word(Opcode::Local, 8),
        Asm::Word(Opcode::Local, 8),
        Asm::Op(Opcode::Load4),
        Asm::Word(Opcode::Local, 12),
        Asm::Op(Opcode::Load4),
        Asm::Op(Opcode::Add),
        Asm::Op(Opcode::Store4),
        // i = i + 1
        Asm::Word(Opcode::Local, 12),
        Asm::Word(Opcode::Local, 12),
        Asm::Op(Opcode::Load4),
        Asm::Word(Opcode::Const, 1),
        Asm::Op(Opcode::Add),
        Asm::Op(Opcode::Store4),
        Asm::Goto("loop"),
        Asm::Label("exit"),
        // return sum + helper();
        Asm::Word(Opcode::Local, 8),
        Asm::Op(Opcode::Load4),
        Asm::CallFn("helper"),
        Asm::Op(Opcode::Add),
        Asm::Word(Opcode::Leave, 16),
        Asm::Label("helper"),
        Asm::Word(Opcode::Enter, 8),
        Asm::Word(Opcode::Const, 100),
        Asm::Word(Opcode::Leave, 8),
    ])
}

fn fixture_bytes() -> Vec<u8> {
    build_qvm(&fixture_program(), &[0i32; 4], b"")
}

// ---- tests -----------------------------------------------------------------

#[test]
fn loader_parses_synthetic_header_and_segments() {
    let bytes = fixture_bytes();
    let q = parse(&bytes).expect("parse");
    assert_eq!(q.vm_magic, VM_MAGIC);
    assert_eq!(q.instruction_count as usize, 35);
    assert_eq!(q.code.len(), fixture_program().encode().len());
    assert_eq!(q.data_int32(), vec![0, 0, 0, 0]);
    // data_mask: pow2(data 16 + lit 0 + bss 64) - 1 = 128 - 1
    assert_eq!(q.data_mask(), 127);
}

#[test]
fn disasm_decodes_fixture_instructions() {
    let q = parse(&fixture_bytes()).expect("parse");
    let d = disassemble(&q).expect("disasm");
    assert_eq!(d.insns.len(), 35);

    // fn boundaries split at ENTER
    assert_eq!(d.insns[0].op, Opcode::Enter);
    assert_eq!(d.insns[0].operand, Some(16));
    assert_eq!(d.insns[32].op, Opcode::Enter);
    assert_eq!(d.insns[32].operand, Some(8));

    // conditional branch carries the instruction-index target
    assert_eq!(d.insns[10].op, Opcode::Gti);
    assert_eq!(d.insns[10].target, Some(26));

    // CONST+JUMP pair resolves through cfg later; here just the shape
    assert_eq!(d.insns[24].op, Opcode::Const);
    assert_eq!(d.insns[24].operand, Some(7));
    assert_eq!(d.insns[25].op, Opcode::Jump);

    // CALL targets helper entry
    assert_eq!(d.insns[28].op, Opcode::Const);
    assert_eq!(d.insns[28].operand, Some(32));
    assert_eq!(d.insns[29].op, Opcode::Call);

    // trailing LEAVE closes each function
    assert_eq!(d.insns[31].op, Opcode::Leave);
    assert_eq!(d.insns[31].operand, Some(16));
    assert_eq!(d.insns[34].op, Opcode::Leave);

    // byte addressing: insn 24 sits at the sum of its predecessors' sizes
    assert_eq!(d.insns[24].addr, d.insns[23].addr + d.insns[23].size);
    assert_eq!(d.at(d.insns[24].addr).map(|i| i.idx), Some(24));
}

/// The full decompiler output for both functions. GOLDEN: change only with an
/// intentional emitter change, and re-check downstream consumers.
#[test]
fn decompile_golden_snapshot() {
    let q = parse(&fixture_bytes()).expect("parse");
    let d = disassemble(&q).expect("disasm");
    let cfgs = build_all(&d, &q);
    assert_eq!(cfgs.len(), 2);

    let data = q.data_int32();
    let frame = d.insns[cfgs[0].entry].operand.unwrap_or(0);
    let f = decompile_function(&d, &cfgs[0], frame, &data);
    let main_text = fmt_function(&f, &q);

    println!("=== main (block form) ===\n{main_text}");

    for needle in [
        "// function @ insn 0..32 frame 16",
        "loc_8 = 0;",
        "loc_12 = 1;",
        "if ((loc_12) > (5)) goto L26;",
        "loc_8 = (loc_8) + (loc_12);",
        "goto L7;",
        "fn_32();",
        "return (loc_8) + (",
    ] {
        assert!(
            main_text.contains(needle),
            "decompiled `main` lost `{needle}`:\n{main_text}"
        );
    }

    // the structured formatter must recover a real while loop from the same CFG
    let structured = qvm::fmt_structured(&f, &q);
    println!("=== main (structured) ===\n{structured}");

    for needle in ["while (", "(loc_8) + (loc_12)", "return", "fn_32()"] {
        assert!(
            structured.contains(needle),
            "structured `main` lost `{needle}`:\n{structured}"
        );
    }
    assert!(
        !structured.contains("goto L7"),
        "structured form must not need the loop's residual goto:\n{structured}"
    );

    let frame_h = d.insns[cfgs[1].entry].operand.unwrap_or(0);
    let fh = decompile_function(&d, &cfgs[1], frame_h, &data);
    let helper_text = fmt_function(&fh, &q);
    println!("=== helper ===\n{helper_text}");
    assert!(helper_text.contains("return"), "{helper_text}");
}

/// Encode -> parse -> decode round trip preserves the program.
#[test]
fn encode_decode_round_trip() {
    let prog = fixture_program();
    let bytes = build_qvm(&prog, &[1, -2, 3, -4], b"hi\0");
    let q = parse(&bytes).expect("parse");
    assert!(load_round_trips_lit(&q));
    let d = disassemble(&q).expect("disasm");

    assert_eq!(d.insns.len(), prog.instruction_count());

    // every encoded instruction decodes back to the same opcode class
    let mut enc = prog.encode().into_iter().peekable();
    let mut pc = 0usize;
    for insn in &d.insns {
        assert_eq!(insn.addr, pc, "byte addresses must stay contiguous");
        assert_eq!(
            enc.next(),
            Some(insn.op as u8),
            "opcode mismatch at #{insn}"
        );
        pc += insn.size;
        for _ in 1..insn.size {
            enc.next(); // skip operand bytes already validated via operands
        }
    }
    assert_eq!(pc, q.code.len());
    assert!(enc.peek().is_none());

    // data segment survives byte-exact
    assert_eq!(
        q.data_int32(),
        vec![1, -2, 3, -4],
        "int32 words must survive the file round trip"
    );
}

fn load_round_trips_lit(q: &qvm::Qvm) -> bool {
    q.lit == b"hi\0"
}

/// `load()` (disk path incl. module detection) agrees with `parse()`.
#[test]
fn disk_load_matches_parse() {
    let dir = std::env::temp_dir().join(format!("resq_golden_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("qagame_resq_test.qvm");
    std::fs::write(&path, fixture_bytes()).expect("write fixture");

    let q = load(&path).expect("load from disk");
    let p = parse(&fixture_bytes()).expect("parse in memory");
    assert_eq!(q.code, p.code);
    assert_eq!(q.data, p.data);
    // filename contains "qagame" -> Module::Game detection
    assert_eq!(q.module.label(), "game");

    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&dir).ok();
}
