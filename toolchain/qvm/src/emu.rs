//! QVM bytecode interpreter.
//!
//! Faithful port of ioq3 `VM_CallInterpreted` (code/qcommon/vm_interpreted.c)
//! plus `VM_BlockCopy` (code/qcommon/vm.c), so it can serve as the reference
//! semantics for the decompiler and for executing real .qvm functions.
//!
//! Key model differences from the C code:
//! - `programCounter` is an INSTRUCTION INDEX (like the operand of branch ops),
//!   not an offset into the expanded int-aligned code image. `CALL`/`JUMP`/
//!   comparison operands are already instruction indices on disk.
//! - The op stack is a 256-entry ring buffer (opStackOfs is `uint8_t` in C);
//!   entry 0 is seeded with `0xDEADBEEF` as in the interpreter.
//! - Memory is a single byte array of `dataMask+1` bytes: data + lit + bss.
//! - Syscalls go through a user-supplied handler `FnMut(&mut Memory, num, args)`.
//!
//! Stack layout on VM entry (from the VM_Call comment):
//!
//! ```text
//! sp+8+4k  arg k
//! sp+4     return stack (0)
//! sp       return address (-1 terminates the VM)
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::disasm::Insn;
use crate::loader::Qvm;
use crate::opcodes::Opcode;

pub const MAX_VMMAIN_ARGS: usize = 13;
pub const MAX_VMSYSCALL_ARGS: usize = 16;
pub const OPSTACK_RING: usize = 256;

/// Default step limit for the interpreter loop (safety valve against
/// non-terminating bytecode). `call` fails with [`EmuError::StepLimit`].
pub const DEFAULT_MAX_STEPS: usize = 100_000_000;

/// The VM data space: `dataMask+1` bytes = data + lit + bss.
///
/// Exposed to the syscall handler so traps can read/write VM memory directly
/// (e.g. `trap_Cvar_VariableStringBuffer`).
#[derive(Debug)]
pub struct Memory {
    pub data: Vec<u8>,
    pub data_mask: u32,
}

impl Memory {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Mask a VM data-space address.
    #[inline]
    pub fn masked(&self, addr: i32) -> usize {
        (addr as u32 & self.data_mask) as usize
    }

    /// Read a 4-byte word at a RAW offset (no masking) — used for the
    /// program stack. Returns `None` if out of bounds.
    pub fn read_i32_raw(&self, addr: i32) -> Option<i32> {
        let a = addr as usize;
        let w = self.data.get(a..a + 4)?;
        Some(i32::from_le_bytes([w[0], w[1], w[2], w[3]]))
    }

    /// Write a 4-byte word at a RAW offset (no masking). Returns `None` if
    /// out of bounds.
    pub fn write_i32_raw(&mut self, addr: i32, v: i32) -> Option<()> {
        let a = addr as usize;
        let w = self.data.get_mut(a..a + 4)?;
        w.copy_from_slice(&v.to_le_bytes());
        Some(())
    }

    #[inline]
    pub fn load1(&self, addr: i32) -> i32 {
        self.data[self.masked(addr)] as i32
    }

    #[inline]
    pub fn load2(&self, addr: i32) -> i32 {
        let a = self.masked(addr);
        (self.data[a] as u16 | (self.data[a + 1] as u16) << 8) as i32
    }

    #[inline]
    pub fn load4(&self, addr: i32) -> i32 {
        let a = self.masked(addr);
        i32::from_le_bytes([self.data[a], self.data[a + 1], self.data[a + 2], self.data[a + 3]])
    }

    #[inline]
    pub fn store1(&mut self, addr: i32, v: i32) {
        let a = self.masked(addr);
        self.data[a] = (v & 0xFF) as u8;
    }

    #[inline]
    pub fn store2(&mut self, addr: i32, v: i32) {
        let a = self.masked(addr);
        self.data[a] = (v & 0xFF) as u8;
        self.data[a + 1] = ((v >> 8) & 0xFF) as u8;
    }

    #[inline]
    pub fn store4(&mut self, addr: i32, v: i32) {
        let a = self.masked(addr);
        self.data[a..a + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// Syscall (trap) handler: `(memory, trap number, args) -> return value`.
/// The trap number is `-1 - CALL_operand` (as in the interpreter). `args`
/// has `MAX_VMSYSCALL_ARGS` slots.
pub type SyscallHandler = Box<dyn FnMut(&mut Memory, i32, &mut [i32]) -> i32>;

#[derive(Debug)]
pub enum EmuError {
    /// Unknown/unsupported opcode reached.
    Unsupported(Opcode),
    /// `max_steps` exceeded (runaway loop).
    StepLimit(usize),
    /// CALL/JUMP to an out-of-range instruction index.
    BadTarget { kind: &'static str, idx: i32 },
    /// Program-counter ran past the end of the instruction array.
    PcOverflow { pc: usize, len: usize },
    /// Raw (unmasked) program-stack access out of the data space.
    BadStackAddr { addr: i32, len: usize },
    /// Division or modulo by zero.
    DivByZero,
    /// BLOCK_COPY destination/source range crossed the data mask.
    BlockCopyRange { dest: u32, src: u32, n: i32, mask: u32 },
}

impl std::fmt::Display for EmuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmuError::Unsupported(op) => write!(f, "unsupported opcode {op:?}"),
            EmuError::StepLimit(n) => write!(f, "step limit ({n}) exceeded"),
            EmuError::BadTarget { kind, idx } => write!(f, "{kind} target out of range: {idx}"),
            EmuError::PcOverflow { pc, len } => write!(f, "program counter {pc} past end of code ({len} insns)"),
            EmuError::BadStackAddr { addr, len } => write!(f, "program-stack access at {addr} out of data space ({len} bytes)"),
            EmuError::DivByZero => write!(f, "division by zero"),
            EmuError::BlockCopyRange { dest, src, n, mask } => {
                write!(f, "BLOCK_COPY out of range: dest={dest:#x} src={src:#x} n={n} mask={mask:#x}")
            }
        }
    }
}

impl std::error::Error for EmuError {}

/// Interpreter statistics, useful for verification and profiling.
#[derive(Debug, Default)]
pub struct Stats {
    /// Instructions executed.
    pub steps: usize,
    /// Number of system calls made.
    pub syscalls: usize,
    /// trap number -> call count.
    pub syscall_counts: HashMap<i32, usize>,
    /// instruction index -> how many times it was the target of `ENTER`.
    pub entries: HashMap<usize, usize>,
}

/// QVM bytecode interpreter.
pub struct Emu<'a> {
    insns: &'a [Insn],
    /// VM data space.
    pub mem: Memory,
    /// Op stack ring buffer.
    op: [i32; OPSTACK_RING],
    op_ofs: u8,
    /// Program stack (frame pointer into the data space).
    program_stack: i32,
    /// Trap handler, if any.
    syscall: Option<SyscallHandler>,
    max_steps: usize,
    /// Interpreter statistics.
    pub stats: Stats,
    /// When set, trace executed instructions to stdout (for debugging).
    pub trace: bool,
    /// When set, log STORE instructions that touch this (masked) address.
    pub watch_store: Option<i32>,
    /// Optional side label printed in WATCH diagnostics.
    pub watch_label: Option<&'static str>,
    /// Instruction index of each system call, in call order (paired with the
    /// trap log recorded by the syscall handler). Useful for attributing traps
    /// to their call sites.
    pub trap_insns: Vec<usize>,
    /// When `trace` is set, the index of every executed instruction is also
    /// pushed here (the pc stream), so diagnostics can diff/loop-analyze the
    /// two sides without parsing stdout.
    pub step_pcs: Option<Rc<RefCell<Vec<usize>>>>,
    /// Optional per-instruction callback, fired BEFORE each instruction with
    /// the current pc (diagnostics: dump frames/globals at a specific insn).
    pub step_hook: Option<Box<dyn FnMut(&mut Emu<'a>, usize)>>,
}

impl<'a> Emu<'a> {
    /// Build an interpreter over decoded instructions. The data space is
    /// assembled as `data + lit + bss` (zero-filled) and the program stack
    /// starts at `dataMask + 1`, matching `VM_Create`.
    pub fn new(insns: &'a [Insn], qvm: &Qvm) -> Self {
        let data_mask = qvm.data_mask();
        let total = data_mask as usize + 1;
        let mut data = vec![0u8; total];
        data[..qvm.data.len()].copy_from_slice(&qvm.data);
        data[qvm.data.len()..qvm.data.len() + qvm.lit.len()].copy_from_slice(&qvm.lit);

        let mut op = [0i32; OPSTACK_RING];
        op[0] = 0xDEADBEEFu32 as i32;

        Emu {
            insns,
            mem: Memory { data, data_mask },
            op,
            op_ofs: 0,
            program_stack: data_mask as i32 + 1,
            syscall: None,
            max_steps: DEFAULT_MAX_STEPS,
            stats: Stats::default(),
            trace: false,
            watch_store: None,
            watch_label: None,
            trap_insns: Vec::new(),
            step_pcs: None,
            step_hook: None,
        }
    }

    /// The decoded instruction at index `pc` (panics if out of range).
    pub fn insn(&self, pc: usize) -> &Insn {
        &self.insns[pc]
    }

    pub fn with_syscall(mut self, handler: SyscallHandler) -> Self {
        self.syscall = Some(handler);
        self
    }

    /// Set a side label used in WATCH diagnostics (orig/rebuilt etc).
    pub fn with_watch_label(mut self, label: &'static str) -> Self {
        self.watch_label = Some(label);
        self
    }

    /// Install a per-instruction hook (fires with the current pc before the
    /// instruction executes). Used by diagnostics to dump frame/memory state.
    pub fn with_step_hook(mut self, hook: Box<dyn FnMut(&mut Emu<'a>, usize)>) -> Self {
        self.step_hook = Some(hook);
        self
    }

    /// Current program stack pointer (frame base) — for step-hook diagnostics.
    pub fn program_stack(&self) -> i32 {
        self.program_stack
    }

    pub fn set_max_steps(&mut self, n: usize) {
        self.max_steps = n;
    }

    /// Direct access to the VM data space (for tests/verification).
    pub fn mem(&self) -> &Memory {
        &self.mem
    }

    pub fn mem_mut(&mut self) -> &mut Memory {
        &mut self.mem
    }

    #[inline]
    fn r0(&self) -> i32 {
        self.op[self.op_ofs as usize]
    }

    #[inline]
    fn r1(&self) -> i32 {
        self.op[self.op_ofs.wrapping_sub(1) as usize]
    }

    /// Call the function at instruction index `entry` with `args`.
    ///
    /// Sets up the initial frame exactly like `VM_CallInterpreted` (args at
    /// `sp+8+4k`, return stack 0, return address -1) and runs until the
    /// terminal `LEAVE`. Returns the value left on top of the op stack.
    pub fn call(&mut self, entry: usize, args: &[i32]) -> Result<i32, EmuError> {
        let data_mask = self.mem.data_mask;
        self.program_stack = data_mask as i32 + 1;
        self.program_stack -= (8 + 4 * MAX_VMMAIN_ARGS) as i32;

        for (k, a) in args.iter().copied().take(MAX_VMMAIN_ARGS).enumerate() {
            self.mem
                .write_i32_raw(self.program_stack + 8 + 4 * k as i32, a)
                .ok_or(EmuError::BadStackAddr {
                    addr: self.program_stack + 8 + 4 * k as i32,
                    len: self.mem.len(),
                })?;
        }
        self.mem
            .write_i32_raw(self.program_stack + 4, 0)
            .ok_or(EmuError::BadStackAddr { addr: self.program_stack + 4, len: self.mem.len() })?;
        self.mem
            .write_i32_raw(self.program_stack, -1)
            .ok_or(EmuError::BadStackAddr { addr: self.program_stack, len: self.mem.len() })?;

        self.op_ofs = 0;
        self.trap_insns.clear();
        let mut pc = entry;

        loop {
            self.stats.steps += 1;
            if self.stats.steps > self.max_steps {
                return Err(EmuError::StepLimit(self.max_steps));
            }
            let insn = self
                .insns
                .get(pc)
                .ok_or(EmuError::PcOverflow { pc, len: self.insns.len() })?;
            if self.trace {
                println!("{:>6}: {insn}", self.op_ofs);
            }
            if let Some(pcs) = self.step_pcs.as_ref() {
                pcs.borrow_mut().push(pc);
            }
            if self.step_hook.is_some() {
                let mut hook = self.step_hook.take().unwrap();
                hook(self, pc);
                self.step_hook = Some(hook);
            }
            let opcode = insn.op;
            // default next instruction; control-flow ops override this.
            let mut npc = pc + 1;

            match opcode {
                Opcode::Undef | Opcode::Ignore => return Err(EmuError::Unsupported(opcode)),
                Opcode::Break => {}

                Opcode::Const => {
                    self.op_ofs = self.op_ofs.wrapping_add(1);
                    self.op[self.op_ofs as usize] = insn.operand.unwrap_or(0);
                }

                Opcode::Local => {
                    self.op_ofs = self.op_ofs.wrapping_add(1);
                    self.op[self.op_ofs as usize] = insn.operand.unwrap_or(0) + self.program_stack;
                }

                Opcode::Load1 => {
                    let a = self.r0();
                    self.op[self.op_ofs as usize] = self.mem.load1(a);
                }
                Opcode::Load2 => {
                    let a = self.r0();
                    self.op[self.op_ofs as usize] = self.mem.load2(a);
                }
                Opcode::Load4 => {
                    let a = self.r0();
                    self.op[self.op_ofs as usize] = self.mem.load4(a);
                }

                Opcode::Store1 => {
                    let (addr, val) = (self.r1(), self.r0());
                    if self.watch_store == Some(addr & self.mem.data_mask as i32) {
                        println!("WATCH[{}] STORE1 addr=0x{:x} val={val} insn={pc}", self.watch_label.unwrap_or("?"), addr as u32);
                    }
                    self.mem.store1(addr, val);
                    self.op_ofs = self.op_ofs.wrapping_sub(2);
                }
                Opcode::Store2 => {
                    let (addr, val) = (self.r1(), self.r0());
                    if self.watch_store == Some(addr & self.mem.data_mask as i32) {
                        println!("WATCH[{}] STORE2 addr=0x{:x} val={val} insn={pc}", self.watch_label.unwrap_or("?"), addr as u32);
                    }
                    self.mem.store2(addr, val);
                    self.op_ofs = self.op_ofs.wrapping_sub(2);
                }
                Opcode::Store4 => {
                    let (addr, val) = (self.r1(), self.r0());
                    let msk = addr as u32 & self.mem.data_mask;
                    if self.watch_store == Some(msk as i32) {
                        println!("WATCH[{}] STORE4 raw=0x{:x} masked=0x{:x} val={val} ({val:#010x}) insn={pc}", self.watch_label.unwrap_or("?"), addr as u32, msk);
                    }
                    self.mem.store4(addr, val);
                    self.op_ofs = self.op_ofs.wrapping_sub(2);
                }

                Opcode::Arg => {
                    let off = insn.operand.unwrap_or(0);
                    let addr = (off + self.program_stack) & self.mem.data_mask as i32;
                    self.mem.store4(addr, self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                }

                Opcode::BlockCopy => {
                    let (dest, src) = (self.r1() as u32, self.r0() as u32);
                    let n = insn.operand.unwrap_or(0);
                    let mask = self.mem.data_mask;
                    if let Some(w) = self.watch_store {
                        let wd = w as u32;
                        let d = dest & mask;
                        if d <= wd && wd < d + n as u32 {
                            println!("WATCH BLOCK_COPY dest=0x{d:x} src=0x{src:x} n={n} covers watch 0x{w:x} insn={pc}");
                        }
                    }
                    if dest & mask != dest || src & mask != src
                        || (dest.wrapping_add(n as u32)) & mask != dest.wrapping_add(n as u32)
                        || (src.wrapping_add(n as u32)) & mask != src.wrapping_add(n as u32)
                    {
                        return Err(EmuError::BlockCopyRange { dest, src, n, mask });
                    }
                    let n = n as usize;
                    let s = src as usize;
                    let d = dest as usize;
                    self.mem.data.copy_within(s..s + n, d);
                    self.op_ofs = self.op_ofs.wrapping_sub(2);
                }

                Opcode::Call => {
                    // save return address in the current frame
                    self.mem
                        .write_i32_raw(self.program_stack, pc as i32 + 1)
                        .ok_or(EmuError::BadStackAddr { addr: self.program_stack, len: self.mem.len() })?;
                    let target = self.r0();
                    self.op_ofs = self.op_ofs.wrapping_sub(1);

                    if target < 0 {
                        // system call
                        let num = -1 - target;
                        self.trap_insns.push(pc);
                        self.mem
                            .write_i32_raw(self.program_stack + 4, num)
                            .ok_or(EmuError::BadStackAddr { addr: self.program_stack + 4, len: self.mem.len() })?;
                        self.stats.syscalls += 1;
                        *self.stats.syscall_counts.entry(num).or_insert(0) += 1;

                        let mut args = [0i32; MAX_VMSYSCALL_ARGS];
                        for i in 0..MAX_VMSYSCALL_ARGS {
                            let a = self.program_stack + 4 + 4 * i as i32;
                            args[i] = self.mem.read_i32_raw(a).ok_or(EmuError::BadStackAddr {
                                addr: a,
                                len: self.mem.len(),
                            })?;
                        }
                        let r = match self.syscall.as_mut() {
                            Some(h) => h(&mut self.mem, num, &mut args),
                            None => 0,
                        };
                        self.op_ofs = self.op_ofs.wrapping_add(1);
                        self.op[self.op_ofs as usize] = r;
                        npc = self
                            .mem
                            .read_i32_raw(self.program_stack)
                            .ok_or(EmuError::BadStackAddr { addr: self.program_stack, len: self.mem.len() })?
                            as usize;
                    } else {
                        if self.trace {
                            println!("      CALL -> #{target}");
                        }
                        if target as usize >= self.insns.len() {
                            return Err(EmuError::BadTarget { kind: "CALL", idx: target });
                        }
                        npc = target as usize;
                    }
                }

                Opcode::Push => self.op_ofs = self.op_ofs.wrapping_add(1),
                Opcode::Pop => self.op_ofs = self.op_ofs.wrapping_sub(1),

                Opcode::Enter => {
                    let v = insn.operand.unwrap_or(0);
                    self.program_stack -= v;
                    if self.trace {
                        // args were written by the caller at ps0+8+4k where
                        // ps0 = program_stack before ENTER subtracted v.
                        let f = self.program_stack + v + 8;
                        let arg = |k: i32| -> String {
                            self.mem.read_i32_raw(f + 4 * k)
                                .map(|x| format!("{x}"))
                                .unwrap_or_else(|| "?".into())
                        };
                        println!("      ENTER v={v} args=[{}, {}, {}]", arg(0), arg(1), arg(2));
                    }
                    *self.stats.entries.entry(pc).or_insert(0) += 1;
                }

                Opcode::Leave => {
                    let v = insn.operand.unwrap_or(0);
                    self.program_stack += v;
                    let ret = self
                        .mem
                        .read_i32_raw(self.program_stack)
                        .ok_or(EmuError::BadStackAddr { addr: self.program_stack, len: self.mem.len() })?;
                    if ret == -1 {
                        // leave the VM: result = op stack top
                        return Ok(self.r0());
                    }
                    if ret as usize >= self.insns.len() {
                        return Err(EmuError::BadTarget { kind: "LEAVE", idx: ret });
                    }
                    npc = ret as usize;
                }

                Opcode::Jump => {
                    let target = self.r0();
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    if target < 0 || target as usize >= self.insns.len() {
                        return Err(EmuError::BadTarget { kind: "JUMP", idx: target });
                    }
                    npc = target as usize;
                }

                // comparisons: pop 2; r1 is the deeper operand, r0 the top
                Opcode::Eq | Opcode::Ne | Opcode::Lti | Opcode::Lei | Opcode::Gti | Opcode::Gei
                | Opcode::Ltu | Opcode::Leu | Opcode::Gtu | Opcode::Geu
                | Opcode::Eqf | Opcode::Nef | Opcode::Ltf | Opcode::Lef | Opcode::Gtf | Opcode::Gef => {
                    let (r1, r0) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(2);
                    let taken = match opcode {
                        Opcode::Eq => r1 == r0,
                        Opcode::Ne => r1 != r0,
                        Opcode::Lti => r1 < r0,
                        Opcode::Lei => r1 <= r0,
                        Opcode::Gti => r1 > r0,
                        Opcode::Gei => r1 >= r0,
                        Opcode::Ltu => (r1 as u32) < (r0 as u32),
                        Opcode::Leu => (r1 as u32) <= (r0 as u32),
                        Opcode::Gtu => (r1 as u32) > (r0 as u32),
                        Opcode::Geu => (r1 as u32) >= (r0 as u32),
                        Opcode::Eqf => f32::from_bits(r1 as u32) == f32::from_bits(r0 as u32),
                        Opcode::Nef => f32::from_bits(r1 as u32) != f32::from_bits(r0 as u32),
                        Opcode::Ltf => f32::from_bits(r1 as u32) < f32::from_bits(r0 as u32),
                        Opcode::Lef => f32::from_bits(r1 as u32) <= f32::from_bits(r0 as u32),
                        Opcode::Gtf => f32::from_bits(r1 as u32) > f32::from_bits(r0 as u32),
                        Opcode::Gef => f32::from_bits(r1 as u32) >= f32::from_bits(r0 as u32),
                        _ => unreachable!(),
                    };
                    if taken {
                        npc = insn.operand.unwrap_or(0) as usize;
                    }
                }

                // unary / binary arithmetic
                Opcode::Negi => self.op[self.op_ofs as usize] = self.r0().wrapping_neg(),
                Opcode::Add => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = a.wrapping_add(b);
                }
                Opcode::Sub => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = a.wrapping_sub(b);
                }
                Opcode::Divi => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    if b == 0 {
                        return Err(EmuError::DivByZero);
                    }
                    let r = if a == i32::MIN && b == -1 { a } else { a / b };
                    self.op[self.op_ofs as usize] = r;
                }
                Opcode::Divu => {
                    let (a, b) = (self.r1() as u32, self.r0() as u32);
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    if b == 0 {
                        return Err(EmuError::DivByZero);
                    }
                    self.op[self.op_ofs as usize] = (a / b) as i32;
                }
                Opcode::Modi => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    if b == 0 {
                        return Err(EmuError::DivByZero);
                    }
                    let r = if a == i32::MIN && b == -1 { 0 } else { a % b };
                    self.op[self.op_ofs as usize] = r;
                }
                Opcode::Modu => {
                    let (a, b) = (self.r1() as u32, self.r0() as u32);
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    if b == 0 {
                        return Err(EmuError::DivByZero);
                    }
                    self.op[self.op_ofs as usize] = (a % b) as i32;
                }
                Opcode::Muli => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = a.wrapping_mul(b);
                }
                Opcode::Mulu => {
                    let (a, b) = (self.r1() as u32, self.r0() as u32);
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = (a.wrapping_mul(b)) as i32;
                }
                Opcode::Band => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = (a as u32 & b as u32) as i32;
                }
                Opcode::Bor => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = (a as u32 | b as u32) as i32;
                }
                Opcode::Bxor => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = (a as u32 ^ b as u32) as i32;
                }
                Opcode::Bcom => self.op[self.op_ofs as usize] = !(self.r0() as u32) as i32,
                Opcode::Lsh => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = a.wrapping_shl((b as u32 & 31) as u32);
                }
                Opcode::Rshi => {
                    let (a, b) = (self.r1(), self.r0());
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = a.wrapping_shr((b as u32 & 31) as u32);
                }
                Opcode::Rshu => {
                    let (a, b) = (self.r1() as u32, self.r0() as u32);
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    self.op[self.op_ofs as usize] = (a.wrapping_shr(b & 31)) as i32;
                }

                Opcode::Negf => {
                    let f = f32::from_bits(self.r0() as u32);
                    self.op[self.op_ofs as usize] = (-f).to_bits() as i32;
                }
                Opcode::AddF | Opcode::SubF | Opcode::DivF | Opcode::MulF => {
                    let a = f32::from_bits(self.r1() as u32);
                    let b = f32::from_bits(self.r0() as u32);
                    self.op_ofs = self.op_ofs.wrapping_sub(1);
                    let r = match opcode {
                        Opcode::AddF => a + b,
                        Opcode::SubF => a - b,
                        Opcode::DivF => a / b,
                        Opcode::MulF => a * b,
                        _ => unreachable!(),
                    };
                    self.op[self.op_ofs as usize] = r.to_bits() as i32;
                }
                Opcode::Cvif => {
                    let v = self.r0();
                    self.op[self.op_ofs as usize] = (v as f32).to_bits() as i32;
                }
                Opcode::Cvfi => {
                    let f = f32::from_bits(self.r0() as u32);
                    self.op[self.op_ofs as usize] = f as i32;
                }
                Opcode::Sex8 => self.op[self.op_ofs as usize] = self.r0() as i8 as i32,
                Opcode::Sex16 => self.op[self.op_ofs as usize] = self.r0() as i16 as i32,
            }

            pc = npc;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::parse;

    fn qvm_from_parts(code: &[u8], instr_count: i32, bss: i32) -> Qvm {
        let mut f = Vec::new();
        for v in [0x12721444u32, instr_count as u32, 32u32, code.len() as u32,
                  32 + code.len() as u32, 0u32, 0u32, bss as u32] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(code);
        parse(&f).unwrap()
    }

    fn emu_for(code: &[u8], instr_count: i32) -> Emu<'static> {
        emu_for_bss(code, instr_count, 64)
    }

    fn emu_for_bss(code: &[u8], instr_count: i32, bss: i32) -> Emu<'static> {
        // decoded Insns are owned by the returned Disassembly; emulate with a
        // leak so the borrow-checker is satisfied (test-only).
        let q = qvm_from_parts(code, instr_count, bss);
        let d = crate::disasm::disassemble(&q).unwrap();
        let insns: &'static [Insn] = Box::leak(d.insns.into_boxed_slice());
        Emu::new(insns, &q)
    }

    /// `int f(int x) { return x + 3; }` (lcc layout)
    const ADD3: &[u8] = &[
        0x03, 0, 0, 0, 0,     // ENTER 0
        0x09, 8, 0, 0, 0,     // LOCAL 8
        0x1d,                 // LOAD4
        0x08, 3, 0, 0, 0,     // CONST 3
        0x26,                 // ADD
        0x04, 0, 0, 0, 0,     // LEAVE 0
    ];

    #[test]
    fn returns_arg_plus_const() {
        let mut e = emu_for(ADD3, 6);
        assert_eq!(e.call(0, &[7]).unwrap(), 10);
        assert_eq!(e.call(0, &[-3]).unwrap(), 0);
    }

    #[test]
    fn store_and_load4() {
        // *(int*)0 = 0x12345678; return *(int*)0;
        let code: &[u8] = &[
            0x03, 0, 0, 0, 0,   // ENTER 0
            0x08, 0, 0, 0, 0,   // CONST 0            (address)
            0x08, 0x78, 0x56, 0x34, 0x12, // CONST 0x12345678
            0x20,               // STORE4
            0x08, 0, 0, 0, 0,   // CONST 0
            0x1d,               // LOAD4
            0x04, 0, 0, 0, 0,   // LEAVE 0
        ];
        let mut e = emu_for(code, 7);
        assert_eq!(e.call(0, &[]).unwrap() as u32, 0x12345678);
    }

    #[test]
    fn conditional_branch() {
        // int f(int x){ if (x < 5) return 1; return 2; }
        // lcc: LTI jumps to the `then` block when x<5 holds.
        let code: &[u8] = &[
            0x03, 0, 0, 0, 0,   // ENTER 0
            0x09, 8, 0, 0, 0,   // LOCAL 8
            0x1d,               // LOAD4
            0x08, 5, 0, 0, 0,   // CONST 5
            0x0d, 7, 0, 0, 0,   // LTI #7          (x<5 -> return 1)
            0x08, 2, 0, 0, 0,   // CONST 2         (else: return 2)
            0x04, 0, 0, 0, 0,   // LEAVE 0
            0x08, 1, 0, 0, 0,   // CONST 1
            0x04, 0, 0, 0, 0,   // LEAVE 0
        ];
        let mut e = emu_for(code, 9);
        assert_eq!(e.call(0, &[3]).unwrap(), 1);
        assert_eq!(e.call(0, &[5]).unwrap(), 2);
        assert_eq!(e.call(0, &[100]).unwrap(), 2);
    }

    #[test]
    fn arg_writes_frame_slot() {
        // ENTER 4; CONST 77; ARG 8; LOCAL 8; LOAD4; LEAVE 4  => 77
        let code: &[u8] = &[
            0x03, 4, 0, 0, 0,   // ENTER 4
            0x08, 77, 0, 0, 0,  // CONST 77
            0x21, 8,            // ARG 8
            0x09, 8, 0, 0, 0,   // LOCAL 8
            0x1d,               // LOAD4
            0x04, 4, 0, 0, 0,   // LEAVE 4
        ];
        let mut e = emu_for(code, 6);
        assert_eq!(e.call(0, &[]).unwrap(), 77);
    }

    #[test]
    fn syscall_returns_value() {
        use std::cell::Cell;
        use std::rc::Rc;
        // ENTER 80; CONST -3; CALL (syscall 2); LEAVE 80
        // (ENTER 80 places the frame deep enough that reading 16 syscall
        //  argument words stays within the data space)
        let code: &[u8] = &[
            0x03, 80, 0, 0, 0,  // ENTER 80
            0x08, 0xFD, 0xFF, 0xFF, 0xFF, // CONST -3  (syscall 2)
            0x05,               // CALL
            0x04, 80, 0, 0, 0,  // LEAVE 80
        ];
        let mut e = emu_for_bss(code, 4, 512);
        let seen = Rc::new(Cell::new(None));
        let seen2 = seen.clone();
        e.syscall = Some(Box::new(move |_mem, num, _args| {
            seen2.set(Some(num));
            100
        }));
        let r = e.call(0, &[]).unwrap();
        assert_eq!(r, 100);
        assert_eq!(seen.get(), Some(2));
        assert_eq!(e.stats.syscalls, 1);
        assert_eq!(e.stats.syscall_counts.get(&2), Some(&1));
    }

    #[test]
    fn float_ops() {
        // return 1.5f + 2.25f  (as bits)
        let code: &[u8] = &[
            0x03, 0, 0, 0, 0,   // ENTER 0
            0x08, 0, 0, 0xC0, 0x3F, // CONST bits(1.5f)
            0x08, 0, 0, 0x10, 0x40, // CONST bits(2.25f)
            0x36,               // ADDF
            0x04, 0, 0, 0, 0,   // LEAVE 0
        ];
        let mut e = emu_for(code, 5);
        let r = e.call(0, &[]).unwrap() as u32;
        assert_eq!(f32::from_bits(r), 3.75);
    }

    #[test]
    fn step_limit_triggered() {
        // CONST 0; JUMP -> #0  (infinite loop)
        let code: &[u8] = &[
            0x08, 0, 0, 0, 0,   // CONST 0
            0x0a,               // JUMP
        ];
        let mut e = emu_for(code, 2);
        e.set_max_steps(1000);
        assert!(matches!(e.call(0, &[]), Err(EmuError::StepLimit(1000))));
    }

    #[test]
    fn block_copy() {
        // mem at data[8] = copy of data[4]; return *(int*)8
        let code: &[u8] = &[
            0x03, 0, 0, 0, 0,   // ENTER 0
            0x08, 8, 0, 0, 0,   // CONST 8        (dest)
            0x08, 4, 0, 0, 0,   // CONST 4        (src)
            0x22, 4, 0, 0, 0,   // BLOCK_COPY 4
            0x08, 8, 0, 0, 0,   // CONST 8
            0x1d,               // LOAD4
            0x04, 0, 0, 0, 0,   // LEAVE 0
        ];
        let mut e = emu_for_bss(code, 7, 512);
        // seed data words 0..3
        e.mem.store4(0, 0x11111111);
        e.mem.store4(4, 0x22222222);
        e.mem.store4(8, 0x00000000);
        let r = e.call(0, &[]).unwrap();
        assert_eq!(r, 0x22222222); // data[8] <- data[4]
        assert_eq!(e.mem.load4(0), 0x11111111);
        assert_eq!(e.mem.load4(8), 0x22222222);
    }
}
