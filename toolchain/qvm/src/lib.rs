//! QVM (Quake 3 VM) toolchain — single source of VM semantics.
//!
//! Modules:
//! - [`loader`]: parse a .qvm file (header, code/data/lit/jtrg segments).
//! - [`opcodes`]: opcode table + instruction lengths.
//! - [`disasm`]: linear disassembly.
//! - [`cfg`]: control-flow graph / functions.
//! - [`decompile`]: stack -> SSA -> C.
//! - [`traps`]: syscall name table for the game VM.
//! - `emu`: interpreter (shares semantics).

pub mod cfg;
pub mod decompile;
pub mod disasm;
pub mod emu;
pub mod loader;
pub mod names;
pub mod opcodes;
pub mod probe_common;
pub mod readable;
pub mod structure;
pub mod traps;
pub mod types;

pub use cfg::{build_all, build_cfg, build_functions, Block, CFG};
pub use decompile::{
    decompile_function, fmt_function, reachable_blocks, Expr, Function, Stmt, Terminator,
};
pub use disasm::{disassemble, DisasmError, Disassembly, Insn};
pub use emu::{Emu, EmuError, Memory, Stats, SyscallHandler};
pub use loader::{load, Qvm, QvmError};
pub use names::{index, load_map, parse_map};
pub use opcodes::{instr_length, Opcode};
pub use structure::{fmt_readable, fmt_structured, CaseKind, Elem, Structure};
pub use traps::trap_name;
