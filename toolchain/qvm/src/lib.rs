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

pub use cfg::{CFG, Block, build_all, build_cfg, build_functions};
pub use decompile::{Expr, Function, Stmt, Terminator, decompile_function, fmt_function, reachable_blocks};
pub use structure::{CaseKind, Elem, Structure, fmt_readable, fmt_structured};
pub use disasm::{DisasmError, Disassembly, Insn, disassemble};
pub use emu::{Emu, EmuError, Memory, Stats, SyscallHandler};
pub use loader::{Qvm, QvmError, load};
pub use names::{index, load_map, parse_map};
pub use opcodes::{Opcode, instr_length};
pub use traps::trap_name;
