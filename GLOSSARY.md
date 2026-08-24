# Glossary

This kit is the **recompiler** only: any Quake 3 `.qvm` → C → q3lcc → playable `.qvm` (`seqdiff` 0). Do not compile identity `.c` as game code. Do not “fix” the emitter while reading a dump.

---

## The three VMs

A Quake 3 **mod** is three bytecode modules, not one program.

| module | runs on | typical file |
|--------|---------|--------------|
| **qagame** | dedicated / listen **server** | `vm/qagame.qvm` |
| **cgame** | **client** (HUD, prediction, events) | `vm/cgame.qvm` |
| **ui** | **menus** (browser, start server, setup) | `vm/ui.qvm` |

**pk3** — zip archive the engine loads as a game directory.

**baseq3a** — a stock-ish Quake 3 source tree. Alignment (`probe_align`) against id Tech3 / baseq3 `game.qvm` + `game.map` is a naming hint, not a port.

---

## QVM file and VM memory

**QVM** — Quake Virtual Machine bytecode (`.qvm`). Header plus **code**, then **data+lit**. BSS is *not* stored in the file.

**insn** — instruction index (the VM’s program counter unit). Identity C labels them `L107760:`. Not a byte offset into the file.

**CONST** — opcode that pushes a 32-bit immediate. That number may be an int, a function entry, or a **VM data address** (string, table, BSS cell). Identity comments like `qvm_mem + 45487` are this address minus 4 (see **−4**).

**data** (`dataLength`) — initialized globals: pointer tables, cvar default blocks, jump tables. Present in the `.qvm`.

**lit** (`litLength`) — read-only C strings, immediately after data in the file. `dump.py str` / `find` see **data+lit only**.

**BSS** — **Block Started by Symbol**. Classic linker name for *uninitialized* globals (Unix `.bss`). The QVM header has `bssLength`; those bytes are **zeros at runtime and absent from the file**. The engine allocates `data+lit+bss` (rounded up to a power of two) and zero-fills the tail.

  What lives there: `g_entities[]`, `g_clients[]`, `level`, cgame `cg` / `cg_entities[]`, particles, and other large arrays. In identity C a BSS cell is `*(int*)(1767984)` or `qvm_mem + N` with **no** string next to it.

**dataMask** — VM data segment size minus one: next power of two of `(data+lit+bss)`, minus 1. Accesses wrap with this mask.

**blob / `qvm_mem_words` / `qvm_mem`** — the recompiler’s identity map of data+lit+bss plus a 4-byte NULL sentinel at VM address 0. Size is that span, **not** `dataMask+1` (the pow2 pad overflows q3asm `MAX_IMAGE`). Emitted as `void *qvm_mem_words[N] = { (void*)0x…, … }`. Huge `.c` files are the blob, not the function text. Real C globals would **shift BSS** and break trap pointers.

**−4 / image offset** — `qvm_mem_words[0]` is VM address **4** (a NULL sentinel occupies 0..3). Emit therefore writes `qvm_mem + (CONST − 4)`. `dump.py str` prints walk-back / at / **+4** because comments are often 4 bytes into a string or 4 bytes before it.

**vec4 / color pointer** — `trap_R_SetColor` and `menutext.color` take a pointer to four floats. lcc does **not** 16-align them. Identity `qvm_mem + N` is **CONST−4**: the bytecode immediate is usually **N+4** (so `qvm_mem + 10904` is yellow at 10908, not white.a at 10904). `dump.py color N` prints RGBA at N−4 / N / N+4; on a tie it prefers **+4**. `probe_findconst` walks **instruction index** (not `insn.size` bytes). `probe_data` prints `f=` and a `vec4(...)` tag. Do not snap N to a 16-byte boundary.

**cvar table / `dump.py cvar`** — gameplay CONSTs `vmCvar+8` (float `.value`, often tested as `int != 0`) or `+12` (`.integer`), plus identity hits anywhere in `[vm, vm+271]`, plus opcode taint / table-pointer chase when identity has no `qvm_mem+N`. Skip Register/Update by **insn range** (table walk + trap), not overlay `Register*` names. Some mods store table name dwords at `find_off+0x100`; `ptrs` searches that too. `xref NAME` follows the C string only. See [docs/CVAR_XREF.md](docs/CVAR_XREF.md).

**stride** — byte size of one array element, recovered from pointer math. **base** — CONST address of an array (`g_entities` / `g_clients` / `level`). Together they are a **data-space key**. `toolchain/qvm/src/types.rs` ships as an empty template; fill it only with base+stride pairs you proved for your module.

---

## Emitted C (the “monomodule”)

**identity emit / identity dump** — `probe_emit` output: one `.c` per VM, gotos, `loc_0`, blob. Built to round-trip through q3lcc. **Oracle for “what did the bytecode do.”** Overlay *titles* on these functions often lie.

**structured dump / `*.struct.c`** — same bytecode, `if`/`while` + overlay field names. **Do not compile it.**

**`--no-typed` (default)** — generic emit: no overlay structs, raw `*(int*)`. **`--typed`** turns on `types.rs` (a per-mod key recovered into that template). Do not pass `--typed` while the template is unfilled.

**typed emit** — identity C plus `types.rs` macros (`level.time`, `e->inuse`). Still a blob. Only as good as the key you filled in.

**`loc_0` / `loc_N`** — words on the VM **program stack** (function frame), not BSS. `loc_0` is the frame blob. Do not paste `loc_*` into a game source tree.

**`va(p0…p59)`** — identity still uses the VM’s wide varargs (`G_Printf` with dozens of `int` args). Real game source uses C `va()`.

**overlay name / `fn[N]`** — human title from `.names` / `struct.c` (`fn[3] G_FindTeams`). **Overlay names lie:** the title can be a collided stock name while the body is a different function. **Identity `int Name(` + first `L<insn>` wins.**

**`.names` / `.sigs`** — function names vs frames/arity from bytecode (`names/`). Not the data overlay.

**key / overlay (data)** — named BSS/data layout (`types.rs`). Different from `.names`. Do not invent field names from hex.

---

## Toolchain and checks

**q3lcc / q3rcc / q3cpp** — lcc retargeted to QVM (C89). No `int x;` after statements; no `for (int i`. Nested `{ int x; }` is fine.

**q3asm** — assembles `.asm` + `syscalls.asm` → `.qvm`.

**trap / syscall** — call from QVM into the **engine** (`trap_SendServerCommand`, `trap_Cvar_Set`, …). Negative CONST in bytecode. Seqdiff compares the **stream** of these, not the `.qvm` bytes.

**seqdiff** — ordered trap-log compare orig vs rebuilt (`probe_seqdiff` / cgame/ui variants). Recompiler bar. **fc** — Windows byte compare of files.

**probe_emit** — decompile → buildable C + syscalls. Live crate: `toolchain/qvm/`.

**dump.py** — oracle for strings, xrefs, insns, slots, pointer tables: `python tools/dump.py --qvm …`. Do not grep 80k-line dumps first. **xref** = string → `qvm_mem + N` in identity. **cvar** / **cvars** = cvar table row → `vmCvar+8` / `+12` loads (empty **xref** of the name ≠ unused). **ptrs** = data dwords pointing at a CONST (also `+256`; when xref is empty). **slot** = `+OFF` field accesses. **hdr** = data/lit/bss sizes.

---

## Not this kit

A **port** rewrites behavior into a source tree (e.g. baseq3a). This zip does not include that tree. Do not invent `pers.*` / pad names from hex. Name a field only when bytecode + strings prove it.

**C89** — language the QVM compiler accepts. PowerShell also aliases `cpp` → `Copy-ItemProperty`; compile q3lcc via `cmd.exe`.
