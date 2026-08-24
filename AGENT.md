# AGENT — dive into any Quake 3 QVM. Analyze, decompile, rebuild.

You are using **RESQ**: Restore Everything from Stale QVM.

This kit is a **generic Q3 VM recompiler and oracle**. It is not a port onto a skeleton.

| job | bar | this kit |
|-----|-----|----------|
| **Recompiler / analysis** | `.qvm` → C89 → q3lcc → playable `.qvm` (`seqdiff` 0 vs the original module) | **yes** |
| **Port onto stock source** | rewrite bodies into another source tree | **no** — do not invent a skeleton or enable an unfilled `types.rs` |

The user gives one or more `.qvm` files. Decompile them, name functions, and explain the bytecode. Do **not** invent struct field names. Do **not** “fix” the emitter while reading a dump.

Docs in this kit are English. If the user writes another language, still keep kit files in English unless they ask otherwise.

---

## Layout

```
resq-kit/
  AGENT.md                 this file
  README.md                human handoff
  GLOSSARY.md              terms (blob, CONST −4, overlay lie, …)
  docs/                    TOOLS / TOOLCHAIN / ARCHITECTURE / COMPAT / WORKFLOW
  toolchain/qvm/           Rust crate (`src/`, Cargo.toml, Cargo.lock only)
  tools/win32-qvm/         q3lcc / q3cpp / q3rcc / q3asm (Windows)
  tools/dump.py            string / hdr / table / ptrs / identity oracle
  scripts/                 emit_qvm.ps1, build_qvm.ps1
  work/                    put input QVMs and emit output here
```

Do not copy `qvm/target`, engines, pk3s, or a specific mod's identity dumps into a new session unless the user attaches them.

---

## Needs

- Rust (`cargo`)
- Python 3
- Windows for the shipped `q3lcc` / `q3asm` (or your own lcc/q3asm)
- The mod’s `vm/qagame.qvm`, `cgame.qvm`, `ui.qvm` (a mod may omit some)

---

## Hard rules

1. **Do not pass `--typed` unless the user asks for typed emit and `src/types.rs` is filled for this module.** Default emit is generic (`loc_0`, blob). The shipped `types.rs` is an empty template; typed C from an unfilled or borrowed key is a lie.
2. **Do not edit `types.rs` to “fit” a module** unless the user explicitly asks for an overlay key backed by evidence. First pass is always generic identity C.
3. **Do not invent `pers.*`, pads, or slot names** from hex offsets. Name a field only when bytecode + strings prove it.
4. **Overlay titles lie.** `fn[N] SomeStockName` in `.names` / structured dump can be a collided name. The identity dump `int RealName(` plus first `L<insn>:` is the bytecode. Identity wins.
5. **CONST comments are often ±4.** A comment `qvm_mem + 45487` may be 4 bytes into a C string or 4 bytes before it. `dump.py str` prints walk-back / at / +4. Prefer the full C string that starts after a NUL. **Color / `vec4` pointers are the same trap:** lcc does not 16-align float4, so `qvm_mem + N` is often the previous vector’s alpha. Use `dump.py color N` (windows at N−4 / N / N+4). Do not snap the address to a 16-byte boundary.
6. **Identity `.c` is not game source.** Do not compile it as `g_main.c`. Do not paste `loc_0`, `qvm_mem`, or `va(p0…p59)` into a port tree.
7. **Lasting emit bugs go in `probe_emit`, not in generated `.c`.** See `docs/COMPAT.md` (Driver Info `Q_strncpyz`, ClientSpawn `FL_NO_BOTS`). Those patches are sample-specific; do not assume they apply to another mod.
8. **q3lcc is C89.** No `int x;` after statements; no `for (int i`. Nested `{ int x; }` is fine.
9. **PowerShell aliases `cpp` → `Copy-ItemProperty`.** Run q3lcc via `cmd.exe`. Set `TMP`/`TEMP` to `%USERPROFILE%\AppData\Local\Temp` (Cursor often points them at a tiny dir).
10. Do not `git commit` or pack a playable pk3 unless the user asks.

---

## Pipeline (one module)

Replace `qagame` with `cgame` / `ui` as needed. Paths below assume you `cd` to `resq-kit/`.

### 0. Build probes (once)

```powershell
cd toolchain\qvm
cargo build --release --bin probe_emit --bin probe_dump_all --bin probe_sigs `
  --bin probe_align --bin probe_names --bin probe_disasm --bin probe_findfn `
  --bin probe_findconst --bin probe_strat --bin probe_findcall --bin probe_findstore `
  --bin probe_check --bin probe_seqdiff --bin probe_uidiff --bin probe_cgamediff `
  --bin probe_callers --bin probe_inventory --bin probe_data --bin probe_table
```

Binaries: `toolchain/qvm/target/release/probe_*.exe`.

### 1. Drop the QVM in `work/`

```
work/qagame.qvm
```

Or pass any path to the scripts.

### 2. Signatures (optional but useful)

```powershell
.\toolchain\qvm\target\release\probe_sigs.exe work\qagame.qvm work\qagame.sigs
```

### 3. Names (optional)

- If you have a matching `.map`: `probe_names.exe work\qagame.qvm qagame.map`
- Else align against **id Tech3 / baseq3** `game.qvm` + `game.map` of the same module class (game/cgame/ui):

```powershell
.\toolchain\qvm\target\release\probe_align.exe `
  path\to\baseq3\game.qvm path\to\baseq3\game.map `
  work\qagame.qvm
```

Writes `qagame.names` in the cwd. Hand names: `fn[N] HumanName` in `overrides.txt`, pass `--overrides`.

**Alignment is a hint.** Many functions will stay `fn_<entry>` or collide with stock names. That is expected.

### 4. Identity emit (buildable C, the oracle)

```powershell
.\scripts\emit_qvm.ps1 -Qvm work\qagame.qvm -OutDir work\qagame
```

Or manual:

```powershell
.\toolchain\qvm\target\release\probe_emit.exe `
  work\qagame.qvm work\qagame\qagame.c work\qagame\syscalls.asm `
  --no-typed --sigs work\qagame.sigs --names work\qagame.names
```

`--no-typed` is the default (the flag is still accepted). `.sigs` / `.names` are optional (suffix-detected if you pass the paths).

### 5. Structured dump (read, do not compile)

```powershell
.\toolchain\qvm\target\release\probe_dump_all.exe `
  work\qagame.qvm work\qagame\qagame.struct.c work\qagame.names
```

Uses a 512 MiB thread stack. Large qagames take minutes. `--raw` keeps `loc_N` spelling.

### 6. Rebuild (only if you need a playable round-trip)

```cmd
cmd.exe /c "set TMP=%USERPROFILE%\AppData\Local\Temp& set TEMP=%USERPROFILE%\AppData\Local\Temp& set PATH=resq-kit\tools\win32-qvm;%PATH%& cd /d resq-kit\work\qagame& q3lcc.exe -DQ3_VM -S qagame.c & q3asm.exe -vq3 -m -o qagame syscalls.asm qagame.asm"
```

Or `.\scripts\build_qvm.ps1 -SrcDir work\qagame -Stem qagame`.

Bar: `probe_check` on the rebuilt QVM; `probe_seqdiff orig.qvm rebuilt.qvm` (qagame), `probe_cgamediff` / `probe_uidiff` for the other modules. Some UI samples keep a known `trap_S_StartLocalSound` Driver Info mismatch — another mod should seqdiff 0 unless you find a similar strcpy overflow.

---

## How to read a dump (oracle)

Prefer `tools/dump.py` over grepping 80k-line `.c` files.

```powershell
python tools\dump.py --qvm work\qagame.qvm hdr
python tools\dump.py --qvm work\qagame.qvm find "Clan Arena"
python tools\dump.py --qvm work\qagame.qvm str 21349
python tools\dump.py --qvm work\qagame.qvm table 19624 -c 8
python tools\dump.py --qvm work\qagame.qvm ptrs 21349
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c --struct work\qagame\qagame.struct.c --names work\qagame.names insn 107760
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c xref SomeString
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar amf_debug
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvars
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c calls G_InitGame
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c slot 668
```

| cmd | needs QVM | needs identity `.c` |
|-----|-----------|---------------------|
| `hdr` `str` `find` `table` `ptrs` | yes | no |
| `insn` `fn` `calls` `slot` `xref` `addcmd` | yes | yes |
| `cvar` `cvars` | yes | identity for `+8`/`obj` grep; opcode taint / table rows from QVM alone |

Bytecode probes (no dump file):

```powershell
.\toolchain\qvm\target\release\probe_disasm.exe work\qagame.qvm 0 100 200
.\toolchain\qvm\target\release\probe_findfn.exe work\qagame.qvm 107760
.\toolchain\qvm\target\release\probe_findconst.exe work\qagame.qvm 45487
.\toolchain\qvm\target\release\probe_strat.exe work\qagame.qvm 45487
```

---

## What the identity C is

- One file per VM. Functions are **gotos** + `L<insn>:` labels. `insn` is the VM program counter, not a file byte offset.
- Locals live in `unsigned char loc_0[frame]`.
- All globals are one **blob** `qvm_mem` / `qvm_mem_words`. Real C globals would **shift BSS** and break trap pointers.
- `qvm_mem + (CONST − 4)` because word 0 is a NULL sentinel; VM address 4 is `qvm_mem[0]`.
- **data** = initialized (in the file). **lit** = C strings (in the file, after data). **BSS** = zeros at runtime, **not** in the `.qvm`. `dump.py` strings only see data+lit.
- Traps are negative CONST (`trap_SendServerCommand`, …).

Structured dump (`*.struct.c`) adds `if`/`while` and overlay names. Still not compile-as-game.

---

## Suggested first report to the user

For each module (`qagame` / `cgame` / `ui` that exists):

1. Header: instruction count, data/lit/bss sizes (`dump.py hdr`).
2. Whether emit + q3lcc succeeded.
3. Function count (`.names` / CFG). How many aligned to stock names vs leftover `fn_*`.
4. Distinctive strings (mod name, extra gametypes, extra commands) from `dump.py find`.
5. Command tables (`addcmd` on cgame; qagame is often a dispatch, not `trap_AddCommand`).
6. Open questions — unnamed BSS, overlay collisions — **listed as leftover, not invented**. Leftover cvars: `cvar` / `cvars` (identity `[vm,vm+271]` + table-pointer taint), not empty `xref NAME`. Zero loads after that still means do not hang behavior on the knob.

Do not start a baseq3a port unless the user asks. This kit is decompile + explain.
