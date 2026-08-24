# Toolchain

Kit-relative paths. Start with [AGENT.md](../AGENT.md). Put input QVMs in `work/`.

## Needs

- Rust (`cargo`)
- `tools/win32-qvm/` (`q3lcc`, `q3cpp`, `q3rcc`, `q3asm`) — Windows binaries in this kit
- Python 3 (`tools/dump.py`)
- one or more stale `.qvm` files from the mod

Put `tools/win32-qvm` on `PATH`, or call the exes by full path. PowerShell aliases `cpp` to `Copy-ItemProperty`; always run q3lcc via `cmd.exe` (see `scripts/build_qvm.ps1`).

## 0. Build a mod QVM from C source (optional)

When you have the mod's C sources instead of a stale `.qvm` (e.g. baseq3a),
mirror the mod's own build script and only swap in the kit tools. Vanilla
game module, flags as in its `compile.bat`:

```bat
rem per .c file (cwd = the source dir):
q3lcc.exe -DQ3_VM -DQAGAME -S -Wf-g g_main.c
rem then assemble:
q3asm.exe -vq3 -m -v -o qagame -f qagame.q3asm
```

Kit-toolchain gotchas, verified against the shipped binaries:

- The shipped `q3lcc`/`q3cpp` pair does **not** honor `-I`, and quoted
  `#include`s are not searched relative to the includer either — they resolve
  against the process CWD only. Compile with CWD inside the source dir, then
  move the produced `.asm` files to your output dir.
- Kit `q3asm` has no `-r` (a fork-only flag); use `-vq3 -m`.
- Kit `q3asm -f` wants the full listfile name (`game.q3asm`; no auto-suffix).
- Keep the `.q3asm` listfile flat (bare basenames) next to the `.asm`
  outputs; copy any out-of-tree `.asm` (e.g. `g_syscalls.asm`) beside them.

## 1. Build probes

Catalog and flags: [TOOLS.md](TOOLS.md).

```powershell
cd toolchain\qvm
cargo build --release --bin probe_emit --bin probe_dump_all --bin probe_sigs `
  --bin probe_align --bin probe_names --bin probe_disasm --bin probe_findfn `
  --bin probe_findconst --bin probe_strat --bin probe_check --bin probe_seqdiff `
  --bin probe_uidiff --bin probe_cgamediff
```

Output: `toolchain/qvm/target/release/`.

## 2. Identity emit (untyped by default)

```powershell
.\scripts\emit_qvm.ps1 -Qvm work\qagame.qvm -OutDir work\qagame
```

That runs `probe_sigs` (if needed), `probe_emit --no-typed`, then `probe_dump_all`.

Manual:

```powershell
cd toolchain\qvm
.\target\release\probe_emit.exe `
  ..\..\work\qagame.qvm `
  ..\..\work\qagame\qagame.c `
  ..\..\work\qagame\syscalls.asm `
  --no-typed --sigs ..\..\work\qagame\qagame.sigs --names ..\..\work\qagame.names
```

Typed emit uses `src/types.rs` — a per-mod data-space overlay shipped as an **empty template**. Fill it from your own recovery (guideline in the file header) before passing `--typed`.

Put lasting C fixes in `probe_emit`, not in generated `.c`. Sample-specific rewrites: [COMPAT.md](COMPAT.md) — do not assume they apply.

## 3. C → QVM (round-trip)

```powershell
.\scripts\build_qvm.ps1 -SrcDir work\qagame -Stem qagame
```

Linux: `./scripts/build_qvm.sh work/qagame qagame` — needs lcc-based `q3lcc` / `q3asm` on `PATH`.

Manual:

```powershell
$tmp = Join-Path $env:USERPROFILE 'AppData\Local\Temp'
$tools = Resolve-Path tools\win32-qvm
cmd.exe /c "set TMP=$tmp& set TEMP=$tmp& set PATH=$tools;%PATH%& cd /d work\qagame& q3lcc.exe -DQ3_VM -S qagame.c & q3asm.exe -vq3 -m -o qagame syscalls.asm qagame.asm"
```

Bar: `probe_check` on the rebuilt QVM; `probe_seqdiff orig.qvm rebuilt.qvm` (qagame). UI/cgame have `probe_uidiff` / `probe_cgamediff`.

## Notes

- This tree ships a hex-aware `q3asm` (large blobs / `0x…` literals).
- Quake3e may peephole bytecode on load: live PC ≠ `probe_disasm` index. Data offsets stay put.
- Cursor/agent shells often point `TMP`/`TEMP` at a tiny dir — `build_qvm.ps1` resets them.
