![RESQ kit logo](assets/resq-logo.png)

# RESQ kit — dive into any Quake 3 QVM. Analyze, decompile, rebuild.

![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![rust](https://img.shields.io/badge/made%20with-Rust-dea584?logo=rust)
![python](https://img.shields.io/badge/made%20with-Python%203-3776AB?logo=python&logoColor=white)
![target](https://img.shields.io/badge/target-id%20Tech%203%20QVM-red)



**R**estore **E**verything from **S**tale **Q**VM.

Generic toolchain for id Tech 3 modules: any `qagame` / `cgame` / `ui` `.qvm` → identity C89 → (optional) q3lcc round-trip back to a playable QVM.

RESQ is not a Swiss-army knife. It speeds the work up, but it does not turn a `.qvm` into a finished project automatically — reading dumps, naming functions, and judging behavior stay with the analyst.


|                         |                                          |
| ----------------------- | ---------------------------------------- |
| Agent standing orders   | `[AGENT.md](AGENT.md)`                   |
| How to run a project    | `[PLAYBOOK.md](PLAYBOOK.md)`             |
| Terms                   | `[GLOSSARY.md](GLOSSARY.md)`             |
| Probe catalog           | `[docs/TOOLS.md](docs/TOOLS.md)`         |
| Cvar BSS xref           | `[docs/CVAR_XREF.md](docs/CVAR_XREF.md)` |
| Emit → q3lcc → q3asm    | `[docs/TOOLCHAIN.md](docs/TOOLCHAIN.md)` |
| Документация на русском | `[README.ru.md](README.ru.md)`           |


## Layout

```
resq-kit/
  toolchain/qvm/       Rust crate (probe_emit, disasm, seqdiff, …)
  tools/win32-qvm/     q3lcc / q3asm (Windows)
  tools/dump.py        strings ±4, identity insn/xref, cvar taint
  tools/qvmbits.py     IEEE i32 ↔ float (and Q3 TFL / CONTENTS)
  tools/scripts/       table / identity helpers (addresses on CLI)
  scripts/             emit_qvm.ps1, build_qvm.ps1
  work/                drop input QVMs here
```

## Quick start

```powershell
cd toolchain\qvm
cargo build --release --bin probe_emit --bin probe_dump_all --bin probe_sigs `
  --bin probe_align --bin probe_disasm --bin probe_findfn --bin probe_findconst `
  --bin probe_check --bin probe_seqdiff --bin probe_uidiff --bin probe_cgamediff

cd ..\..
.\scripts\emit_qvm.ps1 -Qvm work\qagame.qvm -OutDir work\qagame
.\scripts\build_qvm.ps1 -SrcDir work\qagame -Stem qagame
```

On Linux the same flow is `pwsh ./scripts/emit_qvm.ps1 …` plus `./scripts/build_qvm.sh work/qagame qagame` (needs your own `q3lcc`/`q3asm` on `PATH`).

`probe_emit` is **untyped by default** (no `types.rs` overlay; the file ships as an empty template). Pass `--typed` only if you filled that template with a key you can prove.

```powershell
python tools\dump.py --qvm work\qagame.qvm hdr
python tools\dump.py --qvm work\qagame.qvm find "Clan Arena"
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar cg_foo
```

Bar for a rebuild: `probe_check` on the new QVM; `probe_seqdiff orig.qvm rebuilt.qvm` (qagame), `probe_cgamediff` / `probe_uidiff` for the others.

## Needs

- Rust (`cargo`) — analysis, decompile and rebuild tooling is cross-platform
- Python 3
- PowerShell (PowerShell 7 / `pwsh` on Linux) for the wrapper scripts
- Rebuild step (`q3lcc` + `q3asm`):
  - **Windows**: use the shipped binaries in `tools/win32-qvm/`
  - **Linux**: build your own lcc-based `q3lcc` / `q3asm` from any id Tech 3 toolchain source, put them on `PATH`, then call `scripts/build_qvm.sh`

## Do not ship in a zip

`toolchain/qvm/target/`, engines, pk3s, identity dumps of a specific mod.