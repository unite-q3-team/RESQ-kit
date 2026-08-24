# RESQ tools

Kit-relative. After build: `toolchain/qvm/target/release/*.exe`. Wrappers: `scripts/emit_qvm.ps1`, `scripts/build_qvm.ps1`. Standing orders: [AGENT.md](../AGENT.md).

## Build

```powershell
cd toolchain\qvm

# One tool
cargo build --release --bin probe_emit

# Core set
cargo build --release --bin probe_emit --bin probe_uidiff --bin probe_seqdiff `
  --bin probe_disasm --bin probe_findfn --bin probe_findconst --bin probe_check `
  --bin probe_strat --bin probe_align --bin probe_sigs --bin probe_callers

# Every probe_* in src/bin (slow)
Get-ChildItem src\bin\probe_*.rs | ForEach-Object {
  cargo build --release --bin $_.BaseName
}
```

Host QVM compiler (not Rust) lives separately:

| file | role |
|------|------|
| `tools/win32-qvm/q3lcc.exe` | C → asm (`-DQ3_VM -S`) |
| `tools/win32-qvm/q3cpp.exe` / `q3rcc.exe` | lcc preprocessor / backend |
| `tools/win32-qvm/q3asm.exe` | asm → `.qvm` (**hex-aware** build) |
| `tools/win32-qvm/7za.exe` | 7-Zip CLI — unpack the mod's pk3 (zip); not part of the toolchain pipeline |

Wrapper scripts: `scripts/emit_qvm.ps1`, `scripts/build_qvm.ps1` (see `TOOLCHAIN.md`).

---

## Pipeline (minimum)

### `probe_emit`: decompile → buildable C

```text
probe_emit <in.qvm> <out.c> <out-syscalls.asm> [--sigs file] [--names file]
           [--only a,b,c] [--lst stem] [--typed] [--no-typed]
```

```powershell
New-Item -ItemType Directory -Force -Path ..\..\work\ui | Out-Null
.\target\release\probe_emit.exe `
  ..\..\work\ui.qvm `
  ..\..\work\ui\ui.c `
  ..\..\work\ui\syscalls.asm `
  --no-typed
```

Pass extra `.sigs` / `.names` paths when you have generated them (see below). Emits q3lcc-ready C89, `syscalls.asm`, embeds the data image (`qvm_mem_words`). UI may get a Driver Info compat rewrite (`Q_strncpyz`).

Optional flags: `--only a,b,c` emits a function subset plus its call closure; `--wrapper` adds a stub `vmMain` that references every emitted function so q3asm's entry-root pruning keeps the partial set (use with `--only`); `--lst stem` writes a q3asm `.lst` file list (`syscalls.asm` + `<stem>.asm`) for partial builds.

### `q3lcc` + `q3asm`: C → QVM

```powershell
# Prefer scripts/build_qvm.ps1 — it resets TMP and calls q3lcc via cmd.exe
$tmp = Join-Path $env:USERPROFILE 'AppData\Local\Temp'
$env:Path = "$(Resolve-Path ..\..\tools\win32-qvm);$env:Path"
cd ..\..\work\ui
cmd.exe /c "set TMP=$tmp& set TEMP=$tmp& q3lcc.exe -DQ3_VM -S ui.c & q3asm.exe -vq3 -m -o ui_test syscalls.asm ui.asm"
```

Or: `..\..\scripts\build_qvm.ps1 -SrcDir ..\..\work\ui -Stem ui`.

---

## Bytecode diagnostics

| tool | invocation | purpose |
|------|------------|---------|
| `probe_disasm` | `probe_disasm <qvm> [fn] [lo] [hi]` | disassemble `fn[fn]` or an explicit insn range |
| `probe_findfn` | `probe_findfn <qvm> <insn\|entry>` | which function owns an insn |
| `probe_findconst` | `probe_findconst <qvm> <value>` | all `CONST value` + next opcode |
| `probe_findcall` | `probe_findcall <qvm> <target>` | CALLs to fn or trap (negative) |
| `probe_findstore` | `probe_findstore <qvm> <addr>` | STOREs to absolute data address |
| `probe_strat` | `probe_strat <qvm> <off> [off…]` | string at data/lit offset |
| `probe_data` | `probe_data <qvm> <start_byte> [count]` | dump data words around offset (`f=` + `vec4` when color-like) |
| `probe_addr2idx` | `probe_addr2idx <qvm> <byte_addr>` | code byte address → insn index |
| `probe_check` | `probe_check <qvm>` | static checks like `VM_CheckInstructions` |
| `probe_calls` | `probe_calls <qvm> <fn_index>` | CALLs inside one function |
| `probe_callers` | `probe_callers <qvm> [--named] [--min N] [--only N,M,…]` | callers + strings/traps |
| `probe_inventory` | `probe_inventory <qvm>` | per-fn traps and strings |
| `probe_indircall` | `probe_indircall <qvm>` | indirect CALL / table shapes |

Examples:

```powershell
.\target\release\probe_disasm.exe ..\..\work\ui.qvm 0 30504 30570
.\target\release\probe_findfn.exe ..\..\work\ui.qvm 30504
.\target\release\probe_findconst.exe ..\..\work\ui.qvm 19048
.\target\release\probe_strat.exe ..\..\work\ui.qvm 19048 19480
.\target\release\probe_check.exe ..\..\work\ui\ui_test.qvm
```

Live Quake3e may peephole-rewrite bytecode: debugger PCs ≠ `probe_disasm` indices. Data offsets stay put.

---

## Names and signatures

These files are generated for the QVM you are looking at. Write them under `work/<module>/` and pass them to `probe_emit`. Without them, functions become `fn_<entry>` and arity comes from the bytecode. With them, the C uses real names and tighter prototypes.

Format:

```text
# .names
fn[0] vmMain
fn[7] G_InitGame

# .sigs
fn[0] vmMain frame=28 args=3 ret=int
    arg0=ptr arg1=ptr arg2=ptr
```

`fn[N]` is the CFG function index (`probe_findfn` / `build_functions` order). `probe_emit` picks the path by suffix (`.names` / `.sigs`); `--names` / `--sigs` are just markers.

### `.sigs` from the QVM

```powershell
New-Item -ItemType Directory -Force -Path ..\..\work\ui | Out-Null
.\target\release\probe_sigs.exe `
  ..\..\work\ui.qvm `
  ..\..\work\ui\ui.sigs
```

Optional: pass an existing `.names` so the sig lines carry those names. `probe_sigs` infers frame, arity, and `void|int|float` from ENTER / ARG / LEAVE.

### `.names` from a `.map` of the same QVM

If you already have a q3asm `.map` for this binary:

```powershell
cargo build --release --bin probe_names
.\target\release\probe_names.exe ..\..\work\ui.qvm ui.map
# writes ui.names in the current directory
```

`--all` prints unnamed functions too. The tool always writes `{stem}.names`.

### `.names` by aligning against a known build

When the stale QVM has no map, fingerprint it against a related QVM that does (id Tech3 `game.qvm` + `game.map`, or any rebuild that shipped a map):

```powershell
cargo build --release --bin probe_align
.\target\release\probe_align.exe `
  path\to\known\game.qvm `
  path\to\known\game.map `
  ..\..\work\qagame.qvm
# writes qagame.names in the current directory
```

Passes: exact (op+operand), opcode-only, string/trap signature, then trigram Jaccard. Copy the `.names` next to the module.

Hand names that alignment misses go in a local `overrides.txt` (`fn[N] Name`, `#` comments). Pass it with `--overrides`; those rows win:

```powershell
.\target\release\probe_align.exe `
  path\to\known\game.qvm path\to\known\game.map `
  ..\..\work\qagame.qvm `
  --overrides ..\..\work\qagame\overrides.txt
```

### `.map` from `.names`

```powershell
.\target\release\probe_origmap.exe `
  ..\..\work\qagame.qvm `
  ..\..\work\qagame\qagame.names `
  qagame.map
```

### Other

| tool | invocation | purpose |
|------|------------|---------|
| `probe_typer` | `probe_typer <qvm> [types.txt] [--names file]` | cluster memory accesses (types / regions) |

---

## Orig vs rebuilt diffs (emulator)

Run the same `vmMain` scenario on both QVMs and compare trap logs.

| tool | module | typical call |
|------|--------|--------------|
| `probe_uidiff` | ui | `probe_uidiff <orig.ui.qvm> <rebld.ui.qvm>` |
| `probe_seqdiff` | qagame | `probe_seqdiff <orig> <rebld>` |
| `probe_cgamediff` | cgame | `probe_cgamediff <orig> <rebld>` |
| `probe_diff` | one fn | `probe_diff <orig> <rebld> <fn> [args…]` |
| `probe_verify` | one fn | emulate + print traps with strings |
| `probe_emu` | one fn | `probe_emu <qvm> [fn_index] [args…]` |

```powershell
$env:QVM_UI_CROSSHAIR_MODEL = '1'   # optional
.\target\release\probe_uidiff.exe `
  ..\..\work\ui.qvm `
  ..\..\work\ui\ui_test.qvm
```

On the sample UI expect a few known `trap_S_StartLocalSound` arg mismatches. Emulator errors mean something broke.

Env vars:

| variable | effect |
|----------|--------|
| `QVM_UI_CROSSHAIR_MODEL=1` | richer Game Options crosshair coverage |
| `QVM_SEQ_VERBOSE=1` | verbose trap dump on mismatch |
| `QVM_TRACE_CALLS` / `QVM_TRACE_STEP` | ENTER/LEAVE/CALL trace on rebuilt |
| `QVM_ARGV0=<cmd>` | `Argv(0)` for console-command probes |
| `QVM_MODEL_MATH=1` | sin/cos/sqrt in harness |

---

## Narrow probes

For a specific bug. Skip them in the daily build:

`probe_cgcmd`, `probe_cgframe`, `probe_cgdecal`, `probe_ginit`, `probe_pm`, `probe_sqrt`, `probe_state`, `probe_stepdiff`, `probe_persist`, `probe_shift` / `probe_shift2`, `probe_datacmp`, `probe_whocalls`, `probe_decompile`, `probe_structure`, `probe_switch*`, `vmdbg_diff`.

The rest of `src/bin` (`probe_any`, `probe_blocks`, `probe_cfg`, `probe_checklit`, `probe_chk2`, `probe_chkstr`, `probe_cmdtable`, `probe_findlit`, `probe_fn`, `probe_insns`, `probe_load`, `probe_rebld`, `probe_stubs`, `probe_table`, `probe_trace`, `probe_ucmp`, `probe_vf`) is experimental scratch — no catalog, no stability promise. Running with no args usually prints `usage`.

`probe_dump_all` is part of the daily identity pipeline (structured dump). It needs a large thread stack; large qagames take minutes.

Running with no args usually prints `usage`.

---

## Daily toolkit

```powershell
cargo build --release --bin probe_emit --bin probe_check `
  --bin probe_disasm --bin probe_findfn --bin probe_findconst `
  --bin probe_strat --bin probe_uidiff --bin probe_seqdiff --bin probe_cgamediff
```

Then emit → `scripts/build_qvm.ps1`. Pack a pk3 only if the user asks.

---

## dump.py (string / identity oracle)

```powershell
python tools\dump.py --qvm work\qagame.qvm hdr
python tools\dump.py --qvm work\qagame.qvm find "Clan Arena"
python tools\dump.py --qvm work\qagame.qvm str 21349
python tools\dump.py --qvm work\ui.qvm color 5148
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c insn 107760
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar cg_damageKick
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvars
```

`--qvm` is required. `--c` / `--struct` / `--names` are optional and default to siblings of the QVM (`stem.c`, `stem/stem.c`, …). `hdr` / `str` / `find` / `table` / `ptrs` / `color` need only the QVM. `insn` / `fn` / `calls` / `slot` / `xref` / `addcmd` need the identity `.c`. `cvar` / `cvars` need the QVM for the table; identity `.c` for load counts.

**Color pointers:** `str` is for C strings. A `menutext.color` / `SetColor` CONST is a `vec4*`. `color N` prints RGBA at N−4 / N / N+4 (CONST often mid-vector; not 16-byte aligned). `table` prints `f=` on non-string dwords.

**Cvar loads:** `xref` follows the **name string** only. Gameplay usually CONSTs `vmCvar+8` (BSS), so a used cvar can look unused. Use `cvar NAME` / `cvars` (full `[vm,vm+271]`, table-pointer chase, opcode taint; skip Register/Update by insn range). Recipe and the `amf_debug` miss: [CVAR_XREF.md](CVAR_XREF.md).
