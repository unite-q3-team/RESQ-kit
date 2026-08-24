# PLAYBOOK — dive into any Q3 VM with this kit. Analyze, decompile, rebuild.

Standing orders: [`AGENT.md`](AGENT.md). This file is how to run a project from a `.qvm` to identity C (and an optional round-trip), without repeating known traps.

## 0. Project shape

1. **Mod** — `vm/*.qvm` inside the mod’s pk3 (pk3 = zip).
2. **Artifacts** — identity C, struct dumps, sigs/names, trap logs. Live under `work/<project>/`, not inside a game source tree.
3. **Optional skeleton** — only if the user asked for a port. This kit does not include one.

Minimum project docs (if you are porting): a progress journal and a table “bytecode function ↔ role ↔ proof (fn + insn or string)”.

## 1. Setup

```
work/<project>/
  <mod>.qvm
  <mod>.sigs / <mod>.names     # optional
  <mod>/<mod>.c                # identity C
  <mod>/<mod>.struct.c         # structured dump (do not compile)
```

- Put `.names` next to the QVM; the emitter picks them up by suffix.
- Name alignment: build a stock module for the same class (game/cgame/ui), then `probe_align <ref.qvm> <ref.map> <mod.qvm>`. 30–45% hits vs an unrelated skeleton is normal.

## 2. Identify functions

Priority of evidence:

1. format strings (`dump.py find/str`)
2. traps (`probe_inventory`) and neighbor order (lcc keeps file order)
3. struct sizes, field offsets, configstring indexes
4. call graph (`probe_findcall`, `idcallers.py`)
5. aligned names

Typical tells: `player_die` — Kill:/obituary strings; `RunFrame` — frame counter + periodic calls; `ClientCommand` — `trap_Argv(0)` chain.

Trap: `probe_inventory` skips functions with no traps and no strings. The hole in the list is real; find the entry with `probe_findfn`.

## 3. Read identity C

- Control flow matches bytecode 1:1. Struct dump is easier to read and can **lie** about loop nesting — check identity C.
- **Offset rule:** `qvm_mem + N` ↔ true VM address `N + 4` (blob word 0 is a NULL sentinel). Raw disasm uses true addresses.
- Field writes are usually two-step: `loc = base + OFFSET; *loc = *loc + k;` — `tools/scripts/twostep.py`.
- Relocated function pointers in the blob are bare `fn_NNNN,` (no cast). Grep `(int)fn_` misses them.
- Trap logs list the **syscall number first**: `[18, 672, ptr]` is `SetConfigstring(672, ptr)`, not configstring 18.

## 4. QVM facts

- Classic id header: literals immediately after data. Some assemblers add an extra trailing int after `bssCount` — ignore it; detect layout from file size.
- Emit blob size = real `data+lit+bss` (+ sentinel), **not** `pow2(dataMask)`. The pow2 pad blows q3asm `MAX_IMAGE`.
- Check your q3asm limit (classic 0x400000, some builds 0x800000). Keep the blob compact.

## 5. Parity oracle

```
probe_seqdiff <orig.qvm> <rebuilt.qvm>     # qagame-class
probe_cgamediff / probe_uidiff             # cgame / ui
probe_check <rebuilt.qvm>
```

- `QVM_SEQ_MEMDIFF=1` — word diffs after INIT at relocated function-pointer cells are expected (new code indexes). Classify before “fixing”.
- `QVM_RELOC_DEBUG=2` — every blob word that looks like an ENTER.
- Rebuilt step budget is orig + 50000 per call; over-budget often means a loop, but a 4-iteration cycle can false-trigger a naive repeat detector.

## 6. If you are porting (optional)

- Bytecode wins. Skeleton vs bytecode → edit the skeleton.
- Every edit cites proof (fn + insn or string). No cite, no edit.
- Compile the changed file before logging it; delete leftover `.asm`.
- Generate data tables from bytecode (`tools/scripts/tablewalk.py`, `gen*.py`) with addresses on the CLI.

## 7. Environment traps

PowerShell 5.1: no `&&`; `>` is UTF-16LE; `Set-Content -Encoding UTF8` writes a BOM that breaks cpp. Inline Python with quotes/regex belongs in a file. Call `emit_qvm.ps1` without `2>&1`.

## 8. Tools

[`docs/TOOLS.md`](docs/TOOLS.md), [`docs/WORKFLOW.md`](docs/WORKFLOW.md), [`tools/scripts/README.md`](tools/scripts/README.md).
