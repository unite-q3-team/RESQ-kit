# Architecture

```
┌─────────────────┐     probe_emit      ┌──────────────────┐
│  stale .qvm     │ ──────────────────► │  module.c        │
│  (code+data+bss)│   (+names,+sigs)    │  syscalls.asm    │
└─────────────────┘                     └────────┬─────────┘
                                                 │ q3lcc -DQ3_VM -S
                                                 ▼
                                        ┌──────────────────┐
                                        │  module.asm      │
                                        └────────┬─────────┘
                                                 │ q3asm -vq3
                                                 ▼
                                        ┌──────────────────┐
                                        │  module.qvm      │
                                        │  → zzzz-*-fixed  │
                                        └──────────────────┘
```

## `toolchain/qvm` crate

| piece | job |
|-------|-----|
| `loader` / `opcodes` / `disasm` / `cfg` | parse QVM, recover functions |
| `decompile` + `structure` | stack → SSA → C |
| `probe_emit` | q3lcc-ready C + `qvm_mem_words` blob |
| `emu` + `probe_common` | interpret VM, model traps |
| `probe_uidiff` / `probe_seqdiff` / `probe_cgamediff` | compare trap logs orig vs rebuilt |
| `probe_disasm` / `findconst` / `findfn` | spot checks |

## Data addresses

`qvm_mem_words` links at data offset **4** (null page at 0).

Emit writes string refs as `qvm_mem + (orig_addr - 4)` so the linked address matches the original absolute offset.

Bare stores like `*(int*)(260028) = …` keep the original number. The blob must cover that range.

## CONST collisions

A bare `CONST n` can be a string offset or a function entry. Emit picks:

- data → `qvm_mem + …`
- function → `(int)fn_N` (q3asm relocates)

Heuristics that matter on real mods:

- address-taken / global fnptr stores
- field-callback stores (`ent->think` and kin)
- deferred `param_forward` × `bare_call_cells` (confirm-dialog actions)

Wrong pick → bad CALL → menu crash, hang, `unknown type 0`.

## Engine

Live runs used Quake3e. Stay close to upstream. Patch input-VM bugs that show on modern GL (Driver Info) and the ClientSpawn `FL_NO_BOTS` retry in emit compat. Leave client `glconfig` alone.
