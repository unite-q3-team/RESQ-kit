# Workflow — decompile a new mod

This kit is the **QVM recompiler** only: any Quake 3 VM → C89 → q3lcc → playable QVM. Bar: `seqdiff` 0 vs the original module (some UI samples keep a known `trap_S_StartLocalSound` Driver Info mismatch; most mods should match).

A **port onto stock source** (rewrite bodies into baseq3a) is a different product. Do not start one unless the user asks.

Standing orders: [AGENT.md](../AGENT.md).

## New mod → identity C (then optional rebuild)

```
probe_emit <mod.qvm> out.c syscalls.asm --no-typed
q3lcc -DQ3_VM -S out.c
q3asm -vq3 -m -o name syscalls.asm name.asm
```

Kit wrappers:

```powershell
.\scripts\emit_qvm.ps1 -Qvm work\qagame.qvm -OutDir work\qagame
.\scripts\build_qvm.ps1 -SrcDir work\qagame -Stem qagame
```

- Start with untyped emit (default; `--no-typed` is a no-op). That is the generic emitter: blob, `loc_0`, gotos, wide `va` / `G_Printf` prototypes.
- Optional `[foo.names] [foo.sigs]` (suffix-detected) for human function names and frames. They are not a data overlay.
- Typed emit uses the optional `types.rs` overlay. It ships empty; fill it per module before `--typed`.

pk3 / git commit: only when the user asks.

## Names vs overlay

| file | role |
|------|------|
| `.sigs` | auto from bytecode (frame / arity / ret) |
| `.names` | align + hand overrides |
| `.asm` | q3lcc output |
| `types.rs` | optional per-mod data-space key (bases, strides, struct pads); ships empty — unused with `--no-typed` |

## Bisect

If a typed rebuild misbehaves: `probe_emit --no-typed` and compare. If `--no-typed` is fine, the overlay/cosmetics are at fault, not the CFG/blob. Never run typed emit with an unfilled or borrowed key.
