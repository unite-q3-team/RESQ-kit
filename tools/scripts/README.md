# tools/scripts — generic QVM helpers

Offline parsers. Addresses and function names are **CLI arguments**, never baked in.

## Shared

**qvmstr.py** — `QvmStrings(path)` for data/lit. True VM addresses (identity `qvm_mem + N` is N+4).

## Table / cvar generators

| script | usage |
|--------|--------|
| `tablewalk.py` | `<qvm> <base> <count_addr> [stride]` — dump a struct array (name pointer at +4) |
| `genhelp.py` | `<qvm> <base> <count_addr> <out.h> [stride]` — cvar help/range rows |
| `gencvars.py` | `<reg_log.txt> <qvm> <skeleton_cvar.h> <out.txt>` — missing `G_CVAR` lines |
| `cvardiff.py` | `<reg_log.txt> <skeleton_cvar.h>` — names only each side lacks |

Registration log: `probe_verify` / `probe_seqdiff` INIT output (UTF-16 or UTF-8).

## Identity scans

| script | usage |
|--------|--------|
| `twostep.py` | `<identity.c> <off> [off…]` — two-step field writes |
| `idcallers.py` | `<identity.c> <fn_name>` — call sites + enclosing function |
| `keyreads.py` | `<struct.c> <valueforkey_fn> [keys…]` — infostring key reads |

## Conventions

- Print to stdout; write a file only when an output path is given.
- Do not put a mod’s VM addresses or `fn_NNNN` into these files.
