# resq-gui translations

Drop a `<code>.json` file into a `lang/` directory and the language
appears in **View > Language** on the next launch. Two locations are
scanned (files in the later one override the earlier):

1. `lang/` next to the executable
2. `lang/` in the working directory

`en` is built in: English UI strings are the *keys*, so a full English
table is not needed (an `en.json` may still override individual strings).

## File format

```json
{
  "code": "de",
  "name": "Deutsch",
  "translations": {
    "File": "Datei",
    "%A/%B functions": "Funktionen: %A/%B"
  },
  "opcode_help": {
    "Enter": "Funktionsprolog: Stackframe anlegen (Operand = Framegroesse)"
  },
  "mem_hints": {
    "seg.data": "Daten",
    "hint.refs": "verwendet in %N Fkt."
  }
}
```

- `code` — short id, saved in the settings; `name` — shown in the menu
  (write it in the language itself).
- `translations` — UI strings. Keys are the exact English source strings
  (including `%KEY` placeholders — keep them, they are filled at runtime).
  A missing key falls back to English.
- `opcode_help` — per-opcode tooltip text, keyed by the exact mnemonic as
  shown in the Disassembly pane (`UNDEF`, `IGNORE`, `BREAK`, `ENTER`,
  `LEAVE`, `CALL`, `PUSH`, `POP`, `CONST`, `LOCAL`, `JUMP`, `EQ`, `NE`,
  `LTI`, `LEI`, `GTI`, `GEI`, `LTU`, `LEU`, `GTU`, `GEU`, `EQF`, `NEF`,
  `LTF`, `LEF`, `GTF`, `GEF`, `LOAD1`, `LOAD2`, `LOAD4`, `STORE1`,
  `STORE2`, `STORE4`, `ARG`, `BLOCK_COPY`, `SEX8`, `SEX16`, `NEGI`,
  `ADD`, `SUB`, `DIVI`, `DIVU`, `MODI`, `MODU`, `MULI`, `MULU`, `BAND`,
  `BOR`, `BXOR`, `BCOM`, `LSH`, `RSHI`, `RSHU`, `NEGF`, `ADDF`, `SUBF`,
  `DIVF`, `MULF`, `CVIF`, `CVFI`). Missing entries fall back to English.
- `mem_hints` — phrases for the memory-address tooltips:
  `seg.data`, `seg.lit` (segment names), `hint.bss` (BSS global note),
  `hint.ptr` (pointer prefix), `hint.refs` (`%N` = referencing-function
  count).

`ru.json` is embedded into the binary as a working example — copy it as
a starting point for a new language. Files with parse errors are
skipped silently (check the console when launching from a terminal).
