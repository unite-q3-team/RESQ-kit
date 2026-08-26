# resq-gui struct types

Struct definitions for the Ghidra-style **apply type** feature: RMB a
`loc_N` token in the Identity C pane, choose a struct, and field accesses
are rewritten from raw offsets into named fields:

    *(<int>*)((loc_20) + (704)) = 0;     becomes     (loc_20->pers) = 0;

Drop `*.json` files into a `structs/` directory (next to the executable
or in the working directory) and restart. Files are merged; same-name
types from later files win.

## File format

```json
{
  "gclient_t": {
    "size": 1568,
    "fields": {
      "0": "client",
      "704": "pers",
      "712": "ps"
    }
  }
}
```

- top-level keys are type names (shown in the Apply struct menu);
- `size` — total struct size in bytes (optional, informational; should
  match the stride you see in `loc_N = arg * STRIDE + base`);
- `fields` — byte offset (as a string key) -> field name. Nested types
  are not followed: a field at an offset that starts a sub-struct is
  just another name.

Applied types are stored per QVM in a sidecar file next to it
(`<name>.types.json`), keyed by function entry instruction, and are
reloaded automatically. Clear a type via the same menu (`(clear type)`).

Real offsets/names come from your mod's SDK headers. `example.json` is
a synthetic demo — replace it.
