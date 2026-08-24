# Cvar BSS xref (`dump.py cvar`)

Gameplay CONSTs **`vmCvar+8`** (float `.value`, often tested as `int != 0`) or **`+12`** (`.integer`). `dump.py xref NAME` follows the **C string** only. Empty xref ≠ unused.

```powershell
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar amf_debug
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvars
```

`cvar` / `cvars` (alias `cvarxref`) walk the cvar table, then:

1. Identity CONSTs anywhere in **`[vmCvar, vmCvar+271]`** (classified read / write / address-only). Compact `+8` / `+12` and ioq3 `+260` / `+264` are still listed first.
2. Opcode taint on the `.qvm` (CONST / LOAD / ADD / LOCAL → LOAD1/2/4), including **table-pointer chase**: `LOAD *(table+row*stride)` then `LOAD *(p+8)` — identity never prints `qvm_mem+<this BSS>` for that.
3. Pointer escape: `&vmCvar` as a call arg; `BLOCK_COPY` **source** in the 272-byte object (dest-only is not a read).

Skip **Register/Update instruction ranges** (table walk `loc += stride` plus `trap_Cvar_Register|Update`), not overlay names like `RegisterCvars`. A load after the loop in the same function still counts. ROM Update default-copy is not a gameplay read.

Table name dwords may be `find_off` or `find_off+0x100`; `ptrs` searches both. Stride auto-detect is **16–32** (stock cgame/ui often 16; one sample qagame 101×28 @ VM 4). `vmCvar_t` is 272 bytes: **`+280` is the next cvar’s `+8`**, not this `.integer`. `cvars` keeps the `+8` column; `obj` is other `[vm,vm+271]` identity hits; `tbl` is table-pointer / taint identity missed.

If nothing remains: `no CONST, no table-pointer LOAD, no [vm,vm+271] hit outside Register/Update ranges`. Empty `xref NAME` is still not unused.

A worked qagame case below. Kit terms: [GLOSSARY.md](../GLOSSARY.md).

## Symptom (why `xref` lied)

`amf_debug` was catalogued as **leftover** (registered, “no load”): `dump.py xref amf_debug` is empty, and `grep amf_debug` on `qagame.c` is empty except the packed data blob.

In game it is used. With `amf_debug 1`, spectators see stationary plasma (sometimes rocket) orbs at the point a bot is jumping/walking toward.

The bytecode **does** load the cvar. String xref did not show it.

## Why string xref is silent

Gameplay almost never CONSTs the **name string**. It CONSTs the **`vmCvar_t` BSS address**.

| What we grepped | What the VM actually CONST |
|-----------------|----------------------------|
| `"amf_debug"` / `qvm_mem + 13923` (or `@14179`) | `qvm_mem + 54716` (`vmCvar+8`) |
| `trap_Cvar_VariableIntegerValue("amf_debug")` | not used |

`dump.py xref` only follows **string** offsets (`qvm_mem + N` for the C string and ±4). It never walks the cvar table to the BSS cell.

`grep amf_debug` on identity C also fails because lit is packed as `qvm_mem_words[]` hex dwords, not `"amf_debug"` C literals:

```
eWeapon\0amf_debug\0g_blinkImp
```

in `qagame.c` around the data blob (`(void*)0x645f666du` …).

`G_RegisterCvars` / `G_UpdateCvars` walk the table by pointer (`loc_24 += 28`) and call `trap_Cvar_Update`. That is **not** a gameplay load. ROM rows (`flags & 64`) copy the default back onto the `vmCvar` string; still not a read of `.value` for AI.

## Table layout (what `cvar` walks)

Example qagame table: **101 rows**, stride **28**, count at **`qvm_mem+2828`**, first `vmCvar*` at **VM address 4**. Other mods: stride 16 / 20 / 24 / 28 / 32 (auto-detected).

Row layout (same as id `cvarTable_t`):

| off | field |
|-----|--------|
| +0 | `vmCvar_t *` (BSS) |
| +4 | name pointer |
| +8 | default pointer |
| +12 | flags |
| +16 | modificationCount snapshot |
| +20 | trackChange |
| +24 | teamShader |

**Name/default dwords may be `0x100` above `dump.py find` offsets.**  
Example: string at `@13923` vs table dword `14179` (`13923+256`). Current `find amf_debug` on this QVM reports `@14179` (the dword already matches). Same delta on `g_buildWPs` (`14743` vs `14999`). This is **in addition to** the CONST −4 comment rule in the glossary.

Manual recipe (now inside `cvar`):

1. `find NAME` → string offset.
2. Scan the table for `name == find_off` or `find_off + 0x100`. Read `vmCvar`.
3. Identity: `*(int*)(qvm_mem + <vmCvar+8>)` / `*(float*)(qvm_mem + <vmCvar+4>)`.

This QVM tests **`+8`** as an int (`!= 0` works for `"0"`/`"1"` because `0.0f` is all-zero bits). ioq3 `vmCvar_t` has `string[256]` at +0 (`.value` at +260); `cvar` reports both layouts.

## Case: `amf_debug` (was leftover, is a load)

| | |
|--|--|
| table row | 58 |
| flags | 3 (`ARCHIVE\|USERINFO`) |
| default | `"0"` |
| `vmCvar` | `54708` (`0xd5b4`) |
| load | `qvm_mem+54716` (`+8`) |
| identity | `fn_16459` / `L16459` (load line `L16460`) |

`fn_16459(origin, weapon, lifetime_ms)`:

- gate: `*(int*)(qvm_mem+54716) != 0` else return 0
- `G_Spawn`, `classname` `"Mark"` (`qvm_mem+18249`)
- `s.eType = 3` (`ET_MISSILE`), `s.weapon =` arg (`8` plasma / `5` rocket)
- `r.svFlags = 128` (`SVF_USE_CURRENT_ORIGIN`, not `SVF_BROADCAST`), damage/splash 0
- `s.pos.trType = 0` (`TR_STATIONARY`), origin = arg0, Z += 1
- `nextthink = level.time + lifetime`, `think = G_FreeEntity`

Callers pass the bot jump dest (QVM `bs+9368`; port: client table) or a waypoint origin. cgame draws a plasma bolt, so it looks like “plasminki in the air” the bot walks toward.

Identity of `fn_16459` does **not** call `trap_LinkEntity`. Original 0.52 still shows the orbs in-game. Port links so ioq3 snapshots include them.

Port hangs Marks at: waypoint samples (plasma 5000); `fn_34692` DelayedJump landing (plasma 500); `fn_91157` continued jump (plasma 500); RJ commit (rocket 4000). Full `fn_34855` mover is not ported.

Ungated clone `fn_16612` has **no callers**.

`g_debugprint` (`vm+8` = `54444`) is a **different** cvar: `G_LogPrintf_2` text dumps, not Marks.

## Lost cvars re-checked (identity + table-pointer + opcode taint)

These have a **table string** and a `vmCvar` BSS cell. After identity `[vm, vm+271]`, table-pointer LOAD, and QVM taint **outside Register/Update insn ranges** (2026-08-20): **still zero gameplay loads**. Exact `cvar` line:

`no CONST, no table-pointer LOAD, no [vm,vm+271] hit outside Register/Update ranges`

`amf_debug` still hits `+8` at `qvm_mem+54716` (`fn_16459` / `L16460`) — the new chase did not regress.

`trap_Cvar_Variable*` never takes these names. They stay **lost**. Re-audit with `cvar`, not `xref`.

cgame.qvm / ui.qvm: **no C string** for any of these nine — say so and stop.

| name | row | `vmCvar` | flags |
|------|-----|----------|-------|
| `g_buildWPs` | 0 | 47092 | LATCH (32) |
| `g_waypoints` | 65 | 52804 | ROM (64) |
| `bot_speedup` | 72 | 50628 | ROM |
| `bot_hideLGPG` | 70 | 51444 | ROM |
| `bot_enemyacc` | 71 | 51172 | ARCHIVE\|LATCH |
| `bot_newrj` | 83 | 48996 | 0 |
| `bot_maxjump` | 81 | 55252 | 0 |
| `bot_maxdown` | 82 | 54980 | 0 |
| `bot_tfl` | 87 | 47908 | 0 |

Until a LOAD on those 272 bytes exists (this static check or a runtime watchpoint), **do not hang behavior on them**. Changelog text about `bot_speedup` / hide LG / new RJ is intent, not 0.52 wiring.

Readme-only, **no string in qagame/cgame/ui** data+lit: `g_rj_new`, `g_lightningDamage`. Still lost.

ROM lost knobs (`bot_hideLGPG`, `g_waypoints`, `bot_speedup`) are frozen to their defaults by `G_UpdateCvars` (`flags&64`). Hide-LG/PG in bytecode is unconditional (matches ROM default 1), not a read of `bot_hideLGPG`.

Not in `dump.py` (one-off / vmdbg): runtime LOAD watchpoints, `trap_BotLibVarSet` arg provenance, `*.wps` FS. Do not generalize float immediates (0.9 / 1.03 / 1.04).

## Also zero absolute `+8` in qagame (not labeled lost)

Table rows with no `qvm_mem + (vm+8)` in qagame code. Some are engine/UI/`trap_Cvar_Variable*` on the **client**, or ROM banners: `gamename`, `gamedate`, `about`, `g_motd`, `g_log`, `g_banIPs`, `ogc_*`, `g_rankings`, `g_drawBBox`, … Do not mark them lost without checking cgame/ui the same way. `g_drawBBox` is the unlagged client overlay.

## What this is not

- Overlay `struct.c` field names (those lie; identity `L<insn>` wins).
- Inventing BSS names for `gentity` / `bot_state`.
- `dump.py slot` (that is a gclient/gentity **field offset**, not a cvar).
