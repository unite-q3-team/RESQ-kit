# Emit-time compat

A faithful decompile keeps bugs that were in the input `.qvm`. Some of them only blow up on modern hardware. `probe_emit` can rewrite the generated C after emit so the next rebuild still carries the fix.

The two sites below were recovered on specific sample modules. Another mod may not have them. Do not assume they apply; do not copy the insn numbers onto another QVM.

## Driver Info (sample UI)

Symptom: `Setup → System → Graphics → Driver Info` → `program tried to read out of data segment`.

Cause: a UI helper does `strcpy(scratch@365972, extensions@190436)`. Scratch is 1024 bytes (`365972..366996`). A long `GL_EXTENSIONS` stomps the line-pointer table.

Emit rewrite:

```text
fn_66367(365972, 190436)   →   fn_76610(365972, 190436, 1024)
(strcpy)                        (Q_strncpyz)
```

Truncating `extensions_string` in `UI_GETGLCONFIG` was tried and dropped: upstream Quake3e does not do that.

## ClientSpawn / `FL_NO_BOTS` (sample qagame)

Symptom: `spmap q3dm0`, player leaves the start pad, bot Crash joins → hang in `ClientSpawn`.

Cause: lcc left the spawn-spot pointer live across the `FL_NO_BOTS` `continue` back-edge. The loop head then sees a non-NULL spot, skips `SelectSpawnPoint`, and retries the same nobots pad forever. The original bytecode has the same shape; orig usually escapes because its first pick after `GAME_INIT` is bot-ok. Rebuilt’s rand stream more often picks the nobots pad first. Do not cap the retry loop — orig already survives without a cap.

Emit rewrite at the retry label:

```text
L123403:
  *(int*)&loc_0[2000] = (int)vmMain;

→

L123403:
  *(int*)&loc_0[104] = (int)vmMain;   /* clear spot */
  *(int*)&loc_0[2000] = (int)vmMain;
```

## Rules

Fix input-VM bugs in the emitter. Do not keep permanent hand-edits in generated `.c`. Log new compat sites here.
