//! Shared trap-sequence capture for the differential verifiers.
//!
//! A single source of truth for (a) the real argument count of each game trap
//! (so stale stack slots beyond the ARG pushes are ignored), (b) deterministic
//! modeling of trap out-parameters (so callers branch identically on both
//! sides even though frame memory differs), and (c) the string/blob rendering
//! of trap arguments that `probe_diff` / `probe_seqdiff` compare.
//!
//! `GetEntityToken` (game trap 37) feeds a realistic map entity string with
//! engine `COM_Parse` semantics (quote stripping, whitespace skipping, qfalse
//! at EOF). Without it `G_SpawnEntitiesFromString` never parsed any entity and
//! both sides took the `G_Error("SpawnEntities: no entities")` path, hiding the
//! real spawn path where the rebuilt module crashed.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::traps::Module;
use crate::{trap_name, Memory, SyscallHandler};

/// Real argument count for traps (so stale stack slots beyond the actual ARG
/// pushes are ignored in the comparison). Unlisted traps keep the default 8
/// and are the remaining source of false positives. cgame uses the Q3 1.32-era
/// cg_syscalls numbering (see cgame_trap in traps.rs), which differs from the
/// game numbering above 28.
pub fn arity_of(m: Module, n: u32) -> Option<usize> {
    if m == Module::Ui {
        return Some(match n {
            // Q3 1.32-era ui_syscalls numbering (ui_syscalls.asm). NOTE: the
            // ui numbering differs from BOTH game and cgame (Cvar_Register is
            // 50 here, not 3; Cvar_Set is 3).
            0 => 1,         // Error(msg)
            1 => 1,         // Print(msg)
            2 => 0,         // Milliseconds
            3 => 2,         // Cvar_Set(name, value)
            4 => 1,         // Cvar_VariableValue(name)
            5 => 3,         // Cvar_VariableStringBuffer(name, buf, size)
            6 => 2,         // Cvar_SetValue(name, value)
            7 => 1,         // Cvar_Reset(name)
            8 => 3,         // Cvar_Create(name, value, flags)
            9 => 3,         // Cvar_InfoStringBuffer
            10 => 0,        // Argc
            11 => 3,        // Argv(arg, buf, size)
            12 => 2,        // Cmd_ExecuteText(exec_when, text)
            13 => 3,        // FS_FOpenFile(qpath, *f, mode)
            14 => 3,        // FS_Read(buf, len, f)
            15 => 3,        // FS_Write(buf, len, f)
            16 => 1,        // FS_FCloseFile(f)
            17 => 4,        // FS_GetFileList(path, ext, *list, listSize)
            18 => 1,        // R_RegisterModel(name)
            19 => 1,        // R_RegisterSkin(name)
            20 => 1,        // R_RegisterShaderNoMip(name)
            21 => 0,        // R_ClearScene
            22 => 1,        // R_AddRefEntityToScene(&re)
            23 => 3,        // R_AddPolyToScene(shader, numVerts, verts)
            24 => 6,        // R_AddLightToScene(origin, radius, intensity, r, g, b)
            25 => 1,        // R_RenderScene(&refdef)
            26 => 1,        // R_SetColor(vec4)
            27 => 9,        // R_DrawStretchPic(x, y, w, h, s1, t1, s2, t2, shader)
            28 => 0,        // UpdateScreen
            29 => 4,        // CM_LerpTag(tag, refent, tagName, startIndex)
            30 => 1,        // CM_LoadModel(name)
            31 => 2,        // S_RegisterSound(name, compressed)
            32 => 3,        // S_StartLocalSound(sound, channel, volume)
            33 => 3,        // Key_KeynumToStringBuf
            34 => 3,        // Key_GetBindingBuf
            35 => 3,        // Key_SetBinding
            36 => 1,        // Key_IsDown
            37 => 1,        // Key_GetOverstrikeMode
            38 => 1,        // Key_SetOverstrikeMode
            39 => 0,        // Key_ClearStates
            40 => 0,        // Key_GetCatcher
            41 => 1,        // Key_SetCatcher
            42 => 2,        // GetClipboardData
            43 => 1,        // GetGlconfig(&glconfig)
            44 => 1,        // GetClientState(&cl)
            45 => 3,        // GetConfigString(index, buf, size)
            46 => 0,        // LAN_GetPingQueueCount
            47 => 1,        // LAN_ClearPing(n)
            48 => 3,        // LAN_GetPing
            49 => 3,        // LAN_GetPingInfo
            50 => 4,        // Cvar_Register(&var, name, defaultValue, flags)
            51 => 1,        // Cvar_Update(&var)
            52 => 0,        // MemoryRemaining
            53 => 2,        // GetCDKey(buf, len)
            54 => 2,        // SetCDKey(buf, len)
            55 => 3,        // R_RegisterFont(name, pointSize, &font)
            56 => 2,        // R_ModelBounds(model, mins, maxs)
            57 => 1,        // PC_AddGlobalDefine
            58 => 1,        // PC_LoadSource
            59 => 1,        // PC_FreeSource
            60 => 2,        // PC_ReadToken
            61 => 2,        // PC_SourceFileAndLine
            62 => 0,        // S_StopBackgroundTrack
            63 => 2,        // S_StartBackgroundTrack
            64 => 1,        // RealTime(&qtime)
            65 => 1,        // LAN_GetServerCount
            66 => 2,        // LAN_GetServerAddressString
            67 => 3,        // LAN_GetServerInfo
            68 => 2,        // LAN_MarkServerVisible
            69 => 1,        // LAN_UpdateVisiblePings
            70 => 0,        // LAN_ResetPings
            71 => 0,        // LAN_LoadCachedServers
            72 => 0,        // LAN_SaveCachedServers
            73 => 3,        // LAN_AddServer
            74 => 2,        // LAN_RemoveServer
            75 => 6,        // CIN_PlayCinematic(filename, x, y, w, h, systemBits)
            76 => 1,        // CIN_StopCinematic(handle)
            77 => 1,        // CIN_RunCinematic(handle)
            78 => 1,        // CIN_DrawCinematic(handle)
            79 => 5,        // CIN_SetExtents(handle, x, y, w, h)
            80 => 3,        // R_RemapShader
            81 => 2,        // VerifyCDKey
            82 => 3,        // LAN_ServerStatus
            83 => 2,        // LAN_GetServerPing
            84 => 1,        // LAN_ServerIsVisible
            85 => 2,        // LAN_CompareServers
            86 => 3,        // FS_Seek
            87 => 1,        // SetPbClStatus
            100..=102 => 3, // memset/memcpy/strncpy
            103..=108 => 1, // float math helpers
            _ => return None,
        });
    }
    if m == Module::CGame {
        return Some(match n {
            // Q3 1.32-era cg_syscalls numbering (cg_syscalls.c / cg_syscalls.asm).
            // Arity = exact argument count from the real prototypes. An
            // over-count renders stale frame slots as "args" and produces false
            // mismatches (e.g. the loop index in the arg1 slot of
            // trap_AddCommand, which takes only the command name).
            // 1 arg
            0 | 1 | 4 | 13 | 14 | 15 | 16 | 18 | 20 | 21 | 30 | 36 | 37 | 38 | 39 | 41 | 44
            | 45 | 49 | 50 | 53 | 57 | 60 | 62 | 63 | 64 | 65 | 66 | 70 | 71 | 72 | 75 | 76
            | 77 | 81 | 91 => 1,
            // 0 args
            2 | 7 | 17 | 19 | 40 | 54 | 58 | 61 | 69 => 0,
            // 2 args
            5 | 9 | 22 | 29 | 32 | 34 | 35 | 51 | 52 | 55 | 56 | 67 | 82 | 86 | 88 | 93 => 2,
            // 3 args
            6 | 8 | 10 | 11 | 12 | 42 | 47 | 59 | 68 | 79 | 89 | 90 | 100 | 101 | 102 => 3,
            // 4 args
            3 | 23 | 28 | 31 | 33 | 73 | 80 | 87 => 4,
            // 5 args
            43 | 78 | 85 => 5,
            // 6 args
            48 | 74 | 92 => 6,
            // 7 args
            25 | 27 | 83 => 7,
            // 9 args
            26 | 46 | 84 => 9,
            // float math helpers
            103 | 104 | 106 | 107 | 108 | 111 => 1,
            105 | 109 | 110 => 2, // atan2(y,x), testPrintInt, testPrintFloat
            _ => return None,
        });
    }
    Some(match n {
        // 1 arg
        0 | 1 | 4 | 6 | 13 | 14 | 30 | 31 | 34 | 35 | 40 | 41 | 42 | 103 | 104 | 106 | 110
        | 111 => 1,
        // 2 args
        5 | 16 | 17 | 18 | 20 | 21 | 22 | 23 | 25 | 26 | 27 | 28 | 29 | 36 | 37 | 105 => 2,
        // 3 args
        7 | 9 | 10 | 11 | 12 | 19 | 33 | 44 | 45 | 100 | 101 | 102 => 3,
        // 4 args
        3 | 32 | 38 | 39 => 4,
        // 5 args
        15 => 5, // LocateGameData (the reference bytecode pushes 5 args)
        // 7 args
        24 | 43 => 7, // Trace / TraceCapsule (results, start, mins, maxs, end, passEntityNum, contentmask)
        // 0 args
        2 | 8 => 0,
        _ => return None,
    })
}

/// Read an arbitrary NUL-terminated byte string from VM memory (no
/// printable-only restriction; used for cvar default values which may be
/// empty or contain non-printable bytes).
fn q_bytes(mem: &Memory, addr: i32) -> Vec<u8> {
    let a = (addr as u32 & mem.data_mask) as usize;
    let rest = mem.data.get(a..);
    match rest {
        Some(r) => r.iter().take(256).position(|&b| b == 0).map_or_else(
            || r.iter().take(256).copied().collect(),
            |end| r[..end].to_vec(),
        ),
        None => Vec::new(),
    }
}

/// Parse a decimal integer (with optional leading '-') from bytes.
fn parse_int(b: &[u8]) -> i32 {
    let mut i = 0usize;
    let neg = if i < b.len() && b[i] == b'-' {
        i += 1;
        true
    } else {
        false
    };
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v * 10 + (b[i] - b'0') as i64;
        i += 1;
    }
    if neg {
        -v as i32
    } else {
        v as i32
    }
}

fn q_string(mem: &Memory, addr: i32) -> Option<String> {
    let a = (addr as u32 & mem.data_mask) as usize;
    let rest = mem.data.get(a..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    let s = &rest[..end];
    if s.is_empty()
        || !s
            .iter()
            .all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
    {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Map entity string served by the harness `GetEntityToken`. The engine feeds
/// the real map entity text through `sv.entityParsePoint` + `COM_Parse` (see
/// ioq3 `server/sv_game.c` G_GET_ENTITY_TOKEN / `qcommon/q_shared.c`
/// `COM_ParseExt`): whitespace skipping, quote stripping, qfalse + "" at EOF.
/// A minimal but valid level (worldspawn + one spawn point) makes
/// `G_SpawnEntitiesFromString` parse and spawn real entities instead of
/// immediately erroring "SpawnEntities: no entities".
const ENTITY_STRING: &[u8] = b"{\n\
\"classname\" \"worldspawn\"\n\
\"message\" \"q3dm0\"\n\
\"music\" \"sound/music/misc/action.wav\"\n\
\"gravity\" \"800\"\n\
}\n\
{\n\
\"classname\" \"info_player_deathmatch\"\n\
\"origin\" \"128 128 24\"\n\
\"angle\" \"180\"\n\
}\n";

/// Token cursor over the harness entity string, mirroring the engine's
/// `sv.entityParsePoint`. `reset()` is called at each level load (GAME_INIT),
/// exactly like `SV_SpawnServer` re-points `sv.entityParsePoint`.
pub struct EntityTokens {
    src: &'static [u8],
    pos: usize,
}

impl EntityTokens {
    fn new() -> Self {
        // QVM_ENTFILE=<path> replaces the tiny harness map with a real BSP
        // entity lump (e.g. q3dm0) so GAME_INIT can be dumped against orig vs
        // rebuilt. Unset → keep the one-pad default used by seqdiff.
        let src: &'static [u8] = match std::env::var("QVM_ENTFILE") {
            Ok(p) if !p.is_empty() => {
                let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("QVM_ENTFILE {p}: {e}"));
                Box::leak(bytes.into_boxed_slice())
            }
            _ => ENTITY_STRING,
        };
        Self { src, pos: 0 }
    }

    pub fn reset(&mut self) {
        self.pos = 0;
    }

    /// Write the next token (NUL-terminated, quote-stripped) into `data` at
    /// `dst` (buffer `size` bytes, like `Q_strncpyz` into the QVM buffer).
    /// Returns qfalse + empty token at EOF, qtrue otherwise.
    fn next_into(&mut self, data: &mut [u8], dst: usize, size: usize) -> bool {
        let src = self.src;
        let mut i = self.pos;
        while i < src.len() && src[i] <= b' ' {
            i += 1;
        }
        if i >= src.len() {
            self.pos = i;
            if dst < data.len() {
                data[dst] = 0;
            }
            return false;
        }
        let n = size.saturating_sub(1).min(data.len().saturating_sub(dst));
        let mut o = 0usize;
        if src[i] == b'"' {
            i += 1;
            while i < src.len() && src[i] != b'"' {
                if o < n {
                    data[dst + o] = src[i];
                    o += 1;
                }
                i += 1;
            }
            if i < src.len() {
                i += 1; // closing quote
            }
        } else {
            while i < src.len() && src[i] > b' ' {
                if o < n {
                    data[dst + o] = src[i];
                    o += 1;
                }
                i += 1;
            }
        }
        self.pos = i;
        if dst + o < data.len() {
            data[dst + o] = 0;
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct TrapLog {
    pub num: u32,
    pub name: String,
    pub args: Vec<String>,
    pub raw: Vec<i32>,
}

impl PartialEq for TrapLog {
    fn eq(&self, o: &TrapLog) -> bool {
        // `raw` holds blob-relative pointers which legitimately differ between
        // modules; only the rendered semantics matter for equality.
        self.num == o.num && self.name == o.name && self.args == o.args
    }
}

/// Build the syscall handler that models trap out-parameters deterministically
/// and records a `TrapLog` per call. `base` is the blob-relative offset of the
/// image (0 for identity-mapped full-module rebuilds); arg pointers below the
/// stack threshold are rendered blob-relative so both sides compare equal.
pub fn make_handler(m: Module, base: u32, logs: Rc<RefCell<Vec<TrapLog>>>) -> SyscallHandler {
    make_handler_ctrl(m, base, logs).syscall
}

/// `make_handler` plus a handle to the harness entity-token cursor, so
/// persistent-session harnesses can reset it at each level load (GAME_INIT).
pub struct HandlerCtrl {
    pub syscall: SyscallHandler,
    pub entity_tokens: Rc<RefCell<EntityTokens>>,
}

/// Harness state for serving realistic evolving cgame snapshots (see
/// `make_handler_snap`): a monotonically increasing snapshot number and the
/// current server time, advanced by the driver before each DrawActiveFrame.
#[derive(Clone, Copy)]
pub struct SnapState {
    pub snap_num: i32,
    pub snap_time: i32,
}

/// `make_handler` plus a handle to the snapshot state, so a persistent
/// DrawActiveFrame harness can advance snapNum/serverTime each frame.
pub struct HandlerSnap {
    pub syscall: SyscallHandler,
    pub state: Rc<RefCell<SnapState>>,
}

pub fn make_handler_ctrl(m: Module, base: u32, logs: Rc<RefCell<Vec<TrapLog>>>) -> HandlerCtrl {
    let (syscall, entity_tokens) = make_handler_inner(m, base, logs, None);
    HandlerCtrl {
        syscall,
        entity_tokens,
    }
}

/// Snapshot-enabled handler: cgame trap 51/52 serve a full evolving snapshot
/// (see `write_snapshot`) instead of the zeroed buffer, so the entity-rendering
/// path (`CG_AddPacketEntities` -> `CG_AddCEntity` -> trap 32 per entity) runs
/// on both sides. Returns the shared `SnapState` the driver advances per frame.
pub fn make_handler_snap(m: Module, base: u32, logs: Rc<RefCell<Vec<TrapLog>>>) -> HandlerSnap {
    let state = Rc::new(RefCell::new(SnapState {
        snap_num: 2,
        snap_time: 1000,
    }));
    let (syscall, _entity_tokens) = make_handler_inner(m, base, logs, Some(state.clone()));
    HandlerSnap { syscall, state }
}

/// Number of synthetic parse entities served per cgame snapshot by the
/// snapshot harness (matches the entity-rendering sets seen in the reference dumps).
const SNAP_ENTITIES: i32 = 158;

/// Write a cgame snapshot_t at `dest`. Field offsets verified from the rebuilt
/// `_emit_cgame/cgame.c` reads: serverTime@+4, ps.clientNum@+184,
/// numEntities@+512, parse-entity records of 208B starting at +516. `N`
/// entities, each a 208-byte record whose first int is the entity number and
/// eType=ET_GENERAL at +4 — enough for `CG_AddPacketEntities` ->
/// `CG_AddCEntity` -> `CG_SetEntitySoundPosition` to emit one trap 32
/// (`S_UpdateEntityPosition`) per entity in both modules.
///
/// Event exercise (offsets from the reference CG_EntityEvent/CG_Missile reads):
/// entity 1 is a WP_RAILGUN missile (eType=ET_MISSILE) whose `event` field
/// alternates EV_MISSILE_HIT(49) / EV_RAILTRAIL(53) on the parity of snap_num.
/// `CG_CheckEvents` fires `CG_EntityEvent` while `event != previousEvent`
/// (`previousEvent` lives in the centity, not the snapshot record), so both
/// event types execute on alternating frames and drive the explosion FX/sounds
/// and the rail trail (MarkFragments + R_AddPolyToScene) on both sides.
fn write_snapshot(mem: &mut Memory, dest: i32, snap_time: i32, snap_num: i32) {
    let d0 = dest as u32 & mem.data_mask;
    let end = (516 + (SNAP_ENTITIES as usize) * 208) as u32;
    for i in 0..end {
        let o = (d0 + i) as usize;
        if o < mem.data.len() {
            mem.data[o] = 0;
        }
    }
    mem.store4(dest, 0); // snapFlags
    mem.store4(dest + 4, snap_time); // serverTime
    mem.store4(dest + 8, 0); // serverTimeDelta
    mem.store4(dest + 12, 0); // ping
    mem.store4(dest + 184, 0); // ps.clientNum (player entity 0)
    mem.store4(dest + 512, SNAP_ENTITIES); // numEntities
    let event = if snap_num % 2 == 0 { 49 } else { 53 };
    for i in 0..SNAP_ENTITIES {
        let r = dest + 516 + 208 * i;
        mem.store4(r, i); // parse entity number
        if i == 1 {
            mem.store4(r + 4, 3); // eType = ET_MISSILE
            mem.store4(r + 24, snap_time); // origin[0]
            mem.store4(r + 28, 0); // origin[1]
            mem.store4(r + 32, 0); // origin[2]
            mem.store4(r + 140, 16); // missile-dir-ish field read by the explosion helper
            mem.store4(r + 164, 16); // eventParm (16..80 -> child cent)
            mem.store4(r + 168, 0); // clientNum
            mem.store4(r + 180, event); // event
            mem.store4(r + 184, 1); // != 255 -> rail branch taken
            mem.store4(r + 192, 7); // weapon = WP_RAILGUN (rail trail)
        } else {
            mem.store4(r + 4, 1); // eType = ET_GENERAL
        }
    }
}

/// Shared handler body. `snaps = Some(...)` enables the evolving-snapshot
/// harness; `None` keeps the deterministic zeroed-out-params behavior.
fn make_handler_inner(
    m: Module,
    base: u32,
    logs: Rc<RefCell<Vec<TrapLog>>>,
    snaps: Option<Rc<RefCell<SnapState>>>,
) -> (SyscallHandler, Rc<RefCell<EntityTokens>>) {
    let entity_tokens: Rc<RefCell<EntityTokens>> = Rc::new(RefCell::new(EntityTokens::new()));
    let toks = entity_tokens.clone();
    let syscall: SyscallHandler = Box::new(move |mem, num, a| {
        let thresh = mem.data_mask + 1 - 65536;
        let mut tok_ret: Option<i32> = None;
        // Model trap out-parameters deterministically BEFORE logging so the
        // pre-call rendering is identical on both sides. Without this, callers
        // branch on (and the diff renders) uninitialized frame memory, which
        // differs between modules. NOTE: `a` is the interpreter's arg array
        // with a[0] = trap number, so arg0 = a[1], arg1 = a[2], ...
        //
        // IMPORTANT: each module has its OWN trap numbering (see traps.rs).
        // Game out-param handlers must NEVER fire on cgame/ui traps — e.g.
        // cgame trap 36 is R_LoadWorldMap (not GetUsercmd), ui trap 3 is
        // Cvar_Set (not Cvar_Register). Applying a game handler would corrupt
        // the caller's frame/dispatch memory and diverge the two sides.
        let zero = |mem: &mut Memory, dst: i32, n: usize| {
            let d = (dst as u32 & mem.data_mask) as usize;
            for i in 0..n {
                if d + i < mem.data.len() {
                    mem.data[d + i] = 0;
                }
            }
        };
        let store1 = |mem: &mut Memory, dst: i32, v: u8| {
            let d = dst as u32 & mem.data_mask;
            if (d as usize) < mem.data.len() {
                mem.data[d as usize] = v;
            }
        };
        let store4 = |mem: &mut Memory, dst: i32, v: i32| mem.store4(dst, v);
        let argv0 = |mem: &mut Memory, a: &[i32]| {
            // Argv(arg, buf, size): unless QVM_ARGV0 is set, returns an empty
            // string. With QVM_ARGV0=<cmd>, Argv(0, ...) returns that command so
            // console-command dispatch actually reaches the command table
            // (used by probe_cgcmd to exercise CG_ConsoleCommand).
            if let Ok(cmd) = std::env::var("QVM_ARGV0") {
                if a[1] == 0 && !cmd.is_empty() {
                    let src = cmd.as_bytes();
                    let size = (a[3] as usize).min(src.len()).min(1023);
                    let dst = a[2] as u32 & mem.data_mask;
                    for i in 0..size {
                        mem.data[dst as usize + i] = src[i];
                    }
                    mem.data[dst as usize + size] = 0;
                    return;
                }
            }
            store1(mem, a[2], 0);
        };
        let cvar_register = |mem: &mut Memory, a: &[i32]| {
            // Cvar_Register(vmCvar_t*, name, defaultValue, flags): fill the
            // vmCvar_t struct (handle, modCount, value, integer, string[256])
            // from the default so callers read the table's default integer
            // (e.g. sv_maxclients=8 -> level.maxclients). Without this every
            // registered cvar stays 0 and branches on it are skipped.
            //
            // Match the engine: a NULL vmCvar_t* slot (Cvar_Register returns
            // early in cvar.c `if (!vmCvar) return;`) must NOT be written —
            // the cgame calls trap_Cvar_Register(0, ...) for engine-only cvars
            // and writing the struct at address 0 clobbers the vmMain dispatch
            // table (data[0..272]).
            if a[1] == 0 {
                return;
            }
            let slot = a[1] as u32 & mem.data_mask;
            let def = q_bytes(mem, a[3]);
            let iv = parse_int(&def);
            let fv = iv as f32;
            mem.store4(a[1], slot as i32); // handle
            mem.store4(a[1] + 4, 0); // modificationCount
            mem.store4(a[1] + 8, fv.to_bits() as i32); // value (float)
            mem.store4(a[1] + 12, iv); // integer
            let n = def.len().min(256);
            for i in 0..n {
                mem.data[slot as usize + 16 + i] = def[i];
            }
            if n < 256 {
                mem.data[slot as usize + 16 + n] = 0;
            }
        };
        // QVM_TRACEGROUND=1: model an infinite flat floor just below the trace
        // start. The 0.25-down pmove ground probe and the PM_STEP_HEIGHT
        // step-down probe then hit (fraction<1, normal (0,0,1), entityNum=world)
        // while the step-up probe and flat traces miss (fraction=1.0), so both
        // sides actually execute the grounded-walk + step logic. Without it the
        // default flat model (fraction=1.0, nothing hit) never grounds the
        // player and the stair code is dead on both sides (false-green).
        let trace_ground = std::env::var("QVM_TRACEGROUND").unwrap_or_default() == "1";
        let trace = |mem: &mut Memory, a: &[i32]| {
            // Trace/Capsule / CM_*(Capsule)BoxTrace(results, start, mins, maxs,
            // end, ...). trace_t layout (q_shared.h): qboolean allsolid (+0),
            // qboolean startsolid (+4), float fraction (+8), vec3_t endpos
            // (+12), cplane_t plane (+24), surfaceFlags (+40), contents (+44),
            // entityNum (+48).
            let dst = a[1];
            let base = dst as u32 & mem.data_mask;
            for i in 0..72usize {
                mem.data[base as usize + i] = 0;
            }
            if !trace_ground {
                mem.store4(dst + 8, 0x3f800000); // fraction = 1.0f (nothing hit)
                return;
            }
            let st = a[2];
            let en = a[5];
            let sz = f32::from_bits(mem.load4(st + 8) as u32);
            let ez = f32::from_bits(mem.load4(en + 8) as u32);
            let floor = sz - 0.125;
            if sz.min(ez) > floor {
                mem.store4(dst + 8, 0x3f800000); // fraction = 1.0f (miss)
                return;
            }
            // fraction at which the segment crosses the floor; endpos = crossing
            let t = ((floor - sz) / (ez - sz)).clamp(0.0, 1.0);
            let sx = f32::from_bits(mem.load4(st) as u32);
            let sy = f32::from_bits(mem.load4(st + 4) as u32);
            let ex = f32::from_bits(mem.load4(en) as u32);
            let ey = f32::from_bits(mem.load4(en + 4) as u32);
            mem.store4(dst + 8, t.to_bits() as i32); // fraction (hit: < 1.0)
            mem.store4(dst + 12, (sx + (ex - sx) * t).to_bits() as i32);
            mem.store4(dst + 16, (sy + (ey - sy) * t).to_bits() as i32);
            mem.store4(dst + 20, (sz + (ez - sz) * t).to_bits() as i32);
            mem.store4(dst + 24, 0); // plane normal x
            mem.store4(dst + 28, 0); // plane normal y
            mem.store4(dst + 32, 0x3f800000); // plane normal z = 1
            mem.store4(dst + 36, 0); // plane dist
            mem.store4(dst + 40, 0); // surfaceFlags
            mem.store4(dst + 44, 1); // contents = CONTENTS_SOLID
            mem.store4(dst + 48, 0); // entityNum = ENTITYNUM_WORLD
        };
        // Optional realistic player usercmd for trap GetUsercmd (game 36) /
        // GetUserCmd (cgame 55). The default zero cmd keeps pmove stationary
        // and never fires the weapon (PM_Weapon -> EV_FIRE_WEAPON -> FireWeapon
        // path), which is exactly the movement/fire code the symptom hunt is
        // about. QVM_USERCMD=run enables a running + attacking player.
        let usercmd_run = {
            let u = std::env::var("QVM_USERCMD").unwrap_or_default();
            u == "run"
        };
        // vmMain's GAME_CLIENT_THINK argument is a client number, not a
        // monotonically increasing usercmd sequence. Use the trap invocation
        // count instead, otherwise every scripted think receives serverTime
        // 1000 and Pmove rejects all but the first command as stale.
        let usercmd_serial = Rc::new(Cell::new(0i32));
        let usercmd_serial_h = usercmd_serial.clone();
        // Keep the fixture below Pmove's normal 66 ms subdivision when needed:
        // QVM_USERCMD_MSEC=50 makes a single advancing command execute exactly
        // one PmoveSingle, which is useful for first-divergence tracing.
        let usercmd_msec = std::env::var("QVM_USERCMD_MSEC")
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .filter(|&m| (1..=66).contains(&m))
            .unwrap_or(100);
        let usercmd = |mem: &mut Memory, dst: i32, cmdnum: i32| {
            // usercmd_t layout (q_shared.h): int serverTime; int angles[3];
            // int buttons; byte weapon; signed char forwardmove,rightmove,upmove.
            // sizeof(usercmd_t) = 4*5 + 1 + 3 = 24 bytes in every engine
            // (baseq3a/ioq3/Quake3e). The engine's trap_GetUserCmd does a
            // Com_Memcpy of exactly sizeof(usercmd_t), NOT a 64-byte zero.
            //
            // DANGER (fixed 2026-08-07): this handler previously zeroed 64
            // bytes. orig cgame's fn_13220 (Connection Interrupted overlay)
            // calls trap_GetUserCmd with &loc_28 at frame+28 of an ENTER-88
            // frame, i.e. dst = caller_base - 60. A 64-byte write reaches past
            // the 24-byte buffer and clobbers the return-address slot at
            // caller_base -> LEAVE 88 pops 0 -> vmMain infinite "unknown
            // command" loop. Write only sizeof(usercmd_t) bytes.
            //
            // Then, when usercmd_run is on, fill a "run" cmd:
            // yaw=16000 (~88deg), forwardmove=127, buttons=BUTTON_ATTACK.
            // serverTime advances per GetUsercmd invocation so repeated
            // CLIENT_THINK ticks are not discarded by the pmove guard (msec =
            // serverTime - commandTime must be > 0 for Pmove to run).
            const USERCMD_SIZE: usize = 24;
            zero(mem, dst, USERCMD_SIZE);
            if !usercmd_run {
                return;
            }
            let d = dst as u32 & mem.data_mask;
            if (d as usize) + USERCMD_SIZE <= mem.data.len() {
                let serial = usercmd_serial_h.get() + 1;
                usercmd_serial_h.set(serial);
                let _ = cmdnum; // retained in the ABI-shaped closure signature
                mem.store4(dst, serial * usercmd_msec); // serverTime
                mem.store4(dst + 4, 0); // pitch
                mem.store4(dst + 8, 16000); // yaw (short units)
                mem.store4(dst + 12, 0); // roll
                mem.store4(dst + 16, 1); // buttons = BUTTON_ATTACK
                mem.data[d as usize + 20] = 2; // weapon = WP_MACHINEGUN
                mem.data[d as usize + 21] = 127; // forwardmove
                mem.data[d as usize + 22] = 0; // rightmove
                mem.data[d as usize + 23] = 0; // upmove
            }
        };
        match (m, num as u32) {
            // ---- memory/math helpers: SAME numbering in every module ----
            (_, 100) => {
                // memset(dst, c, len)
                let dst = a[1] as u32 & mem.data_mask;
                let c = a[2] as u8;
                let len = a[3].clamp(0, 1 << 20) as usize;
                for i in 0..len {
                    mem.data[dst as usize + i] = c;
                }
            }
            (_, 101) => {
                // memcpy(dst, src, len)
                let dst = a[1] as u32 & mem.data_mask;
                let src = a[2] as u32 & mem.data_mask;
                let len = a[3].clamp(0, 1 << 20) as usize;
                for i in 0..len {
                    mem.data[dst as usize + i] = mem.data[src as usize + i];
                }
            }
            (_, 102) => {
                // strncpy(dst, src, len): copy up to (and including) the NUL;
                // callers (Q_strncpyz) write the terminator themselves.
                let dst = a[1] as u32 & mem.data_mask;
                let src = a[2] as u32 & mem.data_mask;
                let len = a[3].clamp(0, 1 << 20) as usize;
                for i in 0..len {
                    let b = mem.data[src as usize + i];
                    mem.data[dst as usize + i] = b;
                    if b == 0 {
                        break;
                    }
                }
            }
            // ---- game module (qagame/qgame) ----
            (Module::Game, 3) => cvar_register(mem, a),
            (Module::Game, 10) => store4(mem, a[2], -1), // FS_FOpenFile(qpath, *f, mode): fh = -1
            (Module::Game, 7) => store1(mem, a[2], 0), // Cvar_VariableStringBuffer(name, buf, size)
            (Module::Game, 22) => store1(mem, a[1], 0), // GetServerinfo(buf, size)
            (Module::Game, 37) => {
                // GetEntityToken(buf, size): feed the harness map entity
                // string with engine COM_Parse semantics. Previously this
                // returned an empty token, so G_SpawnEntitiesFromString never
                // parsed any entity and both sides error-path'd through
                // "SpawnEntities: no entities" — the real spawn path never
                // executed. Return 1 on token, 0 at EOF (engine qfalse).
                let dst = a[1] as u32 & mem.data_mask;
                let size = (a[2] as usize).clamp(1, 1024);
                let produced = {
                    let mut t = toks.borrow_mut();
                    t.next_into(&mut mem.data, dst as usize, size)
                };
                tok_ret = Some(if produced { 1 } else { 0 });
            }
            (Module::Game, 19) => store1(mem, a[2], 0), // GetConfigstring(index, buf, size)
            (Module::Game, 20) => {
                // GetUserinfo(clientNum, buf, size): a fixed deterministic
                // player userinfo so G_ParseClientInfo takes the same path on
                // both sides (an unmodeled call would leave the frame buffer
                // as divergent garbage).
                const UI: &[u8] = b"name\\TestPlayer\\team\\0\\model\\sarge\\headmodel\\sarge\\color1\\4\\color2\\5\\handicap\\100\\sex\\male\\rate\\25000\\snaps\\20\\fov\\90\\\0";
                let dst = a[2] as u32 & mem.data_mask;
                let size = (a[3] as usize).min(UI.len());
                for i in 0..size {
                    mem.data[dst as usize + i] = UI[i];
                }
            }
            (Module::Game, 9) => argv0(mem, a), // Argv(arg, buf, size): empty unless QVM_ARGV0
            (Module::Game, 36) => usercmd(mem, a[2], a[1]), // GetUsercmd(cmdNum, *cmd)
            (Module::CGame, 55) => usercmd(mem, a[2], a[1]), // GetUserCmd(cmdNum, *cmd)
            (Module::Game, 41) => zero(mem, a[1], 32), // RealTime(qtime_t*)
            (Module::Game, 24 | 43) => trace(mem, a), // Trace / TraceCapsule
            // ---- cgame module (cgame.qvm) ----
            // cgame numbering (traps.rs cgame_trap): trap 3 = Cvar_Register and
            // trap 10 = FS_FOpenFile match game; everything else differs.
            (Module::CGame, 3) => cvar_register(mem, a),
            (Module::CGame, 10) => store4(mem, a[2], -1), // FS_FOpenFile
            (Module::CGame, 6) => store1(mem, a[2], 0), // Cvar_VariableStringBuffer(name, buf, size)
            (Module::CGame, 8) => argv0(mem, a),        // Argv(arg, buf, size)
            (Module::CGame, 25 | 26 | 83 | 84) => trace(mem, a), // CM_*(Capsule)BoxTrace(results, ...)
            (Module::CGame, 49) => zero(mem, a[1], 256),         // GetGlconfig(&glconfig)
            (Module::CGame, 50) => zero(mem, a[1], 24576),       // GetGameState(&gs)
            (Module::CGame, 51) => {
                // GetCurrentSnapshotNumber(*snapshotNumber, *serverTime)
                match &snaps {
                    Some(st) => {
                        let s = st.borrow();
                        store4(mem, a[1], s.snap_num);
                        store4(mem, a[2], s.snap_time);
                    }
                    None => {
                        store4(mem, a[1], 0);
                        store4(mem, a[2], 0);
                    }
                }
            }
            (Module::CGame, 52) => {
                // GetSnapshot(*snap): serve an evolving snapshot under the
                // snapshot harness (write_snapshot), else zero (default).
                match &snaps {
                    Some(st) => {
                        let s = st.borrow();
                        write_snapshot(mem, a[2], s.snap_time, s.snap_num);
                    }
                    None => zero(mem, a[2], 8192),
                }
            }
            (Module::CGame, 53) => store1(mem, a[2], 0), // GetServerCommand(cmdNum, buf, size): empty
            (Module::CGame, 70) => zero(mem, a[1], 32),  // RealTime(qtime_t*)
            (Module::CGame, 86) => store1(mem, a[1], 0), // GetEntityToken(buf, size)
            // ---- ui module (ui.qvm) ----
            // ui numbering (traps.rs ui_trap): Cvar_Register is 50, Cvar_Set 3.
            (Module::Ui, 50) => cvar_register(mem, a),
            (Module::Ui, 5) => store1(mem, a[2], 0), // Cvar_VariableStringBuffer(name, buf, size)
            (Module::Ui, 11) => argv0(mem, a),       // Argv(arg, buf, size)
            (Module::Ui, 13) => store4(mem, a[2], -1), // FS_FOpenFile
            (Module::Ui, 43) => zero(mem, a[1], 256), // GetGlconfig(&glconfig)
            (Module::Ui, 44) => zero(mem, a[1], 1024), // GetClientState(&cl)
            (Module::Ui, 45) => store1(mem, a[2], 0), // GetConfigString(index, buf, size)
            (Module::Ui, 64) => zero(mem, a[1], 32), // RealTime(qtime_t*)
            _ => {}
        }
        if std::env::var("QVM_DUMP_SQRT").is_ok() && num == 106 {
            let rd4 = |mm: &Memory, a: i32| -> i32 {
                let x = (a as u32 & mm.data_mask) as usize;
                i32::from_le_bytes([mm.data[x], mm.data[x + 1], mm.data[x + 2], mm.data[x + 3]])
            };
            let pm = rd4(mem, 0x107590);
            let ps = rd4(mem, pm);
            let vel0 = rd4(mem, ps + 32);
            let vel1 = rd4(mem, ps + 36);
            println!(
                "DUMP_SQRT trap106 arg={} ({:#010x}) pm=0x{:x} ps=0x{:x} vel0={} ({:#010x}) vel1={} ({:#010x})",
                a[1] as f32, a[1] as u32, pm as u32, ps as u32, vel0 as f32, vel0 as u32,
                vel1 as f32, vel1 as u32
            );
        }
        let tname = trap_name(m, num as u32).unwrap_or("?").to_string();
        let nargs = arity_of(m, num as u32).unwrap_or(8);
        let mut args = Vec::new();
        for (i, v) in a.iter().enumerate().take(nargs + 1) {
            if i > 0 {
                if let Some(s) = q_string(mem, *v) {
                    args.push(format!("{s:?}"));
                    continue;
                }
                if *v >= 0 && (*v as u32) < thresh {
                    let u = *v as u32;
                    args.push(format!("{}", if u >= base { u - base } else { u }));
                    continue;
                }
                args.push("_".to_string());
            } else {
                args.push(format!("{v}"));
            }
        }
        logs.borrow_mut().push(TrapLog {
            num: num as u32,
            name: tname,
            args,
            raw: a[..nargs + 1].to_vec(),
        });
        match num as u32 {
            10 => -1,                   // FS_FOpenFile: file not found (no game files in the sandbox)
            37 => tok_ret.unwrap_or(0), // GetEntityToken: token / EOF (set above)
            52 if snaps.is_some() => 1, // snapshot served successfully
            // Opt-in UI models for Game Options / crosshair ownerdraw coverage
            // (QVM_UI_CROSSHAIR_MODEL=1): otherwise keep the historical zero-return.
            4 if m == Module::Ui
                && std::env::var("QVM_UI_CROSSHAIR_MODEL").as_deref() == Ok("1") =>
            {
                if q_string(mem, a[1]).as_deref() == Some("cg_drawCrosshair") {
                    4.0f32.to_bits() as i32
                } else {
                    0
                }
            }
            // Menus only draw when KEYCATCH_UI (2) is set. PushMenu calls
            // SetCatcher, but the harness doesn't track it — force UI catcher
            // so UI_REFRESH reaches Menu_Draw (needed for crosshair ownerdraw
            // and any full refresh comparison).
            40 if m == Module::Ui => 2,
            20 if m == Module::Ui
                && std::env::var("QVM_UI_CROSSHAIR_MODEL").as_deref() == Ok("1") =>
            {
                let p = a[1] as u32;
                if p == 0 {
                    0
                } else {
                    (p % 1000) as i32 + 1
                }
            }
            // Keep the historical zero-return model by default: complete
            // game-session probes deliberately use simplified trace/world
            // behavior. PM probes enable this only around known math calls.
            103 if std::env::var("QVM_MODEL_MATH").as_deref() == Ok("1") => {
                f32::from_bits(a[1] as u32).sin().to_bits() as i32
            }
            104 if std::env::var("QVM_MODEL_MATH").as_deref() == Ok("1") => {
                f32::from_bits(a[1] as u32).cos().to_bits() as i32
            }
            106 if std::env::var("QVM_MODEL_MATH").as_deref() == Ok("1") => {
                f32::from_bits(a[1] as u32).sqrt().to_bits() as i32
            }
            _ => 0,
        }
    });
    (syscall, entity_tokens)
}

/// Zero the top-of-image stack region (~64K) so both sides of a persistent-VM
/// diff start each command with a clean frame area. In the real engine the bss
/// (which holds the stack) is zeroed at VM load; leftover frame garbage from
/// previous commands otherwise differs between modules because of different
/// frame layouts, producing spurious diff artifacts (e.g. the uninitialized
/// stack pmove buffer read by GAME_CLIENT_BEGIN -> PM_CmdScale).
pub fn zero_stack(mem: &mut crate::Memory) {
    let hi = (mem.data_mask + 1).min(mem.data.len() as u32);
    let lo = mem.data_mask + 1 - 65536;
    let lo = lo.min(hi);
    for b in &mut mem.data[lo as usize..hi as usize] {
        *b = 0;
    }
}

/// Run one call on a fresh interpreter and return its trap log, result and
/// interpreter statistics.
pub fn run_once(
    insns: &[crate::Insn],
    qvm: &crate::Qvm,
    entry: usize,
    call_args: &[i32],
    max_steps: usize,
) -> (Vec<TrapLog>, i32, usize, usize) {
    let logs: Rc<RefCell<Vec<TrapLog>>> = Rc::new(RefCell::new(Vec::new()));
    let mut emu =
        crate::Emu::new(insns, qvm).with_syscall(make_handler(qvm.module, 0, logs.clone()));
    emu.set_max_steps(max_steps);
    let result = emu.call(entry, call_args).unwrap_or(i32::MIN);
    let stats = emu.stats;
    (logs.take(), result, stats.steps, stats.syscalls)
}
