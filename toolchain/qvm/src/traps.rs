//! VM syscall (trap) name tables, per VM module.
//!
//! Source: ioq3 / baseq3a `code/{game, cgame, ui}/*_syscalls.asm` — `equ trap_X -N`
//! means the compiler emits `CONST -N; CALL`, which the interpreter maps to
//! syscall index `-1 - (-N) = N-1`. Each module (game, cgame, ui) has its own
//! numbering, fixed by the engine's dispatch, so it is stable across mods of
//! the same Q3 generation.

/// Which VM module a .qvm belongs to. Each module dispatches a different
/// syscall table, so trap names must be looked up per module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    Game,
    CGame,
    Ui,
}

impl Module {
    /// Guess the module from the file name: `cgame*.qvm` -> CGame,
    /// `ui*.qvm` -> Ui, anything else (qagame/qgame/...) -> Game.
    pub fn detect(path: &str) -> Module {
        let stem = std::path::Path::new(path)
            .file_stem()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if stem.starts_with("cgame") {
            Module::CGame
        } else if stem.starts_with("ui") {
            Module::Ui
        } else {
            Module::Game
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Module::Game => "game",
            Module::CGame => "cgame",
            Module::Ui => "ui",
        }
    }
}

/// Name of the syscall with the given index for `m`, if known.
pub fn trap_name(m: Module, n: u32) -> Option<&'static str> {
    Some(match m {
        Module::Game => game_trap(n)?,
        Module::CGame => cgame_trap(n)?,
        Module::Ui => ui_trap(n)?,
    })
}

// ---- game module (qagame/qgame) ----

fn game_trap(n: u32) -> Option<&'static str> {
    Some(match n {
        // game traps (0-45)
        0 => "trap_Print",
        1 => "trap_Error",
        2 => "trap_Milliseconds",
        3 => "trap_Cvar_Register",
        4 => "trap_Cvar_Update",
        5 => "trap_Cvar_Set",
        6 => "trap_Cvar_VariableIntegerValue",
        7 => "trap_Cvar_VariableStringBuffer",
        8 => "trap_Argc",
        9 => "trap_Argv",
        10 => "trap_FS_FOpenFile",
        11 => "trap_FS_Read",
        12 => "trap_FS_Write",
        13 => "trap_FS_FCloseFile",
        14 => "trap_SendConsoleCommand",
        15 => "trap_LocateGameData",
        16 => "trap_DropClient",
        17 => "trap_SendServerCommand",
        18 => "trap_SetConfigstring",
        19 => "trap_GetConfigstring",
        20 => "trap_GetUserinfo",
        21 => "trap_SetUserinfo",
        22 => "trap_GetServerinfo",
        23 => "trap_SetBrushModel",
        24 => "trap_Trace",
        25 => "trap_PointContents",
        26 => "trap_InPVS",
        27 => "trap_InPVSIgnorePortals",
        28 => "trap_AdjustAreaPortalState",
        29 => "trap_AreasConnected",
        30 => "trap_LinkEntity",
        31 => "trap_UnlinkEntity",
        32 => "trap_EntitiesInBox",
        33 => "trap_EntityContact",
        34 => "trap_BotAllocateClient",
        35 => "trap_BotFreeClient",
        36 => "trap_GetUsercmd",
        37 => "trap_GetEntityToken",
        38 => "trap_FS_GetFileList",
        39 => "trap_DebugPolygonCreate",
        40 => "trap_DebugPolygonDelete",
        41 => "trap_RealTime",
        42 => "trap_SnapVector",
        43 => "trap_TraceCapsule",
        44 => "trap_EntityContactCapsule",
        45 => "trap_FS_Seek",
        // memory / math helpers (100-113)
        100 => "memset",
        101 => "memcpy",
        102 => "strncpy",
        103 => "sin",
        104 => "cos",
        105 => "atan2",
        106 => "sqrt",
        110 => "floor",
        111 => "ceil",
        112 => "testPrintInt",
        113 => "testPrintFloat",
        // botlib (200-211)
        200 => "trap_BotLibSetup",
        201 => "trap_BotLibShutdown",
        202 => "trap_BotLibVarSet",
        203 => "trap_BotLibVarGet",
        204 => "trap_BotLibDefine",
        205 => "trap_BotLibStartFrame",
        206 => "trap_BotLibLoadMap",
        207 => "trap_BotLibUpdateEntity",
        208 => "trap_BotLibTest",
        209 => "trap_BotGetSnapshotEntity",
        210 => "trap_BotGetServerCommand",
        211 => "trap_BotUserCommand",
        // AAS (300-318)
        300 => "trap_AAS_EnableRoutingArea",
        301 => "trap_AAS_BBoxAreas",
        302 => "trap_AAS_AreaInfo",
        303 => "trap_AAS_EntityInfo",
        304 => "trap_AAS_Initialized",
        305 => "trap_AAS_PresenceTypeBoundingBox",
        306 => "trap_AAS_Time",
        307 => "trap_AAS_PointAreaNum",
        308 => "trap_AAS_TraceAreas",
        309 => "trap_AAS_PointContents",
        310 => "trap_AAS_NextBSPEntity",
        311 => "trap_AAS_ValueForBSPEpairKey",
        312 => "trap_AAS_VectorForBSPEpairKey",
        313 => "trap_AAS_FloatForBSPEpairKey",
        314 => "trap_AAS_IntForBSPEpairKey",
        315 => "trap_AAS_AreaReachability",
        316 => "trap_AAS_AreaTravelTimeToGoalArea",
        317 => "trap_AAS_Swimming",
        318 => "trap_AAS_PredictClientMovement",
        // EA bot commands (400-423)
        400 => "trap_EA_Say",
        401 => "trap_EA_SayTeam",
        402 => "trap_EA_Command",
        403 => "trap_EA_Action",
        404 => "trap_EA_Gesture",
        405 => "trap_EA_Talk",
        406 => "trap_EA_Attack",
        407 => "trap_EA_Use",
        408 => "trap_EA_Respawn",
        409 => "trap_EA_Crouch",
        410 => "trap_EA_MoveUp",
        411 => "trap_EA_MoveDown",
        412 => "trap_EA_MoveForward",
        413 => "trap_EA_MoveBack",
        414 => "trap_EA_MoveLeft",
        415 => "trap_EA_MoveRight",
        416 => "trap_EA_SelectWeapon",
        417 => "trap_EA_Jump",
        418 => "trap_EA_DelayedJump",
        419 => "trap_EA_Move",
        420 => "trap_EA_View",
        421 => "trap_EA_EndRegular",
        422 => "trap_EA_GetInput",
        423 => "trap_EA_ResetInput",
        // bot AI (500-581)
        500 => "trap_BotLoadCharacter",
        501 => "trap_BotFreeCharacter",
        502 => "trap_Characteristic_Float",
        503 => "trap_Characteristic_BFloat",
        504 => "trap_Characteristic_Integer",
        505 => "trap_Characteristic_BInteger",
        506 => "trap_Characteristic_String",
        507 => "trap_BotAllocChatState",
        508 => "trap_BotFreeChatState",
        509 => "trap_BotQueueConsoleMessage",
        510 => "trap_BotRemoveConsoleMessage",
        511 => "trap_BotNextConsoleMessage",
        512 => "trap_BotNumConsoleMessages",
        513 => "trap_BotInitialChat",
        514 => "trap_BotReplyChat",
        515 => "trap_BotChatLength",
        516 => "trap_BotEnterChat",
        517 => "trap_StringContains",
        518 => "trap_BotFindMatch",
        519 => "trap_BotMatchVariable",
        520 => "trap_UnifyWhiteSpaces",
        521 => "trap_BotReplaceSynonyms",
        522 => "trap_BotLoadChatFile",
        523 => "trap_BotSetChatGender",
        524 => "trap_BotSetChatName",
        525 => "trap_BotResetGoalState",
        526 => "trap_BotResetAvoidGoals",
        527 => "trap_BotPushGoal",
        528 => "trap_BotPopGoal",
        529 => "trap_BotEmptyGoalStack",
        530 => "trap_BotDumpAvoidGoals",
        531 => "trap_BotDumpGoalStack",
        532 => "trap_BotGoalName",
        533 => "trap_BotGetTopGoal",
        534 => "trap_BotGetSecondGoal",
        535 => "trap_BotChooseLTGItem",
        536 => "trap_BotChooseNBGItem",
        537 => "trap_BotTouchingGoal",
        538 => "trap_BotItemGoalInVisButNotVisible",
        539 => "trap_BotGetLevelItemGoal",
        540 => "trap_BotAvoidGoalTime",
        541 => "trap_BotInitLevelItems",
        542 => "trap_BotUpdateEntityItems",
        543 => "trap_BotLoadItemWeights",
        544 => "trap_BotFreeItemWeights",
        545 => "trap_BotSaveGoalFuzzyLogic",
        546 => "trap_BotAllocGoalState",
        547 => "trap_BotFreeGoalState",
        548 => "trap_BotResetMoveState",
        549 => "trap_BotMoveToGoal",
        550 => "trap_BotMoveInDirection",
        551 => "trap_BotResetAvoidReach",
        552 => "trap_BotResetLastAvoidReach",
        553 => "trap_BotReachabilityArea",
        554 => "trap_BotMovementViewTarget",
        555 => "trap_BotAllocMoveState",
        556 => "trap_BotFreeMoveState",
        557 => "trap_BotInitMoveState",
        558 => "trap_BotChooseBestFightWeapon",
        559 => "trap_BotGetWeaponInfo",
        560 => "trap_BotLoadWeaponWeights",
        561 => "trap_BotAllocWeaponState",
        562 => "trap_BotFreeWeaponState",
        563 => "trap_BotResetWeaponState",
        564 => "trap_GeneticParentsAndChildSelection",
        565 => "trap_BotInterbreedGoalFuzzyLogic",
        566 => "trap_BotMutateGoalFuzzyLogic",
        567 => "trap_BotGetNextCampSpotGoal",
        568 => "trap_BotGetMapLocationGoal",
        569 => "trap_BotNumInitialChats",
        570 => "trap_BotGetChatMessage",
        571 => "trap_BotRemoveFromAvoidGoals",
        572 => "trap_BotPredictVisiblePosition",
        573 => "trap_BotSetAvoidGoalTime",
        574 => "trap_BotAddAvoidSpot",
        575 => "trap_AAS_AlternativeRouteGoals",
        576 => "trap_AAS_PredictRoute",
        577 => "trap_AAS_PointReachabilityAreaIndex",
        578 => "trap_BotLibLoadSource",
        579 => "trap_BotLibFreeSource",
        580 => "trap_BotLibReadToken",
        581 => "trap_BotLibSourceFileAndLine",
        _ => return None,
    })
}

// ---- cgame module (cgame.qvm) ----

fn cgame_trap(n: u32) -> Option<&'static str> {
    Some(match n {
        // cgame traps (0-90)
        0 => "trap_Print",
        1 => "trap_Error",
        2 => "trap_Milliseconds",
        3 => "trap_Cvar_Register",
        4 => "trap_Cvar_Update",
        5 => "trap_Cvar_Set",
        6 => "trap_Cvar_VariableStringBuffer",
        7 => "trap_Argc",
        8 => "trap_Argv",
        9 => "trap_Args",
        10 => "trap_FS_FOpenFile",
        11 => "trap_FS_Read",
        12 => "trap_FS_Write",
        13 => "trap_FS_FCloseFile",
        14 => "trap_SendConsoleCommand",
        15 => "trap_AddCommand",
        16 => "trap_SendClientCommand",
        17 => "trap_UpdateScreen",
        18 => "trap_CM_LoadMap",
        19 => "trap_CM_NumInlineModels",
        20 => "trap_CM_InlineModel",
        21 => "trap_CM_LoadModel",
        22 => "trap_CM_TempBoxModel",
        23 => "trap_CM_PointContents",
        24 => "trap_CM_TransformedPointContents",
        25 => "trap_CM_BoxTrace",
        26 => "trap_CM_TransformedBoxTrace",
        27 => "trap_CM_MarkFragments",
        28 => "trap_S_StartSound",
        29 => "trap_S_StartLocalSound",
        30 => "trap_S_ClearLoopingSounds",
        31 => "trap_S_AddLoopingSound",
        32 => "trap_S_UpdateEntityPosition",
        33 => "trap_S_Respatialize",
        34 => "trap_S_RegisterSound",
        35 => "trap_S_StartBackgroundTrack",
        36 => "trap_R_LoadWorldMap",
        37 => "trap_R_RegisterModel",
        38 => "trap_R_RegisterSkin",
        39 => "trap_R_RegisterShader",
        40 => "trap_R_ClearScene",
        41 => "trap_R_AddRefEntityToScene",
        42 => "trap_R_AddPolyToScene",
        43 => "trap_R_AddLightToScene",
        44 => "trap_R_RenderScene",
        45 => "trap_R_SetColor",
        46 => "trap_R_DrawStretchPic",
        47 => "trap_R_ModelBounds",
        48 => "trap_R_LerpTag",
        49 => "trap_GetGlconfig",
        50 => "trap_GetGameState",
        51 => "trap_GetCurrentSnapshotNumber",
        52 => "trap_GetSnapshot",
        53 => "trap_GetServerCommand",
        54 => "trap_GetCurrentCmdNumber",
        55 => "trap_GetUserCmd",
        56 => "trap_SetUserCmdValue",
        57 => "trap_R_RegisterShaderNoMip",
        58 => "trap_MemoryRemaining",
        59 => "trap_R_RegisterFont",
        60 => "trap_Key_IsDown",
        61 => "trap_Key_GetCatcher",
        62 => "trap_Key_SetCatcher",
        63 => "trap_Key_GetKey",
        64 => "trap_PC_AddGlobalDefine",
        65 => "trap_PC_LoadSource",
        66 => "trap_PC_FreeSource",
        67 => "trap_PC_ReadToken",
        68 => "trap_PC_SourceFileAndLine",
        69 => "trap_S_StopBackgroundTrack",
        70 => "trap_RealTime",
        71 => "trap_SnapVector",
        72 => "trap_RemoveCommand",
        73 => "trap_R_LightForPoint",
        74 => "trap_CIN_PlayCinematic",
        75 => "trap_CIN_StopCinematic",
        76 => "trap_CIN_RunCinematic",
        77 => "trap_CIN_DrawCinematic",
        78 => "trap_CIN_SetExtents",
        79 => "trap_R_RemapShader",
        80 => "trap_S_AddRealLoopingSound",
        81 => "trap_S_StopLoopingSound",
        82 => "trap_CM_TempCapsuleModel",
        83 => "trap_CM_CapsuleTrace",
        84 => "trap_CM_TransformedCapsuleTrace",
        85 => "trap_R_AddAdditiveLightToScene",
        86 => "trap_GetEntityToken",
        87 => "trap_R_AddPolysToScene",
        88 => "trap_R_inPVS",
        89 => "trap_FS_Seek",
        // memory / math helpers (100-111)
        100 => "memset",
        101 => "memcpy",
        102 => "strncpy",
        103 => "sin",
        104 => "cos",
        105 => "atan2",
        106 => "sqrt",
        107 => "floor",
        108 => "ceil",
        109 => "testPrintInt",
        110 => "testPrintFloat",
        111 => "acos",
        _ => return None,
    })
}

// ---- ui module (ui.qvm) ----

fn ui_trap(n: u32) -> Option<&'static str> {
    Some(match n {
        // ui traps (0-88)
        0 => "trap_Error",
        1 => "trap_Print",
        2 => "trap_Milliseconds",
        3 => "trap_Cvar_Set",
        4 => "trap_Cvar_VariableValue",
        5 => "trap_Cvar_VariableStringBuffer",
        6 => "trap_Cvar_SetValue",
        7 => "trap_Cvar_Reset",
        8 => "trap_Cvar_Create",
        9 => "trap_Cvar_InfoStringBuffer",
        10 => "trap_Argc",
        11 => "trap_Argv",
        12 => "trap_Cmd_ExecuteText",
        13 => "trap_FS_FOpenFile",
        14 => "trap_FS_Read",
        15 => "trap_FS_Write",
        16 => "trap_FS_FCloseFile",
        17 => "trap_FS_GetFileList",
        18 => "trap_R_RegisterModel",
        19 => "trap_R_RegisterSkin",
        20 => "trap_R_RegisterShaderNoMip",
        21 => "trap_R_ClearScene",
        22 => "trap_R_AddRefEntityToScene",
        23 => "trap_R_AddPolyToScene",
        24 => "trap_R_AddLightToScene",
        25 => "trap_R_RenderScene",
        26 => "trap_R_SetColor",
        27 => "trap_R_DrawStretchPic",
        28 => "trap_UpdateScreen",
        29 => "trap_CM_LerpTag",
        30 => "trap_CM_LoadModel",
        31 => "trap_S_RegisterSound",
        32 => "trap_S_StartLocalSound",
        33 => "trap_Key_KeynumToStringBuf",
        34 => "trap_Key_GetBindingBuf",
        35 => "trap_Key_SetBinding",
        36 => "trap_Key_IsDown",
        37 => "trap_Key_GetOverstrikeMode",
        38 => "trap_Key_SetOverstrikeMode",
        39 => "trap_Key_ClearStates",
        40 => "trap_Key_GetCatcher",
        41 => "trap_Key_SetCatcher",
        42 => "trap_GetClipboardData",
        43 => "trap_GetGlconfig",
        44 => "trap_GetClientState",
        45 => "trap_GetConfigString",
        46 => "trap_LAN_GetPingQueueCount",
        47 => "trap_LAN_ClearPing",
        48 => "trap_LAN_GetPing",
        49 => "trap_LAN_GetPingInfo",
        50 => "trap_Cvar_Register",
        51 => "trap_Cvar_Update",
        52 => "trap_MemoryRemaining",
        53 => "trap_GetCDKey",
        54 => "trap_SetCDKey",
        55 => "trap_R_RegisterFont",
        56 => "trap_R_ModelBounds",
        57 => "trap_PC_AddGlobalDefine",
        58 => "trap_PC_LoadSource",
        59 => "trap_PC_FreeSource",
        60 => "trap_PC_ReadToken",
        61 => "trap_PC_SourceFileAndLine",
        62 => "trap_S_StopBackgroundTrack",
        63 => "trap_S_StartBackgroundTrack",
        64 => "trap_RealTime",
        65 => "trap_LAN_GetServerCount",
        66 => "trap_LAN_GetServerAddressString",
        67 => "trap_LAN_GetServerInfo",
        68 => "trap_LAN_MarkServerVisible",
        69 => "trap_LAN_UpdateVisiblePings",
        70 => "trap_LAN_ResetPings",
        71 => "trap_LAN_LoadCachedServers",
        72 => "trap_LAN_SaveCachedServers",
        73 => "trap_LAN_AddServer",
        74 => "trap_LAN_RemoveServer",
        75 => "trap_CIN_PlayCinematic",
        76 => "trap_CIN_StopCinematic",
        77 => "trap_CIN_RunCinematic",
        78 => "trap_CIN_DrawCinematic",
        79 => "trap_CIN_SetExtents",
        80 => "trap_R_RemapShader",
        81 => "trap_VerifyCDKey",
        82 => "trap_LAN_ServerStatus",
        83 => "trap_LAN_GetServerPing",
        84 => "trap_LAN_ServerIsVisible",
        85 => "trap_LAN_CompareServers",
        86 => "trap_FS_Seek",
        87 => "trap_SetPbClStatus",
        // memory / math helpers (100-108)
        100 => "memset",
        101 => "memcpy",
        102 => "strncpy",
        103 => "sin",
        104 => "cos",
        105 => "atan2",
        106 => "sqrt",
        107 => "floor",
        108 => "ceil",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_module() {
        assert_eq!(Module::detect(r"C:\tmp\sample\vm\qagame.qvm"), Module::Game);
        assert_eq!(Module::detect("qgame.qvm"), Module::Game);
        assert_eq!(Module::detect(r"C:\tmp\sample\vm\cgame.qvm"), Module::CGame);
        assert_eq!(Module::detect(r"C:\tmp\sample\vm\ui.qvm"), Module::Ui);
    }

    #[test]
    fn game_known_traps() {
        assert_eq!(trap_name(Module::Game, 0), Some("trap_Print"));
        assert_eq!(trap_name(Module::Game, 17), Some("trap_SendServerCommand"));
        assert_eq!(trap_name(Module::Game, 101), Some("memcpy"));
        assert_eq!(trap_name(Module::Game, 106), Some("sqrt"));
        assert_eq!(trap_name(Module::Game, 576), Some("trap_AAS_PredictRoute"));
    }

    #[test]
    fn game_unknown_is_none() {
        assert_eq!(trap_name(Module::Game, 999), None);
        assert_eq!(trap_name(Module::Game, 46), None);
    }

    #[test]
    fn cgame_traps() {
        // trap_R_RegisterShaderNoMip is -58 in cgame -> index 57
        assert_eq!(trap_name(Module::CGame, 57), Some("trap_R_RegisterShaderNoMip"));
        assert_eq!(trap_name(Module::CGame, 0), Some("trap_Print"));
        assert_eq!(trap_name(Module::CGame, 16), Some("trap_SendClientCommand"));
        // game-only names must NOT leak into cgame (different numbering)
        assert_ne!(trap_name(Module::CGame, 17), Some("trap_SendServerCommand"));
        assert_eq!(trap_name(Module::CGame, 111), Some("acos"));
    }

    #[test]
    fn ui_traps() {
        assert_eq!(trap_name(Module::Ui, 0), Some("trap_Error"));
        assert_eq!(trap_name(Module::Ui, 1), Some("trap_Print"));
        assert_eq!(trap_name(Module::Ui, 20), Some("trap_R_RegisterShaderNoMip"));
        assert_eq!(trap_name(Module::Ui, 12), Some("trap_Cmd_ExecuteText"));
        assert_eq!(trap_name(Module::Ui, 57), Some("trap_PC_AddGlobalDefine"));
    }
}
