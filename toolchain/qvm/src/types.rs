//! Optional per-mod data-space overlay ("types") for typed emit.
//!
//! Generic emit does **not** use this module: `probe_emit` runs untyped unless
//! you pass `--typed`, which turns whatever key is filled in below onto the
//! emitted C (macros, struct views, comments over `qvm_mem+(vmoff-4)`).
//!
//! **The shipped file is an empty template.** It contains no addresses. A
//! data-space key is something you recover for ONE specific module; enabling
//! someone else's key (or a half-guessed one) produces plausible-looking but
//! wrong C. Fill it only from evidence you can cite, then verify the round-trip
//! (`probe_seqdiff` 0 vs the original module) before trusting any output.
//!
//! ## How to recover a key (guideline)
//!
//! 1. Bases: find array roots in the data/BSS blob — repeated
//!    `base + i*stride + field` patterns (`probe_findconst`, `probe_findstore`,
//!    `tools/scripts/twostep.py`). Cross-check against stock id Tech 3 headers
//!    where the mod reuses them.
//! 2. Strides: from the index multiplier in that same address arithmetic.
//!    A stride is proven by several independent sites, not one loop.
//! 3. Scalars: named single cells get a macro name; only name a cell when
//!    bytecode + strings prove its role (see AGENT.md hard rules).
//! 4. Fill in the tables below (regions, scalars, per-kind field maps,
//!    function-local slots). Everything stays macros/comments over
//!    `qvm_mem`; real C globals would shift BSS and break trap pointers.
//! 5. Rebuild and compare: `probe_check`, then `probe_seqdiff` /
//!    `probe_cgamediff` / `probe_uidiff`. Any nonzero diff means the overlay
//!    lied about something — fix the overlay, never the emitter, to match.
//!
//! VM addresses are the original absolute CONST values. Emit still stores
//! bytes in `qvm_mem`; names are macros / comments over `qvm_mem+(vmoff-4)`
//! ([`image_off`]).

/// Byte address of the first word of the `level`-like global block.
/// FILL IN per module (0 = unfilled).
pub const LEVEL_BASE: usize = 0;
pub const LEVEL_SIZE: usize = 0;
pub const GENTITIES_BASE: usize = 0;
pub const GENTITY_SIZE: usize = 0;
pub const GENTITIES_COUNT: usize = 0;
pub const GENTITIES_END: usize = GENTITIES_BASE + GENTITY_SIZE * GENTITIES_COUNT;
pub const GCLIENTS_BASE: usize = 0;
pub const GCLIENT_SIZE: usize = 0;
pub const GCLIENTS_COUNT: usize = 0;
pub const GCLIENTS_END: usize = GCLIENTS_BASE + GCLIENT_SIZE * GCLIENTS_COUNT;

/// Image offset of a VM address (CONST n → `qvm_mem + n - 4`).
pub fn image_off(vmoff: usize) -> Option<usize> {
    vmoff.checked_sub(4)
}

/// Named scalar cells of the global block: `(offset_from_LEVEL_BASE, macro)`.
/// FILL IN per module. Example row: `(0x20, "level_time")`.
const SCALAR_TABLE: &[(usize, &str)] = &[];

fn level_scalar(off: usize) -> Option<&'static str> {
    SCALAR_TABLE.iter().find(|(o, _)| *o == off).map(|(_, n)| *n)
}

/// `#define` name for an exact scalar BSS cell, if we have one.
pub fn scalar_macro(vmoff: usize) -> Option<&'static str> {
    if vmoff < LEVEL_BASE || vmoff >= LEVEL_BASE + LEVEL_SIZE {
        return None;
    }
    level_scalar(vmoff - LEVEL_BASE)
}

/// Human comment for any classified VM address (arrays included).
pub fn comment(vmoff: usize) -> Option<String> {
    if let Some(name) = scalar_macro(vmoff) {
        return Some(name.replacen('_', ".", 1));
    }
    array_comment(vmoff, GENTITIES_BASE, GENTITY_SIZE, "g_entities", ent_field)
        .or_else(|| array_comment(vmoff, GCLIENTS_BASE, GCLIENT_SIZE, "g_clients", client_root))
}

fn array_comment(
    vmoff: usize,
    base: usize,
    stride: usize,
    arr: &str,
    field: fn(usize) -> Option<String>,
) -> Option<String> {
    if stride == 0 || vmoff < base || vmoff >= base.saturating_add(stride * 1024) {
        return None;
    }
    let rel = vmoff - base;
    let i = rel / stride;
    let off = rel % stride;
    Some(match field(off) {
        Some(f) => format!("{arr}[{i}].{f}"),
        None => format!("{arr}[{i}]+{off}"),
    })
}

/// Field name at `+off` inside the entity structure. FILL IN per module.
fn ent_field(_off: usize) -> Option<String> {
    None
}

/// Field name at `+off` inside the client structure. FILL IN per module.
fn client_root(off: usize) -> Option<String> {
    client_field(off)
}

/// Field of a `gclient_t*` (playerState, pers, sess...). FILL IN per module.
pub fn client_field(_off: usize) -> Option<String> {
    None
}

/// Macro name for an array-stride constant, if the overlay defines one.
pub fn stride_macro(_n: i32) -> Option<&'static str> {
    None
}

/// C preamble: blob-view macros. FILL IN per module (empty by default).
pub fn emit_macros() -> String {
    String::new()
}

/// Padded overlay structs (every word `int` so q3lcc inserts no extra padding;
/// offsets must match `ptr + N` exactly — verify with seqdiff 0).
/// FILL IN per module (empty by default).
pub fn emit_structs() -> String {
    String::new()
}

/// Cgame overlay structs (`centity_t` view). FILL IN per module.
pub fn emit_cgame() -> String {
    String::new()
}

/// UI overlay structs (`menucommon_s` view). FILL IN per module.
pub fn emit_ui() -> String {
    String::new()
}

/// `ptr + N` rendered as `((ty*)ptr)->field` when the overlay knows both.
/// Offsets below the largest structure need a known pointer kind
/// (e.g. `s.origin` vs `ps.origin`). FILL IN per module.
pub fn overlay_ptr_field(_kind: Option<PtrKind>, _n: i32) -> Option<(&'static str, String)> {
    None
}

/// Comment on `ptr + N` when the pointer kind is unknown.
pub fn field_addend_comment(n: i32) -> Option<String> {
    field_addend_for(None, n)
}

pub fn field_addend_for(kind: Option<PtrKind>, n: i32) -> Option<String> {
    match kind {
        Some(PtrKind::Client) => client_field(n.max(0) as usize),
        Some(PtrKind::Entity) => ent_field(n.max(0) as usize),
        Some(PtrKind::Menu) => None,
        None => None,
    }
}

/// Known `loc_0[N]` names inside a named function (macros over the frame blob).
/// FILL IN per module. Example row: `("ClientSpawn", 104) => "spot"`.
pub fn fn_local_slot(fn_name: &str, off: usize) -> Option<&'static str> {
    fn_local_slots(fn_name).iter().find(|(o, _)| *o == off).map(|(_, n)| *n)
}

pub fn fn_local_slots(fn_name: &str) -> &'static [(usize, &'static str)] {
    LOCAL_SLOTS
        .iter()
        .find(|(f, _)| *f == fn_name)
        .map(|(_, slots)| *slots)
        .unwrap_or(&[])
}

/// Per-function local-slot names: `(function, &[(offset, name)])`.
const LOCAL_SLOTS: &[(&str, &[(usize, &'static str)])] = &[];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtrKind {
    Entity,
    Client,
    Menu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayMod {
    Game,
    CGame,
    Ui,
}

impl OverlayMod {
    pub fn from_module(m: crate::traps::Module) -> Self {
        match m {
            crate::traps::Module::Game => OverlayMod::Game,
            crate::traps::Module::CGame => OverlayMod::CGame,
            crate::traps::Module::Ui => OverlayMod::Ui,
        }
    }
}

pub fn overlay_ptr_field_for(
    module: OverlayMod,
    kind: Option<PtrKind>,
    n: i32,
) -> Option<(&'static str, String)> {
    match module {
        OverlayMod::Game => overlay_ptr_field(kind, n),
        // Cgame / UI overlays have their own structures; add dedicated
        // matchers here when you fill a key for such a module.
        OverlayMod::CGame | OverlayMod::Ui => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped template is inert: every lookup misses, every emitter is
    /// empty, and untyped ranges never fire. Filling a key replaces these
    /// expectations with real offset tests.
    #[test]
    fn template_is_inert() {
        assert_eq!(LEVEL_BASE, 0);
        assert_eq!(GENTITIES_END, 0);
        assert_eq!(GCLIENTS_END, 0);
        assert_eq!(scalar_macro(0x103C68), None);
        assert_eq!(comment(220_232 + 520), None);
        assert_eq!(stride_macro(824), None);
        assert_eq!(overlay_ptr_field(Some(PtrKind::Entity), 520), None);
        assert_eq!(overlay_ptr_field_for(OverlayMod::CGame, Some(PtrKind::Entity), 92), None);
        assert_eq!(overlay_ptr_field_for(OverlayMod::Ui, Some(PtrKind::Menu), 44), None);
        assert_eq!(field_addend_comment(520), None);
        assert_eq!(field_addend_for(Some(PtrKind::Client), 20), None);
        assert_eq!(fn_local_slot("ClientSpawn", 104), None);
        assert!(fn_local_slots("G_RunFrame").is_empty());
        assert_eq!(emit_macros(), "");
        assert_eq!(emit_structs(), "");
        assert_eq!(emit_cgame(), "");
        assert_eq!(emit_ui(), "");
    }

    #[test]
    fn api_shapes() {
        // CONST n -> image offset n-4; n < 4 has no image offset.
        assert_eq!(image_off(4), Some(0));
        assert_eq!(image_off(107_760), Some(107_756));
        assert_eq!(image_off(0), None);
        assert_eq!(
            OverlayMod::from_module(crate::traps::Module::CGame),
            OverlayMod::CGame
        );
    }
}
