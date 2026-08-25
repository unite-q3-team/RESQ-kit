//! Runtime-loaded UI localization.
//!
//! English source strings double as keys. Catalogs live in `lang/*.json`
//! files (see `lang/README.md`); the shipped `ru.json` is also embedded via
//! `include_str!` so EN+RU work out of the box, while files next to the
//! executable override/extend them. Users can add a language by dropping a
//! JSON file — no rebuild needed.
//!
//! `LangId` is a small Copy handle indexing the catalog registry (built once,
//! read-only afterwards — safe to use from worker threads).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

/// A handle to a loaded translation catalog. `LangId::EN` (index 0) is the
/// identity catalog: keys are the English strings themselves.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct LangId(pub u8);

/// One translation catalog.
pub struct Catalog {
    /// Short id saved in the settings (`"en"`, `"ru"`, `"de"`, …).
    pub code: String,
    /// Display name in the language itself (`"Русский"`).
    pub name: String,
    /// UI strings: English key -> translation.
    pub map: HashMap<String, String>,
    /// Opcode name (`"Enter"`) -> tooltip text.
    pub opcode_help: HashMap<String, String>,
    /// Memory-hint phrases (`seg.data`, `seg.lit`, `hint.bss`,
    /// `hint.ptr`, `hint.refs`).
    pub mem_hints: HashMap<String, String>,
}

#[derive(serde::Deserialize)]
struct CatalogFile {
    code: String,
    name: String,
    #[serde(default)]
    translations: HashMap<String, String>,
    #[serde(default)]
    opcode_help: HashMap<String, String>,
    #[serde(default)]
    mem_hints: HashMap<String, String>,
}

static CATALOGS: OnceLock<Vec<Catalog>> = OnceLock::new();

fn catalogs() -> &'static Vec<Catalog> {
    CATALOGS.get_or_init(load_all)
}

/// All loaded languages, `EN` first, the rest sorted by display name.
pub fn languages() -> &'static [Catalog] {
    catalogs()
}

impl LangId {
    /// English (the identity catalog, always present at index 0).
    pub const EN: LangId = LangId(0);

    /// Resolve a persisted language code; `None` if that language file is
    /// no longer present.
    pub fn from_code(code: &str) -> Option<LangId> {
        catalogs()
            .iter()
            .position(|c| c.code == code)
            .map(|i| LangId(i as u8))
    }

    pub fn code(self) -> &'static str {
        &catalogs()[self.0 as usize].code
    }

    /// Display name in the language itself (never translated).
    pub fn native_name(self) -> &'static str {
        &catalogs()[self.0 as usize].name
    }
}

/// Translate a static UI string; missing keys fall back to English (the key).
pub fn tr(lang: LangId, key: &'static str) -> &'static str {
    let c = &catalogs()[lang.0 as usize];
    match c.map.get(key) {
        Some(s) => s.as_str(),
        None => key,
    }
}

/// Translate a template, replacing `%KEY` placeholders with the arguments.
pub fn trf(lang: LangId, key: &'static str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    let mut out = tr(lang, key).to_string();
    for (k, v) in args {
        out = out.replace(&format!("%{k}"), &v.to_string());
    }
    out
}

/// Opcode tooltip text by opcode name; `None` = fall back to English.
pub fn opcode_help(lang: LangId, op_name: &str) -> Option<String> {
    let c = &catalogs()[lang.0 as usize];
    c.opcode_help.get(op_name).cloned()
}

/// Memory-hint phrase by key; `None` = fall back to the built-in English.
pub fn mem_hint_phrase(lang: LangId, key: &str) -> Option<String> {
    let c = &catalogs()[lang.0 as usize];
    c.mem_hints.get(key).cloned()
}

// ---------------------------------------------------------------------------
// Catalog loading
// ---------------------------------------------------------------------------

fn identity_catalog() -> Catalog {
    Catalog {
        code: "en".into(),
        name: "English".into(),
        map: HashMap::new(),
        opcode_help: HashMap::new(),
        mem_hints: HashMap::new(),
    }
}

fn parse_catalog(json: &str) -> Option<Catalog> {
    let f: CatalogFile = serde_json::from_str(json).ok()?;
    Some(Catalog {
        code: f.code,
        name: f.name,
        map: f.translations,
        opcode_help: f.opcode_help,
        mem_hints: f.mem_hints,
    })
}

/// Directories scanned for `*.json` catalogs, in override order
/// (later entries win): `lang/` next to the exe, then `lang/` in cwd.
fn lang_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            dirs.push(d.join("lang"));
        }
    }
    dirs.push(PathBuf::from("lang"));
    dirs
}

fn load_all() -> Vec<Catalog> {
    // Built-ins first; disk files with the same code override them.
    let mut by_code: Vec<Catalog> = vec![identity_catalog()];
    let embedded_ru = include_str!("../lang/ru.json");
    if let Some(c) = parse_catalog(embedded_ru) {
        by_code.push(c);
    }

    for dir in lang_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<_> = rd.flatten().collect();
        paths.sort_by_key(|p| p.path());
        for p in paths {
            let fname = p.file_name();
            let Some(name) = fname.to_str() else {
                continue;
            };
            if !name.to_lowercase().ends_with(".json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(p.path()) else {
                continue;
            };
            match parse_catalog(&text) {
                // Same code as an existing entry (incl. built-ins) => override.
                Some(c) => match by_code.iter_mut().find(|e| e.code == c.code) {
                    Some(e) => *e = c,
                    None => by_code.push(c),
                },
                // Broken file: skip it rather than failing the whole app.
                None => eprintln!("i18n: skipping unparseable {}", p.path().display()),
            }
        }
    }

    // EN stays first; the rest sorted by display name for a stable menu.
    let en = by_code.remove(0);
    by_code.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let mut out = vec![en];
    out.extend(by_code);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalogs_load() {
        // EN is the identity mapping.
        assert_eq!(tr(LangId::EN, "File"), "File");
        assert_eq!(tr(LangId::EN, "no such key"), "no such key");

        // Embedded RU ships with the binary.
        let ru = LangId::from_code("ru").expect("embedded ru catalog");
        assert_eq!(tr(ru, "File"), "Файл");
        assert_eq!(tr(ru, "no such key"), "no such key");
        assert_eq!(
            trf(ru, "%A/%B functions", &[("A", &1), ("B", &2)]),
            "функций: 1/2"
        );
        assert_eq!(
            trf(LangId::EN, "%A/%B functions", &[("A", &1), ("B", &2)]),
            "1/2 functions"
        );
        assert!(opcode_help(ru, "ENTER").unwrap().contains("пролог функции"));
        assert_eq!(opcode_help(ru, "NoSuchOp"), None);
        assert_eq!(
            mem_hint_phrase(ru, "hint.refs").unwrap(),
            "упоминается в %N фн."
        );
        assert_eq!(mem_hint_phrase(ru, "nope"), None);

        // Native names and codes.
        assert_eq!(LangId::EN.native_name(), "English");
        assert_eq!(ru.native_name(), "Русский");
        assert_eq!(ru.code(), "ru");
        assert_eq!(LangId::from_code("zz"), None);
    }
}
