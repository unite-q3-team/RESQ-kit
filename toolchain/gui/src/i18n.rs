//! Minimal UI localization: English source strings double as keys.
//! `tr(Lang::Ru, "File")` returns the Russian translation, falling back to
//! the English key when a translation is missing. Domain vocabulary (opcode
//! help, disasm comments, `mem_hint`, segment names) intentionally stays
//! English per AGENT.md.

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum Lang {
    #[default]
    En,
    Ru,
}

impl Lang {
    pub fn all() -> [Lang; 2] {
        [Lang::En, Lang::Ru]
    }

    /// Name in its own language (never translated).
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Ru => "Русский",
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Lang::En => 0,
            Lang::Ru => 1,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Lang::Ru,
            _ => Lang::En,
        }
    }
}

/// Translate a static UI string.
pub fn tr(lang: Lang, s: &'static str) -> &'static str {
    match lang {
        Lang::En => s,
        Lang::Ru => ru(s).unwrap_or(s),
    }
}

/// Translate a template, replacing `%KEY` placeholders with the arguments.
pub fn trf(lang: Lang, s: &'static str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    let mut out = tr(lang, s).to_string();
    for (k, v) in args {
        out = out.replace(&format!("%{k}"), &v.to_string());
    }
    out
}

fn ru(s: &'static str) -> Option<&'static str> {
    Some(match s {
        // ---- menus -------------------------------------------------------
        "File" => "Файл",
        "View" => "Вид",
        "Tools" => "Инструменты",
        "Help" => "Справка",
        "Open… (file dialog)" => "Открыть… (диалог)",
        "Open (path field)" => "Открыть (путь из поля)",
        "Reload" => "Перечитать",
        "Save .map" => "Сохранить .map",
        "Quit" => "Выход",
        "Code view" => "Режим кода",
        "DGraph view (disasm graph)" => "DGraph (граф дизасма)",
        "Call graph (whole image)" => "Граф вызовов (весь образ)",
        "Graph: center on vmMain" => "Граф: центрировать на vmMain",
        "Graph: fit image" => "Граф: вписать",
        "Graph: zoom in" => "Граф: приблизить",
        "Graph: zoom out" => "Граф: отдалить",
        "Language" => "Язык",
        "Export disassembly (.txt)" => "Экспорт дизассемблера (.txt)",
        "Export identity C (selected fn)" => "Экспорт identity C (выбранная функция)",
        "Export identity C (all fns)" => "Экспорт identity C (все функции)",
        "Shortcuts" => "Горячие клавиши",

        // ---- shortcut descriptions ---------------------------------------
        "open a QVM via the file dialog" => "открыть QVM через диалог",
        "load the typed path" => "загрузить путь из поля",
        "reload the current file" => "перечитать текущий файл",
        "save renames to .map" => "сохранить имена в .map",
        "navigate back" => "назад",
        "navigate forward" => "вперёд",
        "center the call graph on vmMain" => "центрировать граф вызовов на vmMain",
        "previous / next function (Code view)" => "предыдущая / следующая функция (режим кода)",
        "pan the canvas" => "панорама канвы",
        "zoom the canvas in / out" => "масштаб канвы + / -",
        "fit the graph to the window" => "вписать граф в окно",
        "jump to function" => "перейти к функции",
        "context menus everywhere" => "контекстные меню везде",
        "zoom / pan; drag node = move" => "зум / панорама; перетаскивание узла = переместить",

        // ---- toolbar ------------------------------------------------------
        "Back" => "Назад",
        "Forward" => "Вперёд",
        "Back (Backspace / Alt+Left)" => "Назад (Backspace / Alt+Left)",
        "Forward (Alt+Right)" => "Вперёд (Alt+Right)",
        "Home - center the call graph on the entry function" => {
            "Home — центрировать граф вызовов на входной функции"
        }
        "loading %PATH…" => "загрузка %PATH…",
        "working in the background…" => "работаю в фоне…",

        // ---- function list ------------------------------------------------
        "filter: name / trap / string..." => "фильтр: имя / трап / строка...",
        "%A/%B functions" => "функций: %A/%B",

        // ---- bottom tabs ---------------------------------------------------
        "Strings" => "Строки",
        "Traps" => "Трапы",
        "Info" => "Инфо",
        "filter strings..." => "фильтр строк...",
        "%A/%B strings" => "строк: %A/%B",
        "@%A  \"%T\"  (%B refs)" => "@%A  \"%T\"  (ссылок: %B)",
        "filter globals by address / function name..." => {
            "фильтр глобалов по адресу / имени функции..."
        }
        "fn[%S] %N: %C callers, %K callees" => "fn[%S] %N: вызывающих %C, вызываемых %K",
        "called by (%N):" => "вызывается из (%N):",
        "calls (%N):" => "вызывает (%N):",
        "  (none)" => "  (нет)",
        "file: %P" => "файл: %P",
        "functions: %A, instructions: %B, lit strings: %C" => {
            "функций: %A, инструкций: %B, строк: %C"
        }

        // ---- center panes ---------------------------------------------------
        "Disassembly" => "Дизассемблер",
        "rename..." => "имя функции...",
        "Rename" => "Переименовать",
        "Code" => "Код",
        "Graph" => "Граф",
        "Fit" => "Вписать",
        "Reset layout" => "Сбросить раскладку",
        "Disassembly graph: CFG with IF/branch edges" => "Граф дизасма: CFG с рёбрами ветвлений",
        "Load a QVM to inspect it." => "Загрузите QVM для анализа.",
        "call graph: drag canvas = pan, wheel = zoom, drag node = move, RMB = menu, dbl-click = open" => {
            "граф вызовов: тянуть канву = панорама, колесо = зум, тянуть узел = переместить, ПКМ = меню, двойной клик = открыть"
        }
        "CFG: drag canvas = pan, wheel = zoom, drag node = move, RMB = menu; taken edge = `if <OP>`, green = `else`" => {
            "CFG: тянуть канву = панорама, колесо = зум, тянуть узел = переместить, ПКМ = меню; ребро условия = `if <OP>`, зелёное = `else`"
        }

        // ---- status messages -------------------------------------------------
        "open a .qvm (File menu, path field, or drag & drop)" => {
            "откройте .qvm (меню Файл, поле пути или drag & drop)"
        }
        "already loading a file…" => "файл уже загружается…",
        "%PATH: %N functions, %I instructions, %S lit strings" => {
            "%PATH: функций %N, инструкций %I, строк %S"
        }
        "not a .qvm, ignored: %NAME" => "не .qvm, пропущено: %NAME",
        "saved %PATH (previous copy: %BAK)" => "сохранено %PATH (копия до перезаписи: %BAK)",
        "saved %PATH" => "сохранено %PATH",
        "nothing loaded" => "ничего не загружено",
        "cleared name of fn[%I]" => "имя fn[%I] очищено",
        "renamed fn[%I] -> %NAME" => "fn[%I] переименована -> %NAME",
        "exported %N lines -> %PATH" => "экспортировано строк %N -> %PATH",
        "exported -> %PATH" => "экспортировано -> %PATH",
        "write %PATH: %ERR" => "запись %PATH: %ERR",
        "decompile: %ERR" => "декомпиляция: %ERR",
        "export already running…" => "экспорт уже выполняется…",
        "exporting %N functions…" => "экспортирую %N функций…",
        "exported %N functions -> %PATH" => "экспортировано функций %N -> %PATH",
        "reopen for export: %ERR" => "повторное открытие для экспорта: %ERR",

        // ---- token context menus ----------------------------------------------
        "Go to function" => "Перейти к функции",
        "Xrefs to %NAME" => "Xrefs: %NAME",
        "Copy name" => "Копировать имя",
        "Hex dump string" => "Hex-дамп строки",
        "Xrefs to string" => "Xrefs строки",
        "Copy text" => "Копировать текст",
        "operand %T" => "операнд %T",
        "Hex dump memory at %X" => "Hex-дамп памяти %X",
        "Xrefs to address" => "Xrefs адреса",
        "Copy value" => "Копировать значение",
        "string @ %A" => "строка @ %A",
        "bss @ %X" => "BSS @ %X",
        "Memory - %T" => "Память - %T",

        // ---- graph panes --------------------------------------------------------
        "%A insns | calls %B | callers %C" => "инструкций %A | вызовов %B | вызывающих %C",
        "fn[%I] %NAME\ninsns %N, callers %C, calls %K" => {
            "fn[%I] %NAME\nинструкций %N, вызывающих %C, вызовов %K"
        }
        "Open in Code view" => "Открыть в режиме кода",
        "Show CFG" => "Показать CFG",
        "Center on this node" => "Центрировать на узле",
        "Scroll Disassembly here" => "Показать в дизассемблере",
        "Copy insn range" => "Копировать диапазон инсн.",
        _ => return None,
    })
}
