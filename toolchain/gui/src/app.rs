//! egui frontend: function list | disasm | identity C | call graph | CFG.
//!
//! UI closures only READ from `Loaded`; every action (jump / scroll / hover /
//! hex dump / tab switch) is collected into locals and applied after the
//! panels are built. That keeps borrows disjoint and egui happy.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use eframe::egui;
use egui::{Color32, RichText, Sense, TextWrapMode};

use crate::state::{escape, insn_bytes, Loaded};

/// Keep at most this many decompiled functions cached.
const C_CACHE_CAP: usize = 128;

#[derive(Clone, Copy, Default, PartialEq)]
enum BottomTab {
    #[default]
    Strings,
    Traps,
    Xrefs,
    Info,
}

#[derive(Clone, Copy, PartialEq)]
enum CenterTab {
    Code,
    Graph,
}

#[derive(Clone, Copy, PartialEq)]
enum GraphMode {
    /// Whole-image call graph (all functions).
    Image,
    /// CFG of the selected function.
    Cfg,
}

/// Request for the floating memory hex-dump window.
#[derive(Clone)]
struct HexReq {
    title: String,
    addr: i32,
    len: usize,
}

// ---------------------------------------------------------------------------
// Syntax palette (dark-theme friendly)
// ---------------------------------------------------------------------------
const C_PLAIN: Color32 = Color32::from_rgb(208, 212, 218);
const C_DIM: Color32 = Color32::from_rgb(120, 128, 138);
const C_KW: Color32 = Color32::from_rgb(198, 120, 221);
const C_NUM: Color32 = Color32::from_rgb(209, 154, 102);
const C_STR: Color32 = Color32::from_rgb(152, 195, 121);
const C_CMT: Color32 = Color32::from_rgb(106, 115, 125);
const C_LBL: Color32 = Color32::from_rgb(97, 175, 239);
const C_FN: Color32 = Color32::from_rgb(229, 192, 123);
const C_TRAP: Color32 = Color32::from_rgb(224, 108, 117);
const C_SLOT: Color32 = Color32::from_rgb(86, 182, 194);
const C_TGT: Color32 = Color32::from_rgb(130, 200, 230);

const TINT_HOVER: Color32 = Color32::from_rgb(70, 62, 28);
const TINT_ENTRY: Color32 = Color32::from_rgb(96, 80, 30);

const KEYWORDS: &[&str] = &[
    "void", "return", "goto", "if", "else", "while", "for", "switch", "case", "default", "break",
    "continue", "sizeof", "unsigned", "signed", "const", "struct", "static", "int", "char",
    "short", "long", "float", "double", "memcpy",
];

/// One rendered chunk of a source line.
#[derive(Clone)]
enum Seg {
    /// Colored static text.
    P(String, Color32),
    /// Known function name -> fn index (clickable, context menu).
    FnTok(String, usize),
    /// Basic-block label `L<n>` -> insn index (clickable, scrolls disasm).
    LblTok(String, usize),
    /// Quoted string literal with its VM address (context menu).
    StrTok(String, i32),
    /// Numeric CONST operand: potential data address (context menu).
    NumTok(String),
}

/// Shared immutable view over `Loaded` maps used by the tokenizers.
struct Tok<'a> {
    names: &'a HashMap<String, usize>,
    traps: &'a HashSet<String>,
    entries: &'a HashMap<usize, usize>,
}

/// Actions collected while rendering one pane.
struct Sink<'a> {
    jump: &'a mut Option<usize>,
    scroll: &'a mut Option<usize>,
    hover_fn: &'a mut Option<usize>,
    hexreq: &'a mut Option<HexReq>,
    /// Open the Xrefs tab for this fn index.
    xref_fn: &'a mut Option<usize>,
}

pub struct App {
    loaded: Option<Loaded>,
    path_edit: String,
    filter: String,
    strings_filter: String,
    selected: Option<usize>,
    c_cache: HashMap<usize, Arc<str>>,
    rename_buf: String,
    status: String,
    tab: BottomTab,
    center: CenterTab,
    graph_mode: GraphMode,
    /// Call-graph view transform (world -> screen: `scr = pan + world * zoom`).
    graph_zoom: f32,
    graph_pan: egui::Vec2,
    /// Fit the call graph to the window on request.
    graph_fit: bool,
    /// CFG canvas pan / zoom.
    cfg_pan: egui::Vec2,
    cfg_zoom: f32,
    cfg_fit: bool,
    /// User-dragged node offsets (world space).
    img_offsets: HashMap<usize, egui::Vec2>,
    cfg_offsets: HashMap<(usize, usize), egui::Vec2>,
    /// Node currently being dragged.
    img_drag: Option<usize>,
    cfg_drag: Option<usize>,
    /// Pending "center call graph on this function" request.
    graph_focus: Option<usize>,
    /// Pending scroll request for the disasm pane (insn index).
    scroll_to: Option<usize>,
    /// Cross-pane highlight (C token hover -> disasm function range tint).
    hover_fn: Option<usize>,
    /// Navigation history (back / forward).
    hist: Vec<usize>,
    hist_fwd: Vec<usize>,
    /// Scroll sync between Disasm and Identity C.
    sync_scroll: bool,
    sync_to_d: Option<f32>,
    sync_to_c: Option<f32>,
    prev_d: f32,
    prev_c: f32,
    /// Floating memory hex-dump window.
    hex_view: Option<HexReq>,
    /// Last window title set (avoids per-frame ViewportCommand spam).
    title: Option<String>,
}

impl App {
    pub fn new(initial: Option<String>) -> Self {
        let mut app = App {
            loaded: None,
            path_edit: initial.unwrap_or_default(),
            filter: String::new(),
            strings_filter: String::new(),
            selected: None,
            c_cache: HashMap::new(),
            rename_buf: String::new(),
            status: "open a .qvm (File menu, path field, or drag & drop)".into(),
            tab: BottomTab::Strings,
            center: CenterTab::Code,
            graph_mode: GraphMode::Image,
            graph_zoom: 1.0,
            graph_pan: egui::Vec2::ZERO,
            graph_fit: true,
            cfg_pan: egui::Vec2::ZERO,
            cfg_zoom: 1.0,
            cfg_fit: true,
            img_offsets: HashMap::new(),
            cfg_offsets: HashMap::new(),
            img_drag: None,
            cfg_drag: None,
            graph_focus: None,
            scroll_to: None,
            hover_fn: None,
            hist: Vec::new(),
            hist_fwd: Vec::new(),
            sync_scroll: false,
            sync_to_d: None,
            sync_to_c: None,
            prev_d: 0.0,
            prev_c: 0.0,
            hex_view: None,
            title: None,
        };
        if !app.path_edit.is_empty() {
            app.load_path(&app.path_edit.clone());
        }
        app
    }

    pub fn load_path(&mut self, path: &str) {
        match Loaded::open(std::path::Path::new(path)) {
            Ok(l) => {
                let n = l.fns.len();
                let insns = l.lines.len();
                self.status = format!(
                    "{}: {n} functions, {insns} instructions, {} lit strings",
                    l.path.display(),
                    l.lit_strings.len()
                );
                self.selected = Some(0);
                self.rename_buf.clear();
                self.c_cache.clear();
                self.scroll_to = l.fns.first().map(|f| f.entry);
                self.hover_fn = None;
                self.graph_fit = false;
                self.hist.clear();
                self.hist_fwd.clear();
                self.graph_focus = Some(l.entry_fn());
                self.img_offsets.clear();
                self.cfg_offsets.clear();
                self.img_drag = None;
                self.cfg_drag = None;
                self.cfg_zoom = 1.0;
                self.cfg_fit = true;
                self.hex_view = None;
                self.sync_to_d = None;
                self.sync_to_c = None;
                self.loaded = Some(l);
            }
            Err(e) => self.status = e,
        }
    }

    /// Select a function; optionally record the current one in history.
    fn jump_to(&mut self, idx: usize, push_hist: bool) {
        let Some(l) = &self.loaded else { return };
        if idx >= l.fns.len() {
            return;
        }
        if push_hist {
            if let Some(cur) = self.selected {
                if cur != idx {
                    self.hist.push(cur);
                    self.hist_fwd.clear();
                }
            }
        }
        self.selected = Some(idx);
        self.rename_buf = l.fns[idx].name.clone().unwrap_or_default();
        self.scroll_to = Some(l.fns[idx].entry);
    }

    fn go_back(&mut self) {
        if let Some(prev) = self.hist.pop() {
            if let Some(cur) = self.selected {
                self.hist_fwd.push(cur);
            }
            self.jump_to(prev, false);
        }
    }

    fn go_forward(&mut self) {
        if let Some(next) = self.hist_fwd.pop() {
            if let Some(cur) = self.selected {
                self.hist.push(cur);
            }
            self.jump_to(next, false);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drag & drop support.
        let dropped: Option<String> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .find_map(|f| f.path.as_deref().map(|p| p.display().to_string()))
        });
        if let Some(p) = dropped {
            if p.to_lowercase().ends_with(".qvm") {
                self.path_edit = p.clone();
                self.load_path(&p);
            }
        }

        // Arrow-key navigation in the function list (no history entries).
        let kb_free = !ctx.wants_keyboard_input();
        let (down, up) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::ArrowDown),
                i.key_pressed(egui::Key::ArrowUp),
            )
        });
        if let Some(cur) = self.selected {
            let n = self.loaded.as_ref().map_or(0, |l| l.fns.len());
            let next = if down {
                cur + 1
            } else if up {
                cur.saturating_sub(1)
            } else {
                cur
            };
            if next != cur && next < n {
                self.jump_to(next, false);
            }
        }

        // Global hotkeys (ignored while a text field has keyboard focus).
        let (back, fwd, reload, save) = ctx.input(|i| {
            (
                kb_free && i.key_pressed(egui::Key::Backspace),
                kb_free && i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight),
                kb_free && i.key_pressed(egui::Key::F5),
                kb_free && i.modifiers.ctrl && i.key_pressed(egui::Key::S),
            )
        });
        if back {
            self.go_back();
        }
        if fwd {
            self.go_forward();
        }
        if reload && !self.path_edit.is_empty() {
            let p = self.path_edit.clone();
            self.load_path(&p);
        }
        if save {
            self.save_map_action();
        }

        // Window title reflects the loaded image.
        let want_title = self
            .loaded
            .as_ref()
            .map(|l| {
                let name = l
                    .path
                    .file_name()
                    .map_or_else(|| l.path.display().to_string(), |n| n.display().to_string());
                format!("{name} — RESQ kit")
            })
            .unwrap_or_else(|| "RESQ kit - QVM analyzer".into());
        if self.title.as_deref() != Some(want_title.as_str()) {
            self.title = Some(want_title.clone());
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(want_title));
        }

        // Panel order matters: side/bottom panels must be shown BEFORE the
        // CentralPanel, otherwise they paint on top of the central content
        // and hide its scrollable area.
        let mut jump: Option<usize> = None;
        self.top_bar(ctx);
        self.function_list(ctx, &mut jump);
        self.bottom_tabs(ctx, &mut jump);
        self.center_panes(ctx);
        if let Some(j) = jump {
            self.jump_to(j, true);
        }

        // Floating memory hex-dump window.
        if let Some(hv) = self.hex_view.clone() {
            if let Some(l) = &self.loaded {
                let mut open = true;
                egui::Window::new(format!("Memory — {}", hv.title))
                    .open(&mut open)
                    .default_width(560.0)
                    .default_height(380.0)
                    .show(ctx, |ui| hex_rows(ui, l, &hv));
                if !open {
                    self.hex_view = None;
                }
            }
        }
    }
}

/// Hex dump rows: `ADDR  xx xx .. xx  |ascii|` (16 bytes per row).
fn hex_rows(ui: &mut egui::Ui, l: &Loaded, hv: &HexReq) {
    ui.monospace(format!("address {:#x}, {} bytes", hv.addr, hv.len));
    let rows = hv.len.div_ceil(16);
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, row_h, rows, |ui, range| {
            for r in range {
                let base = hv.addr + (r * 16) as i32;
                let mut hex = String::new();
                let mut ascii = String::new();
                for k in 0..16 {
                    let b = l.mem_byte(base + k);
                    hex.push_str(&format!("{b:02X} "));
                    ascii.push(if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    });
                }
                ui.monospace(format!("{base:08X}  {hex} |{ascii}|"));
            }
        });
}

impl App {
    fn save_map_action(&mut self) {
        if let Some(l) = &self.loaded {
            match l.save_map() {
                Ok(p) => self.status = format!("saved {}", p.display()),
                Err(e) => self.status = e,
            }
        } else {
            self.status = "nothing loaded".into();
        }
    }

    fn export_disasm(&mut self) {
        let Some(l) = &self.loaded else {
            self.status = "nothing loaded".into();
            return;
        };
        let out = l.path.with_extension("disasm.txt");
        let body = l.lines.join("\n");
        match std::fs::write(&out, body) {
            Ok(()) => {
                self.status = format!("exported {} lines -> {}", l.lines.len(), out.display())
            }
            Err(e) => self.status = format!("write {}: {e}", out.display()),
        }
    }

    fn export_c_selected(&mut self) {
        let Some(l) = &self.loaded else {
            self.status = "nothing loaded".into();
            return;
        };
        let Some(sel) = self.selected else { return };
        match l.decompile(sel) {
            Ok(text) => {
                let raw = l
                    .fns
                    .get(sel)
                    .and_then(|f| f.name.clone())
                    .unwrap_or_else(|| format!("fn{sel}"));
                let name: String = raw
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let out = l.path.with_extension(format!("fn{sel}_{name}.c"));
                match std::fs::write(&out, &*text) {
                    Ok(()) => self.status = format!("exported -> {}", out.display()),
                    Err(e) => self.status = format!("write {}: {e}", out.display()),
                }
            }
            Err(e) => self.status = format!("decompile: {e}"),
        }
    }

    fn export_c_all(&mut self) {
        let Some(l) = &self.loaded else {
            self.status = "nothing loaded".into();
            return;
        };
        let out = l.path.with_extension("all.c");
        let mut body = String::new();
        for f in &l.fns {
            body.push_str(&format!(
                "// ==== fn[{}] {} @ insn {} ====\n",
                f.idx,
                f.display_name(),
                f.entry
            ));
            match l.decompile(f.idx) {
                Ok(text) => body.push_str(&text),
                Err(e) => body.push_str(&format!("// decompile error: {e}\n")),
            }
            body.push('\n');
        }
        match std::fs::write(&out, body) {
            Ok(()) => {
                self.status = format!("exported {} functions -> {}", l.fns.len(), out.display())
            }
            Err(e) => self.status = format!("write {}: {e}", out.display()),
        }
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // ---- File ------------------------------------------------
                ui.menu_button("File", |ui| {
                    if ui.button("Open (path field)").clicked() {
                        ui.close_menu();
                        let p = self.path_edit.clone();
                        self.load_path(&p);
                    }
                    if ui.button("Reload").on_hover_text("F5").clicked() {
                        ui.close_menu();
                        let p = self.path_edit.clone();
                        self.load_path(&p);
                    }
                    if ui.button("Save .map").on_hover_text("Ctrl+S").clicked() {
                        ui.close_menu();
                        self.save_map_action();
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ui.close_menu();
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                // ---- View ------------------------------------------------
                ui.menu_button("View", |ui| {
                    if ui
                        .button("Back")
                        .on_hover_text("Backspace / Alt+Left")
                        .clicked()
                    {
                        ui.close_menu();
                        self.go_back();
                    }
                    if ui.button("Forward").on_hover_text("Alt+Right").clicked() {
                        ui.close_menu();
                        self.go_forward();
                    }
                    ui.separator();
                    if ui.button("Code view").clicked() {
                        ui.close_menu();
                        self.center = CenterTab::Code;
                    }
                    if ui.button("Graph: image (call graph)").clicked() {
                        ui.close_menu();
                        self.center = CenterTab::Graph;
                        self.graph_mode = GraphMode::Image;
                    }
                    if ui.button("Graph: CFG of selected").clicked() {
                        ui.close_menu();
                        self.center = CenterTab::Graph;
                        self.graph_mode = GraphMode::Cfg;
                    }
                    ui.separator();
                    if ui
                        .button("Graph: center on vmMain")
                        .on_hover_text("Home")
                        .clicked()
                    {
                        ui.close_menu();
                        self.center = CenterTab::Graph;
                        self.graph_mode = GraphMode::Image;
                        if let Some(l) = &self.loaded {
                            self.graph_focus = Some(l.entry_fn());
                        }
                    }
                    if ui.button("Graph: fit image").clicked() {
                        ui.close_menu();
                        self.graph_fit = true;
                    }
                    if ui.button("Graph: zoom in").on_hover_text("+").clicked() {
                        ui.close_menu();
                        self.graph_zoom = (self.graph_zoom * 1.3).clamp(0.03, 2.5);
                    }
                    if ui.button("Graph: zoom out").on_hover_text("-").clicked() {
                        ui.close_menu();
                        self.graph_zoom = (self.graph_zoom / 1.3).clamp(0.03, 2.5);
                    }
                });

                // ---- Tools -----------------------------------------------
                ui.menu_button("Tools", |ui| {
                    if ui.button("Export disassembly (.txt)").clicked() {
                        ui.close_menu();
                        self.export_disasm();
                    }
                    if ui.button("Export identity C (selected fn)").clicked() {
                        ui.close_menu();
                        self.export_c_selected();
                    }
                    if ui.button("Export identity C (all fns)").clicked() {
                        ui.close_menu();
                        self.export_c_all();
                    }
                });

                // ---- path field ------------------------------------------
                let edit = egui::TextEdit::singleline(&mut self.path_edit)
                    .desired_width(ui.available_width() - 16.0)
                    .font(egui::TextStyle::Monospace);
                let path_resp = ui.add(edit);
                if path_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let p = self.path_edit.clone();
                    self.load_path(&p);
                }
            });
            ui.horizontal(|ui| {
                let kb_free = !ctx.wants_keyboard_input();
                let home = kb_free && ctx.input(|i| i.key_pressed(egui::Key::Home));
                if ui
                    .add_enabled(self.loaded.is_some(), egui::Button::new("vmMain"))
                    .on_hover_text("Home — center the call graph on the entry function")
                    .clicked()
                    || home
                {
                    self.center = CenterTab::Graph;
                    self.graph_mode = GraphMode::Image;
                    if let Some(l) = &self.loaded {
                        self.graph_focus = Some(l.entry_fn());
                    }
                }
                if ui
                    .add_enabled(!self.hist.is_empty(), egui::Button::new("<"))
                    .on_hover_text("Back (Backspace / Alt+Left)")
                    .clicked()
                {
                    self.go_back();
                }
                if ui
                    .add_enabled(!self.hist_fwd.is_empty(), egui::Button::new(">"))
                    .on_hover_text("Forward (Alt+Right)")
                    .clicked()
                {
                    self.go_forward();
                }
                ui.separator();
                ui.add(egui::Checkbox::new(&mut self.sync_scroll, "Sync scroll"))
                    .on_hover_text("Scroll Disassembly and Identity C together (by fraction)");
                ui.separator();
                ui.colored_label(egui::Color32::LIGHT_BLUE, &self.status);
            });
        });
    }

    fn function_list(&mut self, ctx: &egui::Context, jump: &mut Option<usize>) {
        egui::SidePanel::left("fns")
            .default_width(300.0)
            .width_range(180.0..=520.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("filter: name / trap / string...")
                        .font(egui::TextStyle::Monospace),
                );
                let Some(l) = &self.loaded else { return };
                let needle = self.filter.to_lowercase();
                let rows: Vec<(usize, String)> = l
                    .fns
                    .iter()
                    .filter(|f| needle.is_empty() || f.search.contains(&needle))
                    .map(|f| (f.idx, format!("{}  [{}]", f.display_name(), f.len())))
                    .collect();
                ui.label(format!("{}/{} functions", rows.len(), l.fns.len()));
                let sel = self.selected;
                let row_h = ui.text_style_height(&egui::TextStyle::Body);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, row_h, rows.len(), |ui, range| {
                        for i in range {
                            let (fi, label) = &rows[i];
                            if ui.selectable_label(sel == Some(*fi), label).clicked() {
                                *jump = Some(*fi);
                            }
                        }
                    });
            });
    }

    fn bottom_tabs(&mut self, ctx: &egui::Context, jump: &mut Option<usize>) {
        egui::TopBottomPanel::bottom("bottom")
            .default_height(190.0)
            .height_range(90.0..=420.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for (tab, name) in [
                        (BottomTab::Strings, "Strings"),
                        (BottomTab::Traps, "Traps"),
                        (BottomTab::Xrefs, "Xrefs"),
                        (BottomTab::Info, "Info"),
                    ] {
                        if ui.selectable_label(self.tab == tab, name).clicked() {
                            self.tab = tab;
                        }
                    }
                });
                ui.separator();

                let Some(l) = &self.loaded else { return };
                let mono_h = ui.text_style_height(&egui::TextStyle::Monospace);
                let sel = self.selected.unwrap_or(0);

                match self.tab {
                    BottomTab::Strings => {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.strings_filter)
                                .hint_text("filter strings...")
                                .font(egui::TextStyle::Monospace),
                        );
                        let needle = self.strings_filter.to_lowercase();
                        let rows: Vec<(i32, &String)> = l
                            .lit_strings
                            .iter()
                            .filter(|(addr, s)| {
                                needle.is_empty()
                                    || s.to_lowercase().contains(&needle)
                                    || format!("{addr}").contains(&needle)
                            })
                            .map(|(a, s)| (*a, s))
                            .collect();
                        ui.monospace(format!("{}/{} strings", rows.len(), l.lit_strings.len()));
                        egui::ScrollArea::vertical()
                            .id_salt("strings")
                            .auto_shrink([false, false])
                            .show_rows(ui, mono_h, rows.len(), |ui, range| {
                                for r in range {
                                    let (addr, s) = &rows[r];
                                    let users = l.string_refs.get(addr).map_or(0, Vec::len);
                                    let txt = format!("@{addr}  \"{}\"  ({users} refs)", escape(s));
                                    let resp = ui.selectable_label(false, &txt);
                                    resp.context_menu(|ui| {
                                        ui.label(format!("@{addr}"));
                                        if ui.button("Hex dump string").clicked() {
                                            ui.close_menu();
                                            self.hex_view = Some(HexReq {
                                                title: format!("string @ {addr}"),
                                                addr: *addr,
                                                len: s.len().max(1),
                                            });
                                        }
                                        ui.menu_button("Xrefs to string", |ui| {
                                            match l.string_refs.get(addr) {
                                                Some(v) if !v.is_empty() => {
                                                    for fi in v.iter().take(30) {
                                                        let f = &l.fns[*fi];
                                                        if ui
                                                            .button(format!(
                                                                "fn[{}] {}",
                                                                fi,
                                                                f.display_name()
                                                            ))
                                                            .clicked()
                                                        {
                                                            ui.close_menu();
                                                            *jump = Some(*fi);
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    ui.label("(none)");
                                                }
                                            }
                                        });
                                        if ui.button("Copy text").clicked() {
                                            ui.close_menu();
                                            ui.output_mut(|o| o.copied_text = s.to_string());
                                        }
                                    });
                                    if resp.clicked() {
                                        if let Some(v) = l.string_refs.get(addr) {
                                            if let Some(&first) = v.first() {
                                                *jump = Some(first);
                                            }
                                        }
                                    }
                                }
                            });
                    }
                    BottomTab::Traps => {
                        let entries: Vec<(u32, usize)> = l
                            .trap_users
                            .iter()
                            .map(|(num, users)| (*num, users.len()))
                            .collect();
                        egui::ScrollArea::vertical()
                            .id_salt("traps")
                            .auto_shrink([false, false])
                            .show_rows(ui, mono_h, entries.len(), |ui, rows| {
                                for r in rows {
                                    let (num, count) = entries[r];
                                    let name = qvm::trap_name(l.qvm.module, num).unwrap_or("?");
                                    if ui
                                        .selectable_label(
                                            false,
                                            format!("{num:<4} {name:<28} x{count}"),
                                        )
                                        .clicked()
                                    {
                                        if let Some(v) = l.trap_users.get(&num) {
                                            if let Some(&first) = v.first() {
                                                *jump = Some(first);
                                            }
                                        }
                                    }
                                }
                            });
                    }
                    BottomTab::Xrefs => {
                        let callers = l.callers.get(&sel).cloned().unwrap_or_default();
                        let callees = l.callees.get(&sel).cloned().unwrap_or_default();
                        let fname = l
                            .fns
                            .get(sel)
                            .map_or("?".to_string(), |f| f.display_name().to_string());
                        egui::ScrollArea::vertical()
                            .id_salt("xrefs")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.monospace(format!(
                                    "fn[{sel}] {fname}: {} callers, {} callees",
                                    callers.len(),
                                    callees.len()
                                ));
                                ui.add_space(4.0);
                                ui.monospace(format!("called by ({}):", callers.len()));
                                for ci in &callers {
                                    let f = &l.fns[*ci];
                                    let row =
                                        format!("  <- fn[{ci}] {} [{}]", f.display_name(), f.len());
                                    if ui.selectable_label(false, &row).clicked() {
                                        *jump = Some(*ci);
                                    }
                                }
                                if callers.is_empty() {
                                    ui.monospace("  (none)");
                                }
                                ui.add_space(4.0);
                                ui.monospace(format!("calls ({}):", callees.len()));
                                for ti in &callees {
                                    let f = &l.fns[*ti];
                                    let row =
                                        format!("  -> fn[{ti}] {} [{}]", f.display_name(), f.len());
                                    if ui.selectable_label(false, &row).clicked() {
                                        *jump = Some(*ti);
                                    }
                                }
                                if callees.is_empty() {
                                    ui.monospace("  (none)");
                                }
                            });
                    }
                    BottomTab::Info => {
                        ui.monospace(format!("{}", l.qvm));
                        ui.monospace(format!("file: {}", l.path.display()));
                        ui.monospace(format!(
                            "functions: {}, instructions: {}, lit strings: {}",
                            l.fns.len(),
                            l.lines.len(),
                            l.lit_strings.len()
                        ));
                    }
                }
            });
    }

    fn center_panes(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.loaded.is_none() {
                ui.centered_and_justified(|ui| ui.label("Load a QVM to inspect it."));
                return;
            }

            let mono_h = ui.text_style_height(&egui::TextStyle::Monospace);
            let Some(sel) = self.selected else { return };
            let entry = self.loaded.as_ref().map_or(0, |x| x.fns[sel].entry);

            // Header row: rename + center tabs + graph helpers.
            ui.horizontal(|ui| {
                ui.monospace(format!("fn[{sel}] @ insn {entry}"));
                let resp = ui.add_sized(
                    [320.0, mono_h + 6.0],
                    egui::TextEdit::singleline(&mut self.rename_buf).hint_text("rename..."),
                );
                let commit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if commit || ui.button("Rename").clicked() {
                    let new_name = self.rename_buf.trim().to_string();
                    if let Some(x) = &mut self.loaded {
                        x.rename(sel, &new_name);
                    }
                    // Names propagate into the C output of *other* functions
                    // that call this one, so the whole cache is stale.
                    self.c_cache.clear();
                    self.status = format!("renamed fn[{sel}] -> {new_name}");
                }
                ui.separator();
                if ui
                    .selectable_label(self.center == CenterTab::Code, "Code")
                    .clicked()
                {
                    self.center = CenterTab::Code;
                }
                if ui
                    .selectable_label(self.center == CenterTab::Graph, "Graph")
                    .clicked()
                {
                    self.center = CenterTab::Graph;
                }
                if self.center == CenterTab::Graph {
                    ui.separator();
                    if ui
                        .selectable_label(self.graph_mode == GraphMode::Image, "Image")
                        .clicked()
                    {
                        self.graph_mode = GraphMode::Image;
                    }
                    if ui
                        .selectable_label(self.graph_mode == GraphMode::Cfg, "Cfg")
                        .clicked()
                    {
                        self.graph_mode = GraphMode::Cfg;
                    }
                    if ui.button("Fit").clicked() {
                        match self.graph_mode {
                            GraphMode::Image => self.graph_fit = true,
                            GraphMode::Cfg => self.cfg_fit = true,
                        }
                    }
                    if ui.button("Reset layout").clicked() {
                        match self.graph_mode {
                            GraphMode::Image => self.img_offsets.clear(),
                            GraphMode::Cfg => self.cfg_offsets.clear(),
                        }
                    }
                    ui.separator();
                    match self.graph_mode {
                        GraphMode::Image => ui.monospace(
                            "drag canvas = pan, wheel = zoom, drag node = move, RMB = menu, dbl-click = open",
                        ),
                        GraphMode::Cfg => ui.monospace(
                            "drag canvas = pan, wheel = vscroll, drag node = move, RMB = menu",
                        ),
                    };
                }
            });

            ui.separator();

            // Decompiled C (cache miss -> decompile now; Arc clone per frame).
            let text: Arc<str> = match self.c_cache.get(&sel) {
                Some(t) => t.clone(),
                None => {
                    let t = match self.loaded.as_ref().unwrap().decompile(sel) {
                        Ok(s) => s,
                        Err(e) => format!("// decompile error: {e}\n").into(),
                    };
                    if self.c_cache.len() >= C_CACHE_CAP {
                        self.c_cache.clear();
                    }
                    self.c_cache.insert(sel, t.clone());
                    t
                }
            };

            // Owned/shared data for the pane closures (no &mut self inside).
            let l = self.loaded.as_ref().unwrap();
            let range = l.fn_range(sel).unwrap_or(0..0);
            let tok = Tok {
                names: &l.name_to_idx,
                traps: &l.trap_names,
                entries: &l.entry_to_idx,
            };
            let fn_ranges = &l.fn_ranges;
            let cfg_res = match (self.center, self.graph_mode) {
                (CenterTab::Graph, GraphMode::Cfg) => Some(l.cfg(sel)),
                _ => None,
            };

            // Locals collected inside the panes; applied after building.
            let mut jump_loc: Option<usize> = None;
            let mut hex_loc: Option<HexReq> = None;
            let mut xref_loc: Option<usize> = None;
            let mut open_code = false;
            let hover_fn_prev = self.hover_fn;
            let mut new_hover_fn: Option<usize> = None;
            let scroll_req: Option<usize> = self.scroll_to.take();
            let sync_to_d = self.sync_to_d.take();
            let sync_to_c = self.sync_to_c.take();
            let prev_d = self.prev_d;
            let prev_c = self.prev_c;
            let sync = self.sync_scroll;
            let mut d_now = 0.0f32;
            let mut c_now = 0.0f32;
            let mut pending_scroll: Option<usize> = None;

            match self.center {
                CenterTab::Code => ui.columns(2, |cols| {
                    // ---- left: disassembly ---------------------------------
                    cols[0].heading("Disassembly");
                    let mut sa = egui::ScrollArea::vertical()
                        .id_salt("disasm")
                        .auto_shrink([false, false]);
                    if let Some(t) = scroll_req {
                        if range.contains(&t) {
                            sa = sa.vertical_scroll_offset((t - range.start) as f32 * mono_h);
                        }
                    }
                    if let Some(y) = sync_to_d {
                        sa = sa.vertical_scroll_offset(y);
                    }
                    let d_out = sa.show_rows(&mut cols[0], mono_h, range.len(), |ui, rows| {
                        for i in rows {
                            let ii = range.start + i;
                            paint_row_bg(
                                ui,
                                mono_h,
                                cross_tint_insn(ii, hover_fn_prev, fn_ranges),
                            );
                            let segs = d_segments(&l.lines[ii], &tok);
                            let mut sink = Sink {
                                jump: &mut jump_loc,
                                scroll: &mut pending_scroll,
                                hover_fn: &mut new_hover_fn,
                                hexreq: &mut hex_loc,
                                xref_fn: &mut xref_loc,
                            };
                            render_row(ui, l, &segs, &mut sink);
                        }
                    });
                    d_now = d_out.state.offset.y;

                    // ---- right: decompiled C -------------------------------
                    cols[1].heading("Identity C");
                    let c_rows: Vec<&str> = text.lines().collect();
                    let mut sac = egui::ScrollArea::vertical()
                        .id_salt("decomp")
                        .auto_shrink([false, false]);
                    if let Some(y) = sync_to_c {
                        sac = sac.vertical_scroll_offset(y);
                    }
                    let c_out = sac.show_rows(&mut cols[1], mono_h, c_rows.len(), |ui, rows| {
                        for i in rows {
                            paint_row_bg(ui, mono_h, None);
                            let segs = c_segments(c_rows[i], &tok);
                            let mut sink = Sink {
                                jump: &mut jump_loc,
                                scroll: &mut pending_scroll,
                                hover_fn: &mut new_hover_fn,
                                hexreq: &mut hex_loc,
                                xref_fn: &mut xref_loc,
                            };
                            render_row(ui, l, &segs, &mut sink);
                        }
                    });
                    c_now = c_out.state.offset.y;
                }),
                CenterTab::Graph => match cfg_res {
                    Some(Ok(cfg)) => cfg_canvas(
                        ui,
                        l,
                        sel,
                        &cfg,
                        &mut self.cfg_pan,
                        &mut self.cfg_zoom,
                        &mut self.cfg_fit,
                        &mut self.cfg_offsets,
                        &mut self.cfg_drag,
                        &mut pending_scroll,
                    ),
                    Some(Err(e)) => {
                        ui.colored_label(Color32::LIGHT_RED, format!("CFG error: {e}"));
                    }
                    None => {
                        image_graph_pane(
                            ui,
                            l,
                            sel,
                            &mut self.graph_zoom,
                            &mut self.graph_pan,
                            &mut self.graph_fit,
                            &mut self.graph_focus,
                            &mut self.img_offsets,
                            &mut self.img_drag,
                            &mut self.graph_mode,
                            &mut jump_loc,
                            &mut open_code,
                        );
                    }
                },
            }

            // Fraction-based scroll sync (one frame lag, damped).
            if self.center == CenterTab::Code && sync {
                let d_h = range.len() as f32 * mono_h;
                let c_h = text.lines().count() as f32 * mono_h;
                if (d_now - prev_d).abs() > 0.5 {
                    self.sync_to_c = Some(d_now / d_h.max(1.0) * c_h);
                } else if (c_now - prev_c).abs() > 0.5 {
                    self.sync_to_d = Some(c_now / c_h.max(1.0) * d_h);
                }
            }
            self.prev_d = d_now;
            self.prev_c = c_now;

            // Apply collected actions.
            self.hover_fn = new_hover_fn;
            self.scroll_to = pending_scroll;
            if hex_loc.is_some() {
                self.hex_view = hex_loc;
            }
            if let Some(xf) = xref_loc {
                self.tab = BottomTab::Xrefs;
                self.jump_to(xf, false);
            }
            if open_code {
                self.center = CenterTab::Code;
            }
            if let Some(j) = jump_loc {
                self.jump_to(j, true);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Cross-pane highlighting helpers
// ---------------------------------------------------------------------------

fn cross_tint_insn(
    insn: usize,
    hover_fn: Option<usize>,
    fn_ranges: &[(usize, usize)],
) -> Option<Color32> {
    let hf = hover_fn?;
    let (e, end) = *fn_ranges.get(hf)?;
    if insn == e {
        Some(TINT_ENTRY)
    } else if insn > e && insn < end {
        Some(TINT_HOVER)
    } else {
        None
    }
}

fn paint_row_bg(ui: &mut egui::Ui, row_h: f32, tint: Option<Color32>) {
    if let Some(color) = tint {
        let r = egui::Rect::from_min_size(
            ui.available_rect_before_wrap().min,
            egui::vec2(ui.available_width(), row_h),
        );
        ui.painter().rect_filled(r, 1.0, color);
    }
}

// ---------------------------------------------------------------------------
// Tokenizers
// ---------------------------------------------------------------------------

fn is_num(w: &str) -> bool {
    let w = w.strip_prefix('-').unwrap_or(w);
    !w.is_empty()
        && (w.parse::<i64>().is_ok()
            || w.strip_prefix("0x")
                .is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()))
            || (w.chars().all(|c| c.is_ascii_digit() || c == '.') && w.ends_with('f')))
}

/// Disassembly line: `#12 @0x00c CONST 5 ->#20  ; comment`.
fn d_segments(line: &str, tok: &Tok) -> Vec<Seg> {
    let mut out = Vec::new();
    let (code, cmt) = match line.find("  ;") {
        Some(p) => (&line[..p], Some(&line[p..])),
        None => (line, None),
    };

    let mut cur_op = String::new();
    let mut const_val: Option<i32> = None;
    for w in code.split_whitespace() {
        if w.starts_with("->#") {
            out.push(Seg::P(w.to_string(), C_TGT));
        } else if w.starts_with('#') || w.starts_with('@') {
            out.push(Seg::P(w.to_string(), C_DIM));
        } else if w.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            && w.chars().any(char::is_alphabetic)
        {
            cur_op = w.to_string();
            out.push(Seg::P(w.to_string(), C_LBL)); // opcode mnemonic
        } else if is_num(w) {
            if cur_op == "CONST" {
                const_val = w.parse().ok();
                out.push(Seg::NumTok(w.to_string()));
            } else {
                out.push(Seg::P(w.to_string(), C_NUM));
            }
        } else {
            out.push(Seg::P(w.to_string(), C_PLAIN));
        }
        out.push(Seg::P(" ".into(), C_DIM));
    }
    if let Some(last) = out.pop() {
        let _ = last; // drop trailing space
    }

    if let Some(cm) = cmt {
        out.push(Seg::P("  ".into(), C_CMT));
        let inner = cm.trim_start();
        if let Some(a) = inner.find('"') {
            let (pre, rest) = inner.split_at(a);
            if !pre.is_empty() {
                out.push(Seg::P(pre.to_string(), C_CMT));
            }
            let quoted = match rest[1..].find('"') {
                Some(b) => &rest[..b + 2],
                None => rest,
            };
            out.push(Seg::StrTok(quoted.to_string(), const_val.unwrap_or(0)));
            let tail = &rest[quoted.len()..];
            if !tail.is_empty() {
                out.push(Seg::P(tail.to_string(), C_CMT));
            }
        } else {
            for w in inner.split_whitespace() {
                if w == "syscall" || w == "call" {
                    out.push(Seg::P(format!("{w} "), C_CMT));
                } else if is_num(w) {
                    out.push(Seg::P(format!("{w} "), C_NUM));
                } else if let Some(target) = w.strip_prefix("fn@") {
                    if let Some(idx) = target
                        .parse::<usize>()
                        .ok()
                        .and_then(|e| tok.entries.get(&e))
                    {
                        out.push(Seg::FnTok(format!("fn@{target}"), *idx));
                    } else {
                        out.push(Seg::P(format!("fn@{target} "), C_FN));
                    }
                } else if let Some(&idx) = tok.names.get(w) {
                    out.push(Seg::FnTok(w.to_string(), idx));
                } else if tok.traps.contains(w) {
                    out.push(Seg::P(w.to_string(), C_TRAP));
                } else {
                    out.push(Seg::P(format!("{w} "), C_CMT));
                }
            }
        }
    }
    merge_plain(out)
}

fn classify_ident(w: &str, tok: &Tok, out: &mut Vec<Seg>) {
    if KEYWORDS.contains(&w) {
        out.push(Seg::P(w.to_string(), C_KW));
    } else if let Some(&idx) = tok.names.get(w) {
        out.push(Seg::FnTok(w.to_string(), idx));
    } else if tok.traps.contains(w) {
        out.push(Seg::P(w.to_string(), C_TRAP));
    } else if w.starts_with('s') && w.len() > 1 && w[1..].chars().all(|c| c.is_ascii_digit()) {
        out.push(Seg::P(w.to_string(), C_SLOT));
    } else if let Some(n) = w
        .strip_prefix('L')
        .and_then(|r| r.trim_end_matches(':').parse::<usize>().ok())
    {
        out.push(Seg::LblTok(w.trim_end_matches(':').to_string(), n));
    } else if let Some(n) = w.strip_prefix("fn_").and_then(|d| d.parse::<usize>().ok()) {
        match tok.entries.get(&n) {
            Some(&idx) => out.push(Seg::FnTok(w.to_string(), idx)),
            None => out.push(Seg::P(w.to_string(), C_FN)),
        }
    } else {
        out.push(Seg::P(w.to_string(), C_PLAIN));
    }
}

/// Identity C line.
fn c_segments(line: &str, tok: &Tok) -> Vec<Seg> {
    let t = line.trim_end();
    if t.trim_start().starts_with("//") {
        return vec![Seg::P(t.to_string(), C_CMT)];
    }
    // Label-only line: `L12:` or `L12: // note`.
    let head = t.split_whitespace().next().unwrap_or("");
    if let Some(n) = head.strip_prefix('L').and_then(|r| r.strip_suffix(':')) {
        if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
            let rest = &t[head.len()..];
            let mut out = vec![Seg::LblTok(
                head.trim_end_matches(':').to_string(),
                n.parse().unwrap_or(0),
            )];
            if !rest.is_empty() {
                out.push(Seg::P(rest.to_string(), C_CMT));
            }
            return out;
        }
    }

    let mut out = Vec::new();
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        if c == '"' {
            let st = i;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                } else if b[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            out.push(Seg::P(t[st..i.min(t.len())].to_string(), C_STR));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let st = i;
            while i < b.len() {
                let ch = b[i] as char;
                if ch.is_ascii_alphanumeric() || ch == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            classify_ident(&t[st..i], tok, &mut out);
        } else if c.is_ascii_digit() {
            let st = i;
            i += 1;
            while i < b.len() {
                let ch = b[i] as char;
                if ch.is_ascii_alphanumeric() || ch == '.' {
                    i += 1;
                } else {
                    break;
                }
            }
            out.push(Seg::P(t[st..i].to_string(), C_NUM));
        } else {
            out.push(Seg::P(c.to_string(), C_PLAIN));
            i += 1;
        }
    }
    merge_plain(out)
}

// ---------------------------------------------------------------------------
// Segment rendering (with context menus)
// ---------------------------------------------------------------------------

fn plain_label(ui: &mut egui::Ui, txt: &str, color: Color32) {
    let rt = RichText::new(txt).monospace().color(color);
    ui.add(egui::Label::new(rt).wrap_mode(TextWrapMode::Extend));
}

fn tok_label(ui: &mut egui::Ui, txt: &str, color: Color32) -> egui::Response {
    let rt = RichText::new(txt).monospace().color(color).underline();
    ui.add(
        egui::Label::new(rt)
            .wrap_mode(TextWrapMode::Extend)
            .sense(Sense::click()),
    )
}

/// Merge adjacent same-color plain chunks: fewer widgets per row.
fn merge_plain(mut segs: Vec<Seg>) -> Vec<Seg> {
    segs.dedup_by(|a, b| match (a, b) {
        (Seg::P(at, ac), Seg::P(bt, bc)) => {
            if ac == bc {
                bt.push_str(at);
                true
            } else {
                false
            }
        }
        _ => false,
    });
    segs
}

/// Render one source line as a single horizontal run of tight tokens.
fn render_row(ui: &mut egui::Ui, l: &Loaded, segs: &[Seg], sink: &mut Sink) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for s in segs {
            match s {
                Seg::P(t, c) => plain_label(ui, t, *c),
                Seg::FnTok(t, idx) => {
                    let r = tok_label(ui, t, C_FN);
                    if r.hovered() {
                        *sink.hover_fn = Some(*idx);
                    }
                    if r.double_clicked() {
                        *sink.jump = Some(*idx);
                    }
                    r.context_menu(|ui| {
                        let f = &l.fns[*idx];
                        let addr = l.d.insns[f.entry].addr;
                        ui.label(format!(
                            "fn[{idx}] {} @ insn {} ({addr:#x})",
                            f.display_name(),
                            f.entry
                        ));
                        if ui.button("Go to function").clicked() {
                            ui.close_menu();
                            *sink.jump = Some(*idx);
                        }
                        if ui
                            .button(format!("Xrefs to {}", f.display_name()))
                            .clicked()
                        {
                            ui.close_menu();
                            *sink.xref_fn = Some(*idx);
                        }
                        if ui.button("Copy name").clicked() {
                            ui.close_menu();
                            ui.output_mut(|o| {
                                o.copied_text = f.display_name().to_string();
                            });
                        }
                    });
                }
                Seg::LblTok(t, n) => {
                    let r = tok_label(ui, t, C_LBL);
                    if r.clicked() {
                        *sink.scroll = Some(*n);
                    }
                }
                Seg::StrTok(t, addr) => {
                    let r = tok_label(ui, t, C_STR);
                    r.context_menu(|ui| {
                        ui.label(format!("@{addr}"));
                        if ui.button("Hex dump string").clicked() {
                            ui.close_menu();
                            *sink.hexreq = Some(HexReq {
                                title: format!("string @ {addr}"),
                                addr: *addr,
                                len: t.len().max(1),
                            });
                        }
                        ui.menu_button("Xrefs to string", |ui| match l.string_refs.get(addr) {
                            Some(v) if !v.is_empty() => {
                                for fi in v.iter().take(30) {
                                    let f = &l.fns[*fi];
                                    if ui
                                        .button(format!("fn[{fi}] {}", f.display_name()))
                                        .clicked()
                                    {
                                        ui.close_menu();
                                        *sink.jump = Some(*fi);
                                    }
                                }
                            }
                            _ => {
                                ui.label("(none)");
                            }
                        });
                        if ui.button("Copy text").clicked() {
                            ui.close_menu();
                            ui.output_mut(|o| o.copied_text = t.clone());
                        }
                    });
                }
                Seg::NumTok(t) => {
                    let val = t.parse::<i32>().ok();
                    let r = tok_label(ui, t, C_NUM);
                    r.context_menu(|ui| {
                        ui.label(format!("operand {t}"));
                        if let Some(v) = val {
                            if ui.button(format!("Hex dump memory at {v:#x}")).clicked() {
                                ui.close_menu();
                                *sink.hexreq = Some(HexReq {
                                    title: format!("{v:#x}"),
                                    addr: v,
                                    len: 128,
                                });
                            }
                        }
                        if ui.button("Copy value").clicked() {
                            ui.close_menu();
                            ui.output_mut(|o| o.copied_text = t.clone());
                        }
                    });
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Whole-image call graph
// ---------------------------------------------------------------------------

/// Whole-image call graph: pan (drag), zoom (scroll), draggable nodes,
/// RMB context menu, double-click opens the function.
#[allow(clippy::too_many_arguments)]
fn image_graph_pane(
    ui: &mut egui::Ui,
    l: &Loaded,
    sel: usize,
    zoom: &mut f32,
    pan: &mut egui::Vec2,
    fit: &mut bool,
    focus: &mut Option<usize>,
    offsets: &mut HashMap<usize, egui::Vec2>,
    drag: &mut Option<usize>,
    mode: &mut GraphMode,
    jump: &mut Option<usize>,
    open_code: &mut bool,
) {
    const W: f32 = 168.0;
    const H: f32 = 36.0;
    const GX: f32 = 44.0;
    const GY: f32 = 12.0;
    const M: f32 = 12.0;
    const PREV_LINES: usize = 6;
    const LINE_H: f32 = 12.0;

    let cg = &l.callgraph;
    let n = l.fns.len();
    let node_h = |zi: f32| {
        if zi >= 0.60 {
            H + PREV_LINES as f32 * LINE_H
        } else {
            H
        }
    };
    let base_pos = |i: usize| -> egui::Vec2 {
        egui::Vec2::new(
            M + cg.depth[i] as f32 * (W + GX),
            M + cg.row[i] as f32 * (H + GY),
        )
    };
    let pos = |offs: &HashMap<usize, egui::Vec2>, i: usize| -> egui::Vec2 {
        base_pos(i) + offs.get(&i).copied().unwrap_or_default()
    };
    let total_w = M + (cg.max_depth + 1) as f32 * (W + GX);
    let total_h = M + cg.col_len.iter().copied().max().unwrap_or(1) as f32 * (H + GY);

    let (rect, resp) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
    let p = ui.painter_at(rect);

    // Initial fit / focus.
    if *fit {
        *fit = false;
        *zoom = (rect.width() / total_w)
            .min(rect.height() / total_h)
            .clamp(0.03, 1.0);
        *pan = egui::Vec2::new(8.0, 8.0);
    }
    if let Some(fi) = *focus {
        *focus = None;
        if fi < n {
            *zoom = 1.0; // readable by default: preview text visible
            let c = pos(offsets, fi) + egui::vec2(W / 2.0, node_h(*zoom) / 2.0);
            *pan = rect.size() / 2.0 - c * *zoom;
        }
    }

    // Zoom around the pointer.
    if let Some(pointer) = resp.hover_pos() {
        let scroll_y = ui.input(|i| i.raw_scroll_delta.y);
        if scroll_y != 0.0 {
            let k = (scroll_y * 0.0015).clamp(-0.25, 0.25);
            let old = *zoom;
            *zoom = (*zoom * (1.0 + k)).clamp(0.03, 2.5);
            let rel = pointer - rect.min - *pan;
            let world = rel / old;
            *pan = pointer - rect.min - world * *zoom;
        }
    }

    let to_screen = |pan: egui::Vec2, zoom: f32, w: egui::Vec2| rect.min + pan + w * zoom;
    let clip = rect;

    // Hit test (world space).
    let pointer_world = resp.hover_pos().map(|h| (h - rect.min - *pan) / *zoom);
    let hit_at = |pw: Option<egui::Vec2>| -> Option<usize> {
        let pw = pw?;
        for i in 0..n {
            let r =
                egui::Rect::from_min_size(pos(offsets, i).to_pos2(), egui::vec2(W, node_h(*zoom)));
            if r.contains(pw.to_pos2()) {
                return Some(i);
            }
        }
        None
    };

    // Drag handling: node if a drag started on one, canvas pan otherwise.
    if resp.drag_started() {
        *drag = hit_at(pointer_world);
    }
    let mut panned = false;
    if let Some(dn) = *drag {
        if resp.dragged() {
            let e = offsets.entry(dn).or_default();
            *e += resp.drag_delta() / *zoom;
        }
    } else if resp.dragged() {
        *pan += resp.drag_delta();
        panned = true;
    }
    if resp.drag_stopped() {
        *drag = None;
    }
    let _ = panned;

    // Edges (caller -> callee), culled.
    let edge_color = Color32::from_rgba_unmultiplied(110, 118, 128, 140);
    if *zoom >= 0.08 {
        for (caller, callees_list) in &l.callees {
            let a = to_screen(
                *pan,
                *zoom,
                pos(offsets, *caller) + egui::vec2(W, node_h(*zoom) / 2.0),
            );
            for &t in callees_list {
                let b = to_screen(*pan, *zoom, pos(offsets, t));
                let b = egui::Pos2::new(b.x, b.y + node_h(*zoom) / 2.0);
                let bound = egui::Rect::from_min_max(a.min(b), a.max(b));
                if !clip.intersects(bound) {
                    continue;
                }
                let mid_x = (a.x + b.x) / 2.0;
                let shape = egui::epaint::CubicBezierShape {
                    points: [
                        a,
                        egui::Pos2::new(mid_x, a.y),
                        egui::Pos2::new(mid_x, b.y),
                        b,
                    ],
                    closed: false,
                    fill: Color32::TRANSPARENT,
                    stroke: egui::Stroke::new(1.0, edge_color).into(),
                };
                p.add(shape);
                let dir = if b.x > a.x { -1.0 } else { 1.0 };
                let tip = egui::Pos2::new(b.x + 5.0 * dir, b.y);
                let pts = vec![
                    tip,
                    egui::Pos2::new(b.x - 3.0 * dir, b.y - 3.5),
                    egui::Pos2::new(b.x - 3.0 * dir, b.y + 3.5),
                ];
                p.add(egui::Shape::convex_polygon(
                    pts,
                    edge_color,
                    egui::Stroke::NONE,
                ));
            }
        }
    }

    // Nodes, culled.
    for i in 0..n {
        let w0 = pos(offsets, i);
        let s0 = to_screen(*pan, *zoom, w0);
        let nh = node_h(*zoom);
        let srect = egui::Rect::from_min_size(s0, egui::vec2(W * *zoom, nh * *zoom));
        if !clip.intersects(srect) {
            continue;
        }
        let named = l.fns[i].name.is_some();
        let root = cg.depth[i] == 0;
        let bg = if i == sel {
            Color32::from_rgb(70, 62, 28)
        } else if named {
            Color32::from_rgb(44, 50, 60)
        } else {
            Color32::from_rgb(36, 40, 46)
        };
        p.rect_filled(srect, 2.0, bg);
        let border = if i == sel {
            C_FN
        } else if root {
            C_LBL
        } else {
            Color32::from_rgb(70, 78, 90)
        };
        p.rect_stroke(srect, 2.0, egui::Stroke::new(1.0, border));
        let z = *zoom;
        if z >= 0.30 {
            let label = l.fns[i].display_name();
            let label = if label.chars().count() > 22 {
                format!("{}…", label.chars().take(21).collect::<String>())
            } else {
                label.to_string()
            };
            let color = if named { C_FN } else { C_DIM };
            p.text(
                srect.left_top() + egui::vec2(4.0, 3.0) * z,
                egui::Align2::LEFT_TOP,
                label,
                egui::FontId::monospace(10.0 * z),
                color,
            );
        }
        if z >= 0.55 {
            let info = format!(
                "{} insns | calls {} | callers {}",
                l.fns[i].len(),
                l.callees.get(&i).map_or(0, Vec::len),
                l.callers.get(&i).map_or(0, Vec::len)
            );
            p.text(
                srect.left_top() + egui::vec2(4.0, 16.0) * z,
                egui::Align2::LEFT_TOP,
                info,
                egui::FontId::monospace(9.0 * z),
                C_DIM,
            );
        }
        if z >= 0.60 {
            // Function content preview: hex + disasm, IDA style.
            let f = &l.fns[i];
            let mut y = srect.top() + 30.0 * z;
            for ii in f.entry..(f.entry + PREV_LINES).min(f.end) {
                let line = l.lines.get(ii).map_or("", String::as_str);
                let text = format!("{:<15} {}", insn_bytes(&l.d.insns[ii]), line);
                let text = if text.chars().count() > 46 {
                    format!("{}…", text.chars().take(45).collect::<String>())
                } else {
                    text
                };
                p.text(
                    egui::Pos2::new(srect.left() + 4.0 * z, y),
                    egui::Align2::LEFT_TOP,
                    text,
                    egui::FontId::monospace(9.5 * z),
                    C_PLAIN,
                );
                y += LINE_H * z;
            }
        }

        // Per-node interaction: stable id => no flickering tooltip/menu.
        let f = &l.fns[i];
        let nresp = ui.interact(srect, egui::Id::new(("cgnode", i)), Sense::click());
        let tip = format!(
            "fn[{i}] {}\ninsns {}, callers {}, calls {}",
            f.display_name(),
            f.len(),
            l.callers.get(&i).map_or(0, Vec::len),
            l.callees.get(&i).map_or(0, Vec::len)
        );
        let nresp = nresp.on_hover_text(tip);
        if nresp.clicked() {
            *jump = Some(i);
        }
        if nresp.double_clicked() {
            *jump = Some(i);
            *open_code = true;
        }
        nresp.context_menu(|ui| {
            ui.label(format!("fn[{i}] {}", f.display_name()));
            if ui.button("Open in Code view").clicked() {
                ui.close_menu();
                *jump = Some(i);
                *open_code = true;
            }
            if ui.button("Show CFG").clicked() {
                ui.close_menu();
                *jump = Some(i);
                *mode = GraphMode::Cfg;
            }
            if ui.button("Center on this node").clicked() {
                ui.close_menu();
                *focus = Some(i);
            }
            if ui.button("Copy name").clicked() {
                ui.close_menu();
                ui.output_mut(|o| o.copied_text = f.display_name().to_string());
            }
        });
    }
}

// ---------------------------------------------------------------------------
// CFG canvas (fixed zoom, pan + draggable blocks, hex disasm nodes)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn cfg_canvas(
    ui: &mut egui::Ui,
    l: &Loaded,
    sel: usize,
    cfg: &qvm::CFG,
    pan: &mut egui::Vec2,
    zoom: &mut f32,
    fit: &mut bool,
    offsets: &mut HashMap<(usize, usize), egui::Vec2>,
    drag: &mut Option<usize>,
    scroll: &mut Option<usize>,
) {
    let n = cfg.blocks.len();
    if n == 0 {
        ui.label("(empty CFG)");
        return;
    }

    const LINE_H: f32 = 12.0;
    const W: f32 = 470.0;
    const GX: f32 = 70.0;
    const GY: f32 = 26.0;
    const M: f32 = 14.0;

    // Per-block rendered lines: header + insn rows with hex bytes.
    let block_lines: Vec<Vec<String>> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(bi, b)| {
            let mut v = vec![format!("B{bi} [{}..{})", b.start, b.end)];
            for ii in b.start..b.end {
                let hex = insn_bytes(&l.d.insns[ii]);
                let text = l.lines.get(ii).map_or(String::new(), |s| s.to_string());
                v.push(format!("{hex:<15} {text}"));
            }
            v
        })
        .collect();
    let heights: Vec<f32> = block_lines
        .iter()
        .map(|v| 6.0 + v.len() as f32 * LINE_H + 4.0)
        .collect();

    // BFS depth from the entry block (acyclic layering).
    let mut depth = vec![0usize; n];
    let mut seen = vec![false; n];
    seen[cfg.entry] = true;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(cfg.entry);
    while let Some(bi) = queue.pop_front() {
        for &s in &cfg.blocks[bi].succ {
            if s < n && !seen[s] {
                seen[s] = true;
                depth[s] = depth[bi] + 1;
                queue.push_back(s);
            }
        }
    }
    let park = depth.iter().copied().max().unwrap_or(0) + 1;
    for (bi, s) in seen.iter().enumerate() {
        if !s {
            depth[bi] = park;
        }
    }

    // Base positions: stacked rows per column, variable heights.
    let mut base = vec![egui::Vec2::ZERO; n];
    let mut col_y: Vec<f32> = vec![M; depth.iter().copied().max().unwrap_or(0) + 1];
    for bi in 0..n {
        let d = depth[bi];
        base[bi] = egui::Vec2::new(M + d as f32 * (W + GX), col_y[d]);
        col_y[d] += heights[bi] + GY;
    }
    let total_w = M + (depth.iter().copied().max().unwrap_or(0) + 1) as f32 * (W + GX);
    let total_h = col_y.iter().copied().fold(M, f32::max);

    let pos = |offs: &HashMap<(usize, usize), egui::Vec2>, bi: usize| -> egui::Vec2 {
        base[bi] + offs.get(&(sel, bi)).copied().unwrap_or_default()
    };

    let (rect, resp) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
    let p = ui.painter_at(rect);

    // Fit: zoom so the whole CFG is visible, top-left anchored.
    if *fit {
        *fit = false;
        *zoom = (rect.width() / total_w)
            .min(rect.height() / total_h)
            .clamp(0.15, 1.5);
        *pan = egui::Vec2::new(8.0, 8.0);
    }

    // Wheel = zoom around the pointer.
    if let Some(pointer) = resp.hover_pos() {
        let scroll_y = ui.input(|i| i.raw_scroll_delta.y);
        if scroll_y != 0.0 {
            let k = (scroll_y * 0.0015).clamp(-0.25, 0.25);
            let old = *zoom;
            *zoom = (*zoom * (1.0 + k)).clamp(0.15, 2.5);
            let rel = pointer - rect.min - *pan;
            let world = rel / old;
            *pan = pointer - rect.min - world * *zoom;
        }
    }

    // Hit test.
    let pointer_world = resp.hover_pos().map(|h| (h - rect.min - *pan) / *zoom);
    let hit_at = |pw: Option<egui::Vec2>| -> Option<usize> {
        let pw = pw?;
        for (bi, h) in heights.iter().enumerate() {
            let r = egui::Rect::from_min_size(pos(offsets, bi).to_pos2(), egui::vec2(W, *h));
            if r.contains(pw.to_pos2()) {
                return Some(bi);
            }
        }
        None
    };

    // Drag: node if started on one, canvas pan otherwise.
    if resp.drag_started() {
        *drag = hit_at(pointer_world);
    }
    if let Some(dn) = *drag {
        if resp.dragged() {
            let e = offsets.entry((sel, dn)).or_default();
            *e += resp.drag_delta() / *zoom;
        }
    } else if resp.dragged() {
        *pan += resp.drag_delta();
    }
    if resp.drag_stopped() {
        *drag = None;
    }

    let to_screen = |pan: egui::Vec2, zoom: f32, w: egui::Vec2| rect.min + pan + w * zoom;

    // Edge label: branch op name for taken edges, "ft" for fallthrough.
    let edge_label = |bi: usize, s: usize| -> String {
        let b = &cfg.blocks[bi];
        if s == b.end {
            return "ft".into();
        }
        for ii in b.start..b.end {
            let ins = &l.d.insns[ii];
            if ins.op.is_branch() {
                if let Some(t) = ins.target {
                    if t == s {
                        return ins.op.name().to_string();
                    }
                }
            }
        }
        "jmp".into()
    };

    // Edges first (under the nodes).
    for (bi, b) in cfg.blocks.iter().enumerate() {
        for &s in &b.succ {
            if s >= n {
                continue;
            }
            let a = to_screen(
                *pan,
                *zoom,
                pos(offsets, bi) + egui::Vec2::new(W, heights[bi] / 2.0),
            );
            let bpt = to_screen(*pan, *zoom, pos(offsets, s));
            let bpt = egui::Pos2::new(bpt.x, bpt.y + heights[s] / 2.0 * *zoom);
            let bound = egui::Rect::from_min_max(a.min(bpt), a.max(bpt));
            if !rect.intersects(bound) {
                continue;
            }
            let lbl = edge_label(bi, s);
            let color = if lbl == "ft" {
                Color32::from_rgb(90, 150, 110)
            } else if depth[s] <= depth[bi] {
                Color32::from_rgb(180, 120, 60)
            } else {
                Color32::from_rgb(110, 118, 128)
            };
            let mid_x = (a.x + bpt.x) / 2.0;
            let shape = egui::epaint::CubicBezierShape {
                points: [
                    a,
                    egui::Pos2::new(mid_x, a.y),
                    egui::Pos2::new(mid_x, bpt.y),
                    bpt,
                ],
                closed: false,
                fill: Color32::TRANSPARENT,
                stroke: egui::Stroke::new((1.2 * *zoom).max(0.5), color).into(),
            };
            p.add(shape);
            let dir = if bpt.x > a.x { -1.0 } else { 1.0 };
            let tip = egui::Pos2::new(bpt.x + 5.0 * dir * *zoom, bpt.y);
            let pts = vec![
                tip,
                egui::Pos2::new(bpt.x - 3.0 * dir * *zoom, bpt.y - 3.5 * *zoom),
                egui::Pos2::new(bpt.x - 3.0 * dir * *zoom, bpt.y + 3.5 * *zoom),
            ];
            p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
            // Condition label at the curve midpoint.
            let mid = egui::Pos2::new(
                (a.x + 3.0 * mid_x + 3.0 * mid_x + bpt.x) / 8.0,
                (a.y + 3.0 * a.y + 3.0 * bpt.y + bpt.y) / 8.0,
            );
            let galley = p.layout_no_wrap(lbl.clone(), egui::FontId::monospace(9.5 * *zoom), color);
            let gsize = galley.size();
            let bg = egui::Rect::from_center_size(mid, gsize + egui::vec2(6.0, 2.0));
            p.rect_filled(bg, 2.0, Color32::from_rgb(24, 26, 30));
            p.galley(mid - gsize / 2.0, galley, color);
        }
    }

    // Nodes: full disasm with hex bytes, draggable.
    for (bi, b) in cfg.blocks.iter().enumerate() {
        let s0 = to_screen(*pan, *zoom, pos(offsets, bi));
        let r = egui::Rect::from_min_size(s0, egui::vec2(W * *zoom, heights[bi] * *zoom));
        if !rect.intersects(r) {
            continue;
        }
        p.rect_filled(r, 3.0, Color32::from_rgb(38, 42, 50));
        p.rect_stroke(r, 3.0, egui::Stroke::new(1.0, C_LBL));
        let z = *zoom;
        let mut y = r.top() + 3.0 * z;
        for (li, line) in block_lines[bi].iter().enumerate() {
            let color = if li == 0 { C_LBL } else { C_PLAIN };
            p.text(
                egui::Pos2::new(r.left() + 6.0 * z, y),
                egui::Align2::LEFT_TOP,
                line,
                egui::FontId::monospace(10.0 * z),
                color,
            );
            y += LINE_H * z;
        }

        let node_resp = ui.interact(r, egui::Id::new(("gnode", sel, bi)), Sense::click());
        if node_resp.hovered() {
            p.rect_stroke(r, 3.0, egui::Stroke::new(1.8, C_FN));
        }
        if node_resp.clicked() {
            *scroll = Some(b.start);
        }
        node_resp.context_menu(|ui| {
            ui.label(format!("B{bi} [{}..{})", b.start, b.end));
            if ui.button("Scroll Disassembly here").clicked() {
                ui.close_menu();
                *scroll = Some(b.start);
            }
            if ui.button("Copy insn range").clicked() {
                ui.close_menu();
                ui.output_mut(|o| o.copied_text = format!("{}..{}", b.start, b.end));
            }
        });
    }
}
