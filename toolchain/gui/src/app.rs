//! egui frontend: function list | disasm | identity C | CFG graph.
//!
//! UI closures only READ from `Loaded`; every action (jump / scroll / hover)
//! is collected into locals and applied after the panels are built. That
//! keeps borrows disjoint and egui happy.

use std::collections::{HashMap, HashSet};

use eframe::egui;
use egui::{Color32, RichText, Sense, TextWrapMode};

use crate::state::Loaded;

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
    /// Known function name -> fn index (clickable).
    FnTok(String, usize),
    /// Basic-block label `L<n>` -> insn index (clickable, scrolls disasm).
    LblTok(String, usize),
}

/// Shared immutable view over `Loaded` maps used by the tokenizers.
struct Tok<'a> {
    names: &'a HashMap<String, usize>,
    traps: &'a HashSet<String>,
    entries: &'a HashMap<usize, usize>,
}

pub struct App {
    loaded: Option<Loaded>,
    path_edit: String,
    filter: String,
    selected: Option<usize>,
    c_cache: HashMap<usize, String>,
    rename_buf: String,
    status: String,
    tab: BottomTab,
    center: CenterTab,
    graph_mode: GraphMode,
    /// Call-graph view transform (world -> screen: `scr = pan + world * zoom`).
    graph_zoom: f32,
    graph_pan: egui::Vec2,
    /// Fit the call graph to the window on first show after load.
    graph_fit: bool,
    /// Pending scroll request for the disasm pane (insn index).
    scroll_to: Option<usize>,
    /// Cross-pane highlight state, kept between frames.
    hover_fn: Option<usize>,
    hover_tok: Option<String>,
    /// Navigation history (back / forward), like IDA's Alt+Left/Right.
    hist: Vec<usize>,
    hist_fwd: Vec<usize>,
    /// Pending "center call graph on this function" request.
    graph_focus: Option<usize>,
}

impl App {
    pub fn new(initial: Option<String>) -> Self {
        let mut app = App {
            loaded: None,
            path_edit: initial.unwrap_or_default(),
            filter: String::new(),
            selected: None,
            c_cache: HashMap::new(),
            rename_buf: String::new(),
            status: "open a .qvm (button, path field, or drag & drop)".into(),
            tab: BottomTab::Strings,
            center: CenterTab::Code,
            graph_mode: GraphMode::Image,
            graph_zoom: 1.0,
            graph_pan: egui::Vec2::ZERO,
            graph_fit: true,
            scroll_to: None,
            hover_fn: None,
            hover_tok: None,
            hist: Vec::new(),
            hist_fwd: Vec::new(),
            graph_focus: None,
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
                self.hover_tok = None;
                self.graph_fit = true;
                self.hist.clear();
                self.hist_fwd.clear();
                self.graph_focus = Some(l.entry_fn());
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
        let kb_free = !ctx.wants_keyboard_input();
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
    }
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
                let mut name = l
                    .fns
                    .get(sel)
                    .and_then(|f| f.name.clone())
                    .unwrap_or_else(|| format!("fn{sel}"));
                name = name
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
                match std::fs::write(&out, &text) {
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
        let jump: Option<usize> = None;
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // ---- File ------------------------------------------------
                ui.menu_button("File", |ui| {
                    if ui.button("Open (path field)").clicked() {
                        ui.close_menu();
                        let p = self.path_edit.clone();
                        self.load_path(&p);
                    }
                    if ui.button("Reload (F5)").clicked() {
                        ui.close_menu();
                        let p = self.path_edit.clone();
                        self.load_path(&p);
                    }
                    if ui.button("Save .map (Ctrl+S)").clicked() {
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
                    if ui.button("Back (Backspace / Alt+Left)").clicked() {
                        ui.close_menu();
                        self.go_back();
                    }
                    if ui.button("Forward (Alt+Right)").clicked() {
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
                    if ui.button("Graph: center on vmMain (Home)").clicked() {
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
                    if ui.button("Graph: zoom in (+)").clicked() {
                        ui.close_menu();
                        self.graph_zoom = (self.graph_zoom * 1.3).clamp(0.03, 2.5);
                    }
                    if ui.button("Graph: zoom out (-)").clicked() {
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

                // ---- path field + status --------------------------------
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
                    .add_enabled(self.loaded.is_some(), egui::Button::new("vmMain (Home)"))
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
                    .add_enabled(
                        !self.hist.is_empty(),
                        egui::Button::new("< Back (Backspace)"),
                    )
                    .clicked()
                {
                    self.go_back();
                }
                if ui
                    .add_enabled(
                        !self.hist_fwd.is_empty(),
                        egui::Button::new("Forward (Alt+Right) >"),
                    )
                    .clicked()
                {
                    self.go_forward();
                }
                ui.colored_label(egui::Color32::LIGHT_BLUE, &self.status);
            });
        });
        if let Some(j) = jump {
            self.jump_to(j, true);
        }
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
                        let n = l.lit_strings.len();
                        egui::ScrollArea::vertical()
                            .id_salt("strings")
                            .auto_shrink([false, false])
                            .show_rows(ui, mono_h, n, |ui, rows| {
                                for r in rows {
                                    let (addr, s) = &l.lit_strings[r];
                                    let users = l.string_refs.get(addr).map_or(0, Vec::len);
                                    let txt = format!("@{addr}  \"{s}\"  ({users} refs)");
                                    if ui.selectable_label(false, txt).clicked() {
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

            // Rename row above the panes + center-tab selector.
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
                    self.c_cache.remove(&sel);
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
            });

            ui.separator();

            // Decompiled C (cache miss -> decompile now, sequential borrows).
            let text = match self.c_cache.get(&sel) {
                Some(t) => t.clone(),
                None => {
                    let t = match self.loaded.as_ref().unwrap().decompile(sel) {
                        Ok(s) => s,
                        Err(e) => format!("// decompile error: {e}\n"),
                    };
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
            let fn_ranges: Vec<(usize, usize)> = l.fns.iter().map(|f| (f.entry, f.end)).collect();
            let cfg_res = match self.center {
                CenterTab::Graph => Some(l.cfg(sel)),
                CenterTab::Code => None,
            };

            // Locals collected inside the panes; applied after building.
            let mut jump_loc: Option<usize> = None;
            let mut open_code = false;
            let scroll_req: Option<usize> = self.scroll_to.take();
            let mut pending_scroll: Option<usize> = None;
            let hover_fn_prev = self.hover_fn;
            let hover_tok_prev = self.hover_tok.clone();
            let mut new_hover_fn: Option<usize> = None;
            let mut new_hover_tok: Option<String> = None;

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
                    sa.show_rows(&mut cols[0], mono_h, range.len(), |ui, rows| {
                        for i in rows {
                            let ii = range.start + i;
                            paint_row_bg(
                                ui,
                                mono_h,
                                cross_tint_insn(ii, hover_fn_prev, &fn_ranges),
                            );
                            let segs = d_segments(&l.lines[ii], &tok);
                            render_segs_disasm(
                                ui,
                                &segs,
                                &mut jump_loc,
                                &mut pending_scroll,
                                &mut new_hover_tok,
                            );
                        }
                    });

                    // ---- right: decompiled C -------------------------------
                    cols[1].heading("Identity C");
                    let c_rows: Vec<&str> = text.lines().collect();
                    egui::ScrollArea::vertical()
                        .id_salt("decomp")
                        .auto_shrink([false, false])
                        .show_rows(&mut cols[1], mono_h, c_rows.len(), |ui, rows| {
                            for i in rows {
                                let line = c_rows[i];
                                let tint = hover_tok_prev
                                    .as_ref()
                                    .and_then(|t| token_in_line(line, t).then_some(TINT_HOVER));
                                paint_row_bg(ui, mono_h, tint);
                                let segs = c_segments(line, &tok);
                                render_segs_c(
                                    ui,
                                    &segs,
                                    &mut jump_loc,
                                    &mut pending_scroll,
                                    &mut new_hover_fn,
                                );
                            }
                        });
                }),
                CenterTab::Graph => {
                    ui.horizontal(|ui| {
                        ui.label("Graph:");
                        if ui
                            .selectable_label(self.graph_mode == GraphMode::Image, "Image")
                            .clicked()
                        {
                            self.graph_mode = GraphMode::Image;
                        }
                        if ui
                            .selectable_label(
                                self.graph_mode == GraphMode::Cfg,
                                format!("Cfg fn[{sel}]"),
                            )
                            .clicked()
                        {
                            self.graph_mode = GraphMode::Cfg;
                        }
                        ui.separator();
                        if self.graph_mode == GraphMode::Image {
                            ui.monospace(format!(
                                "whole image: {} functions, {} roots — drag to pan, scroll to zoom, click to select, double-click to open",
                                l.fns.len(),
                                l.callgraph.roots.len()
                            ));
                        } else {
                            ui.monospace("click a block to scroll Disassembly");
                        }
                    });
                    ui.separator();
                    match self.graph_mode {
                        GraphMode::Image => image_graph_pane(
                            ui,
                            l,
                            sel,
                            &mut self.graph_zoom,
                            &mut self.graph_pan,
                            &mut self.graph_fit,
                            &mut self.graph_focus,
                            &mut pending_scroll,
                            &mut jump_loc,
                            &mut open_code,
                        ),
                        GraphMode::Cfg => match cfg_res {
                            Some(Ok(cfg)) => {
                                graph_pane(ui, l, sel, &cfg, &mut pending_scroll, &mut jump_loc)
                            }
                            Some(Err(e)) => {
                                ui.colored_label(Color32::LIGHT_RED, format!("CFG error: {e}"));
                            }
                            None => unreachable!("graph tab implies cfg"),
                        },
                    }
                }
            }

            // Apply collected actions.
            self.hover_fn = new_hover_fn;
            self.hover_tok = new_hover_tok;
            self.scroll_to = pending_scroll;
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

fn token_in_line(line: &str, tok: &str) -> bool {
    // Word-boundary aware containment so "printf" does not match "sprintf".
    line.match_indices(tok).any(|(p, _)| {
        let before = line[..p].chars().next_back();
        let after = line[p + tok.len()..].chars().next();
        let ok = |c: Option<char>| c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        ok(before) && ok(after)
    })
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

    for w in code.split_whitespace() {
        if w.starts_with("->#") {
            out.push(Seg::P(w.to_string(), C_TGT));
        } else if w.starts_with('#') || w.starts_with('@') {
            out.push(Seg::P(w.to_string(), C_DIM));
        } else if w.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            && w.chars().any(char::is_alphabetic)
        {
            out.push(Seg::P(w.to_string(), C_LBL)); // opcode mnemonic
        } else if is_num(w) {
            out.push(Seg::P(w.to_string(), C_NUM));
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
            match rest[1..].find('"') {
                Some(b) => {
                    out.push(Seg::P(rest[..b + 2].to_string(), C_STR));
                    out.push(Seg::P(rest[b + 2..].to_string(), C_CMT));
                }
                None => out.push(Seg::P(rest.to_string(), C_STR)),
            }
        } else {
            for w in inner.split_whitespace() {
                if w == "syscall" || w == "call" {
                    out.push(Seg::P(format!("{w} "), C_CMT));
                } else if let Some(digits) = w.strip_suffix(',') {
                    if digits.parse::<u32>().is_ok() || digits.parse::<i64>().is_ok() {
                        out.push(Seg::P(format!("{digits} "), C_NUM));
                    } else {
                        out.push(Seg::P(format!("{w} "), C_CMT));
                    }
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
            let w = &t[st..i];
            classify_ident(w, tok, &mut out);
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
// Segment rendering
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
fn render_row(ui: &mut egui::Ui, segs: &[Seg], on_tok: &mut impl FnMut(&egui::Response, &Seg)) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for s in segs {
            match s {
                Seg::P(t, c) => plain_label(ui, t, *c),
                Seg::LblTok(t, _) => {
                    let r = tok_label(ui, t, C_LBL);
                    on_tok(&r, s);
                }
                Seg::FnTok(t, _) => {
                    let r = tok_label(ui, t, C_FN);
                    on_tok(&r, s);
                }
            }
        }
    });
}

fn render_segs_disasm(
    ui: &mut egui::Ui,
    segs: &[Seg],
    jump: &mut Option<usize>,
    scroll: &mut Option<usize>,
    hover_tok: &mut Option<String>,
) {
    let mut jump_out = None;
    render_row(ui, segs, &mut |r, s| {
        if let Seg::FnTok(t, idx) = s {
            if r.hovered() {
                *hover_tok = Some(t.clone());
            }
            if r.double_clicked() {
                jump_out = Some(*idx);
            }
        }
    });
    if jump_out.is_some() {
        *jump = jump_out;
    }
    let _ = scroll;
}

fn render_segs_c(
    ui: &mut egui::Ui,
    segs: &[Seg],
    jump: &mut Option<usize>,
    scroll: &mut Option<usize>,
    hover_fn: &mut Option<usize>,
) {
    let mut jump_out = None;
    let mut scroll_out = None;
    render_row(ui, segs, &mut |r, s| match s {
        Seg::FnTok(_, idx) => {
            if r.hovered() {
                *hover_fn = Some(*idx);
            }
            if r.double_clicked() {
                jump_out = Some(*idx);
            }
        }
        Seg::LblTok(_, n) => {
            if r.clicked() {
                scroll_out = Some(*n);
            }
        }
        Seg::P(_, _) => {}
    });
    if jump_out.is_some() {
        *jump = jump_out;
    }
    if scroll_out.is_some() {
        *scroll = scroll_out;
    }
}

// ---------------------------------------------------------------------------
// Whole-image call graph
// ---------------------------------------------------------------------------

/// Whole-image call graph: pan (drag), zoom (scroll), click to select,
/// double-click to open the function in the Code view.
#[allow(clippy::too_many_arguments)]
fn image_graph_pane(
    ui: &mut egui::Ui,
    l: &Loaded,
    sel: usize,
    zoom: &mut f32,
    pan: &mut egui::Vec2,
    fit: &mut bool,
    focus: &mut Option<usize>,
    scroll: &mut Option<usize>,
    jump: &mut Option<usize>,
    open_code: &mut bool,
) {
    const W: f32 = 168.0;
    const H: f32 = 36.0;
    const GX: f32 = 44.0;
    const GY: f32 = 12.0;
    const M: f32 = 12.0;

    let cg = &l.callgraph;
    let n = l.fns.len();
    // World-space node positions.
    let pos = |i: usize| -> egui::Vec2 {
        egui::Vec2::new(
            M + cg.depth[i] as f32 * (W + GX),
            M + cg.row[i] as f32 * (H + GY),
        )
    };
    let total_w = M + (cg.max_depth + 1) as f32 * (W + GX);
    let total_h = M + cg.col_len.iter().copied().max().unwrap_or(1) as f32 * (H + GY);

    let (rect, resp) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());

    // Initial fit: zoom so the whole image is visible.
    if *fit {
        *fit = false;
        let fit_w = rect.width() / total_w;
        let fit_h = rect.height() / total_h;
        *zoom = fit_w.min(fit_h).clamp(0.03, 1.0);
        *pan = egui::Vec2::new(8.0, 8.0);
    }
    // Center on the requested function (vmMain on start, Home button later).
    if let Some(fi) = *focus {
        *focus = None;
        if fi < n {
            *zoom = (*zoom).clamp(0.55, 1.2);
            let c = pos(fi) + egui::vec2(W / 2.0, H / 2.0);
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
    // Pan by drag.
    if resp.dragged() {
        *pan += resp.drag_delta();
    }

    let to_screen = |w: egui::Vec2| rect.min + *pan + w * *zoom;
    let clip = ui.clip_rect();

    let p = ui.painter();

    // Edges (caller -> callee), culled.
    let edge_color = Color32::from_rgba_unmultiplied(110, 118, 128, 140);
    if *zoom >= 0.08 {
        for (caller, callees_list) in &l.callees {
            let a = to_screen(pos(*caller) + egui::vec2(W, H / 2.0));
            for &t in callees_list {
                let b = to_screen(pos(t));
                let b = egui::Pos2::new(b.x, b.y + H / 2.0);
                let lo = a.min(b);
                let hi = a.max(b);
                let bound = egui::Rect::from_min_max(lo, hi);
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
            }
        }
    }

    // Nodes, culled; hit-testing.
    let mut hit: Option<usize> = None;
    let pointer_world = resp.hover_pos().map(|h| (h - rect.min - *pan) / *zoom);
    for i in 0..n {
        let w0 = pos(i);
        let s0 = to_screen(w0);
        let srect = egui::Rect::from_min_size(s0, egui::vec2(W * *zoom, H * *zoom));
        if !clip.intersects(srect) {
            continue;
        }
        if let Some(pw) = pointer_world {
            let wrect = egui::Rect::from_min_size(w0.to_pos2(), egui::vec2(W, H));
            if wrect.contains(pw.to_pos2()) {
                hit = Some(i);
            }
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
        if *zoom >= 0.30 {
            let label = l.fns[i].display_name();
            let label = if label.chars().count() > 22 {
                format!("{}…", label.chars().take(21).collect::<String>())
            } else {
                label.to_string()
            };
            let color = if named { C_FN } else { C_DIM };
            p.text(
                srect.left_top() + egui::vec2(4.0, 3.0),
                egui::Align2::LEFT_TOP,
                label,
                egui::FontId::monospace(10.0),
                color,
            );
        }
        if *zoom >= 0.55 {
            let info = format!(
                "{} insns | calls {} | callers {}",
                l.fns[i].len(),
                l.callees.get(&i).map_or(0, Vec::len),
                l.callers.get(&i).map_or(0, Vec::len)
            );
            p.text(
                srect.left_bottom() + egui::vec2(4.0, -4.0),
                egui::Align2::LEFT_BOTTOM,
                info,
                egui::FontId::monospace(9.0),
                C_DIM,
            );
        }
    }

    // Hover tooltip + click handling.
    if let Some(h) = hit {
        let f = &l.fns[h];
        let tip = format!(
            "fn[{h}] {}\ninsns {}, callers {}, calls {}",
            f.display_name(),
            f.len(),
            l.callers.get(&h).map_or(0, Vec::len),
            l.callees.get(&h).map_or(0, Vec::len)
        );
        let resp = resp
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_ui(|ui| {
                ui.monospace(tip);
            });
        if resp.clicked() {
            *jump = Some(h);
        }
        if resp.double_clicked() {
            *jump = Some(h);
            *open_code = true;
        }
    }
    let _ = scroll;
}

// ---------------------------------------------------------------------------
// CFG graph pane
// ---------------------------------------------------------------------------

fn graph_pane(
    ui: &mut egui::Ui,
    l: &Loaded,
    sel: usize,
    cfg: &qvm::CFG,
    scroll: &mut Option<usize>,
    jump: &mut Option<usize>,
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

    // Per-block rendered lines: `B{bi} [start,end)` header + insn rows
    // with hex bytes, IDA style.
    let block_lines: Vec<Vec<String>> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(bi, b)| {
            let mut v = vec![format!("B{bi} [{}..{})", b.start, b.end)];
            for ii in b.start..b.end {
                let hex = crate::state::insn_bytes(&l.d.insns[ii]);
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
    // Unreachable blocks (defensive): park them one past the deepest layer.
    let max_depth = depth.iter().copied().max().unwrap_or(0);
    let park = max_depth + 1;
    for (bi, s) in seen.iter().enumerate() {
        if !s {
            depth[bi] = park;
        }
    }

    // Positions: stacked rows per column, variable heights.
    let mut pos = vec![egui::Pos2::ZERO; n];
    let mut col_y: Vec<f32> = vec![M; depth.iter().copied().max().unwrap_or(0) + 1];
    for bi in 0..n {
        let d = depth[bi];
        pos[bi] = egui::Pos2::new(M + d as f32 * (W + GX), col_y[d]);
        col_y[d] += heights[bi] + GY;
    }
    let total_w = M + (depth.iter().copied().max().unwrap_or(0) + 1) as f32 * (W + GX);
    let total_h = col_y.iter().copied().fold(M, f32::max);

    ui.monospace(format!(
        "CFG fn[{sel}] {} ({} blocks) — click a block to scroll Disassembly",
        l.fns.get(sel).map_or("?", |f| f.display_name()),
        n
    ));

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

    egui::ScrollArea::both()
        .id_salt("cfggraph")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let (_rect, _) = ui.allocate_exact_size(egui::vec2(total_w, total_h), Sense::click());
            let p = ui.painter();

            // Edges first (under the nodes).
            for (bi, b) in cfg.blocks.iter().enumerate() {
                for &s in &b.succ {
                    if s >= n {
                        continue;
                    }
                    let from = egui::Pos2::new(pos[bi].x + W, pos[bi].y + heights[bi] / 2.0);
                    let to = egui::Pos2::new(pos[s].x, pos[s].y + heights[s] / 2.0);
                    let back = depth[s] <= depth[bi];
                    let color = if back {
                        Color32::from_rgb(180, 120, 60)
                    } else if edge_label(bi, s) == "ft" {
                        Color32::from_rgb(90, 150, 110)
                    } else {
                        Color32::from_rgb(110, 118, 128)
                    };
                    let mid_x = (from.x + to.x) / 2.0;
                    let shape = egui::epaint::CubicBezierShape {
                        points: [
                            from,
                            egui::Pos2::new(mid_x, from.y),
                            egui::Pos2::new(mid_x, to.y),
                            to,
                        ],
                        closed: false,
                        fill: Color32::TRANSPARENT,
                        stroke: egui::Stroke::new(1.2, color).into(),
                    };
                    p.add(shape);
                    // Arrowhead.
                    let dir = if to.x > from.x { -1.0 } else { 1.0 };
                    let tip = egui::Pos2::new(to.x + 5.0 * dir, to.y);
                    let pts = vec![
                        tip,
                        egui::Pos2::new(to.x - 3.0 * dir, to.y - 3.5),
                        egui::Pos2::new(to.x - 3.0 * dir, to.y + 3.5),
                    ];
                    p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
                    // Condition label at the curve midpoint.
                    let mid = egui::Pos2::new(
                        (from.x + 3.0 * mid_x + 3.0 * mid_x + to.x) / 8.0,
                        (from.y + 3.0 * from.y + 3.0 * to.y + to.y) / 8.0,
                    );
                    let lbl = edge_label(bi, s);
                    let galley = p.layout_no_wrap(lbl.clone(), egui::FontId::monospace(9.5), color);
                    let gsize = galley.size();
                    let bg = egui::Rect::from_center_size(mid, gsize + egui::vec2(6.0, 2.0));
                    p.rect_filled(bg, 2.0, Color32::from_rgb(24, 26, 30));
                    p.galley(mid - gsize / 2.0, galley, color);
                }
            }

            // Nodes: full disasm with hex bytes, IDA style.
            for (bi, b) in cfg.blocks.iter().enumerate() {
                let r = egui::Rect::from_min_size(pos[bi], egui::vec2(W, heights[bi]));
                p.rect_filled(r, 3.0, Color32::from_rgb(38, 42, 50));
                p.rect_stroke(r, 3.0, egui::Stroke::new(1.0, C_LBL));
                let mut y = r.top() + 3.0;
                for (li, line) in block_lines[bi].iter().enumerate() {
                    let color = if li == 0 { C_LBL } else { C_PLAIN };
                    p.text(
                        egui::Pos2::new(r.left() + 6.0, y),
                        egui::Align2::LEFT_TOP,
                        line,
                        egui::FontId::monospace(10.0),
                        color,
                    );
                    y += LINE_H;
                }

                let resp = ui.interact(r, egui::Id::new(("gnode", sel, bi)), Sense::click());
                if resp.hovered() {
                    p.rect_stroke(r, 3.0, egui::Stroke::new(1.8, C_FN));
                }
                if resp.clicked() {
                    *scroll = Some(b.start);
                }
                if resp.double_clicked() {
                    *jump = Some(sel);
                }
            }
        });
}
