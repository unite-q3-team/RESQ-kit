//! egui frontend: function list | disasm | identity C | call graph | CFG.
//!
//! UI closures only READ from `Loaded`; every action (jump / scroll / hover /
//! hex dump / tab switch) is collected into locals and applied after the
//! panels are built. That keeps borrows disjoint and egui happy.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use eframe::egui;
use egui::{Color32, RichText, Sense, TextWrapMode};

use crate::state::{escape, insn_bytes, opcode_help, Decompiled, Loaded};

/// Keep at most this many decompiled functions cached (FIFO eviction).
const C_CACHE_CAP: usize = 128;

/// Duration of the flash highlight after a jump, seconds.
const FLASH_SECS: f32 = 0.9;

#[derive(Clone, Copy, Default, PartialEq)]
enum BottomTab {
    #[default]
    Strings,
    Traps,
    Xrefs,
    Bss,
    Info,
}

#[derive(Clone, Copy, PartialEq)]
enum CenterTab {
    Code,
    /// Disassembly graph: CFG of the selected function (IF/branches).
    DGraph,
    /// Whole-image call graph.
    Graph,
}

/// Request for the floating memory hex-dump window.
#[derive(Clone)]
struct HexReq {
    title: String,
    addr: i32,
    len: usize,
}

/// Shared pan / zoom / fit state for a graph canvas.
#[derive(Clone, Copy)]
struct Cam {
    pan: egui::Vec2,
    zoom: f32,
    /// Fit the whole graph to the window on the next frame.
    fit: bool,
}

impl Default for Cam {
    fn default() -> Self {
        Self {
            pan: egui::Vec2::ZERO,
            zoom: 1.0,
            fit: true,
        }
    }
}

impl Cam {
    /// Consume a pending fit request: zoom so `total` world units fill `rect`.
    fn begin_fit(&mut self, rect: &egui::Rect, total: egui::Vec2, lo: f32, hi: f32) {
        if !self.fit {
            return;
        }
        self.fit = false;
        self.zoom = (rect.width() / total.x)
            .min(rect.height() / total.y)
            .clamp(lo, hi);
        self.pan = egui::Vec2::new(8.0, 8.0);
    }

    /// Wheel zoom anchored at the pointer.
    fn wheel_zoom(
        &mut self,
        resp: &egui::Response,
        rect: &egui::Rect,
        delta: f32,
        lo: f32,
        hi: f32,
    ) {
        let Some(pointer) = resp.hover_pos() else {
            return;
        };
        if delta == 0.0 {
            return;
        }
        let k = (delta * 0.0015).clamp(-0.25, 0.25);
        let old = self.zoom;
        self.zoom = (old * (1.0 + k)).clamp(lo, hi);
        let world = (pointer - rect.min - self.pan) / old;
        self.pan = pointer - rect.min - world * self.zoom;
    }

    /// World -> screen transform.
    fn to_screen(self, rect_min: egui::Pos2, w: egui::Vec2) -> egui::Pos2 {
        rect_min + self.pan + w * self.zoom
    }
}

/// Cached filtered rows of the function list: `(needle, generation, rows)`.
type FnRowsCache = Option<(String, u64, Arc<Vec<(usize, String)>>)>;

// ---------------------------------------------------------------------------
// Syntax palette (dark-theme friendly)
// ---------------------------------------------------------------------------
const C_PLAIN: Color32 = Color32::from_rgb(208, 212, 218);
const C_DIM: Color32 = Color32::from_rgb(146, 154, 164);
const C_KW: Color32 = Color32::from_rgb(198, 120, 221);
const C_NUM: Color32 = Color32::from_rgb(209, 154, 102);
const C_STR: Color32 = Color32::from_rgb(152, 195, 121);
const C_CMT: Color32 = Color32::from_rgb(132, 141, 151);
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
    /// Insn to flash-highlight after scrolling (goto / C-line click).
    flash: &'a mut Option<usize>,
    /// Label insn clicked in Identity C: scroll C pane to `L<n>:` + flash.
    c_goto: &'a mut Option<usize>,
}

pub struct App {
    loaded: Option<Loaded>,
    path_edit: String,
    filter: String,
    strings_filter: String,
    bss_filter: String,
    selected: Option<usize>,
    c_cache: HashMap<usize, Arc<Decompiled>>,
    /// Insertion order for FIFO eviction of `c_cache`.
    c_order: VecDeque<usize>,
    rename_buf: String,
    status: String,
    tab: BottomTab,
    center: CenterTab,
    /// Call-graph canvas camera.
    cam_graph: Cam,
    /// CFG canvas camera.
    cam_cfg: Cam,
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
    /// Hovered Identity C line -> insn range tinted in Disassembly.
    c_hover_range: Option<(usize, usize)>,
    /// Recently jumped-to insn: flash-highlight with fade-out.
    flash: Option<(usize, std::time::Instant)>,
    /// Identity C pane: scroll to this line + flash it (goto navigation).
    c_scroll_line: Option<usize>,
    c_flash: Option<(usize, std::time::Instant)>,
    /// Measured world-space widths of call-graph nodes (content-sized).
    img_w: HashMap<usize, f32>,
    img_colw: Vec<f32>,
    /// Navigation history (back / forward), bounded.
    hist: Vec<usize>,
    hist_fwd: Vec<usize>,
    /// Scroll sync between Disasm and Identity C.
    sync_scroll: bool,
    sync_to_d: Option<f32>,
    sync_to_c: Option<f32>,
    prev_d: f32,
    prev_c: f32,
    /// Floating memory hex-dump windows (one per requested address).
    hex_windows: Vec<HexReq>,
    /// Cached filtered rows of the function list: `(needle, gen, rows)`.
    fn_rows: FnRowsCache,
    /// Bumped whenever displayed names change; invalidates `fn_rows`.
    gen: u64,
    /// Scroll the selected row of the function list into view (arrow keys).
    fn_ensure_visible: bool,
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
            bss_filter: String::new(),
            selected: None,
            c_cache: HashMap::new(),
            c_order: VecDeque::new(),
            rename_buf: String::new(),
            status: "open a .qvm (File menu, path field, or drag & drop)".into(),
            tab: BottomTab::Strings,
            center: CenterTab::Code,
            cam_graph: Cam::default(),
            cam_cfg: Cam::default(),
            img_offsets: HashMap::new(),
            cfg_offsets: HashMap::new(),
            img_drag: None,
            cfg_drag: None,
            graph_focus: None,
            scroll_to: None,
            hover_fn: None,
            c_hover_range: None,
            flash: None,
            c_scroll_line: None,
            c_flash: None,
            img_w: HashMap::new(),
            img_colw: Vec::new(),
            hist: Vec::new(),
            hist_fwd: Vec::new(),
            sync_scroll: false,
            sync_to_d: None,
            sync_to_c: None,
            prev_d: 0.0,
            prev_c: 0.0,
            hex_windows: Vec::new(),
            fn_rows: None,
            gen: 0,
            fn_ensure_visible: false,
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
                self.c_order.clear();
                self.fn_rows = None;
                self.scroll_to = l.fns.first().map(|f| f.entry);
                self.hover_fn = None;
                self.c_hover_range = None;
                self.img_w.clear();
                self.img_colw.clear();
                self.cam_graph.fit = true;
                self.hist.clear();
                self.hist_fwd.clear();
                self.graph_focus = Some(l.entry_fn());
                self.img_offsets.clear();
                self.cfg_offsets.clear();
                self.img_drag = None;
                self.cfg_drag = None;
                self.cam_cfg = Cam::default();
                self.hex_windows.clear();
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
                    const HIST_CAP: usize = 100;
                    if self.hist.len() > HIST_CAP {
                        self.hist.remove(0);
                    }
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
            } else {
                let name = std::path::Path::new(&p)
                    .file_name()
                    .map_or_else(|| p.clone(), |n| n.display().to_string());
                self.status = format!("not a .qvm, ignored: {name}");
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
                self.fn_ensure_visible = true;
                self.jump_to(next, false);
            }
        }

        // Global hotkeys (ignored while a text field has keyboard focus).
        let (back, fwd, reload, save, open_dlg) = ctx.input(|i| {
            (
                kb_free && i.key_pressed(egui::Key::Backspace),
                kb_free && i.modifiers.alt && i.key_pressed(egui::Key::ArrowRight),
                kb_free && i.key_pressed(egui::Key::F5),
                kb_free && i.modifiers.ctrl && i.key_pressed(egui::Key::S),
                kb_free && i.modifiers.ctrl && i.key_pressed(egui::Key::O),
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
        if open_dlg {
            self.open_dialog();
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

        // Floating memory hex-dump windows (several can be open at once).
        let hex_windows = std::mem::take(&mut self.hex_windows);
        let mut still_open = Vec::with_capacity(hex_windows.len());
        for hv in hex_windows {
            if let Some(l) = &self.loaded {
                let mut open = true;
                egui::Window::new(format!("Memory — {}", hv.title))
                    .id(egui::Id::new(("hexwin", hv.addr, hv.title.clone())))
                    .open(&mut open)
                    .default_width(560.0)
                    .default_height(380.0)
                    .show(ctx, |ui| hex_rows(ui, l, &hv));
                if open {
                    still_open.push(hv);
                }
            }
        }
        self.hex_windows = still_open;
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
    /// Native file-open dialog (Ctrl+O / File menu).
    fn open_dialog(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("QVM modules", &["qvm"])
            .pick_file()
        {
            let p = p.display().to_string();
            self.path_edit = p.clone();
            self.load_path(&p);
        }
    }

    /// Open another memory hex-dump window; a window for the same address is
    /// not duplicated.
    fn open_hex_window(&mut self, req: HexReq) {
        if !self
            .hex_windows
            .iter()
            .any(|w| w.addr == req.addr && w.title == req.title)
        {
            self.hex_windows.push(req);
        }
    }

    fn save_map_action(&mut self) {
        if let Some(l) = &self.loaded {
            match l.save_map() {
                Ok(p) => {
                    let bak = p.with_extension("map.bak");
                    self.status = if bak.is_file() {
                        format!("saved {} (previous copy: {})", p.display(), bak.display())
                    } else {
                        format!("saved {}", p.display())
                    };
                }
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
            Ok(dec) => {
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
                match std::fs::write(&out, &*dec.text) {
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
                Ok(dec) => body.push_str(&dec.text),
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
                    if ui
                        .button("Open… (file dialog)")
                        .on_hover_text("Ctrl+O")
                        .clicked()
                    {
                        ui.close_menu();
                        self.open_dialog();
                    }
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
                    if ui.button("DGraph view (disasm graph)").clicked() {
                        ui.close_menu();
                        self.center = CenterTab::DGraph;
                    }
                    if ui.button("Call graph (whole image)").clicked() {
                        ui.close_menu();
                        self.center = CenterTab::Graph;
                    }
                    ui.separator();
                    if ui
                        .button("Graph: center on vmMain")
                        .on_hover_text("Home")
                        .clicked()
                    {
                        ui.close_menu();
                        self.center = CenterTab::Graph;
                        if let Some(l) = &self.loaded {
                            self.graph_focus = Some(l.entry_fn());
                        }
                    }
                    if ui.button("Graph: fit image").clicked() {
                        ui.close_menu();
                        self.cam_graph.fit = true;
                    }
                    if ui.button("Graph: zoom in").on_hover_text("+").clicked() {
                        ui.close_menu();
                        self.cam_graph.zoom = (self.cam_graph.zoom * 1.3).clamp(0.03, 2.5);
                    }
                    if ui.button("Graph: zoom out").on_hover_text("-").clicked() {
                        ui.close_menu();
                        self.cam_graph.zoom = (self.cam_graph.zoom / 1.3).clamp(0.03, 2.5);
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

                // ---- Help ------------------------------------------------
                ui.menu_button("Help", |ui| {
                    ui.strong("Shortcuts");
                    for (keys, what) in [
                        ("Ctrl+O", "open a QVM via the file dialog"),
                        ("Enter (path field)", "load the typed path"),
                        ("F5", "reload the current file"),
                        ("Ctrl+S", "save renames to .map"),
                        ("Backspace / Alt+Left", "navigate back"),
                        ("Alt+Right", "navigate forward"),
                        ("Home", "center the call graph on vmMain"),
                        ("Arrow Up / Down", "previous / next function"),
                        ("Dbl-click fn name", "jump to function"),
                        ("RMB", "context menus everywhere"),
                        ("Graphs: wheel / drag", "zoom / pan; drag node = move"),
                    ] {
                        ui.label(format!("{keys:<22} {what}"));
                    }
                    ui.separator();
                    ui.label(format!("resq-gui v{}", env!("CARGO_PKG_VERSION")));
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
                    if let Some(l) = &self.loaded {
                        self.graph_focus = Some(l.entry_fn());
                    }
                }
                if ui
                    .add_enabled(!self.hist.is_empty(), egui::Button::new("Back"))
                    .on_hover_text("Back (Backspace / Alt+Left)")
                    .clicked()
                {
                    self.go_back();
                }
                if ui
                    .add_enabled(!self.hist_fwd.is_empty(), egui::Button::new("Fwd"))
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
        // Filtered + formatted rows are cached per (needle, generation);
        // rebuilding them every frame costs one allocation per function.
        let needle = self.filter.to_lowercase();
        let ensure_visible = std::mem::take(&mut self.fn_ensure_visible);
        if self
            .fn_rows
            .as_ref()
            .is_none_or(|(n, g, _)| *n != needle || *g != self.gen)
        {
            let rows: Vec<(usize, String)> = self
                .loaded
                .as_ref()
                .map(|l| {
                    l.fns
                        .iter()
                        .filter(|f| needle.is_empty() || f.search.contains(&needle))
                        .map(|f| (f.idx, format!("{}  [{}]", f.display_name(), f.len())))
                        .collect()
                })
                .unwrap_or_default();
            self.fn_rows = Some((needle.clone(), self.gen, Arc::new(rows)));
        }
        let rows = match &self.fn_rows {
            Some((_, _, r)) => r.clone(),
            None => return,
        };

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
                ui.label(format!("{}/{} functions", rows.len(), l.fns.len()));
                let sel = self.selected;
                let row_h = ui.text_style_height(&egui::TextStyle::Body);
                let mut sa = egui::ScrollArea::vertical().auto_shrink([false, false]);
                // Keep the arrow-key-selected row in view even when it is
                // outside the rendered window (virtualized list).
                if ensure_visible {
                    if let Some(pos_i) = rows.iter().position(|(fi, _)| Some(*fi) == sel) {
                        let vp = ui.available_height().max(row_h * 4.0);
                        let target = (pos_i as f32 * row_h - vp / 2.0).max(0.0);
                        sa = sa.vertical_scroll_offset(target);
                    }
                }
                sa.show_rows(ui, row_h, rows.len(), |ui, range| {
                    for i in range {
                        let (fi, label) = &rows[i];
                        let resp = ui.selectable_label(sel == Some(*fi), label);
                        if sel == Some(*fi) && ensure_visible {
                            resp.scroll_to_me(Some(egui::Align::Center));
                        }
                        if resp.clicked() {
                            *jump = Some(*fi);
                        }
                    }
                });
            });
    }

    fn bottom_tabs(&mut self, ctx: &egui::Context, jump: &mut Option<usize>) {
        // Hex-dump requests collected inside the panel (the `l` borrow of
        // self.loaded is alive while rendering; applied after it ends).
        let mut hex_loc: Option<HexReq> = None;
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
                        (BottomTab::Bss, "BSS"),
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
                                            hex_loc = Some(HexReq {
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
                    BottomTab::Bss => {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.bss_filter)
                                .hint_text("filter globals by address / function name...")
                                .font(egui::TextStyle::Monospace),
                        );
                        let needle = self.bss_filter.to_lowercase();
                        let (b0, b1) = l.bss_range;
                        ui.monospace(format!(
                            "BSS {b0:#x}..{b1:#x} ({} referenced addresses)",
                            l.bss_refs.len()
                        ));
                        let rows: Vec<(&i32, &Vec<usize>)> = l
                            .bss_refs
                            .iter()
                            .filter(|(a, users)| {
                                needle.is_empty()
                                    || format!("{a:#x}").contains(&needle)
                                    || format!("{a}").contains(&needle)
                                    || users.iter().any(|u| {
                                        l.fns[*u].display_name().to_lowercase().contains(&needle)
                                    })
                            })
                            .collect();
                        egui::ScrollArea::vertical()
                            .id_salt("bss")
                            .auto_shrink([false, false])
                            .show_rows(ui, mono_h, rows.len(), |ui, range| {
                                for r in range {
                                    let (addr, users) = rows[r];
                                    let names: Vec<String> = users
                                        .iter()
                                        .take(3)
                                        .map(|u| l.fns[*u].display_name().to_string())
                                        .collect();
                                    let more = users.len().saturating_sub(3);
                                    let txt = if more > 0 {
                                        format!(
                                            "@{addr:#10x}  ({}) {} +{more}",
                                            users.len(),
                                            names.join(", ")
                                        )
                                    } else {
                                        format!(
                                            "@{addr:#10x}  ({}) {}",
                                            users.len(),
                                            names.join(", ")
                                        )
                                    };
                                    let resp = ui.selectable_label(false, &txt);
                                    resp.context_menu(|ui| {
                                        ui.label(format!("@{addr:#x}"));
                                        if ui.button("Hex dump memory").clicked() {
                                            ui.close_menu();
                                            hex_loc = Some(HexReq {
                                                title: format!("bss @ {addr:#x}"),
                                                addr: *addr,
                                                len: 128,
                                            });
                                        }
                                        ui.menu_button("Xrefs", |ui| {
                                            for fi in users.iter().take(30) {
                                                let f = &l.fns[*fi];
                                                if ui
                                                    .button(format!(
                                                        "fn[{fi}] {}",
                                                        f.display_name()
                                                    ))
                                                    .clicked()
                                                {
                                                    ui.close_menu();
                                                    *jump = Some(*fi);
                                                }
                                            }
                                        });
                                    });
                                    if resp.clicked() {
                                        if let Some(&first) = users.first() {
                                            *jump = Some(first);
                                        }
                                    }
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
        if let Some(h) = hex_loc {
            self.open_hex_window(h);
        }
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
                    self.c_order.clear();
                    self.gen += 1; // display names changed -> rebuild list rows
                    self.status = if new_name.is_empty() {
                        format!("cleared name of fn[{sel}]")
                    } else {
                        format!("renamed fn[{sel}] -> {new_name}")
                    };
                }
                ui.separator();
                if ui
                    .selectable_label(self.center == CenterTab::Code, "Code")
                    .clicked()
                {
                    self.center = CenterTab::Code;
                }
                if ui
                    .selectable_label(self.center == CenterTab::DGraph, "DGraph")
                    .on_hover_text("Disassembly graph: CFG with IF/branch edges")
                    .clicked()
                {
                    self.center = CenterTab::DGraph;
                }
                if ui
                    .selectable_label(self.center == CenterTab::Graph, "Graph")
                    .clicked()
                {
                    self.center = CenterTab::Graph;
                }
                if self.center == CenterTab::Graph {
                    ui.separator();
                    if ui.button("Fit").clicked() {
                        self.cam_graph.fit = true;
                    }
                    if ui.button("Reset layout").clicked() {
                        self.img_offsets.clear();
                    }
                    ui.separator();
                    ui.monospace(
                        "call graph: drag canvas = pan, wheel = zoom, drag node = move, RMB = menu, dbl-click = open",
                    );
                }
                if self.center == CenterTab::DGraph {
                    ui.separator();
                    if ui.button("Fit").clicked() {
                        self.cam_cfg.fit = true;
                    }
                    if ui.button("Reset layout").clicked() {
                        self.cfg_offsets.clear();
                    }
                    ui.separator();
                    ui.monospace(
                        "CFG: drag canvas = pan, wheel = zoom, drag node = move, RMB = menu; taken edge = `if <OP>`, green = `else`",
                    );
                }
            });

            ui.separator();

            // Decompiled C (cache miss -> decompile now; Arc clone per frame).
            let dec: Arc<Decompiled> = match self.c_cache.get(&sel) {
                Some(d) => d.clone(),
                None => {
                    let d = match self.loaded.as_ref().unwrap().decompile(sel) {
                        Ok(d) => d,
                        Err(e) => Decompiled {
                            text: format!("// decompile error: {e}\n").into(),
                            ranges: Vec::new().into(),
                            labels: HashMap::new().into(),
                        },
                    };
                    let d = Arc::new(d);
                    if self.c_cache.len() >= C_CACHE_CAP {
                        // FIFO eviction of the oldest entry (no clear-all thrash).
                        while let Some(old) = self.c_order.pop_front() {
                            if self.c_cache.remove(&old).is_some() {
                                break;
                            }
                        }
                    }
                    self.c_cache.insert(sel, d.clone());
                    self.c_order.push_back(sel);
                    d
                }
            };
            let text: Arc<str> = dec.text.clone();

            // Owned/shared data for the pane closures (no &mut self inside).
            let l = self.loaded.as_ref().unwrap();
            let range = l.fn_range(sel).unwrap_or(0..0);
            let tok = Tok {
                names: &l.name_to_idx,
                traps: &l.trap_names,
                entries: &l.entry_to_idx,
            };
            let fn_ranges = &l.fn_ranges;
            let cfg_res = match self.center {
                CenterTab::DGraph => Some(l.cfg(sel)),
                _ => None,
            };
            // Locals collected inside the panes; applied after building.
            let mut jump_loc: Option<usize> = None;
            let mut hex_loc: Option<HexReq> = None;
            let mut xref_loc: Option<usize> = None;
            let mut open_code = false;
            let hover_fn_prev = self.hover_fn;
            let c_range_prev = self.c_hover_range;
            let flash_prev = self.flash;
            let c_flash_prev = self.c_flash;
            let c_scroll_line: Option<usize> = self.c_scroll_line.take();
            let mut new_hover_fn: Option<usize> = None;
            let mut new_c_range: Option<(usize, usize)> = None;
            let mut flash_loc: Option<usize> = None;
            let mut c_goto_loc: Option<usize> = None;
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
                            // Fade flash of the recently jumped-to instruction.
                            let flash_tint = flash_tint(flash_prev, ii);
                            let tint = if flash_tint.is_some() {
                                flash_tint
                            } else if let Some((rs, re)) = c_range_prev {
                                if ii >= rs && ii < re {
                                    Some(TINT_ENTRY)
                                } else {
                                    cross_tint_insn(ii, hover_fn_prev, fn_ranges)
                                }
                            } else {
                                cross_tint_insn(ii, hover_fn_prev, fn_ranges)
                            };
                            paint_row_bg(ui, mono_h, tint);
                            let ins = &l.d.insns[ii];
                            let segs = d_segments(&l.lines[ii], &tok);
                            let mut sink = Sink {
                                jump: &mut jump_loc,
                                scroll: &mut pending_scroll,
                                hover_fn: &mut new_hover_fn,
                                hexreq: &mut hex_loc,
                                xref_fn: &mut xref_loc,
                                flash: &mut flash_loc,
                                c_goto: &mut c_goto_loc,
                            };
                            render_row(ui, l, &segs, &mut sink);
                            // Instruction help tooltip on hover.
                            let row = egui::Rect::from_min_size(
                                ui.available_rect_before_wrap().min,
                                egui::vec2(ui.available_width(), mono_h),
                            );
                            let mut help =
                                format!("[{}] {}", ins.op.name(), opcode_help(ins.op));
                            if let Some(t) = ins.target {
                                help.push_str(&format!("\ntarget: insn {t}"));
                            }
                            help.push_str(&format!(
                                "\naddr {:#x}, {} bytes",
                                ins.addr, ins.size
                            ));
                            ui.interact(row, egui::Id::new(("drow", ii)), Sense::hover())
                                .on_hover_text(help);
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
                    if let Some(n) = c_scroll_line {
                        if let Some(&li) = dec.labels.get(&n) {
                            sac = sac.vertical_scroll_offset(li as f32 * mono_h);
                        }
                    }
                    let c_out = sac.show_rows(&mut cols[1], mono_h, c_rows.len(), |ui, rows| {
                        for i in rows {
                            // Fade flash on the goto landing line.
                            let c_flash_tint = flash_tint(c_flash_prev, i);
                            paint_row_bg(ui, mono_h, c_flash_tint);
                            let segs = c_segments(c_rows[i], &tok);
                            let mut sink = Sink {
                                jump: &mut jump_loc,
                                scroll: &mut pending_scroll,
                                hover_fn: &mut new_hover_fn,
                                hexreq: &mut hex_loc,
                                xref_fn: &mut xref_loc,
                                flash: &mut flash_loc,
                                c_goto: &mut c_goto_loc,
                            };
                            render_row(ui, l, &segs, &mut sink);
                            // Hover/click a C line -> highlight its instructions.
                            let span = dec.ranges.get(i).copied();
                            let row = egui::Rect::from_min_size(
                                ui.available_rect_before_wrap().min,
                                egui::vec2(ui.available_width(), mono_h),
                            );
                            let r = ui.interact(
                                row,
                                egui::Id::new(("crow", sel, i)),
                                Sense::click(),
                            );
                            if r.hovered() {
                                new_c_range = span;
                            }
                            if r.clicked() {
                                if let Some((rs, _)) = span {
                                    pending_scroll = Some(rs);
                                    flash_loc = Some(rs);
                                }
                            }
                        }
                    });
                    c_now = c_out.state.offset.y;
                }),
                CenterTab::DGraph | CenterTab::Graph => match cfg_res {
                    Some(Ok(cfg)) => cfg_canvas(
                        ui,
                        l,
                        sel,
                        &cfg,
                        &tok,
                        &mut self.cam_cfg,
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
                            &tok,
                            &mut self.cam_graph,
                            &mut self.graph_focus,
                            &mut self.img_offsets,
                            &mut self.img_drag,
                            &mut self.img_w,
                            &mut self.img_colw,
                            &mut self.center,
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
            self.c_hover_range = new_c_range;
            self.scroll_to = pending_scroll;
            // Disasm flash: keep the new target, expire the old one.
            self.flash = match flash_loc {
                Some(t) => Some((t, std::time::Instant::now())),
                None => flash_prev.filter(|(_, at)| at.elapsed().as_secs_f32() < FLASH_SECS),
            };
            // Identity C flash: navigate to the clicked label line.
            self.c_scroll_line = c_goto_loc.and_then(|n| dec.labels.get(&n).copied());
            self.c_flash = match self.c_scroll_line {
                Some(li) => Some((li, std::time::Instant::now())),
                None => c_flash_prev.filter(|(_, at)| at.elapsed().as_secs_f32() < FLASH_SECS),
            };
            if self.flash.is_some() || self.c_flash.is_some() {
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(33));
            }
            if let Some(h) = hex_loc {
                if !self
                    .hex_windows
                    .iter()
                    .any(|w| w.addr == h.addr && w.title == h.title)
                {
                    self.hex_windows.push(h);
                }
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

/// Alpha tint for a fading flash highlight on row `at` (None once expired).
fn flash_tint(flash: Option<(usize, std::time::Instant)>, at: usize) -> Option<Color32> {
    let (t, started) = flash?;
    if t != at {
        return None;
    }
    let k = started.elapsed().as_secs_f32() / FLASH_SECS;
    if k >= 1.0 {
        None
    } else {
        let a = ((1.0 - k) * 150.0) as u8;
        Some(Color32::from_rgba_unmultiplied(97, 175, 239, a))
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
                    out.push(Seg::P(" ".into(), C_CMT));
                } else if tok.traps.contains(w) {
                    out.push(Seg::P(format!("{w} "), C_TRAP));
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
    // Char-based scan: byte indexing would garble non-ASCII (UTF-8) text
    // such as function names from a `.map` file.
    let cs: Vec<char> = t.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c == '"' {
            let st = i;
            i += 1;
            while i < cs.len() {
                if cs[i] == '\\' {
                    i += 2;
                } else if cs[i] == '"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            let end = i.min(cs.len());
            let s: String = cs[st..end].iter().collect();
            out.push(Seg::P(s, C_STR));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let st = i;
            while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '_') {
                i += 1;
            }
            let w: String = cs[st..i].iter().collect();
            classify_ident(&w, tok, &mut out);
        } else if c.is_ascii_digit() {
            let st = i;
            while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '.') {
                i += 1;
            }
            let w: String = cs[st..i].iter().collect();
            out.push(Seg::P(w, C_NUM));
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
                        *sink.flash = Some(*n);
                        *sink.c_goto = Some(*n);
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

/// Flat `(text, color)` view of a token for painter-only rendering.
fn seg_parts(seg: &Seg) -> (&str, Color32) {
    match seg {
        Seg::P(t, c) => (t, *c),
        Seg::FnTok(t, _) => (t, C_FN),
        Seg::StrTok(t, _) => (t, C_STR),
        Seg::NumTok(t) => (t, C_NUM),
        Seg::LblTok(t, _) => (t, C_LBL),
    }
}

/// One cubic-bezier edge with an arrowhead at `to`, culled against `clip`.
/// `width` is the stroke width; `arrow_s` scales the arrowhead (1.0 = screen
/// pixels, canvas zoom for scaled canvases).
fn draw_edge(
    p: &egui::Painter,
    from: egui::Pos2,
    to: egui::Pos2,
    clip: egui::Rect,
    color: Color32,
    width: f32,
    arrow_s: f32,
) {
    let bound = egui::Rect::from_min_max(from.min(to), from.max(to));
    if !clip.intersects(bound) {
        return;
    }
    let mid_x = (from.x + to.x) / 2.0;
    p.add(egui::epaint::CubicBezierShape {
        points: [
            from,
            egui::Pos2::new(mid_x, from.y),
            egui::Pos2::new(mid_x, to.y),
            to,
        ],
        closed: false,
        fill: Color32::TRANSPARENT,
        stroke: egui::Stroke::new(width, color).into(),
    });
    let dir = if to.x > from.x { -1.0 } else { 1.0 };
    let pts = vec![
        egui::Pos2::new(to.x + 5.0 * dir * arrow_s, to.y),
        egui::Pos2::new(to.x - 3.0 * dir * arrow_s, to.y - 3.5 * arrow_s),
        egui::Pos2::new(to.x - 3.0 * dir * arrow_s, to.y + 3.5 * arrow_s),
    ];
    p.add(egui::Shape::convex_polygon(pts, color, egui::Stroke::NONE));
}

/// Measure monospace text width (world units at the given font size).
fn p_width(ui: &egui::Ui, text: &str, size: f32) -> f32 {
    ui.ctx().fonts(|f| {
        f.layout_no_wrap(
            text.to_string(),
            egui::FontId::monospace(size),
            Color32::WHITE,
        )
        .size()
        .x
    })
}

/// Whole-image call graph: pan (drag), zoom (scroll), draggable nodes,
/// RMB context menu, double-click opens the function. Nodes are sized to
/// their content (name, stats, disasm preview with syntax colors).
#[allow(clippy::too_many_arguments)]
fn image_graph_pane(
    ui: &mut egui::Ui,
    l: &Loaded,
    sel: usize,
    tok: &Tok,
    cam: &mut Cam,
    focus: &mut Option<usize>,
    offsets: &mut HashMap<usize, egui::Vec2>,
    drag: &mut Option<usize>,
    img_w: &mut HashMap<usize, f32>,
    img_colw: &mut Vec<f32>,
    center: &mut CenterTab,
    jump: &mut Option<usize>,
    open_code: &mut bool,
) {
    const W_MIN: f32 = 150.0;
    const W_MAX: f32 = 560.0;
    const H: f32 = 36.0;
    const GX: f32 = 56.0;
    const GY: f32 = 14.0;
    const M: f32 = 12.0;
    const PREV_LINES: usize = 6;
    const LINE_H: f32 = 12.0;

    let cg = &l.callgraph;
    let n = l.fns.len();

    // Measure content-sized world widths once per load (font-size 1.0 basis).
    if img_w.is_empty() && n > 0 {
        for f in &l.fns {
            let mut w = p_width(ui, f.display_name(), 10.0);
            w = w.max(p_width(
                ui,
                &format!(
                    "{} insns | calls {} | callers {}",
                    f.len(),
                    l.callees.get(&f.idx).map_or(0, Vec::len),
                    l.callers.get(&f.idx).map_or(0, Vec::len)
                ),
                9.0,
            ));
            for ii in f.entry..(f.entry + PREV_LINES).min(f.end) {
                let text = format!("{:<15} {}", insn_bytes(&l.d.insns[ii]), l.lines[ii]);
                w = w.max(p_width(ui, &text, 9.5));
            }
            img_w.insert(f.idx, w.clamp(W_MIN, W_MAX) + 10.0);
        }
        let mut colw = vec![0.0f32; cg.max_depth + 1];
        for f in &l.fns {
            let d = cg.depth[f.idx];
            colw[d] = colw[d].max(img_w.get(&f.idx).copied().unwrap_or(W_MIN));
        }
        *img_colw = colw;
    }
    let col_x = |d: usize| -> f32 { M + img_colw.iter().take(d).sum::<f32>() + d as f32 * GX };
    let width = |i: usize| -> f32 { img_w.get(&i).copied().unwrap_or(W_MIN) };
    let prev_lines = |i: usize| -> usize { l.fns[i].len().min(PREV_LINES) };
    let node_h = |i: usize, zi: f32| {
        if zi >= 0.60 {
            H + prev_lines(i) as f32 * LINE_H
        } else {
            H
        }
    };
    let base_pos = |i: usize| -> egui::Vec2 {
        egui::Vec2::new(col_x(cg.depth[i]), M + cg.row[i] as f32 * (H + GY))
    };
    let pos = |offs: &HashMap<usize, egui::Vec2>, i: usize| -> egui::Vec2 {
        base_pos(i) + offs.get(&i).copied().unwrap_or_default()
    };
    let total_w = M + img_colw.iter().sum::<f32>() + cg.max_depth as f32 * GX;
    let total_h = M + cg.col_len.iter().copied().max().unwrap_or(1) as f32 * (H + GY);

    let (rect, resp) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
    let p = ui.painter_at(rect);

    // Initial fit / focus.
    cam.begin_fit(&rect, egui::vec2(total_w, total_h), 0.03, 1.0);
    if let Some(fi) = *focus {
        *focus = None;
        if fi < n {
            cam.zoom = 1.0; // readable by default: preview text visible
            let c = pos(offsets, fi) + egui::vec2(width(fi) / 2.0, node_h(fi, cam.zoom) / 2.0);
            cam.pan = rect.size() / 2.0 - c * cam.zoom;
        }
    }

    // Zoom around the pointer.
    let scroll_y = ui.input(|i| i.raw_scroll_delta.y);
    cam.wheel_zoom(&resp, &rect, scroll_y, 0.03, 2.5);

    let clip = rect;

    // Hit test (world space).
    let pointer_world = resp
        .hover_pos()
        .map(|h| (h - rect.min - cam.pan) / cam.zoom);
    let hit_at = |pw: Option<egui::Vec2>| -> Option<usize> {
        let pw = pw?;
        for i in 0..n {
            let r = egui::Rect::from_min_size(
                pos(offsets, i).to_pos2(),
                egui::vec2(width(i), node_h(i, cam.zoom)),
            );
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
    if let Some(dn) = *drag {
        if resp.dragged() {
            let e = offsets.entry(dn).or_default();
            *e += resp.drag_delta() / cam.zoom;
        }
    } else if resp.dragged() {
        cam.pan += resp.drag_delta();
    }
    if resp.drag_stopped() {
        *drag = None;
    }

    // Edges (caller -> callee), culled.
    let edge_color = Color32::from_rgba_unmultiplied(110, 118, 128, 140);
    if cam.zoom >= 0.08 {
        for (caller, callees_list) in &l.callees {
            let a = cam.to_screen(
                rect.min,
                pos(offsets, *caller) + egui::vec2(width(*caller), node_h(*caller, cam.zoom) / 2.0),
            );
            for &t in callees_list {
                let b = cam.to_screen(rect.min, pos(offsets, t));
                let b = egui::Pos2::new(b.x, b.y + node_h(t, cam.zoom) / 2.0);
                draw_edge(&p, a, b, rect, edge_color, 1.0, 1.0);
            }
        }
    }

    // Nodes, culled. Content-sized, disasm preview with syntax colors.
    for i in 0..n {
        let w0 = pos(offsets, i);
        let s0 = cam.to_screen(rect.min, w0);
        let nw = width(i);
        let nh = node_h(i, cam.zoom);
        let srect = egui::Rect::from_min_size(s0, egui::vec2(nw * cam.zoom, nh * cam.zoom));
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
        let z = cam.zoom;
        if z >= 0.30 {
            let label = l.fns[i].display_name();
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
            // Function content preview: hex + disasm, syntax colored.
            let f = &l.fns[i];
            let mut y = srect.top() + 30.0 * z;
            let font = egui::FontId::monospace(9.5 * z);
            for ii in f.entry..(f.entry + prev_lines(i)).min(f.end) {
                let line = l.lines.get(ii).map_or("", String::as_str);
                let text = format!("{:<15} {}", insn_bytes(&l.d.insns[ii]), line);
                let mut cx = srect.left() + 4.0 * z;
                for seg in d_segments(&text, tok) {
                    let (t, c) = seg_parts(&seg);
                    let galley = p.layout_no_wrap(t.to_string(), font.clone(), c);
                    let gp = egui::Pos2::new(cx, y);
                    p.galley(gp, galley.clone(), c);
                    cx += galley.size().x;
                }
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
                *center = CenterTab::DGraph;
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
    tok: &Tok,
    cam: &mut Cam,
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
    cam.begin_fit(&rect, egui::vec2(total_w, total_h), 0.15, 1.5);

    // Wheel = zoom around the pointer.
    let scroll_y = ui.input(|i| i.raw_scroll_delta.y);
    cam.wheel_zoom(&resp, &rect, scroll_y, 0.15, 2.5);

    // Hit test.
    let pointer_world = resp
        .hover_pos()
        .map(|h| (h - rect.min - cam.pan) / cam.zoom);
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
            *e += resp.drag_delta() / cam.zoom;
        }
    } else if resp.dragged() {
        cam.pan += resp.drag_delta();
    }
    if resp.drag_stopped() {
        *drag = None;
    }

    // Edge label: `if <OP>` for taken branches, `else` for fallthrough.
    let edge_label = |bi: usize, s: usize| -> String {
        let b = &cfg.blocks[bi];
        if s == b.end {
            return "else".into();
        }
        for ii in b.start..b.end {
            let ins = &l.d.insns[ii];
            if ins.op.is_branch() {
                if let Some(t) = ins.target {
                    if t == s {
                        return format!("if {}", ins.op.name());
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
            let a = cam.to_screen(
                rect.min,
                pos(offsets, bi) + egui::Vec2::new(W, heights[bi] / 2.0),
            );
            let bpt = cam.to_screen(rect.min, pos(offsets, s));
            let bpt = egui::Pos2::new(bpt.x, bpt.y + heights[s] / 2.0 * cam.zoom);
            let lbl = edge_label(bi, s);
            let color = if lbl == "else" {
                Color32::from_rgb(90, 150, 110)
            } else if depth[s] <= depth[bi] {
                Color32::from_rgb(180, 120, 60)
            } else {
                Color32::from_rgb(110, 118, 128)
            };
            draw_edge(&p, a, bpt, rect, color, (1.2 * cam.zoom).max(0.5), cam.zoom);
            // Condition label at the curve midpoint.
            let mid_x = (a.x + bpt.x) / 2.0;
            let mid = egui::Pos2::new(
                (a.x + 3.0 * mid_x + 3.0 * mid_x + bpt.x) / 8.0,
                (a.y + 3.0 * a.y + 3.0 * bpt.y + bpt.y) / 8.0,
            );
            let galley =
                p.layout_no_wrap(lbl.clone(), egui::FontId::monospace(9.5 * cam.zoom), color);
            let gsize = galley.size();
            let bg = egui::Rect::from_center_size(mid, gsize + egui::vec2(6.0, 2.0));
            p.rect_filled(bg, 2.0, Color32::from_rgb(24, 26, 30));
            p.galley(mid - gsize / 2.0, galley, color);
        }
    }

    // Nodes: full disasm with hex bytes, draggable.
    for (bi, b) in cfg.blocks.iter().enumerate() {
        let s0 = cam.to_screen(rect.min, pos(offsets, bi));
        let r = egui::Rect::from_min_size(s0, egui::vec2(W * cam.zoom, heights[bi] * cam.zoom));
        if !rect.intersects(r) {
            continue;
        }
        p.rect_filled(r, 3.0, Color32::from_rgb(38, 42, 50));
        p.rect_stroke(r, 3.0, egui::Stroke::new(1.0, C_LBL));
        let z = cam.zoom;
        let mut y = r.top() + 3.0 * z;
        for (li, line) in block_lines[bi].iter().enumerate() {
            if li == 0 {
                p.text(
                    egui::Pos2::new(r.left() + 6.0 * z, y),
                    egui::Align2::LEFT_TOP,
                    line,
                    egui::FontId::monospace(10.0 * z),
                    C_LBL,
                );
                y += LINE_H * z;
                continue;
            }
            let font = egui::FontId::monospace(10.0 * z);
            let mut cx = r.left() + 6.0 * z;
            for seg in d_segments(line, tok) {
                let (t, c) = seg_parts(&seg);
                let galley = p.layout_no_wrap(t.to_string(), font.clone(), c);
                p.galley(egui::Pos2::new(cx, y), galley.clone(), c);
                cx += galley.size().x;
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tok() -> Tok<'static> {
        Tok {
            names: Box::leak(Box::new(HashMap::new())),
            traps: Box::leak(Box::new(HashSet::new())),
            entries: Box::leak(Box::new(HashMap::new())),
        }
    }

    fn seg_text(segs: &[Seg]) -> String {
        segs.iter()
            .map(seg_parts)
            .map(|(t, _)| t.to_string())
            .collect()
    }

    #[test]
    fn d_segments_keeps_space_after_known_fn_in_comment() {
        let names = HashMap::from([("G_InitGame".to_string(), 3usize)]);
        let traps = HashSet::from(["trap_SendServerCommand".to_string()]);
        let entries = HashMap::new();
        let t = Tok {
            names: &names,
            traps: &traps,
            entries: &entries,
        };
        let segs = d_segments("#12 @0x0 CONST -5 ->#20  ; call G_InitGame ret", &t);
        let s = seg_text(&segs);
        assert!(s.contains("G_InitGame ret"), "glued tokens: {s}");

        let segs = d_segments("#1 @0x4 CONST -6  ; syscall 5 trap_SendServerCommand x", &t);
        let s = seg_text(&segs);
        assert!(
            s.contains("trap_SendServerCommand x"),
            "glued trap token: {s}"
        );
    }

    #[test]
    fn c_segments_is_lossless_for_non_ascii() {
        let t = tok();
        for line in [
            "unsigned loc_0[16]; // привет мир",
            "goto L12; // кириллица + \"строка\"",
        ] {
            let segs = c_segments(line, &t);
            assert_eq!(seg_text(&segs), line.trim_end(), "mangled: {line}");
        }
    }

    #[test]
    fn c_segments_classifies_label_lines() {
        let t = tok();
        // Label-only lines drop the trailing colon by design.
        let segs = c_segments("L12: ; note", &t);
        assert!(matches!(segs.first(), Some(Seg::LblTok(name, 12)) if name == "L12"));
    }

    #[test]
    fn flash_tint_fades_out() {
        let now = std::time::Instant::now();
        assert_eq!(flash_tint(Some((7, now)), 8), None);
        assert!(flash_tint(Some((7, now)), 7).is_some());
        let old = std::time::Instant::now() - std::time::Duration::from_secs(2);
        assert_eq!(flash_tint(Some((7, old)), 7), None);
    }
}
