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
    /// Pending scroll request for the disasm pane (insn index).
    scroll_to: Option<usize>,
    /// Cross-pane highlight state, kept between frames.
    hover_fn: Option<usize>,
    hover_tok: Option<String>,
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
            scroll_to: None,
            hover_fn: None,
            hover_tok: None,
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
                self.loaded = Some(l);
            }
            Err(e) => self.status = e,
        }
    }

    fn apply_jump(&mut self, jump: Option<usize>) {
        let Some(idx) = jump else { return };
        if let Some(l) = &self.loaded {
            if idx < l.fns.len() {
                self.selected = Some(idx);
                self.rename_buf = l.fns[idx].name.clone().unwrap_or_default();
                self.scroll_to = Some(l.fns[idx].entry);
            }
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

        // Arrow-key navigation in the function list.
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
                self.apply_jump(Some(next));
            }
        }

        // Panel order matters: side/bottom panels must be shown BEFORE the
        // CentralPanel, otherwise they paint on top of the central content
        // and hide its scrollable area.
        let mut jump: Option<usize> = None;
        self.top_bar(ctx);
        self.function_list(ctx, &mut jump);
        self.bottom_tabs(ctx, &mut jump);
        self.center_panes(ctx);
        self.apply_jump(jump);
    }
}

impl App {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let edit = egui::TextEdit::singleline(&mut self.path_edit)
                    .desired_width(ui.available_width() - 190.0)
                    .font(egui::TextStyle::Monospace);
                let path_resp = ui.add(edit);
                if ui.button("Open").clicked()
                    || (path_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    let p = self.path_edit.clone();
                    self.load_path(&p);
                }
                if ui
                    .add_enabled(self.loaded.is_some(), egui::Button::new("Save .map"))
                    .clicked()
                {
                    if let Some(l) = &self.loaded {
                        match l.save_map() {
                            Ok(p) => self.status = format!("saved {}", p.display()),
                            Err(e) => self.status = e,
                        }
                    }
                }
            });
            ui.colored_label(egui::Color32::LIGHT_BLUE, &self.status);
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
                CenterTab::Graph => match cfg_res {
                    Some(Ok(cfg)) => {
                        graph_pane(ui, l, sel, &cfg, &mut pending_scroll, &mut jump_loc)
                    }
                    Some(Err(e)) => {
                        ui.colored_label(Color32::LIGHT_RED, format!("CFG error: {e}"));
                    }
                    None => unreachable!("graph tab implies cfg"),
                },
            }

            // Apply collected actions.
            self.hover_fn = new_hover_fn;
            self.hover_tok = new_hover_tok;
            self.scroll_to = pending_scroll;
            if let Some(j) = jump_loc {
                self.apply_jump(Some(j));
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
    out
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
    out
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

fn render_segs_disasm(
    ui: &mut egui::Ui,
    segs: &[Seg],
    jump: &mut Option<usize>,
    scroll: &mut Option<usize>,
    hover_tok: &mut Option<String>,
) {
    for s in segs {
        match s {
            Seg::P(t, c) => plain_label(ui, t, *c),
            Seg::LblTok(_, _) => {}
            Seg::FnTok(t, idx) => {
                let r = tok_label(ui, t, C_FN);
                if r.hovered() {
                    *hover_tok = Some(t.clone());
                }
                if r.double_clicked() {
                    *jump = Some(*idx);
                }
            }
        }
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
    for s in segs {
        match s {
            Seg::P(t, c) => plain_label(ui, t, *c),
            Seg::FnTok(t, idx) => {
                let r = tok_label(ui, t, C_FN);
                if r.hovered() {
                    *hover_fn = Some(*idx);
                }
                if r.double_clicked() {
                    *jump = Some(*idx);
                }
            }
            Seg::LblTok(t, n) => {
                let r = tok_label(ui, t, C_LBL);
                if r.clicked() {
                    *scroll = Some(*n);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CFG graph pane
// ---------------------------------------------------------------------------

fn short_insn(line: &str) -> String {
    // Strip `#idx @0xaddr ` prefix and trailing comment.
    let mut it = line.splitn(3, ' ');
    let _idx = it.next();
    let _addr = it.next();
    let rest = it.next().unwrap_or("");
    let rest = rest.split("  ;").next().unwrap_or(rest);
    let s = rest.trim();
    if s.chars().count() > 24 {
        format!("{}…", s.chars().take(23).collect::<String>())
    } else {
        s.to_string()
    }
}

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
    let mut next_free = max_depth + 1;
    for bi in 0..n {
        if !seen[bi] {
            depth[bi] = next_free;
            next_free += 1;
        }
    }

    // Row index within each layer.
    let mut pos = vec![egui::Pos2::ZERO; n];
    const W: f32 = 176.0;
    const H: f32 = 58.0;
    const GX: f32 = 64.0;
    const GY: f32 = 22.0;
    const M: f32 = 14.0;
    let mut col_heights: HashMap<usize, usize> = HashMap::new();
    for bi in 0..n {
        let d = depth[bi];
        let row = col_heights.entry(d).or_insert(0);
        pos[bi] = egui::Pos2::new(M + d as f32 * (W + GX), M + *row as f32 * (H + GY));
        *row += 1;
    }
    let total_w = M + (depth.iter().copied().max().unwrap_or(0) + 1) as f32 * (W + GX);
    let max_col = col_heights.values().copied().max().unwrap_or(1);
    let total_h = M + max_col as f32 * (H + GY);

    ui.monospace(format!(
        "CFG fn[{sel}] {} ({} blocks) — click a block to scroll Disassembly",
        l.fns.get(sel).map_or("?", |f| f.display_name()),
        n
    ));

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
                    let from = egui::Pos2::new(pos[bi].x + W, pos[bi].y + H / 2.0);
                    let to = egui::Pos2::new(pos[s].x, pos[s].y + H / 2.0);
                    let back = depth[s] <= depth[bi];
                    let color = if back {
                        Color32::from_rgb(180, 120, 60)
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
                }
            }

            // Nodes.
            for (bi, b) in cfg.blocks.iter().enumerate() {
                let r = egui::Rect::from_min_size(pos[bi], egui::vec2(W, H));
                p.rect_filled(r, 3.0, Color32::from_rgb(38, 42, 50));
                p.rect_stroke(r, 3.0, egui::Stroke::new(1.0, C_LBL));
                let first = b.start.min(l.lines.len().saturating_sub(1));
                let last = b.end.saturating_sub(1).min(l.lines.len().saturating_sub(1));
                let txt = format!("B{bi} [{}, {})", b.start, b.end);
                p.text(
                    r.left_top() + egui::vec2(6.0, 4.0),
                    egui::Align2::LEFT_TOP,
                    txt,
                    egui::FontId::monospace(11.0),
                    C_LBL,
                );
                p.text(
                    r.left_top() + egui::vec2(6.0, 19.0),
                    egui::Align2::LEFT_TOP,
                    short_insn(&l.lines[first]),
                    egui::FontId::monospace(10.5),
                    C_PLAIN,
                );
                p.text(
                    r.left_top() + egui::vec2(6.0, 33.0),
                    egui::Align2::LEFT_TOP,
                    short_insn(&l.lines[last]),
                    egui::FontId::monospace(10.5),
                    C_DIM,
                );

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
