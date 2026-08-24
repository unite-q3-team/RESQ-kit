//! egui frontend: function list | disasm | identity C, strings/traps tabs.
//!
//! UI closures only READ from `Loaded`; every "jump to function" action
//! pushes into a `jump: Option<usize>` queue which is applied after the
//! panels are built. That keeps borrows disjoint and egui happy.

use std::collections::HashMap;

use eframe::egui;

use crate::state::Loaded;

#[derive(Clone, Copy, Default, PartialEq)]
enum BottomTab {
    #[default]
    Strings,
    Traps,
    Info,
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
                ui_ctx_scroll_hint();
            }
        }
    }
}

/// Scroll the decompile pane to top on selection change is handled by egui's
/// scroll area id staying stable; nothing to do yet — placeholder for later.
fn ui_ctx_scroll_hint() {}

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

        let mut jump: Option<usize> = None;
        self.top_bar(ctx);
        self.function_list(ctx, &mut jump);
        self.center_panes(ctx);
        self.bottom_tabs(ctx, &mut jump);
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

    fn center_panes(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.loaded.is_none() {
                ui.centered_and_justified(|ui| ui.label("Load a QVM to inspect it."));
                return;
            }

            let mono_h = ui.text_style_height(&egui::TextStyle::Monospace);

            // Rename row above the panes.
            let Some(sel) = self.selected else { return };
            let entry = self.loaded.as_ref().map_or(0, |x| x.fns[sel].entry);
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
            let range = self
                .loaded
                .as_ref()
                .and_then(|x| x.fn_range(sel))
                .unwrap_or(0..0);
            let disasm_lines = &self.loaded.as_ref().unwrap().lines;

            ui.columns(2, |cols| {
                // ---- left: disassembly ---------------------------------
                cols[0].heading("Disassembly");
                egui::ScrollArea::vertical()
                    .id_salt("disasm")
                    .auto_shrink([false, false])
                    .show_rows(&mut cols[0], mono_h, range.len(), |ui, rows| {
                        for i in rows {
                            let ii = range.start + i;
                            ui.label(egui::RichText::new(&disasm_lines[ii]).monospace());
                        }
                    });

                // ---- right: decompiled C -------------------------------
                cols[1].heading("Identity C");
                egui::ScrollArea::vertical()
                    .id_salt("decomp")
                    .auto_shrink([false, false])
                    .show_rows(&mut cols[1], mono_h, text.lines().count(), |ui, rows| {
                        for i in rows {
                            let line = text.lines().nth(i).unwrap_or("");
                            ui.label(egui::RichText::new(line).monospace());
                        }
                    });
            });
        });
    }

    fn bottom_tabs(&mut self, ctx: &egui::Context, jump: &mut Option<usize>) {
        egui::TopBottomPanel::bottom("bottom")
            .default_height(190.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for (tab, name) in [
                        (BottomTab::Strings, "Strings"),
                        (BottomTab::Traps, "Traps"),
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
                                    ui.horizontal(|ui| {
                                        ui.monospace(format!("@{addr}"));
                                        ui.monospace(s);
                                        if users > 0 && ui.small_button("refs").clicked() {
                                            *jump = l.string_refs[addr][0].into();
                                        }
                                    });
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
                                        if let Some(first) =
                                            l.trap_users.get(&num).and_then(|v| v.first())
                                        {
                                            *jump = Some(*first);
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
    }
}
