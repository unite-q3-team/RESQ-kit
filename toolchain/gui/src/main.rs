//! resq-gui — interactive QVM analyzer for the RESQ kit.
//!
//! Usage: `resq-gui [path.qvm]` (path is optional; drag & drop works too).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    let initial: Option<String> = std::env::args().nth(1);

    // Embedded window/taskbar icon.
    let (iw, ih, irgba) =
        resq_gui::app::decode_png_rgba(include_bytes!("../../../assets/resq-icon.png"));
    let icon = std::sync::Arc::new(eframe::egui::IconData {
        width: iw,
        height: ih,
        rgba: irgba,
    });

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 620.0])
            .with_icon(icon)
            .with_title("RESQ kit - QVM analyzer"),
        ..Default::default()
    };

    eframe::run_native(
        "RESQ kit",
        options,
        Box::new(move |cc| Ok(Box::new(resq_gui::app::App::new(cc, initial)))),
    )
}
