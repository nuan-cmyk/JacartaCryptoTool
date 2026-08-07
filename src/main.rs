#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod gui;
mod pki;

use eframe::egui;

fn main() -> eframe::Result<()> {
    // Get command line arguments (files passed via drag-and-drop on the executable)
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dropped_files = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = args.into_iter().map(std::path::PathBuf::from).collect();
    while let Some(p) = stack.pop() {
        if p.is_file() {
            if !dropped_files.contains(&p) {
                dropped_files.push(p);
            }
        } else if p.is_dir() {
            if let Ok(entries) = std::fs::read_dir(p) {
                for entry in entries.flatten() {
                    stack.push(entry.path());
                }
            }
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 350.0])
            .with_min_inner_size([480.0, 350.0])
            .with_title("JaCarta Crypto Tool"),
        ..Default::default()
    };

    eframe::run_native(
        "JaCarta Crypto Tool",
        options,
        Box::new(move |cc| {
            let mut app = gui::JacartaApp::new(cc);
            app.dropped_files = dropped_files;
            Ok(Box::new(app))
        }),
    )
}
