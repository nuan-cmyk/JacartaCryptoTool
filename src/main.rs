// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod gui;
mod pki;

use eframe::egui;

fn main() -> eframe::Result<()> {
    // Write a panic log if the app crashes silently
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("Panic occurred: {}", info);
        let _ = std::fs::write("jacarta_crash.log", msg);
    }));

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
        // Force a specific graphics backend if default fails
        // wgpu_options: egui_wgpu::WgpuConfiguration {
        //     backends: egui_wgpu::wgpu::Backends::GL,
        //     ..Default::default()
        // },
        ..Default::default()
    };

    let result = eframe::run_native(
        "JaCarta Crypto Tool",
        options,
        Box::new(move |cc| {
            let mut app = gui::JacartaApp::new(cc);
            app.dropped_files = dropped_files;
            Ok(Box::new(app))
        }),
    );

    // If it fails to start (e.g. graphics driver issues), write to a file
    if let Err(e) = &result {
        let _ = std::fs::write("jacarta_startup_error.log", format!("Startup failed: {:?}", e));
    }
    
    result
}
