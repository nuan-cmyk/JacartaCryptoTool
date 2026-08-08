#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod gui;
mod pki;

use eframe::egui;

/// Check if any wgpu GPU adapter is available.
/// If not, force wgpu to use Microsoft WARP (built-in Windows software renderer).
/// WARP is always available on Windows 10+ regardless of GPU hardware or drivers.
fn ensure_gpu_adapter() {
    use eframe::wgpu::{Backends, Instance, InstanceDescriptor};

    let instance = Instance::new(InstanceDescriptor {
        backends: Backends::all(),
        ..Default::default()
    });

    let any_adapter = instance.enumerate_adapters(Backends::all()).len() > 0;

    if !any_adapter {
        // No hardware or software adapter found via normal means.
        // Explicitly tell wgpu to use Microsoft WARP (DX12 software renderer).
        // WARP ("Microsoft Basic Render Driver") is built into every Windows 10/11 installation.
        // This works even in VMs, Remote Desktop, and machines with no GPU drivers.
        unsafe {
            std::env::set_var("WGPU_BACKEND", "dx12");
            std::env::set_var("WGPU_ADAPTER_NAME", "Warp");
        }
    }
}

fn main() -> eframe::Result<()> {
    // Write a panic log if the app crashes silently
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("Panic occurred: {}", info);
        let _ = std::fs::write("jacarta_crash.log", msg);
    }));

    // Run GPU adapter pre-flight check BEFORE wgpu initializes
    ensure_gpu_adapter();

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

    let wgpu_options = eframe::egui_wgpu::WgpuConfiguration {
        // Try every available backend: DX12 -> Vulkan -> OpenGL
        supported_backends: eframe::wgpu::Backends::all(),
        power_preference: eframe::wgpu::PowerPreference::None,
        ..Default::default()
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 350.0])
            .with_min_inner_size([480.0, 350.0])
            .with_title("JaCarta Crypto Tool"),
        wgpu_options,
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

    if let Err(e) = &result {
        let _ = std::fs::write("jacarta_startup_error.log", format!("Startup failed: {:?}", e));
    }

    result
}
