use eframe::egui;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use zeroize::{Zeroize, Zeroizing};

pub enum WorkerMessage {
    Progress { current: usize, total: usize, current_file: String },
    PreviewReady(String, Zeroizing<Vec<u8>>), // When previewing in RAM
    Done(Result<String, String>),
}

pub struct JacartaApp {
    pub dropped_files: Vec<PathBuf>,
    pub user_pin: String,
    pub new_user_pin: String,
    pub delete_originals: bool,
    pub action_status: Option<(bool, String)>, // (is_error, message)
    pub token: Option<crate::pki::JacartaToken>,
    pub show_settings: bool,

    // Background processing
    pub worker_rx: Option<Receiver<WorkerMessage>>,
    pub is_processing: bool,
    pub progress: f32,
    pub current_file: String,
    pub preview_data: Option<(String, Zeroizing<Vec<u8>>)>,
    pub security_applied: bool,
}

impl JacartaApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        setup_custom_styles(&_cc.egui_ctx);
        
        #[cfg(target_pointer_width = "64")]
        let dll_bytes = include_bytes!("../drivers/jcPKCS11_2_Win64.dll");
        #[cfg(target_pointer_width = "32")]
        let dll_bytes = include_bytes!("../drivers/jcPKCS11_2_Win32.dll");

        let dll_name = if cfg!(target_pointer_width = "64") {
            "jcPKCS11_2_Win64_temp.dll"
        } else {
            "jcPKCS11_2_Win32_temp.dll"
        };

        let dll_path = std::env::temp_dir().join(dll_name);
        let _ = std::fs::write(&dll_path, dll_bytes);

        let token = crate::pki::JacartaToken::new(dll_path.to_str().unwrap()).ok();
        Self {
            dropped_files: Vec::new(),
            delete_originals: false,
            user_pin: String::new(),
            new_user_pin: String::new(),
            action_status: None,
            token,
            show_settings: false,

            worker_rx: None,
            is_processing: false,
            progress: 0.0,
            current_file: String::new(),
            preview_data: None,
            security_applied: false,
        }
    }
}

fn setup_custom_styles(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    
    style.visuals.window_fill = egui::Color32::from_rgb(25, 27, 33);
    style.visuals.panel_fill = egui::Color32::from_rgb(25, 27, 33);
    style.visuals.override_text_color = Some(egui::Color32::from_rgb(230, 230, 230));
    
    style.visuals.window_rounding = egui::Rounding::same(12.0);
    style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(8.0);
    
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    
    ctx.set_style(style);
}

impl eframe::App for JacartaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        unsafe {
            if windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent() != 0 {
                std::process::exit(1);
            }
        }

        if !self.security_applied {
            unsafe extern "system" fn enum_window_callback(hwnd: windows_sys::Win32::Foundation::HWND, _lparam: isize) -> i32 {
                let mut pid = 0;
                unsafe {
                    windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId(hwnd, &mut pid);
                    if pid == std::process::id() as u32 {
                        windows_sys::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity(hwnd, windows_sys::Win32::UI::WindowsAndMessaging::WDA_EXCLUDEFROMCAPTURE);
                    }
                }
                1
            }
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows(Some(enum_window_callback), 0);
            }
            self.security_applied = true;
        }

        // Handle background messages
        if let Some(rx) = self.worker_rx.take() {
            let mut keep_rx = true;
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    WorkerMessage::Progress { current, total, current_file } => {
                        self.progress = current as f32 / total as f32;
                        self.current_file = current_file;
                    }
                    WorkerMessage::PreviewReady(file, data) => {
                        self.preview_data = Some((file, data));
                        self.is_processing = false;
                        keep_rx = false;
                        self.dropped_files.clear();
                        self.action_status = Some((false, "File decrypted in RAM".to_string()));
                        break;
                    }
                    WorkerMessage::Done(result) => {
                        self.is_processing = false;
                        keep_rx = false;
                        self.dropped_files.clear();
                        match result {
                            Ok(msg) => self.action_status = Some((false, msg)),
                            Err(err) => self.action_status = Some((true, err)),
                        }
                        break;
                    }
                }
            }
            if keep_rx {
                self.worker_rx = Some(rx);
            }
            if self.is_processing {
                ctx.request_repaint();
            }
        }

        if !self.is_processing && self.preview_data.is_none() {
            ctx.input(|i| {
                if !i.raw.dropped_files.is_empty() {
                    for file in &i.raw.dropped_files {
                        if let Some(path) = &file.path {
                            if !self.dropped_files.contains(path) {
                                self.dropped_files.push(path.clone());
                            }
                        }
                    }
                }
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Header
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("JaCarta Crypto").size(24.0).strong().color(egui::Color32::from_rgb(90, 160, 255)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(if self.show_settings { "Close" } else { "Settings" }).clicked() {
                        self.show_settings = !self.show_settings;
                        self.action_status = None;
                    }
                });
            });
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            if self.token.is_none() {
                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), "Error: Failed to load PKCS#11 driver.");
                ui.label("Ensure the token is connected and restart the program.");
                return;
            }

            if self.is_processing {
                self.show_progress_panel(ui);
            } else if self.preview_data.is_some() {
                self.show_preview_panel(ui);
            } else if self.show_settings {
                self.show_settings_panel(ui);
            } else if self.dropped_files.is_empty() {
                self.show_idle_panel(ui);
            } else {
                self.show_encryption_panel(ui);
            }

            // Status bar at the bottom
            if let Some((is_error, status)) = &self.action_status {
                ui.add_space(15.0);
                egui::Frame::none()
                    .fill(if *is_error { egui::Color32::from_rgb(60, 20, 20) } else { egui::Color32::from_rgb(20, 60, 30) })
                    .rounding(8.0)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            let color = if *is_error { egui::Color32::from_rgb(255, 120, 120) } else { egui::Color32::from_rgb(120, 255, 150) };
                            ui.add(egui::Label::new(egui::RichText::new(status).color(color)).wrap());
                        });
                    });
            }
        });
    }
}

impl JacartaApp {
    fn show_idle_panel(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.label(egui::RichText::new("+").size(60.0));
            ui.add_space(20.0);
            ui.label(egui::RichText::new("Drag and drop files here").size(20.0).strong());
            ui.add_space(10.0);
            ui.label(egui::RichText::new("For automatic encryption or decryption").color(egui::Color32::GRAY));
        });
    }

    fn show_settings_panel(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.group(|ui| {
                ui.label(egui::RichText::new("Token Master Key Initialization").heading());
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Creates a 256-bit secure key. Required before first encryption.").color(egui::Color32::GRAY));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("User PIN:");
                    ui.add(egui::TextEdit::singleline(&mut self.user_pin).password(true));
                });
                ui.add_space(8.0);
                if ui.button("Create Master Key").clicked() {
                    let token = self.token.as_ref().unwrap();
                    match token.get_or_create_master_key(&self.user_pin) {
                        Ok(_) => self.action_status = Some((false, "Success: Master Key created!".to_string())),
                        Err(e) => self.action_status = Some((true, format!("Token access error: {}", e))),
                    }
                }
            });

            ui.add_space(20.0);

            ui.group(|ui| {
                ui.label(egui::RichText::new("Change User PIN").heading());
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Current PIN:");
                    ui.add(egui::TextEdit::singleline(&mut self.user_pin).password(true));
                });
                ui.horizontal(|ui| {
                    ui.label("New PIN:   ");
                    ui.add(egui::TextEdit::singleline(&mut self.new_user_pin).password(true));
                });
                ui.add_space(8.0);
                if ui.button("Change PIN").clicked() {
                    match self.token.as_ref().unwrap().change_pin(&self.user_pin, &self.new_user_pin, false) {
                        Ok(_) => self.action_status = Some((false, "Success: User PIN changed.".to_string())),
                        Err(e) => self.action_status = Some((true, format!("PIN change error: {}", e))),
                    }
                }
            });
        });
    }

    fn show_progress_panel(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading("Operation in progress...");
            ui.add_space(20.0);
            
            let progress_bar = egui::ProgressBar::new(self.progress)
                .show_percentage()
                .animate(true);
            ui.add(progress_bar);
            
            ui.add_space(10.0);
            ui.label(format!("Processing: {}", self.current_file));
        });
    }

    fn show_preview_panel(&mut self, ui: &mut egui::Ui) {
        let mut close_preview = false;
        
        if let Some((file_name, data)) = &self.preview_data {
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new(format!("Preview: {}", file_name)).color(egui::Color32::from_rgb(255, 180, 50)));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close and clear memory").clicked() {
                        close_preview = true;
                    }
                });
            });
            ui.add_space(10.0);

            egui::Frame::none()
                .fill(egui::Color32::from_rgb(15, 15, 15))
                .rounding(6.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical().max_height(350.0).show(ui, |ui| {
                        if let Ok(text) = std::str::from_utf8(data) {
                            let mut text_buf = text.to_string();
                            ui.add(egui::TextEdit::multiline(&mut text_buf).desired_width(f32::INFINITY).interactive(false));
                        } else {
                            ui.label(egui::RichText::new("Warning: This is a binary file (not text).").color(egui::Color32::from_rgb(255, 100, 100)));
                            ui.add_space(5.0);
                            let hex: String = data.iter().take(1024).map(|b| format!("{:02X} ", b)).collect();
                            ui.label(egui::RichText::new(if data.len() > 1024 { format!("{}...", hex) } else { hex }).family(egui::FontFamily::Monospace).size(12.0));
                        }
                    });
                });
        }
        
        if close_preview {
            self.preview_data = None;
        }
    }

    fn show_encryption_panel(&mut self, ui: &mut egui::Ui) {
        let mut crypt_count = 0;
        for f in &self.dropped_files {
            if let Some(ext) = f.extension() {
                if ext == "crypt" {
                    crypt_count += 1;
                }
            }
        }
        
        let auto_decrypt = crypt_count > (self.dropped_files.len() / 2);

        ui.label(egui::RichText::new(format!("Selected files: {}", self.dropped_files.len())).strong());
        ui.add_space(5.0);

        egui::Frame::none()
            .fill(egui::Color32::from_rgb(35, 38, 45))
            .rounding(6.0)
            .inner_margin(8.0)
            .show(ui, |ui| {
                let display_limit = 5;
                for (i, f) in self.dropped_files.iter().enumerate() {
                    if i >= display_limit {
                        ui.label(egui::RichText::new(format!("...and {} more files", self.dropped_files.len() - display_limit)).italics().color(egui::Color32::GRAY));
                        break;
                    }
                    ui.label(egui::RichText::new(format!("- {}", f.file_name().unwrap_or_default().to_string_lossy())).small());
                }
            });

        ui.add_space(10.0);
        
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Your PIN:").strong());
            ui.add(egui::TextEdit::singleline(&mut self.user_pin).password(true).desired_width(150.0));
        });

        ui.add_space(5.0);
        ui.checkbox(&mut self.delete_originals, "Delete originals after successful operation");

        ui.add_space(15.0);

        ui.horizontal(|ui| {
            if auto_decrypt {
                if ui.add_sized([130.0, 40.0], egui::Button::new(egui::RichText::new("Decrypt").size(16.0).color(egui::Color32::BLACK)).fill(egui::Color32::from_rgb(100, 200, 100))).clicked() {
                    self.start_processing(false, false);
                }
                if ui.add_sized([130.0, 40.0], egui::Button::new(egui::RichText::new("Encrypt").size(16.0))).clicked() {
                    self.start_processing(true, false);
                }
            } else {
                if ui.add_sized([130.0, 40.0], egui::Button::new(egui::RichText::new("Encrypt").size(16.0).color(egui::Color32::BLACK)).fill(egui::Color32::from_rgb(100, 150, 255))).clicked() {
                    self.start_processing(true, false);
                }
                if ui.add_sized([130.0, 40.0], egui::Button::new(egui::RichText::new("Decrypt").size(16.0))).clicked() {
                    self.start_processing(false, false);
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_sized([100.0, 40.0], egui::Button::new(egui::RichText::new("Cancel").size(16.0))).clicked() {
                    self.dropped_files.clear();
                    self.action_status = None;
                }
            });
        });
        
        if auto_decrypt {
            ui.add_space(5.0);
            if ui.button(egui::RichText::new("Preview text/code without saving (RAM only)").color(egui::Color32::from_rgb(255, 180, 50))).clicked() {
                self.start_processing(false, true);
            }
        }
    }

    fn start_processing(&mut self, encrypt: bool, preview_only: bool) {
        let token = self.token.as_ref().unwrap();
        let pin = self.user_pin.clone();
        
        let master_key = Zeroizing::new(match token.get_or_create_master_key(&pin) {
            Ok(key) => key,
            Err(e) => {
                self.action_status = Some((true, format!("Token authorization error: {}", e)));
                self.user_pin.zeroize();
                return;
            }
        });
        
        self.user_pin.zeroize();

        let files = self.dropped_files.clone();
        let (tx, rx) = channel();
        self.worker_rx = Some(rx);
        self.is_processing = true;
        self.progress = 0.0;
        self.action_status = None;

        let delete_originals = self.delete_originals;

        thread::spawn(move || {
            let total = files.len();
            if total == 0 {
                let _ = tx.send(WorkerMessage::Done(Ok("Nothing to process".to_string())));
                return;
            }

            if preview_only {
                let input_path = &files[0];
                let mut temp_name = input_path.file_name().unwrap_or_default().to_string_lossy().into_owned();
                if temp_name.ends_with(".crypt") {
                    temp_name = temp_name[..temp_name.len() - 6].to_string();
                }
                
                match crate::crypto::decrypt_file_to_memory(input_path, &master_key) {
                    Ok(data) => {
                        use std::io::Cursor;
                        let mut archive = tar::Archive::new(Cursor::new(data));
                        let mut preview_text = String::new();
                        
                        if let Ok(entries) = archive.entries() {
                            for entry in entries {
                                if let Ok(mut file) = entry {
                                    let path = file.path().unwrap().to_string_lossy().into_owned();
                                    preview_text.push_str(&format!("--- FILE: {} ---\n", path));
                                    if file.header().entry_type().is_file() {
                                        let mut content = Vec::new();
                                        if std::io::Read::read_to_end(&mut file, &mut content).is_ok() {
                                            if let Ok(s) = std::str::from_utf8(&content) {
                                                preview_text.push_str(s);
                                            } else {
                                                preview_text.push_str("[BINARY DATA]\n");
                                            }
                                        }
                                    }
                                    preview_text.push_str("\n\n");
                                }
                            }
                            let _ = tx.send(WorkerMessage::PreviewReady("Archive Preview".to_string(), Zeroizing::new(preview_text.into_bytes())));
                        } else {
                            let _ = tx.send(WorkerMessage::Done(Err("Failed to parse archive in RAM".to_string())));
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(WorkerMessage::Done(Err(format!("Decryption error {}: {:?}", input_path.display(), e))));
                    }
                }
                return;
            }

            if encrypt {
                let _ = tx.send(WorkerMessage::Progress { current: 0, total, current_file: "Creating archive...".to_string() });
                
                let first_path = &files[0];
                let mut output_path = first_path.clone();
                let original_name = first_path.file_name().unwrap().to_string_lossy().into_owned();
                output_path.set_file_name(format!("{}.crypt", original_name));

                let out_file = match std::fs::File::create(&output_path) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = tx.send(WorkerMessage::Done(Err(format!("Error creating output file: {:?}", e))));
                        return;
                    }
                };

                let mut encrypt_stream = match crate::crypto::EncryptStream::new(out_file, &master_key) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(WorkerMessage::Done(Err(format!("Encryption init error: {:?}", e))));
                        return;
                    }
                };

                {
                    let mut builder = tar::Builder::new(&mut encrypt_stream);
                    for (i, path) in files.iter().enumerate() {
                        let _ = tx.send(WorkerMessage::Progress { current: i, total, current_file: format!("Packing {}", path.display()) });
                        let name = path.file_name().unwrap();
                        if path.is_dir() {
                            if let Err(e) = builder.append_dir_all(name, path) {
                                let _ = tx.send(WorkerMessage::Done(Err(format!("Error packing dir {}: {:?}", path.display(), e))));
                                let _ = std::fs::remove_file(&output_path);
                                return;
                            }
                        } else {
                            if let Err(e) = builder.append_path_with_name(path, name) {
                                let _ = tx.send(WorkerMessage::Done(Err(format!("Error packing file {}: {:?}", path.display(), e))));
                                let _ = std::fs::remove_file(&output_path);
                                return;
                            }
                        }
                    }
                    
                    if let Err(e) = builder.finish() {
                        let _ = tx.send(WorkerMessage::Done(Err(format!("Error finalizing tar: {:?}", e))));
                        let _ = std::fs::remove_file(&output_path);
                        return;
                    }
                }

                if let Err(e) = encrypt_stream.finish() {
                    let _ = std::fs::remove_file(&output_path);
                    let _ = tx.send(WorkerMessage::Done(Err(format!("Encryption finalization error: {:?}", e))));
                    return;
                }

                if delete_originals {
                    for path in &files {
                        let _ = tx.send(WorkerMessage::Progress { current: total, total, current_file: format!("Deleting {}", path.display()) });
                        if path.is_dir() {
                            crate::gui::secure_delete_dir(path);
                        } else {
                            crate::gui::secure_delete_file(path);
                        }
                    }
                }
            } else {
                let input_path = &files[0];
                if input_path.extension().unwrap_or_default() != "crypt" {
                    let _ = tx.send(WorkerMessage::Done(Err("Selected file is not a .crypt archive.".to_string())));
                    return;
                }

                let _ = tx.send(WorkerMessage::Progress { current: 0, total: 1, current_file: "Decrypting and unpacking...".to_string() });
                
                let in_file = match std::fs::File::open(input_path) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = tx.send(WorkerMessage::Done(Err(format!("Error opening archive: {:?}", e))));
                        return;
                    }
                };

                let decrypt_stream = match crate::crypto::DecryptStream::new(in_file, &master_key) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(WorkerMessage::Done(Err(format!("Decryption init error: {:?}", e))));
                        return;
                    }
                };

                let mut archive = tar::Archive::new(decrypt_stream);
                let parent_dir = input_path.parent().unwrap();
                
                if let Err(e) = archive.unpack(parent_dir) {
                    let _ = tx.send(WorkerMessage::Done(Err(format!("Error unpacking archive: {:?}", e))));
                    return;
                }
                
                if delete_originals {
                    crate::gui::secure_delete_file(input_path);
                }
            }
            
            let _ = tx.send(WorkerMessage::Progress { current: total, total, current_file: "Completed".to_string() });
            let _ = tx.send(WorkerMessage::Done(Ok("Success: Operation completed!".to_string())));
        });
    }
}

pub fn secure_delete_file(path: &std::path::Path) {
    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
        if let Ok(metadata) = file.metadata() {
            let size = metadata.len();
            let chunk = vec![0u8; 65536];
            let mut written = 0;
            while written < size {
                let to_write = std::cmp::min(chunk.len() as u64, size - written);
                if std::io::Write::write_all(&mut file, &chunk[..to_write as usize]).is_err() {
                    break;
                }
                written += to_write;
            }
            let _ = file.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

pub fn secure_delete_dir(path: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                secure_delete_dir(&p);
            } else {
                secure_delete_file(&p);
            }
        }
    }
    let _ = std::fs::remove_dir(path);
}
