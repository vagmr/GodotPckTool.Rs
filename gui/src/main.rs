//! GodotPckTool GUI - A graphical interface for godotpck-rs
//!
//! Features:
//! - Load and inspect PCK files
//! - Extract files with progress
//! - File drag & drop support
//! - Dark/Light theme toggle

use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use eframe::egui;
use godotpck_rs::{ExtractOptions, NoKeyMode, PckEntry, PckFile};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "GodotPckTool GUI",
        options,
        Box::new(|cc| {
            configure_fonts(&cc.egui_ctx);
            configure_style(&cc.egui_ctx);
            Box::new(App::default())
        }),
    )
}

// ============================================================================
// Message types for background task communication
// ============================================================================

/// Messages sent from background tasks to the UI
#[allow(dead_code)]
enum TaskMessage {
    /// PCK file loaded successfully
    PckLoaded(Box<PckFile>),
    /// Error occurred during operation
    Error(String),
    /// Log message
    Log(String),
    /// Extraction progress update (current, total)
    ExtractProgress(usize, usize),
    /// Extraction completed
    ExtractDone(usize),
}

/// Represents a loaded PCK file with cached info
struct LoadedPck {
    pck: PckFile,
    file_count: usize,
    total_size: u64,
    entries: Vec<PckEntryInfo>,
}

/// Simplified entry info for display
#[derive(Clone)]
struct PckEntryInfo {
    path: String,
    size: u64,
    is_encrypted: bool,
}

impl From<&PckEntry> for PckEntryInfo {
    fn from(entry: &PckEntry) -> Self {
        Self {
            path: entry.path.clone(),
            size: entry.size,
            is_encrypted: entry.flags & godotpck_rs::PCK_FILE_ENCRYPTED != 0,
        }
    }
}

// ============================================================================
// Main Application State
// ============================================================================

struct App {
    // UI State
    pck_path: String,
    output_dir: String,
    encryption_key_hex: String,
    filter_text: String,
    show_about: bool,
    #[allow(dead_code)]
    show_settings: bool,

    // Extract options
    overwrite_existing: bool,
    verify_md5: bool,

    // Loaded PCK data
    loaded_pck: Option<LoadedPck>,

    // Task communication
    task_tx: Sender<TaskMessage>,
    task_rx: Receiver<TaskMessage>,

    // Status
    logs: Vec<String>,
    status: String,
    is_busy: bool,
    progress: Option<(usize, usize)>,

    // File list filter
    filtered_entries: Vec<usize>,
    selected_entry: Option<usize>,
}

impl Default for App {
    fn default() -> Self {
        let (task_tx, task_rx) = channel();
        Self {
            pck_path: String::new(),
            output_dir: String::new(),
            encryption_key_hex: String::new(),
            filter_text: String::new(),
            show_about: false,
            show_settings: false,
            overwrite_existing: false,
            verify_md5: false,
            loaded_pck: None,
            task_tx,
            task_rx,
            logs: Vec::new(),
            status: "就绪".to_string(),
            is_busy: false,
            progress: None,
            filtered_entries: Vec::new(),
            selected_entry: None,
        }
    }
}

impl App {
    /// Push a log message
    fn log(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.logs.push(format!("[{}] {}", chrono_lite(), msg));
    }

    /// Parse encryption key from hex string
    fn parse_key(&self) -> Option<[u8; 32]> {
        let hex = self.encryption_key_hex.trim();
        if hex.is_empty() {
            return None;
        }
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        if hex.len() != 64 {
            return None;
        }
        let mut key = [0u8; 32];
        for i in 0..32 {
            if let Ok(b) = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                key[i] = b;
            } else {
                return None;
            }
        }
        Some(key)
    }

    /// Load a PCK file in background
    fn load_pck(&mut self) {
        if self.is_busy {
            return;
        }
        let path = self.pck_path.trim().to_string();
        if path.is_empty() {
            self.log("错误：请先选择 PCK 文件");
            return;
        }

        self.is_busy = true;
        self.status = "正在加载 PCK...".to_string();
        self.log(format!("加载: {}", path));

        let tx = self.task_tx.clone();
        let key = self.parse_key();

        thread::spawn(move || {
            match PckFile::load(&path, None, key) {
                Ok(pck) => {
                    tx.send(TaskMessage::PckLoaded(Box::new(pck))).ok();
                }
                Err(e) => {
                    tx.send(TaskMessage::Error(format!("加载失败: {:#}", e))).ok();
                }
            }
        });
    }

    /// Extract PCK to output directory
    fn extract_pck(&mut self) {
        if self.is_busy {
            return;
        }
        let pck = match &self.loaded_pck {
            Some(p) => p,
            None => {
                self.log("错误：请先加载 PCK 文件");
                return;
            }
        };

        let output = self.output_dir.trim().to_string();
        if output.is_empty() {
            self.log("错误：请选择输出目录");
            return;
        }

        self.is_busy = true;
        self.status = "正在解压...".to_string();
        self.progress = Some((0, pck.file_count));
        self.log(format!("解压到: {}", output));

        // Clone necessary data for the thread
        let pck_path = self.pck_path.clone();
        let key = self.parse_key();
        let overwrite = self.overwrite_existing;
        let check_md5 = self.verify_md5;
        let tx = self.task_tx.clone();

        thread::spawn(move || {
            // Reload PCK in thread (PckFile is not Send)
            let pck = match PckFile::load(&pck_path, None, key) {
                Ok(p) => p,
                Err(e) => {
                    tx.send(TaskMessage::Error(format!("重新加载失败: {:#}", e))).ok();
                    return;
                }
            };

            let options = ExtractOptions {
                overwrite,
                check_md5,
                no_key_mode: NoKeyMode::Skip,
            };

            // Extract with progress tracking
            let total = pck.entries().count();
            let _extracted = 0;

            match pck.extract_with_options(&output, false, &options) {
                Ok(()) => {
                    tx.send(TaskMessage::ExtractDone(total)).ok();
                }
                Err(e) => {
                    tx.send(TaskMessage::Error(format!("解压失败: {:#}", e))).ok();
                }
            }
        });
    }

    /// Update filtered entries based on filter text
    fn update_filter(&mut self) {
        self.filtered_entries.clear();
        if let Some(loaded) = &self.loaded_pck {
            let filter = self.filter_text.to_lowercase();
            for (i, entry) in loaded.entries.iter().enumerate() {
                if filter.is_empty() || entry.path.to_lowercase().contains(&filter) {
                    self.filtered_entries.push(i);
                }
            }
        }
    }

    /// Process messages from background tasks
    fn process_messages(&mut self) {
        while let Ok(msg) = self.task_rx.try_recv() {
            match msg {
                TaskMessage::PckLoaded(pck) => {
                    let file_count = pck.entries().count();
                    let total_size: u64 = pck.entries().map(|e| e.size).sum();
                    let entries: Vec<PckEntryInfo> = pck.entries().map(|e| e.into()).collect();

                    let header = pck.header();
                    self.log(format!(
                        "已加载: {} 个文件, 总大小: {}, Godot 版本: {}",
                        file_count,
                        format_size(total_size),
                        header.godot_version_string()
                    ));

                    if pck.is_encrypted() {
                        self.log("⚠️ PCK 文件已加密");
                    }
                    if pck.is_embedded() {
                        self.log("📦 嵌入式 PCK (来自可执行文件)");
                    }

                    self.loaded_pck = Some(LoadedPck {
                        pck: *pck,
                        file_count,
                        total_size,
                        entries,
                    });
                    self.update_filter();
                    self.is_busy = false;
                    self.status = format!("已加载 {} 个文件", file_count);
                }
                TaskMessage::Error(e) => {
                    self.log(format!("❌ {}", e));
                    self.is_busy = false;
                    self.status = "操作失败".to_string();
                    self.progress = None;
                }
                TaskMessage::Log(msg) => {
                    self.log(msg);
                }
                TaskMessage::ExtractProgress(current, total) => {
                    self.progress = Some((current, total));
                }
                TaskMessage::ExtractDone(count) => {
                    self.log(format!("✅ 解压完成: {} 个文件", count));
                    self.is_busy = false;
                    self.status = "解压完成".to_string();
                    self.progress = None;
                }
            }
        }
    }
}

// ============================================================================
// eframe::App Implementation - UI Rendering
// ============================================================================

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Process background task messages
        self.process_messages();

        // Handle dropped files
        ctx.input(|i| {
            for file in &i.raw.dropped_files {
                if let Some(path) = &file.path {
                    let path_str = path.to_string_lossy().to_string();
                    if path_str.to_lowercase().ends_with(".pck")
                        || path_str.to_lowercase().ends_with(".exe")
                    {
                        self.pck_path = path_str;
                        self.load_pck();
                    }
                }
            }
        });

        // Top panel - Title bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🎮 GodotPckTool GUI");
                ui.separator();
                ui.label(format!("v{}", env!("CARGO_PKG_VERSION")));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("❓ 关于").clicked() {
                        self.show_about = true;
                    }
                    if ui.button("🌙/☀️").clicked() {
                        toggle_theme(ctx);
                    }
                });
            });
        });

        // Bottom panel - Status bar
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                if let Some((current, total)) = self.progress {
                    ui.separator();
                    let progress = current as f32 / total.max(1) as f32;
                    ui.add(egui::ProgressBar::new(progress).show_percentage());
                    ui.label(format!("{}/{}", current, total));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🗑️ 清空日志").clicked() {
                        self.logs.clear();
                    }
                });
            });
        });

        // Left panel - Controls
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(320.0)
            .show(ctx, |ui| {
                ui.heading("📁 文件选择");
                ui.separator();

                // PCK file path
                ui.horizontal(|ui| {
                    ui.label("PCK 文件:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.pck_path)
                            .hint_text("拖放或选择 .pck/.exe 文件")
                            .desired_width(180.0),
                    );
                    if ui.button("📂").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("PCK/EXE", &["pck", "exe"])
                            .pick_file()
                        {
                            self.pck_path = path.to_string_lossy().to_string();
                        }
                    }
                });

                // Load button
                ui.horizontal(|ui| {
                    let load_btn = ui.add_enabled(!self.is_busy, egui::Button::new("📥 加载 PCK"));
                    if load_btn.clicked() {
                        self.load_pck();
                    }
                    if self.loaded_pck.is_some() {
                        ui.label("✅");
                    }
                });

                ui.add_space(10.0);
                ui.separator();
                ui.heading("📤 解压设置");

                // Output directory
                ui.horizontal(|ui| {
                    ui.label("输出目录:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.output_dir)
                            .hint_text("选择解压目标目录")
                            .desired_width(180.0),
                    );
                    if ui.button("📂").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.output_dir = path.to_string_lossy().to_string();
                        }
                    }
                });

                // Extract options
                ui.checkbox(&mut self.overwrite_existing, "覆盖已存在文件");
                ui.checkbox(&mut self.verify_md5, "校验 MD5");

                // Extract button
                let extract_enabled = !self.is_busy && self.loaded_pck.is_some();
                let extract_btn =
                    ui.add_enabled(extract_enabled, egui::Button::new("📦 解压全部"));
                if extract_btn.clicked() {
                    self.extract_pck();
                }

                ui.add_space(10.0);
                ui.separator();
                ui.heading("🔐 加密设置");

                // Encryption key
                ui.horizontal(|ui| {
                    ui.label("密钥 (Hex):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.encryption_key_hex)
                            .hint_text("64 位十六进制")
                            .desired_width(200.0)
                            .password(true),
                    );
                });
                if !self.encryption_key_hex.is_empty() {
                    if self.parse_key().is_some() {
                        ui.label("✅ 密钥格式正确");
                    } else {
                        ui.colored_label(egui::Color32::RED, "❌ 密钥格式错误 (需要 64 位 hex)");
                    }
                }

                ui.add_space(10.0);
                ui.separator();

                // PCK Info
                if let Some(loaded) = &self.loaded_pck {
                    ui.heading("📊 PCK 信息");
                    ui.label(format!("文件数: {}", loaded.file_count));
                    ui.label(format!("总大小: {}", format_size(loaded.total_size)));
                    let header = loaded.pck.header();
                    ui.label(format!("Godot 版本: {}", header.godot_version_string()));
                    ui.label(format!("PCK 格式版本: {}", header.format_version));
                    if loaded.pck.is_encrypted() {
                        ui.colored_label(egui::Color32::YELLOW, "🔒 已加密");
                    }
                    if loaded.pck.is_embedded() {
                        ui.label("📦 嵌入式 PCK");
                    }
                }
            });

        // Central panel - File list and logs
        egui::CentralPanel::default().show(ctx, |ui| {
            // Tabs
            ui.horizontal(|ui| {
                ui.heading("📋 内容");
                ui.separator();
                // Filter
                ui.label("🔍");
                let filter_response = ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text("过滤文件...")
                        .desired_width(150.0),
                );
                if filter_response.changed() {
                    self.update_filter();
                }
                if let Some(loaded) = &self.loaded_pck {
                    ui.label(format!(
                        "({}/{})",
                        self.filtered_entries.len(),
                        loaded.file_count
                    ));
                }
            });

            ui.separator();

            // Split view: file list on top, logs on bottom
            let available_height = ui.available_height();

            // File list (top half)
            egui::ScrollArea::vertical()
                .id_source("file_list")
                .max_height(available_height * 0.6)
                .show(ui, |ui| {
                    if let Some(loaded) = &self.loaded_pck {
                        egui::Grid::new("file_grid")
                            .num_columns(3)
                            .striped(true)
                            .show(ui, |ui| {
                                // Header
                                ui.strong("路径");
                                ui.strong("大小");
                                ui.strong("状态");
                                ui.end_row();

                                // Entries
                                for &idx in &self.filtered_entries {
                                    if let Some(entry) = loaded.entries.get(idx) {
                                        let selected = self.selected_entry == Some(idx);
                                        if ui
                                            .selectable_label(selected, &entry.path)
                                            .clicked()
                                        {
                                            self.selected_entry = Some(idx);
                                        }
                                        ui.label(format_size(entry.size));
                                        if entry.is_encrypted {
                                            ui.label("🔒");
                                        } else {
                                            ui.label("");
                                        }
                                        ui.end_row();
                                    }
                                }
                            });
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label("📂 拖放 PCK 文件到此处，或点击左侧「加载 PCK」按钮");
                        });
                    }
                });

            ui.separator();
            ui.label("📝 日志");

            // Logs (bottom)
            egui::ScrollArea::vertical()
                .id_source("logs")
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log in &self.logs {
                        ui.label(log);
                    }
                });
        });

        // About dialog
        if self.show_about {
            egui::Window::new("关于 GodotPckTool GUI")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("🎮 GodotPckTool GUI");
                        ui.label(format!("版本: {}", env!("CARGO_PKG_VERSION")));
                        ui.add_space(10.0);
                        ui.label("Godot PCK 文件查看/解压工具");
                        ui.label("基于 godotpck-rs 库");
                        ui.add_space(10.0);
                        ui.hyperlink_to("GitHub", "https://github.com/vagmr/GodotPckTool");
                        ui.add_space(10.0);
                        if ui.button("关闭").clicked() {
                            self.show_about = false;
                        }
                    });
                });
        }

        // Request repaint if busy (for progress updates)
        if self.is_busy {
            ctx.request_repaint();
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Simple timestamp without external crate
fn chrono_lite() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let hours = (secs / 3600) % 24;
    let mins = (secs / 60) % 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

/// Format file size in human-readable form
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Configure fonts for Chinese support
fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Try to load Chinese fonts from Windows
    let font_paths = [
        "C:/Windows/Fonts/msyh.ttc",
        "C:/Windows/Fonts/msyh.ttf",
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/simsun.ttc",
    ];

    for path in font_paths {
        if let Ok(font_data) = std::fs::read(path) {
            fonts.font_data.insert(
                "chinese".to_owned(),
                egui::FontData::from_owned(font_data).into(),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "chinese".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("chinese".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

/// Configure visual style
fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    // Rounded corners
    style.visuals.window_rounding = egui::Rounding::same(10.0);
    style.visuals.menu_rounding = egui::Rounding::same(8.0);
    style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);
    style.visuals.widgets.active.rounding = egui::Rounding::same(6.0);

    ctx.set_style(style);

    // Default to dark mode
    ctx.set_visuals(egui::Visuals::dark());
}

/// Toggle between dark and light theme
fn toggle_theme(ctx: &egui::Context) {
    let visuals = ctx.style().visuals.clone();
    if visuals.dark_mode {
        ctx.set_visuals(egui::Visuals::light());
    } else {
        ctx.set_visuals(egui::Visuals::dark());
    }
}
