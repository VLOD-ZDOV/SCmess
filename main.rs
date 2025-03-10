use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::KeyInit; // для создания нового экземпляра шифра
use aes_gcm::aead::Aead;
use base64::{encode, decode};
use chrono::Local;
use dirs;
use eframe;
use egui;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme, PublicKey};
use rsa::pkcs8::{
    EncodePrivateKey, EncodePublicKey, DecodePublicKey, DecodePrivateKey, LineEnding,
};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use std::fs;
use std::io::Read;

//
// Структуры для конфигурации и хранения ключей
//
#[derive(Serialize, Deserialize)]
struct Config {
    legacy_mode: bool,
    pqc_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { legacy_mode: false, pqc_mode: false }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct KeyEntry {
    username: String,
    public_key_path: Option<String>,
        private_key_path: Option<String>,
}

//
// Состояние приложения
//
#[derive(Default)]
struct AppState {
    config: Config,
    keys: Vec<KeyEntry>,
    selected_tab: usize, // 0: Ключи, 1: Текст, 2: Файлы, 3: Настройки, 4: Информация
    text_input: String,
    file_path: String,
    // Временные поля для ввода
    input_username: String,
    input_key_type: String, // "public" или "private"
    password: String,
    message: String,
}

impl AppState {
    fn load_config(&mut self) {
        let config_path = "config.json";
        if let Ok(data) = fs::read_to_string(config_path) {
            if let Ok(cfg) = serde_json::from_str::<Config>(&data) {
                self.config = cfg;
            } else {
                self.config = Config::default();
                self.save_config();
            }
        } else {
            self.config = Config::default();
            self.save_config();
        }
    }
    fn save_config(&self) {
        let _ = fs::write("config.json", serde_json::to_string_pretty(&self.config).unwrap());
    }
    fn load_keys(&mut self) {
        let keys_path = "keys.json";
        if let Ok(data) = fs::read_to_string(keys_path) {
            if let Ok(keys) = serde_json::from_str::<Vec<KeyEntry>>(&data) {
                self.keys = keys;
            } else {
                self.keys = vec![];
                self.save_keys();
            }
        } else {
            self.keys = vec![];
            self.save_keys();
        }
    }
    fn save_keys(&self) {
        let _ = fs::write("keys.json", serde_json::to_string_pretty(&self.keys).unwrap());
    }
}

//
// Функции работы с RSA-ключами и AES-GCM шифрованием текста/файлов
//

// Генерация пары RSA-ключей (4096 бит) и сохранение в файлы
fn generate_key_pair(username: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    let current_time = Local::now().format("%Y%m%d%H%M%S").to_string();
    let priv_filename = format!("RSA_{}_priv_{}.pem", username, current_time);
    let pub_filename = format!("RSA_{}_pub_{}.pem", username, current_time);
    fs::write(&priv_filename, private_key.to_pkcs8_pem(LineEnding::LF)?.to_string())?;
    fs::write(&pub_filename, public_key.to_public_key_pem(LineEnding::LF)?)?;
    Ok((priv_filename, pub_filename))
}

// AES-GCM: шифрование текста (AES-ключ генерируется случайно, а затем зашифровывается RSA)
fn encrypt_text_gcm(public_key_path: &str, text: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let aes_key: [u8; 32] = rand::random();
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ciphertext = cipher.encrypt(Nonce::from_slice(&iv), text.as_bytes())
    .map_err(|e| -> Box<dyn std::error::Error> { format!("AES encrypt error: {}", e).into() })?;
    let pub_key_pem = fs::read_to_string(public_key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&pub_key_pem)?;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let encrypted_aes_key = public_key.encrypt(&mut OsRng, padding, &aes_key)?;
    Ok(serde_json::json!({
        "aes_key": encode(&encrypted_aes_key),
                         "iv": encode(&iv),
                         "ciphertext": encode(&ciphertext)
    }))
}

// AES-GCM: расшифровка текста
fn decrypt_text_gcm(private_key_path: &str, encrypted_data: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_aes_key = decode(encrypted_data["aes_key"].as_str().unwrap())?;
    let iv = decode(encrypted_data["iv"].as_str().unwrap())?;
    let ciphertext = decode(encrypted_data["ciphertext"].as_str().unwrap())?;
    let priv_key_pem = fs::read_to_string(private_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&priv_key_pem)?;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let aes_key = private_key.decrypt(padding, &encrypted_aes_key)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let plaintext = cipher.decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
    .map_err(|e| -> Box<dyn std::error::Error> { format!("AES decrypt error: {}", e).into() })?;
    Ok(String::from_utf8(plaintext)?)
}

// AES-GCM: шифрование файла
fn encrypt_file_gcm(public_key_path: &str, file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let aes_key: [u8; 32] = rand::random();
    let iv: [u8; 12] = rand::random();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let plaintext = fs::read(file_path)?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&iv), plaintext.as_ref())
    .map_err(|e| -> Box<dyn std::error::Error> { format!("AES encrypt file error: {}", e).into() })?;
    let pub_key_pem = fs::read_to_string(public_key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&pub_key_pem)?;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let encrypted_aes_key = public_key.encrypt(&mut OsRng, padding, &aes_key)?;
    let mut out = Vec::new();
    out.extend_from_slice(&encrypted_aes_key);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    let encrypted_file_path = format!("{}.enc", file_path);
    fs::write(&encrypted_file_path, &out)?;
    Ok(encrypted_file_path)
}

// AES-GCM: расшифровка файла
fn decrypt_file_gcm(private_key_path: &str, encrypted_file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(encrypted_file_path)?;
    let mut encrypted_aes_key = vec![0u8; 512]; // 4096 бит = 512 байт
    file.read_exact(&mut encrypted_aes_key)?;
    let mut iv = vec![0u8; 12];
    file.read_exact(&mut iv)?;
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;
    let priv_key_pem = fs::read_to_string(private_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&priv_key_pem)?;
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let aes_key = private_key.decrypt(padding, &encrypted_aes_key)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let plaintext = cipher.decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
    .map_err(|e| -> Box<dyn std::error::Error> { format!("AES decrypt file error: {}", e).into() })?;
    let decrypted_file_path = encrypted_file_path.strip_suffix(".enc").unwrap_or("decrypted_file").to_string();
    fs::write(&decrypted_file_path, &plaintext)?;
    Ok(decrypted_file_path)
}

//
// Заглушки для legacy и PQC режимов
//
fn encrypt_text_legacy(_public_key_path: &str, _text: &str) -> Result<String, Box<dyn std::error::Error>> {
    Err("Legacy RSA шифрование не реализовано".into())
}

fn decrypt_text_legacy(_private_key_path: &str, _encrypted_message: &str) -> Result<String, Box<dyn std::error::Error>> {
    Err("Legacy RSA расшифровка не реализовано".into())
}

fn encrypt_file_legacy(_public_key_path: &str, _file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    Err("Legacy RSA шифрование файла не реализовано".into())
}

fn decrypt_file_legacy(_private_key_path: &str, _encrypted_file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    Err("Legacy RSA расшифровка файла не реализовано".into())
}

fn encrypt_text_xchacha_rsa(_public_key_path: &str, _text: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Err("PQC (Kyber + XChaCha20) шифрование не реализовано".into())
}

fn decrypt_text_xchacha_rsa(_private_key_path: &str, _encrypted_data: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    Err("PQC (Kyber + XChaCha20) расшифровка не реализовано".into())
}

fn encrypt_xchacha(_plaintext: &str, _password: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Err("XChaCha20 шифрование с паролем не реализовано".into())
}

fn decrypt_xchacha(_encrypted_data: &serde_json::Value, _password: &str) -> Result<String, Box<dyn std::error::Error>> {
    Err("XChaCha20 расшифровка с паролем не реализовано".into())
}

//
// Графический интерфейс с использованием eframe/egui
//
impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.selected_tab == 0, "Ключи").clicked() { self.selected_tab = 0; }
                if ui.selectable_label(self.selected_tab == 1, "Текст").clicked() { self.selected_tab = 1; }
                if ui.selectable_label(self.selected_tab == 2, "Файлы").clicked() { self.selected_tab = 2; }
                if ui.selectable_label(self.selected_tab == 3, "Настройки").clicked() { self.selected_tab = 3; }
                if ui.selectable_label(self.selected_tab == 4, "Информация").clicked() { self.selected_tab = 4; }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_tab {
                0 => self.ui_keys_tab(ui),
                                           1 => self.ui_text_tab(ui),
                                           2 => self.ui_files_tab(ui),
                                           3 => self.ui_settings_tab(ui),
                                           4 => self.ui_info_tab(ui),
                                           _ => {},
            }
        });
    }
}

impl AppState {
    fn ui_keys_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Ключи");
        ui.separator();
        // Создание пары ключей
        ui.horizontal(|ui| {
            ui.label("Имя пользователя:");
            ui.text_edit_singleline(&mut self.input_username);
            if ui.button("Создать пару ключей").clicked() {
                if !self.input_username.is_empty() {
                    match generate_key_pair(&self.input_username) {
                        Ok((priv_path, pub_path)) => {
                            self.keys.push(KeyEntry {
                                username: self.input_username.clone(),
                                           public_key_path: Some(pub_path.clone()),
                                               private_key_path: Some(priv_path.clone()),
                            });
                            self.save_keys();
                            self.message = format!("Ключи созданы:\nПриватный: {}\nПубличный: {}", priv_path, pub_path);
                        },
                        Err(e) => self.message = format!("Ошибка создания ключей: {}", e),
                    }
                }
            }
        });
        ui.separator();
        // Добавление ключа
        ui.horizontal(|ui| {
            ui.label("Имя пользователя:");
            ui.text_edit_singleline(&mut self.input_username);
            ui.label("Тип ключа (public/private):");
            ui.text_edit_singleline(&mut self.input_key_type);
            if ui.button("Добавить ключ").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    let path_str = path.to_string_lossy().to_string();
                    if let Some(entry) = self.keys.iter_mut().find(|e| e.username == self.input_username) {
                        if self.input_key_type == "public" {
                            entry.public_key_path = Some(path_str.clone());
                        } else {
                            entry.private_key_path = Some(path_str.clone());
                        }
                    } else {
                        let mut entry = KeyEntry {
                            username: self.input_username.clone(),
                      public_key_path: None,
                          private_key_path: None,
                        };
                        if self.input_key_type == "public" {
                            entry.public_key_path = Some(path_str.clone());
                        } else {
                            entry.private_key_path = Some(path_str.clone());
                        }
                        self.keys.push(entry);
                    }
                    self.save_keys();
                    self.message = format!("{} ключ для '{}' добавлен.", self.input_key_type, self.input_username);
                }
            }
        });
        ui.separator();
        if ui.button("Показать пользователей").clicked() {
            let mut info = String::new();
            for entry in &self.keys {
                info.push_str(&format!("Имя: {}, Публичный: {:?}, Приватный: {:?}\n",
                                       entry.username, entry.public_key_path, entry.private_key_path));
            }
            self.message = info;
        }
        if ui.button("Удалить пользователя (по имени)").clicked() {
            self.keys.retain(|e| e.username != self.input_username);
            self.save_keys();
            self.message = format!("Пользователь '{}' удалён.", self.input_username);
        }
        if ui.button("Автоскан ключей (public)").clicked() {
            let found = scan_for_keys("public");
            self.message = format!("Найдено ключей: {:?}", found);
        }
        ui.separator();
        ui.label(&self.message);
    }

    fn ui_text_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Текст");
        ui.separator();
        ui.label("Введите текст:");
        ui.text_edit_multiline(&mut self.text_input);
        ui.separator();
        if ui.button("Зашифровать текст (AES-GCM)").clicked() {
            if let Some(entry) = self.keys.iter().find(|e| e.public_key_path.is_some()) {
                if let Some(pub_key) = &entry.public_key_path {
                    match encrypt_text_gcm(pub_key, &self.text_input) {
                        Ok(result) => {
                            self.text_input = serde_json::to_string_pretty(&result).unwrap();
                            self.message = "Текст зашифрован (AES-GCM).".to_string();
                        },
                        Err(e) => self.message = format!("Ошибка шифрования: {}", e),
                    }
                }
            } else {
                self.message = "Нет пользователей с публичными ключами.".to_string();
            }
        }
        if ui.button("Расшифровать текст (AES-GCM)").clicked() {
            if let Some(entry) = self.keys.iter().find(|e| e.private_key_path.is_some()) {
                if let Some(priv_key) = &entry.private_key_path {
                    match serde_json::from_str::<serde_json::Value>(&self.text_input) {
                        Ok(val) => {
                            match decrypt_text_gcm(priv_key, &val) {
                                Ok(txt) => {
                                    self.text_input = txt;
                                    self.message = "Текст расшифрован (AES-GCM).".to_string();
                                },
                                Err(e) => self.message = format!("Ошибка расшифровки: {}", e),
                            }
                        },
                        Err(e) => self.message = format!("Ошибка парсинга: {}", e),
                    }
                }
            } else {
                self.message = "Нет пользователей с приватными ключами.".to_string();
            }
        }
        // Заглушки для legacy и PQC режимов
        if self.config.legacy_mode {
            ui.separator();
            if ui.button("Зашифровать текст (Legacy RSA)").clicked() {
                match encrypt_text_legacy("", &self.text_input) {
                    Ok(res) => self.text_input = res,
                    Err(e) => self.message = format!("Ошибка: {}", e),
                }
            }
            if ui.button("Расшифровать текст (Legacy RSA)").clicked() {
                match decrypt_text_legacy("", &self.text_input) {
                    Ok(res) => self.text_input = res,
                    Err(e) => self.message = format!("Ошибка: {}", e),
                }
            }
        }
        if self.config.pqc_mode {
            ui.separator();
            if ui.button("Зашифровать текст (Kyber + XChaCha20)").clicked() {
                match encrypt_text_xchacha_rsa("", &self.text_input) {
                    Ok(res) => self.text_input = serde_json::to_string_pretty(&res).unwrap(),
                    Err(e) => self.message = format!("Ошибка: {}", e),
                }
            }
            if ui.button("Расшифровать текст (Kyber + XChaCha20)").clicked() {
                match serde_json::from_str::<serde_json::Value>(&self.text_input) {
                    Ok(val) => {
                        match decrypt_text_xchacha_rsa("", &val) {
                            Ok(res) => self.text_input = res,
                            Err(e) => self.message = format!("Ошибка: {}", e),
                        }
                    },
                    Err(e) => self.message = format!("Ошибка парсинга: {}", e),
                }
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Пароль:");
                ui.text_edit_singleline(&mut self.password);
            });
            if ui.button("Зашифровать текст (XChaCha20 с паролем)").clicked() {
                match encrypt_xchacha(&self.text_input, &self.password) {
                    Ok(res) => self.text_input = serde_json::to_string_pretty(&res).unwrap(),
                    Err(e) => self.message = format!("Ошибка: {}", e),
                }
            }
            if ui.button("Расшифровать текст (XChaCha20 с паролем)").clicked() {
                match serde_json::from_str::<serde_json::Value>(&self.text_input) {
                    Ok(val) => {
                        match decrypt_xchacha(&val, &self.password) {
                            Ok(res) => self.text_input = res,
                            Err(e) => self.message = format!("Ошибка: {}", e),
                        }
                    },
                    Err(e) => self.message = format!("Ошибка парсинга: {}", e),
                }
            }
        }
        ui.separator();
        ui.label(&self.message);
    }

    fn ui_files_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Файлы");
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Путь к файлу:");
            ui.text_edit_singleline(&mut self.file_path);
            if ui.button("Выбрать файл").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.file_path = path.to_string_lossy().to_string();
                }
            }
        });
        ui.separator();
        if ui.button("Зашифровать файл (AES-GCM)").clicked() {
            if let Some(entry) = self.keys.iter().find(|e| e.public_key_path.is_some()) {
                if let Some(pub_key) = &entry.public_key_path {
                    match encrypt_file_gcm(pub_key, &self.file_path) {
                        Ok(enc_file) => self.message = format!("Файл зашифрован (AES-GCM): {}", enc_file),
                        Err(e) => self.message = format!("Ошибка: {}", e),
                    }
                }
            }
        }
        if ui.button("Расшифровать файл (AES-GCM)").clicked() {
            if let Some(entry) = self.keys.iter().find(|e| e.private_key_path.is_some()) {
                if let Some(priv_key) = &entry.private_key_path {
                    match decrypt_file_gcm(priv_key, &self.file_path) {
                        Ok(dec_file) => self.message = format!("Файл расшифрован (AES-GCM): {}", dec_file),
                        Err(e) => self.message = format!("Ошибка: {}", e),
                    }
                }
            }
        }
        if self.config.legacy_mode {
            ui.separator();
            if ui.button("Зашифровать файл (Legacy RSA)").clicked() {
                match encrypt_file_legacy("", &self.file_path) {
                    Ok(res) => self.message = res,
                    Err(e) => self.message = format!("Ошибка: {}", e),
                }
            }
            if ui.button("Расшифровать файл (Legacy RSA)").clicked() {
                match decrypt_file_legacy("", &self.file_path) {
                    Ok(res) => self.message = res,
                    Err(e) => self.message = format!("Ошибка: {}", e),
                }
            }
        }
        ui.separator();
        ui.label(&self.message);
    }

    fn ui_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Настройки");
        ui.separator();
        let mut legacy = self.config.legacy_mode;
        if ui.checkbox(&mut legacy, "Legacy-режим").changed() {
            self.config.legacy_mode = legacy;
            self.save_config();
        }
        let mut pqc = self.config.pqc_mode;
        if ui.checkbox(&mut pqc, "PQC-режим").changed() {
            self.config.pqc_mode = pqc;
            self.save_config();
        }
    }

    fn ui_info_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Информация");
        ui.separator();
        if ui.button("Показать информацию").clicked() {
            self.message = "1. Сначала сгенерируйте ключи и отправьте публичный ключ другу.\n\
2. Используйте автоскан для поиска ключей или добавьте их вручную.\n\
3. Для шифрования текста рекомендуется AES-GCM (поддерживает до 64 ГБ).\n\
4. Для сброса удалите keys.json и ключи.\n\
5. GitHub: https://github.com/VLOD-ZDOV\n\
6. Версия: 5.4".to_string();
        }
        ui.separator();
        ui.label(&self.message);
    }
}

//
// Функция сканирования директорий на наличие файлов-ключей
//
fn scan_for_keys(key_type: &str) -> Vec<String> {
    let mut found_keys = Vec::new();
    if let Some(home) = dirs::home_dir() {
        let dirs_to_scan = vec![
            home.clone(),
            home.join("Downloads"),
            home.join("Desktop"),
            home.join("Documents"),
        ];
        for dir in dirs_to_scan {
            if dir.exists() {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                                if key_type == "public" {
                                    if filename.starts_with("RSA_") && filename.contains("_pub_") && filename.ends_with(".pem") {
                                        found_keys.push(path.to_string_lossy().to_string());
                                    }
                                } else if key_type == "private" {
                                    if filename.starts_with("RSA_") && filename.contains("_priv_") && filename.ends_with(".pem") {
                                        found_keys.push(path.to_string_lossy().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    found_keys
}

//
// Точка входа
//
fn main() {
    let native_options = eframe::NativeOptions::default();
    let mut app = AppState::default();
    app.load_config();
    app.load_keys();
    eframe::run_native("SCmess", native_options, Box::new(|_cc| Box::new(app)));
}
