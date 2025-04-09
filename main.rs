use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{LineEnding, EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey};
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, Payload};
use serde::{Serialize, Deserialize};
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use chrono::Utc;
use base64::prelude::*;
use dirs;
use sha2::Sha256;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct KeyData {
    username: String,
    public_key_path: String,
        private_key_path: Option<String>,
}

// Получение директорий для ключей
fn get_private_key_directory() -> String {
    dirs::home_dir()
    .unwrap_or_else(|| Path::new(".").to_path_buf())
    .to_string_lossy()
    .into_owned()
}

fn get_public_key_directory() -> String {
    dirs::download_dir()
    .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| Path::new(".").to_path_buf()))
    .to_string_lossy()
    .into_owned()
}

// Генерация пары ключей RSA
fn generate_key_pair(username: &str) -> (String, String) {
    let mut rng = OsRng;
    let bits = 4096;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("Ошибка генерации приватного ключа");
    let pub_key = priv_key.to_public_key();

    let current_time = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let priv_dir = get_private_key_directory();
    let pub_dir = get_public_key_directory();

    let priv_filename = format!("{}/RSA_{}_priv_{}.pem", priv_dir, username, current_time);
    let pub_filename = format!("{}/RSA_{}_pub_{}.pem", pub_dir, username, current_time);

    let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).expect("Ошибка сериализации приватного ключа");
    let pub_pem = pub_key.to_public_key_pem(LineEnding::LF).expect("Ошибка сериализации публичного ключа");

    fs::write(&priv_filename, priv_pem).expect("Ошибка записи приватного ключа");
    fs::write(&pub_filename, pub_pem).expect("Ошибка записи публичного ключа");

    println!("Приватный ключ сохранен в: {}", priv_filename);
    println!("Публичный ключ сохранен в: {}", pub_filename);

    (priv_filename, pub_filename)
}

// Сохранение ключей в JSON
fn save_keys_to_json(username: &str, pub_filename: &str, priv_filename: Option<&str>, json_file: &str) {
    let key_data = KeyData {
        username: username.to_string(),
        public_key_path: pub_filename.to_string(),
            private_key_path: priv_filename.map(String::from),
    };

    let mut data: Vec<KeyData> = if Path::new(json_file).exists() {
        let contents = fs::read_to_string(json_file).unwrap_or_default();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    };

    data.push(key_data);
    let json = serde_json::to_string_pretty(&data).expect("Ошибка сериализации JSON");
    fs::write(json_file, json).expect("Ошибка записи в JSON файл");
}

// Вывод списка пользователей
fn list_users(json_file: &str) {
    if !Path::new(json_file).exists() {
        println!("JSON файл не существует или пуст.");
        return;
    }

    let contents = fs::read_to_string(json_file).expect("Ошибка чтения JSON файла");
    let data: Vec<KeyData> = serde_json::from_str(&contents).expect("Ошибка парсинга JSON");

    if data.is_empty() {
        println!("Список пользователей пуст.");
    } else {
        println!("Список пользователей:");
        for (idx, entry) in data.iter().enumerate() {
            let public_key = &entry.public_key_path;
            let default_private_key = "Не указан".to_string();
            let private_key = entry.private_key_path.as_ref().unwrap_or(&default_private_key);
            println!(
                "{}. Имя пользователя: {}, Путь к публичному ключу: {}, Путь к приватному ключу: {}",
                idx + 1, entry.username, public_key, private_key
            );
        }
    }
}

// Выбор пользователя для шифрования
fn get_user_to_encrypt(json_file: &str) -> Option<(String, KeyData)> {
    let contents = fs::read_to_string(json_file).expect("Ошибка чтения JSON файла");
    let data: Vec<KeyData> = serde_json::from_str(&contents).expect("Ошибка парсинга JSON");
    let valid_users: Vec<&KeyData> = data.iter().filter(|entry| entry.public_key_path.len() > 0).collect();

    if valid_users.is_empty() {
        println!("Нет пользователей с публичными ключами.");
        return None;
    }

    println!("Доступные пользователи для шифрования:");
    for (idx, entry) in valid_users.iter().enumerate() {
        println!("{}. {}", idx + 1, entry.username);
    }

    println!("Выберите пользователя (введите номер): ");
    let mut choice = String::new();
    io::stdin().lock().read_line(&mut choice).expect("Ошибка чтения выбора");
    let choice: usize = choice.trim().parse::<usize>().expect("Введите корректный номер") - 1;

    if choice < valid_users.len() {
        Some((valid_users[choice].public_key_path.clone(), valid_users[choice].clone()))
    } else {
        println!("Неверный выбор.");
        None
    }
}

// Выбор пользователя для расшифрования
fn get_user_to_decrypt(json_file: &str) -> Option<(String, KeyData)> {
    let contents = fs::read_to_string(json_file).expect("Ошибка чтения JSON файла");
    let data: Vec<KeyData> = serde_json::from_str(&contents).expect("Ошибка парсинга JSON");
    let valid_users: Vec<&KeyData> = data.iter().filter(|entry| entry.private_key_path.is_some()).collect();

    if valid_users.is_empty() {
        println!("Нет пользователей с приватными ключами.");
        return None;
    }

    println!("Доступные пользователи для расшифрования:");
    for (idx, entry) in valid_users.iter().enumerate() {
        println!("{}. {}", idx + 1, entry.username);
    }

    println!("Выберите пользователя (введите номер): ");
    let mut choice = String::new();
    io::stdin().lock().read_line(&mut choice).expect("Ошибка чтения выбора");
    let choice: usize = choice.trim().parse::<usize>().expect("Введите корректный номер") - 1;

    if choice < valid_users.len() {
        Some((valid_users[choice].private_key_path.clone().unwrap(), valid_users[choice].clone()))
    } else {
        println!("Неверный выбор.");
        None
    }
}

// Ввод многострочного текста
fn get_multiline_input(prompt: &str) -> String {
    println!("{}", prompt);
    println!("Введите текст (для завершения введите пустую строку):");
    let stdin = io::stdin();
    let mut lines = Vec::new();
    for line in stdin.lock().lines() {
        let line = line.expect("Ошибка чтения строки");
        if line.trim().is_empty() {
            break;
        }
        lines.push(line);
    }
    lines.join("\n")
}

// Поиск ключей в домашней директории
fn find_keys_in_directory(dir: &Path) -> Vec<(String, Option<String>, String)> {
    let mut keys: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();

    fn visit_dirs(dir: &Path, keys: &mut HashMap<String, (Option<String>, Option<String>)>) -> io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, keys)?;
                } else if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.starts_with("RSA_") && filename.ends_with(".pem") {
                        let parts: Vec<&str> = filename.split('_').collect();
                        if parts.len() == 4 {
                            let username = parts[1];
                            let key_type = parts[2];
                            let key_entry = keys.entry(username.to_string()).or_insert((None, None));
                            if key_type == "priv" {
                                key_entry.0 = Some(path.to_string_lossy().into_owned());
                            } else if key_type == "pub" {
                                key_entry.1 = Some(path.to_string_lossy().into_owned());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    if let Err(e) = visit_dirs(dir, &mut keys) {
        println!("Ошибка при поиске ключей: {}", e);
    }

    keys.into_iter()
    .filter_map(|(username, (priv_path, pub_path))| {
        pub_path.map(|pub_p| (username, priv_path, pub_p))
    })
    .collect()
}

// Добавление найденных ключей в JSON
fn add_found_keys_to_json(json_file: &str) {
    let home_dir = dirs::home_dir().expect("Не удалось определить домашнюю директорию");
    let found_keys = find_keys_in_directory(&home_dir);

    if found_keys.is_empty() {
        println!("Ключи не найдены в домашней директории.");
        return;
    }

    println!("Найденные ключи:");
    for (idx, (username, priv_path, pub_path)) in found_keys.iter().enumerate() {
        println!(
            "{}. Пользователь: {}, Публичный ключ: {}, Приватный ключ: {}",
            idx + 1,
            username,
            pub_path,
            priv_path.as_ref().map_or("Не найден".to_string(), |p| p.clone())
        );
    }

    println!("Выберите ключи для добавления в базу (введите номера через запятую, например, 1, 3): ");
    let mut input = String::new();
    io::stdin().lock().read_line(&mut input).expect("Ошибка чтения ввода");
    let selections: Vec<usize> = input
    .split(',')
    .filter_map(|s| s.trim().parse::<usize>().ok())
    .map(|n| n - 1)
    .filter(|&n| n < found_keys.len())
    .collect();

    for &idx in &selections {
        let (username, priv_path, pub_path) = &found_keys[idx];
        save_keys_to_json(
            username,
            pub_path,
            priv_path.as_ref().map(|p| p.as_str()),
                          json_file,
        );
        println!("Ключи для {} добавлены в базу.", username);
    }
}

// Шифрование текста с использованием RSA + AES-GCM
#[derive(Serialize, Deserialize, Debug)]
struct EncryptedData {
    aes_key: String,
    iv: String,
    tag: String,
    ciphertext: String,
}

fn encrypt_text_gcm(public_key_path: &str, text: &str) -> EncryptedData {
    let mut rng = OsRng;
    let aes_key = Aes256Gcm::generate_key(&mut rng);
    let iv_bytes = rand::random::<[u8; 12]>();
    let iv = Nonce::from_slice(&iv_bytes);

    let cipher = Aes256Gcm::new(&aes_key);
    let payload = Payload {
        msg: text.as_bytes(),
        aad: b"",
    };
    let ciphertext = cipher.encrypt(iv, payload).expect("Ошибка шифрования AES-GCM");

    let pub_key_pem = fs::read_to_string(public_key_path).expect("Ошибка чтения публичного ключа");
    let pub_key = RsaPublicKey::from_public_key_pem(&pub_key_pem).expect("Ошибка парсинга публичного ключа");
    let encrypted_aes_key = pub_key.encrypt(
        &mut rng,
        rsa::Oaep::new::<Sha256>(),
                                            &aes_key,
    ).expect("Ошибка шифрования AES-ключа");

    EncryptedData {
        aes_key: BASE64_STANDARD.encode(&encrypted_aes_key),
        iv: BASE64_STANDARD.encode(iv),
        tag: BASE64_STANDARD.encode(&ciphertext[ciphertext.len() - 16..]),
        ciphertext: BASE64_STANDARD.encode(&ciphertext[..ciphertext.len() - 16]),
    }
}

// Расшифровка текста с использованием RSA + AES-GCM
fn decrypt_text_gcm(private_key_path: &str, encrypted_data: EncryptedData) -> String {
    let priv_key_pem = fs::read_to_string(private_key_path).expect("Ошибка чтения приватного ключа");
    let priv_key = RsaPrivateKey::from_pkcs8_pem(&priv_key_pem).expect("Ошибка парсинга приватного ключа");

    let encrypted_aes_key = BASE64_STANDARD.decode(&encrypted_data.aes_key).expect("Ошибка декодирования aes_key");
    let aes_key = priv_key.decrypt(
        rsa::Oaep::new::<Sha256>(),
                                   &encrypted_aes_key,
    ).expect("Ошибка расшифровки AES-ключа");

    let iv = BASE64_STANDARD.decode(&encrypted_data.iv).expect("Ошибка декодирования IV");
    let tag = BASE64_STANDARD.decode(&encrypted_data.tag).expect("Ошибка декодирования тега");
    let ciphertext = BASE64_STANDARD.decode(&encrypted_data.ciphertext).expect("Ошибка декодирования ciphertext");

    let mut full_ciphertext = Vec::new();
    full_ciphertext.extend_from_slice(&ciphertext);
    full_ciphertext.extend_from_slice(&tag);

    let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("Ошибка создания AES-GCM");
    let nonce = Nonce::from_slice(&iv);
    let plaintext = cipher.decrypt(nonce, &*full_ciphertext).expect("Ошибка расшифровки");

    String::from_utf8(plaintext).expect("Ошибка преобразования в строку")
}

// Основная функция
fn main() {
    let json_file = "keys.json";
    if !Path::new(json_file).exists() {
        fs::write(json_file, "[]").expect("Ошибка создания JSON файла");
    }

    loop {
        println!(
            "\n--- Главное меню ---\n\
1. Создать пару ключей и сохранить в JSON\n\
2. Зашифровать текст с использованием AES-GCM\n\
3. Расшифровать текст с использованием AES-GCM\n\
4. Показать всех пользователей\n\
5. Найти и добавить ключи из домашней директории\n\
0. Выйти из программы"
        );

        let mut choice = String::new();
        io::stdin().lock().read_line(&mut choice).expect("Ошибка чтения ввода");
        match choice.trim() {
            "1" => {
                println!("Введите имя пользователя: ");
                let mut username = String::new();
                io::stdin().lock().read_line(&mut username).expect("Ошибка чтения имени");
                let (priv_filename, pub_filename) = generate_key_pair(username.trim());
                save_keys_to_json(username.trim(), &pub_filename, Some(&priv_filename), json_file);
            }
            "2" => {
                if let Some((public_key_path, _)) = get_user_to_encrypt(json_file) {
                    let text = get_multiline_input("Введите текст для шифрования");
                    let encrypted = encrypt_text_gcm(&public_key_path, &text);
                    println!("Зашифрованные данные:\n{}", serde_json::to_string_pretty(&encrypted).unwrap());
                }
            }
            "3" => {
                if let Some((private_key_path, _)) = get_user_to_decrypt(json_file) {
                    let input = get_multiline_input("Введите зашифрованные данные в формате JSON");
                    let encrypted_data: EncryptedData = serde_json::from_str(&input).expect("Ошибка парсинга JSON");
                    let decrypted = decrypt_text_gcm(&private_key_path, encrypted_data);
                    println!("Расшифрованный текст:\n{}", decrypted);
                }
            }
            "4" => {
                list_users(json_file);
            }
            "5" => {
                add_found_keys_to_json(json_file);
            }
            "0" => {
                println!("Выход из программы.");
                break;
            }
            _ => println!("Неверный выбор."),
        }
    }
}
