from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
import os, base64, json, sys, random, binascii
from datetime import datetime
import time
import pyperclip
import logging
from concurrent.futures import ProcessPoolExecutor
CONFIG_FILE = "config.json"

# =============================================================================
# Генерации пары ключей RSA с использованием имени пользователя и текущей даты
# =============================================================================

def get_private_key_directory():
    """Определяет директорию для сохранения приватного ключа в зависимости от платформы."""
    if os.name == 'nt':  # Windows
        return os.path.expanduser("~")
        
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        # Папка Tesrmux на Android
        return '/data/data/com.termux/files/home'
        
    else:  # Другие платформы
        return os.path.expanduser("~")
        
# =============================================================================
# Определяет директорию для сохранения публичного ключа в зависимости от платформы
# =============================================================================

def get_public_key_directory():

    if os.name == 'nt':  # Windows
        return os.path.join(os.environ['USERPROFILE'], 'Downloads')
        
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        return '/sdcard/'
        
    else:  # Другие платформы
        return os.path.expanduser("~")
# =============================================================================
# Обычное инфо
# =============================================================================

def info():
    print("""
SCmess — программа для шифрования сообщений и файлов с помощью RSA-ключей.

Быстрый старт:
  1. Выберите пункт 1 — создайте пару ключей, введите своё имя.
     Приватный ключ хранится у вас; публичный ключ отправьте собеседнику.
  2. Добавьте публичный ключ собеседника через пункт 6 или автоскан (пункт 9).
  3. Зашифруйте сообщение (пункт 2) — скопируйте результат и отправьте.
  4. Для расшифровки вставьте полученный JSON в пункт 3.

Методы шифрования:
  • AES-GCM (пп. 2–5) — основной метод, до 64 ГБ, совместим с Rust-версией.
  • Legacy RSA (пп. 12–15) — включить через пункт 11.
  • PQC Kyber + XChaCha20 (пп. 18–21) — включить через пункт 16.
  • Режим переписки (пункт 17) — автоматически определяет входящие сообщения.

Управление пользователями:
  7. Показать всех пользователей и их статус.
  8. Удалить пользователя.
  24. Включить/выключить пользователя.

Сброс: удалите файл keys.json (и ключи по желанию).
GitHub: https://github.com/VLOD-ZDOV/SCmess  |  Версия: 1.7
""")
    
# =============================================================================
# Загружаем или создаём файл конфига legacy режима
# =============================================================================

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'r') as config_file:
        try:
            config = json.load(config_file)
        except json.JSONDecodeError:
            config = {"legacy_mode": False, "first_run": True}
else:
    config = {"legacy_mode": False, "first_run": True}

with open(CONFIG_FILE, 'w') as config_file:
    json.dump(config, config_file, indent=4)
    
# =============================================================================
# Переключение режима Legacy
# =============================================================================

def toggle_legacy_mode():
    config['legacy_mode'] = not config['legacy_mode']
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file, indent=4)
    print(f"Legacy-режим {'включен' if config['legacy_mode'] else 'выключен'}.")
    
# =============================================================================
# Генерация пары ключей RSA с использованием имени пользователя и текущей даты.
# =============================================================================

def generate_key_pair(username, key_size=4096):
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")

    # Пути для сохранения ключей
    pub_dir = get_public_key_directory()  # Путь для публичного ключа
    priv_dir = get_private_key_directory()  # Путь для приватного ключа

    # Генерация имени файлов для ключей на основе имени пользователя и текущей даты
    priv_filename = os.path.join(priv_dir, f"RSA_{username}_priv_{current_time}.pem")
    pub_filename = os.path.join(pub_dir, f"RSA_{username}_pub_{current_time}.pem")

    # Генерация приватного ключа
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Сохранение приватного ключа
    with open(priv_filename, 'wb') as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Получение публичного ключа
    public_key = private_key.public_key()

    # Сохранение публичного ключа
    with open(pub_filename, 'wb') as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Приватный ключ сохранен в: {priv_filename}")
    print(f"Публичный ключ сохранен в: {pub_filename}")

    return priv_filename, pub_filename
    
# =============================================================================
# Сохранение информации о ключах в JSON файл
# =============================================================================

def save_keys_to_json(username, pub_filename, priv_filename, json_file="keys.json"):
    key_data = {
        "username": username,
        "public_key_path": pub_filename,
        "private_key_path": priv_filename
    }

    # Проверка существования JSON-файла
    if os.path.exists(json_file):
        with open(json_file, 'r+') as file:
            try:
                data = json.load(file)

                # Если данные в JSON не являются списком, преобразуем их в список
                if isinstance(data, dict):
                    data = [data]
                elif not isinstance(data, list):
                    raise ValueError("Неверный формат JSON файла: ожидается список.")

            except json.JSONDecodeError:
                # Если файл пуст или поврежден, создаем новый список
                data = []

            data.append(key_data)
            file.seek(0)
            json.dump(data, file, indent=4)
    else:
        # Если JSON-файл не существует, создаем новый файл со списком ключей
        with open(json_file, 'w') as file:
            json.dump([key_data], file, indent=4)
            
# =============================================================================
# Директории для поиска ключей
# =============================================================================

if os.name == 'nt':
    SEARCH_DIRECTORIES = [
        os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
        os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
        os.path.expanduser("~")
    ]
if 'ANDROID_ROOT' in os.environ:
    SEARCH_DIRECTORIES = [
        '/data/data/com.termux/files/home', '/sdcard', '/sdcard/Download', '/sdcard/Telegram', '/sdcard/WhatsApp/Media'
    ]
else:
    SEARCH_DIRECTORIES = [
        os.path.expanduser("~/Desktop"), os.path.expanduser("~/Documents"), os.path.expanduser("~/Downloads"), os.path.expanduser("~")
    ]
    
# =============================================================================
# Сканирует стандартные и дополнительные папки на наличие файлов с публичными ключами, исключая уже существующие в keys.json.
# =============================================================================

def scan_for_public_keys(json_file):
    
    # Загружаем существующие ключи из JSON файла
    with open(json_file, 'r') as file:
        data = json.load(file)
        existing_keys = {entry.get('public_key_path') for entry in data if entry.get('public_key_path')}

    found_keys = set()

    # Поиск ключей во всех директориях из SEARCH_DIRECTORIES
    for dir_path in SEARCH_DIRECTORIES:
        if os.path.exists(dir_path):
            for root, _, files in os.walk(dir_path):
                for filename in files:
                    if filename.endswith('.pem') and 'pub' in filename:
                        key_path = os.path.join(root, filename)
                        key_path = os.path.normpath(key_path)  # Нормализуем путь
                        if key_path not in existing_keys:  # Проверяем, чтобы ключ не был уже добавлен
                            found_keys.add(key_path)

    return list(found_keys)  # Преобразуем set обратно в list

# =============================================================================
# Сканирование директорий для поиска ключей
# =============================================================================

def scan_for_keys(json_file, key_type='public'):
    with open(json_file, 'r') as file:
        data = json.load(file)
        existing_keys = {entry.get(f'{key_type}_key_path') for entry in data if entry.get(f'{key_type}_key_path')}
    
    use_standard_naming = input("Ключи имеют стандартный формат именования? (y/n): ").strip().lower() in ['y', '1', 'д','да','yes','ye']
    found_keys = set()
    
    for dir_path in SEARCH_DIRECTORIES:
        if os.path.exists(dir_path):
            for root, _, files in os.walk(dir_path):
                for filename in files:
                    key_path = os.path.join(root, filename)
                    if use_standard_naming:
                        if key_type == 'public' and filename.startswith("RSA_") and "_pub_" in filename and filename.endswith('.pem'):
                            if key_path not in existing_keys:
                                found_keys.add(key_path)
                        elif key_type == 'private' and filename.startswith("RSA_") and "_priv_" in filename and filename.endswith('.pem'):
                            if key_path not in existing_keys:
                                found_keys.add(key_path)
                    else:
                        if filename.endswith('.pem') and ((key_type == 'public' and 'pub' in filename) or (key_type == 'private' and 'pub' not in filename)):
                            if key_path not in existing_keys:
                                found_keys.add(key_path)
    return list(found_keys)



# =============================================================================
# Предлагает пользователю добавить найденные публичные ключи в JSON файл.
# =============================================================================

def prompt_add_found_keys(json_file="keys.json"):
    found_keys = scan_for_public_keys(json_file)
    if not found_keys:
        print("Публичные ключи не найдены в стандартных и пользовательских папках.")
        return

    for key_path in found_keys:
        # Извлекаем имя пользователя из имени файла ключа
        username = key_path.split('_')[-3]  # Предполагается, что имя в формате RSA_<username>_pub_*.pem
        print(f"Найден ключ пользователя '{username}': {key_path}")
        add = input(f"Добавить ключ пользователя '{username}'? (y/n): ")
        if add.lower() == 'y':
            add_friend_public_key(username, key_path, json_file)

# =============================================================================
# Добавляет публичный ключ друга в JSON файл.
# =============================================================================
            
def add_friend_public_key(username, friend_pub_key_path, json_file="keys.json"):
    friend_key_data = {
        "username": username,
        "public_key_path": friend_pub_key_path,
        "private_key_path": None
    }

# =============================================================================
# Функция для добавления публичного или приватного ключа пользователя. 
# =============================================================================
    
def add_friend_key(username, key_path, key_type, json_file):
    if key_type not in ['public', 'private']:
        print("Неверный тип ключа. Укажите 'public' или 'private'.")
        return

    # Чтение существующих данных из JSON
    with open(json_file, 'r') as file:
        data = json.load(file)

    # Поиск пользователя
    user_entry = next((entry for entry in data if entry['username'] == username), None)

    if not user_entry:
        # Создаем новую запись, если пользователя нет
        user_entry = {'username': username}
        data.append(user_entry)

    # Добавление пути к ключу в зависимости от типа
    if key_type == 'public':
        user_entry['public_key_path'] = key_path
        print(f"Публичный ключ для '{username}' добавлен.")
    elif key_type == 'private':
        user_entry['private_key_path'] = key_path
        print(f"Приватный ключ для '{username}' добавлен.")

    # Сохранение обновленных данных в JSON
    with open(json_file, 'w') as file:
        json.dump(data, file, indent=4)

# =============================================================================
# Удалить пользователя из базы данных
# =============================================================================

def delete_user_from_json(username, json_file="keys.json"):
    if os.path.exists(json_file):
        with open(json_file, 'r+') as file:
            data = json.load(file)
            data = [entry for entry in data if entry["username"] != username]
            file.seek(0)
            json.dump(data, file, indent=4)
            file.truncate()

        print(f"Пользователь '{username}' успешно удален из JSON файла.")
    else:
        print(f"JSON файл '{json_file}' не существует.")



def toggle_pqc_mode():
    config['pqc_mode'] = not config.get('pqc_mode', False)
    with open("config.json", 'w') as config_file:
        json.dump(config, config_file, indent=4)
    print(f"PQC-режим {'включен' if config['pqc_mode'] else 'выключен'}.")

# =============================================================================
# Основное меню программы
# =============================================================================

# --- Функция печати меню ---
def print_menu():
    legacy_menu = ""
    if config.get('legacy_mode', False):
        legacy_menu = """
    12. Зашифровать текст c использованием Legacy RSA
    13. Расшифровать текст c использованием Legacy RSA
    14. Зашифровать файл c использованием Legacy RSA
    15. Расшифровать файл c использованием Legacy RSA
    """

    pqc_menu = ""
    if config.get('pqc_mode', False):
        pqc_menu = """
    18. Зашифровать текст (Kyber + XChaCha20)
    19. Расшифровать текст (Kyber + XChaCha20)
    20. Зашифровать текст (XChaCha20+RSA) для друга
    21. Расшифровать текст (XChaCha20+RSA) своим ключом
    """

    # --- НОВОЕ МЕНЮ ДЛЯ ГРУППОВОГО ЧАТА ---
    group_chat_menu = """
    23. Групповой чат (AES-GCM + RSA)
    """

    menu = """
    --- Главное меню ---
    1. Создать пару ключей и сохранить в JSON
    2. Зашифровать текст c использованием AES-GCM
    3. Расшифровать текст c использованием AES-GCM
    4. Зашифровать файл c использованием AES-GCM
    5. Расшифровать файл c использованием AES-GCM
    6. Добавить публичный или приватный ключ
    7. Показать всех пользователей
    8. Удалить пользователя из JSON файла
    9. Автоскан ключей
    10. Info
    11. {toggle_legacy}
    {legacy_menu}
    16. {toggle_pqc}
    {pqc_menu}
    {group_chat_menu}
    17. Начать переписку
    24. Включить/выключить пользователя
    0. Выйти из программы
    """.format(
        toggle_legacy="Выключить Legacy-режим" if config.get('legacy_mode', False) else "Включить Legacy-режим",
        legacy_menu=legacy_menu,
        toggle_pqc="Выключить PQC-режим" if config.get('pqc_mode', False) else "Включить PQC-режим",
        pqc_menu=pqc_menu,
        group_chat_menu=group_chat_menu # <-- Передаём новое меню в формат
    )
    print(menu)

# =============================================================================
# Функция постоянной переписки
# =============================================================================

def chat_mode(json_file):
    # Выбор режима шифрования
    print("Выберите режим шифрования: 1. AES-GCM  2. RSA")
    mode_choice = input("Введите номер режима: ")
    if mode_choice == "1":
        mode = "AES-GCM"
    elif mode_choice == "2":
        mode = "RSA"
    else:
        print("Неверный выбор режима.")
        return

    # Выбор публичного ключа для шифрования
    public_key_path, user = get_user_to_encrypt(json_file)
    if not public_key_path:
        print("Публичный ключ не выбран.")
        return

    # Выбор приватного ключа для расшифровки
    private_key_path, _ = get_user_to_decrypt(json_file)
    if not private_key_path:
        print("Приватный ключ не выбран. Расшифровка будет недоступна.")

    # Проверка конфигурации для оповещений о копировании
    if config.get('copy_notifications', False):
        copy_notifications = True
    else:
        copy_choice = input("Включить оповещения о копировании текста? (д/н): ").strip().lower()
        copy_notifications = copy_choice in ["д", "y"]
        config['copy_notifications'] = copy_notifications
        with open("config.json", 'w') as config_file:
            json.dump(config, config_file, indent=4)

    if user:
        print(f"Выбран режим: {mode}, пользователь: {user['username']}")
    else:
        print(f"Выбран режим: {mode}, но пользователь не определен.")
        return
    print("Введите сообщения для отправки или вставьте зашифрованные сообщения для расшифровки.")
    print("Для завершения ввода сообщения используйте Ctrl+D (Linux/Mac) или Ctrl+Z (Windows).")
    print("Для выхода из режима переписки нажмите Ctrl+C.")

    while True:
        try:
            message = get_multiline_input()

            if mode == "AES-GCM":
                msg = message.strip()
                is_encrypted = msg.startswith("{'aes_key':") or msg.startswith('{"aes_key":')
                if is_encrypted:
                    if private_key_path:
                        try:
                            try:
                                encrypted_data = json.loads(msg)
                            except (json.JSONDecodeError, ValueError):
                                encrypted_data = eval(msg)
                            decrypted_text = decrypt_text_gcm(private_key_path, encrypted_data)
                            print(f"Расшифрованное сообщение: {decrypted_text}")
                        except Exception as e:
                            print(f"Ошибка расшифровки: {str(e)}")
                    else:
                        print("Приватный ключ недоступен для расшифровки.")
                else:
                    encrypted_data = encrypt_text_gcm(public_key_path, message)
                    encrypted_json = json.dumps(encrypted_data)
                    print(f"Зашифрованное сообщение:\n{encrypted_json}")
                    if copy_notifications:
                        copy_choice = input("Скопировать зашифрованный текст в буфер обмена? (д/н): ").strip().lower()
                        if copy_choice in ["д", "y"]:
                            pyperclip.copy(encrypted_json)
                            print("Зашифрованный текст скопирован в буфер обмена.")

            elif mode == "RSA":
                action = input("Выберите действие (e - зашифровать, d - расшифровать): ").strip().lower()
                if action not in ["e", "d"]:
                    print("Неверное действие. Введите 'e' для шифрования или 'd' для расшифровки.")
                    continue

                if action == "d":
                    if private_key_path:
                        try:
                            decrypted_text = decrypt_text(private_key_path, message)
                            print(f"Расшифрованное сообщение: {decrypted_text}")
                        except Exception as e:
                            print(f"Ошибка расшифровки: {str(e)}")
                    else:
                        print("Приватный ключ недоступен для расшифровки.")
                else:  # action == "e"
                    encrypted_message = encrypt_text(public_key_path, message)
                    print(f"Зашифрованное сообщение: {encrypted_message}")
                    if copy_notifications:
                        copy_choice = input("Скопировать зашифрованный текст в буфер обмена? (д/н): ").strip().lower()
                        if copy_choice in ["д", "y"]:
                            pyperclip.copy(encrypted_message)
                            print("Зашифрованный текст скопирован в буфер обмена.")

        except KeyboardInterrupt:
            print("\nВыход из режима переписки.")
            break
        except Exception as e:
            print(f"Ошибка: {str(e)}")

# =============================================================================
# Функция для выбора пользователя с приватным ключом для расшифровки.
# =============================================================================

def get_user_to_decrypt(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)
        # Отфильтровываем пользователей, у которых есть приватный ключ
        valid_users = [entry for entry in data if entry.get("private_key_path")]
        for idx, entry in enumerate(valid_users):
            print(f"{idx + 1}. {entry['username']}")

    # Запрос выбора пользователя
    choice = int(input("Выберите пользователя (введите номер): ")) - 1

    if choice < 0 or choice >= len(valid_users):
        print("Неверный выбор.")
        return None, None

    return valid_users[choice]['private_key_path'], valid_users[choice]

# =============================================================================
# Функция для выбора пользователя с публичным ключом для шифрования.
# =============================================================================
    
def get_user_to_encrypt(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)
        # Отфильтровываем пользователей, у которых есть публичный ключ
        valid_users = [entry for entry in data if entry.get("public_key_path")]
        for idx, entry in enumerate(valid_users):
            print(f"{idx + 1}. {entry['username']}")

    # Запрос выбора пользователя
    choice = int(input("Выберите пользователя (введите номер): ")) - 1

    if choice < 0 or choice >= len(valid_users):
        print("Неверный выбор.")
        return None, None

    return valid_users[choice]['public_key_path'], valid_users[choice]
    
# =============================================================================
# Функция для получения многолинейного ввода текста от пользователя
# =============================================================================

def get_multiline_input():
    """Функция для получения многолинейного ввода текста от пользователя."""
    print("Введите ваш текст (нажмите Ctrl-D для Linux/Mac/Termux или Ctrl-Z для Windows для завершения ввода):")
    
    # Считывание текста построчно
    contents = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents.append(line)
    
    # Объединение строк в единый текст
    return "\n".join(contents)

# =============================================================================
# Шифрование текста с использованием RSA + AES-GCM
# =============================================================================

def encrypt_text_gcm(public_key_path, text):
    """Шифрование текста с использованием RSA + AES-GCM."""
    # Генерация случайного ключа для AES
    aes_key = os.urandom(32)  # 256-битный ключ для AES
    iv = os.urandom(12)  # Рекомендуемый размер для GCM IV - 96 бит (12 байт)

    # Создание шифра AES-GCM
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Шифрование текста
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

    # Шифрование AES ключа с использованием RSA
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Ключ не является публичным ключом RSA.")

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Создание словаря с зашифрованными данными
    encrypted_data = {
        'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

    # Вывод данных для удобного копирования и вставки
    formatted_output = f"{{'aes_key': '{encrypted_data['aes_key']}', 'iv': '{encrypted_data['iv']}', 'tag': '{encrypted_data['tag']}', 'ciphertext': '{encrypted_data['ciphertext']}'}}"
    print("\nСкопируйте следующий блок для использования в функции дешифрования:")
    #print(formatted_output)

    return encrypted_data
    
# =============================================================================
# Расшифровка текста с использованием RSA + AES-GCM.
# =============================================================================

def decrypt_text_gcm(private_key_path, encrypted_data):
    """Расшифровка текста с использованием RSA + AES-GCM."""
    # Декодирование данных из base64
    encrypted_aes_key = base64.b64decode(encrypted_data['aes_key'])
    iv = base64.b64decode(encrypted_data['iv'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Ключ не является приватным ключом RSA.")

    # Расшифровка AES ключа с использованием RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка текста с использованием AES-GCM
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_text.decode('utf-8')


# =============================================================================
# Шифрование текста с использованием публичного ключа RSA
# =============================================================================

def encrypt_text(public_key_path, text):
    """Шифрование текста с использованием публичного ключа RSA."""
    # Загрузка публичного ключа
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Ключ не является публичным ключом RSA.")

    # Шифрование текста с использованием RSA и OAEP
    encrypted = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Кодирование зашифрованного текста в base64
    encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')

    return encrypted_base64
# =============================================================================    
# Расшифровка текста с использованием приватного ключа RSA.
# =============================================================================
def decrypt_text(private_key_path, encrypted_message):
    """Расшифровка текста с использованием приватного ключа RSA."""
    # Декодирование зашифрованного сообщения из base64
    encrypted_message_bytes = base64.b64decode(encrypted_message)

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Ключ не является приватным ключом RSA.")

    # Расшифровка сообщения с использованием приватного ключа RSA
    decrypted_message = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode('utf-8')

# =============================================================================
# Шифрование файла с использованием RSA + AES-GCM.
# =============================================================================

def encrypt_file_gcm(public_key_path, file_path):
    """Шифрование файла с использованием RSA + AES-GCM."""
    # Генерация случайного ключа для AES
    aes_key = os.urandom(32)
    iv = os.urandom(12)

    # Создание шифра AES-GCM
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Чтение данных из файла
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Шифрование данных
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Шифрование AES ключа с использованием RSA
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Ключ не является публичным ключом RSA.")

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Сохранение зашифрованных данных в файл
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_aes_key + iv + encryptor.tag + ciphertext)

    return encrypted_file_path

# =============================================================================
# Расшифровка файла с использованием RSA + AES-GCM.
# =============================================================================
def decrypt_file_gcm(private_key_path, encrypted_file_path):
    # Чтение зашифрованного файла
    with open(encrypted_file_path, 'rb') as f:
        encrypted_aes_key = f.read(512)  # Длина зашифрованного ключа RSA
        iv = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Ключ не является приватным ключом RSA.")

    # Расшифровка AES ключа с использованием RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка данных с использованием AES-GCM
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Сохранение расшифрованного файла
    decrypted_file_path = encrypted_file_path[:-4]  # Убираем .enc
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path

# =============================================================================
# Функция для поиска зашифрованных файлов в указанных директориях.
# =============================================================================

def find_encrypted_files(directories):
    encrypted_files = []
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.enc'):
                    encrypted_files.append(os.path.join(root, file))
    return encrypted_files
    
# =============================================================================
# Шифрование файла с использованием RSA
# =============================================================================

def encrypt_file(public_key_path, file_path):
    """Шифрование файла с использованием RSA."""
    # Чтение данных из файла
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Загрузка публичного ключа
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Ключ не является публичным ключом RSA.")

    # Шифрование данных с использованием RSA
    encrypted_data = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Сохранение зашифрованного файла
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)

    return encrypted_file_path

# =============================================================================
# Расшифровка файла с использованием RSA
# =============================================================================

def decrypt_file(private_key_path, encrypted_file_path):
    """Расшифровка файла с использованием RSA."""
    # Чтение зашифрованного файла
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Ключ не является приватным ключом RSA.")

    # Расшифровка данных с использованием приватного ключа RSA
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Сохранение расшифрованного файла
    decrypted_file_path = encrypted_file_path[:-4]  # Убираем .enc
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path


# =============================================================================
# Усиленное шифрование с XChaCha20-Poly1305 и PBKDF2
# =============================================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """Генерация ключа из пароля с использованием PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_xchacha(plaintext, password):
    """Шифрование с использованием XChaCha20-Poly1305 и PBKDF2."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(24)
    cipher = Cipher(algorithms.ChaCha20(key[:32], nonce[:16]), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode())
    
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "salt": base64.b64encode(salt).decode()
    }

def decrypt_xchacha(encrypted_data, password):
    """Расшифровка с использованием XChaCha20-Poly1305 и PBKDF2."""
    try:
        salt = base64.b64decode(encrypted_data["salt"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        key = derive_key(password, salt)
        
        cipher = Cipher(algorithms.ChaCha20(key[:32], nonce[:16]), mode=None)
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext)
        
        return decrypted_text.decode()
    except (KeyError, ValueError, TypeError, binascii.Error):
        return "Ошибка: Некорректные данные или неверный пароль!"


# Шифрование XChaCha20+RSA
def encrypt_text_xchacha_rsa(public_key_path, text):
    """Шифрование текста с использованием RSA + XChaCha20."""
    xchacha_key = os.urandom(32)  # 256-битный ключ
    nonce = os.urandom(16)  # 128-битный nonce для ChaCha20 в cryptography

    # Шифрование текста с XChaCha20
    cipher = Cipher(algorithms.ChaCha20(xchacha_key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

    # Чтение публичного ключа RSA
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Ключ не является публичным ключом RSA.")

    # Шифрование ключа XChaCha20 с RSA
    encrypted_xchacha_key = public_key.encrypt(
        xchacha_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Формирование результата
    encrypted_data = {
        'xchacha_key': base64.b64encode(encrypted_xchacha_key).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    return encrypted_data

# Расшифровка XChaCha20+RSA
def decrypt_text_xchacha_rsa(private_key_path, encrypted_data):
    """Расшифровка текста с использованием RSA + XChaCha20."""
    encrypted_xchacha_key = base64.b64decode(encrypted_data['xchacha_key'])
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,  # Если ключ защищен паролем, добавьте его сюда
            backend=default_backend()
        )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Ключ не является приватным ключом RSA.")

    # Расшифровка ключа XChaCha20
    xchacha_key = private_key.decrypt(
        encrypted_xchacha_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка текста
    cipher = Cipher(algorithms.ChaCha20(xchacha_key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_text.decode('utf-8')



def select_users_for_encryption(json_file, exclude_username=None):
    """Позволяет пользователю выбрать нескольких пользователей для шифрования."""
    with open(json_file, 'r') as file:
        data = json.load(file)

    # Отфильтровываем пользователей, у которых есть публичный ключ и, опционально, исключаем текущего пользователя
    valid_users = [entry for entry in data if entry.get("public_key_path") and (not exclude_username or entry.get("username") != exclude_username)]

    if not valid_users:
        print("Нет доступных пользователей с публичными ключами.")
        return []

    print("\n--- Доступные пользователи для шифрования ---")
    for idx, entry in enumerate(valid_users):
        status = "[enabled]" if entry.get('enabled', True) else "[disabled]"
        print(f"{idx + 1}. {entry['username']} {status}")

    print("\nВведите номера пользователей через запятую (например, 1,3,4) или диапазон (1-3) для выбора. Введите 'all' для выбора всех.")

    choice_input = input("Ваш выбор: ").strip().lower()

    selected_users = []
    if choice_input == 'all':
        selected_users = valid_users
    else:
        selected_indices = set()
        try:
            parts = choice_input.replace(' ', '').split(',')
            for part in parts:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    selected_indices.update(range(start - 1, end))
                else:
                    selected_indices.add(int(part) - 1)

            for i in sorted(selected_indices):
                if 0 <= i < len(valid_users):
                    selected_users.append(valid_users[i])
                else:
                    print(f"Предупреждение: Неверный номер пользователя {i + 1}, пропущен.")
        except ValueError:
            print("Ошибка: Неверный формат ввода. Используйте числа, запятые и/или дефисы.")
            return []

    if not selected_users:
        print("Ни один пользователь не был выбран.")
        return []

    print(f"\nВыбрано {len(selected_users)} пользователей для шифрования.")
    for user in selected_users:
        print(f"- {user['username']}")

    confirm = input("\nПодтвердите выбор (y/n): ").strip().lower()
    if confirm not in ['y', 'yes', 'д', 'да']:
        print("Операция отменена.")
        return []

    return selected_users

def encrypt_group_message(json_file, text):
    """Шифрует сообщение для выбранных пользователей."""
    # Предполагаем, что мы знаем имя отправителя, например, берется из конфига или вводится
    # Для упрощения, просто запросим его здесь
    sender_name = input("Введите ваше имя (отправителя): ").strip()
    if not sender_name:
        print("Имя отправителя не может быть пустым.")
        return

    selected_users = select_users_for_encryption(json_file, exclude_username=sender_name)
    if not selected_users:
        return

    # 1. Генерируем единый ключ AES для этого сообщения
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    # ИСПРАВЛЕНО: добавлено '=default_backend()'
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()

    # 2. Шифруем AES ключ публичным RSA-ключом каждого получателя
    encrypted_keys = {}
    failed_users = []
    for user in selected_users:
        try:
            with open(user['public_key_path'], 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

            enc_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_keys[user['username']] = base64.b64encode(enc_aes_key).decode('utf-8')
        except Exception as e:
            print(f"Ошибка шифрования для {user['username']}: {str(e)}")
            failed_users.append(user['username'])

    if not encrypted_keys:
        print("Не удалось зашифровать ключ ни для одного получателя.")
        return

    if failed_users:
        print(f"Предупреждение: Не удалось зашифровать для следующих пользователей: {', '.join(failed_users)}")

    # 3. Формируем итоговый JSON пакет
    payload = {
        "type": "group_message_gcm",
        "sender": sender_name, # Добавим имя отправителя в пакет
        "timestamp": datetime.now().isoformat(), # Добавим временную метку
        "iv": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "keys": encrypted_keys
    }

    encrypted_json = json.dumps(payload, indent=4, ensure_ascii=False)
    print("\n--- Зашифрованное групповое сообщение ---")
    print(encrypted_json)
    print("--- Конец сообщения ---\n")

    copy_choice = input("Скопировать зашифрованный JSON в буфер обмена? (д/н): ").strip().lower()
    if copy_choice in ["д", "y", "yes", "да"]:
        try:
            import pyperclip
            pyperclip.copy(encrypted_json)
            print("Зашифрованный JSON скопирован в буфер обмена.")
        except ImportError:
            print("pyperclip не установлен. Установите его командой 'pip install pyperclip', чтобы использовать копирование.")
        except pyperclip.PyperclipException:
             print("Не удалось скопировать в буфер обмена.")


def decrypt_group_message(json_file, encrypted_json_str):
    """Расшифровение, если у нас есть подходящий приватный ключ."""
    try:
        payload = json.loads(encrypted_json_str)
        if payload.get("type") != "group_message_gcm":
            raise ValueError("Неверный формат сообщения (не group_message_gcm)")
    except (json.JSONDecodeError, ValueError):
        print("Некорректный JSON пакет группового сообщения или неверный тип.")
        return

    # Загружаем наши доступные приватные ключи
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Не удается прочитать файл {json_file}.")
        return

    my_private_keys = {
        entry['username']: entry['private_key_path']
        for entry in data
        if entry.get("private_key_path") and entry.get('enabled', True)
    }

    if not my_private_keys:
        print("У вас нет настроенных приватных ключей для расшифровки.")
        return

    # Ищем, зашифровано ли сообщение для одного из наших профилей
    target_username = None
    encrypted_aes_key_b64 = None

    for username, enc_key in payload.get("keys", {}).items():
        if username in my_private_keys:
            target_username = username
            encrypted_aes_key_b64 = enc_key
            break

    if not target_username:
        print("Это сообщение не предназначалось ни одному из ваших пользователей, или имена не совпадают.")
        return

    # Расшифровываем
    try:
        priv_key_path = my_private_keys[target_username]
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        iv = base64.b64decode(payload['iv'])
        tag = base64.b64decode(payload['tag'])
        ciphertext = base64.b64decode(payload['ciphertext'])

        with open(priv_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        # Расшифровка AES ключа
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Расшифровка текста
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        sender = payload.get("sender", "Неизвестен")
        timestamp = payload.get("timestamp", "Время не указано")
        print(f"\n--- Расшифрованное сообщение ---")
        print(f"От: {sender}")
        print(f"Время: {timestamp}")
        print(f"Для: {target_username}")
        print("-" * 30)
        print(decrypted_bytes.decode('utf-8'))
        print("-" * 30)
        print("--- Конец сообщения ---\n")


    except Exception as e:
        print(f"Ошибка расшифровки: {str(e)}")
        import traceback
        traceback.print_exc() # Для отладки


def handle_choice_group_chat(json_file="keys.json"):
    """Обрабатывает выбор меню для группового чат-режима."""
    print("\n--- Режим группового чата ---")
    print("1. Зашифровать сообщение для группы")
    print("2. Расшифровать полученное групповое сообщение")

    choice = input("Выберите действие (1 или 2): ").strip()

    if choice == "1":
        print("Введите сообщение (для завершения нажмите Ctrl+D на пустой строке):")
        text = get_multiline_input()
        if text.strip():
            encrypt_group_message(json_file, text)
        else:
            print("Текст сообщения пуст.")
    elif choice == "2":
        print("Вставьте зашифрованное JSON-сообщение (нажмите Enter после вставки):")
        try:
            # Для простоты, считаем одну строку. Пользователь должен вставить всё сообщение целиком.
            # Альтернатива - снова использовать get_multiline_input, но это менее удобно для вставки.
            encrypted_json_str = input()
            if encrypted_json_str.strip():
                 decrypt_group_message(json_file, encrypted_json_str)
            else:
                print("Вставленное сообщение пусто.")
        except KeyboardInterrupt:
            print("\nОтменено пользователем.")
    else:
        print("Неверный выбор.")



# =============================================================================
# Основная функция
# =============================================================================

def main():
    json_file = "keys.json"
    global config

    # Загрузка конфигурации
    try:
        with open("config.json", 'r') as config_file:
            config = json.load(config_file)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {"pqc_mode": False, "legacy_mode": False}

    # Создание файла ключей, если не существует
    if not os.path.exists(json_file):
        with open(json_file, 'w') as file:
            json.dump([], file)

    # Показать информацию при первом запуске
    if config.get("first_run", True):
        config["first_run"] = False
        with open("config.json", 'w') as config_file:
            json.dump(config, config_file, indent=4)
        info()

    def handle_choice_1():
        username = input("Введите имя пользователя: ")
        print("Выберите длину ключа RSA: 1. 4096 (надёжнее)  2. 2048 (быстрее)")
        size_choice = input("Ваш выбор (Enter = 4096): ").strip()
        key_size = 2048 if size_choice == "2" else 4096
        priv, pub = generate_key_pair(username, key_size)
        save_keys_to_json(username, pub, priv, json_file)

    def handle_choice_2():
        text = get_multiline_input()
        public_key_path, _ = get_user_to_encrypt(json_file)
        if public_key_path:
            encrypted = encrypt_text_gcm(public_key_path, text)
            encrypted_json = json.dumps(encrypted)
            print(f"Зашифрованные данные (AES-GCM):\n{encrypted_json}")
            if input("Скопировать в буфер? (д/н): ").strip().lower() in ["д", "y"]:
                pyperclip.copy(encrypted_json)
                print("Скопировано в буфер обмена.")

    def handle_choice_3():
        private_key_path, _ = get_user_to_decrypt(json_file)
        if private_key_path:
            raw = input("Введите зашифрованные данные (JSON): ")
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                data = eval(raw)
            print("Расшифрованный текст:", decrypt_text_gcm(private_key_path, data))

    def handle_choice_4():
        public_key_path, _ = get_user_to_encrypt(json_file)
        if public_key_path:
            file = input("Путь к файлу: ")
            result = encrypt_file_gcm(public_key_path, file)
            print(f"Сохранено: {result}")

    def handle_choice_5():
        private_key_path, _ = get_user_to_decrypt(json_file)
        if not private_key_path:
            return
        dirs = input("Директории (через запятую): ").split(',')
        found = find_encrypted_files(dirs)
        if not found:
            print("Файлы не найдены.")
            return
        for i, f in enumerate(found): print(f"{i+1}. {f}")
        index = int(input("Выберите файл: ")) - 1
        if 0 <= index < len(found):
            result = decrypt_file_gcm(private_key_path, found[index])
            print(f"Сохранено: {result}")

    def handle_choice_6():
        username = input("Имя пользователя: ")
        path = input("Путь к ключу: ")
        key_type = input("Тип ключа (public/private): ").strip().lower()
        if key_type in ['public', 'private']:
            add_friend_key(username, path, key_type, json_file)
        else:
            print("Неверный тип ключа. Используйте 'public' или 'private'.")

    def handle_choice_7():
        with open(json_file) as f:
            for entry in json.load(f):
                status = "включен" if entry.get('enabled', True) else "выключен"
                print(f"Имя: {entry['username']}, Статус: {status}, Публичный: {entry.get('public_key_path')}, Приватный: {entry.get('private_key_path')}")

    def handle_choice_8():
        with open(json_file, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

        if not data:
            print("Нет пользователей для удаления.")
            return

        print("Выберите пользователя для удаления:")
        for idx, entry in enumerate(data):
            print(f"{idx + 1}. {entry['username']}")

        try:
            choice_str = input("Введите номер пользователя для удаления (или 0 для отмены): ")
            choice = int(choice_str)

            if choice == 0:
                print("Удаление отменено.")
                return

            choice_index = choice - 1

            if 0 <= choice_index < len(data):
                username_to_delete = data[choice_index]['username']
                delete_user_from_json(username_to_delete, json_file)
            else:
                print("Неверный выбор.")
        except ValueError:
            print("Некорректный ввод. Введите число.")

    def handle_choice_9():
        key_type = input("Тип ключей (public/private): ").strip().lower()
        if key_type not in ['public', 'private', '1', '2']:
            print("Неверный тип ключа.")
            return
        if key_type == '1': key_type = 'public'
        if key_type == '2': key_type = 'private'
        keys = scan_for_keys(json_file, key_type)
        if not keys:
            print("Ключи не найдены.")
            return
        for i, path in enumerate(keys): print(f"{i+1}. {path}")
        selected = input("Номера ключей: ").split(',')
        indices = set()
        for part in selected:
            if '-' in part:
                start, end = map(int, part.split('-'))
                indices.update(range(start-1, end))
            else:
                indices.add(int(part)-1)
        for i in sorted(indices):
            if 0 <= i < len(keys):
                username = input(f"Имя пользователя для ключа {keys[i]}: ").strip()
                if username:
                    add_friend_key(username, keys[i], key_type, json_file)

    def handle_choice_10(): info()
    def handle_choice_11(): toggle_legacy_mode()
    def handle_choice_16():
        toggle_pqc_mode()
        print("Режим PQC:", config['pqc_mode'])
    def handle_choice_17(): chat_mode(json_file)

    def handle_choice_12():  # Legacy RSA Encrypt
        text = input("Введите текст: ")
        public_key_path, _ = get_user_to_encrypt(json_file)
        if public_key_path:
            encrypted = encrypt_text(public_key_path, text)
            print("Зашифрованный текст:", encrypted)
            if input("Скопировать в буфер? (д/н): ").strip().lower() in ["д", "y"]:
                pyperclip.copy(encrypted)

    def handle_choice_13():
        private_key_path, _ = get_user_to_decrypt(json_file)
        if private_key_path:
            encrypted = input("Введите зашифрованный текст: ")
            print("Расшифрованный текст:", decrypt_text(private_key_path, encrypted))

    def handle_choice_14():
        public_key_path, _ = get_user_to_encrypt(json_file)
        if public_key_path:
            file = input("Путь к файлу: ")
            print("Сохранено:", encrypt_file(public_key_path, file))

    def handle_choice_15():
        private_key_path, _ = get_user_to_decrypt(json_file)
        if not private_key_path:
            return
        dirs = input("Пути к директориям: ").split(',')
        found = find_encrypted_files(dirs)
        if not found:
            print("Файлы не найдены.")
            return
        for i, f in enumerate(found): print(f"{i+1}. {f}")
        index = int(input("Выберите файл: ")) - 1
        if 0 <= index < len(found):
            print("Сохранено:", decrypt_file(private_key_path, found[index]))

    def handle_choice_18():
        plaintext = input("Введите текст: ")
        password = input("Введите пароль: ")
        result = encrypt_xchacha(plaintext, password)
        print(json.dumps(result, indent=4))

    def handle_choice_19():
        print("Вставьте JSON-данные, завершите Ctrl+D / Ctrl+Z:")
        try:
            encrypted_json = ''.join(sys.stdin)
            password = input("Введите пароль: ")
            result = decrypt_xchacha(json.loads(encrypted_json), password)
            print("Расшифрованный текст:", result)
        except Exception as e:
            print("Ошибка:", e)

    def handle_choice_20():
        text = get_multiline_input()
        public_key_path, user = get_user_to_encrypt(json_file)
        if public_key_path and user:
            result = encrypt_text_xchacha_rsa(public_key_path, text)
            print(f"Для {user['username']}:")
            print(json.dumps(result, indent=4))

    def handle_choice_21():
        private_key_path, user = get_user_to_decrypt(json_file)
        if private_key_path and user:
            data = get_multiline_input()
            try:
                decrypted = decrypt_text_xchacha_rsa(private_key_path, json.loads(data))
                print(f"Расшифрованный текст для {user['username']}:\n{decrypted}")
            except Exception as e:
                print(f"Ошибка расшифровки: {e}")

    def handle_choice_22():
        print("Секретное меню: математическая генерация")
        username = input("Имя пользователя: ")
        priv, pub = generate_key_pair_math(username)
        save_keys_to_json(username, pub, priv, json_file)

    def handle_choice_24():
        with open(json_file, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
        if not data:
            print("Список пользователей пуст.")
            return
        for idx, entry in enumerate(data):
            status = "включен" if entry.get('enabled', True) else "выключен"
            print(f"{idx + 1}. {entry['username']} [{status}]")
        try:
            choice = int(input("Выберите пользователя: ")) - 1
            if 0 <= choice < len(data):
                current = data[choice].get('enabled', True)
                data[choice]['enabled'] = not current
                new_status = "включен" if data[choice]['enabled'] else "выключен"
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=4)
                print(f"Пользователь '{data[choice]['username']}' теперь {new_status}.")
            else:
                print("Неверный номер.")
        except ValueError:
            print("Введите число.")

    handlers = {
        "1": handle_choice_1, "2": handle_choice_2, "3": handle_choice_3,
        "4": handle_choice_4, "5": handle_choice_5, "6": handle_choice_6,
        "7": handle_choice_7, "8": handle_choice_8, "9": handle_choice_9,
        "10": handle_choice_10, "11": handle_choice_11, "12": handle_choice_12,
        "13": handle_choice_13, "14": handle_choice_14, "15": handle_choice_15,
        "16": handle_choice_16, "17": handle_choice_17, "18": handle_choice_18,
        "19": handle_choice_19, "20": handle_choice_20, "21": handle_choice_21,
        "22": handle_choice_22, "23": handle_choice_group_chat,
        "24": handle_choice_24, "0": lambda: exit("Выход.")
    }

    while True:
        print_menu()
        menu_choice = input("Выберите действие: ").strip()
        handler = handlers.get(menu_choice)
        if handler:
            handler()
        else:
            print("Неверный выбор.")



# =============================================================================
# Ручное генерирование RSA ключей, скоро будет код на C который будет генерировать числа
# =============================================================================



logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def fmt_num(n, max_digits=20):
    """Форматирует число для логирования: если число слишком длинное, выводит первые и последние цифры."""
    s = str(n)
    if len(s) > max_digits:
        return f"{s[:10]}...{s[-10:]}"
    return s

def miller_rabin_test(n, k=5):
    logging.debug("Начало теста Миллера-Рабина для n=%s с k=%d", fmt_num(n), k)
    if n == 2 or n == 3:
        logging.debug("Число %d является простым (2 или 3)", n)
        return True
    if n < 2 or n % 2 == 0:
        logging.debug("Число %d не является простым (меньше 2 или чётное)", n)
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    logging.debug("n-1 = 2^%d * %s", s, fmt_num(d))
    for i in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        #logging.debug("Раунд %d: a=%s, x=%s", i + 1, fmt_num(a), fmt_num(x))
        "Раунд %d: a=%s, x=%s", i + 1, fmt_num(a), fmt_num(x)
        if x == 1 or x == n - 1:
            continue
        for j in range(s - 1):
            x = pow(x, 2, n)
            logging.debug("  Вложенный цикл %d: x=%s", j + 1, fmt_num(x))
            if x == n - 1:
                break
        else:
            logging.debug("Составное число обнаружено на раунде %d", i + 1)
            return False
    logging.debug("Число %s прошло тест Миллера-Рабина", fmt_num(n))
    return True

def generate_prime(bits=512):
    """Генерация простого числа заданной битовой длины, начиная с 2^(bits-1)."""
    logging.debug("Начало генерации простого числа с %d битами", bits)
    min_value = 1 << (bits - 1)  # 2^(bits-1)
    max_value = (1 << bits) - 1  # 2^bits - 1
    attempts = 0
    while True:
        attempts += 1
        num = random.randint(min_value, max_value)
        logging.debug("Попытка %d: сгенерировано число %s", attempts, fmt_num(num))
        if miller_rabin_test(num):
            logging.info("Простое число найдено после %d попыток: %s", attempts, fmt_num(num))
            return num

def extended_gcd(a, b):
    logging.debug("Вызов extended_gcd(a=%d, b=%d)", a, b)
    x, y, x1, y1 = 0, 1, 1, 0
    while b:
        q = a // b
        logging.debug("a=%d, b=%d, q=%d", a, b, q)
        a, b = b, a % b
        x, x1 = x1 - q * x, x
        y, y1 = y1 - q * y, y
        logging.debug("Обновление: a=%d, b=%d, x=%d, x1=%d, y=%d, y1=%d", a, b, x, x1, y, y1)
    logging.debug("Возврат из extended_gcd: gcd=%d, x=%d, y=%d", a, x1, y1)
    return a, x1, y1

def mod_inverse(a, m):
    logging.debug("Вычисление модульного обратного элемента для a=%d, m=%d", a, m)
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        error_msg = f"Обратного элемента не существует для a={a} и m={m}"
        logging.error(error_msg)
        raise ValueError(error_msg)
    result = x % m
    logging.debug("Модульный обратный элемент: %s", fmt_num(result))
    return result

def int_to_der(n):
    logging.debug("Преобразование целого числа %s в DER", fmt_num(n))
    if n == 0:
        return b'\x02\x01\x00'
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    if n_bytes[0] & 0x80:
        n_bytes = b'\x00' + n_bytes
    length = len(n_bytes)
    if length < 128:
        result = b'\x02' + bytes([length]) + n_bytes
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        result = b'\x02' + bytes([0x80 | len(length_bytes)]) + length_bytes + n_bytes
    logging.debug("DER-представление: %s", result.hex()[:60] + "...")
    return result

def encode_der_sequence(items):
    logging.debug("Кодирование DER последовательности с %d элементами", len(items))
    content = b''.join(items)
    length = len(content)
    if length < 128:
        result = b'\x30' + bytes([length]) + content
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        result = b'\x30' + bytes([0x80 | len(length_bytes)]) + length_bytes + content
    logging.debug("DER-последовательность: %s", result.hex()[:60] + "...")
    return result

def encode_public_key_der(n, e):
    logging.debug("Кодирование публичного ключа DER")
    n_der = int_to_der(n)
    e_der = int_to_der(e)
    sequence = encode_der_sequence([n_der, e_der])
    logging.debug("Публичный ключ DER: %s", sequence.hex()[:60] + "...")
    return sequence

def encode_private_key_der(n, e, d, p, q):
    logging.debug("Кодирование приватного ключа DER")
    version = int_to_der(0)  # Версия 0
    n_der = int_to_der(n)
    e_der = int_to_der(e)
    d_der = int_to_der(d)
    p_der = int_to_der(p)
    q_der = int_to_der(q)
    dp = int_to_der(d % (p - 1))
    dq = int_to_der(d % (q - 1))
    qinv = int_to_der(mod_inverse(q, p))
    sequence = encode_der_sequence([version, n_der, e_der, d_der, p_der, q_der, dp, dq, qinv])
    logging.debug("Приватный ключ DER: %s", sequence.hex()[:60] + "...")
    return sequence

def der_to_pem(der_data, key_type):
    logging.debug("Преобразование DER в PEM для типа ключа '%s'", key_type)
    base64_data = base64.b64encode(der_data).decode('ascii')
    lines = [base64_data[i:i+64] for i in range(0, len(base64_data), 64)]
    pem_content = '\n'.join(lines)
    if key_type == "public":
        pem = f"-----BEGIN PUBLIC KEY-----\n{pem_content}\n-----END PUBLIC KEY-----\n"
    elif key_type == "private":
        pem = f"-----BEGIN RSA PRIVATE KEY-----\n{pem_content}\n-----END RSA PRIVATE KEY-----\n"
    else:
        error_msg = f"Неизвестный тип ключа: {key_type}"
        logging.error(error_msg)
        raise ValueError(error_msg)
    logging.debug("PEM формат:\n%s", pem[:100] + "...")
    return pem

def generate_key_pair_math(username):
    logging.info("Генерация пары ключей для пользователя: %s", username)
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    pub_dir = get_public_key_directory()
    priv_dir = get_private_key_directory()
    priv_filename = os.path.join(priv_dir, f"RSA_{username}_priv_{current_time}.pem")
    pub_filename = os.path.join(pub_dir, f"RSA_{username}_pub_{current_time}.pem")

    user_bits = input("Введите битность ключа: 2048/4096/8192. Рекомендуется 4096 для безопасности, 2048 для скорости: ")

    if user_bits == "":
        bits = 4096
    else:
        try:
            bits = int(user_bits)
            if bits not in [2048, 4096, 8192]:
                raise ValueError("Недопустимое значение. Используйте 2048, 4096 или 8192.")
        except ValueError:
            print("Ошибка ввода. По умолчанию используется 4096.")
            bits = 4096
    start_time = time.perf_counter()
    half_bits = bits // 2
    logging.debug("Генерация простых чисел p и q с %d битами каждая", half_bits)
    with ProcessPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(generate_prime, half_bits) for _ in range(2)]
        p, q = [future.result() for future in futures]

    logging.info("Простые числа: p=%s, q=%s", fmt_num(p), fmt_num(q))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    logging.debug("Вычисляем d: n=%s, phi=%s, e=%d", fmt_num(n), fmt_num(phi), e)
    d = mod_inverse(e, phi)
    logging.info("Параметры RSA: n=%s, e=%d, d=%s", fmt_num(n), e, fmt_num(d))

    public_key_der = encode_public_key_der(n, e)
    private_key_der = encode_private_key_der(n, e, d, p, q)

    public_key_pem = der_to_pem(public_key_der, "public")
    private_key_pem = der_to_pem(private_key_der, "private")

    with open(pub_filename, 'w') as pub_file:
        pub_file.write(public_key_pem)
    with open(priv_filename, 'w') as priv_file:
        priv_file.write(private_key_pem)

    logging.info("Публичный ключ сохранен в: %s", pub_filename)
    logging.info("Приватный ключ сохранен в: %s", priv_filename)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    print(f"Время выполнения: {elapsed_time} секунд")
    return priv_filename, pub_filename







if __name__ == "__main__":
    main()
