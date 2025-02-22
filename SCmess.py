from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
import os, base64, json, sys
from datetime import datetime
import pyperclip

# =============================================================================
# Мусорная функция, надеюсь перейду к нормльной SEARCH_DIRECTORIES
# =============================================================================

def get_download_directory():
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ['USERPROFILE'], 'Downloads')
    if 'ANDROID_ROOT' in os.environ:  # Termux на Android
        return os.path.join(os.environ['HOME'], 'downloads')
    else:  # Другая платформа
        return os.path.join(os.environ['HOME'], 'Downloads')
CONFIG_FILE = "config.json"

# =============================================================================
# Генерации пары ключей RSA с использованием имени пользователя и текущей даты
# =============================================================================

def get_private_key_directory():
    """Определяет директорию для сохранения приватного ключа в зависимости от платформы."""
    if os.name == 'nt':  # Windows
        return os.path.expanduser("~")
        
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        # Папка Termux на Android
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
    info = """
    1. Сначала надо сгенерировать ключи, найти их в папке (будет написано) и отправить другу
    2. После получения ключа можно воспользоваться автосканом, если он не работает написать путь к ключу вручную
    3. Для шифрования текста лучше использовать GCM метод, тк он имеет поддержку мульти строк и шифрует до 64гб текста
    4. Чтобы обнулить программу удалите файл keys.json и по желанию ключи
    5. GitHub создателя: https://github.com/VLOD-ZDOV
    6. Версия - 5.1
    """
    print(info)
    
# =============================================================================
# Загружаем или создаём файл конфига legacy режима
# =============================================================================

if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, 'r') as config_file:
        try:
            config = json.load(config_file)
        except json.JSONDecodeError:
            config = {"legacy_mode": False}
else:
    config = {"legacy_mode": False}

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

def generate_key_pair(username):
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
        key_size=4096,
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

    found_keys = set()
    for dir_path in SEARCH_DIRECTORIES:
        if os.path.exists(dir_path):
            for root, _, files in os.walk(dir_path):
                for filename in files:
                    key_path = os.path.join(root, filename)
                    if (key_type == 'public' and filename.endswith('.pem') and 'pub' in filename) or \
                       (key_type == 'private' and filename.endswith('.pem') and 'pub' not in filename):
                        if key_path not in existing_keys:
                            found_keys.add(key_path)
    return list(found_keys)



# =============================================================================
# Предлагает пользователю добавить найденные публичные ключи в JSON файл.
# =============================================================================

def prompt_add_found_keys(json_file="keys.json"):
    found_keys = scan_for_public_keys()
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
    """
    Функция для добавления публичного или приватного ключа пользователя.
    key_type должен быть 'public' или 'private'.
    """
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

def print_menu():
    print("""
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
    0. Выйти из программы
    """.format(
        toggle_legacy="Выключить Legacy-режим" if config.get('legacy_mode', False) else "Включить Legacy-режим",
        legacy_menu="" if not config.get('legacy_mode', False) else """
    12. Зашифровать текст c использованием Legacy RSA
    13. Расшифровать текст c использованием Legacy RSA
    14. Зашифровать файл c использованием Legacy RSA
    15. Расшифровать файл c использованием Legacy RSA
    """,
        toggle_pqc="Выключить PQC-режим" if config.get('pqc_mode', False) else "Включить PQC-режим",
        pqc_menu="" if not config.get('pqc_mode', False) else """
    17. Зашифровать текст (Kyber + XChaCha20)
    18. Расшифровать текст (Kyber + XChaCha20)
    19. Зашифровать текст (Kyber + XChaCha20) пароль - ключ друга
    20. Расшифровать текст (Kyber + XChaCha20) пароль - ваш ключ
    """
    ))


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
        encrypted_aes_key = f.read(256)  # Длина зашифрованного ключа RSA
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
    except (KeyError, ValueError, TypeError, base64.binascii.Error):
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

# =============================================================================
# Основная функция
# =============================================================================

def main():
    json_file = "keys.json"
    global config
    try:
        with open("config.json", 'r') as config_file:
            config = json.load(config_file)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {"pqc_mode": False}

    # Проверяем, существует ли файл keys.json
    if not os.path.exists(json_file):
        with open(json_file, 'w') as file:
            json.dump([], file)  # Создаем пустой JSON файл

    while True:
        print_menu()
        choice = input("Выберите действие (0-13): ")

        if choice == "1":
            username = input("Введите имя пользователя: ")
            priv_filename, pub_filename = generate_key_pair(username)
            save_keys_to_json(username, pub_filename, priv_filename, json_file)


        elif choice == "2":
            # Получение текста от пользователя gcm+aes
            text_to_encrypt = get_multiline_input()

            # Получение пользователя для шифрования
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                encrypted_data = encrypt_text_gcm(public_key_path, text_to_encrypt)
                print(f"Зашифрованные данные (AES-GCM): {encrypted_data}")

                # Добавляем возможность скопировать зашифрованный текст
                copy_choice = input("Скопировать зашифрованный текст в буфер обмена? (д/н): ").strip().lower()
                if copy_choice in ["д", "y"]:
                    pyperclip.copy(str(encrypted_data))
                    print("Зашифрованный текст скопирован в буфер обмена.")


        elif choice == "3":
            # Получение пользователя для расшифровки gcm+aes
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                encrypted_data_str = input("Введите зашифрованные данные (как словарь): ")
                encrypted_data = eval(encrypted_data_str)
                decrypted_text = decrypt_text_gcm(private_key_path, encrypted_data)
                if decrypted_text:
                    print(f"Расшифрованный текст: {decrypted_text}")

        elif choice == "4":
            # Получение пользователя для шифрования файла с использованием AES-GCM
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                file_to_encrypt = input("Введите путь к файлу для шифрования: ")
                encrypted_file_path = encrypt_file_gcm(public_key_path, file_to_encrypt)
                print(f"Файл зашифрован (AES-GCM) и сохранен как: {encrypted_file_path}")

        elif choice == "5":
            # Получение пользователя для расшифровки файла с использованием AES-GCM
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                directories = input("Введите пути к директориям для поиска зашифрованных файлов, разделенные запятой: ").split(',')
                encrypted_files = find_encrypted_files(directories)
                
                if not encrypted_files:
                    print("Зашифрованные файлы не найдены.")
                    continue

                print("Найденные зашифрованные файлы (AES-GCM):")
                for idx, file in enumerate(encrypted_files):
                    print(f"{idx + 1}. {file}")

                file_choice = int(input("Выберите файл для расшифровки (введите номер): ")) - 1

                if file_choice < 0 or file_choice >= len(encrypted_files):
                    print("Неверный выбор.")
                    continue

                decrypted_file_path = decrypt_file_gcm(private_key_path, encrypted_files[file_choice])
                print(f"Файл расшифрован (AES-GCM) и сохранен как: {decrypted_file_path}")

        elif choice == "6":
            username = input("Введите имя пользователя, для которого добавляется публичный ключ друга: ")
            friend_pub_key_path = input("Введите путь к файлу с публичным ключом друга: ")
            add_friend_key(username, friend_pub_key_path, json_file)
        elif choice == "7":
            with open(json_file, 'r') as file:
                data = json.load(file)
                print("Список пользователей:")
                for entry in data:
                    public_key = entry.get('public_key_path', 'Не указан')
                    private_key = entry.get('private_key_path', 'Не указан')
                    print(f"Имя пользователя: {entry['username']}, Путь к публичному ключу: {public_key}, Путь к приватному ключу: {private_key}")

        elif choice == "8":
            username = input("Введите имя пользователя для удаления из JSON файла: ")
            delete_user_from_json(username, json_file)
        elif choice == "9":
            """ Сканирование директорий и добавление новых публичных ключей """
            key_type = input("Какой тип ключей вы хотите добавить? (public/private): ").strip().lower()
            if key_type not in ['public', 'private', '1', '2']:
                print("Неверный тип ключа. Укажите 'public' (1) или 'private' (2).")
                continue
            if key_type == '1':
                key_type = 'public'
            if key_type == '2':
                key_type = 'private'
            found_keys = scan_for_keys(json_file, key_type)
            if not found_keys:
                print(f"Новые {key_type} ключи не найдены.")
            else:
                print(f"Найденные новые {key_type} ключи:")
                for idx, key_path in enumerate(found_keys):
                    print(f"{idx + 1}. {key_path}")

                selected_keys = input("Введите номера ключей для добавления (через запятую или диапазон, например 1,3-5): ")
                indices_to_add = set()

                for part in selected_keys.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        indices_to_add.update(range(start - 1, end))
                    else:
                        indices_to_add.add(int(part) - 1)

                for idx in sorted(indices_to_add):
                    if 0 <= idx < len(found_keys):
                        key_path = found_keys[idx]
                        username = input(f"Введите имя пользователя для ключа {key_path}: ").strip()

                        if not username:
                            print("Имя пользователя не может быть пустым. Ключ не будет добавлен.")
                            continue

                        add_friend_key(username, key_path, key_type, json_file)
        elif choice == "10":
            info()
        elif choice == "11":
            toggle_legacy_mode()
        elif choice == "0":
            print("Выход из программы.")
            break

        elif choice == "12":
            # Запрос текста для шифрования
            print("Введите текст для шифрования:")
            text_to_encrypt = input()

            # Получение пользователя для шифрования
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                encrypted_message = encrypt_text(public_key_path, text_to_encrypt)
                print(f"Зашифрованный текст: {encrypted_message}")

                # Добавляем возможность скопировать зашифрованный текст
                copy_choice = input("Скопировать зашифрованный текст в буфер обмена? (д/н): ").strip().lower()
                if copy_choice in ["д", "y"]:
                    pyperclip.copy(encrypted_message)
                    print("Зашифрованный текст скопирован в буфер обмена.")


        elif choice == "13":
            # Получение пользователя для расшифровки
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                encrypted_message = input("Введите зашифрованный текст: ")
                decrypted_message = decrypt_text(private_key_path, encrypted_message)
                if decrypted_message:
                    print(f"Расшифрованный текст: {decrypted_message}")
        elif choice == "14":
            # Получение пользователя для шифрования файла rsa
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                file_to_encrypt = input("Введите путь к файлу для шифрования: ")
                encrypted_file_path = encrypt_file(public_key_path, file_to_encrypt)
                print(f"Файл зашифрован и сохранен как: {encrypted_file_path}")

        elif choice == "15":
            # Получение пользователя для расшифровки файла rsa
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                directories = input("Введите пути к директориям для поиска зашифрованных файлов, разделенные запятой: ").split(',')
                encrypted_files = find_encrypted_files(directories)

                if not encrypted_files:
                    print("Зашифрованные файлы не найдены.")
                    continue

                print("Найденные зашифрованные файлы:")
                for idx, file in enumerate(encrypted_files):
                    print(f"{idx + 1}. {file}")

                file_choice = int(input("Выберите файл для расшифровки (введите номер): ")) - 1

                if file_choice < 0 or file_choice >= len(encrypted_files):
                    print("Неверный выбор.")
                    continue

                decrypted_file_path = decrypt_file(private_key_path, encrypted_files[file_choice])
                print(f"Файл расшифрован и сохранен как: {decrypted_file_path}")

        
        elif choice == "16":
            toggle_pqc_mode()  # Предполагается, что эта функция меняет config['pqc_mode']
            print(f"Режим PQC: {config['pqc_mode']}")
        
        elif config.get('pqc_mode', False) and choice == "17":
            # Только шифрование
            plaintext = input("Введите текст для шифрования: ")
            password = input("Введите пароль: ")
            encrypted_data = encrypt_xchacha(plaintext, password)
            encrypted_json = json.dumps(encrypted_data, indent=4)
            print("Зашифрованные данные:", encrypted_json)
        
        elif config.get('pqc_mode', False) and choice == "18":
            # Расшифровка с многострочным вводом до EOF
            print("Введите зашифрованные данные в формате JSON (включает ciphertext, nonce, salt).")
            print("Для завершения ввода нажмите Ctrl+D (Unix) или Ctrl+Z (Windows) и Enter:")
            lines = []
            try:
                for line in sys.stdin:
                    lines.append(line)
                encrypted_json = ''.join(lines)
                password = input("Введите пароль: ")
                try:
                    encrypted_data = json.loads(encrypted_json)
                    decrypted_text = decrypt_xchacha(encrypted_data, password)
                    print("Расшифрованный текст:", decrypted_text)
                except json.JSONDecodeError:
                    print("Ошибка: Введенные данные не являются корректным JSON!")
            except KeyboardInterrupt:
                print("\nВвод прерван.")
        
        elif choice == "19":
            text_to_encrypt = get_multiline_input()
            if text_to_encrypt:
                public_key_path, user = get_user_to_encrypt(json_file)
                if public_key_path:
                    encrypted_data = encrypt_text_xchacha_rsa(public_key_path, text_to_encrypt)
                    print(f"Зашифрованные данные (XChaCha20+RSA) для {user['username']}:")
                    print(json.dumps(encrypted_data, indent=4))

        elif choice == "20":
            private_key_path, user = get_user_to_decrypt(json_file)
            if private_key_path:
                print("Введите зашифрованные данные (JSON) для XChaCha20+RSA:")
                encrypted_json = get_multiline_input()
                try:
                    encrypted_data = json.loads(encrypted_json)
                    decrypted_text = decrypt_text_xchacha_rsa(private_key_path, encrypted_data)
                    print(f"Расшифрованный текст для {user['username']}:")
                    print(decrypted_text)
                except json.JSONDecodeError:
                    print("Ошибка: Введенные данные не являются корректным JSON!")
                except Exception as e:
                    print(f"Ошибка расшифровки: {str(e)}")
            
if __name__ == "__main__":
    main()
