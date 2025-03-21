from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
import os, base64, json, sys
from datetime import datetime
import pyperclip

CONFIG_FILE = "config.json"
# =============================================================================
# Генерации пары ключей RSA � и�пользованием имени пользовател� и текущей даты
# =============================================================================

def get_private_key_directory() -> None:
    """Определ�ет директорию дл� �охранени� приватного ключа в зави�имо�ти от платформы."""
    if os.name == 'nt':  # Windows
        return os.path.expanduser("~")
        
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        # Папка Termux на Android
        return '/data/data/com.termux/files/home'
        
    else:  # Другие платформы
        return os.path.expanduser("~")
        
# =============================================================================
# Определ�ет директорию дл� �охранени� публичного ключа в зави�имо�ти от платформы
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
    1. Сначала надо �генерировать ключи, найти их в папке (будет напи�ано) и отправить другу
    2. По�ле получени� ключа можно во�пользовать�� авто�каном, е�ли он не работает напи�ать путь к ключу вручную
    3. Дл� шифровани� тек�та лучше и�пользовать GCM метод, тк он имеет поддержку мульти �трок и шифрует до 64гб тек�та
    4. Чтобы обнулить программу удалите файл keys.json и по желанию ключи
    5. GitHub �оздател�: https://github.com/VLOD-ZDOV
    6. Вер�и� - 5.4
    """
    print(info)
    
# =============================================================================
# Загружаем или �оздаём файл конфига legacy режима
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
# Генераци� пары ключей RSA � и�пользованием имени пользовател� и текущей даты.
# =============================================================================

def generate_key_pair(username):
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")

    # Пути дл� �охранени� ключей
    pub_dir = get_public_key_directory()  # Путь дл� публичного ключа
    priv_dir = get_private_key_directory()  # Путь дл� приватного ключа

    # Генераци� имени файлов дл� ключей на о�нове имени пользовател� и текущей даты
    priv_filename = os.path.join(priv_dir, f"RSA_{username}_priv_{current_time}.pem")
    pub_filename = os.path.join(pub_dir, f"RSA_{username}_pub_{current_time}.pem")

    # Генераци� приватного ключа
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

    print(f"Приватный ключ �охранен в: {priv_filename}")
    print(f"Публичный ключ �охранен в: {pub_filename}")

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

    # Проверка �уще�твовани� JSON-файла
    if os.path.exists(json_file):
        with open(json_file, 'r+') as file:
            try:
                data = json.load(file)

                # Е�ли данные в JSON не �вл�ют�� �пи�ком, преобразуем их в �пи�ок
                if isinstance(data, dict):
                    data = [data]
                elif not isinstance(data, list):
                    raise ValueError("�еверный формат JSON файла: ожидает�� �пи�ок.")

            except json.JSONDecodeError:
                # Е�ли файл пу�т или поврежден, �оздаем новый �пи�ок
                data = []

            data.append(key_data)
            file.seek(0)
            json.dump(data, file, indent=4)
    else:
        # Е�ли JSON-файл не �уще�твует, �оздаем новый файл �о �пи�ком ключей
        with open(json_file, 'w') as file:
            json.dump([key_data], file, indent=4)
            
# =============================================================================
# Директории дл� пои�ка ключей
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
# Сканирует �тандартные и дополнительные папки на наличие файлов � публичными ключами, и�ключа� уже �уще�твующие в keys.json.
# =============================================================================

def scan_for_public_keys(json_file):
    
    # Загружаем �уще�твующие ключи из JSON файла
    with open(json_file, 'r') as file:
        data = json.load(file)
        existing_keys = {entry.get('public_key_path') for entry in data if entry.get('public_key_path')}

    found_keys = set()

    # Пои�к ключей во в�ех директори�х из SEARCH_DIRECTORIES
    for dir_path in SEARCH_DIRECTORIES:
        if os.path.exists(dir_path):
            for root, _, files in os.walk(dir_path):
                for filename in files:
                    if filename.endswith('.pem') and 'pub' in filename:
                        key_path = os.path.join(root, filename)
                        key_path = os.path.normpath(key_path)  # �ормализуем путь
                        if key_path not in existing_keys:  # Провер�ем, чтобы ключ не был уже добавлен
                            found_keys.add(key_path)

    return list(found_keys)  # Преобразуем set обратно в list

# =============================================================================
# Сканирование директорий дл� пои�ка ключей
# =============================================================================

def scan_for_keys(json_file, key_type='public'):
    with open(json_file, 'r') as file:
        data = json.load(file)
        existing_keys = {entry.get(f'{key_type}_key_path') for entry in data if entry.get(f'{key_type}_key_path')}
    
    use_standard_naming = input("Ключи имеют �тандартный формат именовани�? (y/n): ").strip().lower() in ['y', '1', 'д','да','yes','ye']
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
    found_keys = scan_for_public_keys()
    if not found_keys:
        print("Публичные ключи не найдены в �тандартных и пользователь�ких папках.")
        return

    for key_path in found_keys:
        # Извлекаем им� пользовател� из имени файла ключа
        username = key_path.split('_')[-3]  # Предполагает��, что им� в формате RSA_<username>_pub_*.pem
        print(f"�айден ключ пользовател� '{username}': {key_path}")
        add = input(f"Добавить ключ пользовател� '{username}'? (y/n): ")
        if add.lower() == 'y':
            add_friend_public_key(username, key_path, json_file)

# =============================================================================
# Добавл�ет публичный ключ друга в JSON файл.
# =============================================================================
            
def add_friend_public_key(username, friend_pub_key_path, json_file="keys.json"):
    friend_key_data = {
        "username": username,
        "public_key_path": friend_pub_key_path,
        "private_key_path": None
    }

# =============================================================================
# Функци� дл� добавлени� публичного или приватного ключа пользовател�. 
# =============================================================================
    
def add_friend_key(username, key_path, key_type, json_file):
    if key_type not in ['public', 'private']:
        print("�еверный тип ключа. Укажите 'public' или 'private'.")
        return

    # Чтение �уще�твующих данных из JSON
    with open(json_file, 'r') as file:
        data = json.load(file)

    # Пои�к пользовател�
    user_entry = next((entry for entry in data if entry['username'] == username), None)

    if not user_entry:
        # Создаем новую запи�ь, е�ли пользовател� нет
        user_entry = {'username': username}
        data.append(user_entry)

    # Добавление пути к ключу в зави�имо�ти от типа
    if key_type == 'public':
        user_entry['public_key_path'] = key_path
        print(f"Публичный ключ дл� '{username}' добавлен.")
    elif key_type == 'private':
        user_entry['private_key_path'] = key_path
        print(f"Приватный ключ дл� '{username}' добавлен.")

    # Сохранение обновленных данных в JSON
    with open(json_file, 'w') as file:
        json.dump(data, file, indent=4)

# =============================================================================
# Удалить пользовател� из базы данных
# =============================================================================

def delete_user_from_json(username, json_file="keys.json"):
    if os.path.exists(json_file):
        with open(json_file, 'r+') as file:
            data = json.load(file)
            data = [entry for entry in data if entry["username"] != username]
            file.seek(0)
            json.dump(data, file, indent=4)
            file.truncate()

        print(f"Пользователь '{username}' у�пешно удален из JSON файла.")
    else:
        print(f"JSON файл '{json_file}' не �уще�твует.")



def toggle_pqc_mode():
    config['pqc_mode'] = not config.get('pqc_mode', False)
    with open("config.json", 'w') as config_file:
        json.dump(config, config_file, indent=4)
    print(f"PQC-режим {'включен' if config['pqc_mode'] else 'выключен'}.")

# =============================================================================
# О�новное меню программы
# =============================================================================

def print_menu():
    print("""
    --- Главное меню ---
    1. Создать пару ключей и �охранить в JSON
    2. Зашифровать тек�т c и�пользованием AES-GCM
    3. Ра�шифровать тек�т c и�пользованием AES-GCM
    4. Зашифровать файл c и�пользованием AES-GCM
    5. Ра�шифровать файл c и�пользованием AES-GCM
    6. Добавить публичный или приватный ключ
    7. Показать в�ех пользователей
    8. Удалить пользовател� из JSON файла
    9. �вто�кан ключей
    10. Info
    11. {toggle_legacy}
    {legacy_menu}
    16. {toggle_pqc}
    {pqc_menu}
    0. Выйти из программы
    """.format(
        toggle_legacy="Выключить Legacy-режим" if config.get('legacy_mode', False) else "Включить Legacy-режим",
        legacy_menu="" if not config.get('legacy_mode', False) else """
    12. Зашифровать тек�т c и�пользованием Legacy RSA
    13. Ра�шифровать тек�т c и�пользованием Legacy RSA
    14. Зашифровать файл c и�пользованием Legacy RSA
    15. Ра�шифровать файл c и�пользованием Legacy RSA
    """,
        toggle_pqc="Выключить PQC-режим" if config.get('pqc_mode', False) else "Включить PQC-режим",
        pqc_menu="" if not config.get('pqc_mode', False) else """
    17. Зашифровать тек�т (Kyber + XChaCha20)
    18. Ра�шифровать тек�т (Kyber + XChaCha20)
    19. Зашифровать тек�т (Kyber + XChaCha20) пароль - ключ друга
    20. Ра�шифровать тек�т (Kyber + XChaCha20) пароль - ваш ключ
    """
    ))


# =============================================================================
# Функци� дл� выбора пользовател� � приватным ключом дл� ра�шифровки.
# =============================================================================

def get_user_to_decrypt(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)
        # Отфильтровываем пользователей, у которых е�ть приватный ключ
        valid_users = [entry for entry in data if entry.get("private_key_path")]
        for idx, entry in enumerate(valid_users):
            print(f"{idx + 1}. {entry['username']}")

    # Запро� выбора пользовател�
    choice = int(input("Выберите пользовател� (введите номер): ")) - 1

    if choice < 0 or choice >= len(valid_users):
        print("�еверный выбор.")
        return None, None

    return valid_users[choice]['private_key_path'], valid_users[choice]

# =============================================================================
# Функци� дл� выбора пользовател� � публичным ключом дл� шифровани�.
# =============================================================================
    
def get_user_to_encrypt(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)
        # Отфильтровываем пользователей, у которых е�ть публичный ключ
        valid_users = [entry for entry in data if entry.get("public_key_path")]
        for idx, entry in enumerate(valid_users):
            print(f"{idx + 1}. {entry['username']}")

    # Запро� выбора пользовател�
    choice = int(input("Выберите пользовател� (введите номер): ")) - 1

    if choice < 0 or choice >= len(valid_users):
        print("�еверный выбор.")
        return None, None

    return valid_users[choice]['public_key_path'], valid_users[choice]
    
# =============================================================================
# Функци� дл� получени� многолинейного ввода тек�та от пользовател�
# =============================================================================

def get_multiline_input():
    """Функци� дл� получени� многолинейного ввода тек�та от пользовател�."""
    print("Введите ваш тек�т (нажмите Ctrl-D дл� Linux/Mac/Termux или Ctrl-Z дл� Windows дл� завершени� ввода):")
    
    # Считывание тек�та по�трочно
    contents = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents.append(line)
    
    # Объединение �трок в единый тек�т
    return "\n".join(contents)

# =============================================================================
# Шифрование тек�та � и�пользованием RSA + AES-GCM
# =============================================================================

def encrypt_text_gcm(public_key_path, text):
    """Шифрование тек�та � и�пользованием RSA + AES-GCM."""
    # Генераци� �лучайного ключа дл� AES
    aes_key = os.urandom(32)  # 256-битный ключ дл� AES
    iv = os.urandom(12)  # Рекомендуемый размер дл� GCM IV - 96 бит (12 байт)

    # Создание шифра AES-GCM
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Шифрование тек�та
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

    # Шифрование AES ключа � и�пользованием RSA
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

    # Создание �ловар� � зашифрованными данными
    encrypted_data = {
        'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

    # Вывод данных дл� удобного копировани� и в�тавки
    formatted_output = f"{{'aes_key': '{encrypted_data['aes_key']}', 'iv': '{encrypted_data['iv']}', 'tag': '{encrypted_data['tag']}', 'ciphertext': '{encrypted_data['ciphertext']}'}}"
    print("\nСкопируйте �ледующий блок дл� и�пользовани� в функции дешифровани�:")
    #print(formatted_output)

    return encrypted_data
    
# =============================================================================
# Ра�шифровка тек�та � и�пользованием RSA + AES-GCM.
# =============================================================================

def decrypt_text_gcm(private_key_path, encrypted_data):
    """Ра�шифровка тек�та � и�пользованием RSA + AES-GCM."""
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

    # Ра�шифровка AES ключа � и�пользованием RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ра�шифровка тек�та � и�пользованием AES-GCM
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_text.decode('utf-8')


# =============================================================================
# Шифрование тек�та � и�пользованием публичного ключа RSA
# =============================================================================

def encrypt_text(public_key_path, text):
    """Шифрование тек�та � и�пользованием публичного ключа RSA."""
    # Загрузка публичного ключа
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    # Шифрование тек�та � и�пользованием RSA и OAEP
    encrypted = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Кодирование зашифрованного тек�та в base64
    encrypted_base64 = base64.b64encode(encrypted).decode('utf-8')

    return encrypted_base64
# =============================================================================    
# Ра�шифровка тек�та � и�пользованием приватного ключа RSA.
# =============================================================================
def decrypt_text(private_key_path, encrypted_message):
    """Ра�шифровка тек�та � и�пользованием приватного ключа RSA."""
    # Декодирование зашифрованного �ообщени� из base64
    encrypted_message_bytes = base64.b64decode(encrypted_message)

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    # Ра�шифровка �ообщени� � и�пользованием приватного ключа RSA
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
# Шифрование файла � и�пользованием RSA + AES-GCM.
# =============================================================================

def encrypt_file_gcm(public_key_path, file_path):
    """Шифрование файла � и�пользованием RSA + AES-GCM."""
    # Генераци� �лучайного ключа дл� AES
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

    # Шифрование AES ключа � и�пользованием RSA
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
# Ра�шифровка файла � и�пользованием RSA + AES-GCM.
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

    # Ра�шифровка AES ключа � и�пользованием RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ра�шифровка данных � и�пользованием AES-GCM
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Сохранение ра�шифрованного файла
    decrypted_file_path = encrypted_file_path[:-4]  # Убираем .enc
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path

# =============================================================================
# Функци� дл� пои�ка зашифрованных файлов в указанных директори�х.
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
# Шифрование файла � и�пользованием RSA
# =============================================================================

def encrypt_file(public_key_path, file_path):
    """Шифрование файла � и�пользованием RSA."""
    # Чтение данных из файла
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Загрузка публичного ключа
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    # Шифрование данных � и�пользованием RSA
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
# Ра�шифровка файла � и�пользованием RSA
# =============================================================================

def decrypt_file(private_key_path, encrypted_file_path):
    """Ра�шифровка файла � и�пользованием RSA."""
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

    # Ра�шифровка данных � и�пользованием приватного ключа RSA
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Сохранение ра�шифрованного файла
    decrypted_file_path = encrypted_file_path[:-4]  # Убираем .enc
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file_path


# =============================================================================
# У�иленное шифрование � XChaCha20-Poly1305 и PBKDF2
# =============================================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """Генераци� ключа из парол� � и�пользованием PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_xchacha(plaintext, password):
    """Шифрование � и�пользованием XChaCha20-Poly1305 и PBKDF2."""
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
    """Ра�шифровка � и�пользованием XChaCha20-Poly1305 и PBKDF2."""
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
        return "Ошибка: �екорректные данные или неверный пароль!"


# Шифрование XChaCha20+RSA
def encrypt_text_xchacha_rsa(public_key_path, text):
    """Шифрование тек�та � и�пользованием RSA + XChaCha20."""
    xchacha_key = os.urandom(32)  # 256-битный ключ
    nonce = os.urandom(16)  # 128-битный nonce дл� ChaCha20 в cryptography

    # Шифрование тек�та � XChaCha20
    cipher = Cipher(algorithms.ChaCha20(xchacha_key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

    # Чтение публичного ключа RSA
    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    # Шифрование ключа XChaCha20 � RSA
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

# Ра�шифровка XChaCha20+RSA
def decrypt_text_xchacha_rsa(private_key_path, encrypted_data):
    """Ра�шифровка тек�та � и�пользованием RSA + XChaCha20."""
    encrypted_xchacha_key = base64.b64decode(encrypted_data['xchacha_key'])
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])

    # Чтение приватного ключа RSA
    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,  # Е�ли ключ защищен паролем, добавьте его �юда
            backend=default_backend()
        )

    # Ра�шифровка ключа XChaCha20
    xchacha_key = private_key.decrypt(
        encrypted_xchacha_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Ра�шифровка тек�та
    cipher = Cipher(algorithms.ChaCha20(xchacha_key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_text.decode('utf-8')

# =============================================================================
# О�новна� функци�
# =============================================================================

def main():
    json_file = "keys.json"
    global config
    try:
        with open("config.json", 'r') as config_file:
            config = json.load(config_file)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {"pqc_mode": False}

    # Провер�ем, �уще�твует ли файл keys.json
    if not os.path.exists(json_file):
        with open(json_file, 'w') as file:
            json.dump([], file)  # Создаем пу�той JSON файл

    while True:
        print_menu()
        choice = input("Выберите дей�твие (0-13): ")

        if choice == "1":
            username = input("Введите им� пользовател�: ")
            priv_filename, pub_filename = generate_key_pair(username)
            save_keys_to_json(username, pub_filename, priv_filename, json_file)


        elif choice == "2":
            # Получение тек�та от пользовател� gcm+aes
            text_to_encrypt = get_multiline_input()

            # Получение пользовател� дл� шифровани�
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                encrypted_data = encrypt_text_gcm(public_key_path, text_to_encrypt)
                print(f"Зашифрованные данные (AES-GCM): {encrypted_data}")

                # Добавл�ем возможно�ть �копировать зашифрованный тек�т
                copy_choice = input("Скопировать зашифрованный тек�т в буфер обмена? (д/н): ").strip().lower()
                if copy_choice in ["д", "y"]:
                    pyperclip.copy(str(encrypted_data))
                    print("Зашифрованный тек�т �копирован в буфер обмена.")


        elif choice == "3":
            # Получение пользовател� дл� ра�шифровки gcm+aes
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                encrypted_data_str = input("Введите зашифрованные данные (как �ловарь): ")
                encrypted_data = eval(encrypted_data_str)
                decrypted_text = decrypt_text_gcm(private_key_path, encrypted_data)
                if decrypted_text:
                    print(f"Ра�шифрованный тек�т: {decrypted_text}")

        elif choice == "4":
            # Получение пользовател� дл� шифровани� файла � и�пользованием AES-GCM
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                file_to_encrypt = input("Введите путь к файлу дл� шифровани�: ")
                encrypted_file_path = encrypt_file_gcm(public_key_path, file_to_encrypt)
                print(f"Файл зашифрован (AES-GCM) и �охранен как: {encrypted_file_path}")

        elif choice == "5":
            # Получение пользовател� дл� ра�шифровки файла � и�пользованием AES-GCM
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                directories = input("Введите пути к директори�м дл� пои�ка зашифрованных файлов, разделенные зап�той: ").split(',')
                encrypted_files = find_encrypted_files(directories)
                
                if not encrypted_files:
                    print("Зашифрованные файлы не найдены.")
                    continue

                print("�айденные зашифрованные файлы (AES-GCM):")
                for idx, file in enumerate(encrypted_files):
                    print(f"{idx + 1}. {file}")

                file_choice = int(input("Выберите файл дл� ра�шифровки (введите номер): ")) - 1

                if file_choice < 0 or file_choice >= len(encrypted_files):
                    print("�еверный выбор.")
                    continue

                decrypted_file_path = decrypt_file_gcm(private_key_path, encrypted_files[file_choice])
                print(f"Файл ра�шифрован (AES-GCM) и �охранен как: {decrypted_file_path}")

        elif choice == "6":
            username = input("Введите им� пользовател�, дл� которого добавл�ет�� публичный ключ друга: ")
            friend_pub_key_path = input("Введите путь к файлу � публичным ключом друга: ")
            add_friend_key(username, friend_pub_key_path, json_file)
        elif choice == "7":
            with open(json_file, 'r') as file:
                data = json.load(file)
                print("Спи�ок пользователей:")
                for entry in data:
                    public_key = entry.get('public_key_path', '�е указан')
                    private_key = entry.get('private_key_path', '�е указан')
                    print(f"Им� пользовател�: {entry['username']}, Путь к публичному ключу: {public_key}, Путь к приватному ключу: {private_key}")

        elif choice == "8":
            username = input("Введите им� пользовател� дл� удалени� из JSON файла: ")
            delete_user_from_json(username, json_file)
        elif choice == "9":
            key_type = input("Какой тип ключей вы хотите добавить? (public/private): ").strip().lower()
            if key_type not in ['public', 'private', '1', '2']:
                print("�еверный тип ключа. Укажите 'public' (1) или 'private' (2).")
                continue
            if key_type == '1':
                key_type = 'public'
            if key_type == '2':
                key_type = 'private'
            found_keys = scan_for_keys(json_file, key_type)
            if not found_keys:
                print(f"�овые {key_type} ключи не найдены.")
            else:
                print(f"�айденные новые {key_type} ключи:")
                for idx, key_path in enumerate(found_keys):
                    print(f"{idx + 1}. {key_path}")
                selected_keys = input("Введите номера ключей дл� добавлени� (через зап�тую или диапазон, например 1,3-5): ")
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
                        username = input(f"Введите им� пользовател� дл� ключа {key_path}: ").strip()
                        if not username:
                            print("Им� пользовател� не может быть пу�тым. Ключ не будет добавлен.")
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
            # Запро� тек�та дл� шифровани�
            print("Введите тек�т дл� шифровани�:")
            text_to_encrypt = input()

            # Получение пользовател� дл� шифровани�
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                encrypted_message = encrypt_text(public_key_path, text_to_encrypt)
                print(f"Зашифрованный тек�т: {encrypted_message}")

                # Добавл�ем возможно�ть �копировать зашифрованный тек�т
                copy_choice = input("Скопировать зашифрованный тек�т в буфер обмена? (д/н): ").strip().lower()
                if copy_choice in ["д", "y"]:
                    pyperclip.copy(encrypted_message)
                    print("Зашифрованный тек�т �копирован в буфер обмена.")


        elif choice == "13":
            # Получение пользовател� дл� ра�шифровки
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                encrypted_message = input("Введите зашифрованный тек�т: ")
                decrypted_message = decrypt_text(private_key_path, encrypted_message)
                if decrypted_message:
                    print(f"Ра�шифрованный тек�т: {decrypted_message}")
        elif choice == "14":
            # Получение пользовател� дл� шифровани� файла rsa
            public_key_path, _ = get_user_to_encrypt(json_file)
            if public_key_path:
                file_to_encrypt = input("Введите путь к файлу дл� шифровани�: ")
                encrypted_file_path = encrypt_file(public_key_path, file_to_encrypt)
                print(f"Файл зашифрован и �охранен как: {encrypted_file_path}")

        elif choice == "15":
            # Получение пользовател� дл� ра�шифровки файла rsa
            private_key_path, _ = get_user_to_decrypt(json_file)
            if private_key_path:
                directories = input("Введите пути к директори�м дл� пои�ка зашифрованных файлов, разделенные зап�той: ").split(',')
                encrypted_files = find_encrypted_files(directories)

                if not encrypted_files:
                    print("Зашифрованные файлы не найдены.")
                    continue

                print("�айденные зашифрованные файлы:")
                for idx, file in enumerate(encrypted_files):
                    print(f"{idx + 1}. {file}")

                file_choice = int(input("Выберите файл дл� ра�шифровки (введите номер): ")) - 1

                if file_choice < 0 or file_choice >= len(encrypted_files):
                    print("�еверный выбор.")
                    continue

                decrypted_file_path = decrypt_file(private_key_path, encrypted_files[file_choice])
                print(f"Файл ра�шифрован и �охранен как: {decrypted_file_path}")

        
        elif choice == "16":
            toggle_pqc_mode()  # Предполагает��, что �та функци� мен�ет config['pqc_mode']
            print(f"Режим PQC: {config['pqc_mode']}")
        
        elif config.get('pqc_mode', False) and choice == "17":
            # Только шифрование
            plaintext = input("Введите тек�т дл� шифровани�: ")
            password = input("Введите пароль: ")
            encrypted_data = encrypt_xchacha(plaintext, password)
            encrypted_json = json.dumps(encrypted_data, indent=4)
            print("Зашифрованные данные:", encrypted_json)
        
        elif config.get('pqc_mode', False) and choice == "18":
            # Ра�шифровка � много�трочным вводом до EOF
            print("Введите зашифрованные данные в формате JSON (включает ciphertext, nonce, salt).")
            print("Дл� завершени� ввода нажмите Ctrl+D (Unix) или Ctrl+Z (Windows) и Enter:")
            lines = []
            try:
                for line in sys.stdin:
                    lines.append(line)
                encrypted_json = ''.join(lines)
                password = input("Введите пароль: ")
                try:
                    encrypted_data = json.loads(encrypted_json)
                    decrypted_text = decrypt_xchacha(encrypted_data, password)
                    print("Ра�шифрованный тек�т:", decrypted_text)
                except json.JSONDecodeError:
                    print("Ошибка: Введенные данные не �вл�ют�� корректным JSON!")
            except KeyboardInterrupt:
                print("\nВвод прерван.")
        
        elif choice == "19":
            text_to_encrypt = get_multiline_input()
            if text_to_encrypt:
                public_key_path, user = get_user_to_encrypt(json_file)
                if public_key_path:
                    encrypted_data = encrypt_text_xchacha_rsa(public_key_path, text_to_encrypt)
                    print(f"Зашифрованные данные (XChaCha20+RSA) дл� {user['username']}:")
                    print(json.dumps(encrypted_data, indent=4))

        elif choice == "20":
            private_key_path, user = get_user_to_decrypt(json_file)
            if private_key_path:
                print("Введите зашифрованные данные (JSON) дл� XChaCha20+RSA:")
                encrypted_json = get_multiline_input()
                try:
                    encrypted_data = json.loads(encrypted_json)
                    decrypted_text = decrypt_text_xchacha_rsa(private_key_path, encrypted_data)
                    print(f"Ра�шифрованный тек�т дл� {user['username']}:")
                    print(decrypted_text)
                except json.JSONDecodeError:
                    print("Ошибка: Введенные данные не �вл�ют�� корректным JSON!")
                except Exception as e:
                    print(f"Ошибка ра�шифровки: {str(e)}")
            
if __name__ == "__main__":
    main()
