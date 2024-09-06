from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
from datetime import datetime
# Определение пути к директории "Загрузки" в зависимости от платформы
def get_download_directory():
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ['USERPROFILE'], 'Downloads')
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        return os.path.join(os.environ['HOME'], 'downloads')
    else:  # Другая платформа
        return os.path.join(os.environ['HOME'], 'Downloads')

# Генерация пары ключей RSA с указанием владельца и назначения
# Функция генерации пары ключей RSA с использованием имени пользователя и текущей даты
def get_private_key_directory():
    """Определяет директорию для сохранения приватного ключа в зависимости от платформы."""
    if os.name == 'nt':  # Windows
        # Папка пользователя на Windows
        return os.path.expanduser("~")
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        # Папка Termux на Android
        return '/data/data/com.termux/files/home'
    else:  # Другие платформы
        # Папка по умолчанию на других системах
        return os.path.expanduser("~")

def get_public_key_directory():
    """Определяет директорию для сохранения публичного ключа в зависимости от платформы."""
    if os.name == 'nt':  # Windows
        # Папка "Загрузки" пользователя на Windows
        return os.path.join(os.environ['USERPROFILE'], 'Downloads')
    elif 'ANDROID_ROOT' in os.environ:  # Termux на Android
        # Папка на Android для сохранения публичных ключей
        return '/sdcard/'
    else:  # Другие платформы
        return os.path.expanduser("~")

def find_public_key(username):
    """Ищет публичный ключ в папке загрузок на платформе Android или Windows."""
    if 'ANDROID_ROOT' in os.environ:  # Termux на Android
        download_dir = '/sdcard/Download'
    else:
        download_dir = get_download_directory()

    for filename in os.listdir(download_dir):
        if filename.startswith(f"RSA_{username}_pub_") and filename.endswith(".pem"):
            return os.path.join(download_dir, filename)
    return None

def generate_key_pair(username):
    """Генерация пары ключей RSA с использованием имени пользователя и текущей даты."""
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Определяем пути для сохранения ключей
    pub_dir = get_public_key_directory()  # Путь для публичного ключа
    priv_dir = get_private_key_directory()  # Путь для приватного ключа

    # Генерация имени файлов для ключей на основе имени пользователя и текущей даты
    priv_filename = os.path.join(priv_dir, f"RSA_{username}_priv_{current_time}.pem")
    pub_filename = os.path.join(pub_dir, f"RSA_{username}_pub_{current_time}.pem")

    # Генерация приватного ключа
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
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
# Сохранение информации о ключах в JSON файл
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
# Поиск публичного ключа в директории "Загрузки"
def find_public_key(username):
    download_dir = get_download_directory()
    for filename in os.listdir(download_dir):
        if filename.startswith(f"RSA_{username}_to_") and filename.endswith("_pub.pem"):
            return os.path.join(download_dir, filename)
    return None

# Добавление ключа друга в JSON
def scan_for_public_keys():
    """Сканирует папку загрузок на наличие файлов с публичными ключами и предлагает добавить их."""
    if 'ANDROID_ROOT' in os.environ:  # Termux на Android
        download_dir = '/sdcard/Download'
    else:  # Windows
        download_dir = os.path.join(os.environ['USERPROFILE'], 'Downloads')

    found_keys = []
    for filename in os.listdir(download_dir):
        if filename.endswith('.pem') and 'pub' in filename:
            found_keys.append(os.path.join(download_dir, filename))

    return found_keys

def prompt_add_found_keys(json_file="keys.json"):
    """Предлагает пользователю добавить найденные публичные ключи в JSON файл."""
    found_keys = scan_for_public_keys()
    if not found_keys:
        print("Публичные ключи не найдены в папке загрузок.")
        return

    for key_path in found_keys:
        # Извлекаем имя пользователя из имени файла ключа
        username = key_path.split('_')[-3]  # Предполагается, что имя в формате RSA_<username>_pub_*.pem
        print(f"Найден ключ пользователя '{username}': {key_path}")
        add = input(f"Добавить ключ пользователя '{username}'? (y/n): ")
        if add.lower() == 'y':
            add_friend_public_key(username, key_path, json_file)

def add_friend_public_key(username, friend_pub_key_path, json_file="keys.json"):
    """Добавляет публичный ключ друга в JSON файл."""
    friend_key_data = {
        "username": username,
        "public_key_path": friend_pub_key_path,
        "private_key_path": None
    }

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

            data.append(friend_key_data)
            file.seek(0)
            json.dump(data, file, indent=4)
    else:
        # Если JSON-файл не существует, создаем новый файл со списком ключей
        with open(json_file, 'w') as file:
            json.dump([friend_key_data], file, indent=4)

    print(f"Публичный ключ пользователя '{username}' успешно добавлен в JSON файл.")

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

# Функция расшифровки с выбором ключа
def decrypt_message_choice(json_file, encrypted_message):
    """Функция для расшифровки сообщения с выбором ключа."""
    with open(json_file, 'r') as file:
        data = json.load(file)
        print("Доступные пользователи для расшифровки:")
        for idx, entry in enumerate(data):
            print(f"{idx + 1}. {entry['username']}")

    choice = int(input("Выберите пользователя (введите номер): ")) - 1
    user_data = data[choice]

    private_key_path = user_data['private_key_path']

    # Декодируем сообщение из base64
    encrypted_message_bytes = base64.b64decode(encrypted_message)

    with open(private_key_path, 'rb') as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )
    decrypted_message = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode('utf-8')
def encrypt_message(public_key_path, message):

    with open(public_key_path, 'rb') as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read(), backend=default_backend())

    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted).decode('utf-8')
def encrypt_file_rsa_aes(public_key_path, file_path):
    # Генерация случайного ключа для AES
    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)

    # Шифрование файла AES
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher_aes = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    encryptor = cipher_aes.encryptor()
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

    # Сохранение зашифрованного файла и ключа
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_aes_key)
        file.write(aes_iv)
        file.write(ciphertext)

    print(f"Файл успешно зашифрован и сохранен как '{encrypted_file_path}'.")
def decrypt_file_rsa_aes(private_key_path, encrypted_file_path):
    # Чтение зашифрованного файла
    with open(encrypted_file_path, 'rb') as file:
        encrypted_aes_key = file.read(256)  # Длина зашифрованного ключа RSA
        aes_iv = file.read(16)
        ciphertext = file.read()

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

    # Расшифровка текста с использованием AES
    cipher_aes = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
    decryptor = cipher_aes.decryptor()
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    # Сохранение расшифрованного файла
    decrypted_file_path = f"{encrypted_file_path[:-4]}_decrypted.txt"
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_text)

    print(f"Файл успешно расшифрован и сохранен как '{decrypted_file_path}'.")
def print_menu():
    print("Меню:\n1. Создать RSA ключи и сохранить в JSON файл\n2. Шифровать текст\n3. Расшифровать текст\n4. Зашифровать файл\n5. Расшифровать файл\n6. Добавить публичный ключ друга\n7. Удалить пользователя из JSON файла\n8. Показать всех пользователей\n9. Выход")

# Основная функция
def main():
        json_file = "keys.json"
        while True:
            print_menu()
            choice = input("Выберите действие (1-9): ")

            if choice == "1":
                username = input("Введите имя пользователя: ")
                priv_filename, pub_filename = generate_key_pair(username)
                save_keys_to_json(username, pub_filename, priv_filename, json_file)

            elif choice == "2":
                print("Доступные пользователи для шифрования:")
                with open(json_file, 'r') as file:
                    data = json.load(file)
                    for entry in data:
                        print(entry["username"])

                username = input("Введите имя пользователя: ")
                public_key_path = next((entry["public_key_path"] for entry in data if entry["username"] == username), None)

                if not public_key_path:
                    print(f"Публичный ключ для пользователя '{username}' не найден в JSON файле.")
                    continue

                text_to_encrypt = input("Введите текст для шифрования: ")
                encrypted_message = encrypt_message(public_key_path, text_to_encrypt)
                print (f"Зашифрованный текст: {encrypted_message}")

            elif choice == "3":
                print("Доступные пользователи для расшифровки:")
                with open(json_file, 'r') as file:
                    data = json.load(file)
                    for entry in data:
                        print(entry["username"])

                encrypted_message = input("Введите зашифрованный текст (hex): ")
                decrypted_message = decrypt_message_choice(json_file, encrypted_message)
                if decrypted_message:
                    print(f"Расшифрованный текст: {decrypted_message}")

            elif choice == "4":
                print("Доступные пользователи для зашифровки файла:")
                with open(json_file, 'r') as file:
                    data = json.load(file)
                    for entry in data:
                        print(entry["username"])

                username = input("Введите имя пользователя: ")
                public_key_path = next((entry["public_key_path"] for entry in data if entry["username"] == username), None)

                if not public_key_path:
                    print(f"Публичный ключ для пользователя '{username}' не найден в JSON файле.")
                    continue

                file_to_encrypt = input("Введите путь к файлу для шифрования: ")
                encrypt_file_rsa_aes(public_key_path, file_to_encrypt)

            elif choice == "5":
                print("Доступные пользователи для расшифровки файла:")
                with open(json_file, 'r') as file:
                    data = json.load(file)
                    for entry in data:
                        print(entry["username"])

                username = input("Введите имя пользователя: ")
                private_key_path = next((entry["private_key_path"] for entry in data if entry["username"] == username), None)

                if not private_key_path:
                    print(f"Приватный ключ для пользователя '{username}' не найден в JSON файле.")
                    continue

                file_to_decrypt = input("Введите путь к файлу для расшифровки: ")
                decrypt_file_rsa_aes(private_key_path, file_to_decrypt)

            elif choice == "6":
                username = input("Введите имя пользователя, для которого добавляется публичный ключ друга: ")
                friend_pub_key_path = input("Введите путь к файлу с публичным ключом друга: ")
                add_friend_public_key(username, friend_pub_key_path, json_file)

            elif choice == "7":
                username = input("Введите имя пользователя для удаления из JSON файла: ")
                delete_user_from_json(username, json_file)

            elif choice == "8":
                with open(json_file, 'r') as file:
                    data = json.load(file)
                    print("Список пользователей:")
                    for entry in data:
                        print(f"Имя пользователя: {entry['username']}, Путь к публичному ключу: {entry['public_key_path']}, Путь к приватному ключу: {entry['private_key_path']}")

            elif choice == "9":
                print("Выход из программы.")
                break

            else:
                print("Неверный выбор. Пожалуйста, выберите от 1 до 9.")

if __name__ == "__main__":
    prompt_add_found_keys()
    main()
