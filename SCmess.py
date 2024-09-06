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
def generate_key_pair(owner, recipient, pub_dir=None, priv_dir=None):
    current_time = datetime.now().strftime("%Y%m%d%H%M%S")
    if not pub_dir or not priv_dir:
        pub_dir = get_download_directory()
        priv_dir = get_download_directory()

    priv_filename = os.path.join(priv_dir, f"RSA_{owner}_to_{recipient}_priv_{current_time}.pem")
    pub_filename = os.path.join(pub_dir, f"RSA_{owner}_to_{recipient}_pub_{current_time}.pem")

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

    return priv_filename, pub_filename

# Сохранение информации о ключах в JSON файл
def save_keys_to_json(username, pub_filename, priv_filename, json_file="keys.json"):
    key_data = {
        "username": username,
        "public_key_path": pub_filename,
        "private_key_path": priv_filename
    }

    if os.path.exists(json_file):
        with open(json_file, 'r+') as file:
            data = json.load(file)
            data.append(key_data)
            file.seek(0)
            json.dump(data, file, indent=4)
    else:
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
def add_friend_public_key(username, friend_username, json_file="keys.json"):
    friend_pub_key_path = find_public_key(friend_username)
    if friend_pub_key_path:
        friend_key_data = {
            "username": friend_username,
            "public_key_path": friend_pub_key_path,
            "private_key_path": None
        }

        if os.path.exists(json_file):
            with open(json_file, 'r+') as file:
                data = json.load(file)
                data.append(friend_key_data)
                file.seek(0)
                json.dump(data, file, indent=4)
        else:
            with open(json_file, 'w') as file:
                json.dump([friend_key_data], file, indent=4)

        print(f"Публичный ключ друга '{friend_username}' успешно добавлен в JSON файл.")
    else:
        print(f"Публичный ключ для '{friend_username}' не найден в директории загрузок.")
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
def decrypt_message_choice(json_file="keys.json"):
    with open(json_file, 'r') as file:
        data = json.load(file)
        print("Доступные пользователи для расшифровки:")
        for idx, entry in enumerate(data):
            print(f"{idx + 1}. {entry['username']}")

    choice = int(input("Выберите пользователя (введите номер): ")) - 1
    user_data = data[choice]

    if user_data['private_key_path']:
        private_key_path = user_data['private_key_path']
    else:
        print("У пользователя нет приватного ключа.")
        return

    encrypted_message = input("Введите зашифрованный текст: ")
    decrypted_message = decrypt_message_choice(private_key_path, encrypted_message)
    if decrypted_message:
        print(f"Расшифрованный текст: {decrypted_message}")
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

                username = input("Введите имя пользователя: ")
                private_key_path = next((entry["private_key_path"] for entry in data if entry["username"] == username), None)

                if not private_key_path:
                    print(f"Приватный ключ для пользователя '{username}' не найден в JSON файле.")
                    continue

                encrypted_message = input("Введите зашифрованный текст (hex): ")
                decrypted_message = decrypt_message_choice(private_key_path, encrypted_message)
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
    main()
