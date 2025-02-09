from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
from datetime import datetime
import pygame
import sys
import tkinter as tk
from tkinter import filedialog
from pygame.locals import *
from SCmess.py import generate_key_pair, save_keys_to_json, get_user_to_encrypt, get_user_to_decrypt, encrypt_text_gcm, decrypt_text_gcm, scan_for_keys, add_friend_key, delete_user_from_json
from pygame.locals import *

#Инициализация Pygame
pygame.init()
WIDTH, HEIGHT = 800, 500  # Размер окна
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("GSCmess GUI")
font = pygame.font.Font(None, 24)
clock = pygame.time.Clock()

# Цвета
COLORS = {
    'background': (30, 30, 30),
    'text': (255, 255, 255),
    'button': (70, 70, 70),
    'button_hover': (100, 100, 100),
    'input': (40, 40, 40)
}

# Переменные
log_messages = []  # Лог для консоли
legacy_mode = False
buttons = []
current_input = ""
input_active = False

def draw_text(text, pos, color=COLORS['text']):
    text_surf = font.render(text, True, color)
    screen.blit(text_surf, pos)

def add_log(message):
    global log_messages
    log_messages.append(message)
    if len(log_messages) > 4:
        log_messages.pop(0)

def draw_console():
    y = HEIGHT - 100
    pygame.draw.rect(screen, COLORS['input'], (10, HEIGHT - 120, WIDTH - 20, 100))
    for msg in log_messages:
        text_surf = font.render(msg, True, COLORS['text'])
        screen.blit(text_surf, (20, y))
        y += 20
    pygame.draw.rect(screen, COLORS['text'], (10, HEIGHT - 40, WIDTH - 20, 30), 1)
    draw_text(current_input, (20, HEIGHT - 35))

def create_keys():
    username = "user"
    priv_key, pub_key = generate_key_pair(username)
    save_keys_to_json(username, pub_key, priv_key)
    add_log(f"Ключи созданы: {pub_key}")

def open_file_dialog():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    if file_path:
        add_log(f"Выбран файл: {file_path}")

def toggle_legacy():
    global legacy_mode
    legacy_mode = not legacy_mode
    add_log(f"Legacy режим {'включен' if legacy_mode else 'выключен'}")
    update_buttons()

def update_buttons():
    global buttons
    buttons = [
        Button(10, 100, 180, 40, "Создать ключи", create_keys),
        Button(200, 100, 180, 40, "Шифровать текст", lambda: set_input_target("encrypt")),
        Button(390, 100, 180, 40, "Дешифровать текст", lambda: set_input_target("decrypt")),
        Button(10, 160, 180, 40, "Выбрать файл", open_file_dialog),
        Button(200, 160, 180, 40, "Добавить ключ", lambda: set_input_target("add_key")),
        Button(390, 160, 180, 40, "Список пользователей", show_users),
        Button(10, 220, 180, 40, "Удалить пользователя", lambda: set_input_target("delete_user")),
        Button(200, 220, 180, 40, "Legacy режим", toggle_legacy),
        Button(WIDTH//2 - 100, HEIGHT - 80, 200, 40, "Выход", lambda: sys.exit())
    ]

def set_input_target(target):
    global current_input, input_active, selected_function
    current_input = ""
    input_active = True
    selected_function = target
    add_log("Введите данные...")

def handle_input():
    global current_input, selected_function
    if selected_function == "encrypt":
        pub_key, _ = get_user_to_encrypt("keys.json")
        encrypted = encrypt_text_gcm(pub_key, current_input)
        add_log("Текст зашифрован")
    elif selected_function == "decrypt":
        priv_key, _ = get_user_to_decrypt("keys.json")
        decrypted = decrypt_text_gcm(priv_key, eval(current_input))
        add_log("Текст расшифрован")
    elif selected_function == "add_key":
        username, key_path = current_input.split(" ")
        add_friend_key(username, key_path)
        add_log("Ключ добавлен")
    elif selected_function == "delete_user":
        delete_user_from_json(current_input)
        add_log("Пользователь удален")
    current_input = ""
    input_active = False

def show_users():
    with open("keys.json", "r") as f:
        data = json.load(f)
        for user in data:
            add_log(f"User: {user['username']}")

class Button:
    def __init__(self, x, y, w, h, text, callback):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.callback = callback
        self.hover = False

    def draw(self):
        color = COLORS['button_hover'] if self.hover else COLORS['button']
        pygame.draw.rect(screen, color, self.rect)
        text_surf = font.render(self.text, True, COLORS['text'])
        screen.blit(text_surf, (self.rect.x + 10, self.rect.y + 10))

    def check_hover(self, pos):
        self.hover = self.rect.collidepoint(pos)

    def check_click(self, pos):
        if self.rect.collidepoint(pos):
            self.callback()

update_buttons()

def main_loop():
    while True:
        screen.fill(COLORS['background'])
        draw_text("GSCmess GUI", (10, 10))
        mouse_pos = pygame.mouse.get_pos()
        for btn in buttons:
            btn.check_hover(mouse_pos)
            btn.draw()
        draw_console()
        pygame.display.flip()
        for event in pygame.event.get():
            if event.type == QUIT:
                pygame.quit()
                sys.exit()
            elif event.type == MOUSEBUTTONDOWN:
                for btn in buttons:
                    btn.check_click(event.pos)
            elif event.type == KEYDOWN and input_active:
                if event.key == K_RETURN:
                    handle_input()
                elif event.key == K_BACKSPACE:
                    current_input = current_input[:-1]
                else:
                    current_input += event.unicode
        clock.tick(30)
# Мусорная функция, надеюсь перейду к нормльной SEARCH_DIRECTORIES
def get_download_directory():
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ['USERPROFILE'], 'Downloads')
    if 'ANDROID_ROOT' in os.environ:  # Termux на Android
        return os.path.join(os.environ['HOME'], 'downloads')
    else:  # Другая платформа
        return os.path.join(os.environ['HOME'], 'Downloads')
CONFIG_FILE = "config.json"
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

# Загружаем или создаём конфигурацию


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

# Переключение режима Legacy
def toggle_legacy_mode():
    config['legacy_mode'] = not config['legacy_mode']
    with open(CONFIG_FILE, 'w') as config_file:
        json.dump(config, config_file, indent=4)
    print(f"Legacy-режим {'включен' if config['legacy_mode'] else 'выключен'}.")



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


# Добавление ключа друга в JSON
# Общие директории для поиска ключей и зашифрованных файлов
# Директории для поиска ключей
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

def scan_for_public_keys(json_file):
    """Сканирует стандартные и дополнительные папки на наличие файлов с публичными ключами, исключая уже существующие в keys.json."""
    
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

# Сканирование директорий для поиска ключей
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




def prompt_add_found_keys(json_file="keys.json"):
    """Предлагает пользователю добавить найденные публичные ключи в JSON файл."""
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
def add_friend_public_key(username, friend_pub_key_path, json_file="keys.json"):
    """Добавляет публичный ключ друга в JSON файл."""
    friend_key_data = {
        "username": username,
        "public_key_path": friend_pub_key_path,
        "private_key_path": None
    }
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

# Основное меню программы

def print_menu():
    menu = """
    Пожалуйста, выберите действие:

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
    11. {toggle_text}
    {legacy_menu}
    0. Выйти из программы
    """.format(
        toggle_text="Выключить Legacy-режим" if config['legacy_mode'] else "Включить Legacy-режим",
        legacy_menu="" if not config['legacy_mode'] else """
    12. Зашифровать текст c использованием Legacy RSA
    13. Расшифровать текст c использованием Legacy RSA
    14. Зашифровать файл c использованием Legacy RSA
    15. Расшифровать файл c использованием Legacy RSA
    """
    )
    print(menu)
def main_menu():
    font = pygame.font.SysFont('Arial', 24)
    if config['legacy_mode']:
        buttons += [
            Button(10, 250, 200, 40, "Legacy Шифровать текст", lambda: set_selected_function ('encrypt_text_legacy')),
            Button(220, 250, 200, 40, "Legacy Дешифровать текст", lambda: set_selected_function('decrypt_text_legacy'))
        ]
    return buttons


def get_user_to_decrypt(json_file):
    """Функция для выбора пользователя с приватным ключом для расшифровки."""
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
def get_user_to_encrypt(json_file):
    """Функция для выбора пользователя с публичным ключом для шифрования."""
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
    
def set_selected_function(func_name):
    global selected_function, input_target, current_input
    selected_function = func_name
    input_target = None
    current_input = ""

    if func_name in ['encrypt_text', 'decrypt_text', 'add_key', 'delete_user']:
        input_target = 'text'
    elif func_name in ['encrypt_file', 'decrypt_file']:
        input_target = 'file_path'

def info_gui():
    info_text = """
    1. Сначала сгенерируйте ключи
    2. Для шифрования используйте AES-GCM
    3. Удалите keys.json для сброса
    4. GitHub: https://github.com/VLOD-ZDOV
    """
    add_output(info_text)

def show_users():
    with open("keys.json", "r") as f:
        data = json.load(f)
        for user in data:
            add_output(f"User: {user['username']} | Pub: {user.get('public_key_path', '')}")


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

def decrypt_file_gcm(private_key_path, encrypted_file_path):
    """Расшифровка файла с использованием RSA + AES-GCM."""
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


def find_encrypted_files(directories):
    """Функция для поиска зашифрованных файлов в указанных директориях."""
    encrypted_files = []
    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.enc'):
                    encrypted_files.append(os.path.join(root, file))
    return encrypted_files
def add_log(message):
    global log_messages
    log_messages.append(message)
    if len(log_messages) > 5:
        log_messages.pop(0)


def draw_console():
    y = HEIGHT - 100
    pygame.draw.rect(screen, COLORS['input'], (10, HEIGHT - 120, WIDTH - 20, 100))
    for msg in log_messages:
        text_surf = font.render(msg, True, COLORS['text'])
        screen.blit(text_surf, (20, y))
        y += 20

def create_keys():
    key_path = os.path.join(os.getcwd(), "keys")
    os.makedirs(key_path, exist_ok=True)
    add_log(f"Ключи созданы в {key_path}")

def open_file_dialog():
    if sys.platform == "win32":
        os.system("explorer")
    else:
        os.system("xdg-open .")
    add_log("Открытие файлового менеджера")

def toggle_legacy():
    global legacy_mode
    legacy_mode = not legacy_mode
    add_log(f"Legacy режим {'включен' if legacy_mode else 'выключен'}")
    update_buttons()

def update_buttons():
    global buttons
    buttons = [
        Button(10, 100, 180, 40, "Создать ключи", create_keys),
        Button(200, 100, 180, 40, "Шифровать текст", lambda: add_log("Ожидание текста...")),
        Button(390, 100, 180, 40, "Дешифровать текст", lambda: add_log("Ожидание текста...")),
        Button(10, 160, 180, 40, "Шифровать файл", open_file_dialog),
        Button(200, 160, 180, 40, "Дешифровать файл", open_file_dialog),
        Button(390, 160, 180, 40, "Legacy режим", toggle_legacy),
        Button(WIDTH//2 - 100, HEIGHT - 80, 200, 40, "Выход", lambda: sys.exit())
    ]
    if legacy_mode:
        buttons.append(Button(10, 220, 180, 40, "Legacy Шифровать", lambda: add_log("Legacy шифрование")))
        buttons.append(Button(200, 220, 180, 40, "Legacy Дешифровать", lambda: add_log("Legacy дешифрование")))

update_buttons()
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


# Основная функция
def main():
    json_file = "keys.json"

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




def handle_input():
    global current_input, selected_function
    if selected_function == 'encrypt_text':
        pub_key, user = get_user_to_encrypt("keys.json")
        encrypted = encrypt_text_gcm(pub_key, current_input)
        add_output(f"Зашифрованный текст: {encrypted}")
    elif selected_function == 'decrypt_text':
        priv_key, user = get_user_to_decrypt("keys.json")
        decrypted = decrypt_text_gcm(priv_key, eval(current_input))
        add_output(f"Расшифрованный текст: {decrypted}")
    # ... Аналогичные обработчики для других функций ...

if __name__ == "__main__":
    # Инициализация конфигурации (из оригинального кода)
    CONFIG_FILE = "config.json"
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                config = json.load(f)
            except:
                config = {"legacy_mode": False}
    else:
        config = {"legacy_mode": False}

    main_loop()
