import os
import json
import base64
import threading
from datetime import datetime

from kivy.config import Config
Config.set('graphics', 'maxfps', '120')

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kivy.app import App
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.switch import Switch
from kivy.uix.colorpicker import ColorPicker
from kivy.clock import Clock
from kivy.utils import platform
from kivy.properties import ListProperty, StringProperty, BooleanProperty
from kivy.metrics import dp

if platform == 'android':
    try:
        from android import activity
        from jnius import autoclass, cast
    except Exception:
        pass

Window.clearcolor = (0.05, 0.05, 0.08, 1)

# ==================== ТЕМА ====================
DEFAULT_THEME = {
    "bg_color": [0.05, 0.05, 0.08, 1],
    "btn_bg": [0.13, 0.13, 0.18, 1],
    "btn_border": [0.25, 0.45, 0.85, 1],
    "btn_text": [1, 1, 1, 1],
    "accent": [0.25, 0.45, 0.85, 1],
    "input_bg": [0.08, 0.08, 0.12, 1],
    "input_fg": [0.92, 0.92, 0.95, 1],
    "title_color": [0.3, 0.6, 1, 1],
    "label_muted": [0.5, 0.5, 0.6, 1],
    "danger_bg": [0.7, 0.15, 0.15, 1],
    "success_bg": [0.15, 0.55, 0.25, 1],
    "log_bg": [0.06, 0.06, 0.1, 1],
}

THEME_PRESETS = {
    "Тёмная (AMOLED)": DEFAULT_THEME.copy(),
    "Синяя ночь": {
        **DEFAULT_THEME,
        "bg_color": [0.03, 0.05, 0.12, 1],
        "btn_bg": [0.07, 0.1, 0.22, 1],
        "btn_border": [0.2, 0.4, 0.9, 1],
        "accent": [0.2, 0.4, 0.9, 1],
        "input_bg": [0.05, 0.07, 0.15, 1],
        "title_color": [0.4, 0.7, 1, 1],
    },
    "Зелёная (Matrix)": {
        **DEFAULT_THEME,
        "bg_color": [0.02, 0.06, 0.02, 1],
        "btn_bg": [0.05, 0.13, 0.05, 1],
        "btn_border": [0.1, 0.75, 0.1, 1],
        "accent": [0.1, 0.75, 0.1, 1],
        "input_bg": [0.04, 0.09, 0.04, 1],
        "input_fg": [0.6, 1, 0.6, 1],
        "title_color": [0.2, 1, 0.2, 1],
        "label_muted": [0.3, 0.6, 0.3, 1],
    },
    "Пурпурная": {
        **DEFAULT_THEME,
        "bg_color": [0.08, 0.04, 0.12, 1],
        "btn_bg": [0.15, 0.08, 0.22, 1],
        "btn_border": [0.6, 0.2, 0.9, 1],
        "accent": [0.6, 0.2, 0.9, 1],
        "input_bg": [0.1, 0.05, 0.15, 1],
        "title_color": [0.8, 0.4, 1, 1],
    },
}

SETTINGS_FILE = None  # будет задан после init

# ==================== KV ====================
KV = '''
#:import dp kivy.metrics.dp

<StyledButton@Button>:
    background_normal: ''
    background_color: app.theme['btn_bg']
    color: app.theme['btn_text']
    font_size: '15sp'
    bold: True
    canvas.before:
        Color:
            rgba: app.theme['btn_border']
        Line:
            width: 1.4
            rounded_rectangle: self.x+1, self.y+1, self.width-2, self.height-2, 6
        Color:
            rgba: app.theme['btn_bg']
        RoundedRectangle:
            pos: self.x+2, self.y+2
            size: self.width-4, self.height-4
            radius: [5]

<DangerButton@Button>:
    background_normal: ''
    background_color: app.theme['danger_bg']
    color: 1, 1, 1, 1
    font_size: '15sp'
    bold: True
    canvas.before:
        Color:
            rgba: 1, 0.3, 0.3, 1
        Line:
            width: 1.2
            rounded_rectangle: self.x+1, self.y+1, self.width-2, self.height-2, 6
        Color:
            rgba: app.theme['danger_bg']
        RoundedRectangle:
            pos: self.x+2, self.y+2
            size: self.width-4, self.height-4
            radius: [5]

<StyledInput@TextInput>:
    background_color: app.theme['input_bg']
    foreground_color: app.theme['input_fg']
    cursor_color: app.theme['accent']
    font_size: '16sp'
    padding: [12, 10, 12, 10]
    hint_text_color: 0.45, 0.45, 0.55, 1

<SectionLabel@Label>:
    font_size: '13sp'
    color: app.theme['label_muted']
    size_hint_y: None
    height: dp(24)
    halign: 'left'
    text_size: self.width, None

<MenuScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(20), dp(24), dp(20), dp(16)]
        spacing: dp(10)
        BoxLayout:
            size_hint_y: None
            height: dp(60)
            Label:
                id: app_title
                text: 'SCmess'
                font_size: '28sp'
                bold: True
                color: app.theme['title_color']
                on_touch_down: root.title_tapped(self, args[1])
            BoxLayout:
                size_hint_x: None
                width: dp(90)
                spacing: dp(8)
                StyledButton:
                    text: 'Логи'
                    opacity: 1 if app.dev_mode else 0
                    disabled: not app.dev_mode
                    on_release: root.show_logs()
                StyledButton:
                    text: '[b]=[/b]'
                    markup: True
                    on_release: root.manager.current = 'settings'
        SectionLabel:
            text: 'RSA + AES-256-GCM'
            color: app.theme['accent']
            height: dp(20)
        Widget:
            size_hint_y: None
            height: dp(6)
        StyledButton:
            text: 'Ключи и Пользователи'
            size_hint_y: None
            height: dp(52)
            on_release: root.manager.current = 'keys'
        StyledButton:
            text: 'Шифрование Текста'
            size_hint_y: None
            height: dp(52)
            on_release: root.manager.current = 'text'
        StyledButton:
            text: 'Шифрование Файлов'
            size_hint_y: None
            height: dp(52)
            on_release: root.manager.current = 'files'
        StyledButton:
            text: 'Групповой Чат'
            size_hint_y: None
            height: dp(52)
            on_release: root.manager.current = 'group'
        Widget:
        StyledButton:
            text: 'Помощь'
            size_hint_y: None
            height: dp(44)
            on_release: root.show_help()

<TextScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(14), dp(14), dp(14), dp(10)]
        spacing: dp(8)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Label:
                text: 'Шифрование текста'
                font_size: '18sp'
                bold: True
                color: app.theme['title_color']
        Spinner:
            id: user_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(46)
        Label:
            id: user_warning
            text: ''
            color: 1, 0.25, 0.25, 1
            font_size: '13sp'
            size_hint_y: None
            height: dp(0)
        BoxLayout:
            size_hint_y: None
            height: dp(42)
            spacing: dp(10)
            padding: [dp(4), dp(4), dp(4), dp(4)]
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [6]
            Label:
                text: 'Авто-копировать в буфер'
                font_size: '14sp'
                color: app.theme['btn_text']
                size_hint_x: 0.72
                halign: 'left'
                text_size: self.width - dp(8), None
            Switch:
                id: auto_copy_switch
                active: True
                size_hint_x: 0.28
        StyledInput:
            id: text_input
            hint_text: 'Введите текст для шифровки или вставьте JSON для расшифровки'
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            StyledButton:
                text: 'Зашифровать'
                on_release: root.encrypt_action()
            StyledButton:
                text: 'Расшифровать'
                on_release: root.decrypt_action()
            StyledButton:
                text: 'Очистить'
                on_release: root.clear_field()
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'

<FileScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(14), dp(14), dp(14), dp(10)]
        spacing: dp(8)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Label:
                text: 'Шифрование файлов'
                font_size: '18sp'
                bold: True
                color: app.theme['title_color']
        Spinner:
            id: user_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(46)
        Label:
            id: user_warning
            text: ''
            color: 1, 0.25, 0.25, 1
            font_size: '13sp'
            size_hint_y: None
            height: dp(0)
        BoxLayout:
            size_hint_y: None
            height: dp(42)
            spacing: dp(10)
            padding: [dp(4), dp(4), dp(4), dp(4)]
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [6]
            Label:
                text: 'Android Document UI'
                font_size: '14sp'
                color: app.theme['btn_text']
                size_hint_x: 0.72
                halign: 'left'
                text_size: self.width - dp(8), None
            Switch:
                id: native_switch
                active: False
                size_hint_x: 0.28
        BoxLayout:
            size_hint_y: None
            height: dp(40)
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [5]
            Label:
                id: file_label
                text: 'Файл не выбран'
                color: app.theme['label_muted']
                font_size: '13sp'
                halign: 'left'
                padding_x: dp(10)
                text_size: self.width - dp(10), None
        StyledButton:
            text: 'Выбрать файл'
            size_hint_y: None
            height: dp(50)
            on_release: root.choose_file()
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            StyledButton:
                text: 'Зашифровать'
                on_release: root.encrypt_file()
            StyledButton:
                text: 'Расшифровать'
                on_release: root.decrypt_file()
        Widget:
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'

<GroupScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(14), dp(14), dp(14), dp(10)]
        spacing: dp(8)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Label:
                text: 'Групповой чат'
                font_size: '18sp'
                bold: True
                color: app.theme['title_color']
        SectionLabel:
            text: 'Отметьте получателей:'
        ScrollView:
            size_hint_y: 0.28
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [6]
            BoxLayout:
                id: group_users_layout
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                padding: [dp(6), dp(4), dp(6), dp(4)]
                spacing: dp(4)
        StyledInput:
            id: group_input
            hint_text: 'Текст для шифровки ИЛИ полученный JSON для расшифровки'
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            StyledButton:
                text: 'Зашифровать'
                on_release: root.encrypt_group()
            StyledButton:
                text: 'Расшифровать'
                on_release: root.decrypt_group()
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'

<KeysScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(14), dp(14), dp(14), dp(10)]
        spacing: dp(8)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Label:
                text: 'Ключи и Пользователи'
                font_size: '18sp'
                bold: True
                color: app.theme['title_color']
        StyledButton:
            text: 'Сгенерировать свои ключи'
            size_hint_y: None
            height: dp(52)
            on_release: root.generate_keys_dialog()
        SectionLabel:
            text: 'Добавить друга'
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(8)
            StyledButton:
                text: 'Из файла'
                on_release: root.add_key_dialog()
            StyledButton:
                text: 'Текстом'
                on_release: root.add_key_text_dialog()
        SectionLabel:
            text: 'Нажмите на пользователя для управления:'
        ScrollView:
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [6]
            BoxLayout:
                id: users_list
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                padding: [dp(6), dp(6), dp(6), dp(6)]
                spacing: dp(6)
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'

<SettingsScreen>:
    canvas.before:
        Color:
            rgba: app.theme['bg_color']
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: 'vertical'
        padding: [dp(14), dp(14), dp(14), dp(10)]
        spacing: dp(8)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            Label:
                text: 'Настройки'
                font_size: '18sp'
                bold: True
                color: app.theme['title_color']
        SectionLabel:
            text: 'Цветовая тема:'
            height: dp(28)
        Spinner:
            id: preset_spinner
            text: 'Тёмная (AMOLED)'
            values: ['Темная (AMOLED)', 'Синяя ночь', 'Зеленая (Matrix)', 'Пурпурная']
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(46)
            on_text: root.apply_preset(self.text)
        SectionLabel:
            text: 'Настройка цветов вручную:'
            height: dp(28)
        ScrollView:
            BoxLayout:
                id: color_rows
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                spacing: dp(6)
        Widget:
            size_hint_y: None
            height: dp(6)
        StyledButton:
            text: 'Сохранить настройки'
            size_hint_y: None
            height: dp(48)
            on_release: root.save_settings()
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'
'''

# ==================== HELPERS ====================

def show_msg(title, text):
    app = App.get_running_app()
    theme = app.theme if app else DEFAULT_THEME
    content = Label(
        text=text,
        text_size=(dp(340), None),
        color=theme['btn_text'],
        halign='left',
        valign='top',
    )
    popup = Popup(
        title=title,
        content=content,
        size_hint=(0.88, None),
        height=dp(260),
        background_color=theme['input_bg'],
        title_color=theme['title_color'],
        separator_color=theme['accent'],
    )
    content.bind(texture_size=lambda *a: content.setter('height')(content, content.texture_size[1]))
    popup.open()


# ==================== BACKEND ====================

class CryptoBackend:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.keys_file = os.path.join(self.data_dir, "keys.json")
        self.keys_dir = os.path.join(self.data_dir, "keys")
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
        if not os.path.exists(self.keys_file):
            with open(self.keys_file, 'w') as f:
                json.dump([], f)

    def load_users(self):
        try:
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []

    def save_users(self, data):
        with open(self.keys_file, 'w') as f:
            json.dump(data, f, indent=4)

    def delete_user(self, username):
        users = self.load_users()
        new_users = []
        for u in users:
            if u['username'] == username:
                for key_type in ['public_key_path', 'private_key_path']:
                    if u.get(key_type) and os.path.exists(u[key_type]):
                        try:
                            os.remove(u[key_type])
                        except Exception:
                            pass
            else:
                new_users.append(u)
        self.save_users(new_users)

    def generate_key_pair(self, username, key_size):
        current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        priv_filename = os.path.join(self.keys_dir, f"RSA_{username}_priv_{current_time}.pem")
        pub_filename = os.path.join(self.keys_dir, f"RSA_{username}_pub_{current_time}.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        with open(priv_filename, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(pub_filename, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        data = self.load_users()
        data.append({
            "username": username,
            "public_key_path": pub_filename,
            "private_key_path": priv_filename
        })
        self.save_users(data)

    def add_friend_key(self, username, key_path, is_private=False):
        data = self.load_users()
        user = next((u for u in data if u['username'] == username), None)
        if not user:
            user = {"username": username}
            data.append(user)

        key_name = os.path.basename(key_path)
        new_path = os.path.join(self.keys_dir, key_name)
        with open(key_path, 'rb') as src, open(new_path, 'wb') as dst:
            dst.write(src.read())

        if is_private:
            user['private_key_path'] = new_path
        else:
            user['public_key_path'] = new_path
        self.save_users(data)

    def add_friend_key_from_text(self, username, key_text, is_private=False):
        data = self.load_users()
        user = next((u for u in data if u['username'] == username), None)
        if not user:
            user = {"username": username}
            data.append(user)

        current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        k_type = "priv" if is_private else "pub"
        new_path = os.path.join(self.keys_dir, f"RSA_imported_{username}_{k_type}_{current_time}.pem")

        with open(new_path, 'w', encoding='utf-8') as f:
            f.write(key_text)

        if is_private:
            user['private_key_path'] = new_path
        else:
            user['public_key_path'] = new_path
        self.save_users(data)

    def encrypt_text_gcm(self, public_key_path, text):
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()

        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        encrypted_aes_key = public_key.encrypt(
            aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return json.dumps({
            'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        })

    def decrypt_text_gcm(self, private_key_path, json_str):
        data = json.loads(json_str)
        encrypted_aes_key = base64.b64decode(data['aes_key'])
        iv = base64.b64decode(data['iv'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ciphertext'])

        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        aes_key = private_key.decrypt(
            encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')

    def encrypt_file_gcm(self, public_key_path, file_path):
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()

        with open(file_path, 'rb') as f:
            plaintext = f.read()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        encrypted_aes_key = public_key.encrypt(
            aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        out_path = file_path + ".enc"
        with open(out_path, 'wb') as f:
            f.write(encrypted_aes_key + iv + encryptor.tag + ciphertext)
        return out_path

    def decrypt_file_gcm(self, private_key_path, file_path):
        with open(file_path, 'rb') as f:
            encrypted_aes_key = f.read(512)
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        aes_key = private_key.decrypt(
            encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        if file_path.lower().endswith('.enc'):
            out_path = file_path[:-4]
        else:
            out_path = file_path + ".dec"
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
        return out_path

    def encrypt_group(self, public_keys_dict, text):
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()

        encrypted_keys = {}
        for username, pub_path in public_keys_dict.items():
            with open(pub_path, 'rb') as f:
                pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
            enc_aes = pub_key.encrypt(
                aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            encrypted_keys[username] = base64.b64encode(enc_aes).decode('utf-8')

        payload = {
            "type": "group_message_gcm",
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "keys": encrypted_keys
        }
        return json.dumps(payload, ensure_ascii=False)

    def decrypt_group(self, payload_str):
        payload = json.loads(payload_str)
        users = self.load_users()

        for user in users:
            if user['username'] in payload.get("keys", {}) and user.get("private_key_path"):
                target_priv_key = user['private_key_path']
                enc_aes_key_b64 = payload["keys"][user['username']]
                break
        else:
            raise Exception("Нет подходящего приватного ключа для расшифровки.")

        encrypted_aes_key = base64.b64decode(enc_aes_key_b64)
        iv = base64.b64decode(payload['iv'])
        tag = base64.b64decode(payload['tag'])
        ciphertext = base64.b64decode(payload['ciphertext'])

        with open(target_priv_key, 'rb') as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        aes_key = priv_key.decrypt(
            encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')


# ==================== ЭКРАНЫ ====================

class MenuScreen(Screen):
    taps = 0

    def title_tapped(self, widget, touch):
        if widget.collide_point(*touch.pos):
            self.taps += 1
            if self.taps >= 10:
                app = App.get_running_app()
                app.dev_mode = not app.dev_mode
                status = "ВКЛЮЧЁН" if app.dev_mode else "ВЫКЛЮЧЕН"
                show_msg("Режим разработчика", f"Режим разработчика {status}\nПовтори 10 нажатий для смены.")
                self.taps = 0

    def show_help(self):
        help_text = (
            "Как начать:\n\n"
            "1. Ключи и Пользователи - Сгенерировать свои ключи\n"
            "2. Добавь друзей (Из файла / Текстом)\n"
            "3. В шифровании текста можно включить авто-копирование\n"
            "4. В файлах можно переключить Android Document UI\n"
            "5. Настройки - смена темы и цветов интерфейса\n"
            "6. Логи доступны в режиме разработчика (10 тапов по заголовку)"
        )
        popup = Popup(
            title="Помощь",
            content=Label(text=help_text, text_size=(dp(360), None), halign='left', valign='top'),
            size_hint=(0.9, 0.8)
        )
        popup.open()

    def show_logs(self):
        app = App.get_running_app()
        theme = app.theme
        if not app.action_log:
            content = Label(text="Логов пока нет.", color=theme['label_muted'])
        else:
            sv = ScrollView()
            box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(2), padding=dp(6))
            box.bind(minimum_height=box.setter('height'))
            for line in reversed(app.action_log):
                lbl = Label(
                    text=line,
                    size_hint_y=None,
                    height=dp(32),
                    halign='left',
                    valign='middle',
                    text_size=(dp(500), None),
                    color=theme['input_fg'],
                    font_size='13sp',
                )
                box.add_widget(lbl)
            sv.add_widget(box)
            content = sv
        popup = Popup(
            title="Логи приложения (dev mode)",
            content=content,
            size_hint=(0.95, 0.85),
            background_color=theme['log_bg'],
            title_color=theme['title_color'],
            separator_color=theme['accent'],
        )
        popup.open()


class KeysScreen(Screen):
    def on_enter(self):
        self.refresh_users()

    def refresh_users(self):
        backend = App.get_running_app().backend
        users = backend.load_users()
        layout = self.ids.users_list
        layout.clear_widgets()
        theme = App.get_running_app().theme
        for u in users:
            has_pub = bool(u.get('public_key_path'))
            has_priv = bool(u.get('private_key_path'))
            text = f"{u['username']}\nПуб: {'OK' if has_pub else '--'}   Прив: {'OK' if has_priv else '--'}"
            btn = Button(
                text=text,
                size_hint_y=None,
                height=dp(64),
                background_normal='',
                background_color=theme['btn_bg'],
                color=theme['btn_text'],
                halign='left',
                valign='middle',
                text_size=(Window.width - dp(60), None),
                font_size='14sp',
            )
            btn.bind(on_release=lambda x, user=u: self.show_user_options(user))
            layout.add_widget(btn)

    def show_user_options(self, user):
        app = App.get_running_app()
        theme = app.theme
        box = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(8))

        pub_text = "Публичный ключ отсутствует"
        if user.get('public_key_path') and os.path.exists(user['public_key_path']):
            with open(user['public_key_path'], 'r') as f:
                pub_text = f.read()

        pub_view = TextInput(
            text=pub_text, readonly=True,
            background_color=theme['input_bg'],
            foreground_color=theme['accent'],
            font_size='10sp', size_hint_y=0.45,
        )
        copy_pub = Button(
            text="Копировать публичный ключ",
            size_hint_y=None, height=dp(42),
            background_normal='', background_color=theme['btn_bg'],
            color=theme['btn_text'],
        )

        if app.dev_mode and user.get('private_key_path') and os.path.exists(user['private_key_path']):
            with open(user['private_key_path'], 'r') as f:
                priv_text = f.read()
            priv_view = TextInput(
                text=priv_text, readonly=True,
                background_color=[0.12, 0.03, 0.03, 1],
                foreground_color=[1, 0.4, 0.4, 1],
                font_size='10sp', size_hint_y=0.3,
            )
            copy_priv = Button(
                text="Копировать приватный ключ (ОПАСНО!)",
                size_hint_y=None, height=dp(42),
                background_normal='', background_color=theme['danger_bg'],
                color=[1, 1, 1, 1],
            )
            box.add_widget(Label(text="ПРИВАТНЫЙ КЛЮЧ (dev mode)", size_hint_y=None, height=dp(28), color=[1, 0.4, 0.4, 1]))
            box.add_widget(priv_view)
            box.add_widget(copy_priv)

            def copy_priv_key(_):
                Clipboard.copy(priv_text)
                show_msg("Скопировано", "Приватный ключ в буфере")
            copy_priv.bind(on_release=copy_priv_key)

        box.add_widget(Label(text=f"Пользователь: {user['username']}", size_hint_y=None, height=dp(32), color=theme['title_color']))
        box.add_widget(pub_view)
        box.add_widget(copy_pub)

        del_btn = Button(
            text="Удалить пользователя",
            size_hint_y=None, height=dp(42),
            background_normal='', background_color=theme['danger_bg'],
            color=[1, 1, 1, 1],
        )
        box.add_widget(del_btn)

        popup = Popup(
            title="Управление пользователем",
            content=box, size_hint=(0.9, 0.9),
            background_color=theme['input_bg'],
            title_color=theme['title_color'],
        )

        def copy_pub_key(_):
            Clipboard.copy(pub_text)
            show_msg("Скопировано", "Публичный ключ в буфере обмена")
        copy_pub.bind(on_release=copy_pub_key)

        def delete_confirm(_):
            App.get_running_app().backend.delete_user(user['username'])
            popup.dismiss()
            self.refresh_users()
            App.get_running_app().log_action(f"Удалён пользователь {user['username']}")
            show_msg("Удалено", f"Пользователь {user['username']} удалён")
        del_btn.bind(on_release=delete_confirm)

        popup.open()

    def generate_keys_dialog(self):
        theme = App.get_running_app().theme
        box = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(10))
        inp = TextInput(
            hint_text="Имя пользователя", size_hint_y=None, height=dp(48),
            background_color=theme['input_bg'], foreground_color=theme['input_fg'],
        )
        spinner = Spinner(
            text='4096', values=('2048', '4096'),
            size_hint_y=None, height=dp(46),
            background_normal='', background_color=theme['btn_bg'],
            color=theme['btn_text'],
        )
        btn = Button(
            text="Создать", size_hint_y=None, height=dp(52),
            background_normal='', background_color=theme['accent'],
            color=[1, 1, 1, 1],
        )
        box.add_widget(inp)
        box.add_widget(Label(text="Размер RSA ключа (бит):", size_hint_y=None, height=dp(28), color=theme['label_muted']))
        box.add_widget(spinner)
        box.add_widget(btn)

        popup = Popup(title="Генерация ключей", content=box, size_hint=(0.85, 0.55),
                      background_color=theme['input_bg'], title_color=theme['title_color'])

        def on_create(instance):
            if not inp.text.strip():
                return
            size = int(spinner.text)
            wait_popup = Popup(
                title="Генерация...",
                content=Label(text=f"Создаём {size}-бит ключи...\nПодождите", color=theme['input_fg']),
                size_hint=(0.8, 0.35), auto_dismiss=False,
                background_color=theme['input_bg'], title_color=theme['title_color'],
            )
            popup.dismiss()
            wait_popup.open()
            threading.Thread(target=self._gen_keys_thread, args=(inp.text.strip(), size, wait_popup)).start()

        btn.bind(on_release=on_create)
        popup.open()

    def _gen_keys_thread(self, username, size, wait_popup):
        try:
            App.get_running_app().backend.generate_key_pair(username, size)
            Clock.schedule_once(lambda dt: [self.refresh_users(), wait_popup.dismiss(),
                                            show_msg("Успех", f"Ключи для {username} созданы!")], 0)
        except Exception as e:
            Clock.schedule_once(lambda dt: [wait_popup.dismiss(), show_msg("Ошибка", str(e))], 0)

    def add_key_dialog(self):
        storage_path = '/storage/emulated/0/Download' if platform == 'android' else os.path.expanduser('~')
        chooser = FileChooserListView(path=storage_path, filters=['*.pem'])
        box = BoxLayout(orientation='vertical')
        box.add_widget(chooser)
        btn = Button(text="Выбрать как публичный", size_hint_y=None, height=dp(48),
                     background_normal='', background_color=App.get_running_app().theme['btn_bg'])
        box.add_widget(btn)
        popup = Popup(title="Выбор файла ключа", content=box, size_hint=(0.9, 0.9))

        def on_select(instance):
            if chooser.selection:
                path = chooser.selection[0]
                name_box = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(8))
                name_inp = TextInput(hint_text="Имя владельца", size_hint_y=0.6)
                ok_btn = Button(text="Сохранить", size_hint_y=0.4, background_normal='',
                                background_color=App.get_running_app().theme['accent'])
                name_box.add_widget(name_inp)
                name_box.add_widget(ok_btn)
                name_popup = Popup(title="Имя пользователя", content=name_box, size_hint=(0.75, 0.32))

                def save_key(_):
                    if name_inp.text.strip():
                        App.get_running_app().backend.add_friend_key(name_inp.text.strip(), path, False)
                        name_popup.dismiss()
                        popup.dismiss()
                        self.refresh_users()
                        show_msg("Готово", "Ключ добавлен")
                ok_btn.bind(on_release=save_key)
                name_popup.open()
        btn.bind(on_release=on_select)
        popup.open()

    def add_key_text_dialog(self):
        theme = App.get_running_app().theme
        box = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(10))
        inp_name = TextInput(hint_text="Имя пользователя", size_hint_y=None, height=dp(48),
                             background_color=theme['input_bg'], foreground_color=theme['input_fg'])
        inp_key = TextInput(hint_text="Вставьте PEM ключ сюда...",
                            background_color=theme['input_bg'], foreground_color=theme['input_fg'])
        btn = Button(text="Сохранить как публичный", size_hint_y=None, height=dp(52),
                     background_normal='', background_color=theme['accent'], color=[1, 1, 1, 1])

        box.add_widget(inp_name)
        box.add_widget(inp_key)
        box.add_widget(btn)

        popup = Popup(title="Импорт ключа текстом", content=box, size_hint=(0.9, 0.78),
                      background_color=theme['input_bg'], title_color=theme['title_color'])

        def save(instance):
            if inp_name.text.strip() and inp_key.text.strip():
                App.get_running_app().backend.add_friend_key_from_text(inp_name.text.strip(), inp_key.text.strip(), False)
                popup.dismiss()
                self.refresh_users()
                show_msg("Готово", "Ключ импортирован")
        btn.bind(on_release=save)
        popup.open()


class TextScreen(Screen):
    def on_enter(self):
        users = App.get_running_app().backend.load_users()
        self.ids.user_spinner.values = [u['username'] for u in users if u.get('public_key_path')]
        self._hide_warning()

    def _show_warning(self, text="Выберите пользователя из списка!"):
        w = self.ids.user_warning
        w.text = text
        w.height = dp(28)

    def _hide_warning(self):
        w = self.ids.user_warning
        w.text = ''
        w.height = dp(0)

    def clear_field(self):
        self.ids.text_input.text = ''
        self._hide_warning()

    def encrypt_action(self):
        username = self.ids.user_spinner.text
        text = self.ids.text_input.text.strip()
        if username == 'Выберите пользователя' or not username:
            self._show_warning("Выберите пользователя из списка!")
            return
        if not text:
            show_msg("Ошибка", "Введите текст для шифрования!")
            return
        self._hide_warning()
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "У пользователя нет публичного ключа!")
            return
        try:
            res = backend.encrypt_text_gcm(user['public_key_path'], text)
            self.ids.text_input.text = res
            # FIX: уважаем переключатель авто-копирования
            if self.ids.auto_copy_switch.active:
                Clipboard.copy(res)
                show_msg("Успех", "Текст зашифрован и скопирован в буфер!")
            else:
                show_msg("Успех", "Текст зашифрован!")
            App.get_running_app().log_action(f"Зашифрован текст для {username}")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def decrypt_action(self):
        username = self.ids.user_spinner.text
        text = self.ids.text_input.text.strip()
        if username == 'Выберите пользователя' or not username:
            self._show_warning("Выберите пользователя из списка!")
            return
        if not text:
            show_msg("Ошибка", "Вставьте зашифрованный JSON!")
            return
        self._hide_warning()
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа для этого пользователя!")
            return
        try:
            res = backend.decrypt_text_gcm(user['private_key_path'], text)
            self.ids.text_input.text = res
            show_msg("Успех", "Текст расшифрован")
            App.get_running_app().log_action(f"Расшифрован текст для {username}")
        except Exception as e:
            show_msg("Ошибка расшифровки", str(e))


class FileScreen(Screen):
    selected_file = None

    def on_enter(self):
        users = App.get_running_app().backend.load_users()
        self.ids.user_spinner.values = [u['username'] for u in users if u.get('public_key_path')]
        self._hide_warning()

    def _show_warning(self, text="Выберите пользователя из списка!"):
        w = self.ids.user_warning
        w.text = text
        w.height = dp(28)

    def _hide_warning(self):
        w = self.ids.user_warning
        w.text = ''
        w.height = dp(0)

    def choose_file(self):
        # FIX: Android Document UI — корректно читаем состояние переключателя
        if platform == 'android' and self.ids.native_switch.active:
            self.open_native_android_picker()
        else:
            self._open_kivy_picker()

    def _open_kivy_picker(self):
        storage_path = '/storage/emulated/0/Download' if platform == 'android' else os.path.expanduser('~')
        chooser = FileChooserListView(path=storage_path)
        box = BoxLayout(orientation='vertical')
        box.add_widget(chooser)
        btn = Button(
            text="Выбрать", size_hint_y=None, height=dp(50),
            background_normal='', background_color=App.get_running_app().theme['accent'],
        )
        box.add_widget(btn)
        popup = Popup(title="Выбор файла", content=box, size_hint=(0.95, 0.92))

        def on_select(instance):
            if chooser.selection:
                self.selected_file = chooser.selection[0]
                self.ids.file_label.text = os.path.basename(self.selected_file)
                self.ids.file_label.color = App.get_running_app().theme['input_fg']
                App.get_running_app().log_action(f"Выбран файл: {os.path.basename(self.selected_file)}")
            popup.dismiss()
        btn.bind(on_release=on_select)
        popup.open()

    def open_native_android_picker(self):
        # FIX: обработка результата через on_activity_result
        try:
            from jnius import autoclass
            Intent = autoclass('android.content.Intent')
            PythonActivity = autoclass('org.kivy.android.PythonActivity')

            intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            intent.setType("*/*")

            # Регистрируем обработчик результата
            try:
                from android import activity as android_activity
                android_activity.bind(on_activity_result=self._on_android_result)
            except Exception:
                pass

            PythonActivity.mActivity.startActivityForResult(intent, 1234)
            App.get_running_app().log_action("Открыт Android Document UI")
        except Exception as e:
            show_msg("Ошибка Document UI", str(e))
            # Откат на Kivy-пикер
            self._open_kivy_picker()

    def _on_android_result(self, requestCode, resultCode, intent):
        if requestCode != 1234 or intent is None:
            return
        try:
            from jnius import autoclass
            uri = intent.getData()
            # Конвертируем URI в путь через ContentResolver
            context = autoclass('org.kivy.android.PythonActivity').mActivity
            cursor = context.getContentResolver().query(uri, None, None, None, None)
            if cursor and cursor.moveToFirst():
                idx = cursor.getColumnIndex("_data")
                if idx >= 0:
                    path = cursor.getString(idx)
                    if path:
                        self.selected_file = path
                        self.ids.file_label.text = os.path.basename(path)
                        self.ids.file_label.color = App.get_running_app().theme['input_fg']
                        return
            # Если путь не получен — показываем URI
            self.ids.file_label.text = str(uri)
            show_msg("Файл выбран", "Файл выбран через Document UI.\nМожно продолжить.")
        except Exception as e:
            show_msg("Ошибка", f"Не удалось прочитать файл: {e}")

    def encrypt_file(self):
        username = self.ids.user_spinner.text
        if username == 'Выберите пользователя' or not username:
            self._show_warning("Выберите пользователя из списка!")
            return
        self._hide_warning()
        if not self.selected_file:
            show_msg("Ошибка", "Сначала выберите файл!")
            return
        user = next((u for u in App.get_running_app().backend.load_users()
                     if u['username'] == username), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "Нет публичного ключа!")
            return
        try:
            out = App.get_running_app().backend.encrypt_file_gcm(user['public_key_path'], self.selected_file)
            App.get_running_app().log_action(f"Зашифрован файл: {os.path.basename(self.selected_file)}")
            show_msg("Успех", f"Файл зашифрован!\nСохранён как:\n{out}")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def decrypt_file(self):
        username = self.ids.user_spinner.text
        if username == 'Выберите пользователя' or not username:
            self._show_warning("Выберите пользователя из списка!")
            return
        self._hide_warning()
        if not self.selected_file:
            show_msg("Ошибка", "Сначала выберите файл!")
            return
        user = next((u for u in App.get_running_app().backend.load_users()
                     if u['username'] == username), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа!")
            return
        try:
            out = App.get_running_app().backend.decrypt_file_gcm(user['private_key_path'], self.selected_file)
            App.get_running_app().log_action(f"Расшифрован файл: {os.path.basename(self.selected_file)}")
            show_msg("Успех", f"Файл расшифрован!\nСохранён как:\n{out}")
        except Exception as e:
            show_msg("Ошибка", str(e))


class GroupScreen(Screen):
    def on_enter(self):
        backend = App.get_running_app().backend
        users = backend.load_users()
        layout = self.ids.group_users_layout
        layout.clear_widgets()
        from kivy.uix.checkbox import CheckBox
        self.checkboxes = {}
        theme = App.get_running_app().theme
        for u in users:
            if u.get('public_key_path'):
                row = BoxLayout(size_hint_y=None, height=dp(44), padding=[dp(6), 0, dp(6), 0])
                chk = CheckBox(size_hint_x=None, width=dp(40), color=theme['accent'])
                lbl = Label(text=u['username'], color=theme['input_fg'], halign='left',
                            text_size=(Window.width - dp(80), None))
                row.add_widget(chk)
                row.add_widget(lbl)
                layout.add_widget(row)
                self.checkboxes[u['username']] = chk

    def encrypt_group(self):
        text = self.ids.group_input.text.strip()
        if not text:
            show_msg("Ошибка", "Введите текст!")
            return
        selected = {name: chk for name, chk in self.checkboxes.items() if chk.active}
        if not selected:
            show_msg("Ошибка", "Выберите хотя бы одного получателя!")
            return

        backend = App.get_running_app().backend
        users = backend.load_users()
        pub_dict = {}
        for name in selected:
            u = next((u for u in users if u['username'] == name), None)
            if u and u.get('public_key_path'):
                pub_dict[name] = u['public_key_path']

        try:
            res = backend.encrypt_group(pub_dict, text)
            self.ids.group_input.text = res
            Clipboard.copy(res)
            show_msg("Успех", "Групповое сообщение зашифровано и скопировано!")
            App.get_running_app().log_action("Выполнено групповое шифрование")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def decrypt_group(self):
        text = self.ids.group_input.text.strip()
        if not text:
            show_msg("Ошибка", "Вставьте JSON для расшифровки!")
            return
        try:
            res = App.get_running_app().backend.decrypt_group(text)
            self.ids.group_input.text = res
            show_msg("Успех", "Сообщение расшифровано")
            App.get_running_app().log_action("Выполнена групповая расшифровка")
        except Exception as e:
            show_msg("Ошибка расшифровки", str(e))


# ==================== НАСТРОЙКИ ====================

COLOR_LABELS = {
    "bg_color": "Фон приложения",
    "btn_bg": "Фон кнопок",
    "btn_border": "Рамка кнопок",
    "btn_text": "Текст кнопок",
    "accent": "Акцентный цвет",
    "input_bg": "Фон поля ввода",
    "input_fg": "Текст в полях",
    "title_color": "Цвет заголовков",
    "label_muted": "Второстепенный текст",
    "danger_bg": "Цвет опасных кнопок",
    "success_bg": "Цвет успеха",
    "log_bg": "Фон логов",
}


def rgba_to_hex(rgba):
    r, g, b = int(rgba[0]*255), int(rgba[1]*255), int(rgba[2]*255)
    return f"#{r:02X}{g:02X}{b:02X}"


def hex_to_rgba(hex_str, alpha=1.0):
    hex_str = hex_str.strip().lstrip('#')
    if len(hex_str) == 6:
        r = int(hex_str[0:2], 16) / 255
        g = int(hex_str[2:4], 16) / 255
        b = int(hex_str[4:6], 16) / 255
        return [r, g, b, alpha]
    return [1, 1, 1, 1]


class SettingsScreen(Screen):
    _color_inputs = {}

    def on_enter(self):
        self._color_inputs = {}
        self._build_color_rows()
        # Установить текущий пресет в спиннер
        self.ids.preset_spinner.values = list(THEME_PRESETS.keys())

    def _build_color_rows(self):
        box = self.ids.color_rows
        box.clear_widgets()
        self._color_inputs = {}
        theme = App.get_running_app().theme

        for key, label in COLOR_LABELS.items():
            row = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8), padding=[dp(4), dp(4), dp(4), dp(4)])

            # Цветной квадрат
            from kivy.uix.widget import Widget
            color_preview = Widget(size_hint_x=None, width=dp(32))
            rgba = theme.get(key, [1, 1, 1, 1])
            with color_preview.canvas:
                from kivy.graphics import Color as GColor, RoundedRectangle as GRR
                GColor(*rgba)
                GRR(pos=color_preview.pos, size=color_preview.size, radius=[4])

            name_label = Label(
                text=label,
                color=theme['label_muted'],
                font_size='13sp',
                size_hint_x=0.55,
                halign='left',
                text_size=(Window.width * 0.45, None),
            )

            hex_val = rgba_to_hex(rgba)
            inp = TextInput(
                text=hex_val,
                size_hint_x=0.35,
                size_hint_y=None,
                height=dp(38),
                background_color=theme['input_bg'],
                foreground_color=theme['input_fg'],
                font_size='13sp',
                multiline=False,
            )
            self._color_inputs[key] = inp

            # Живое обновление превью при вводе
            preview_ref = [color_preview, rgba]
            def make_updater(widget, key_name, preview_widget):
                def on_text(instance, value):
                    try:
                        new_rgba = hex_to_rgba(value, alpha=App.get_running_app().theme.get(key_name, [1,1,1,1])[3])
                        preview_widget.canvas.clear()
                        with preview_widget.canvas:
                            from kivy.graphics import Color as GColor, RoundedRectangle as GRR
                            GColor(*new_rgba)
                            GRR(pos=preview_widget.pos, size=preview_widget.size, radius=[4])
                    except Exception:
                        pass
                return on_text
            inp.bind(text=make_updater(inp, key, color_preview))

            row.add_widget(color_preview)
            row.add_widget(name_label)
            row.add_widget(inp)
            box.add_widget(row)

    def apply_preset(self, preset_name):
        preset = THEME_PRESETS.get(preset_name)
        if not preset:
            return
        app = App.get_running_app()
        app.theme = dict(preset)
        Window.clearcolor = tuple(app.theme['bg_color'])
        app.save_theme()
        self._build_color_rows()

    def save_settings(self):
        app = App.get_running_app()
        new_theme = dict(app.theme)
        for key, inp in self._color_inputs.items():
            try:
                alpha = app.theme.get(key, [1, 1, 1, 1])[3]
                new_theme[key] = hex_to_rgba(inp.text, alpha=alpha)
            except Exception:
                pass
        app.theme = new_theme
        Window.clearcolor = tuple(app.theme['bg_color'])
        app.save_theme()
        show_msg("Настройки", "Тема сохранена!")


# ==================== APP ====================

class SCMessApp(App):
    theme = DEFAULT_THEME.copy()

    def build(self):
        if platform == 'android':
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
            except Exception:
                pass

        self.dev_mode = False
        self.action_log = []

        self.backend = CryptoBackend(self.user_data_dir)

        global SETTINGS_FILE
        SETTINGS_FILE = os.path.join(self.user_data_dir, "settings.json")
        self.load_theme()

        Builder.load_string(KV)

        sm = ScreenManager()
        sm.add_widget(MenuScreen(name='menu'))
        sm.add_widget(KeysScreen(name='keys'))
        sm.add_widget(TextScreen(name='text'))
        sm.add_widget(FileScreen(name='files'))
        sm.add_widget(GroupScreen(name='group'))
        sm.add_widget(SettingsScreen(name='settings'))

        return sm

    def load_theme(self):
        try:
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r') as f:
                    data = json.load(f)
                if 'theme' in data:
                    loaded = data['theme']
                    # Merge with default to avoid missing keys
                    merged = dict(DEFAULT_THEME)
                    merged.update(loaded)
                    self.theme = merged
                    Window.clearcolor = tuple(self.theme['bg_color'])
        except Exception:
            self.theme = dict(DEFAULT_THEME)

    def save_theme(self):
        try:
            data = {}
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                try:
                    with open(SETTINGS_FILE, 'r') as f:
                        data = json.load(f)
                except Exception:
                    data = {}
            data['theme'] = self.theme
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            pass

    def log_action(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.action_log.append(entry)
        if len(self.action_log) > 200:
            self.action_log.pop(0)


if __name__ == '__main__':
    SCMessApp().run()
