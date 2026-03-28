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

from kivy.core.text import LabelBase
if os.path.exists('/system/fonts/NotoColorEmoji.ttf'):
    LabelBase.register(name='EmojiFont', fn_regular='/system/fonts/NotoColorEmoji.ttf')

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
from kivy.clock import Clock
from kivy.utils import platform

# Импорты для Java-моста
if platform == 'android':
    from android import activity
    from jnius import autoclass, cast

Window.clearcolor = (0, 0, 0, 1)

# ==================== KV ====================
KV = '''
<AMOLEDButton@Button>:
    background_normal: ''
    background_color: 0.1, 0.1, 0.1, 1
    color: 1, 1, 1, 1
    canvas.before:
        Color:
            rgba: 0.3, 0.5, 0.8, 1
        Line:
            width: 1.2
            rectangle: self.x, self.y, self.width, self.height

<AMOLEDTextInput@TextInput>:
    background_color: 0.05, 0.05, 0.05, 1
    foreground_color: 1, 1, 1, 1
    cursor_color: 0.3, 0.5, 0.8, 1
    font_size: '16sp'

<MenuScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 15
        Label:
            id: app_title
            text: 'SCmess (RSA + AES-GCM)'
            font_size: '24sp'
            size_hint_y: 0.18
            color: 0.3, 0.6, 1, 1
            on_touch_down: root.title_tapped(self, args[1])
        AMOLEDButton:
            text: 'Ключи и Пользователи'
            on_release: root.manager.current = 'keys'
        AMOLEDButton:
            text: 'Шифрование Текста'
            on_release: root.manager.current = 'text'
        AMOLEDButton:
            text: 'Шифрование Файлов'
            on_release: root.manager.current = 'files'
        AMOLEDButton:
            text: 'Групповой Чат'
            on_release: root.manager.current = 'group'
        BoxLayout:
            size_hint_y: 0.12
            spacing: 10
            AMOLEDButton:
                text: 'Помощь'
                on_release: root.show_help()
            AMOLEDButton:
                text: 'Логи'
                on_release: root.show_logs()
                opacity: 1 if app.dev_mode else 0
                disabled: not app.dev_mode

<TextScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 10
        Spinner:
            id: user_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: 0.15, 0.15, 0.15, 1
            size_hint_y: 0.1
        BoxLayout:
            size_hint_y: 0.08
            spacing: 10
            Label:
                text: 'Авто-копировать в буфер'
                size_hint_x: 0.75
            Switch:
                id: auto_copy_switch
                active: True
        AMOLEDTextInput:
            id: text_input
            hint_text: 'Введите текст для шифровки или вставьте JSON для расшифровки'
        BoxLayout:
            size_hint_y: 0.15
            spacing: 10
            AMOLEDButton:
                text: 'Зашифровать'
                on_release: root.encrypt_action()
            AMOLEDButton:
                text: 'Расшифровать'
                on_release: root.decrypt_action()
        AMOLEDButton:
            text: 'Назад'
            size_hint_y: 0.1
            on_release: root.manager.current = 'menu'

<FileScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 10
        Spinner:
            id: user_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: 0.15, 0.15, 0.15, 1
            size_hint_y: 0.1
        BoxLayout:
            size_hint_y: 0.08
            spacing: 10
            Label:
                text: 'Android Document UI'
                size_hint_x: 0.65
            Switch:
                id: native_switch
                active: app.use_native_picker
        Label:
            id: file_label
            text: 'Файл не выбран'
            size_hint_y: 0.1
        AMOLEDButton:
            text: 'Выбрать файл'
            size_hint_y: 0.15
            on_release: root.choose_file()
        BoxLayout:
            size_hint_y: 0.15
            spacing: 10
            AMOLEDButton:
                text: 'Зашифровать'
                on_release: root.encrypt_file()
            AMOLEDButton:
                text: 'Расшифровать'
                on_release: root.decrypt_file()
        AMOLEDButton:
            text: 'Назад'
            size_hint_y: 0.1
            on_release: root.manager.current = 'menu'

<GroupScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 10
        Label:
            text: 'Групповой чат (отметьте получателей)'
            size_hint_y: 0.1
        ScrollView:
            size_hint_y: 0.3
            BoxLayout:
                id: group_users_layout
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
        AMOLEDTextInput:
            id: group_input
            hint_text: 'Текст для шифровки ИЛИ полученный JSON для расшифровки'
        BoxLayout:
            size_hint_y: 0.15
            spacing: 10
            AMOLEDButton:
                text: 'Зашифровать'
                on_release: root.encrypt_group()
            AMOLEDButton:
                text: 'Расшифровать'
                on_release: root.decrypt_group()
        AMOLEDButton:
            text: 'Назад'
            size_hint_y: 0.1
            on_release: root.manager.current = 'menu'

<KeysScreen>:
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 10
        Label:
            text: 'Управление ключами'
            size_hint_y: 0.08
        AMOLEDButton:
            text: 'Сгенерировать свои ключи'
            size_hint_y: 0.12
            on_release: root.generate_keys_dialog()
        Label:
            text: 'Добавить друга'
            font_size: '16sp'
            color: 0.3, 0.6, 1, 1
            size_hint_y: 0.06
        BoxLayout:
            size_hint_y: 0.12
            spacing: 5
            AMOLEDButton:
                text: 'Из файла'
                on_release: root.add_key_dialog()
            AMOLEDButton:
                text: 'Текстом'
                on_release: root.add_key_text_dialog()
        Label:
            text: 'Нажмите на пользователя для управления:'
            font_size: '12sp'
            size_hint_y: 0.05
            color: 0.5, 0.5, 0.5, 1
        ScrollView:
            BoxLayout:
                id: users_list
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                spacing: 5
        AMOLEDButton:
            text: 'Назад'
            size_hint_y: 0.12
            on_release: root.manager.current = 'menu'
'''

def show_msg(title, text):
    popup = Popup(title=title, content=Label(text=text, text_size=(400, None)), size_hint=(0.85, 0.5))
    popup.open()


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
                        except:
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

    # === Шифрование ===
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
            out_path = file_path[:-4]          # ← оригинальное расширение
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
                status = "✅ ВКЛЮЧЁН" if app.dev_mode else "❌ ВЫКЛЮЧЕН"
                show_msg("Режим разработчика", f"Режим разработчика {status}\nПовтори 10 нажатий для смены.")
                self.taps = 0

    def show_help(self):
        help_text = (
            "Как начать:\n\n"
            "1. Ключи и Пользователи → Сгенерировать свои ключи\n"
            "2. Добавь друзей (Из файла / Текстом)\n"
            "3. В шифровании текста можно включить авто-копирование\n"
            "4. В файлах можно переключать обычный выбор ↔ Android Document UI\n"
            "Эмодзи теперь отображаются корректно (используется Roboto)"
        )
        popup = Popup(title="Помощь", content=Label(text=help_text, text_size=(380, None)), size_hint=(0.9, 0.75))
        popup.open()

    def show_logs(self):
        app = App.get_running_app()
        if not app.action_log:
            content = Label(text="Логов пока нет")
        else:
            content = ScrollView()
            box = BoxLayout(orientation='vertical', size_hint_y=None, height=len(app.action_log) * 35)
            for line in reversed(app.action_log):
                box.add_widget(Label(text=line, size_hint_y=None, height=35, halign='left'))
            content.add_widget(box)
        popup = Popup(title="Логи приложения (dev mode)", content=content, size_hint=(0.95, 0.85))
        popup.open()


class KeysScreen(Screen):
    def on_enter(self):
        self.refresh_users()

    def refresh_users(self):
        backend = App.get_running_app().backend
        users = backend.load_users()
        layout = self.ids.users_list
        layout.clear_widgets()
        for u in users:
            text = f"{u['username']}\n[Pub: {'OK' if u.get('public_key_path') else '--'} | Priv: {'OK' if u.get('private_key_path') else '--'}]"
            btn = Button(text=text, size_hint_y=None, height=75, background_color=(0.12, 0.12, 0.12, 1))
            btn.bind(on_release=lambda x, user=u: self.show_user_options(user))
            layout.add_widget(btn)

    def show_user_options(self, user):
        app = App.get_running_app()
        box = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Публичный ключ
        pub_text = "Публичный ключ отсутствует"
        if user.get('public_key_path') and os.path.exists(user['public_key_path']):
            with open(user['public_key_path'], 'r') as f:
                pub_text = f.read()

        pub_view = TextInput(text=pub_text, readonly=True, background_color=(0,0,0,1),
                             foreground_color=(0.3,0.6,1,1), font_size='10sp', size_hint_y=0.4)

        copy_pub = Button(text="Копировать публичный ключ", size_hint_y=0.1)

        # Приватный ключ — только в dev-режиме
        if app.dev_mode and user.get('private_key_path') and os.path.exists(user['private_key_path']):
            with open(user['private_key_path'], 'r') as f:
                priv_text = f.read()
            priv_view = TextInput(text=priv_text, readonly=True, background_color=(0.1,0,0,1),
                                  foreground_color=(1,0.3,0.3,1), font_size='10sp', size_hint_y=0.3)
            copy_priv = Button(text="Копировать приватный ключ (ОПАСНО!)", size_hint_y=0.1,
                               background_color=(0.8,0.2,0.2,1))
            box.add_widget(Label(text="🔑 ПРИВАТНЫЙ КЛЮЧ (dev mode)", size_hint_y=0.05))
            box.add_widget(priv_view)
            box.add_widget(copy_priv)
            def copy_priv_key(_): Clipboard.copy(priv_text); show_msg("Скопировано", "Приватный ключ в буфере")
            copy_priv.bind(on_release=copy_priv_key)

        box.add_widget(Label(text=f"Пользователь: {user['username']}", size_hint_y=0.08))
        box.add_widget(pub_view)
        box.add_widget(copy_pub)
        del_btn = Button(text="Удалить пользователя", size_hint_y=0.1, background_color=(0.8,0.2,0.2,1))

        box.add_widget(del_btn)

        popup = Popup(title="Управление пользователем", content=box, size_hint=(0.9, 0.9))

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
        box = BoxLayout(orientation='vertical', spacing=10, padding=10)
        inp = TextInput(hint_text="Имя пользователя", size_hint_y=None, height='50dp',
                        background_color=(0.1,0.1,0.1,1), foreground_color=(1,1,1,1))
        spinner = Spinner(text='4096', values=('2048', '4096'), size_hint_y=None, height='50dp',
                          background_color=(0.15, 0.15, 0.15, 1))
        btn = Button(text="Создать", background_color=(0.2,0.4,0.8,1), size_hint_y=None, height='60dp')

        box.add_widget(inp)
        box.add_widget(Label(text="Размер RSA ключа (бит):", size_hint_y=None, height='30dp'))
        box.add_widget(spinner)
        box.add_widget(btn)

        popup = Popup(title="Генерация ключей", content=box, size_hint=(0.8, 0.55))

        def on_create(instance):
            if not inp.text.strip(): return
            size = int(spinner.text)
            wait_popup = Popup(title="Генерация...", content=Label(text=f"Создаём {size}-бит ключи...\nПодождите"),
                               size_hint=(0.8, 0.4), auto_dismiss=False)
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
        btn = Button(text="Выбрать как публичный", size_hint_y=0.15)
        box.add_widget(btn)
        popup = Popup(title="Выбор файла ключа", content=box, size_hint=(0.9, 0.9))

        def on_select(instance):
            if chooser.selection:
                path = chooser.selection[0]
                name_box = BoxLayout(orientation='vertical', padding=10)
                name_inp = TextInput(hint_text="Имя владельца", size_hint_y=0.6)
                ok_btn = Button(text="Сохранить", size_hint_y=0.4)
                name_box.add_widget(name_inp)
                name_box.add_widget(ok_btn)
                name_popup = Popup(title="Имя пользователя", content=name_box, size_hint=(0.7, 0.3))

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
        box = BoxLayout(orientation='vertical', spacing=10, padding=10)
        inp_name = TextInput(hint_text="Имя пользователя", size_hint_y=None, height='50dp',
                             background_color=(0.1,0.1,0.1,1), foreground_color=(1,1,1,1))
        inp_key = TextInput(hint_text="Вставьте PEM ключ сюда...",
                            background_color=(0.1,0.1,0.1,1), foreground_color=(1,1,1,1))
        btn = Button(text="Сохранить как публичный", size_hint_y=None, height='60dp',
                     background_color=(0.3, 0.5, 0.8, 1))

        box.add_widget(inp_name)
        box.add_widget(inp_key)
        box.add_widget(btn)

        popup = Popup(title="Импорт ключа текстом", content=box, size_hint=(0.9, 0.75))

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

    def encrypt_action(self):
        username = self.ids.user_spinner.text
        text = self.ids.text_input.text.strip()
        if not text or username == 'Выберите пользователя':
            return
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "У пользователя нет публичного ключа!")
            return
        try:
            res = backend.encrypt_text_gcm(user['public_key_path'], text)
            self.ids.text_input.text = res
            Clipboard.copy(res)
            show_msg("Успех", "Текст зашифрован и скопирован в буфер!")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def decrypt_action(self):
        username = self.ids.user_spinner.text
        text = self.ids.text_input.text.strip()
        if not text or username == 'Выберите пользователя':
            return
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа для этого пользователя!")
            return
        try:
            res = backend.decrypt_text_gcm(user['private_key_path'], text)
            self.ids.text_input.text = res
            show_msg("Успех", "Текст расшифрован")
        except Exception as e:
            show_msg("Ошибка расшифровки", str(e))


class FileScreen(Screen):
    selected_file = None

    def on_enter(self):
        users = App.get_running_app().backend.load_users()
        self.ids.user_spinner.values = [u['username'] for u in users if u.get('public_key_path')]

    def choose_file(self):
        app = App.get_running_app()
        if platform == 'android' and self.ids.native_switch.active:
            self.open_native_android_picker()
        else:
            # обычный Kivy-выбор
            storage_path = '/storage/emulated/0/Download' if platform == 'android' else os.path.expanduser('~')
            chooser = FileChooserListView(path=storage_path)
            box = BoxLayout(orientation='vertical')
            box.add_widget(chooser)
            btn = Button(text="Выбрать", size_hint_y=0.15)
            box.add_widget(btn)
            popup = Popup(title="Выбор файла (Kivy)", content=box, size_hint=(0.9, 0.9))

            def on_select(instance):
                if chooser.selection:
                    self.selected_file = chooser.selection[0]
                    self.ids.file_label.text = os.path.basename(self.selected_file)
                popup.dismiss()
            btn.bind(on_release=on_select)
            popup.open()

    def open_native_android_picker(self):
        try:
            from jnius import autoclass
            Intent = autoclass('android.content.Intent')
            PythonActivity = autoclass('org.kivy.android.PythonActivity')

            intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            intent.setType("*/*")                     # любой файл
            PythonActivity.mActivity.startActivityForResult(intent, 1234)  # request code

            show_msg("Android Document UI", "Открыт системный выбор файлов Android.\n\n"
                                            "Результат пока не обрабатывается автоматически.\n"
                                            "Выбранный файл нужно будет указать вручную или доработать on_activity_result.")
            # Примечание: полная обработка результата требует добавления on_activity_result в SCMessApp
        except Exception as e:
            show_msg("Ошибка запуска Document UI", str(e))

    def encrypt_file(self):
        if not self.selected_file: return
        user = next((u for u in App.get_running_app().backend.load_users()
                     if u['username'] == self.ids.user_spinner.text), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "Нет публичного ключа!")
            return
        try:
            out = App.get_running_app().backend.encrypt_file_gcm(user['public_key_path'], self.selected_file)
            show_msg("Успех", f"Файл зашифрован!\nСохранён как:\n{out}")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def decrypt_file(self):
        if not self.selected_file: return
        user = next((u for u in App.get_running_app().backend.load_users()
                     if u['username'] == self.ids.user_spinner.text), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа!")
            return
        try:
            out = App.get_running_app().backend.decrypt_file_gcm(user['private_key_path'], self.selected_file)
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
        for u in users:
            if u.get('public_key_path'):
                row = BoxLayout(size_hint_y=None, height=45)
                chk = CheckBox(size_hint_x=0.2, color=[0.3, 0.6, 1, 1])
                lbl = Label(text=u['username'], size_hint_x=0.8)
                row.add_widget(chk)
                row.add_widget(lbl)
                layout.add_widget(row)
                self.checkboxes[u['username']] = chk

    def encrypt_group(self):
        text = self.ids.group_input.text.strip()
        if not text: return

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
        if not text: return
        try:
            res = App.get_running_app().backend.decrypt_group(text)
            self.ids.group_input.text = res
            show_msg("Успех", "Сообщение расшифровано")
            App.get_running_app().log_action("Выполнена групповая расшифровка")
        except Exception as e:
            show_msg("Ошибка расшифровки", str(e))


class SCMessApp(App):
    def build(self):
        if platform == 'android':
            from android.permissions import request_permissions, Permission
            request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])

        self.dev_mode = False
        self.action_log = []
        self.use_native_picker = False      # по умолчанию Kivy-выбор
        self.auto_copy_text = True          # авто-копирование включено по умолчанию

        self.backend = CryptoBackend(self.user_data_dir)
        Builder.load_string(KV)

        sm = ScreenManager()
        sm.add_widget(MenuScreen(name='menu'))
        sm.add_widget(KeysScreen(name='keys'))
        sm.add_widget(TextScreen(name='text'))
        sm.add_widget(FileScreen(name='files'))
        sm.add_widget(GroupScreen(name='group'))

        return sm

    def log_action(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.action_log.append(entry)
        if len(self.action_log) > 150:
            self.action_log.pop(0)

if __name__ == '__main__':
    SCMessApp().run()
