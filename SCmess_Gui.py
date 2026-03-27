import sys
import os
import json
import base64
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                               QPushButton, QTextEdit, QLineEdit, QLabel, QCheckBox, QFileDialog,
                               QMessageBox, QInputDialog, QComboBox, QDialog, QListWidget,
                               QListWidgetItem, QDialogButtonBox, QHBoxLayout)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = "config.json"
KEYS_FILE = "keys.json"

class SCMessGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SCmess - Multi-Recipient")
        self.setGeometry(100, 100, 900, 700)

        # Загрузка конфигурации
        self.load_config()

        # Создание вкладок
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Инициализация вкладок
        self.init_tabs()
        self.init_keys_tab()
        self.init_text_tab()
        self.init_files_tab()
        self.init_group_tab() # Новая вкладка группы
        self.init_settings_tab()
        self.init_info_tab()

        # Применение темы из конфигурации
        self.apply_theme(config.get("theme", "system"))

    def load_config(self):
        """Загрузка или создание файла конфигурации."""
        global config
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                try:
                    config = json.load(f)
                except json.JSONDecodeError:
                    config = {"legacy_mode": False, "pqc_mode": False, "theme": "system"}
        else:
            config = {"legacy_mode": False, "pqc_mode": False, "theme": "system"}
        self.save_config()

        if not os.path.exists(KEYS_FILE):
            with open(KEYS_FILE, 'w') as f:
                json.dump([], f)

    def save_config(self):
        """Сохранение конфигурации."""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)

    def init_tabs(self):
        """Создание вкладок."""
        self.keys_tab = QWidget()
        self.text_tab = QWidget()
        self.files_tab = QWidget()
        self.group_tab = QWidget() # Инициализация
        self.settings_tab = QWidget()
        self.info_tab = QWidget()

        self.keys_layout = QVBoxLayout()
        self.text_layout = QVBoxLayout()
        self.files_layout = QVBoxLayout()
        self.group_layout = QVBoxLayout() # Макет
        self.settings_layout = QVBoxLayout()
        self.info_layout = QVBoxLayout()

        self.keys_tab.setLayout(self.keys_layout)
        self.text_tab.setLayout(self.text_layout)
        self.files_tab.setLayout(self.files_layout)
        self.group_tab.setLayout(self.group_layout)
        self.settings_tab.setLayout(self.settings_layout)
        self.info_tab.setLayout(self.info_layout)

        self.tabs.addTab(self.keys_tab, "Ключи")
        self.tabs.addTab(self.text_tab, "Текст")
        self.tabs.addTab(self.files_tab, "Файлы")
        self.tabs.addTab(self.group_tab, "Группа") # Добавление в интерфейс
        self.tabs.addTab(self.settings_tab, "Настройки")
        self.tabs.addTab(self.info_tab, "Информация")

    # ========================== ВКЛАДКА КЛЮЧИ ==========================
    def init_keys_tab(self):
        self.create_keys_btn = QPushButton("Создать пару ключей")
        self.add_key_btn = QPushButton("Добавить ключ")
        self.show_users_btn = QPushButton("Показать пользователей")
        self.delete_user_btn = QPushButton("Удалить пользователя")
        self.autoscan_keys_btn = QPushButton("Автоскан ключей")
        self.toggle_user_interaction_btn = QPushButton("Вкл/выкл взаимодействие с ключом")

        self.create_keys_btn.clicked.connect(self.create_keys)
        self.add_key_btn.clicked.connect(self.add_key)
        self.show_users_btn.clicked.connect(self.show_users)
        self.delete_user_btn.clicked.connect(self.delete_user)
        self.autoscan_keys_btn.clicked.connect(self.autoscan_keys)
        self.toggle_user_interaction_btn.clicked.connect(self.toggle_user_interaction)

        self.keys_layout.addWidget(self.create_keys_btn)
        self.keys_layout.addWidget(self.add_key_btn)
        self.keys_layout.addWidget(self.show_users_btn)
        self.keys_layout.addWidget(self.delete_user_btn)
        self.keys_layout.addWidget(self.autoscan_keys_btn)
        self.keys_layout.addWidget(self.toggle_user_interaction_btn)
        self.keys_layout.addStretch()

    # ========================== ВКЛАДКА ТЕКСТ ==========================
    def init_text_tab(self):
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Введите текст для шифрования/расшифровки...")
        self.text_layout.addWidget(self.text_input)

        self.encrypt_gcm_btn = QPushButton("Зашифровать текст (AES-GCM)")
        self.decrypt_gcm_btn = QPushButton("Расшифровать текст (AES-GCM)")
        self.encrypt_gcm_btn.clicked.connect(self.encrypt_text_gcm)
        self.decrypt_gcm_btn.clicked.connect(self.decrypt_text_gcm)
        self.text_layout.addWidget(self.encrypt_gcm_btn)
        self.text_layout.addWidget(self.decrypt_gcm_btn)

        self.update_text_tab_buttons()

    # ========================== ВКЛАДКА ФАЙЛЫ ==========================
    def init_files_tab(self):
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Выберите файл...")
        self.select_file_btn = QPushButton("Выбрать файл")
        self.select_file_btn.clicked.connect(self.select_file)

        self.files_layout.addWidget(self.file_path_input)
        self.files_layout.addWidget(self.select_file_btn)

        self.encrypt_file_gcm_btn = QPushButton("Зашифровать файл (AES-GCM)")
        self.decrypt_file_gcm_btn = QPushButton("Расшифровать файл (AES-GCM)")
        self.encrypt_file_gcm_btn.clicked.connect(self.encrypt_file_gcm)
        self.decrypt_file_gcm_btn.clicked.connect(self.decrypt_file_gcm)
        self.files_layout.addWidget(self.encrypt_file_gcm_btn)
        self.files_layout.addWidget(self.decrypt_file_gcm_btn)

        self.update_files_tab_buttons()

    # ========================== НОВАЯ ВКЛАДКА ГРУППЫ ==========================
    def init_group_tab(self):
        """Инициализация вкладки 'Группа' для мульти-шифрования."""
        # Верхняя панель: список получателей
        self.group_users_label = QLabel("Выберите получателей (с включенными публичными ключами):")
        self.group_users_list = QListWidget()
        self.refresh_group_btn = QPushButton("Обновить список пользователей")
        self.refresh_group_btn.clicked.connect(self.refresh_group_users)
        
        # Средняя панель: Ввод/Вывод
        self.group_input = QTextEdit()
        self.group_input.setPlaceholderText("Введи текст для зашифровки (для выбранных друзей) ИЛИ вставь сюда полученный зашифрованный JSON...")
        
        # Кнопки действий
        btn_layout = QHBoxLayout()
        self.encrypt_group_btn = QPushButton("Зашифровать для выбранных (AES-GCM + RSA)")
        self.decrypt_group_btn = QPushButton("Расшифровать сообщение")
        
        self.encrypt_group_btn.clicked.connect(self.encrypt_group_message)
        self.decrypt_group_btn.clicked.connect(self.decrypt_group_message)
        
        btn_layout.addWidget(self.encrypt_group_btn)
        btn_layout.addWidget(self.decrypt_group_btn)

        # Сборка интерфейса вкладки
        self.group_layout.addWidget(self.group_users_label)
        self.group_layout.addWidget(self.group_users_list)
        self.group_layout.addWidget(self.refresh_group_btn)
        self.group_layout.addWidget(QLabel("Сообщение / Зашифрованный JSON:"))
        self.group_layout.addWidget(self.group_input)
        self.group_layout.addLayout(btn_layout)

        # При открытии вкладки обновляем список
        self.tabs.currentChanged.connect(self.on_tab_changed)

    def on_tab_changed(self, index):
        if self.tabs.widget(index) == self.group_tab:
            self.refresh_group_users()

    def refresh_group_users(self):
        """Обновляет список пользователей во вкладке группы."""
        self.group_users_list.clear()
        try:
            with open(KEYS_FILE, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        for entry in data:
            if entry.get("public_key_path") and entry.get('enabled', True):
                item = QListWidgetItem(entry['username'])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Unchecked)
                # Сохраняем путь к ключу в данных элемента
                item.setData(Qt.UserRole, entry['public_key_path'])
                self.group_users_list.addItem(item)

    def encrypt_group_message(self):
        """Шифрует сообщение для всех выбранных пользователей."""
        text = self.group_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования.")
            return

        selected_users = []
        for i in range(self.group_users_list.count()):
            item = self.group_users_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_users.append({
                    "username": item.text(),
                    "pub_key": item.data(Qt.UserRole)
                })

        if not selected_users:
            QMessageBox.warning(self, "Ошибка", "Выберите хотя бы одного получателя.")
            return

        # 1. Генерируем единый ключ AES для этого сообщения
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()

        # 2. Шифруем AES ключ публичным RSA-ключом каждого получателя
        encrypted_keys = {}
        for user in selected_users:
            try:
                with open(user['pub_key'], 'rb') as f:
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
                QMessageBox.warning(self, "Внимание", f"Не удалось зашифровать для {user['username']}: {str(e)}")

        if not encrypted_keys:
            QMessageBox.critical(self, "Ошибка", "Не удалось зашифровать ключ ни для одного получателя.")
            return

        # 3. Формируем итоговый JSON пакет
        payload = {
            "type": "group_message_gcm",
            "iv": base64.b64encode(iv).decode('utf-8'),
            "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "keys": encrypted_keys
        }

        self.group_input.setText(json.dumps(payload, indent=4))
        QMessageBox.information(self, "Успех", f"Сообщение зашифровано для {len(encrypted_keys)} получателей.")

    def decrypt_group_message(self):
        """Расшифровывает групповое сообщение, если у нас есть подходящий приватный ключ."""
        text = self.group_input.toPlainText()
        try:
            payload = json.loads(text)
            if payload.get("type") != "group_message_gcm":
                raise ValueError("Неверный формат сообщения")
        except Exception:
            QMessageBox.warning(self, "Ошибка", "Некорректный JSON пакет группового сообщения.")
            return

        # Загружаем наши доступные приватные ключи
        try:
            with open(KEYS_FILE, 'r') as f:
                data = json.load(f)
        except Exception:
            data = []

        my_private_keys = {
            entry['username']: entry['private_key_path'] 
            for entry in data 
            if entry.get("private_key_path") and entry.get('enabled', True)
        }

        if not my_private_keys:
            QMessageBox.warning(self, "Ошибка", "У вас нет настроенных приватных ключей для расшифровки.")
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
            QMessageBox.critical(self, "Ошибка доступа", "Это сообщение не предназначалось ни одному из ваших пользователей, или имена не совпадают.")
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
            
            self.group_input.setText(decrypted_bytes.decode('utf-8'))
            QMessageBox.information(self, "Успех", f"Расшифровано с помощью ключа профиля: {target_username}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка расшифровки", f"Произошла ошибка: {str(e)}")

    # ========================== ВКЛАДКА НАСТРОЙКИ И INFO ==========================
    def init_settings_tab(self):
        self.legacy_mode_cb = QCheckBox("Legacy-режим")
        self.pqc_mode_cb = QCheckBox("PQC-режим")
        self.legacy_mode_cb.setChecked(config.get("legacy_mode", False))
        self.pqc_mode_cb.setChecked(config.get("pqc_mode", False))
        self.legacy_mode_cb.stateChanged.connect(self.toggle_legacy_mode)
        self.pqc_mode_cb.stateChanged.connect(self.toggle_pqc_mode)

        self.settings_layout.addWidget(self.legacy_mode_cb)
        self.settings_layout.addWidget(self.pqc_mode_cb)

        self.theme_label = QLabel("Тема интерфейса:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Системная", "Светлая", "Тёмная"])
        current_theme = config.get("theme", "system")
        index_map = {"system": 0, "light": 1, "dark": 2}
        self.theme_combo.setCurrentIndex(index_map.get(current_theme, 0))
        self.theme_combo.currentIndexChanged.connect(self.on_theme_changed)

        self.settings_layout.addWidget(self.theme_label)
        self.settings_layout.addWidget(self.theme_combo)
        self.settings_layout.addStretch()

    def init_info_tab(self):
        self.show_info_btn = QPushButton("Показать информацию")
        self.show_info_btn.clicked.connect(self.show_info)
        self.info_layout.addWidget(self.show_info_btn)
        self.info_layout.addStretch()

    # ========================== МЕТОДЫ УПРАВЛЕНИЯ КЛЮЧАМИ ==========================
    def create_keys(self):
        username, ok = QInputDialog.getText(self, "Создать пару ключей", "Введите имя пользователя:")
        if ok and username:
            priv_filename, pub_filename = self.generate_key_pair(username)
            self.save_keys_to_json(username, pub_filename, priv_filename)
            QMessageBox.information(self, "Успех", f"Ключи созданы:\nПриватный: {priv_filename}\nПубличный: {pub_filename}")
            if self.tabs.currentWidget() == self.group_tab:
                self.refresh_group_users()

    def add_key(self):
        username, ok = QInputDialog.getText(self, "Добавить ключ", "Введите имя пользователя:")
        if not ok or not username:
            return
        key_type, ok = QInputDialog.getItem(self, "Тип ключа", "Выберите тип ключа:", ["public", "private"], 0, False)
        if not ok:
            return
        key_path, _ = QFileDialog.getOpenFileName(self, f"Выберите {key_type} ключ", "", "PEM Files (*.pem)")
        if key_path:
            self.add_friend_key(username, key_path, key_type)
            QMessageBox.information(self, "Успех", f"{key_type.capitalize()} ключ для '{username}' добавлен.")
            if self.tabs.currentWidget() == self.group_tab:
                self.refresh_group_users()

    def show_users(self):
        with open(KEYS_FILE, 'r') as f:
            data = json.load(f)
        if not data:
            QMessageBox.information(self, "Пользователи", "Список пользователей пуст.")
            return
        users_info = "Список пользователей:\n"
        for entry in data:
            pub = entry.get('public_key_path', 'Не указан')
            priv = entry.get('private_key_path', 'Не указан')
            enabled = entry.get('enabled', True)
            status = 'включен' if enabled else 'выключен'
            users_info += f"Имя: {entry['username']}, Статус: {status}, Публичный: {pub}, Приватный: {priv}\n"
        QMessageBox.information(self, "Пользователи", users_info)

    def delete_user(self):
        with open(KEYS_FILE, 'r') as f:
            data = json.load(f)
        if not data:
            QMessageBox.information(self, "Удаление", "Список пользователей пуст.")
            return
        usernames = [entry['username'] for entry in data]
        username, ok = QInputDialog.getItem(self, "Удалить пользователя", "Выберите пользователя для удаления:", usernames, 0, False)
        if ok and username:
            self.delete_user_from_json(username)
            QMessageBox.information(self, "Успех", f"Пользователь '{username}' удалён.")
            if self.tabs.currentWidget() == self.group_tab:
                self.refresh_group_users()

    def autoscan_keys(self):
        key_type, ok = QInputDialog.getItem(self, "Тип ключа", "Выберите тип ключа для сканирования:", ["public", "private"], 0, False)
        if not ok:
            return
        found_keys = self.scan_for_keys(key_type)
        if not found_keys:
            QMessageBox.information(self, "Результат", f"Новые {key_type} ключи не найдены.")
            return
        selected_indices = self.show_checkbox_selection_dialog(
            title=f"Найденные {key_type} ключи",
            items=found_keys
        )
        if selected_indices is None:
            return
        added_any = False
        for idx in selected_indices:
            if 0 <= idx < len(found_keys):
                username, ok = QInputDialog.getText(self, "Имя пользователя", f"Введите имя для ключа {found_keys[idx]}:")
                if ok and username:
                    self.add_friend_key(username, found_keys[idx], key_type)
                    added_any = True
        if added_any:
            QMessageBox.information(self, "Успех", "Выбранные ключи добавлены.")
            if self.tabs.currentWidget() == self.group_tab:
                self.refresh_group_users()
        else:
            QMessageBox.information(self, "Результат", "Ключи не были добавлены.")

    def show_checkbox_selection_dialog(self, title, items):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        layout = QVBoxLayout(dialog)

        list_widget = QListWidget(dialog)
        for text in items:
            item = QListWidgetItem(text)
            item.setCheckState(Qt.Unchecked)
            list_widget.addItem(item)
        layout.addWidget(list_widget)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, parent=dialog)
        layout.addWidget(button_box)

        def accept(): dialog.accept()
        def reject(): dialog.reject()

        button_box.accepted.connect(accept)
        button_box.rejected.connect(reject)

        if dialog.exec() == QDialog.Accepted:
            selected = []
            for i in range(list_widget.count()):
                if list_widget.item(i).checkState() == Qt.Checked:
                    selected.append(i)
            return selected
        return None

    # ========================== БАЗОВЫЕ МЕТОДЫ ШИФРОВАНИЯ ТЕКСТА ==========================
    def encrypt_text_gcm(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования.")
            return
        public_key_path = self.get_user_to_encrypt()
        if public_key_path:
            encrypted_data = self.encrypt_text_gcm_backend(public_key_path, text)
            self.text_input.setText(str(encrypted_data))
            QMessageBox.information(self, "Успех", "Текст зашифрован (AES-GCM).")

    def decrypt_text_gcm(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите зашифрованный текст.")
            return
        private_key_path = self.get_user_to_decrypt()
        if private_key_path:
            try:
                encrypted_data = eval(text)
                decrypted_text = self.decrypt_text_gcm_backend(private_key_path, encrypted_data)
                self.text_input.setText(decrypted_text)
                QMessageBox.information(self, "Успех", "Текст расшифрован (AES-GCM).")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать: {str(e)}")

    # ========================== БАЗОВЫЕ МЕТОДЫ ШИФРОВАНИЯ ФАЙЛОВ ==========================
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.file_path_input.setText(file_path)

    def encrypt_file_gcm(self):
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Ошибка", "Выберите существующий файл.")
            return
        public_key_path = self.get_user_to_encrypt()
        if public_key_path:
            encrypted_file = self.encrypt_file_gcm_backend(public_key_path, file_path)
            QMessageBox.information(self, "Успех", f"Файл зашифрован (AES-GCM): {encrypted_file}")

    def decrypt_file_gcm(self):
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Ошибка", "Выберите существующий файл.")
            return
        private_key_path = self.get_user_to_decrypt()
        if private_key_path:
            decrypted_file = self.decrypt_file_gcm_backend(private_key_path, file_path)
            QMessageBox.information(self, "Успех", f"Файл расшифрован (AES-GCM): {decrypted_file}")

    # ========================== УПРАВЛЕНИЕ UI НАСТРОЙКАМИ ==========================
    def toggle_legacy_mode(self):
        config["legacy_mode"] = self.legacy_mode_cb.isChecked()
        self.save_config()
        self.update_text_tab_buttons()
        self.update_files_tab_buttons()

    def toggle_pqc_mode(self):
        config["pqc_mode"] = self.pqc_mode_cb.isChecked()
        self.save_config()
        self.update_text_tab_buttons()

    def update_text_tab_buttons(self):
        if hasattr(self, "encrypt_legacy_btn"):
            self.text_layout.removeWidget(self.encrypt_legacy_btn)
            self.encrypt_legacy_btn.deleteLater()
            self.text_layout.removeWidget(self.decrypt_legacy_btn)
            self.decrypt_legacy_btn.deleteLater()
        if hasattr(self, "encrypt_pqc_btn"):
            self.text_layout.removeWidget(self.encrypt_pqc_btn)
            self.encrypt_pqc_btn.deleteLater()
            self.text_layout.removeWidget(self.decrypt_pqc_btn)
            self.decrypt_pqc_btn.deleteLater()
            self.text_layout.removeWidget(self.encrypt_pqc_pass_btn)
            self.encrypt_pqc_pass_btn.deleteLater()
            self.text_layout.removeWidget(self.decrypt_pqc_pass_btn)
            self.decrypt_pqc_pass_btn.deleteLater()

        if config.get("legacy_mode", False):
            self.encrypt_legacy_btn = QPushButton("Зашифровать текст (Legacy RSA)")
            self.decrypt_legacy_btn = QPushButton("Расшифровать текст (Legacy RSA)")
            self.encrypt_legacy_btn.clicked.connect(self.encrypt_text_legacy)
            self.decrypt_legacy_btn.clicked.connect(self.decrypt_text_legacy)
            self.text_layout.addWidget(self.encrypt_legacy_btn)
            self.text_layout.addWidget(self.decrypt_legacy_btn)

        if config.get("pqc_mode", False):
            self.encrypt_pqc_btn = QPushButton("Зашифровать текст (Kyber + XChaCha20)")
            self.decrypt_pqc_btn = QPushButton("Расшифровать текст (Kyber + XChaCha20)")
            self.encrypt_pqc_pass_btn = QPushButton("Зашифровать текст (Kyber + XChaCha20) с паролем")
            self.decrypt_pqc_pass_btn = QPushButton("Расшифровать текст (Kyber + XChaCha20) с паролем")
            self.encrypt_pqc_btn.clicked.connect(self.encrypt_text_pqc)
            self.decrypt_pqc_btn.clicked.connect(self.decrypt_text_pqc)
            self.encrypt_pqc_pass_btn.clicked.connect(self.encrypt_text_pqc_pass)
            self.decrypt_pqc_pass_btn.clicked.connect(self.decrypt_text_pqc_pass)
            self.text_layout.addWidget(self.encrypt_pqc_btn)
            self.text_layout.addWidget(self.decrypt_pqc_btn)
            self.text_layout.addWidget(self.encrypt_pqc_pass_btn)
            self.text_layout.addWidget(self.decrypt_pqc_pass_btn)

        self.text_layout.addStretch()

    def update_files_tab_buttons(self):
        for btn in [self.encrypt_file_gcm_btn, self.decrypt_file_gcm_btn]:
            current_widgets = [self.files_layout.itemAt(i).widget() for i in range(self.files_layout.count()) if self.files_layout.itemAt(i).widget()]
            if btn not in current_widgets:
                self.files_layout.addWidget(btn)

        if hasattr(self, "encrypt_file_legacy_btn") and self.encrypt_file_legacy_btn is not None:
            self.files_layout.removeWidget(self.encrypt_file_legacy_btn)
            self.encrypt_file_legacy_btn.deleteLater()
            self.encrypt_file_legacy_btn = None

        if hasattr(self, "decrypt_file_legacy_btn") and self.decrypt_file_legacy_btn is not None:
            self.files_layout.removeWidget(self.decrypt_file_legacy_btn)
            self.decrypt_file_legacy_btn.deleteLater()
            self.decrypt_file_legacy_btn = None

        if config.get("legacy_mode", False):
            self.encrypt_file_legacy_btn = QPushButton("Зашифровать файл (Legacy RSA)")
            self.decrypt_file_legacy_btn = QPushButton("Расшифровать файл (Legacy RSA)")
            self.encrypt_file_legacy_btn.clicked.connect(self.encrypt_file_legacy)
            self.decrypt_file_legacy_btn.clicked.connect(self.decrypt_file_legacy)
            self.files_layout.addWidget(self.encrypt_file_legacy_btn)
            self.files_layout.addWidget(self.decrypt_file_legacy_btn)

        self.files_layout.addStretch()

    def show_info(self):
        info_text = """
        1. Сначала сгенерируйте ключи и отправьте публичный ключ другу.
        2. Используйте автоскан для поиска ключей или добавьте их вручную.
        3. Для шифрования текста рекомендуется AES-GCM (поддерживает до 64 ГБ).
        4. Для сброса удалите keys.json и ключи.
        5. GitHub: https://github.com/VLOD-ZDOV
        6. Версия: 5.4 + Group Chat
        """
        QMessageBox.information(self, "Информация", info_text)

    # ========================== БЭКЕНД: КЛЮЧИ ==========================
    def generate_key_pair(self, username):
        current_time = datetime.now().strftime("%Y%m%d%H%M%S")
        pub_dir = self.get_public_key_directory()
        priv_dir = self.get_private_key_directory()
        priv_filename = os.path.join(priv_dir, f"RSA_{username}_priv_{current_time}.pem")
        pub_filename = os.path.join(pub_dir, f"RSA_{username}_pub_{current_time}.pem")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        with open(priv_filename, 'wb') as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.PKCS8,
                                             encryption_algorithm=serialization.NoEncryption()))
        public_key = private_key.public_key()
        with open(pub_filename, 'wb') as f:
            f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        return priv_filename, pub_filename

    def get_private_key_directory(self):
        if os.name == 'nt':
            return os.path.expanduser("~")
        elif 'ANDROID_ROOT' in os.environ:
            return '/data/data/com.termux/files/home'
        else:
            return os.path.expanduser("~")

    def get_public_key_directory(self):
        if os.name == 'nt':
            return os.path.join(os.environ['USERPROFILE'], 'Downloads')
        elif 'ANDROID_ROOT' in os.environ:
            return '/sdcard/'
        else:
            return os.path.expanduser("~")

    def save_keys_to_json(self, username, pub_filename, priv_filename):
        key_data = {"username": username, "public_key_path": pub_filename, "private_key_path": priv_filename, "enabled": True}
        with open(KEYS_FILE, 'r+') as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
            except json.JSONDecodeError:
                data = []
            data.append(key_data)
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()

    def add_friend_key(self, username, key_path, key_type):
        with open(KEYS_FILE, 'r+') as f:
            data = json.load(f)
            user_entry = next((entry for entry in data if entry['username'] == username), None)
            if not user_entry:
                user_entry = {'username': username, 'enabled': True}
                data.append(user_entry)
            user_entry[f"{key_type}_key_path"] = key_path
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()

    def delete_user_from_json(self, username):
        with open(KEYS_FILE, 'r+') as f:
            data = json.load(f)
            data = [entry for entry in data if entry["username"] != username]
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()

    def scan_for_keys(self, key_type):
        SEARCH_DIRECTORIES = [os.path.expanduser("~"), os.path.expanduser("~/Downloads"),
                              os.path.expanduser("~/Desktop"), os.path.expanduser("~/Documents")]
        with open(KEYS_FILE, 'r') as f:
            data = json.load(f)
            existing_keys = {entry.get(f'{key_type}_key_path') for entry in data if entry.get(f'{key_type}_key_path')}

        found_keys = set()
        for dir_path in SEARCH_DIRECTORIES:
            if os.path.exists(dir_path):
                for root, _, files in os.walk(dir_path):
                    for filename in files:
                        key_path = os.path.join(root, filename)
                        if key_type == 'public' and filename.startswith("RSA_") and "_pub_" in filename and filename.endswith('.pem'):
                            if key_path not in existing_keys:
                                found_keys.add(key_path)
                        elif key_type == 'private' and filename.startswith("RSA_") and "_priv_" in filename and filename.endswith('.pem'):
                            if key_path not in existing_keys:
                                found_keys.add(key_path)
        return list(found_keys)

    def get_user_to_encrypt(self):
        with open(KEYS_FILE, 'r') as f:
            data = json.load(f)
            valid_users = [entry for entry in data if entry.get("public_key_path") and entry.get('enabled', True)]
        if not valid_users:
            QMessageBox.warning(self, "Ошибка", "Нет доступных пользователей с включённым публичным ключом.")
            return None
        usernames = [entry['username'] for entry in valid_users]
        username, ok = QInputDialog.getItem(self, "Выбор пользователя", "Выберите пользователя для шифрования:", usernames, 0, False)
        if ok:
            return next(entry['public_key_path'] for entry in valid_users if entry['username'] == username)
        return None

    def get_user_to_decrypt(self):
        with open(KEYS_FILE, 'r') as f:
            data = json.load(f)
            valid_users = [entry for entry in data if entry.get("private_key_path") and entry.get('enabled', True)]
        if not valid_users:
            QMessageBox.warning(self, "Ошибка", "Нет доступных пользователей с включённым приватным ключом.")
            return None
        usernames = [entry['username'] for entry in valid_users]
        username, ok = QInputDialog.getItem(self, "Выбор пользователя", "Выберите пользователя для расшифровки:", usernames, 0, False)
        if ok:
            return next(entry['private_key_path'] for entry in valid_users if entry['username'] == username)
        return None

    def toggle_user_interaction(self):
        with open(KEYS_FILE, 'r+') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
            if not data:
                QMessageBox.information(self, "Пользователи", "Список пользователей пуст.")
                return
            usernames = [entry['username'] for entry in data]
            username, ok = QInputDialog.getItem(self, "Переключить взаимодействие", "Выберите пользователя:", usernames, 0, False)
            if not ok or not username:
                return
            for entry in data:
                if entry['username'] == username:
                    current = entry.get('enabled', True)
                    entry['enabled'] = not current
                    status = 'включено' if entry['enabled'] else 'выключено'
                    break
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()
        QMessageBox.information(self, "Статус обновлён", f"Взаимодействие для '{username}' {status}.")
        if self.tabs.currentWidget() == self.group_tab:
            self.refresh_group_users()

    # ========================== БЭКЕНД: AES-GCM ==========================
    def encrypt_text_gcm_backend(self, public_key_path, text):
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        return {
            'aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_text_gcm_backend(self, private_key_path, encrypted_data):
        encrypted_aes_key = base64.b64decode(encrypted_data['aes_key'])
        iv = base64.b64decode(encrypted_data['iv'])
        tag = base64.b64decode(encrypted_data['tag'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_bytes.decode('utf-8')

    def encrypt_file_gcm_backend(self, public_key_path, file_path):
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()).encryptor()
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_aes_key + iv + encryptor.tag + ciphertext)
        return encrypted_file_path

    def decrypt_file_gcm_backend(self, private_key_path, encrypted_file_path):
        with open(encrypted_file_path, 'rb') as f:
            encrypted_aes_key = f.read(512)
            iv = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_file_path = encrypted_file_path[:-4]
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        return decrypted_file_path

    # ========================== БЭКЕНД: LEGACY ==========================
    def encrypt_text_legacy(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования.")
            return
        public_key_path = self.get_user_to_encrypt()
        if public_key_path:
            encrypted = self.encrypt_text(public_key_path, text)
            self.text_input.setText(encrypted)
            QMessageBox.information(self, "Успех", "Текст зашифрован (Legacy RSA).")

    def decrypt_text_legacy(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите зашифрованный текст.")
            return
        private_key_path = self.get_user_to_decrypt()
        if private_key_path:
            decrypted = self.decrypt_text(private_key_path, text)
            self.text_input.setText(decrypted)
            QMessageBox.information(self, "Успех", "Текст расшифрован (Legacy RSA).")

    def encrypt_file_legacy(self):
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Ошибка", "Выберите существующий файл.")
            return
        public_key_path = self.get_user_to_encrypt()
        if public_key_path:
            encrypted_file = self.encrypt_file(public_key_path, file_path)
            QMessageBox.information(self, "Успех", f"Файл зашифрован (Legacy RSA): {encrypted_file}")

    def decrypt_file_legacy(self):
        file_path = self.file_path_input.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Ошибка", "Выберите существующий файл.")
            return
        private_key_path = self.get_user_to_decrypt()
        if private_key_path:
            decrypted_file = self.decrypt_file(private_key_path, file_path)
            QMessageBox.information(self, "Успех", f"Файл расшифрован (Legacy RSA): {decrypted_file}")

    def encrypt_text(self, public_key_path, text):
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        encrypted = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_text(self, private_key_path, encrypted_message):
        encrypted_message_bytes = base64.b64decode(encrypted_message)
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        decrypted = private_key.decrypt(encrypted_message_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                            algorithm=hashes.SHA256(), label=None))
        return decrypted.decode('utf-8')

    def encrypt_file(self, public_key_path, file_path):
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        encrypted_data = public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        return encrypted_file_path

    def decrypt_file(self, private_key_path, encrypted_file_path):
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        decrypted_data = private_key.decrypt(encrypted_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                        algorithm=hashes.SHA256(), label=None))
        decrypted_file_path = encrypted_file_path[:-4]
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        return decrypted_file_path

    # ========================== БЭКЕНД: PQC / ChaCha ==========================
    def encrypt_text_pqc(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования.")
            return
        public_key_path = self.get_user_to_encrypt()
        if public_key_path:
            encrypted = self.encrypt_text_xchacha_rsa(public_key_path, text)
            self.text_input.setText(json.dumps(encrypted, indent=4))
            QMessageBox.information(self, "Успех", "Текст зашифрован (Kyber + XChaCha20).")

    def decrypt_text_pqc(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите зашифрованный текст.")
            return
        private_key_path = self.get_user_to_decrypt()
        if private_key_path:
            try:
                encrypted_data = json.loads(text)
                decrypted = self.decrypt_text_xchacha_rsa(private_key_path, encrypted_data)
                self.text_input.setText(decrypted)
                QMessageBox.information(self, "Успех", "Текст расшифрован (Kyber + XChaCha20).")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать: {str(e)}")

    def encrypt_text_pqc_pass(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования.")
            return
        password, ok = QInputDialog.getText(self, "Пароль", "Введите пароль для шифрования:")
        if ok and password:
            encrypted = self.encrypt_xchacha(text, password)
            self.text_input.setText(json.dumps(encrypted, indent=4))
            QMessageBox.information(self, "Успех", "Текст зашифрован (XChaCha20 с паролем).")

    def decrypt_text_pqc_pass(self):
        text = self.text_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите зашифрованный текст.")
            return
        password, ok = QInputDialog.getText(self, "Пароль", "Введите пароль для расшифровки:")
        if ok and password:
            try:
                encrypted_data = json.loads(text)
                decrypted = self.decrypt_xchacha(encrypted_data, password)
                self.text_input.setText(decrypted)
                QMessageBox.information(self, "Успех", "Текст расшифрован (XChaCha20 с паролем).")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать: {str(e)}")

    def encrypt_xchacha(self, plaintext, password):
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        nonce = os.urandom(24)
        cipher = Cipher(algorithms.ChaCha20(key[:32], nonce[:16]), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode())
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "salt": base64.b64encode(salt).decode()
        }

    def decrypt_xchacha(self, encrypted_data, password):
        salt = base64.b64decode(encrypted_data["salt"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.ChaCha20(key[:32], nonce[:16]), mode=None)
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext)
        return decrypted_text.decode()

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=100000)
        return kdf.derive(password.encode())

    def encrypt_text_xchacha_rsa(self, public_key_path, text):
        xchacha_key = os.urandom(32)
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(xchacha_key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        encrypted_xchacha_key = public_key.encrypt(xchacha_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                            algorithm=hashes.SHA256(), label=None))
        return {
            'xchacha_key': base64.b64encode(encrypted_xchacha_key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_text_xchacha_rsa(self, private_key_path, encrypted_data):
        encrypted_xchacha_key = base64.b64decode(encrypted_data['xchacha_key'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        xchacha_key = private_key.decrypt(encrypted_xchacha_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                             algorithm=hashes.SHA256(), label=None))
        cipher = Cipher(algorithms.ChaCha20(xchacha_key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_text.decode('utf-8')

    # ========================== ТЕМЫ ИНТЕРФЕЙСА ==========================№

	def on_theme_changed(self, index):
	    # Добавлен индекс 3 для AMOLED
	    theme_map = {0: "system", 1: "light", 2: "dark", 3: "amoled"} # Обновлен словарь
	    theme_value = theme_map.get(index, "system")
	    config["theme"] = theme_value
	    self.save_config()
	    self.apply_theme(theme_value)

    def apply_theme(self, theme):
            app = QApplication.instance()
    if app is None:
        return

    # Убедимся, что используем стиль Fusion для более предсказуемого поведения палитры
    try:
        QApplication.setStyle("Fusion")
    except Exception:
        pass # Если Fusion недоступен, продолжаем с текущим стилем

    if theme == "system":
        system_theme = self.detect_system_theme()
        if system_theme == "dark":
            self.set_fusion_dark_palette(app)
        else:
            self.set_fusion_light_palette(app) # Используем специальную светлую палитру
        return

    if theme == "dark":
        self.set_fusion_dark_palette(app)
        return

    if theme == "light":
        self.set_fusion_light_palette(app) # Используем специальную светлую палитру
        return

    if theme == "amoled": # Новый блок для AMOLED
        self.set_fusion_amoled_palette(app)
        return

    # На всякий случай, если тема неизвестна, возвращаем к системной
    system_theme = self.detect_system_theme()
    if system_theme == "dark":
        self.set_fusion_dark_palette(app)
    else:
        self.set_fusion_light_palette(app)

    def set_fusion_dark_palette(self, app):
    # Убрали повторный вызов QApplication.setStyle("Fusion")
    # Он теперь вызывается в apply_theme перед этой функцией
    dark_palette = QPalette()
    dark_color = QColor(53, 53, 53)
    base_color = QColor(35, 35, 35) # Этот цвет для полей ввода
    text_color = QColor(220, 220, 220)
    disabled_text = QColor(127, 127, 127)

    dark_palette.setColor(QPalette.Window, dark_color)          # Фон основного окна
    dark_palette.setColor(QPalette.WindowText, text_color)      # Текст на фоне
    dark_palette.setColor(QPalette.Base, base_color)            # Фон полей ввода (QTextEdit, QLineEdit)
    dark_palette.setColor(QPalette.AlternateBase, dark_color)   # Альтернативный фон (например, в списках)
    dark_palette.setColor(QPalette.ToolTipBase, dark_color)     # Фон подсказок
    dark_palette.setColor(QPalette.ToolTipText, text_color)     # Текст подсказок
    dark_palette.setColor(QPalette.Text, text_color)            # Текст в полях ввода
    dark_palette.setColor(QPalette.Disabled, QPalette.Text, disabled_text) # Отключенный текст в полях ввода
    dark_palette.setColor(QPalette.Button, dark_color)          # Фон кнопок
    dark_palette.setColor(QPalette.ButtonText, text_color)      # Текст на кнопках
    dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_text) # Отключенный текст на кнопках
    dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0)) # Яркий текст (например, для ошибок)
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))  # Цвет ссылок
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218)) # Цвет фокуса/выделения
    dark_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0ст на фокусе/выделении

    app.setPalette(dark_palette)

    def set_fusion_light_palette(self, app = QPalette()
    # Яркие, чистые цвета для светлой темы
    window_color = QColor(255, 255, 255) # Белый фон
    window_text_color = QColor(0, 0, 0)  # Черный текст на фоне
    base_color = QColor(255, 255, 255)   # Белый фон полей ввода
    text_color = QColor(0, 0, 0)         # Черный текст в полях ввода
    button_color = QColor(240, 240, 240) # Светло-серый фон кнопок
    button_text_color = QColor(0, 0, 0)  # Черный текст на кнопках
    tooltip_base_color = QColor(255, 255, 220) # Желтоватый фон подсказок
    tooltip_text_color = QColor(0, 0, 0)       # Черный текст подсказок
    disabled_text_color = QColor(128, 1128) # Серый отключенный текст

(QPalette.Window, window_color)
    light_palette.setColor(QPalette.WindowText, window_text_color)
    light_palette.setColor(QPalette.Base, base_color)
    light_palette.setColor(QPalette.AlternateBase, QColor(247, 247, 247)) # Сlightly off-white for alternate rows
    light_palette.setColor(QPalette.ToolTipBase, tooltip_base_color)
    light_palette.setColor(QPalette.ToolTipText, tooltip_text_color)
    light_palette.setColor(QPalette.Text, text_color)
    light_palette.setColor(QPalette.Disabled, QPalette.Text, disabled_text_color)
    light_palette.setColor(QPalette.Button, button_color)
    light_palette.setColor(QPalette.ButtonText, button_text_color)
    light_palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_text_color)
    light_palette.setColor(QPalette.BrightText, QColor(255, 0, 0)) # Яркий текст (ок)
    light_palette.setColor(QPalette.Link, QColor(0, 0, 255))       # Цвет ссылок (синий)
    light_palette.setColor(QPalette.Highlight, QColor(51, 153, 255)) # Цвет фокуса/выделения (голубой)
    light_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255)) # Белый текст на фокусе/выделении

    app.setPalette(light_palette)

    def set_fusion_amoled_palette(self, app):
    amoled_palette = QPalette()
    # Цвета для AMOLED: максимально черный фон
    window_color = QColor(0, 0, 0)       # Чёрный фон
    window_text_color = QColor(220, 220, 220) # Светло-серый текст на фоне
    base_color = QColor(0, 0, 0)         # Чёрный фон полей ввода
    text_color = QColor(220, 220, 220)   # Светло-серый текст в полях ввода
    button_color = QColor(30, 30, 30)    # Очень тёмно-серый фон кнопок
    button_text_color = QColor(220, 220, 220) # Светло-серый текст на кнопках
    tooltip_base_color = QColor(0, 0, 0) # Чёрный фон подсказок
    tooltip_text_color = QColor(220, 220, 220) # Светло-серый текст подсказок
    disabled_text_color = QColor(80, 80, 80) # Тусклый серый отключенный текст

    amoled_palette.setColor(QPalette.Window, window_color)
    amoled_palette.setColor(QPalette.WindowText, window_text_color)
    amoled_palette.setColor(QPalette.Base, base_color)
    amoled_palette.setColor(QPalette.AlternateBase, QColor(10, 10, 10)) # Очень тёмный серый для альтернативных рядов
    amoled_palette.setColor(QPalette.ToolTipBase, tooltip_base_color)
    amoled_palette.setColor(QPalette.ToolTipText, tooltip_text_color)
    amoled_palette.setColor(QPalette.Text, text_color)
    amoled_palette.setColor(QPalette.Disabled, QPalette.Text, disabled_text_color)
    amoled_palette.setColor(QPalette.Button, button_color)
    amoled_palette.setColor(QPalette.ButtonText, button_text_color)
    amoled_palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled_text_color)
    amoled_palette.setColor(QPalette.BrightText, QColor(255, 50, 50)) # Ярко-красный текст (например, для ошибок)
    amoled_palette.setColor(QPalette.Link, QColor(100, 200, 255))     # Светло-голубой цвет ссылок
    amoled_palette.setColor(QPalette.Highlight, QColor(42, 130, 218)) # Цвет фокуса/выделения (голубой)
    amoled_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0)) # Чёрный текст на фокусе/выделении

    app.setPalette(amoled_palette)

    def detect_system_theme(self):
        if os.name == 'nt':
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize") as key:
                    value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                    return "light" if int(value) == 1 else "dark"
            except Exception:
                return "light"

        if os.name == 'posix' and (os.environ.get('KDE_FULL_SESSION') == 'true' or (os.environ.get('XDG_CURRENT_DESKTOP') or '').lower().find('kde') != -1):
            try:
                kdeglobals = os.path.expanduser("~/.config/kdeglobals")
                if os.path.exists(kdeglobals):
                    with open(kdeglobals, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line.strip().startswith('ColorScheme'):
                                if 'Dark' in line or 'BreezeDark' in line:
                                    return "dark"
                                break
                return "light"
            except Exception:
                return "light"

        return "light"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SCMessGUI()
    window.show()
    sys.exit(app.exec())
