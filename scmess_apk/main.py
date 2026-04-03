import os
import io
import json
import base64
import threading
from datetime import datetime

from kivy.config import Config
Config.set('graphics', 'maxfps', '120')
# Отключаем системное меню выделения текста (Select all / Paste)
Config.set('kivy', 'allow_screensaver', '0')

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kivy.app import App
from kivy.lang import Builder
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.uix.screenmanager import ScreenManager, Screen, NoTransition
from kivy.uix.modalview import ModalView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.widget import Widget
from kivy.clock import Clock
from kivy.utils import platform
from kivy.properties import ObjectProperty, StringProperty, BooleanProperty, ListProperty, DictProperty
from kivy.metrics import dp
from kivy.graphics import Color, RoundedRectangle, Rectangle, Line

if platform == 'android':
    try:
        from android import activity as _android_activity
        from jnius import autoclass as _autoclass, cast as _cast
    except Exception:
        pass

# ==================== ТЕМА ====================
DEFAULT_THEME = {
    "bg_color":     [0.0,  0.0,  0.0,  1],   # #000000 — истинный чёрный AMOLED
    "btn_bg":       [0.10, 0.10, 0.13, 1],
    "btn_border":   [0.25, 0.45, 0.85, 1],
    "btn_text":     [1,    1,    1,    1],
    "accent":       [0.25, 0.45, 0.85, 1],
    "input_bg":     [0.07, 0.07, 0.10, 1],
    "input_fg":     [0.92, 0.92, 0.95, 1],
    "title_color":  [0.3,  0.6,  1,    1],
    "label_muted":  [0.5,  0.5,  0.6,  1],
    "danger_bg":    [0.7,  0.15, 0.15, 1],
    "success_bg":   [0.15, 0.55, 0.25, 1],
    "log_bg":       [0.04, 0.04, 0.06, 1],
}

THEME_PRESETS = {
    "Тёмная (AMOLED)": DEFAULT_THEME.copy(),
    "Синяя ночь": {
        **DEFAULT_THEME,
        "bg_color":    [0.03, 0.05, 0.12, 1],
        "btn_bg":      [0.07, 0.10, 0.22, 1],
        "btn_border":  [0.20, 0.40, 0.90, 1],
        "accent":      [0.20, 0.40, 0.90, 1],
        "input_bg":    [0.05, 0.07, 0.15, 1],
        "title_color": [0.40, 0.70, 1.00, 1],
    },
    "Зелёная (Matrix)": {
        **DEFAULT_THEME,
        "bg_color":    [0.02, 0.06, 0.02, 1],
        "btn_bg":      [0.05, 0.13, 0.05, 1],
        "btn_border":  [0.10, 0.75, 0.10, 1],
        "accent":      [0.10, 0.75, 0.10, 1],
        "input_bg":    [0.04, 0.09, 0.04, 1],
        "input_fg":    [0.60, 1.00, 0.60, 1],
        "title_color": [0.20, 1.00, 0.20, 1],
        "label_muted": [0.30, 0.60, 0.30, 1],
    },
    "Пурпурная": {
        **DEFAULT_THEME,
        "bg_color":    [0.08, 0.04, 0.12, 1],
        "btn_bg":      [0.15, 0.08, 0.22, 1],
        "btn_border":  [0.60, 0.20, 0.90, 1],
        "accent":      [0.60, 0.20, 0.90, 1],
        "input_bg":    [0.10, 0.05, 0.15, 1],
        "title_color": [0.80, 0.40, 1.00, 1],
    },
}

SETTINGS_FILE = None

# ==================== KV ====================
KV = '''
#:import dp kivy.metrics.dp

# ── Кастомный переключатель (без системного Switch) ──────────────────
<ToggleBtn@Button>:
    active: False
    background_normal: ''
    background_color: 0, 0, 0, 0
    size_hint_x: None
    width: dp(52)
    canvas.before:
        Color:
            rgba: app.theme['accent'] if self.active else app.theme['label_muted']
        RoundedRectangle:
            pos: self.x, self.y + self.height*0.2
            size: self.width, self.height*0.6
            radius: [self.height*0.3]
        Color:
            rgba: 1, 1, 1, 1
        RoundedRectangle:
            pos: (self.x + self.width - dp(22)) if self.active else (self.x + dp(2)), self.y + self.height*0.2 + dp(2)
            size: self.height*0.6 - dp(4), self.height*0.6 - dp(4)
            radius: [self.height*0.3]
    on_release:
        self.active = not self.active

# ── Кнопка ────────────────────────────────────────────────────────────
<StyledButton@Button>:
    background_normal: ''
    background_color: 0, 0, 0, 0
    color: app.theme['btn_text']
    font_size: '15sp'
    bold: True
    canvas.before:
        Color:
            rgba: app.theme['btn_border']
        RoundedRectangle:
            pos: self.x, self.y
            size: self.width, self.height
            radius: [7]
        Color:
            rgba: app.theme['btn_bg']
        RoundedRectangle:
            pos: self.x+1.5, self.y+1.5
            size: self.width-3, self.height-3
            radius: [6]

<DangerButton@Button>:
    background_normal: ''
    background_color: 0, 0, 0, 0
    color: 1, 1, 1, 1
    font_size: '15sp'
    bold: True
    canvas.before:
        Color:
            rgba: 1, 0.3, 0.3, 0.8
        RoundedRectangle:
            pos: self.x, self.y
            size: self.width, self.height
            radius: [7]
        Color:
            rgba: app.theme['danger_bg']
        RoundedRectangle:
            pos: self.x+1.5, self.y+1.5
            size: self.width-3, self.height-3
            radius: [6]

# ── TextInput без пузыря выделения ────────────────────────────────────
<StyledInput@TextInput>:
    background_color: app.theme['input_bg']
    foreground_color: app.theme['input_fg']
    cursor_color: app.theme['accent']
    font_size: '16sp'
    padding: [12, 10, 12, 10]
    hint_text_color: 0.40, 0.40, 0.55, 1
    use_bubble: False
    use_handles: False

<SectionLabel@Label>:
    font_size: '13sp'
    color: app.theme['label_muted']
    size_hint_y: None
    height: dp(24)
    halign: 'left'
    text_size: self.width, None

# ── Экраны ────────────────────────────────────────────────────────────
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
                width: dp(100)
                spacing: dp(8)
                StyledButton:
                    text: 'Логи'
                    opacity: 1 if app.dev_mode else 0
                    disabled: not app.dev_mode
                    on_release: root.show_logs()
                StyledButton:
                    text: '='
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
        StyledButton:
            text: 'Legacy шифрование'
            size_hint_y: None
            height: dp(52)
            on_release: root.manager.current = 'legacy'
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
        # ── Шифрование ──
        SectionLabel:
            text: 'Для шифрования (публичный ключ):'
        Spinner:
            id: user_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(44)
        Label:
            id: user_warning
            text: ''
            color: 1, 0.25, 0.25, 1
            font_size: '13sp'
            size_hint_y: None
            height: dp(0)
        # ── Расшифровка ──
        SectionLabel:
            text: 'Для расшифровки (приватный ключ):'
        Spinner:
            id: decrypt_spinner
            text: 'Нет приватных ключей'
            background_normal: ''
            background_color: app.theme['input_bg']
            color: app.theme['accent']
            font_size: '15sp'
            size_hint_y: None
            height: dp(44)
        # ── Авто-копирование ──
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(10)
            padding: [dp(10), dp(4), dp(4), dp(4)]
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [7]
            Label:
                text: 'Авто-копировать в буфер'
                font_size: '14sp'
                color: app.theme['btn_text']
                halign: 'left'
                text_size: self.width, None
            ToggleBtn:
                id: auto_copy_switch
                active: True
        StyledInput:
            id: text_input
            hint_text: 'Текст для шифровки / JSON для расшифровки'
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
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(8)
            StyledButton:
                text: 'Вставить'
                on_release: root.paste_from_clipboard()
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
        SectionLabel:
            text: 'Для шифрования (публичный ключ):'
        Spinner:
            id: enc_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(44)
        SectionLabel:
            text: 'Для расшифровки (приватный ключ):'
        Spinner:
            id: dec_spinner
            text: 'Нет приватных ключей'
            background_normal: ''
            background_color: app.theme['input_bg']
            color: app.theme['accent']
            font_size: '15sp'
            size_hint_y: None
            height: dp(44)
        Label:
            id: user_warning
            text: ''
            color: 1, 0.25, 0.25, 1
            font_size: '13sp'
            size_hint_y: None
            height: dp(0)
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(10)
            padding: [dp(10), dp(4), dp(4), dp(4)]
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [7]
            Label:
                text: 'Android Document UI'
                font_size: '14sp'
                color: app.theme['btn_text']
                halign: 'left'
                text_size: self.width, None
            ToggleBtn:
                id: native_switch
                active: False
        BoxLayout:
            size_hint_y: None
            height: dp(42)
            canvas.before:
                Color:
                    rgba: app.theme['input_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [6]
            Label:
                id: file_label
                text: 'Файл не выбран'
                color: app.theme['label_muted']
                font_size: '13sp'
                halign: 'left'
                valign: 'middle'
                padding_x: dp(12)
                text_size: self.width - dp(12), None
        # Прогресс-бар (скрыт по умолчанию)
        Label:
            id: progress_label
            text: ''
            color: app.theme['accent']
            font_size: '12sp'
            size_hint_y: None
            height: dp(0)
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
            size_hint_y: 0.25
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
        # Авто-копирование
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(10)
            padding: [dp(10), dp(4), dp(4), dp(4)]
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [7]
            Label:
                text: 'Авто-копировать в буфер'
                font_size: '14sp'
                color: app.theme['btn_text']
                halign: 'left'
                text_size: self.width, None
            ToggleBtn:
                id: group_auto_copy
                active: True
        StyledInput:
            id: group_input
            hint_text: 'Текст для шифровки ИЛИ полученный JSON для расшифровки'
        # Кнопки действий
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
        # Кнопки утилит
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(8)
            StyledButton:
                text: 'Вставить'
                on_release: root.paste_from_clipboard()
            StyledButton:
                text: 'Очистить'
                on_release: root.clear_field()
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
            text: 'Выберите пресет...'
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(46)
            on_text: root.apply_preset(self.text)
        SectionLabel:
            text: 'Ручная настройка цветов (HEX):'
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
            height: dp(8)
        StyledButton:
            text: 'Сохранить тему'
            size_hint_y: None
            height: dp(48)
            on_release: root.save_settings()
        StyledButton:
            text: 'Логи приложения'
            size_hint_y: None
            height: dp(44)
            on_release: root.show_logs()
        StyledButton:
            text: 'Версия 1.7 — Что нового?'
            size_hint_y: None
            height: dp(44)
            on_release: root.show_changelog()
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'

<LegacyScreen>:
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
                text: 'Legacy шифрование (RSA-OAEP)'
                font_size: '17sp'
                bold: True
                color: app.theme['title_color']
        SectionLabel:
            text: 'Для шифрования (публичный ключ):'
        Spinner:
            id: enc_spinner
            text: 'Выберите пользователя'
            background_normal: ''
            background_color: app.theme['btn_bg']
            color: app.theme['btn_text']
            font_size: '15sp'
            size_hint_y: None
            height: dp(44)
        SectionLabel:
            text: 'Для расшифровки (приватный ключ):'
        Spinner:
            id: dec_spinner
            text: 'Нет приватных ключей'
            background_normal: ''
            background_color: app.theme['input_bg']
            color: app.theme['accent']
            font_size: '15sp'
            size_hint_y: None
            height: dp(44)
        Label:
            id: info_label
            text: 'Прямое RSA-OAEP шифрование без AES. Работает только с короткими текстами (< размер ключа).'
            font_size: '12sp'
            color: app.theme['label_muted']
            size_hint_y: None
            height: dp(36)
            halign: 'left'
            text_size: self.width, None
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(10)
            padding: [dp(10), dp(4), dp(4), dp(4)]
            canvas.before:
                Color:
                    rgba: app.theme['btn_bg']
                RoundedRectangle:
                    pos: self.x, self.y
                    size: self.width, self.height
                    radius: [7]
            Label:
                text: 'Авто-копировать в буфер'
                font_size: '14sp'
                color: app.theme['btn_text']
                halign: 'left'
                text_size: self.width, None
            ToggleBtn:
                id: legacy_auto_copy
                active: True
        StyledInput:
            id: legacy_input
            hint_text: 'Текст для шифровки / base64 для расшифровки'
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
        BoxLayout:
            size_hint_y: None
            height: dp(44)
            spacing: dp(8)
            StyledButton:
                text: 'Вставить'
                on_release: root.paste_clipboard()
            StyledButton:
                text: 'Очистить'
                on_release: root.clear_field()
        StyledButton:
            text: 'Назад'
            size_hint_y: None
            height: dp(44)
            on_release: root.manager.current = 'menu'
'''

# ==================== УВЕДОМЛЕНИЕ ====================

def show_msg(title, text):
    """Простой надёжный попап-карточка. Открывается сразу, без Clock-хаков."""
    app = App.get_running_app()
    t = app.theme if app else DEFAULT_THEME

    # ModalView — контейнер без стандартного фона
    mv = ModalView(
        size_hint=(0.88, None),
        height=dp(1),           # временно; обновим после компоновки
        background='',
        background_color=[0, 0, 0, 0],
        overlay_color=[0, 0, 0, 0.5],
        auto_dismiss=True,
    )

    # Карточка
    card = BoxLayout(
        orientation='vertical',
        padding=[dp(16), dp(16), dp(16), dp(8)],
        spacing=dp(10),
    )
    with card.canvas.before:
        Color(*t['input_bg'])
        card_bg = RoundedRectangle(pos=card.pos, size=card.size, radius=[dp(14)])
        Color(*t['btn_border'])
        card_border = RoundedRectangle(
            pos=(card.x - 1, card.y - 1),
            size=(card.width + 2, card.height + 2),
            radius=[dp(14)],
        )
    def _upd(inst, _):
        card_bg.pos   = inst.pos;  card_bg.size   = inst.size
        card_border.pos = (inst.x-1, inst.y-1); card_border.size = (inst.width+2, inst.height+2)
    card.bind(pos=_upd, size=_upd)

    # Акцентная полоска слева
    row = BoxLayout(spacing=dp(12))
    stripe = Widget(size_hint_x=None, width=dp(4))
    with stripe.canvas:
        Color(*t['accent'])
        stripe_rect = RoundedRectangle(pos=stripe.pos, size=stripe.size, radius=[dp(4)])
    stripe.bind(pos=lambda i,_: setattr(stripe_rect,'pos',i.pos),
                size=lambda i,_: setattr(stripe_rect,'size',i.size))

    texts = BoxLayout(orientation='vertical', spacing=dp(8))

    title_lbl = Label(
        text=title,
        font_size='16sp',
        bold=True,
        color=t['title_color'],
        size_hint_y=None,
        height=dp(24),
        halign='left',
        valign='middle',
    )
    title_lbl.bind(size=lambda i,_: setattr(i,'text_size',(i.width, None)))

    body_lbl = Label(
        text=text,
        font_size='14sp',
        color=t['input_fg'],
        size_hint_y=None,
        halign='left',
        valign='top',
    )
    # Высота body под содержимое
    def _body_size(inst, sz):
        inst.text_size = (inst.width, None)
    def _body_texture(inst, ts):
        inst.height = max(ts[1], dp(18))
    body_lbl.bind(size=_body_size, texture_size=_body_texture)

    texts.add_widget(title_lbl)
    texts.add_widget(body_lbl)
    row.add_widget(stripe)
    row.add_widget(texts)
    card.add_widget(row)

    # Разделитель
    sep = Widget(size_hint_y=None, height=dp(1))
    with sep.canvas:
        Color(*t['btn_border'])
        Rectangle(pos=sep.pos, size=sep.size)
    sep.bind(pos=lambda i,_: setattr(sep.canvas.children[-1],'pos',i.pos),
             size=lambda i,_: setattr(sep.canvas.children[-1],'size',i.size))
    card.add_widget(sep)

    ok_btn = Button(
        text='OK',
        size_hint_y=None,
        height=dp(40),
        background_normal='',
        background_color=[0, 0, 0, 0],
        color=t['accent'],
        bold=True,
        font_size='15sp',
    )
    ok_btn.bind(on_release=mv.dismiss)
    card.add_widget(ok_btn)

    mv.add_widget(card)

    # Считаем высоту после добавления виджетов — texture ещё не готов,
    # поэтому ставим разумный минимум и пересчитываем после первого frame
    mv.height = dp(180)

    def _fix_height(dt):
        # body_lbl.texture_size уже посчитан
        body_h = body_lbl.texture_size[1] if body_lbl.texture else dp(20)
        mv.height = dp(24) + dp(10) + body_h + dp(10) + dp(1) + dp(40) + dp(16) + dp(8) + dp(32)

    Clock.schedule_once(_fix_height, 0)
    mv.open()

# ==================== BACKEND ====================

class CryptoBackend:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.keys_file = os.path.join(self.data_dir, "keys.json")
        self.keys_dir  = os.path.join(self.data_dir, "keys")
        os.makedirs(self.keys_dir, exist_ok=True)
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
                for k in ['public_key_path', 'private_key_path']:
                    if u.get(k) and os.path.exists(u[k]):
                        try: os.remove(u[k])
                        except: pass
            else:
                new_users.append(u)
        self.save_users(new_users)

    def generate_key_pair(self, username, key_size):
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        priv_f = os.path.join(self.keys_dir, f"RSA_{username}_priv_{ts}.pem")
        pub_f  = os.path.join(self.keys_dir, f"RSA_{username}_pub_{ts}.pem")
        pk = rsa.generate_private_key(65537, key_size, default_backend())
        with open(priv_f, 'wb') as f:
            f.write(pk.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        with open(pub_f, 'wb') as f:
            f.write(pk.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
        data = self.load_users()
        data.append({"username": username, "public_key_path": pub_f, "private_key_path": priv_f})
        self.save_users(data)

    def add_friend_key(self, username, key_path, is_private=False):
        data = self.load_users()
        user = next((u for u in data if u['username'] == username), None)
        if not user:
            user = {"username": username}
            data.append(user)
        new_path = os.path.join(self.keys_dir, os.path.basename(key_path))
        with open(key_path, 'rb') as src, open(new_path, 'wb') as dst:
            dst.write(src.read())
        user['private_key_path' if is_private else 'public_key_path'] = new_path
        self.save_users(data)

    def add_friend_key_from_text(self, username, key_text, is_private=False):
        data = self.load_users()
        user = next((u for u in data if u['username'] == username), None)
        if not user:
            user = {"username": username}
            data.append(user)
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        kt = "priv" if is_private else "pub"
        new_path = os.path.join(self.keys_dir, f"RSA_imported_{username}_{kt}_{ts}.pem")
        with open(new_path, 'w', encoding='utf-8') as f:
            f.write(key_text)
        user['private_key_path' if is_private else 'public_key_path'] = new_path
        self.save_users(data)

    # ─── Крипто ───────────────────────────────────────────────────────
    @staticmethod
    def _oaep():
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    @staticmethod
    def key_fingerprint(key_path, is_private=False):
        """Возвращает короткий SHA-256 fingerprint ключа (8 групп по 2 символа).
        Для приватного ключа вычисляется через его публичную часть."""
        import hashlib
        with open(key_path, 'rb') as f:
            data = f.read()
        if is_private:
            k = serialization.load_pem_private_key(data, None, default_backend())
            der = k.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            k = serialization.load_pem_public_key(data, default_backend())
            der = k.public_bytes(serialization.Encoding.DER,
                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        h = hashlib.sha256(der).hexdigest()[:16].upper()
        return ':'.join(h[i:i+2] for i in range(0, 16, 2))  # A3:F7:C2:D1:E9:B0:4A:1C

    @staticmethod
    def detect_key_type(pem_text):
        """Определяет тип ключа по содержимому PEM-строки."""
        txt = pem_text.strip()
        if 'PRIVATE' in txt:
            return 'private'
        if 'PUBLIC' in txt:
            return 'public'
        # Пробуем загрузить
        try:
            serialization.load_pem_private_key(txt.encode(), None, default_backend())
            return 'private'
        except Exception:
            pass
        try:
            serialization.load_pem_public_key(txt.encode(), default_backend())
            return 'public'
        except Exception:
            pass
        return 'unknown'

    # ── Legacy: прямое RSA-шифрование (без AES-обёртки) ──────────────
    def encrypt_text_legacy(self, pub_key_path, text):
        with open(pub_key_path, 'rb') as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        if not isinstance(pub, rsa.RSAPublicKey):
            raise TypeError("Ключ не является публичным ключом RSA.")
        encrypted = pub.encrypt(text.encode(), self._oaep())
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_text_legacy(self, priv_key_path, encrypted_b64):
        enc_bytes = base64.b64decode(encrypted_b64)
        with open(priv_key_path, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), None, default_backend())
        if not isinstance(priv, rsa.RSAPrivateKey):
            raise TypeError("Ключ не является приватным ключом RSA.")
        return priv.decrypt(enc_bytes, self._oaep()).decode('utf-8')

    def encrypt_text_gcm(self, pub_key_path, text):
        aes_key = os.urandom(32); iv = os.urandom(12)
        enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv), default_backend()).encryptor()
        ct  = enc.update(text.encode()) + enc.finalize()
        with open(pub_key_path, 'rb') as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        enc_key = pub.encrypt(aes_key, self._oaep())
        return json.dumps({'aes_key': base64.b64encode(enc_key).decode(),
                           'iv': base64.b64encode(iv).decode(),
                           'tag': base64.b64encode(enc.tag).decode(),
                           'ciphertext': base64.b64encode(ct).decode()})

    def decrypt_text_gcm(self, priv_key_path, json_str):
        d = json.loads(json_str)
        enc_key = base64.b64decode(d['aes_key']); iv  = base64.b64decode(d['iv'])
        tag = base64.b64decode(d['tag']);          ct  = base64.b64decode(d['ciphertext'])
        with open(priv_key_path, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), None, default_backend())
        aes_key = priv.decrypt(enc_key, self._oaep())
        dec = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), default_backend()).decryptor()
        return (dec.update(ct) + dec.finalize()).decode()

    def encrypt_file_gcm(self, pub_key_path, file_path, progress_cb=None):
        """Потоковое шифрование файла блоками по 64 КБ.
        progress_cb(fraction) вызывается в процессе, если передан.
        Результат сохраняется рядом с оригиналом (или в Downloads на Android)."""
        from cryptography.exceptions import InvalidTag

        with open(pub_key_path, 'rb') as f:
            pub = serialization.load_pem_public_key(f.read(), default_backend())
        # Определяем длину зашифрованного RSA-блока по размеру ключа (не хардкодим 512)
        rsa_block_len = pub.key_size // 8  # 4096→512, 2048→256

        aes_key = os.urandom(32)
        iv      = os.urandom(12)
        enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv), default_backend()).encryptor()
        enc_aes_key = pub.encrypt(aes_key, self._oaep())

        # Выходной файл — рядом с оригиналом если возможно, иначе в Downloads
        out = self._output_path(file_path, '.enc')

        file_size = os.path.getsize(file_path)
        CHUNK = 65536

        with open(file_path, 'rb') as src, open(out, 'wb') as dst:
            # Заголовок: 2 байта длина RSA-блока + RSA-блок + IV
            dst.write(rsa_block_len.to_bytes(2, 'big'))
            dst.write(enc_aes_key)
            dst.write(iv)
            # Шифруем блоками
            done = 0
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                dst.write(enc.update(chunk))
                done += len(chunk)
                if progress_cb and file_size:
                    progress_cb(done / file_size)
            dst.write(enc.finalize())
            dst.write(enc.tag)   # 16 байт тега в конце файла

        return out

    def decrypt_file_gcm(self, priv_key_path, file_path, progress_cb=None):
        """Потоковая расшифровка. Формат: 2б(len) + RSA_key + IV + ciphertext + 16б(tag)."""
        from cryptography.exceptions import InvalidTag

        with open(priv_key_path, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), None, default_backend())

        with open(file_path, 'rb') as src:
            # Читаем заголовок
            rsa_block_len = int.from_bytes(src.read(2), 'big')
            enc_aes_key   = src.read(rsa_block_len)
            iv            = src.read(12)
            # Всё остальное — шифртекст + 16-байт тег в конце
            body          = src.read()

        if len(body) < 16:
            raise ValueError("Файл повреждён или не является зашифрованным файлом SCmess.")

        ciphertext = body[:-16]
        tag        = body[-16:]

        try:
            aes_key = priv.decrypt(enc_aes_key, self._oaep())
        except Exception:
            raise ValueError("Неверный ключ: не удалось расшифровать сессионный ключ.")

        dec = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), default_backend()).decryptor()

        out = self._output_path(file_path, None)  # убираем .enc или добавляем .dec
        CHUNK = 65536
        total = len(ciphertext)
        done  = 0

        try:
            with open(out, 'wb') as dst:
                for i in range(0, total, CHUNK):
                    block = ciphertext[i:i+CHUNK]
                    dst.write(dec.update(block))
                    done += len(block)
                    if progress_cb and total:
                        progress_cb(done / total)
                dst.write(dec.finalize())
        except InvalidTag:
            # Удаляем битый выходной файл
            try: os.remove(out)
            except: pass
            raise ValueError("Ошибка проверки целостности (GCM tag). Файл повреждён или использован неверный ключ.")

        return out

    @staticmethod
    def _output_path(src_path, suffix):
        """Вычислить путь для выходного файла рядом с исходным.
        suffix='.enc' → добавляет .enc; suffix=None → убирает .enc или добавляет .dec.
        Если директория недоступна для записи — падаем в Downloads."""
        if suffix == '.enc':
            candidate = src_path + '.enc'
        else:
            candidate = src_path[:-4] if src_path.lower().endswith('.enc') else src_path + '.dec'

        # Проверяем доступность директории
        out_dir = os.path.dirname(candidate) or '.'
        try:
            test = os.path.join(out_dir, '.scmess_write_test')
            with open(test, 'wb') as f: f.write(b'')
            os.remove(test)
            return candidate
        except (OSError, PermissionError):
            # Нет прав — сохраняем в Downloads
            dl = '/storage/emulated/0/Download' if platform == 'android' else os.path.expanduser('~/Downloads')
            os.makedirs(dl, exist_ok=True)
            return os.path.join(dl, os.path.basename(candidate))

    def encrypt_group(self, pub_paths_list, text):
        """Шифруем для списка публичных ключей.
        В JSON вместо имён хранятся SHA-256 fingerprint'ы публичных ключей —
        имена получателей нигде не фигурируют."""
        aes_key = os.urandom(32); iv = os.urandom(12)
        enc = Cipher(algorithms.AES(aes_key), modes.GCM(iv), default_backend()).encryptor()
        ct = enc.update(text.encode()) + enc.finalize()
        keys = {}
        for path in pub_paths_list:
            with open(path, 'rb') as f:
                pub_data = f.read()
            pub = serialization.load_pem_public_key(pub_data, default_backend())
            # Fingerprint = SHA-256 от DER-представления ключа (первые 16 байт hex)
            der = pub.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
            import hashlib
            fp = hashlib.sha256(der).hexdigest()[:32]
            keys[fp] = base64.b64encode(pub.encrypt(aes_key, self._oaep())).decode()
        return json.dumps({"type": "group_message_gcm",
                           "iv": base64.b64encode(iv).decode(),
                           "tag": base64.b64encode(enc.tag).decode(),
                           "ciphertext": base64.b64encode(ct).decode(),
                           "keys": keys}, ensure_ascii=False)

    def decrypt_group(self, payload_str):
        """Расшифровка: ищем совпадение fingerprint'а нашего публичного ключа.
        Если ни один не совпал — сообщение зашифровано не для нас."""
        import hashlib
        p = json.loads(payload_str)
        stored_keys = p.get("keys", {})
        for user in self.load_users():
            pub_path = user.get("private_key_path") and user.get("public_key_path")
            if not pub_path or not user.get("private_key_path"):
                continue
            # Считаем fingerprint нашего публичного ключа
            try:
                with open(user['public_key_path'], 'rb') as f:
                    pub_data = f.read()
                pub = serialization.load_pem_public_key(pub_data, default_backend())
                der = pub.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
                fp = hashlib.sha256(der).hexdigest()[:32]
            except Exception:
                continue
            if fp not in stored_keys:
                continue
            # Нашли наш слот — расшифровываем
            enc_key = base64.b64decode(stored_keys[fp])
            iv  = base64.b64decode(p['iv']);  tag = base64.b64decode(p['tag'])
            ct  = base64.b64decode(p['ciphertext'])
            with open(user['private_key_path'], 'rb') as f:
                priv = serialization.load_pem_private_key(f.read(), None, default_backend())
            aes_key = priv.decrypt(enc_key, self._oaep())
            dec = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), default_backend()).decryptor()
            return (dec.update(ct) + dec.finalize()).decode()
        raise Exception("Это сообщение зашифровано не для вас.")


# ==================== ЭКРАНЫ ====================

class MenuScreen(Screen):
    taps = 0
    def title_tapped(self, widget, touch):
        if widget.collide_point(*touch.pos):
            self.taps += 1
            if self.taps >= 10:
                app = App.get_running_app()
                app.dev_mode = not app.dev_mode
                show_msg("Режим разработчика",
                         f"{'ВКЛЮЧЁН' if app.dev_mode else 'ВЫКЛЮЧЕН'}\n10 тапов для смены.")
                self.taps = 0

    def show_help(self):
        show_msg("Помощь",
                 "1. Ключи → Сгенерировать свои ключи\n"
                 "2. Добавь друзей (Из файла / Текстом)\n"
                 "3. Текст → авто-копирование по переключателю\n"
                 "4. Файлы → переключи Document UI для системного пикера\n"
                 "5. Настройки → тема, цвета\n"
                 "6. Логи → 10 тапов по заголовку (dev mode)")

    def show_logs(self):
        app = App.get_running_app()
        t = app.theme
        if not app.action_log:
            show_msg("Логи", "Логов пока нет.")
            return
        sv = ScrollView()
        box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(2), padding=dp(6))
        box.bind(minimum_height=box.setter('height'))
        for line in reversed(app.action_log):
            lbl = Label(text=line, size_hint_y=None, height=dp(30), halign='left', valign='middle',
                        color=t['input_fg'], font_size='12sp')
            lbl.bind(width=lambda i, v: setattr(i, 'text_size', (v, None)))
            box.add_widget(lbl)
        sv.add_widget(box)
        mv = ModalView(size_hint=(0.95, 0.85), background_color=t['log_bg'])
        outer = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(8))
        outer.add_widget(Label(text="Логи (dev mode)", font_size='16sp', bold=True,
                               color=t['title_color'], size_hint_y=None, height=dp(36)))
        outer.add_widget(sv)
        btn = Button(text='Закрыть', size_hint_y=None, height=dp(42),
                     background_normal='', background_color=t['btn_bg'], color=t['btn_text'])
        btn.bind(on_release=mv.dismiss)
        outer.add_widget(btn)
        mv.add_widget(outer)
        mv.open()


class KeysScreen(Screen):
    def on_enter(self): self.refresh_users()

    def refresh_users(self):
        layout = self.ids.users_list
        layout.clear_widgets()
        t = App.get_running_app().theme
        for u in App.get_running_app().backend.load_users():
            hp = bool(u.get('public_key_path')); hpr = bool(u.get('private_key_path'))
            text = f"{u['username']}\nПуб: {'OK' if hp else '--'}   Прив: {'OK' if hpr else '--'}"
            btn = Button(text=text, size_hint_y=None, height=dp(64),
                         background_normal='', background_color=t['btn_bg'],
                         color=t['btn_text'], halign='left', valign='middle',
                         text_size=(Window.width - dp(60), None), font_size='14sp')
            btn.bind(on_release=lambda x, user=u: self.show_user_options(user))
            layout.add_widget(btn)

    def show_user_options(self, user):
        app = App.get_running_app(); t = app.theme
        mv = ModalView(size_hint=(0.92, 0.90), background_color=t['input_bg'])
        sv = ScrollView()
        box = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(8),
                        size_hint_y=None)
        box.bind(minimum_height=box.setter('height'))

        box.add_widget(Label(text=f"Пользователь: {user['username']}", size_hint_y=None,
                             height=dp(32), color=t['title_color'], bold=True))

        # ── Публичный ключ ──
        if user.get('public_key_path') and os.path.exists(user['public_key_path']):
            with open(user['public_key_path']) as f: pub_text = f.read()
            try:
                fp = app.backend.key_fingerprint(user['public_key_path'], is_private=False)
            except Exception:
                fp = "н/д"
            box.add_widget(Label(text=f"Публичный ключ  |  FP: {fp}", size_hint_y=None,
                                 height=dp(24), color=t['accent'], font_size='12sp',
                                 halign='left', text_size=(Window.width * 0.85, None)))
            pub_view = TextInput(text=pub_text, readonly=True, background_color=t['input_bg'],
                                 foreground_color=t['accent'], font_size='10sp',
                                 size_hint_y=None, height=dp(120),
                                 use_bubble=False, use_handles=False)
            box.add_widget(pub_view)
            copy_pub = Button(text="Копировать публичный ключ", size_hint_y=None, height=dp(42),
                              background_normal='', background_color=t['btn_bg'], color=t['btn_text'])
            copy_pub.bind(on_release=lambda _: (Clipboard.copy(pub_text),
                                                 show_msg("Скопировано", "Публичный ключ в буфере")))
            box.add_widget(copy_pub)
        else:
            pub_text = ""
            box.add_widget(Label(text="Публичный ключ отсутствует", size_hint_y=None, height=dp(28),
                                 color=t['label_muted']))

        # ── Приватный ключ ──
        if user.get('private_key_path') and os.path.exists(user['private_key_path']):
            try:
                fp_priv = app.backend.key_fingerprint(user['private_key_path'], is_private=True)
            except Exception:
                fp_priv = "н/д"
            box.add_widget(Label(text=f"Приватный ключ  |  FP: {fp_priv}", size_hint_y=None,
                                 height=dp(24), color=[1, 0.5, 0.3, 1], font_size='12sp',
                                 halign='left', text_size=(Window.width * 0.85, None)))
            if app.dev_mode:
                with open(user['private_key_path']) as f: priv_text = f.read()
                prv = TextInput(text=priv_text, readonly=True,
                                background_color=[0.08, 0.02, 0.02, 1],
                                foreground_color=[1, 0.4, 0.4, 1], font_size='10sp',
                                size_hint_y=None, height=dp(100),
                                use_bubble=False, use_handles=False)
                box.add_widget(prv)
                cp = Button(text="Копировать приватный ключ (ОПАСНО!)", size_hint_y=None, height=dp(42),
                            background_normal='', background_color=t['danger_bg'], color=[1,1,1,1])
                cp.bind(on_release=lambda _: (Clipboard.copy(priv_text),
                                               show_msg("Скопировано", "Приватный ключ в буфере")))
                box.add_widget(cp)
        else:
            box.add_widget(Label(text="Приватный ключ отсутствует", size_hint_y=None, height=dp(28),
                                 color=t['label_muted']))

        # ── Кнопки ──
        del_btn = Button(text="Удалить пользователя", size_hint_y=None, height=dp(44),
                         background_normal='', background_color=t['danger_bg'], color=[1,1,1,1])
        close_btn = Button(text="Закрыть", size_hint_y=None, height=dp(44),
                           background_normal='', background_color=t['btn_bg'], color=t['btn_text'])

        def do_delete(_):
            # Подтверждение удаления
            conf = ModalView(size_hint=(0.8, 0.32), background_color=t['input_bg'])
            cb = BoxLayout(orientation='vertical', padding=dp(14), spacing=dp(10))
            cb.add_widget(Label(text=f"Удалить «{user['username']}»?\nЭто удалит ключи с диска.",
                                color=t['input_fg'], font_size='14sp', size_hint_y=0.6,
                                halign='center', text_size=(Window.width * 0.7, None)))
            row = BoxLayout(size_hint_y=0.4, spacing=dp(10))
            yes = Button(text="Удалить", background_normal='', background_color=t['danger_bg'], color=[1,1,1,1])
            no  = Button(text="Отмена", background_normal='', background_color=t['btn_bg'], color=t['btn_text'])
            def confirm(_):
                conf.dismiss(); mv.dismiss()
                app.backend.delete_user(user['username'])
                self.refresh_users()
                app.log_action(f"Удалён пользователь {user['username']}")
                show_msg("Удалено", f"Пользователь «{user['username']}» удалён")
            yes.bind(on_release=confirm)
            no.bind(on_release=conf.dismiss)
            row.add_widget(yes); row.add_widget(no)
            cb.add_widget(row)
            conf.add_widget(cb); conf.open()

        del_btn.bind(on_release=do_delete)
        close_btn.bind(on_release=mv.dismiss)
        box.add_widget(del_btn); box.add_widget(close_btn)
        sv.add_widget(box)
        mv.add_widget(sv); mv.open()

    def _styled_input(self, **kw):
        t = App.get_running_app().theme
        return TextInput(background_color=t['input_bg'], foreground_color=t['input_fg'],
                         use_bubble=False, use_handles=False, **kw)

    def _styled_btn(self, text, color_key='accent', **kw):
        t = App.get_running_app().theme
        return Button(text=text, background_normal='', background_color=t[color_key],
                      color=[1,1,1,1], **kw)

    def generate_keys_dialog(self):
        t = App.get_running_app().theme
        mv = ModalView(size_hint=(0.85, 0.52), background_color=t['input_bg'])
        box = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(12))
        inp = self._styled_input(hint_text="Имя пользователя", size_hint_y=None, height=dp(48), multiline=False)
        sp  = Spinner(text='4096', values=('2048','4096'), size_hint_y=None, height=dp(46),
                      background_normal='', background_color=t['btn_bg'], color=t['btn_text'])
        btn = self._styled_btn("Создать", size_hint_y=None, height=dp(52))
        box.add_widget(inp)
        box.add_widget(Label(text="Размер RSA ключа (бит):", size_hint_y=None, height=dp(28),
                             color=t['label_muted']))
        box.add_widget(sp); box.add_widget(btn)
        mv.add_widget(box)

        def on_create(_):
            if not inp.text.strip(): return
            size = int(sp.text)
            wait = ModalView(size_hint=(0.8, 0.32), background_color=t['input_bg'], auto_dismiss=False)
            wait.add_widget(Label(text=f"Создаём {size}-бит ключи...\nПодождите",
                                  color=t['input_fg']))
            mv.dismiss(); wait.open()
            threading.Thread(target=self._gen_thread, args=(inp.text.strip(), size, wait)).start()

        btn.bind(on_release=on_create); mv.open()

    def _gen_thread(self, username, size, wait):
        try:
            App.get_running_app().backend.generate_key_pair(username, size)
            Clock.schedule_once(lambda dt: [self.refresh_users(), wait.dismiss(),
                                            show_msg("Успех", f"Ключи для {username} созданы!")], 0)
        except Exception as e:
            Clock.schedule_once(lambda dt: [wait.dismiss(), show_msg("Ошибка", str(e))], 0)

    def add_key_dialog(self):
        """Импорт ключа из файла — тип определяется автоматически."""
        path = '/storage/emulated/0/Download' if platform == 'android' else os.path.expanduser('~')
        chooser = FileChooserListView(path=path, filters=['*.pem'])
        box = BoxLayout(orientation='vertical')
        box.add_widget(chooser)
        t = App.get_running_app().theme
        btn = Button(text="Выбрать файл ключа", size_hint_y=None, height=dp(48),
                     background_normal='', background_color=t['accent'])
        box.add_widget(btn)
        popup = ModalView(size_hint=(0.95, 0.92))
        popup.add_widget(box)

        def on_sel(_):
            if not chooser.selection: return
            fpath = chooser.selection[0]
            try:
                with open(fpath, 'rb') as f: raw = f.read()
                kt = App.get_running_app().backend.detect_key_type(raw.decode('utf-8', errors='ignore'))
            except Exception:
                kt = 'unknown'
            type_hint = "ПРИВАТНЫЙ" if kt == 'private' else ("ПУБЛИЧНЫЙ" if kt == 'public' else "НЕИЗВЕСТНЫЙ")
            ni = self._styled_input(hint_text="Имя пользователя", size_hint_y=0.45, multiline=False)
            type_lbl = Label(text=f"Тип: {type_hint}", size_hint_y=None, height=dp(28),
                             color=[1, 0.5, 0.3, 1] if kt == 'private' else t['accent'])
            ok = self._styled_btn("Сохранить", size_hint_y=0.35)
            nb = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(8))
            nb.add_widget(ni); nb.add_widget(type_lbl); nb.add_widget(ok)
            np_ = ModalView(size_hint=(0.78, 0.38))
            np_.add_widget(nb)
            def save(_):
                if ni.text.strip():
                    App.get_running_app().backend.add_friend_key(ni.text.strip(), fpath, kt == 'private')
                    np_.dismiss(); popup.dismiss(); self.refresh_users()
                    show_msg("Готово", f"Ключ добавлен ({type_hint.lower()})")
            ok.bind(on_release=save); np_.open()
        btn.bind(on_release=on_sel); popup.open()

    def add_key_text_dialog(self):
        t = App.get_running_app().theme
        mv = ModalView(size_hint=(0.92, 0.84), background_color=t['input_bg'])
        box = BoxLayout(orientation='vertical', spacing=dp(10), padding=dp(12))
        box.add_widget(Label(text="Импорт ключа", bold=True, font_size='16sp',
                             color=t['title_color'], size_hint_y=None, height=dp(30)))
        box.add_widget(Label(
            text="Тип определяется автоматически по слову PRIVATE / PUBLIC в PEM",
            font_size='12sp', color=t['label_muted'], size_hint_y=None, height=dp(32),
            halign='left', text_size=(Window.width * 0.8, None)))
        n_inp = self._styled_input(hint_text="Имя пользователя (нового или существующего)",
                                   size_hint_y=None, height=dp(48), multiline=False)
        k_inp = self._styled_input(hint_text="Вставьте PEM ключ сюда...")
        id_lbl = Label(text="", font_size='12sp', color=t['accent'],
                       size_hint_y=None, height=dp(22), halign='left',
                       text_size=(Window.width * 0.8, None))

        def on_key_text(inst, val):
            kt = App.get_running_app().backend.detect_key_type(val)
            if kt == 'private':
                id_lbl.text = "Определён: ПРИВАТНЫЙ ключ"
                id_lbl.color = [1, 0.5, 0.3, 1]
            elif kt == 'public':
                id_lbl.text = "Определён: ПУБЛИЧНЫЙ ключ"
                id_lbl.color = t['accent']
            else:
                id_lbl.text = ""
        k_inp.bind(text=on_key_text)

        paste_btn = Button(text="Вставить из буфера", size_hint_y=None, height=dp(40),
                           background_normal='', background_color=t['btn_bg'], color=t['btn_text'])
        paste_btn.bind(on_release=lambda _: setattr(k_inp, 'text', Clipboard.paste() or ''))
        btn = self._styled_btn("Сохранить", size_hint_y=None, height=dp(52))

        box.add_widget(n_inp); box.add_widget(paste_btn)
        box.add_widget(k_inp); box.add_widget(id_lbl); box.add_widget(btn)
        mv.add_widget(box)

        def save(_):
            name = n_inp.text.strip(); key_text = k_inp.text.strip()
            if not name or not key_text: show_msg("Ошибка", "Заполните имя и ключ!"); return
            kt = App.get_running_app().backend.detect_key_type(key_text)
            if kt == 'unknown': show_msg("Ошибка", "Не удалось определить тип ключа."); return
            App.get_running_app().backend.add_friend_key_from_text(name, key_text, kt == 'private')
            mv.dismiss(); self.refresh_users()
            show_msg("Готово", f"Импортирован {'приватный' if kt=='private' else 'публичный'} ключ для «{name}»")
        btn.bind(on_release=save); mv.open()


class TextScreen(Screen):
    def on_enter(self):
        users = App.get_running_app().backend.load_users()
        # Спиннер шифрования — пользователи с публичным ключом
        enc_users = [u['username'] for u in users if u.get('public_key_path')]
        self.ids.user_spinner.values = enc_users

        # Спиннер расшифровки — пользователи с приватным ключом
        dec_users = [u['username'] for u in users if u.get('private_key_path')]
        self.ids.decrypt_spinner.values = dec_users
        # По умолчанию — первый сгенерированный (первый в списке с приватным ключом)
        if dec_users and (not self.ids.decrypt_spinner.text or
                          self.ids.decrypt_spinner.text not in dec_users):
            self.ids.decrypt_spinner.text = dec_users[0]
        elif not dec_users:
            self.ids.decrypt_spinner.text = 'Нет приватных ключей'
        self._hide_warning()

    def _show_warning(self, txt="Выберите пользователя из списка!"):
        self.ids.user_warning.text = txt
        self.ids.user_warning.height = dp(28)

    def _hide_warning(self):
        self.ids.user_warning.text = ''
        self.ids.user_warning.height = dp(0)

    def clear_field(self):
        self.ids.text_input.text = ''
        self._hide_warning()

    def paste_from_clipboard(self):
        txt = Clipboard.paste()
        if txt:
            self.ids.text_input.text = txt

    def encrypt_action(self):
        username = self.ids.user_spinner.text
        text = self.ids.text_input.text.strip()
        if username == 'Выберите пользователя' or not username:
            self._show_warning(); return
        if not text:
            show_msg("Ошибка", "Введите текст!"); return
        self._hide_warning()
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "У пользователя нет публичного ключа!"); return
        try:
            res = backend.encrypt_text_gcm(user['public_key_path'], text)
            self.ids.text_input.text = res
            if self.ids.auto_copy_switch.active:
                Clipboard.copy(res)
                show_msg("Успех", "Зашифровано и скопировано в буфер!")
            else:
                show_msg("Успех", "Текст зашифрован!")
            App.get_running_app().log_action(f"Зашифрован текст для {username}")
        except Exception as e:
            show_msg("Ошибка шифрования", str(e))

    def decrypt_action(self):
        # Используем спиннер расшифровки
        username = self.ids.decrypt_spinner.text
        text = self.ids.text_input.text.strip()
        if not username or username == 'Нет приватных ключей':
            show_msg("Ошибка", "Нет пользователя с приватным ключом!"); return
        if not text:
            show_msg("Ошибка", "Вставьте зашифрованный JSON!"); return
        self._hide_warning()
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа!"); return
        try:
            res = backend.decrypt_text_gcm(user['private_key_path'], text)
            self.ids.text_input.text = res
            show_msg("Успех", "Текст расшифрован!")
            App.get_running_app().log_action(f"Расшифрован текст для {username}")
        except Exception as e:
            show_msg("Ошибка расшифровки", str(e))


# ────────────────────────────────────────────────────────────────────
# Файловый экран — главная точка фикса Document UI
# ────────────────────────────────────────────────────────────────────
class FileScreen(Screen):
    selected_file = None
    _pending_uri  = None
    _busy         = False   # блокировка повторного нажатия во время операции

    def on_enter(self):
        app   = App.get_running_app()
        users = app.backend.load_users()
        enc_users = [u['username'] for u in users if u.get('public_key_path')]
        dec_users = [u['username'] for u in users if u.get('private_key_path')]
        self.ids.enc_spinner.values = enc_users
        self.ids.dec_spinner.values = dec_users
        if dec_users and self.ids.dec_spinner.text not in dec_users:
            self.ids.dec_spinner.text = dec_users[0]
        elif not dec_users:
            self.ids.dec_spinner.text = 'Нет приватных ключей'
        self._hide_warning()
        self._hide_progress()

    def _show_warning(self, txt="Выберите пользователя!"):
        self.ids.user_warning.text   = txt
        self.ids.user_warning.height = dp(28)

    def _hide_warning(self):
        self.ids.user_warning.text   = ''
        self.ids.user_warning.height = dp(0)

    def _show_progress(self, txt):
        self.ids.progress_label.text   = txt
        self.ids.progress_label.height = dp(22)

    def _hide_progress(self):
        self.ids.progress_label.text   = ''
        self.ids.progress_label.height = dp(0)

    # ── Выбор файла ──────────────────────────────────────────────────
    def choose_file(self):
        if platform == 'android' and self.ids.native_switch.active:
            self._open_document_ui()
        else:
            self._open_kivy_picker()

    def _open_kivy_picker(self):
        storage_path = '/storage/emulated/0/Download' if platform == 'android' else os.path.expanduser('~')
        chooser = FileChooserListView(path=storage_path)
        box = BoxLayout(orientation='vertical')
        box.add_widget(chooser)
        t   = App.get_running_app().theme
        btn = Button(text="Выбрать", size_hint_y=None, height=dp(50),
                     background_normal='', background_color=t['accent'])
        box.add_widget(btn)
        mv = ModalView(size_hint=(0.97, 0.93))
        mv.add_widget(box)
        def on_sel(_):
            if chooser.selection:
                self._set_file(chooser.selection[0])
            mv.dismiss()
        btn.bind(on_release=on_sel)
        mv.open()

    def _set_file(self, path):
        self.selected_file = path
        self._pending_uri  = None
        self.ids.file_label.text  = os.path.basename(path)
        self.ids.file_label.color = App.get_running_app().theme['input_fg']
        App.get_running_app().log_action(f"Выбран файл: {os.path.basename(path)}")

    def _open_document_ui(self):
        try:
            Intent         = _autoclass('android.content.Intent')
            PythonActivity = _autoclass('org.kivy.android.PythonActivity')
            intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            intent.setType("*/*")
            try: _android_activity.unbind(on_activity_result=self._on_android_result)
            except: pass
            _android_activity.bind(on_activity_result=self._on_android_result)
            PythonActivity.mActivity.startActivityForResult(intent, 42)
            App.get_running_app().log_action("Открыт Android Document UI")
        except Exception as e:
            show_msg("Ошибка Document UI", str(e))
            self._open_kivy_picker()

    def _on_android_result(self, requestCode, resultCode, data):
        if requestCode != 42:
            return
        try: _android_activity.unbind(on_activity_result=self._on_android_result)
        except: pass
        if resultCode != -1 or data is None:
            show_msg("Файл не выбран", "Выбор файла отменён.")
            return
        try:
            uri = data.getData()
            if uri is None:
                show_msg("Ошибка", "URI файла не получен."); return
            display_name = self._get_display_name(uri)
            self._show_progress("Копирование файла...")
            # Копируем в поток чтобы UI не завис
            def copy_thread():
                tmp = self._copy_uri_fast(uri, display_name)
                def done(dt):
                    self._hide_progress()
                    if tmp:
                        self._set_file(tmp)
                    else:
                        show_msg("Ошибка", "Не удалось прочитать файл.")
                Clock.schedule_once(done, 0)
            threading.Thread(target=copy_thread, daemon=True).start()
        except Exception as e:
            self._hide_progress()
            show_msg("Ошибка Document UI", str(e))

    def _get_display_name(self, uri):
        try:
            context = _autoclass('org.kivy.android.PythonActivity').mActivity
            cursor  = context.getContentResolver().query(uri, None, None, None, None)
            if cursor and cursor.moveToFirst():
                for col in ("_display_name", "display_name"):
                    idx = cursor.getColumnIndex(col)
                    if idx >= 0:
                        name = cursor.getString(idx)
                        cursor.close()
                        if name: return name
            if cursor: cursor.close()
        except Exception:
            pass
        try:
            s = uri.toString()
            return s.split('/')[-1].split('%2F')[-1] or "document_file"
        except:
            return "document_file"

    def _copy_uri_fast(self, uri, filename):
        """Копирование через ParcelFileDescriptor fd → os.read() — быстро, без JNI-цикла."""
        try:
            context  = _autoclass('org.kivy.android.PythonActivity').mActivity
            resolver = context.getContentResolver()
            pfd      = resolver.openFileDescriptor(uri, "r")
            if pfd is None: return None
            fd       = pfd.getFd()
            cache_dir = context.getCacheDir().getAbsolutePath()
            tmp_path  = os.path.join(cache_dir, filename)
            CHUNK = 1 << 20
            with open(tmp_path, 'wb') as out:
                while True:
                    chunk = os.read(fd, CHUNK)
                    if not chunk: break
                    out.write(chunk)
            pfd.close()
            return tmp_path
        except Exception as e:
            show_msg("Ошибка чтения файла", str(e))
            return None

    # ── Шифрование / расшифровка ──────────────────────────────────────
    def encrypt_file(self):
        if self._busy: return
        username = self.ids.enc_spinner.text
        if not username or username == 'Выберите пользователя':
            self._show_warning("Выберите пользователя для шифрования!"); return
        self._hide_warning()
        if not self.selected_file:
            show_msg("Ошибка", "Сначала выберите файл!"); return
        app  = App.get_running_app()
        user = next((u for u in app.backend.load_users() if u['username'] == username), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "Нет публичного ключа!"); return

        self._busy = True
        self._show_progress("Шифрование... 0%")

        def progress(frac):
            Clock.schedule_once(lambda dt: self._show_progress(f"Шифрование... {int(frac*100)}%"), 0)

        def run():
            try:
                out = app.backend.encrypt_file_gcm(user['public_key_path'], self.selected_file, progress)
                app.log_action(f"Зашифрован: {os.path.basename(self.selected_file)}")
                def done(dt):
                    self._busy = False; self._hide_progress()
                    show_msg("Готово", f"Зашифрован!\nСохранён: {os.path.basename(out)}\nПапка: {os.path.dirname(out)}")
                Clock.schedule_once(done, 0)
            except Exception as e:
                def err(dt):
                    self._busy = False; self._hide_progress()
                    show_msg("Ошибка шифрования", str(e))
                Clock.schedule_once(err, 0)

        threading.Thread(target=run, daemon=True).start()

    def decrypt_file(self):
        if self._busy: return
        username = self.ids.dec_spinner.text
        if not username or username == 'Нет приватных ключей':
            self._show_warning("Нет пользователя с приватным ключом!"); return
        self._hide_warning()
        if not self.selected_file:
            show_msg("Ошибка", "Сначала выберите файл!"); return
        app  = App.get_running_app()
        user = next((u for u in app.backend.load_users() if u['username'] == username), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа!"); return

        self._busy = True
        self._show_progress("Расшифровка... 0%")

        def progress(frac):
            Clock.schedule_once(lambda dt: self._show_progress(f"Расшифровка... {int(frac*100)}%"), 0)

        def run():
            try:
                out = app.backend.decrypt_file_gcm(user['private_key_path'], self.selected_file, progress)
                app.log_action(f"Расшифрован: {os.path.basename(self.selected_file)}")
                def done(dt):
                    self._busy = False; self._hide_progress()
                    show_msg("Готово", f"Расшифрован!\nСохранён: {os.path.basename(out)}\nПапка: {os.path.dirname(out)}")
                Clock.schedule_once(done, 0)
            except Exception as e:
                def err(dt):
                    self._busy = False; self._hide_progress()
                    show_msg("Ошибка расшифровки", str(e))
                Clock.schedule_once(err, 0)

        threading.Thread(target=run, daemon=True).start()


class GroupScreen(Screen):
    def on_enter(self):
        from kivy.uix.checkbox import CheckBox
        layout = self.ids.group_users_layout
        layout.clear_widgets()
        t = App.get_running_app().theme
        self.checkboxes = {}
        for u in App.get_running_app().backend.load_users():
            if u.get('public_key_path'):
                row = BoxLayout(size_hint_y=None, height=dp(46), padding=[dp(6), 0, dp(6), 0])
                chk = CheckBox(size_hint_x=None, width=dp(40), color=t['accent'])
                lbl = Label(text=u['username'], color=t['input_fg'], halign='left',
                            text_size=(Window.width - dp(80), None))
                row.add_widget(chk); row.add_widget(lbl)
                layout.add_widget(row)
                self.checkboxes[u['username']] = chk

    def encrypt_group(self):
        text = self.ids.group_input.text.strip()
        if not text: show_msg("Ошибка", "Введите текст!"); return
        selected_names = [n for n, c in self.checkboxes.items() if c.active]
        if not selected_names: show_msg("Ошибка", "Выберите хотя бы одного получателя!"); return
        backend = App.get_running_app().backend
        users   = backend.load_users()
        # Собираем список путей к публичным ключам — имена в JSON не попадут
        pub_paths = []
        for name in selected_names:
            u = next((u for u in users if u['username'] == name), None)
            if u and u.get('public_key_path'):
                pub_paths.append(u['public_key_path'])
        if not pub_paths:
            show_msg("Ошибка", "Нет публичных ключей у выбранных!"); return
        try:
            res = backend.encrypt_group(pub_paths, text)
            self.ids.group_input.text = res
            if self.ids.group_auto_copy.active:
                Clipboard.copy(res)
                show_msg("Успех", "Зашифровано и скопировано в буфер!")
            else:
                show_msg("Успех", "Сообщение зашифровано!")
            App.get_running_app().log_action("Групповое шифрование")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def decrypt_group(self):
        text = self.ids.group_input.text.strip()
        if not text: show_msg("Ошибка", "Вставьте JSON!"); return
        try:
            res = App.get_running_app().backend.decrypt_group(text)
            self.ids.group_input.text = res
            show_msg("Успех", "Сообщение расшифровано!")
            App.get_running_app().log_action("Групповая расшифровка")
        except Exception as e:
            show_msg("Ошибка", str(e))

    def clear_field(self):
        self.ids.group_input.text = ''

    def paste_from_clipboard(self):
        txt = Clipboard.paste()
        if txt:
            self.ids.group_input.text = txt


# ==================== LEGACY ЭКРАН ====================

class LegacyScreen(Screen):
    """Прямое RSA-OAEP без AES-обёртки — совместимость со старой консольной версией."""

    def on_enter(self):
        users = App.get_running_app().backend.load_users()
        enc_users = [u['username'] for u in users if u.get('public_key_path')]
        dec_users = [u['username'] for u in users if u.get('private_key_path')]

        self.ids.enc_spinner.values = enc_users
        self.ids.dec_spinner.values = dec_users

        if dec_users and self.ids.dec_spinner.text not in dec_users:
            self.ids.dec_spinner.text = dec_users[0]
        elif not dec_users:
            self.ids.dec_spinner.text = 'Нет приватных ключей'

    def clear_field(self):
        self.ids.legacy_input.text = ''

    def paste_clipboard(self):
        txt = Clipboard.paste()
        if txt:
            self.ids.legacy_input.text = txt

    def encrypt_action(self):
        username = self.ids.enc_spinner.text
        text = self.ids.legacy_input.text.strip()
        if not username or username == 'Выберите пользователя':
            show_msg("Ошибка", "Выберите пользователя для шифрования!"); return
        if not text:
            show_msg("Ошибка", "Введите текст!"); return
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('public_key_path'):
            show_msg("Ошибка", "Нет публичного ключа!"); return
        try:
            res = backend.encrypt_text_legacy(user['public_key_path'], text)
            self.ids.legacy_input.text = res
            if self.ids.legacy_auto_copy.active:
                Clipboard.copy(res)
                show_msg("Успех", "Зашифровано (Legacy) и скопировано!")
            else:
                show_msg("Успех", "Текст зашифрован (Legacy)!")
            App.get_running_app().log_action(f"Legacy шифрование для {username}")
        except Exception as e:
            show_msg("Ошибка шифрования", str(e))

    def decrypt_action(self):
        username = self.ids.dec_spinner.text
        text = self.ids.legacy_input.text.strip()
        if not username or username == 'Нет приватных ключей':
            show_msg("Ошибка", "Нет пользователя с приватным ключом!"); return
        if not text:
            show_msg("Ошибка", "Вставьте base64-строку для расшифровки!"); return
        backend = App.get_running_app().backend
        user = next((u for u in backend.load_users() if u['username'] == username), None)
        if not user or not user.get('private_key_path'):
            show_msg("Ошибка", "Нет приватного ключа!"); return
        try:
            res = backend.decrypt_text_legacy(user['private_key_path'], text)
            self.ids.legacy_input.text = res
            show_msg("Успех", "Текст расшифрован (Legacy)!")
            App.get_running_app().log_action(f"Legacy расшифровка для {username}")
        except Exception as e:
            show_msg("Ошибка расшифровки", str(e))


# ==================== НАСТРОЙКИ ====================

COLOR_LABELS = {
    "bg_color":    "Фон приложения",
    "btn_bg":      "Фон кнопок",
    "btn_border":  "Рамка кнопок",
    "btn_text":    "Текст кнопок",
    "accent":      "Акцентный цвет",
    "input_bg":    "Фон поля ввода",
    "input_fg":    "Текст в полях",
    "title_color": "Заголовки",
    "label_muted": "Второстепенный текст",
    "danger_bg":   "Цвет опасных кнопок",
    "success_bg":  "Цвет успеха",
    "log_bg":      "Фон логов",
}

def rgba_to_hex(rgba):
    return "#{:02X}{:02X}{:02X}".format(int(rgba[0]*255), int(rgba[1]*255), int(rgba[2]*255))

def hex_to_rgba(s, alpha=1.0):
    s = s.strip().lstrip('#')
    if len(s) == 6:
        return [int(s[0:2],16)/255, int(s[2:4],16)/255, int(s[4:6],16)/255, alpha]
    return [1,1,1,1]


class SettingsScreen(Screen):
    _color_inputs = {}

    def on_enter(self):
        self._color_inputs = {}
        self.ids.preset_spinner.values = list(THEME_PRESETS.keys())
        self._build_color_rows()

    def _build_color_rows(self):
        box = self.ids.color_rows
        box.clear_widgets()
        self._color_inputs = {}
        t = App.get_running_app().theme

        for key, label in COLOR_LABELS.items():
            row  = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(8),
                             padding=[dp(4), dp(5), dp(4), dp(5)])
            rgba = t.get(key, [1,1,1,1])

            # Цветной квадрат
            preview = Widget(size_hint_x=None, width=dp(34))
            with preview.canvas:
                Color(*rgba)
                rr = RoundedRectangle(pos=(preview.x, preview.y),
                                      size=(preview.width, preview.height), radius=[dp(5)])

            def _bind_preview(prev_widget, rr_inst):
                def upd(inst, val):
                    rr_inst.pos  = inst.pos
                    rr_inst.size = inst.size
                prev_widget.bind(pos=upd, size=upd)
            _bind_preview(preview, rr)

            name_lbl = Label(text=label, color=t['label_muted'], font_size='13sp',
                             size_hint_x=0.55, halign='left',
                             text_size=(Window.width * 0.45, None))

            inp = TextInput(text=rgba_to_hex(rgba), size_hint_x=0.35,
                            size_hint_y=None, height=dp(40),
                            background_color=t['input_bg'], foreground_color=t['input_fg'],
                            font_size='13sp', multiline=False,
                            use_bubble=False, use_handles=False)
            self._color_inputs[key] = inp

            def _make_live(pv, rr_ref, k):
                def on_text(inst, val):
                    try:
                        c = hex_to_rgba(val, App.get_running_app().theme.get(k,[1,1,1,1])[3])
                        pv.canvas.clear()
                        with pv.canvas:
                            Color(*c)
                            RoundedRectangle(pos=pv.pos, size=pv.size, radius=[dp(5)])
                    except: pass
                return on_text
            inp.bind(text=_make_live(preview, rr, key))

            row.add_widget(preview); row.add_widget(name_lbl); row.add_widget(inp)
            box.add_widget(row)

    def apply_preset(self, name):
        preset = THEME_PRESETS.get(name)
        if not preset: return
        app = App.get_running_app()
        app.theme = dict(preset)
        app._apply_theme()
        self._build_color_rows()

    def save_settings(self):
        app = App.get_running_app()
        new_theme = dict(app.theme)
        for key, inp in self._color_inputs.items():
            try:
                alpha = app.theme.get(key, [1,1,1,1])[3]
                new_theme[key] = hex_to_rgba(inp.text, alpha)
            except: pass
        app.theme = new_theme
        app._apply_theme()
        show_msg("Настройки", "Тема сохранена!")

    def show_logs(self):
        app = App.get_running_app()
        t   = app.theme
        if not app.action_log:
            show_msg("Логи", "Пока нет записей.\nДействия появляются здесь автоматически\n(шифрование, расшифровка, выбор файлов и т.д.).")
            return
        sv  = ScrollView()
        box = BoxLayout(orientation='vertical', size_hint_y=None, spacing=dp(2), padding=dp(8))
        box.bind(minimum_height=box.setter('height'))
        for line in reversed(app.action_log):
            lbl = Label(text=line, size_hint_y=None, height=dp(30), halign='left',
                        valign='middle', color=t['input_fg'], font_size='12sp')
            lbl.bind(width=lambda i, v: setattr(i, 'text_size', (v, None)))
            box.add_widget(lbl)
        sv.add_widget(box)
        mv = ModalView(size_hint=(0.96, 0.86), background_color=t['log_bg'])
        outer = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(8))
        outer.add_widget(Label(text="Логи приложения", font_size='16sp', bold=True,
                               color=t['title_color'], size_hint_y=None, height=dp(36)))
        outer.add_widget(sv)
        btn = Button(text='Закрыть', size_hint_y=None, height=dp(44),
                     background_normal='', background_color=t['btn_bg'], color=t['btn_text'])
        btn.bind(on_release=mv.dismiss)
        outer.add_widget(btn)
        mv.add_widget(outer)
        mv.open()

    def show_changelog(self):
        changelog = (
            "SCmess v1.7\n\n"
            "НОВОЕ:\n"
            "• Потоковое шифрование файлов — теперь файлы любого размера\n"
            "  шифруются блоками по 64 КБ в фоновом потоке, интерфейс\n"
            "  не зависает, показывается прогресс в процентах.\n\n"
            "• Фикс RSA-2048: заголовок файла теперь хранит точную длину\n"
            "  RSA-блока (2 байта), что обеспечивает совместимость ключей\n"
            "  любого размера (2048 и 4096 бит).\n\n"
            "• Файлы сохраняются рядом с оригиналом. Если папка недоступна\n"
            "  (Document UI) — автоматически в Download.\n\n"
            "• Экран файлов: два отдельных спиннера для шифрования\n"
            "  (публичный ключ) и расшифровки (приватный ключ по умолчанию).\n\n"
            "• Быстрое копирование файлов через Document UI:\n"
            "  ParcelFileDescriptor + os.read() вместо побайтового JNI.\n\n"
            "• Автоопределение типа ключа (PRIVATE/PUBLIC) при импорте\n"
            "  из файла и текстом. Один пользователь может иметь оба ключа.\n\n"
            "• Fingerprint ключей в карточке пользователя (SHA-256, 8 байт).\n\n"
        )
        show_msg("Что нового в v1.7", changelog)


# ==================== APP ====================

class SCMessApp(App):
    # DictProperty: KV-биндинги срабатывают при замене значения по ключу
    theme = DictProperty(DEFAULT_THEME.copy())

    def _apply_theme(self):
        """Применить тему немедленно без перезапуска.
        Заменяем весь dict целиком — это гарантированно триггерит все KV-биндинги."""
        Window.clearcolor = tuple(self.theme.get('bg_color', [0.05, 0.05, 0.08, 1]))
        self.save_theme()
        # Копируем текущие значения и переприсваиваем — DictProperty пошлёт событие
        snapshot = dict(self.theme)
        self.theme = snapshot

    def build(self):
        if platform == 'android':
            try:
                from android.permissions import request_permissions, Permission
                request_permissions([
                    Permission.READ_EXTERNAL_STORAGE,
                    Permission.WRITE_EXTERNAL_STORAGE,
                    Permission.READ_MEDIA_IMAGES,
                    Permission.READ_MEDIA_VIDEO,
                    Permission.READ_MEDIA_AUDIO,
                ])
            except Exception:
                pass

        self.dev_mode   = False
        self.action_log = []
        self.backend    = CryptoBackend(self.user_data_dir)

        global SETTINGS_FILE
        SETTINGS_FILE = os.path.join(self.user_data_dir, "settings.json")
        self._load_theme_from_disk()

        Builder.load_string(KV)

        sm = ScreenManager(transition=NoTransition())
        sm.add_widget(MenuScreen(name='menu'))
        sm.add_widget(KeysScreen(name='keys'))
        sm.add_widget(TextScreen(name='text'))
        sm.add_widget(FileScreen(name='files'))
        sm.add_widget(GroupScreen(name='group'))
        sm.add_widget(LegacyScreen(name='legacy'))
        sm.add_widget(SettingsScreen(name='settings'))
        return sm

    def _load_theme_from_disk(self):
        try:
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE) as f:
                    data = json.load(f)
                if 'theme' in data:
                    merged = dict(DEFAULT_THEME)
                    merged.update(data['theme'])
                    self.theme = merged
        except Exception:
            self.theme = dict(DEFAULT_THEME)
        Window.clearcolor = tuple(self.theme.get('bg_color', [0.05, 0.05, 0.08, 1]))

    def save_theme(self):
        try:
            data = {}
            if SETTINGS_FILE and os.path.exists(SETTINGS_FILE):
                try:
                    with open(SETTINGS_FILE) as f: data = json.load(f)
                except: pass
            data['theme'] = self.theme
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def log_action(self, message):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        self.action_log.append(entry)
        if len(self.action_log) > 200:
            self.action_log.pop(0)


if __name__ == '__main__':
    SCMessApp().run()
