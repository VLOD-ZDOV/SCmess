#include "MainWindow.h"
#include <QTabWidget>
#include <QPushButton>
#include <QInputDialog>
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QDir>
#include <QRegularExpression>
#include <QVBoxLayout>
#include <QHBoxLayout>

extern "C" {
    #include "CCmess.h"
}

#define KEYS_FILE "keys.json"

// Конструктор
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    auto *tabs = new QTabWidget(this);
    tabs->addTab(createKeysTab(), "Ключи");
    tabs->addTab(createTextTab(), "Текст");
    tabs->addTab(createFileTab(), "Файлы");
    setCentralWidget(tabs);
    setWindowTitle("SCmess-on-C");
    resize(800, 600);
}

// Создание вкладки управления ключами
QWidget* MainWindow::createKeysTab() {
    auto *widget = new QWidget;
    auto *layout = new QVBoxLayout(widget);

    auto *createBtn = new QPushButton("Создать пару ключей");
    auto *addBtn = new QPushButton("Добавить ключ");
    auto *showBtn = new QPushButton("Показать пользователей");
    auto *deleteBtn = new QPushButton("Удалить пользователя");
    auto *scanBtn = new QPushButton("Автопоиск ключей");

    layout->addWidget(createBtn);
    layout->addWidget(addBtn);
    layout->addWidget(showBtn);
    layout->addWidget(deleteBtn);
    layout->addWidget(scanBtn);
    layout->addStretch();

    connect(createBtn, &QPushButton::clicked, this, &MainWindow::createKeys);
    connect(addBtn, &QPushButton::clicked, this, &MainWindow::addKey);
    connect(showBtn, &QPushButton::clicked, this, &MainWindow::showUsers);
    connect(deleteBtn, &QPushButton::clicked, this, &MainWindow::deleteUser);
    connect(scanBtn, &QPushButton::clicked, this, &MainWindow::autoscanKeys);

    return widget;
}

// Создание вкладки для работы с текстом
QWidget* MainWindow::createTextTab() {
    auto *widget = new QWidget;
    auto *layout = new QVBoxLayout(widget);

    textEdit = new QTextEdit;
    layout->addWidget(textEdit);

    auto *btnLayout = new QHBoxLayout;
    auto *encBtn = new QPushButton("Зашифровать");
    auto *decBtn = new QPushButton("Расшифровать");
    btnLayout->addWidget(encBtn);
    btnLayout->addWidget(decBtn);

    layout->addLayout(btnLayout);

    connect(encBtn, &QPushButton::clicked, this, &MainWindow::encryptText);
    connect(decBtn, &QPushButton::clicked, this, &MainWindow::decryptText);

    return widget;
}

// Создание вкладки для работы с файлами
QWidget* MainWindow::createFileTab() {
    auto *widget = new QWidget;
    auto *layout = new QVBoxLayout(widget);

    filePathEdit = new QLineEdit;
    layout->addWidget(filePathEdit);

    auto *btnLayout = new QHBoxLayout;
    auto *chooseBtn = new QPushButton("Выбрать файл");
    auto *encBtn = new QPushButton("Зашифровать файл");
    auto *decBtn = new QPushButton("Расшифровать файл");
    btnLayout->addWidget(chooseBtn);
    btnLayout->addWidget(encBtn);
    btnLayout->addWidget(decBtn);

    layout->addLayout(btnLayout);

    connect(chooseBtn, &QPushButton::clicked, this, &MainWindow::chooseFile);
    connect(encBtn, &QPushButton::clicked, this, &MainWindow::encryptFile);
    connect(decBtn, &QPushButton::clicked, this, &MainWindow::decryptFile);

    return widget;
}

void MainWindow::createKeys() {
    bool ok;
    QString username = QInputDialog::getText(this, "Создать ключи",
                                             "Имя пользователя:", QLineEdit::Normal, "", &ok);

    if (!ok || username.isEmpty()) return;

    char *pub = nullptr, *priv = nullptr;
    if (generate_key_pair(username.toUtf8().constData(), &pub, &priv) == 0) {
        save_keys_to_json(username.toUtf8().constData(), pub, priv);
        QMessageBox::information(this, "Успех",
                                 QString("Ключи созданы:\nПубличный: %1\nПриватный: %2").arg(pub).arg(priv));
        free(pub);
        free(priv);
    } else {
        QMessageBox::critical(this, "Ошибка", "Ошибка генерации ключей");
    }
}

void MainWindow::addKey() {
    bool ok;
    QString username = QInputDialog::getText(this, "Добавить ключ",
                                             "Имя пользователя:", QLineEdit::Normal, "", &ok);
    if (!ok || username.isEmpty()) return;

    QStringList types = {"Публичный", "Приватный"};
    QString type = QInputDialog::getItem(this, "Тип ключа",
                                         "Выберите тип ключа:", types, 0, false, &ok);
    if (!ok) return;

    QString keyPath = QFileDialog::getOpenFileName(this,
                                                   "Выберите ключ", "", "PEM Files (*.pem)");
    if (keyPath.isEmpty()) return;

    QFile keyFile(keyPath);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключа");
        return;
    }

    // Проверка формата ключа
    QByteArray keyData = keyFile.readAll();
    bool isPublic = type == "Публичный";
    if ((isPublic && !keyData.contains("PUBLIC KEY")) ||
        (!isPublic && !keyData.contains("PRIVATE KEY"))) {
        QMessageBox::critical(this, "Ошибка", "Некорректный формат ключа");
    return;
        }

        // Сохранение в JSON
        QFile jsonFile(KEYS_FILE);
        QJsonArray keysArray;

        if (jsonFile.exists()) {
            jsonFile.open(QIODevice::ReadOnly);
            keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
            jsonFile.close();
        }

        QJsonObject newKey;
        newKey["username"] = username;
        if (isPublic) {
            newKey["public_key_path"] = keyPath;
        } else {
            newKey["private_key_path"] = keyPath;
        }

        keysArray.append(newKey);

        jsonFile.open(QIODevice::WriteOnly);
        jsonFile.write(QJsonDocument(keysArray).toJson());
        jsonFile.close();

        QMessageBox::information(this, "Успех", "Ключ успешно добавлен");
}

void MainWindow::showUsers() {
    QFile jsonFile(KEYS_FILE);
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::information(this, "Ошибка", "Файл ключей не найден");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::information(this, "Информация", "Список пользователей пуст");
        return;
    }

    QString info = "Список пользователей:\n\n";
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        info += QString("Пользователь: %1\nПубличный: %2\nПриватный: %3\n\n")
        .arg(obj["username"].toString())
        .arg(obj["public_key_path"].toString("Не указан"))
        .arg(obj["private_key_path"].toString("Не указан"));
    }

    QMessageBox::information(this, "Пользователи", info);
}

void MainWindow::deleteUser() {
    QFile jsonFile(KEYS_FILE);
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::information(this, "Ошибка", "Файл ключей не найден");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    QStringList users;
    for (const QJsonValue &value : keysArray) {
        users << value.toObject()["username"].toString();
    }

    bool ok;
    QString user = QInputDialog::getItem(this, "Удаление",
                                         "Выберите пользователя:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) return;

    QJsonArray newArray;
    for (const QJsonValue &value : keysArray) {
        if (value.toObject()["username"].toString() != user) {
            newArray.append(value);
        }
    }

    jsonFile.open(QIODevice::WriteOnly);
    jsonFile.write(QJsonDocument(newArray).toJson());
    jsonFile.close();

    QMessageBox::information(this, "Успех", "Пользователь удалён");
}

void MainWindow::autoscanKeys() {
    QStringList types = {"Публичный", "Приватный"};
    bool ok;
    QString type = QInputDialog::getItem(this, "Автопоиск",
                                         "Тип ключа:", types, 0, false, &ok);
    if (!ok) return;

    const char *key_type = (type == "Публичный") ? "public" : "private";
    int count = 0;
    char **foundKeys = scan_for_keys(key_type, &count);

    if (count == 0) {
        QMessageBox::information(this, "Результат", "Ключи не найдены");
        for (int i = 0; i < count; i++) free(foundKeys[i]);
        free(foundKeys);
        return;
    }

    QStringList keyList;
    for (int i = 0; i < count; i++) {
        keyList << QString(foundKeys[i]);
    }

    QString selected = QInputDialog::getItem(this, "Выбор ключа",
                                             "Найденные ключи:", keyList, 0, false, &ok);
    if (!ok || selected.isEmpty()) {
        for (int i = 0; i < count; i++) free(foundKeys[i]);
        free(foundKeys);
        return;
    }

    QString username = QInputDialog::getText(this, "Имя пользователя",
                                             "Введите имя для ключа:", QLineEdit::Normal, "", &ok);
    if (!ok || username.isEmpty()) {
        for (int i = 0; i < count; i++) free(foundKeys[i]);
        free(foundKeys);
        return;
    }

    QFile jsonFile(KEYS_FILE);
    QJsonArray keysArray;
    if (jsonFile.exists()) {
        jsonFile.open(QIODevice::ReadOnly);
        keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
        jsonFile.close();
    }

    QJsonObject newKey;
    newKey["username"] = username;
    if (type == "Публичный") {
        newKey["public_key_path"] = selected;
    } else {
        newKey["private_key_path"] = selected;
    }

    keysArray.append(newKey);

    jsonFile.open(QIODevice::WriteOnly);
    jsonFile.write(QJsonDocument(keysArray).toJson());
    jsonFile.close();

    QMessageBox::information(this, "Успех", "Ключ добавлен");

    for (int i = 0; i < count; i++) free(foundKeys[i]);
    free(foundKeys);
}

void MainWindow::encryptText() {
    // Читаем ключи из keys.json
    QFile jsonFile("keys.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключей");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет доступных ключей");
        return;
    }

    // Формируем список пользователей с публичными ключами
    QStringList users;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj.contains("public_key_path")) {
            users << obj["username"].toString();
        }
    }

    if (users.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет публичных ключей");
        return;
    }

    // Запрашиваем выбор пользователя
    bool ok;
    QString user = QInputDialog::getItem(this, "Выбор ключа",
                                         "Выберите пользователя для шифрования:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) return;

    // Находим путь к публичному ключу
    QString pubKeyPath;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj["username"].toString() == user) {
            pubKeyPath = obj["public_key_path"].toString();
            break;
        }
    }

    auto plain = textEdit->toPlainText().toUtf8();
    char *encrypted = nullptr;
    if (encrypt_text(plain.constData(), pubKeyPath.toUtf8().constData(), &encrypted) == 0) {
        textEdit->setPlainText(QString::fromUtf8(encrypted));
        free(encrypted);
    } else {
        QMessageBox::critical(this, "Ошибка", "Не удалось зашифровать текст");
    }
}

void MainWindow::decryptText() {
    // Читаем ключи из keys.json
    QFile jsonFile("keys.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключей");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет доступных ключей");
        return;
    }

    // Формируем список пользователей с приватными ключами
    QStringList users;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj.contains("private_key_path")) {
            users << obj["username"].toString();
        }
    }

    if (users.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет приватных ключей для расшифровки");
        return;
    }

    // Запрашиваем выбор пользователя
    bool ok;
    QString user = QInputDialog::getItem(this, "Выбор ключа",
                                         "Выберите пользователя для расшифровки:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) return;

    // Находим путь к приватному ключу
    QString privKeyPath;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj["username"].toString() == user) {
            privKeyPath = obj["private_key_path"].toString();
            break;
        }
    }

    auto cipher = textEdit->toPlainText().toUtf8();
    char *decrypted = nullptr;
    if (decrypt_text(cipher.constData(), privKeyPath.toUtf8().constData(), &decrypted) == 0) {
        textEdit->setPlainText(QString::fromUtf8(decrypted));
        free(decrypted);
    } else {
        QMessageBox::critical(this, "Ошибка", "Не удалось расшифровать текст");
    }
}

void MainWindow::chooseFile() {
    QString path = QFileDialog::getOpenFileName(this, "Выбор файла");
    if (!path.isEmpty()) filePathEdit->setText(path);
}

void MainWindow::encryptFile() {
    QString path = filePathEdit->text();
    if (path.isEmpty()) return;
    QString outPath = path + ".enc";
    if (encrypt_file(path.toUtf8().constData(), outPath.toUtf8().constData()) == 0) {
        QMessageBox::information(this, "Успех", "Файл зашифрован: " + outPath);
    } else {
        QMessageBox::critical(this, "Ошибка", "Ошибка шифрования файла");
    }
}

void MainWindow::decryptFile() {
    QString path = filePathEdit->text();
    if (path.isEmpty()) return;

    // Читаем ключи из keys.json
    QFile jsonFile("keys.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключей");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет доступных ключей");
        return;
    }

    // Формируем список пользователей с приватными ключами
    QStringList users;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj.contains("private_key_path")) {
            users << obj["username"].toString();
        }
    }

    if (users.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет приватных ключей для расшифровки");
        return;
    }

    // Запрашиваем выбор пользователя
    bool ok;
    QString user = QInputDialog::getItem(this, "Выбор ключа",
                                         "Выберите пользователя для расшифровки файла:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) return;

    // Находим путь к приватному ключу
    QString privKeyPath;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj["username"].toString() == user) {
            privKeyPath = obj["private_key_path"].toString();
            break;
        }
    }

    QString outPath = path + ".dec";
    if (decrypt_file(path.toUtf8().constData(), outPath.toUtf8().constData(), privKeyPath.toUtf8().constData()) == 0) {
        QMessageBox::information(this, "Успех", "Файл расшифрован: " + outPath);
    } else {
        QMessageBox::critical(this, "Ошибка", "Ошибка дешифровки файла");
    }
}
