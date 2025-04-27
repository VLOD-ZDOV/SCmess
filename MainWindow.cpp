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
#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QDialogButtonBox>
#include <QDateTime>
#include <QFile>

extern "C" {
    #include "CCmess.h"
}

#define KEYS_FILE "keys.json"
#define LOG_FILE "app.log"

// Конструктор
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    auto *tabs = new QTabWidget(this);
    tabs->addTab(createKeysTab(), "Ключи");
    tabs->addTab(createTextTab(), "Текст");
    tabs->addTab(createFileTab(), "Файлы");
    tabs->addTab(createLogsTab(), "Логи");
    setCentralWidget(tabs);
    setWindowTitle("SCmess-on-C");
    resize(800, 600);

    // Initialize log file
    QFile logFile(LOG_FILE);
    if (logFile.open(QIODevice::WriteOnly | QIODevice::Append)) {
        logFile.close();
    }
    logMessage("Application started");
}

void MainWindow::logMessage(const QString &message) {
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    QString logEntry = QString("[%1] %2").arg(timestamp, message);
    logEdit->append(logEntry);

    QFile logFile(LOG_FILE);
    if (logFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QTextStream out(&logFile);
        out << logEntry << "\n";
        logFile.close();
    }
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

// Создание вкладки для логов
QWidget* MainWindow::createLogsTab() {
    auto *widget = new QWidget;
    auto *layout = new QVBoxLayout(widget);

    logEdit = new QTextEdit;
    logEdit->setReadOnly(true);
    layout->addWidget(logEdit);

    return widget;
}

void MainWindow::createKeys() {
    QDialog dialog(this);
    dialog.setWindowTitle("Создать ключи");

    QFormLayout *formLayout = new QFormLayout;
    QLineEdit *usernameEdit = new QLineEdit;
    QCheckBox *useCustomGen = new QCheckBox("Генерация без OpenSSL");
    QComboBox *keySizeCombo = new QComboBox;
    keySizeCombo->addItem("4096 бит", 4096);
    keySizeCombo->addItem("2048 бит", 2048);
    keySizeCombo->setCurrentIndex(0);

    formLayout->addRow("Имя пользователя:", usernameEdit);
    formLayout->addRow("", useCustomGen);
    formLayout->addRow("Размер ключа:", keySizeCombo);

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    formLayout->addRow(buttonBox);

    dialog.setLayout(formLayout);

    if (dialog.exec() != QDialog::Accepted) return;

    QString username = usernameEdit->text();
    if (username.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Имя пользователя не может быть пустым");
        logMessage("Ошибка: Имя пользователя пустое при создании ключей");
        return;
    }

    char *pub = nullptr, *priv = nullptr;
    int result;
    if (useCustomGen->isChecked()) {
        int keySize = keySizeCombo->currentData().toInt();
        result = generate_key_pair_custom(username.toUtf8().constData(), keySize, &pub, &priv);
    } else {
        result = generate_key_pair(username.toUtf8().constData(), &pub, &priv);
    }

    if (result == 0) {
        save_keys_to_json(username.toUtf8().constData(), pub, priv);
        QMessageBox::information(this, "Успех",
                                 QString("Ключи созданы:\nПубличный: %1\nПриватный: %2").arg(pub).arg(priv));
        logMessage(QString("Ключи созданы для %1: Публичный=%2, Приватный=%3").arg(username, pub, priv));
        free(pub);
        free(priv);
    } else {
        QMessageBox::critical(this, "Ошибка", QString("Ошибка генерации ключей: код %1").arg(result));
        logMessage(QString("Ошибка генерации ключей для %1: код %2").arg(username).arg(result));
    }
}

void MainWindow::addKey() {
    bool ok;
    QString username = QInputDialog::getText(this, "Добавить ключ",
                                             "Имя пользователя:", QLineEdit::Normal, "", &ok);
    if (!ok || username.isEmpty()) {
        logMessage("Добавление ключа отменено: пустое имя пользователя");
        return;
    }

    QStringList types = {"Публичный", "Приватный"};
    QString type = QInputDialog::getItem(this, "Тип ключа",
                                         "Выберите тип ключа:", types, 0, false, &ok);
    if (!ok) {
        logMessage("Добавление ключа отменено: тип ключа не выбран");
        return;
    }

    QString keyPath = QFileDialog::getOpenFileName(this,
                                                   "Выберите ключ", "", "PEM Files (*.pem)");
    if (keyPath.isEmpty()) {
        logMessage("Добавление ключа отменено: файл ключа не выбран");
        return;
    }

    QFile keyFile(keyPath);
    if (!keyFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключа");
        logMessage(QString("Ошибка: Не удалось открыть файл ключа %1").arg(keyPath));
        return;
    }

    QByteArray keyData = keyFile.readAll();
    bool isPublic = type == "Публичный";
    if ((isPublic && !keyData.contains("PUBLIC KEY")) ||
        (!isPublic && !keyData.contains("PRIVATE KEY"))) {
        QMessageBox::critical(this, "Ошибка", "Некорректный формат ключа");
    logMessage(QString("Ошибка: Некорректный формат ключа %1").arg(keyPath));
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
        if (isPublic) {
            newKey["public_key_path"] = QDir::toNativeSeparators(keyPath);
        } else {
            newKey["private_key_path"] = QDir::toNativeSeparators(keyPath);
        }

        keysArray.append(newKey);

        jsonFile.open(QIODevice::WriteOnly);
        jsonFile.write(QJsonDocument(keysArray).toJson());
        jsonFile.close();

        QMessageBox::information(this, "Успех", "Ключ успешно добавлен");
        logMessage(QString("Ключ добавлен: %1, тип=%2, путь=%3").arg(username, type, keyPath));
}

void MainWindow::showUsers() {
    QFile jsonFile(KEYS_FILE);
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::information(this, "Ошибка", "Файл ключей не найден");
        logMessage("Ошибка: Файл ключей не найден при показе пользователей");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::information(this, "Информация", "Список пользователей пуст");
        logMessage("Список пользователей пуст");
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
    logMessage("Показан список пользователей");
}

void MainWindow::deleteUser() {
    QFile jsonFile(KEYS_FILE);
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::information(this, "Ошибка", "Файл ключей не найден");
        logMessage("Ошибка: Файл ключей не найден при удалении пользователя");
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
    if (!ok || user.isEmpty()) {
        logMessage("Удаление пользователя отменено");
        return;
    }

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
    logMessage(QString("Пользователь %1 удалён").arg(user));
}

void MainWindow::autoscanKeys() {
    QStringList types = {"Публичный", "Приватный"};
    bool ok;
    QString type = QInputDialog::getItem(this, "Автопоиск",
                                         "Тип ключа:", types, 0, false, &ok);
    if (!ok) {
        logMessage("Автопоиск ключей отменен: тип ключа не выбран");
        return;
    }

    const char *key_type = (type == "Публичный") ? "public" : "private";
    int count = 0;
    char **foundKeys = scan_for_keys(key_type, &count);

    if (count == 0) {
        QMessageBox::information(this, "Результат", "Ключи не найдены");
        logMessage(QString("Автопоиск: Ключи типа %1 не найдены").arg(type));
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
        logMessage("Автопоиск: Выбор ключа отменен");
        for (int i = 0; i < count; i++) free(foundKeys[i]);
        free(foundKeys);
        return;
    }

    QString username = QInputDialog::getText(this, "Имя пользователя",
                                             "Введите имя для ключа:", QLineEdit::Normal, "", &ok);
    if (!ok || username.isEmpty()) {
        logMessage("Автопоиск: Добавление ключа отменено, имя пользователя не указано");
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
        newKey["public_key_path"] = QDir::toNativeSeparators(selected);
    } else {
        newKey["private_key_path"] = QDir::toNativeSeparators(selected);
    }

    keysArray.append(newKey);

    jsonFile.open(QIODevice::WriteOnly);
    jsonFile.write(QJsonDocument(keysArray).toJson());
    jsonFile.close();

    QMessageBox::information(this, "Успех", "Ключ добавлен");
    logMessage(QString("Ключ добавлен через автопоиск: %1, тип=%2, путь=%3").arg(username, type, selected));

    for (int i = 0; i < count; i++) free(foundKeys[i]);
    free(foundKeys);
}

void MainWindow::encryptText() {
    QFile jsonFile("keys.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключей");
        logMessage("Ошибка: Не удалось открыть файл ключей при шифровании текста");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет доступных ключей");
        logMessage("Ошибка: Нет доступных ключей при шифровании текста");
        return;
    }

    QStringList users;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj.contains("public_key_path")) {
            users << obj["username"].toString();
        }
    }

    if (users.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет публичных ключей");
        logMessage("Ошибка: Нет публичных ключей при шифровании текста");
        return;
    }

    bool ok;
    QString user = QInputDialog::getItem(this, "Выбор ключа",
                                         "Выберите пользователя для шифрования:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) {
        logMessage("Шифрование текста отменено: пользователь не выбран");
        return;
    }

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
        logMessage(QString("Текст зашифрован для пользователя %1").arg(user));
        free(encrypted);
    } else {
        QMessageBox::critical(this, "Ошибка", "Не удалось зашифровать текст");
        logMessage(QString("Ошибка: Не удалось зашифровать текст для %1").arg(user));
    }
}

void MainWindow::decryptText() {
    QFile jsonFile("keys.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключей");
        logMessage("Ошибка: Не удалось открыть файл ключей при расшифровке текста");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет доступных ключей");
        logMessage("Ошибка: Нет доступных ключей при расшифровке текста");
        return;
    }

    QStringList users;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj.contains("private_key_path")) {
            users << obj["username"].toString();
        }
    }

    if (users.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет приватных ключей для расшифровки");
        logMessage("Ошибка: Нет приватных ключей при расшифровке текста");
        return;
    }

    bool ok;
    QString user = QInputDialog::getItem(this, "Выбор ключа",
                                         "Выберите пользователя для расшифровки:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) {
        logMessage("Расшифровка текста отменена: пользователь не выбран");
        return;
    }

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
        logMessage(QString("Текст расшифрован для пользователя %1").arg(user));
        free(decrypted);
    } else {
        QMessageBox::critical(this, "Ошибка", "Не удалось расшифровать текст");
        logMessage(QString("Ошибка: Не удалось расшифровать текст для %1").arg(user));
    }
}

void MainWindow::chooseFile() {
    QString path = QFileDialog::getOpenFileName(this, "Выбор файла");
    if (!path.isEmpty()) {
        filePathEdit->setText(QDir::toNativeSeparators(path));
        logMessage(QString("Выбран файл: %1").arg(path));
    }
}

void MainWindow::encryptFile() {
    QString path = filePathEdit->text();
    if (path.isEmpty()) {
        logMessage("Шифрование файла отменено: путь не указан");
        return;
    }
    QString outPath = path + ".enc";
    if (encrypt_file(path.toUtf8().constData(), outPath.toUtf8().constData()) == 0) {
        QMessageBox::information(this, "Успех", "Файл зашифрован: " + outPath);
        logMessage(QString("Файл зашифрован: %1 -> %2").arg(path, outPath));
    } else {
        QMessageBox::critical(this, "Ошибка", "Ошибка шифрования файла");
        logMessage(QString("Ошибка шифрования файла %1").arg(path));
    }
}

void MainWindow::decryptFile() {
    QString path = filePathEdit->text();
    if (path.isEmpty()) {
        logMessage("Расшифровка файла отменена: путь не указан");
        return;
    }

    QFile jsonFile("keys.json");
    if (!jsonFile.open(QIODevice::ReadOnly)) {
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл ключей");
        logMessage("Ошибка: Не удалось открыть файл ключей при расшифровке файла");
        return;
    }

    QJsonArray keysArray = QJsonDocument::fromJson(jsonFile.readAll()).array();
    jsonFile.close();

    if (keysArray.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет доступных ключей");
        logMessage("Ошибка: Нет доступных ключей при расшифровке файла");
        return;
    }

    QStringList users;
    for (const QJsonValue &value : keysArray) {
        QJsonObject obj = value.toObject();
        if (obj.contains("private_key_path")) {
            users << obj["username"].toString();
        }
    }

    if (users.isEmpty()) {
        QMessageBox::critical(this, "Ошибка", "Нет приватных ключей для расшифровки");
        logMessage("Ошибка: Нет приватных ключей при расшифровке файла");
        return;
    }

    bool ok;
    QString user = QInputDialog::getItem(this, "Выбор ключа",
                                         "Выберите пользователя для расшифровки файла:", users, 0, false, &ok);
    if (!ok || user.isEmpty()) {
        logMessage("Расшифровка файла отменена: пользователь не выбран");
        return;
    }

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
        logMessage(QString("Файл расшифрован: %1 -> %2").arg(path, outPath));
    } else {
        QMessageBox::critical(this, "Ошибка", "Ошибка дешифровки файла");
        logMessage(QString("Ошибка дешифровки файла %1").arg(path));
    }
}
