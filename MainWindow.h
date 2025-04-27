#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QComboBox>

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    void logMessage(const QString &message);

private:
    QWidget* createKeysTab();
    QWidget* createTextTab();
    QWidget* createFileTab();
    QWidget* createLogsTab();
    void createKeys();
    void addKey();
    void showUsers();
    void deleteUser();
    void autoscanKeys();
    void encryptText();
    void decryptText();
    void chooseFile();
    void encryptFile();
    void decryptFile();

    QTextEdit *textEdit;
    QLineEdit *filePathEdit;
    QTextEdit *logEdit;
};

#endif // MAINWINDOW_H
