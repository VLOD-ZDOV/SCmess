#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QLineEdit>

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    QWidget *createKeysTab();
    QWidget *createTextTab();
    QWidget *createFileTab();

    QTextEdit *textEdit;
    QLineEdit *filePathEdit;

private slots:
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
};

#endif
