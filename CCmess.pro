QT       += core gui widgets
TARGET    = CCmess
TEMPLATE  = app

# Source files
SOURCES  += main.cpp \
            MainWindow.cpp \
            CCmess.c \
            rsa_keygen_2048.c \
            rsa_keygen_4096.c

# Header files
HEADERS  += MainWindow.h \
            CCmess.h \
            rsa_keygen.h

# Compiler flags
QMAKE_CFLAGS += -std=c99

# Platform-specific settings
unix {
    LIBS += -L/usr/lib -lcrypto -lssl -lcjson -lgmp -lpthread
    INCLUDEPATH += /usr/include \
                   /usr/include/cjson \
                   /usr/include/openssl \
                   /usr/include/gmp
}

win32 {
    # Adjust these paths based on your Windows installation
    LIBS += -L"C:/OpenSSL-Win64/lib" -lcrypto -lssl
    LIBS += -L"C:/path/to/gmp/lib" -lgmp
    LIBS += -L"C:/path/to/cjson/lib" -lcjson
    LIBS += -lws2_32  # For Windows socket functions, if needed
    INCLUDEPATH += "C:/OpenSSL-Win64/include" \
                   "C:/path/to/gmp/include" \
                   "C:/path/to/cjson/include"
    # Ensure MSVC uses correct C standard
    QMAKE_CFLAGS += /std:c99
}
