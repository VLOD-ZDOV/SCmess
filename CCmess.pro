QT       += core gui widgets
TARGET    = CCmess
TEMPLATE  = app
SOURCES  += main.cpp MainWindow.cpp CCmess.c
HEADERS  += MainWindow.h CCmess.h
LIBS     += -L/usr/lib -lcrypto -lcjson
INCLUDEPATH += /usr/include/cjson
