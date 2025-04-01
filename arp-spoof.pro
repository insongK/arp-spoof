TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
        function.cpp \
        main.cpp

HEADERS += \
        pch.h \
        headers.h \
        function.h
