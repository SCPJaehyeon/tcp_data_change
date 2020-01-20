TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnetfilter_queue
SOURCES += \
        cpp/check_checksum.cpp \
        cpp/main.cpp \
        cpp/show.cpp \

HEADERS += \
        header/header.h \
