QT += core gui widgets sql testlib
CONFIG += console c++11 testcase
TEMPLATE = app
TARGET = SourceQueryTests
SOURCES += SourceQueryTests.cpp
HEADERS += ../plugin/SourceQueryInterface.h
HEADERS += ../../NewAnalysis/BoardIdentity.h
win32:QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
