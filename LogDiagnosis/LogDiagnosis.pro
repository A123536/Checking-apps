QT += core gui widgets sql network concurrent

CONFIG += c++11
TEMPLATE = app
TARGET = LogDiagnosis

SOURCES += \
    DeepSeekClient.cpp \
    LegacyParserAdapter.cpp \
    MainWindow.cpp \
    OpbFaultSampleStore.cpp \
    OpbDiagnosticAnalyzer.cpp \
    OpbSnapshotAnalyzer.cpp \
    main.cpp \
    ../NewAnalysis/Common/common.cpp \
    ../NewAnalysis/OpbBaselineAnalyzer.cpp \
    ../NewAnalysis/ReadThread.cpp \
    ../NewAnalysis/readword.cpp

HEADERS += \
    RcaTrace.h \
    ../NewAnalysis/BoardIdentity.h \
    ../NewAnalysis/LogCsvReader.h \
    ../NewAnalysis/LogTaskControl.h \
    DeepSeekClient.h \
    LegacyParserAdapter.h \
    MainWindow.h \
    OpbFaultSampleStore.h \
    OpbDiagnosticAnalyzer.h \
    OpbSnapshotAnalyzer.h \
    ../NewAnalysis/Common/common.h \
    ../NewAnalysis/OpbBaselineAnalyzer.h \
    ../NewAnalysis/ReadThread.h \
    ../NewAnalysis/readword.h

INCLUDEPATH += \
    ../NewAnalysis \
    ../NewAnalysis/Common

RC_ICONS = ../NewAnalysis/cat.ico

win32:LIBS += -ladvapi32
