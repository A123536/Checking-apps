QT += core gui widgets sql network testlib concurrent
HEADERS += ../NewAnalysis/BoardIdentity.h
HEADERS += ../RcaTrace.h ../OpbSnapshotAnalyzer.h
CONFIG += console c++11 testcase
CONFIG -= app_bundle
TEMPLATE = app
TARGET = DiagnosisUiTests
INCLUDEPATH += .. ../NewAnalysis
SOURCES += DiagnosisUiTests.cpp ../DiagnosisPage.cpp ../OpbDiagnosticAnalyzer.cpp ../OpbSnapshotAnalyzer.cpp ../OpbFaultSampleStore.cpp ../NewAnalysis/OpbBaselineAnalyzer.cpp \
    ../MainWindow.cpp ../DeepSeekClient.cpp ../LegacyParserAdapter.cpp ../NewAnalysis/ReadThread.cpp \
    ../NewAnalysis/readword.cpp ../NewAnalysis/Common/common.cpp
HEADERS += ../DiagnosisPage.h ../OpbDiagnosticAnalyzer.h ../OpbFaultSampleStore.h ../NewAnalysis/OpbBaselineAnalyzer.h \
    ../NewAnalysis/LogCsvReader.h \
    ../MainWindow.h ../DeepSeekClient.h ../LegacyParserAdapter.h ../NewAnalysis/ReadThread.h ../NewAnalysis/readword.h
INCLUDEPATH += ../NewAnalysis/Common
win32:LIBS += -ladvapi32
