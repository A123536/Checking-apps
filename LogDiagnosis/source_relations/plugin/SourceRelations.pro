QT += core gui widgets sql
CONFIG += plugin c++11
TEMPLATE = lib
TARGET = SourceRelations
SOURCES += SourceRelationsPlugin.cpp SourceQueryWidget.cpp SourceEvidenceProvider.cpp
HEADERS += SourceRelationsPlugin.h SourceQueryWidget.h SourceQueryInterface.h SourceEvidenceProvider.h
DISTFILES += source-relations.json
HEADERS += ../../NewAnalysis/BoardIdentity.h
win32:QMAKE_CXXFLAGS += -finput-charset=UTF-8 -fexec-charset=UTF-8
