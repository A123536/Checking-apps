#ifndef OPBSNAPSHOTANALYZER_H
#define OPBSNAPSHOTANALYZER_H

#include "OpbDiagnosticAnalyzer.h"
#include <QJsonArray>
#include <QVector>

struct OpbSnapshotEvent
{
    quint64 index = 0;
    int line = 0;
    QString sourceFile;
    QString level;
    QString code;
    QString description;
    QString rawValue;
    QString decodedValue;
    bool hasCycle = false;
    quint64 cycle = 0;
};

class OpbSnapshotAnalyzer
{
public:
    OpbDiagnosticAnalyzer::Result Analyze(const OpbDiagnosticAnalyzer::Input &input,
                                        const QVector<OpbSnapshotEvent> &events,
                                        const QString &sourceType,
                                        const QJsonArray &sourceReferences,
                                        bool versionMatched) const;
};

#endif
