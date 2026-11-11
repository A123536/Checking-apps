#ifndef OPBBASELINEANALYZER_H
#define OPBBASELINEANALYZER_H

#include <QString>
#include <QStringList>
#include <QtGlobal>
#include "LogTaskControl.h"

class OpbBaselineAnalyzer
{
public:
    struct BuildResult
    {
        bool success;
        bool cancelled;
        QString errorMessage;
        QString databasePath;
        quint64 totalEventCount;
        quint64 baselineEventCount;
        quint64 packetCount;
        int totalCycleCount;
        int baselineCycleCount;
        int excludedCycleCount;
        int eventCodeCount;
        int pendingDescriptionCodeCount;
        int unknownDescriptionEventCount;
        quint64 baselineCycleStart;
        quint64 baselineCycleEnd;

        BuildResult();
    };

    OpbBaselineAnalyzer();

    BuildResult BuildBaseline(const QStringList &csvFilePaths,
                              const QString &databasePath,
                              const QString &softwareVersion = QString(),
                              const std::shared_ptr<LogTaskControl> &control = nullptr,
                              const QString &boardType = QString()) const;

    static QStringList FindParsedCsvFiles(const QString &sourceLogPath);
};

#endif // OPBBASELINEANALYZER_H
