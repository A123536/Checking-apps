#ifndef OPBDIAGNOSTICANALYZER_H
#define OPBDIAGNOSTICANALYZER_H

#include <QJsonObject>
#include <QStringList>
#include <atomic>
#include <memory>

class OpbDiagnosticAnalyzer
{
public:
    struct Input
    {
        QString baselinePath;
        QStringList csvPaths;
        QString faultDatabasePath;
        qint64 incidentId = 0;
        QString softwareVersion;
        QString boardType;
        bool allowMissingBaseline = false;
        std::shared_ptr<std::atomic_bool> cancelled;
    };

    struct Result
    {
        bool success = false;
        QString errorMessage;
        QString summary;
        QJsonObject evidence;
    };

    Result Analyze(const Input &input) const;
};

#endif
