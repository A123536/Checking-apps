#ifndef OPBFAULTSAMPLESTORE_H
#define OPBFAULTSAMPLESTORE_H

#include <QString>
#include <QStringList>
#include <QtGlobal>
#include "LogTaskControl.h"

class OpbFaultSampleStore
{
public:
    struct ImportResult
    {
        bool success;
        bool cancelled;
        bool duplicate;
        QString errorMessage;
        QString databasePath;
        QString logFormat;
        qint64 incidentId;
        int sourceFileCount;
        quint64 eventCount;
        int cycleCount;
        quint64 cycleStart;
        quint64 cycleEnd;
        quint64 unknownDescriptionEventCount;

        ImportResult();
    };

    ImportResult ImportIncident(const QStringList &csvFilePaths,
                                const QString &databasePath,
                                const QString &boardType,
                                const QString &knownCause = QString(),
                                const std::shared_ptr<LogTaskControl> &control = nullptr) const;
};

#endif // OPBFAULTSAMPLESTORE_H
