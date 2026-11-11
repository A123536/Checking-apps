#include "SourceRelationsPlugin.h"
#include "SourceQueryWidget.h"
#include "SourceEvidenceProvider.h"

QWidget *SourceRelationsPlugin::createQueryWidget(const QString &databasePath, QWidget *parent)
{
    return new SourceQueryWidget(databasePath, parent);
}

QJsonObject SourceRelationsPlugin::collectEvidence(const QString &databasePath, const QJsonObject &logEvidence,
                                                 const QString &softwareVersion, const QString &board,
                                                 const std::shared_ptr<std::atomic_bool> &cancelled)
{
    return SourceEvidenceProvider().collect(databasePath, logEvidence, softwareVersion, board, cancelled);
}
