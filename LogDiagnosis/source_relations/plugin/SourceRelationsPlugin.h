#ifndef SOURCERELATIONSPLUGIN_H
#define SOURCERELATIONSPLUGIN_H
#include <QObject>
#include "SourceQueryInterface.h"

class SourceRelationsPlugin : public QObject, public SourceQueryInterface
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID SourceQueryInterface_iid FILE "source-relations.json")
    Q_INTERFACES(SourceQueryInterface)
public:
    QWidget *createQueryWidget(const QString &databasePath, QWidget *parent) override;
    QJsonObject collectEvidence(const QString &databasePath, const QJsonObject &logEvidence,
                               const QString &softwareVersion, const QString &board,
                               const std::shared_ptr<std::atomic_bool> &cancelled) override;
};
#endif
