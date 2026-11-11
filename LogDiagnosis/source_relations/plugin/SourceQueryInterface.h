#ifndef SOURCEQUERYINTERFACE_H
#define SOURCEQUERYINTERFACE_H

#include <QtPlugin>
#include <QString>
#include <QJsonObject>
#include <atomic>
#include <memory>
class QWidget;

class SourceQueryInterface
{
public:
    virtual ~SourceQueryInterface() {}
    virtual QWidget *createQueryWidget(const QString &databasePath, QWidget *parent) = 0;
    virtual QJsonObject collectEvidence(const QString &databasePath, const QJsonObject &logEvidence,
                                       const QString &softwareVersion, const QString &board,
                                       const std::shared_ptr<std::atomic_bool> &cancelled) = 0;
};

#define SourceQueryInterface_iid "org.logdiagnosis.SourceQueryInterface/2.0"
Q_DECLARE_INTERFACE(SourceQueryInterface, SourceQueryInterface_iid)
#endif
