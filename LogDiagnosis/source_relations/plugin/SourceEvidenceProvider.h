#ifndef SOURCEEVIDENCEPROVIDER_H
#define SOURCEEVIDENCEPROVIDER_H
#include <QJsonObject>
#include <QString>
#include <atomic>
#include <memory>

class SourceEvidenceProvider
{
public:
    QJsonObject collect(const QString &databasePath, const QJsonObject &logEvidence,
                        const QString &softwareVersion, const QString &board,
                        const std::shared_ptr<std::atomic_bool> &cancelled) const;
};
#endif
