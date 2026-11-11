#ifndef BOARDIDENTITY_H
#define BOARDIDENTITY_H
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

class BoardIdentity
{
public:
    static QStringList boards() { return {"ATP", "IPB", "OPB", "SPB"}; }
    static QString fromName(const QString &name, QString *error = nullptr)
    {
        if(error) error->clear();
        static const QRegularExpression pattern("(?:^|[^A-Z0-9])(ATP|IPB|OPB|SPB)(?=$|[^A-Z0-9])",
                                                QRegularExpression::CaseInsensitiveOption);
        QSet<QString> found;
        auto matches = pattern.globalMatch(QFileInfo(name).fileName());
        while(matches.hasNext()) found.insert(matches.next().captured(1).toUpper());
        if(found.size() > 1) {
            if(error) *error = QStringLiteral("日志名称包含多个板卡标识，请核对文件名");
            return QString();
        }
        return found.isEmpty() ? QString() : *found.constBegin();
    }
    static QString fromFiles(const QStringList &paths, QString *error, bool allowUnknown = false)
    {
        if(error) error->clear();
        QString board;
        for(const QString &path : paths) {
            QString reason;
            const QString current = fromName(path, &reason);
            if(!reason.isEmpty() || (current.isEmpty() && !allowUnknown)) {
                if(error) *error = reason.isEmpty() ? QStringLiteral("无法识别板卡，文件名需包含 ATP、IPB、OPB 或 SPB") : reason;
                return QString();
            }
            if(!current.isEmpty() && !board.isEmpty() && current != board) {
                if(error) *error = QStringLiteral("一次任务不能混合不同板卡的日志");
                return QString();
            }
            if(!current.isEmpty()) board = current;
        }
        return board;
    }
    static QString sourceDatabase(const QString &path, const QString &board)
    {
        if(!boards().contains(board)) return path;
        const QFileInfo info(path);
        QString stem = info.completeBaseName();
        stem.remove(QRegularExpression("\\.(ATP|MCP|IPB|OPB|SPB|SIG)$", QRegularExpression::CaseInsensitiveOption));
        const QString candidate = info.absolutePath() + '/' + stem + '.' + board + '.' + info.suffix();
        return QFileInfo::exists(candidate) ? candidate : path;
    }
};
#endif
