#include "OpbFaultSampleStore.h"
#include "LogCsvReader.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QTextStream>
#include <QUuid>
#include <QVariant>
#include <QVector>

#include <algorithm>

namespace
{
struct DatabaseConnectionCleanup
{
    QString name;
    ~DatabaseConnectionCleanup() { QSqlDatabase::removeDatabase(name); }
};

int CsvSegmentIndex(const QString &filePath)
{
    const QRegularExpression expression(QStringLiteral("\\.txt(\\d+)\\.csv$"),
                                         QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = expression.match(QFileInfo(filePath).fileName());
    return match.hasMatch() ? match.captured(1).toInt() : 0;
}

QString CaptureId(const QString &filePath)
{
    const QString fileName = QFileInfo(filePath).fileName();
    const QRegularExpression expression(QStringLiteral("^(.*\\.txt)\\d+\\.csv$"),
                                         QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = expression.match(fileName);
    return match.hasMatch() ? match.captured(1).toLower() : fileName.toLower();
}

QString NormalizeCode(const QString &text)
{
    bool ok = false;
    const uint value = text.trimmed().toUInt(&ok, 16);
    return ok ? QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper(), 4, QChar('0'))
              : text.trimmed();
}

bool ExecuteSql(QSqlQuery &query, const QString &sql, QString *errorMessage)
{
    if(query.exec(sql))
    {
        return true;
    }
    if(errorMessage != nullptr)
    {
        *errorMessage = query.lastError().text() + QStringLiteral("; SQL: ") + sql;
    }
    return false;
}

bool FileSha256(const QString &path, QByteArray *digest, QString *errorMessage,
                const std::shared_ptr<LogTaskControl> &control,
                qint64 completedBytes, qint64 totalBytes)
{
    QFile file(path);
    if(!file.open(QIODevice::ReadOnly))
    {
        if(errorMessage != nullptr)
        {
            *errorMessage = QStringLiteral("无法读取CSV文件: ") + path;
        }
        return false;
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while(!file.atEnd())
    {
        if(control && control->IsCancelled()) return false;
        const QByteArray data = file.read(1024 * 1024);
        if(file.error() != QFile::NoError)
        {
            *errorMessage = QStringLiteral("读取CSV文件失败: ") + path;
            return false;
        }
        hash.addData(data);
        if(control) control->SetProgress(totalBytes > 0
                        ? static_cast<int>(15.0 * (completedBytes + file.pos()) / totalBytes) : 0,
                        QStringLiteral("校验 CSV 文件指纹"));
    }
    *digest = hash.result();
    return true;
}
}

OpbFaultSampleStore::ImportResult::ImportResult()
    : success(false),
      cancelled(false),
      duplicate(false),
      incidentId(0),
      sourceFileCount(0),
      eventCount(0u),
      cycleCount(0),
      cycleStart(0u),
      cycleEnd(0u),
      unknownDescriptionEventCount(0u)
{
}

OpbFaultSampleStore::ImportResult OpbFaultSampleStore::ImportIncident(
        const QStringList &csvFilePaths,
        const QString &databasePath,
        const QString &boardType,
        const QString &knownCause,
        const std::shared_ptr<LogTaskControl> &control) const
{
    ImportResult result;
    LogTaskCompletion completion(control);
    const auto progress = [&](int percent, const QString &message) {
        if(control) control->SetProgress(percent, message);
    };
    const auto cancelled = [&]() {
        if(!control || !control->IsCancelled()) return false;
        result.cancelled = true;
        result.errorMessage = QStringLiteral("故障入库已取消，本次记录未保存");
        return true;
    };
    progress(0, QStringLiteral("准备校验故障日志"));
    if(cancelled()) return result;
    result.databasePath = QFileInfo(databasePath).absoluteFilePath();
    if(csvFilePaths.isEmpty())
    {
        result.errorMessage = QStringLiteral("请至少添加一个宕机日志CSV文件");
        return result;
    }
    if(boardType.trimmed().isEmpty())
    {
        result.errorMessage = QStringLiteral("板卡类型不能为空");
        return result;
    }
    QString boardError;
    const QString detectedBoard = BoardIdentity::fromFiles(csvFilePaths, &boardError, true);
    if(!boardError.isEmpty() || !BoardIdentity::boards().contains(boardType) ||
       (!detectedBoard.isEmpty() && detectedBoard != boardType)) {
        result.errorMessage = boardError.isEmpty() ? QStringLiteral("故障样本板卡与日志名称不一致") : boardError;
        return result;
    }

    QStringList orderedPaths;
    for(int index = 0; index < csvFilePaths.size(); ++index)
    {
        const QFileInfo info(csvFilePaths.at(index));
        if(!info.exists() || !info.isFile())
        {
            result.errorMessage = QStringLiteral("CSV文件不存在: ") + csvFilePaths.at(index);
            return result;
        }
        if(info.suffix().compare(QStringLiteral("csv"), Qt::CaseInsensitive) != 0)
        {
            result.errorMessage = QStringLiteral("宕机样本只接受解析后的CSV文件: ") + info.fileName();
            return result;
        }
        orderedPaths.append(info.absoluteFilePath());
    }

    std::sort(orderedPaths.begin(), orderedPaths.end(), [](const QString &left, const QString &right) {
        const int leftIndex = CsvSegmentIndex(left);
        const int rightIndex = CsvSegmentIndex(right);
        return leftIndex == rightIndex ? left < right : leftIndex < rightIndex;
    });

    const QString captureId = CaptureId(orderedPaths.first());
    for(int index = 1; index < orderedPaths.size(); ++index)
    {
        if(CaptureId(orderedPaths.at(index)) != captureId)
        {
            result.errorMessage = QStringLiteral(
                        "一次只能添加同一份原始日志解析出的CSV分段，请不要混入其他日志");
            return result;
        }
    }

    QVector<QByteArray> fileHashes;
    qint64 totalBytes = 0, completedBytes = 0;
    for(const QString &path : orderedPaths) totalBytes += qMax<qint64>(0, QFileInfo(path).size());
    QCryptographicHash incidentHash(QCryptographicHash::Sha256);
    QCryptographicHash legacyIncidentHash(QCryptographicHash::Sha256);
    // Preserve historical OPB fingerprints. Other boards use separate namespaces.
    if(boardType != "OPB") incidentHash.addData(boardType.toUtf8());
    for(int index = 0; index < orderedPaths.size(); ++index)
    {
        if(cancelled()) return result;
        QByteArray digest;
        if(!FileSha256(orderedPaths.at(index), &digest, &result.errorMessage,
                       control, completedBytes, totalBytes))
        {
            cancelled();
            return result;
        }
        completedBytes += QFileInfo(orderedPaths.at(index)).size();
        fileHashes.append(digest);
        incidentHash.addData(digest);
        legacyIncidentHash.addData(digest);
    }
    const QString contentHash = QString::fromLatin1(incidentHash.result().toHex());
    const QString legacyHash = QString::fromLatin1(legacyIncidentHash.result().toHex());
    progress(15, QStringLiteral("开始导入故障事件"));
    if(cancelled()) return result;
    completedBytes = 0;

    QDir databaseDirectory = QFileInfo(result.databasePath).absoluteDir();
    if(!databaseDirectory.exists() && !databaseDirectory.mkpath(QStringLiteral(".")))
    {
        result.errorMessage = QStringLiteral("无法创建故障样本数据库目录: ") +
                databaseDirectory.absolutePath();
        return result;
    }

    const QString connectionName = QStringLiteral("OpbFaultSample_%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    DatabaseConnectionCleanup connectionCleanup{connectionName};
    bool databaseSuccess = false;
    QString databaseError;

    {
        QSqlDatabase database = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        database.setConnectOptions(QStringLiteral("QSQLITE_BUSY_TIMEOUT=2000"));
        database.setDatabaseName(result.databasePath);
        if(!database.open())
        {
            databaseError = database.lastError().text();
        }
        else
        {
            QSqlQuery query(database);
            databaseSuccess = ExecuteSql(query, QStringLiteral("PRAGMA foreign_keys = ON"), &databaseError);
            if(databaseSuccess)
            {
                databaseSuccess = database.transaction();
                if(!databaseSuccess) databaseError = database.lastError().text();
            }
            databaseSuccess = databaseSuccess &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE TABLE IF NOT EXISTS fault_schema_meta ("
                                   "key TEXT PRIMARY KEY, value TEXT NOT NULL)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE TABLE IF NOT EXISTS fault_incident ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                   "board_type TEXT NOT NULL, capture_id TEXT NOT NULL, "
                                   "content_hash TEXT NOT NULL UNIQUE, known_cause TEXT, "
                                   "created_utc TEXT NOT NULL, source_file_count INTEGER NOT NULL, "
                                   "event_count INTEGER NOT NULL, cycle_count INTEGER NOT NULL, "
                                   "cycle_start INTEGER, cycle_end INTEGER, "
                                   "unknown_description_event_count INTEGER NOT NULL)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE TABLE IF NOT EXISTS fault_source_file ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, "
                                   "segment_index INTEGER NOT NULL, file_name TEXT NOT NULL, "
                                   "original_path TEXT NOT NULL, file_size INTEGER NOT NULL, "
                                   "modified_utc TEXT NOT NULL, sha256 TEXT NOT NULL, "
                                   "FOREIGN KEY(incident_id) REFERENCES fault_incident(id) ON DELETE CASCADE)"),
                               &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE TABLE IF NOT EXISTS fault_event ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, "
                                   "source_file_id INTEGER NOT NULL, line_number INTEGER NOT NULL, "
                                   "cycle_number INTEGER NOT NULL, packet_sequence INTEGER, "
                                   "level TEXT NOT NULL, code TEXT NOT NULL, description TEXT NOT NULL, "
                                   "description_state TEXT NOT NULL, raw_value TEXT, decoded_value TEXT, "
                                   "FOREIGN KEY(incident_id) REFERENCES fault_incident(id) ON DELETE CASCADE, "
                                   "FOREIGN KEY(source_file_id) REFERENCES fault_source_file(id) ON DELETE CASCADE)"),
                               &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE INDEX IF NOT EXISTS idx_fault_event_incident "
                                   "ON fault_event(incident_id)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE INDEX IF NOT EXISTS idx_fault_event_code "
                                   "ON fault_event(incident_id, code)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE TABLE IF NOT EXISTS fault_incident_format ("
                                   "incident_id INTEGER PRIMARY KEY, log_format TEXT NOT NULL, "
                                   "FOREIGN KEY(incident_id) REFERENCES fault_incident(id) ON DELETE CASCADE)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE TABLE IF NOT EXISTS fault_snapshot_event ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, "
                                   "source_file_id INTEGER NOT NULL, line_number INTEGER NOT NULL, "
                                   "event_index INTEGER NOT NULL, level TEXT NOT NULL, code TEXT NOT NULL, "
                                   "description TEXT NOT NULL, description_state TEXT NOT NULL, "
                                   "raw_value TEXT, decoded_value TEXT, "
                                   "FOREIGN KEY(incident_id) REFERENCES fault_incident(id) ON DELETE CASCADE, "
                                   "FOREIGN KEY(source_file_id) REFERENCES fault_source_file(id) ON DELETE CASCADE)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "CREATE INDEX IF NOT EXISTS idx_fault_snapshot_incident "
                                   "ON fault_snapshot_event(incident_id, event_index)"), &databaseError) &&
                    ExecuteSql(query, QStringLiteral(
                                   "INSERT OR REPLACE INTO fault_schema_meta(key, value) "
                                   "VALUES('schema_version', '2')"), &databaseError);

            if(databaseSuccess)
            {
                query.prepare(QStringLiteral("SELECT i.id, i.source_file_count, i.event_count, i.cycle_count, "
                                             "i.cycle_start, i.cycle_end, i.unknown_description_event_count, "
                                             "COALESCE(f.log_format, 'cyclic') FROM fault_incident i "
                                             "LEFT JOIN fault_incident_format f ON f.incident_id=i.id WHERE i.content_hash=:hash "
                                             "OR (i.content_hash=:legacy_hash AND i.board_type=:board)"));
                query.bindValue(QStringLiteral(":hash"), contentHash);
                query.bindValue(QStringLiteral(":legacy_hash"), legacyHash);
                query.bindValue(QStringLiteral(":board"), boardType);
                if(!query.exec())
                {
                    databaseSuccess = false;
                    databaseError = query.lastError().text();
                }
                else if(query.next())
                {
                    result.success = true;
                    result.duplicate = true;
                    result.incidentId = query.value(0).toLongLong();
                    result.sourceFileCount = query.value(1).toInt();
                    result.eventCount = query.value(2).toULongLong();
                    result.cycleCount = query.value(3).toInt();
                    result.cycleStart = query.value(4).toULongLong();
                    result.cycleEnd = query.value(5).toULongLong();
                    result.unknownDescriptionEventCount = query.value(6).toULongLong();
                    result.logFormat = query.value(7).toString();
                }
            }

            if(databaseSuccess && !result.duplicate)
            {
                query.prepare(QStringLiteral(
                                  "INSERT INTO fault_incident("
                                  "board_type, capture_id, content_hash, known_cause, created_utc, "
                                  "source_file_count, event_count, cycle_count, cycle_start, cycle_end, "
                                  "unknown_description_event_count) "
                                  "VALUES(:board, :capture, :hash, :cause, :created, :files, 0, 0, NULL, NULL, 0)"));
                query.bindValue(QStringLiteral(":board"), boardType.trimmed());
                query.bindValue(QStringLiteral(":capture"), captureId);
                query.bindValue(QStringLiteral(":hash"), contentHash);
                query.bindValue(QStringLiteral(":cause"), knownCause.trimmed().isEmpty()
                                ? QVariant() : QVariant(knownCause.trimmed()));
                query.bindValue(QStringLiteral(":created"),
                                QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
                query.bindValue(QStringLiteral(":files"), orderedPaths.size());
                databaseSuccess = query.exec();
                if(databaseSuccess)
                {
                    result.incidentId = query.lastInsertId().toLongLong();
                }
                else
                {
                    databaseError = query.lastError().text();
                }
            }

            QSet<quint64> cycles;
            bool snapshotMode = true;
            for(const QString &path : orderedPaths)
            {
                QFile probe(path);
                if(!probe.open(QIODevice::ReadOnly)) continue;
                QTextStream probeStream(&probe); LogCsvReader::Configure(probeStream, probe); LogCsvReader reader;
                while(!probeStream.atEnd())
                {
                    if(cancelled()) { databaseSuccess = false; break; }
                    const QString line = probeStream.readLine(); QStringList event;
                    if(line.startsWith(QStringLiteral("包序号:")) ||
                       (reader.Read(line, &event, nullptr) && reader.hasPacket))
                    { snapshotMode = false; break; }
                }
                if(!snapshotMode || !databaseSuccess) break;
            }
            bool hasCycle = false;
            quint64 currentCycle = 0u;
            bool hasPacketSequence = false;
            quint64 currentPacketSequence = 0u;

            for(int fileIndex = 0;
                databaseSuccess && !result.duplicate && fileIndex < orderedPaths.size();
                ++fileIndex)
            {
                if(cancelled()) { databaseSuccess = false; break; }
                const QFileInfo fileInfo(orderedPaths.at(fileIndex));
                query.prepare(QStringLiteral(
                                  "INSERT INTO fault_source_file("
                                  "incident_id, segment_index, file_name, original_path, file_size, "
                                  "modified_utc, sha256) "
                                  "VALUES(:incident, :segment, :name, :path, :size, :modified, :sha256)"));
                query.bindValue(QStringLiteral(":incident"), result.incidentId);
                query.bindValue(QStringLiteral(":segment"), CsvSegmentIndex(fileInfo.absoluteFilePath()));
                query.bindValue(QStringLiteral(":name"), fileInfo.fileName());
                query.bindValue(QStringLiteral(":path"), fileInfo.absoluteFilePath());
                query.bindValue(QStringLiteral(":size"), fileInfo.size());
                query.bindValue(QStringLiteral(":modified"),
                                fileInfo.lastModified().toUTC().toString(Qt::ISODate));
                query.bindValue(QStringLiteral(":sha256"),
                                QString::fromLatin1(fileHashes.at(fileIndex).toHex()));
                if(!query.exec())
                {
                    databaseSuccess = false;
                    databaseError = query.lastError().text();
                    break;
                }
                const qint64 sourceFileId = query.lastInsertId().toLongLong();

                QFile file(fileInfo.absoluteFilePath());
                if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
                {
                    databaseSuccess = false;
                    databaseError = QStringLiteral("无法打开CSV文件: ") + fileInfo.absoluteFilePath();
                    break;
                }
                QTextStream stream(&file);
                LogCsvReader::Configure(stream, file);
                LogCsvReader csv;
                csv.expectedBoard = boardType;
                int lineNumber = 0;
                QSqlQuery snapshotInsert(database);
                snapshotInsert.prepare(QStringLiteral(
                                  "INSERT INTO fault_snapshot_event(incident_id, source_file_id, line_number, event_index, "
                                  "level, code, description, description_state, raw_value, decoded_value) "
                                  "VALUES(:incident, :source, :line, :event_index, :level, :code, :description, :state, :raw, :decoded)"));

                query.prepare(QStringLiteral(
                                  "INSERT INTO fault_event("
                                  "incident_id, source_file_id, line_number, cycle_number, packet_sequence, "
                                  "level, code, description, description_state, raw_value, decoded_value) "
                                  "VALUES(:incident, :source, :line, :cycle, :packet, :level, :code, "
                                  ":description, :state, :raw, :decoded)"));

                while(databaseSuccess && !stream.atEnd())
                {
                    if(cancelled()) { databaseSuccess = false; break; }
                    const QString line = stream.readLine();
                    ++lineNumber;
                    if((lineNumber % 1024) == 0)
                    {
                        progress(totalBytes > 0
                                 ? 15 + static_cast<int>(80.0 * (completedBytes + file.pos()) / totalBytes) : 15,
                                 QStringLiteral("导入 CSV %1/%2，已写入 %3 条事件")
                                 .arg(fileIndex + 1).arg(orderedPaths.size()).arg(result.eventCount));
                        if(cancelled()) { databaseSuccess = false; break; }
                    }
                    if(line.trimmed().isEmpty())
                    {
                        continue;
                    }
                    if(line.startsWith(QStringLiteral("Cycle Num :"))) continue;
                    if(line.startsWith(QStringLiteral("包序号:")))
                    {
                        bool ok = false;
                        currentPacketSequence = line.section(':', 1).trimmed().toULongLong(&ok, 10);
                        if(!ok)
                        {
                            databaseSuccess = false;
                            databaseError = QStringLiteral("包序号格式错误: %1:%2")
                                    .arg(fileInfo.absoluteFilePath()).arg(lineNumber);
                            break;
                        }
                        hasPacketSequence = true;
                        continue;
                    }

                    QStringList fields;
                    if(!csv.Read(line, &fields, &databaseError))
                    {
                        databaseSuccess = false;
                        databaseError = QStringLiteral("CSV事件格式错误: %1:%2：%3")
                                .arg(fileInfo.absoluteFilePath()).arg(lineNumber).arg(databaseError);
                        break;
                    }
                    if(fields.isEmpty()) continue;
                    if(csv.hasCycle)
                    {
                        currentCycle = csv.cycle; hasCycle = true; cycles.insert(currentCycle);
                        if(cycles.size() == 1) result.cycleStart = result.cycleEnd = currentCycle;
                        else { result.cycleStart = qMin(result.cycleStart, currentCycle); result.cycleEnd = qMax(result.cycleEnd, currentCycle); }
                    }
                    if(csv.hasPacket)
                    {
                        currentPacketSequence = csv.packet; hasPacketSequence = true;
                    }

                    const QString code = NormalizeCode(fields.at(1));
                    const QString level = fields.at(0).trimmed();
                    bool codeOk = false; fields.at(1).trimmed().toUInt(&codeOk, 16);
                    if(!codeOk || !QStringList({QStringLiteral("错误"), QStringLiteral("警告"),
                                                QStringLiteral("提示"), QStringLiteral("调试")}).contains(level))
                    {
                        databaseSuccess = false;
                        databaseError = QStringLiteral("CSV事件编码或等级无效: %1:%2").arg(fileInfo.fileName()).arg(lineNumber);
                        break;
                    }
                    const bool storeSnapshot = snapshotMode || !hasCycle;
                    QString description = fields.at(2).trimmed();
                    QString descriptionState = QStringLiteral("known");
                    if(description.isEmpty())
                    {
                        description = QStringLiteral("UNKNOWN:") + code;
                        descriptionState = QStringLiteral("unknown");
                        ++result.unknownDescriptionEventCount;
                    }

                    QSqlQuery &eventInsert = storeSnapshot ? snapshotInsert : query;
                    eventInsert.bindValue(QStringLiteral(":incident"), result.incidentId);
                    eventInsert.bindValue(QStringLiteral(":source"), sourceFileId);
                    eventInsert.bindValue(QStringLiteral(":line"), lineNumber);
                    if(storeSnapshot) eventInsert.bindValue(":event_index", static_cast<qulonglong>(result.eventCount + 1));
                    else
                    {
                        eventInsert.bindValue(QStringLiteral(":cycle"), static_cast<qulonglong>(currentCycle));
                        eventInsert.bindValue(QStringLiteral(":packet"), hasPacketSequence
                                        ? QVariant::fromValue<qulonglong>(currentPacketSequence) : QVariant());
                    }
                    eventInsert.bindValue(QStringLiteral(":level"), level);
                    eventInsert.bindValue(QStringLiteral(":code"), code);
                    eventInsert.bindValue(QStringLiteral(":description"), description);
                    eventInsert.bindValue(QStringLiteral(":state"), descriptionState);
                    eventInsert.bindValue(QStringLiteral(":raw"), fields.at(3).trimmed());
                    eventInsert.bindValue(QStringLiteral(":decoded"),
                                    fields.mid(4).join(QStringLiteral(",")).trimmed());
                    if(!eventInsert.exec())
                    {
                        databaseSuccess = false;
                        databaseError = eventInsert.lastError().text();
                        break;
                    }
                    ++result.eventCount;
                }
                if(file.error() != QFile::NoError)
                {
                    databaseSuccess = false;
                    databaseError = QStringLiteral("读取CSV文件失败: ") + fileInfo.absoluteFilePath();
                }
                completedBytes += file.size();
            }

            if(!result.duplicate)
            {
                result.sourceFileCount = orderedPaths.size();
                result.cycleCount = cycles.size();
                result.logFormat = (snapshotMode || !hasCycle) ? QStringLiteral("snapshot") : QStringLiteral("cyclic");
            }
            if(databaseSuccess && !result.duplicate && result.eventCount == 0u)
            {
                databaseSuccess = false;
                databaseError = QStringLiteral("所选CSV中没有可入库的日志事件");
            }
            if(databaseSuccess && !result.duplicate)
            {
                query.prepare(QStringLiteral(
                                  "UPDATE fault_incident SET event_count=:events, cycle_count=:cycles, "
                                  "cycle_start=:start, cycle_end=:end, "
                                  "unknown_description_event_count=:unknown WHERE id=:id"));
                query.bindValue(QStringLiteral(":events"), static_cast<qulonglong>(result.eventCount));
                query.bindValue(QStringLiteral(":cycles"), result.cycleCount);
                query.bindValue(QStringLiteral(":start"), hasCycle
                                ? QVariant::fromValue<qulonglong>(result.cycleStart) : QVariant());
                query.bindValue(QStringLiteral(":end"), hasCycle
                                ? QVariant::fromValue<qulonglong>(result.cycleEnd) : QVariant());
                query.bindValue(QStringLiteral(":unknown"),
                                static_cast<qulonglong>(result.unknownDescriptionEventCount));
                query.bindValue(QStringLiteral(":id"), result.incidentId);
                databaseSuccess = query.exec();
                if(!databaseSuccess)
                {
                    databaseError = query.lastError().text();
                }
            }

            if(databaseSuccess && !result.duplicate)
            {
                query.prepare(QStringLiteral("INSERT INTO fault_incident_format(incident_id, log_format) VALUES(:id, :format)"));
                query.bindValue(":id", result.incidentId); query.bindValue(":format", result.logFormat);
                databaseSuccess = query.exec();
                if(!databaseSuccess) databaseError = query.lastError().text();
            }
            if(databaseSuccess && !result.duplicate)
            {
                progress(99, QStringLiteral("准备提交故障样本"));
                if(control && !control->BeginCommit())
                {
                    cancelled();
                    databaseSuccess = false;
                }
            }
            if(databaseSuccess && !result.duplicate)
            {
                databaseSuccess = database.commit();
                if(!databaseSuccess)
                {
                    databaseError = database.lastError().text();
                }
            }
            if((!databaseSuccess || result.duplicate) && database.isOpen())
            {
                database.rollback();
            }
            database.close();
        }
    }

    if(result.duplicate)
    {
        progress(100, QStringLiteral("样本已存在，未重复导入"));
        return result;
    }
    if(!databaseSuccess)
    {
        if(cancelled() || result.cancelled) return result;
        result.errorMessage = QStringLiteral("写入故障样本数据库失败: ") + databaseError;
        return result;
    }
    result.success = true;
    progress(100, QStringLiteral("故障样本入库完成"));
    return result;
}
