#include "SourceEvidenceProvider.h"
#include "../../../NewAnalysis/BoardIdentity.h"
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>
#include <QSet>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QUuid>
#include <QVariantMap>
#include <QVector>
#include <QRegularExpression>
#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QProcess>
#include <QElapsedTimer>
#include <stdexcept>
#include <algorithm>

namespace {
const int MaximumCodes = 12;
const int MaximumSites = 12;
const int MaximumBytes = 48000;
const int MaximumSelfCheckBytes = 128000;

class ReadConnection
{
public:
    QString name = QUuid::createUuid().toString();
    QSqlDatabase database = QSqlDatabase::addDatabase("QSQLITE", name);
    ~ReadConnection()
    {
        database.close();
        database = QSqlDatabase();
        QSqlDatabase::removeDatabase(name);
    }

    QVector<QVariantMap> query(const QString &sql, const QVariantList &parameters = {})
    {
        QSqlQuery request(database);
        if(!request.prepare(sql)) throw std::runtime_error("Source index query preparation failed");
        for(const QVariant &value : parameters) request.addBindValue(value);
        if(!request.exec()) throw std::runtime_error("Source index query failed");
        QVector<QVariantMap> rows;
        while(request.next()) {
            QVariantMap row;
            const QSqlRecord record = request.record();
            for(int column = 0; column < record.count(); ++column)
                row.insert(record.fieldName(column), request.value(column));
            rows.append(row);
        }
        return rows;
    }
};

void refreshChangedConfiguration(const QString &path, const QString &board,
                                 const std::shared_ptr<std::atomic_bool> &cancelled)
{
    QVariantMap metadata;
    {
        ReadConnection connection;
        connection.database.setDatabaseName(path);
        connection.database.setConnectOptions("QSQLITE_OPEN_READONLY");
        if(!connection.database.open()) return;
        for(const auto &row : connection.query("SELECT key,value FROM metadata"))
            metadata.insert(row["key"].toString(), row["value"]);
    }
    if(metadata["board"].toString() != board) return;
    const auto dependencies = QJsonDocument::fromJson(metadata["configuration_dependencies"].toString().toUtf8()).object();
    bool changed = false;
    for(auto entry = dependencies.begin(); entry != dependencies.end(); ++entry) {
        QFile header(entry.key());
        if(!header.open(QIODevice::ReadOnly)) continue;
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if(hash.addData(&header) && QString::fromLatin1(hash.result().toHex()) != entry.value().toString()) changed = true;
    }
    const QDir configDirectory = QFileInfo(metadata["configuration_header_path"].toString()).absoluteDir();
    for(const auto &name : QJsonDocument::fromJson(metadata["missing_configuration_includes"].toString().toUtf8()).array())
        if(QFileInfo::exists(configDirectory.filePath(name.toString()))) changed = true;
    if(!changed) return;
    const QString executable = QCoreApplication::applicationDirPath() + "/source_relations/SourceIndexer.exe";
    if(!QFileInfo::exists(executable)) throw std::runtime_error("Configuration changed but source indexer is unavailable");
    const QString cancelPath = QFileInfo(path).absolutePath() + "/.board-refresh-" + QUuid::createUuid().toString(QUuid::WithoutBraces) + ".cancel";
    QProcess worker;
    worker.setProcessChannelMode(QProcess::MergedChannels);
    QStringList arguments{"--source", metadata["source_root"].toString(), "--output", path,
                          "--board", board, "--version", metadata["software_version"].toString(), "--cancel-file", cancelPath};
    const QString manifest = metadata["profile_manifest_path"].toString();
    if(QFileInfo::exists(manifest)) arguments << "--profiles" << manifest;
    worker.start(executable, arguments);
    if(!worker.waitForStarted(5000)) throw std::runtime_error("Source indexer could not start");
    QElapsedTimer timer; timer.start();
    while(!worker.waitForFinished(100)) {
        worker.readAllStandardOutput();
        if((cancelled && cancelled->load()) || timer.elapsed() > 120000) {
            QFile marker(cancelPath); if(marker.open(QIODevice::WriteOnly)) marker.close();
            if(!worker.waitForFinished(2000)) { worker.kill(); worker.waitForFinished(1000); }
            QFile::remove(cancelPath);
            throw std::runtime_error("Configuration refresh cancelled or timed out");
        }
    }
    if(worker.exitStatus() != QProcess::NormalExit || worker.exitCode() != 0)
        throw std::runtime_error("Configuration refresh failed");
}

QString normalizedCode(const QJsonValue &value)
{
    if(!value.isString()) return QString();
    const QString input = value.toString().trimmed();
    bool valid = false;
    const uint code = input.toUInt(&valid, input.startsWith("0x", Qt::CaseInsensitive) ? 16 : 10);
    return valid && code <= 0xffff ? QString("0x%1").arg(code, 4, 16, QChar('0')).toUpper().replace("0X", "0x") : QString();
}

struct LookupCodes
{
    QStringList ordered;
    QMap<QString, QJsonArray> references;

    void add(const QJsonObject &event, const QString &origin)
    {
        const QString code = normalizedCode(event["code"]);
        if(code.isEmpty()) return;
        QJsonObject reference{{"origin", origin}};
        for(const QString &key : {QString("evidence_id"), QString("event_index"), QString("cycle")})
            if(event.contains(key)) reference.insert(key, event[key]);
        if(!references.contains(code)) ordered.append(code);
        if(references[code].size() < 4) references[code].append(reference);
    }
};

LookupCodes selectCodes(const QJsonObject &evidence)
{
    LookupCodes selected;
    if(evidence["rca_trace"].toObject()["observed_cycle_marker_count"].toInt() > 0)
        selected.add(QJsonObject{{"code", "0x0A1A"}}, "rca_cycle_boundary");
    for(const QString &key : {QString("explicit_failures"), QString("candidates")})
        for(const auto &event : evidence[key].toArray()) selected.add(event.toObject(), key);
    if(!selected.ordered.isEmpty() || evidence["source_lookup_scope"].toString() == "candidate_codes") return selected;
    const auto tail = evidence["sequence_tail"].toArray();
    for(int index = tail.size() - 1; index >= 0; --index) selected.add(tail[index].toObject(), "sequence_tail");
    for(const auto &code : evidence["source_lookup_codes"].toArray())
        selected.add(QJsonObject{{"code", code}}, "observed_log_code");
    return selected;
}

QJsonObject snippet(const QString &content, int center, int before, int after)
{
    const auto lines = content.split('\n');
    const int first = qBound(1, center - before, qMax(1, lines.size()));
    const int last = qMin(lines.size(), center + after);
    QStringList excerpt;
    bool clipped = false;
    int characters = 0;
    for(int line = first; line <= last; ++line) {
        const QString original = lines[line - 1];
        QString value = original.left(200);
        if(value.size() < original.size()) { value += " …"; clipped = true; }
        if(characters + value.size() > 1400) { clipped = true; break; }
        excerpt.append(QString::number(line) + "  " + value);
        characters += value.size();
    }
    return QJsonObject{{"start_line", first}, {"end_line", first + excerpt.size() - 1},
                       {"text", excerpt.join('\n')}, {"truncated", clipped}};
}

QJsonArray relations(ReadConnection &connection, qint64 functionId)
{
    QJsonArray result;
    // Two bounded breadth-first levels, with explicit graph direction and ambiguity.
    for(const bool incoming : {true, false}) {
        QList<QPair<qint64, int>> pending{{functionId, 1}};
        QSet<qint64> visited{functionId};
        int count = 0;
        while(!pending.isEmpty() && count < 4) {
            const auto current = pending.takeFirst();
            QString sql;
            if(incoming) {
                sql = "SELECT c.function_id AS next_id,c.caller AS function,c.caller,t.name AS callee,c.path,c.line,c.condition,c.has_errors,e.resolution,e.evidence FROM edges e JOIN call_details c ON c.id=e.call_id JOIN functions t ON t.id=e.target_id WHERE e.target_id=? ORDER BY c.path,c.line LIMIT 5";
            } else {
                sql = "SELECT t.id AS next_id,coalesce(t.name,c.name) AS function,c.caller,coalesce(t.name,c.name) AS callee,c.path,c.line,c.condition,c.has_errors,coalesce(e.resolution,c.kind) AS resolution,e.evidence,t.condition AS target_condition FROM call_details c LEFT JOIN edges e ON e.call_id=c.id LEFT JOIN functions t ON t.id=e.target_id WHERE c.function_id=? ORDER BY c.line,t.name LIMIT 5";
            }
            const auto rows = connection.query(sql, {current.first});
            for(const auto &row : rows) {
                if(count == 4) break;
                ++count;
                QJsonObject item = QJsonObject::fromVariantMap(row);
                item.remove("next_id");
                item.insert("direction", incoming ? "caller" : "callee");
                item.insert("depth", current.second);
                result.append(item);
                const qint64 next = row["next_id"].toLongLong();
                if(next && current.second < 2 && !visited.contains(next)) {
                    visited.insert(next);
                    pending.append(qMakePair(next, current.second + 1));
                }
            }
        }
    }
    return result;
}

QJsonObject selfCheckReview(ReadConnection &connection, const QJsonObject &evidence,
                           const std::shared_ptr<std::atomic_bool> &cancelled)
{
    QMap<QString, QString> observed;
    for(const auto &value : evidence["rca_trace"].toObject()["events"].toArray()) {
        const auto event = value.toObject();
        const QString code = normalizedCode(event["code"]);
        if(!code.isEmpty()) observed.insert(code, event["description"].toString());
    }
    QJsonArray items, unmatched, unresolvedSelfChecks, sources;
    QSet<QString> paths;
    QMap<QString, QSet<int>> contextLines;
    for(auto event = observed.constBegin(); event != observed.constEnd(); ++event) {
        if(cancelled && cancelled->load()) throw std::runtime_error("Self-check review cancelled");
        bool valid = false;
        const int code = event.key().mid(2).toInt(&valid, 16);
        if(!valid) continue;
        const auto locations = connection.query(
            "SELECT DISTINCT s.path,c.line,f.name AS function,c.condition FROM log_sites l JOIN calls c ON c.id=l.call_id "
            "JOIN functions f ON f.id=c.function_id JOIN files s ON s.id=f.file_id WHERE l.code=? ORDER BY s.path,c.line", {code});
        bool isSelfCheck = event.value().contains(QStringLiteral("自检"));
        for(const auto &location : locations) {
            const QString name = location["function"].toString().toLower();
            if(location["path"].toString().toLower().contains("selfche") || name.contains("selfche") || name.contains("selfchk")) isSelfCheck = true;
        }
        QJsonArray references;
        for(const auto &location : locations) {
            references.append(QJsonObject::fromVariantMap(location));
            if(isSelfCheck) {
                const QString path = location["path"].toString();
                paths.insert(path);
                const int line = location["line"].toInt();
                for(int number = qMax(1, line - 12); number <= line + 12; ++number) contextLines[path].insert(number);
            }
        }
        if(isSelfCheck && !locations.isEmpty())
            items.append(QJsonObject{{"code", event.key()}, {"description", event.value()}, {"source_locations", references},
                                     {"source_state", "located"}});
        else if(isSelfCheck) unresolvedSelfChecks.append(event.key());
        if(locations.isEmpty()) unmatched.append(event.key());
    }
    const auto codePaths = paths.values();
    for(const QString &path : codePaths) {
        if(path.toLower().contains("selfche") && path.endsWith(".c", Qt::CaseInsensitive)) paths.insert(path.left(path.size() - 2) + ".h");
    }
    QStringList orderedPaths = paths.values(); orderedPaths.sort();
    std::stable_sort(orderedPaths.begin(), orderedPaths.end(), [](const QString &a, const QString &b) {
        return a.toLower().contains("selfche") && !b.toLower().contains("selfche");
    });
    int bytes = QJsonDocument(items).toJson(QJsonDocument::Compact).size() + 4096;
    bool truncated = false;
    for(const QString &path : orderedPaths) {
        if(cancelled && cancelled->load()) throw std::runtime_error("Self-check review cancelled");
        const auto rows = connection.query("SELECT path,content,sha256,has_errors FROM files WHERE path=?", {path});
        if(rows.isEmpty()) continue;
        const QStringList lines = rows[0]["content"].toString().split('\n');
        QStringList numbered;
        bool clipped = false;
        const bool fullFile = path.toLower().contains("selfche");
        for(int line = 0; line < lines.size(); ++line) {
            if(!fullFile && !contextLines.value(path).contains(line + 1)) continue;
            if(lines[line].trimmed().isEmpty()) continue;
            const QString text = QString::number(line + 1) + "  " + lines[line];
            // Reserve space for JSON escaping, file metadata and coverage records.
            const int cost = QJsonDocument(QJsonArray{text}).toJson(QJsonDocument::Compact).size() + 2;
            if(bytes + cost > MaximumSelfCheckBytes - 1024) { clipped = truncated = true; break; }
            bytes += cost;
            numbered.append(text);
        }
        sources.append(QJsonObject{{"source_id", QString("CHK%1").arg(sources.size() + 1, 3, 10, QChar('0'))},
                                   {"path", path}, {"sha256", rows[0]["sha256"].toString()},
                                   {"has_errors", rows[0]["has_errors"].toBool()},
                                   {"text_scope", fullFile ? "board_filtered_self_check_file" : "observed_log_site_contexts"},
                                   {"text", numbered.join('\n')}, {"truncated", clipped}});
    }
    return QJsonObject{{"scope", "observed_trace_self_check_items_in_board_source"}, {"items", items},
                       {"unresolved_self_check_codes", unresolvedSelfChecks},
                       {"sources", sources}, {"unmatched_observed_codes", unmatched}, {"truncated", truncated},
                       {"trace_truncated", evidence["rca_trace"].toObject()["truncated"]}, {"max_bytes", MaximumSelfCheckBytes}};
}

QString labelMatch(const QString &source, const QString &requested)
{
    if(source.isEmpty() || requested.isEmpty() || source == "all-configurations") return "UNKNOWN";
    return source == requested ? "label_match" : "mismatch";
}
}

QJsonObject SourceEvidenceProvider::collect(const QString &databasePath, const QJsonObject &logEvidence,
                                          const QString &softwareVersion, const QString &board,
                                          const std::shared_ptr<std::atomic_bool> &cancelled) const
{
    QJsonObject result{{"schema_version", "source-evidence/1"}, {"status", "unavailable"},
                       {"records", QJsonArray()}, {"version_match", "UNKNOWN"},
                       {"firmware_correspondence", "unverified"},
                       {"limits", QJsonObject{{"max_codes", MaximumCodes}, {"max_sites", MaximumSites},
                                               {"max_bytes", MaximumBytes + (logEvidence.contains("rca_trace") ? MaximumSelfCheckBytes : 0)},
                                               {"max_self_check_bytes", MaximumSelfCheckBytes}, {"max_relation_depth", 2}}}};
    const auto isCancelled = [&]() { return cancelled && cancelled->load(); };
    if(isCancelled()) { result.insert("status", "cancelled"); return result; }
    const QString selectedDatabase = BoardIdentity::sourceDatabase(databasePath, board);
    if(!BoardIdentity::boards().contains(board) || !QFileInfo(selectedDatabase).isFile()) {
        result.insert("message", QStringLiteral("%1 板卡专用源码关系库不可用，请重建四板卡关系库").arg(board));
        return result;
    }
    try {
        refreshChangedConfiguration(selectedDatabase, board, cancelled);
        ReadConnection connection;
        connection.database.setDatabaseName(selectedDatabase);
        connection.database.setConnectOptions("QSQLITE_OPEN_READONLY;QSQLITE_BUSY_TIMEOUT=1000");
        if(!connection.database.open() || !connection.database.transaction())
            throw std::runtime_error("Source index cannot be opened read-only");
        const auto metadataRows = connection.query("SELECT key,value FROM metadata");
        QVariantMap metadata;
        for(const auto &row : metadataRows) metadata.insert(row["key"].toString(), row["value"]);
        if(metadata["format"] != "logdiagnosis-source-relations" || metadata["schema_version"] != "1")
            throw std::runtime_error("Unsupported source index format or schema");
        if(metadata["board"].toString() != board || metadata["analysis_mode"] != "board_scoped_conditionals")
            throw std::runtime_error("Source database does not match the selected board configuration");
        QJsonObject snapshot;
        for(const QString &key : {QString("snapshot_id"), QString("source_hash"), QString("software_version"),
                                  QString("board"), QString("parser"), QString("analysis_mode"), QString("configuration_sha256")})
            snapshot.insert(key, metadata[key].toString().left(512));
        snapshot.insert("quality", QJsonDocument::fromJson(metadata["summary"].toString().toUtf8()).object());
        result.insert("snapshot", snapshot);
        result.insert("board_configuration", QJsonObject{
            {"state", metadata["configuration_state"].toString()},
            {"profile", QJsonDocument::fromJson(metadata["board_profile"].toString().toUtf8()).object()},
            {"missing_includes", QJsonDocument::fromJson(metadata["missing_configuration_includes"].toString().toUtf8()).array()},
            {"unresolved_macros", QJsonDocument::fromJson(metadata["unresolved_configuration"].toString().toUtf8()).array()}});
        result.insert("requested_software_version", softwareVersion.left(512));
        result.insert("requested_board", board.left(512));
        if(logEvidence.contains("rca_trace")) result.insert("self_check_review", selfCheckReview(connection, logEvidence, cancelled));
        result.insert("version_match", labelMatch(metadata["software_version"].toString(), softwareVersion));
        result.insert("board_match", labelMatch(metadata["board"].toString(), board));
        result.insert("limitations", QJsonArray{
            QStringLiteral("其他板卡分支已排除，当前板卡内未确认的功能宏分支仅为候选，需按记录的条件表达式核实，未验证与运行固件的完整对应关系。"),
            QStringLiteral("版本及板型仅比较标签；不匹配或未知时，源码内容仅供候选解释和核查。"),
            QStringLiteral("静态调用关系与候选目标不能证明实际执行路径或根因，间接调用集合可能不完整。"),
            QStringLiteral("源码片段和上下游关系已限量截取，未列出的调用及日志点仍可能相关。")});
        const LookupCodes selected = selectCodes(logEvidence);
        QJsonArray records, lookups;
        bool truncated = selected.ordered.size() > MaximumCodes;
        for(const QString &code : selected.ordered.mid(0, MaximumCodes)) {
            if(isCancelled()) { result.insert("status", "cancelled"); return result; }
            bool valid = false;
            const int numericCode = code.mid(2).toInt(&valid, 16);
            if(!valid) continue;
            const auto countRows = connection.query("SELECT count(*) AS count FROM log_sites WHERE code=?", {numericCode});
            const int total = countRows.first()["count"].toInt();
            lookups.append(QJsonObject{{"code", code}, {"total_sites", total},
                                       {"log_references", selected.references.value(code)}});
            if(records.size() == MaximumSites) { truncated = true; continue; }
            const auto sites = connection.query(
                "SELECT l.code_expression,l.data_expression,l.length_expression,c.line,c.condition AS log_condition,"
                "c.has_errors AS call_has_errors,f.id AS function_id,f.name AS function,f.signature,f.line AS function_line,"
                "f.condition AS function_condition,f.has_errors AS function_has_errors,s.path,s.sha256,s.content,s.has_errors AS file_has_errors "
                "FROM log_sites l JOIN calls c ON c.id=l.call_id JOIN functions f ON f.id=c.function_id JOIN files s ON s.id=f.file_id "
                "WHERE l.code=? ORDER BY c.has_errors,f.has_errors,s.path,c.line LIMIT 3", {numericCode});
            if(total > sites.size()) truncated = true;
            for(const auto &site : sites) {
                if(isCancelled()) { result.insert("status", "cancelled"); return result; }
                if(records.size() == MaximumSites) { truncated = true; break; }
                QJsonObject record = QJsonObject::fromVariantMap(site);
                record.remove("content");
                record.remove("function_id");
                record.insert("signature", site["signature"].toString().left(400));
                record.insert("source_id", QString("SRC%1").arg(records.size() + 1, 3, 10, QChar('0')));
                record.insert("code", code);
                bool unresolvedCondition = !result["board_configuration"].toObject()["missing_includes"].toArray().isEmpty();
                const QString conditions = site["log_condition"].toString() + ' ' + site["function_condition"].toString();
                for(const auto &macro : result["board_configuration"].toObject()["unresolved_macros"].toArray()) {
                    if(QRegularExpression("\\b" + QRegularExpression::escape(macro.toString()) + "\\b").match(conditions).hasMatch()) {
                        unresolvedCondition = true;
                        break;
                    }
                }
                record.insert("requires_configuration_confirmation", unresolvedCondition);
                record.insert("log_references", selected.references.value(code));
                record.insert("log_context", snippet(site["content"].toString(), site["line"].toInt(), 8, 8));
                record.insert("function_start", snippet(site["content"].toString(), site["function_line"].toInt(), 0, 9));
                record.insert("relations", relations(connection, site["function_id"].toLongLong()));
                QJsonArray proposed = records;
                proposed.append(record);
                if(QJsonDocument(proposed).toJson(QJsonDocument::Compact).size() > MaximumBytes - 10000) {
                    truncated = true;
                    break;
                }
                records = proposed;
            }
        }
        result.insert("records", records);
        result.insert("lookups", lookups);
        result.insert("selected_code_count", lookups.size());
        result.insert("omitted_code_count", qMax(0, selected.ordered.size() - MaximumCodes));
        result.insert("truncated", truncated);
        const int selfCheckSources = result["self_check_review"].toObject()["sources"].toArray().size();
        const bool hasSource = !records.isEmpty() || selfCheckSources > 0;
        result.insert("status", hasSource ? "reference_only" : "no_matches");
        result.insert("message", hasSource ? QStringLiteral("已关联 %1 个关键记录点及 %2 份自检源码，固件对应关系待核实").arg(records.size()).arg(selfCheckSources)
                                          : QStringLiteral("已查询源码关系库，所选日志编码未获得可发送的源码记录点"));
        if(selected.ordered.isEmpty() && selfCheckSources == 0)
            result.insert("message", QStringLiteral("已连接源码关系库，当前诊断没有需要展开源码的候选编码"));
        if(result["version_match"].toString() == "mismatch")
            result.insert("message", result["message"].toString() + QStringLiteral("；版本标签不匹配，源码仅供参考"));
        if(result["board_match"].toString() == "mismatch")
            result.insert("message", result["message"].toString() + QStringLiteral("；板型标签不匹配，源码仅供参考"));
        const int maximumResultBytes = MaximumBytes + (result.contains("self_check_review") ? MaximumSelfCheckBytes : 0);
        while(!records.isEmpty() && QJsonDocument(result).toJson(QJsonDocument::Compact).size() > maximumResultBytes) {
            records.removeLast();
            result.insert("records", records);
            result.insert("truncated", true);
        }
        connection.database.rollback();
    } catch(const std::exception &) {
        result.insert("status", isCancelled() ? "cancelled" : "unavailable");
        result.insert("message", QStringLiteral("源码关系库打开、配置同步或查询失败，请检查配置文件和数据库"));
    }
    return result;
}
