#include "OpbDiagnosticAnalyzer.h"
#include "OpbSnapshotAnalyzer.h"
#include "LogCsvReader.h"
#include "RcaTrace.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
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
#include <cmath>
#include <limits>

namespace
{
// A separate, read-only connection is created in the worker thread for each run.
class ReadDatabase
{
public:
    explicit ReadDatabase(const QString &path)
        : name(QUuid::createUuid().toString()),
          db(QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), name))
    {
        db.setConnectOptions(QStringLiteral("QSQLITE_OPEN_READONLY"));
        db.setDatabaseName(path);
    }
    ~ReadDatabase()
    {
        db.close();
        db = QSqlDatabase();
        QSqlDatabase::removeDatabase(name);
    }
    QString name;
    QSqlDatabase db;
};

struct Baseline
{
    double presence = 0;
    double countMin = 0;
    double countP99 = 0;
    int numericCount = 0;
    double valueMin = 0;
    double valueMax = 0;
    bool hasRange = false;
};

struct Metric
{
    quint64 count = 0;
    double minimum = std::numeric_limits<double>::infinity();
    double maximum = -std::numeric_limits<double>::infinity();
    bool hasNumeric = false;
};

struct Cycle
{
    quint64 number = 0;
    bool incomplete = false;
    QHash<QString, Metric> codes;
};

struct Finding
{
    QString rule;
    QString code;
    QString title;
    QString meaning;
    QJsonValue expected;
    quint64 firstCycle = 0;
    quint64 lastCycle = 0;
    int affectedCycles = 0;
    QJsonArray examples;
};

QString Number(quint64 number) { return QString::number(number); }

bool Next(quint64 previous, quint64 current)
{
    return (previous < std::numeric_limits<quint64>::max() && current == previous + 1) ||
            (previous == 0xFFFFFFFFu && current == 0);
}

bool ParseUnsigned(const QString &text, quint64 *number)
{
    if(!QRegularExpression(QStringLiteral("^[0-9]+$")).match(text.trimmed()).hasMatch())
        return false;
    bool ok = false;
    *number = text.trimmed().toULongLong(&ok);
    return ok;
}

QString NormalizeCode(const QString &text)
{
    bool ok = false;
    const uint value = text.trimmed().toUInt(&ok, 16);
    return ok ? QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper(), 4, QChar('0'))
              : QString();
}

struct Capture
{
    QVector<Cycle> cycles;
    QVector<OpbSnapshotEvent> snapshotEvents;
    bool mixedFormat = false;
    quint64 eventCount = 0;
    quint64 unknownCount = 0;
    quint64 packetGaps = 0;
    quint64 cycleGaps = 0;
    quint64 packets = 0;
    quint64 missingPacketEvents = 0;
    bool hasPacket = false;
    bool hasPreviousPacket = false;
    quint64 previousPacket = 0;
    quint64 packet = 0;
    QJsonArray cycleGapExamples;
    QJsonArray packetGapExamples;

    void BeginCycle(quint64 number)
    {
        if(cycles.isEmpty() || cycles.last().number != number)
        {
            if(!cycles.isEmpty() && !Next(cycles.last().number, number))
            {
                ++cycleGaps;
                if(cycleGapExamples.size() < 3)
                    cycleGapExamples.append(QJsonObject{{"previous_cycle", Number(cycles.last().number)},
                                                       {"next_cycle", Number(number)}});
            }
            Cycle cycle;
            cycle.number = number;
            cycles.append(cycle);
        }
    }

    void BeginPacket(quint64 number)
    {
        if(hasPreviousPacket && !Next(previousPacket, number))
        {
            ++packetGaps;
            if(!cycles.isEmpty()) cycles.last().incomplete = true;
            if(cycles.size() > 1) cycles[cycles.size() - 2].incomplete = true;
            if(packetGapExamples.size() < 3)
                packetGapExamples.append(QJsonObject{{"cycle", cycles.isEmpty() ? QJsonValue() : Number(cycles.last().number)},
                                                     {"previous_packet", Number(previousPacket)},
                                                     {"next_packet", Number(number)}});
        }
        packet = number;
        previousPacket = number;
        hasPreviousPacket = true;
        hasPacket = true;
        ++packets;
    }

    bool Event(const QString &level, const QString &codeText, const QString &description,
               const QString &value, QString *error, const QString &raw = QString(), int sourceLine = 0,
               const QString &sourceFile = QString())
    {
        const QString code = NormalizeCode(codeText);
        if(mixedFormat || code.isEmpty() ||
           !QStringList({QStringLiteral("错误"), QStringLiteral("警告"),
                         QStringLiteral("提示"), QStringLiteral("调试")}).contains(level))
        {
            *error = mixedFormat ? QStringLiteral("同一组日志混合了有周期与无周期两种格式")
                                : QStringLiteral("事件编码或日志等级无效");
            return false;
        }
        ++eventCount;
        if(description.trimmed().isEmpty() || description.startsWith(QStringLiteral("UNKNOWN:")) ||
           description.startsWith(QStringLiteral("待确认："))) ++unknownCount;
        {
            OpbSnapshotEvent event;
            event.index = eventCount; event.line = sourceLine;
            event.sourceFile = sourceFile;
            event.level = level; event.code = code; event.description = description.trimmed();
            event.rawValue = raw.trimmed(); event.decodedValue = value.trimmed();
            event.hasCycle = !cycles.isEmpty();
            if(event.hasCycle) event.cycle = cycles.last().number;
            snapshotEvents.append(event);
        }
        if(cycles.isEmpty()) return true;
        Metric &metric = cycles.last().codes[code];
        ++metric.count;
        if(!hasPacket && code != "0x0A1A") { ++missingPacketEvents; cycles.last().incomplete = true; }
        bool ok = false;
        const double number = value.trimmed().toDouble(&ok);
        if(ok && std::isfinite(number))
        {
            metric.hasNumeric = true;
            metric.minimum = qMin(metric.minimum, number);
            metric.maximum = qMax(metric.maximum, number);
        }
        return true;
    }
};

QString CaptureName(const QString &path, int *segment)
{
    const QString name = QFileInfo(path).fileName().toLower();
    const QRegularExpressionMatch match = QRegularExpression(
                QStringLiteral("^(.*\\.txt)([0-9]+)\\.csv$")).match(name);
    *segment = match.hasMatch() ? match.captured(2).toInt() : 0;
    return match.hasMatch() ? match.captured(1) : name;
}

void AddFinding(QVector<Finding> *findings, QHash<QString, int> *indices,
                const QString &rule, const QString &code, const QString &title,
                const QString &meaning, const QJsonValue &expected,
                quint64 cycle, const QJsonValue &actual)
{
    const QString key = rule + ':' + code;
    if(!indices->contains(key))
    {
        Finding finding;
        finding.rule = rule; finding.code = code; finding.title = title;
        finding.meaning = meaning; finding.expected = expected; finding.firstCycle = cycle;
        indices->insert(key, findings->size());
        findings->append(finding);
    }
    Finding &finding = (*findings)[indices->value(key)];
    finding.lastCycle = cycle;
    ++finding.affectedCycles;
    if(finding.examples.size() < 3)
        finding.examples.append(QJsonObject{{"cycle", Number(cycle)}, {"observed", actual}});
}
}

OpbDiagnosticAnalyzer::Result OpbDiagnosticAnalyzer::Analyze(const Input &input) const
{
    Result result;
    const auto cancelled = [&]() {
        if(input.cancelled && input.cancelled->load())
        {
            result.errorMessage = QStringLiteral("诊断已取消");
            return true;
        }
        return false;
    };
    if(cancelled()) return result;
    QStringList unknowns;
    unknowns << QStringLiteral("规则为候选规则，尚未使用真实宕机样本校准；命中不等于根因。")
             << QStringLiteral("宕机时刻、运行阶段和事件语义约束未提供，不能确认宕机原因。")
             << QStringLiteral("未命中规则仅表示本次比较未发现差异，不表示设备正常。")
             << QStringLiteral("未使用历史故障标签推断原因，当前根因结论为 UNKNOWN。");

    QHash<QString, Baseline> baseline;
    QHash<QString, QString> meta;
    QString boardError;
    QString board = BoardIdentity::fromFiles(input.csvPaths, &boardError, true);
    if(!boardError.isEmpty() || (!input.boardType.isEmpty() && !board.isEmpty() && board != input.boardType)) {
        result.errorMessage = boardError.isEmpty() ? QStringLiteral("待分析日志板卡与任务板卡不一致") : boardError;
        return result;
    }
    if(board.isEmpty()) board = input.boardType;
    QJsonArray sourceReferences;
    const bool hasBaseline = QFileInfo(input.baselinePath).isFile();
    if(!hasBaseline && !input.allowMissingBaseline)
    {
        result.errorMessage = QStringLiteral("正常基线数据库不存在，请先建立基线或选择已有数据库");
        return result;
    }
    if(hasBaseline) {
        ReadDatabase connection(input.baselinePath);
        if(!connection.db.open())
        {
            result.errorMessage = QStringLiteral("无法只读打开基线：") + connection.db.lastError().text();
            return result;
        }
        QSqlQuery query(connection.db);
        if(!query.exec(QStringLiteral("SELECT key, value FROM opb_baseline_meta")))
        {
            result.errorMessage = QStringLiteral("所选数据库不是有效的正常基线数据库");
            return result;
        }
        while(query.next()) meta.insert(query.value(0).toString(), query.value(1).toString());
        bool cycleCountOk = false;
        const int baselineCycles = meta.value("baseline_cycle_count").toInt(&cycleCountOk);
        if(board.isEmpty()) board = meta.value("board_type");
        if(!BoardIdentity::boards().contains(board) || meta.value("board_type") != board || meta.value("schema_version") != "1" ||
           meta.value("training_label") != "normal" || !cycleCountOk || baselineCycles <= 0)
        {
            result.errorMessage = QStringLiteral("基线板卡、格式版本或训练周期元数据无效，需使用 %1 正常基线").arg(board);
            return result;
        }
        if(!query.exec(QStringLiteral("SELECT code, presence_rate, count_min, count_p99, "
                                      "numeric_count, value_min, value_max FROM opb_event_baseline")))
        {
            result.errorMessage = QStringLiteral("基线缺少诊断所需的事件统计字段");
            return result;
        }
        while(query.next())
        {
            Baseline b;
            const QString code = NormalizeCode(query.value(0).toString());
            bool presenceOk = false, minOk = false, p99Ok = false, numericOk = false;
            b.presence = query.value(1).toDouble(&presenceOk);
            b.countMin = query.value(2).toDouble(&minOk);
            b.countP99 = query.value(3).toDouble(&p99Ok);
            b.numericCount = query.value(4).toInt(&numericOk);
            bool lowOk = false, highOk = false;
            b.valueMin = query.value(5).toDouble(&lowOk);
            b.valueMax = query.value(6).toDouble(&highOk);
            b.hasRange = b.numericCount > 0 && lowOk && highOk &&
                    std::isfinite(b.valueMin) && std::isfinite(b.valueMax) && b.valueMin <= b.valueMax;
            if(code.isEmpty() || baseline.contains(code) || !presenceOk || !minOk || !p99Ok ||
               !numericOk || b.numericCount < 0 || !std::isfinite(b.presence) ||
               !std::isfinite(b.countMin) || !std::isfinite(b.countP99) ||
               b.presence < 0 || b.presence > 1 || b.countMin < 0 || b.countP99 < b.countMin ||
               (b.numericCount > 0 && !b.hasRange))
            {
                result.errorMessage = QStringLiteral("基线事件统计损坏或数值范围无效");
                return result;
            }
            baseline.insert(code, b);
        }
        if(query.lastError().isValid() || baseline.isEmpty())
        {
            result.errorMessage = QStringLiteral("基线没有有效事件统计");
            return result;
        }
    }
    if(!BoardIdentity::boards().contains(board)) {
        result.errorMessage = QStringLiteral("无法确定日志板卡，需提供明确的板卡名称");
        return result;
    }
    const QString baselineVersion = meta.value("software_version", "UNKNOWN").trimmed();
    const QString inputVersion = input.softwareVersion.trimmed();
    const bool versionMatched = !baselineVersion.isEmpty() && baselineVersion != "UNKNOWN" &&
            !inputVersion.isEmpty() && inputVersion != "UNKNOWN";
    if(versionMatched && baselineVersion != inputVersion)
    {
        result.errorMessage = QStringLiteral("软件版本不匹配：基线为 %1，待分析日志为 %2")
                .arg(baselineVersion, inputVersion);
        return result;
    }
    if(!versionMatched) unknowns << QStringLiteral("软件版本未完全提供，基线兼容性 UNKNOWN。");

    Capture capture;
    QString sourceType;
    if(!input.csvPaths.isEmpty() && input.incidentId > 0)
    {
        result.errorMessage = QStringLiteral("请选择一种诊断来源：CSV 或已入库事件");
        return result;
    }
    if(input.incidentId > 0)
    {
        sourceType = QStringLiteral("stored_incident");
        if(!QFileInfo(input.faultDatabasePath).isFile())
        {
            result.errorMessage = QStringLiteral("故障样本数据库不存在");
            return result;
        }
        ReadDatabase connection(input.faultDatabasePath);
        if(!connection.db.open())
        {
            result.errorMessage = QStringLiteral("无法只读打开故障样本数据库");
            return result;
        }
        QSqlQuery query(connection.db);
        query.prepare(QStringLiteral("SELECT board_type FROM fault_incident WHERE id=:id"));
        query.bindValue(":id", input.incidentId);
        if(!query.exec() || !query.next() || query.value(0).toString() != board)
        {
            result.errorMessage = QStringLiteral("未找到所选 %1 故障事件").arg(board);
            return result;
        }
        sourceReferences.append(QJsonObject{{"incident_id", QString::number(input.incidentId)}});
        QHash<qint64, QString> storedFiles;
        QSqlQuery names(connection.db);
        names.prepare("SELECT id,file_name FROM fault_source_file WHERE incident_id=:id"); names.bindValue(":id", input.incidentId);
        if(names.exec()) while(names.next()) storedFiles.insert(names.value(0).toLongLong(), QFileInfo(names.value(1).toString()).fileName());
        bool storedSnapshot = false;
        if(connection.db.tables().contains("fault_incident_format"))
        {
            query.prepare(QStringLiteral("SELECT log_format FROM fault_incident_format WHERE incident_id=:id"));
            query.bindValue(":id", input.incidentId);
            if(!query.exec()) { result.errorMessage = QStringLiteral("无法读取故障事件格式"); return result; }
            if(query.next()) storedSnapshot = query.value(0).toString() == "snapshot";
        }
        unknowns << QStringLiteral("已入库事件没有独立的版本字段，所填日志版本由用户确认。");
        unknowns << QStringLiteral("故障库的周期和包序号按事件重建；无事件的空周期、空包未独立保存，完整性 UNKNOWN。");
        query.setForwardOnly(true);
        const bool hasSnapshotTable = connection.db.tables().contains("fault_snapshot_event");
        query.prepare(hasSnapshotTable
                      ? QStringLiteral("SELECT cycle_number, packet_sequence, level, code, description, decoded_value, raw_value, line_number, source_file_id FROM ("
                                       "SELECT NULL AS cycle_number, NULL AS packet_sequence, level, code, description, decoded_value, raw_value, line_number, source_file_id FROM fault_snapshot_event WHERE incident_id=:id "
                                       "UNION ALL SELECT cycle_number, packet_sequence, level, code, description, decoded_value, raw_value, line_number, source_file_id FROM fault_event WHERE incident_id=:id) ORDER BY source_file_id, line_number")
                      : storedSnapshot
                      ? QStringLiteral("SELECT NULL, NULL, level, code, description, decoded_value, raw_value, line_number, source_file_id "
                                       "FROM fault_snapshot_event WHERE incident_id=:id ORDER BY event_index, id")
                      : QStringLiteral("SELECT cycle_number, packet_sequence, level, code, description, "
                                       "decoded_value, raw_value, line_number, source_file_id FROM fault_event WHERE incident_id=:id ORDER BY id"));
        query.bindValue(":id", input.incidentId);
        if(!query.exec())
        {
            result.errorMessage = QStringLiteral("无法读取故障事件明细");
            return result;
        }
        while(query.next())
        {
            if(cancelled()) return result;
            quint64 cycle = 0, packet = 0;
            bool trueCycle = false;
            if(!LogCsvReader::CycleNumber(query.value(3).toString(), query.value(6).toString(),
                                         query.value(5).toString(), &trueCycle, &cycle, &result.errorMessage)) return result;
            const bool changedCycle = trueCycle && (capture.cycles.isEmpty() || capture.cycles.last().number != cycle);
            if(changedCycle) capture.BeginCycle(cycle);
            if(query.value(1).isNull()) capture.hasPacket = false;
            else
            {
                if(!ParseUnsigned(query.value(1).toString(), &packet))
                {
                    result.errorMessage = QStringLiteral("已入库事件的包序号无效");
                    return result;
                }
                if(!capture.hasPacket || capture.packet != packet)
                    capture.BeginPacket(packet);
            }
            if(!capture.Event(query.value(2).toString(), query.value(3).toString(),
                              query.value(4).toString(), query.value(5).toString(), &result.errorMessage,
                              query.value(6).toString(), query.value(7).toInt(), storedFiles.value(query.value(8).toLongLong())))
                return result;
        }
        if(query.lastError().isValid())
        {
            result.errorMessage = QStringLiteral("读取故障事件中断：") + query.lastError().text();
            return result;
        }
    }
    else
    {
        sourceType = QStringLiteral("parsed_csv");
        if(input.csvPaths.isEmpty())
        {
            result.errorMessage = QStringLiteral("请添加同一份日志的解析 CSV 分段");
            return result;
        }
        QStringList paths = input.csvPaths;
        std::sort(paths.begin(), paths.end(), [](const QString &a, const QString &b) {
            int ai = 0, bi = 0; CaptureName(a, &ai); CaptureName(b, &bi);
            return ai == bi ? a < b : ai < bi;
        });
        QString name;
        QSet<int> segments;
        QSet<QString> seenPaths;
        for(int index = 0; index < paths.size(); ++index)
        {
            const QFileInfo info(paths.at(index));
            int segment = 0;
            const QString currentName = CaptureName(paths.at(index), &segment);
            if(!info.isFile() || info.suffix().compare("csv", Qt::CaseInsensitive) != 0)
            {
                result.errorMessage = QStringLiteral("待分析 CSV 不存在或格式不正确：") + paths.at(index);
                return result;
            }
            if(index > 0 && name != currentName)
            {
                result.errorMessage = QStringLiteral("一次诊断只能选择同一份原始日志生成的 CSV 分段");
                return result;
            }
            const QString canonical = info.canonicalFilePath().toLower();
            if(seenPaths.contains(canonical) || segments.contains(segment))
            {
                result.errorMessage = QStringLiteral("所选 CSV 存在重复文件或重复分段号");
                return result;
            }
            seenPaths.insert(canonical); segments.insert(segment); name = currentName;
        }
        if(!segments.contains(0))
        {
            QList<int> sorted = segments.values(); std::sort(sorted.begin(), sorted.end());
            bool gap = sorted.first() != 1;
            for(int i = 1; i < sorted.size(); ++i) gap = gap || sorted.at(i) != sorted.at(i - 1) + 1;
            if(gap) unknowns << QStringLiteral("CSV 分段序号缺失，数据完整性 UNKNOWN。");
        }
        for(int index = 0; index < paths.size(); ++index)
        {
            if(cancelled()) return result;
            QFile file(paths.at(index));
            if(!file.open(QIODevice::ReadOnly))
            {
                result.errorMessage = QStringLiteral("无法打开 CSV：") + paths.at(index);
                return result;
            }
            QCryptographicHash hash(QCryptographicHash::Sha256);
            if(!hash.addData(&file) || !file.seek(0))
            {
                result.errorMessage = QStringLiteral("无法完整读取 CSV：") + paths.at(index);
                return result;
            }
            sourceReferences.append(QJsonObject{{"part", index + 1},
                                               {"sha256", QString::fromLatin1(hash.result().toHex())}});
            QTextStream stream(&file);
            LogCsvReader::Configure(stream, file);
            LogCsvReader csv;
            csv.expectedBoard = board;
            int lineNumber = 0;
            while(!stream.atEnd())
            {
                if(cancelled()) return result;
                const QString line = stream.readLine(); ++lineNumber;
                if(line.trimmed().isEmpty()) continue;
                if(line.startsWith(QStringLiteral("Cycle Num :"))) continue;
                if(line.startsWith(QStringLiteral("包序号:")))
                {
                    quint64 number = 0;
                    if(!ParseUnsigned(line.section(':', 1), &number))
                    {
                        result.errorMessage = QStringLiteral("包序号无效或缺少周期号");
                        return result;
                    }
                    capture.BeginPacket(number); continue;
                }
                QStringList fields;
                if(!csv.Read(line, &fields, &result.errorMessage))
                {
                    result.errorMessage = QStringLiteral("CSV 第 %1 段第 %2 行格式错误：%3")
                            .arg(index + 1).arg(lineNumber).arg(result.errorMessage);
                    return result;
                }
                if(fields.isEmpty()) continue;
                if(csv.hasCycle && (capture.cycles.isEmpty() || capture.cycles.last().number != csv.cycle))
                    capture.BeginCycle(csv.cycle);
                if(csv.hasPacket)
                {
                    if(!capture.hasPacket || capture.packet != csv.packet) capture.BeginPacket(csv.packet);
                }
                if(!capture.Event(fields.value(0).trimmed(), fields.value(1), fields.value(2),
                                  fields.mid(4).join(','), &result.errorMessage, fields.value(3), lineNumber, QFileInfo(paths.at(index)).fileName()))
                {
                    result.errorMessage = QStringLiteral("CSV 第 %1 段第 %2 行格式错误：%3")
                            .arg(index + 1).arg(lineNumber).arg(result.errorMessage);
                    return result;
                }
            }
            if(file.error() != QFile::NoError)
            {
                result.errorMessage = QStringLiteral("读取 CSV 时发生文件错误");
                return result;
            }
        }
    }
    if(capture.mixedFormat)
    {
        result.errorMessage = QStringLiteral("同一组日志混合了有周期与无周期两种格式"); return result;
    }
    if(capture.eventCount == 0)
    {
        result.errorMessage = QStringLiteral("待分析数据中没有有效事件");
        return result;
    }

    if(!hasBaseline || capture.cycles.isEmpty() || !capture.hasPreviousPacket)
    {
        auto snapshotInput = input;
        snapshotInput.boardType = board;
        return OpbSnapshotAnalyzer().Analyze(snapshotInput, capture.snapshotEvents, sourceType, sourceReferences, versionMatched);
    }

    if(meta.value("cycle_source") != "0x0A1A")
    {
        result.errorMessage = QStringLiteral("正常基线使用旧周期规则，请按 0x0A1A 重新建立基线");
        return result;
    }

    QVector<Finding> findings;
    QHash<QString, int> indices;
    int comparableCycles = 0;
    int unassignedCycleEvents = 0;
    for(const auto &event : capture.snapshotEvents) if(!event.hasCycle) ++unassignedCycleEvents;
    for(int cycleIndex = 0; cycleIndex < capture.cycles.size(); ++cycleIndex)
    {
        if(cancelled()) return result;
        const Cycle &cycle = capture.cycles.at(cycleIndex);
        // Boundary and gap-adjacent cycles may contain incomplete captures.
        const bool interior = !cycle.incomplete && cycleIndex > 0 && cycleIndex + 1 < capture.cycles.size() &&
                Next(capture.cycles.at(cycleIndex - 1).number, cycle.number) &&
                Next(cycle.number, capture.cycles.at(cycleIndex + 1).number);
        if(interior) ++comparableCycles;
        QStringList codes = cycle.codes.keys(); std::sort(codes.begin(), codes.end());
        for(const QString &code : codes)
        {
            if(code == "0x0A1A") continue; // execution counter is context, not an abnormal value
            const Metric metric = cycle.codes.value(code);
            if(!baseline.contains(code))
            {
                AddFinding(&findings, &indices, "NEW_CODE", code, QStringLiteral("基线未见编码"),
                           QStringLiteral("仅表示基线训练阶段未见该编码，可能是阶段差异。"),
                           QStringLiteral("未出现在基线"), cycle.number, Number(metric.count));
                continue;
            }
            const Baseline b = baseline.value(code);
            if(interior && metric.count > b.countP99)
                AddFinding(&findings, &indices, "COUNT_ABOVE_P99", code,
                           QStringLiteral("每周期次数超过基线 P99"),
                           QStringLiteral("统计尾部候选异常，P99 不是故障硬阈值。"), b.countP99,
                           cycle.number, Number(metric.count));
            if(metric.hasNumeric && b.hasRange &&
               (metric.minimum < b.valueMin || metric.maximum > b.valueMax))
                AddFinding(&findings, &indices, "VALUE_OUTSIDE_BASELINE", code,
                           QStringLiteral("数值超出基线观测范围"),
                           QStringLiteral("基线观测范围不是设备安全上下限。"),
                           QJsonObject{{"min", b.valueMin}, {"max", b.valueMax}}, cycle.number,
                           QJsonObject{{"min", metric.minimum}, {"max", metric.maximum}});
        }
        if(interior)
        {
            QStringList baselineCodes = baseline.keys(); std::sort(baselineCodes.begin(), baselineCodes.end());
            for(const QString &code : baselineCodes)
            {
                const Baseline b = baseline.value(code);
                if(b.presence >= 0.99 && b.countMin >= 1 && !cycle.codes.contains(code))
                    AddFinding(&findings, &indices, "STABLE_CODE_MISSING", code,
                               QStringLiteral("稳定出现的编码在当前周期缺失"),
                               QStringLiteral("日志遗漏与执行分支变化均可能导致缺失，原因 UNKNOWN。"),
                               QJsonObject{{"presence_rate", b.presence}, {"count_min", b.countMin}},
                               cycle.number, 0);
            }
        }
    }
    if(comparableCycles == 0)
        unknowns << QStringLiteral("没有可比较的连续内部周期，次数和缺失规则未运行。");
    unknowns << QStringLiteral("首尾周期、周期跳变两侧及包上下文不完整的周期不进行次数、缺失判断，边界异常可能遗漏。")
             << QStringLiteral("尚不识别启动/稳态/关机阶段，阶段差异可能被标为候选异常。");

    QJsonArray quality;
    if(capture.cycleGaps)
        quality.append(QJsonObject{{"rule", "CYCLE_DISCONTINUITY"}, {"state", "UNKNOWN"},
                                   {"count", Number(capture.cycleGaps)}, {"examples", capture.cycleGapExamples},
                                   {"meaning", QStringLiteral("周期不连续；采集缺失或运行跳变原因未知。")}});
    if(capture.packetGaps)
        quality.append(QJsonObject{{"rule", "PACKET_DISCONTINUITY"}, {"state", "UNKNOWN"},
                                   {"count", Number(capture.packetGaps)}, {"examples", capture.packetGapExamples},
                                   {"meaning", QStringLiteral("包序号不连续；不能据此确定设备宕机。")}});
    if(capture.missingPacketEvents)
        quality.append(QJsonObject{{"rule", "PACKET_CONTEXT_MISSING"}, {"state", "UNKNOWN"},
                                   {"count", Number(capture.missingPacketEvents)}});

    QJsonArray candidateJson;
    QStringList lines;
    lines << QStringLiteral("%1 本地诊断完成").arg(board)
          << QStringLiteral("根因结论：UNKNOWN（待证据确认）")
          << QStringLiteral("来源：%1；事件：%2；周期段数：%3；可比较内部周期：%4")
             .arg(sourceType == "parsed_csv" ? QStringLiteral("解析 CSV") : QStringLiteral("已入库事件"))
             .arg(capture.eventCount).arg(capture.cycles.size()).arg(comparableCycles)
          << QStringLiteral("按出现顺序首周期：%1；末周期：%2")
             .arg(capture.cycles.first().number).arg(capture.cycles.last().number)
          << QStringLiteral("未知描述事件：%1；数据质量提示：%2")
             .arg(capture.unknownCount).arg(quality.size())
          << QStringLiteral("候选差异组数：%1（相同规则和编码合并）").arg(findings.size())
          << QString();
    // Findings remain ordered by first observed cycle position, not assumed root-cause probability.
    const int limit = 80;
    for(int index = 0; index < qMin(limit, findings.size()); ++index)
    {
        const Finding &f = findings.at(index);
        const QString evidenceId = QStringLiteral("E%1").arg(index + 1, 3, 10, QChar('0'));
        candidateJson.append(QJsonObject{{"evidence_id", evidenceId}, {"rule", f.rule},
                                         {"code", f.code}, {"title", f.title}, {"state", "candidate"},
                                         {"first_cycle", Number(f.firstCycle)}, {"last_cycle", Number(f.lastCycle)},
                                         {"affected_cycles", f.affectedCycles}, {"baseline", f.expected},
                                         {"examples", f.examples}, {"interpretation_limit", f.meaning}});
        lines << QStringLiteral("%1  %2  %3；首见周期 %4，末见周期 %5，命中 %6 个周期")
                 .arg(evidenceId, f.code, f.title).arg(f.firstCycle).arg(f.lastCycle).arg(f.affectedCycles);
    }
    if(findings.isEmpty()) lines << QStringLiteral("未命中当前候选规则；不能据此判定正常。");
    if(findings.size() > limit)
        lines << QStringLiteral("仅展示前 %1 组，另有 %2 组未展开，证据并非完整清单。")
                 .arg(limit).arg(findings.size() - limit);
    lines << QString() << QStringLiteral("数据质量：周期跳变 %1 次，包序号跳变 %2 次。")
             .arg(capture.cycleGaps).arg(capture.packetGaps)
          << QStringLiteral("未知与限制：") << unknowns;

    QJsonArray unknownJson; for(const QString &unknown : unknowns) unknownJson.append(unknown);
    QJsonArray baselineSnapshot;
    QStringList sortedBaselineCodes = baseline.keys();
    std::sort(sortedBaselineCodes.begin(), sortedBaselineCodes.end());
    for(const QString &code : sortedBaselineCodes)
    {
        const Baseline b = baseline.value(code);
        baselineSnapshot.append(QJsonObject{{"code", code}, {"presence", b.presence},
                                            {"count_min", b.countMin}, {"count_p99", b.countP99},
                                            {"numeric_count", b.numericCount},
                                            {"value_min", b.hasRange ? QJsonValue(b.valueMin) : QJsonValue()},
                                            {"value_max", b.hasRange ? QJsonValue(b.valueMax) : QJsonValue()}});
    }
    const QString baselineHash = QString::fromLatin1(QCryptographicHash::hash(
                QJsonDocument(baselineSnapshot).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
    QJsonArray sourceLookupCodes;
    QSet<QString> sourceLookupSeen;
    for(int index = capture.snapshotEvents.size() - 1; index >= 0 && sourceLookupCodes.size() < 32; --index) {
        const QString code = capture.snapshotEvents.at(index).code;
        if(!sourceLookupSeen.contains(code)) { sourceLookupSeen.insert(code); sourceLookupCodes.append(code); }
    }
    auto traceInput = input;
    traceInput.boardType = board;
    result.evidence = QJsonObject{
        {"schema_version", "opb-diagnostic-evidence/1"}, {"board_type", board},
        {"analysis_mode", "cyclic_log"},
        {"cycle_source", "0x0A1A"},
        {"generated_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
        {"root_cause_status", "UNKNOWN"}, {"rule_state", "candidate"}, {"source_type", sourceType},
        {"source_references", sourceReferences},
        {"baseline_reference", QJsonObject{{"metrics_sha256", baselineHash},
                                           {"created_utc", meta.value("created_utc")},
                                           {"schema_version", meta.value("schema_version")}}},
        {"version_match", versionMatched ? "matched" : "UNKNOWN"},
        {"statistics", QJsonObject{{"event_count", Number(capture.eventCount)},
                                    {"cycle_segment_count", capture.cycles.size()},
                                    {"compared_interior_cycles", comparableCycles},
                                    {"unassigned_cycle_events", unassignedCycleEvents},
                                    {"first_cycle", Number(capture.cycles.first().number)},
                                    {"last_cycle", Number(capture.cycles.last().number)},
                                    {"unknown_description_events", Number(capture.unknownCount)},
                                    {"baseline_cycle_count", meta.value("baseline_cycle_count")}}},
        {"candidate_group_count", findings.size()}, {"omitted_candidate_groups", qMax(0, findings.size() - limit)},
        {"candidates", candidateJson}, {"data_quality", quality}, {"unknowns", unknownJson},
        {"source_lookup_codes", sourceLookupCodes},
        {"rca_trace", RcaTrace::Build(capture.snapshotEvents, traceInput)},
        {"export_policy", "parsed_log_events_with_log_basenames_no_absolute_paths"}
    };
    result.summary = lines.join('\n');
    result.success = true;
    return result;
}
