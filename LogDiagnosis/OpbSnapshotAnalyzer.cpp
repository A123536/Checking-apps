#include "OpbSnapshotAnalyzer.h"
#include "LogCsvReader.h"
#include "RcaTrace.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonDocument>
#include <QMap>
#include <QSet>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTextStream>
#include <QUuid>
#include <QVariant>
#include <algorithm>
#include <cmath>
#include <limits>

namespace
{
QString Code(const QString &value)
{
    bool ok = false; const uint number = value.trimmed().toUInt(&ok, 16);
    return ok ? QStringLiteral("0x%1").arg(QString::number(number, 16).toUpper(), 4, '0') : QString();
}

bool Numeric(const QString &value, double *number)
{
    bool ok = false;
    *number = value.trimmed().toDouble(&ok);
    return ok && std::isfinite(*number);
}

QString Raw(const QString &value) { return value.simplified().toLower(); }
QString Key(const QString &raw, const QString &decoded)
{
    return Raw(raw) + QChar(0x1f) + decoded.trimmed();
}

bool Identity(const QString &label)
{
    return label.contains(QStringLiteral("版本")) || label.contains("MD5", Qt::CaseInsensitive) ||
            label.contains("checksum", Qt::CaseInsensitive);
}
bool Discrete(const QString &label)
{
    for(const QString &word : QStringList{QStringLiteral("状态"), QStringLiteral("标志"),
                                         QStringLiteral("自检结果"), QStringLiteral("开关"),
                                         QStringLiteral("板卡ID"), QStringLiteral("CPUID")})
        if(label.contains(word)) return true;
    return false;
}
bool SelfTestFocus(const QString &label)
{
    return label.contains(QStringLiteral("自检")) &&
            (label.contains(QStringLiteral("继电器")) || label.contains(QStringLiteral("光耦")) ||
             label.contains(QStringLiteral("输出")));
}

struct Variable
{
    quint64 count = 0;
    quint64 numericCount = 0;
    double low = std::numeric_limits<double>::infinity();
    double high = -std::numeric_limits<double>::infinity();
    QMap<QString, QJsonObject> values;
    QSet<QString> numbers;
    bool valuesComplete = true;
    bool numbersComplete = true;
    QString description;
    QString scope = QStringLiteral("normal_capture");

    void Add(const QString &raw, const QString &decoded, const QString &label)
    {
        ++count;
        if(description.isEmpty()) description = label.trimmed();
        const QString key = Key(raw, decoded);
        if(values.size() < 64 || values.contains(key))
            values.insert(key, QJsonObject{{"raw", raw.trimmed()}, {"decoded", decoded.trimmed()}});
        else valuesComplete = false;
        double number = 0;
        if(Numeric(decoded, &number))
        {
            ++numericCount; low = qMin(low, number); high = qMax(high, number);
            const QString numericKey = QString::number(number, 'g', 17);
            if(numbers.size() < 64 || numbers.contains(numericKey)) numbers.insert(numericKey);
            else numbersComplete = false;
        }
    }

    QJsonArray Samples(int limit = 12) const
    {
        QJsonArray result;
        for(auto it = values.constBegin(); it != values.constEnd() && result.size() < limit; ++it)
            result.append(it.value());
        return result;
    }
};

struct Source { QString path; qint64 size; QString modified; };

struct ReferenceConnection
{
    QString name = QUuid::createUuid().toString();
    QSqlDatabase db;
    explicit ReferenceConnection(const QString &path)
        : db(QSqlDatabase::addDatabase("QSQLITE", name))
    {
        db.setConnectOptions("QSQLITE_OPEN_READONLY"); db.setDatabaseName(path);
    }
    ~ReferenceConnection() { db.close(); db = QSqlDatabase(); QSqlDatabase::removeDatabase(name); }
};

struct Group
{
    QString rule, code, description, title, state;
    QJsonObject reference;
    quint64 first = 0, last = 0;
    int count = 0;
    QJsonArray examples;
};
}

OpbDiagnosticAnalyzer::Result OpbSnapshotAnalyzer::Analyze(
        const OpbDiagnosticAnalyzer::Input &input, const QVector<OpbSnapshotEvent> &events,
        const QString &sourceType, const QJsonArray &sourceReferences, bool versionMatched) const
{
    OpbDiagnosticAnalyzer::Result result;
    const auto cancelled = [&]() {
        if(input.cancelled && input.cancelled->load())
        {
            result.errorMessage = QStringLiteral("诊断已取消"); return true;
        }
        return false;
    };
    if(cancelled()) return result;
    QStringList limits;
    limits << QStringLiteral("本文件按宕机事件序列分析；周期仅来自 0x0A1A，事件序号只表示保存顺序，不是周期号或时间。")
           << QStringLiteral("本次只比较同一编码的变量值和日志明确记录的失败状态，不运行周期次数、缺失、包连续性规则。")
           << QStringLiteral("正常观测范围不是硬件安全限值；差异不直接等于根因，未知位定义、单位或阶段必须注明 UNKNOWN。")
           << QStringLiteral("完整正常日志参照可能混合启动和稳态阶段，同编码复用语义或阶段差异仍需人工确认。")
           << QStringLiteral("版本号、MD5 的跨日志差异单列为构建背景，不据此判断硬件或校验故障；包计数、温度、时间等也可能随工况变化。")
           << QStringLiteral("错误级别或明确失败是日志事实，可能是后续保护动作；不据最后一条错误直接确定根因。");
    if(!versionMatched) limits << QStringLiteral("软件版本兼容性 UNKNOWN。");

    QHash<QString, Variable> steady, reference;
    QVector<Source> sources;
    QSet<QString> wanted;
    for(const auto &event : events) wanted.insert(event.code);
    QString baselineCreated;
    if(QFileInfo(input.baselinePath).isFile()) {
        ReferenceConnection connection(input.baselinePath);
        if(!connection.db.open()) { result.errorMessage = QStringLiteral("无法读取正常变量参照"); return result; }
        QSqlQuery query(connection.db);
        if(!query.exec("SELECT code, description, numeric_count, value_min, value_max FROM opb_event_baseline"))
        { result.errorMessage = QStringLiteral("基线缺少数值统计"); return result; }
        while(query.next())
        {
            const QString code = Code(query.value(0).toString());
            if(!wanted.contains(code) || query.value(2).toLongLong() <= 0) continue;
            Variable variable;
            variable.description = query.value(1).toString();
            variable.numericCount = query.value(2).toULongLong();
            variable.low = query.value(3).toDouble(); variable.high = query.value(4).toDouble();
            variable.valuesComplete = false; variable.numbersComplete = false;
            variable.scope = QStringLiteral("steady_state_statistics");
            steady.insert(code, variable);
        }
        if(query.exec("SELECT file_path, file_size, modified_utc FROM opb_baseline_source ORDER BY id"))
            while(query.next()) sources.append({query.value(0).toString(), query.value(1).toLongLong(), query.value(2).toString()});
        if(query.exec("SELECT value FROM opb_baseline_meta WHERE key='created_utc'") && query.next())
            baselineCreated = query.value(0).toString();
    }

    bool completeCapture = !sources.isEmpty();
    QJsonArray normalHashes;
    // A partial set could hide valid values. Only publish complete references.
    QHash<QString, Variable> captureReference;
    for(const Source &source : sources)
    {
        if(cancelled()) return result;
        const QFileInfo info(source.path);
        if(!info.isFile() || info.size() != source.size ||
           (!source.modified.isEmpty() && info.lastModified().toUTC().toString(Qt::ISODate) != source.modified))
        { completeCapture = false; break; }
        QFile file(source.path);
        if(!file.open(QIODevice::ReadOnly)) { completeCapture = false; break; }
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if(!hash.addData(&file) || !file.seek(0)) { completeCapture = false; break; }
        normalHashes.append(QString::fromLatin1(hash.result().toHex()));
        QTextStream stream(&file);
        LogCsvReader::Configure(stream, file);
        LogCsvReader csv;
        csv.expectedBoard = input.boardType;
        while(!stream.atEnd())
        {
            if(cancelled()) return result;
            const QString line = stream.readLine();
            if(line.trimmed().isEmpty() || line.startsWith("Cycle Num :") ||
               line.startsWith(QStringLiteral("包序号:"))) continue;
            QStringList fields;
            if(!csv.Read(line, &fields, nullptr))
            { completeCapture = false; break; }
            if(fields.isEmpty()) continue;
            const QString code = Code(fields.at(1));
            if(code.isEmpty()) { completeCapture = false; break; }
            if(wanted.contains(code)) captureReference[code].Add(fields.at(3), fields.mid(4).join(','), fields.at(2));
        }
        if(!completeCapture || file.error() != QFile::NoError) { completeCapture = false; break; }
    }
    reference = steady;
    if(completeCapture)
    {
        for(auto it = captureReference.constBegin(); it != captureReference.constEnd(); ++it) reference.insert(it.key(), it.value());
        limits << QStringLiteral("数值参照优先使用该基线记录的完整正常日志（含上电过程），不以正常日志中未出现的变量直接认定故障。");
    }
    else
    {
        normalHashes = QJsonArray();
        limits << (QFileInfo(input.baselinePath).isFile()
                   ? QStringLiteral("正常源 CSV 缺失、已变更或无法完整读取，仅使用已有稳态数值统计；上电变量的参照可能不足。")
                   : QStringLiteral("未配置本板卡正常基线，本次仅使用日志明确失败记录与对应源码，不作数值范围差异推断。"));
    }

    QVector<Group> groups;
    QHash<QString, int> groupIndices;
    const auto add = [&](const QString &rule, const OpbSnapshotEvent &event, const QString &title,
                         const QString &state, const QJsonObject &normal) {
        const QString key = rule + ':' + event.code;
        if(!groupIndices.contains(key))
        {
            Group group;
            group.rule = rule; group.code = event.code; group.description = event.description;
            group.title = title; group.state = state; group.reference = normal; group.first = event.index;
            groupIndices.insert(key, groups.size()); groups.append(group);
        }
        Group &group = groups[groupIndices.value(key)];
        ++group.count; group.last = event.index;
        if(group.examples.size() < 3)
            group.examples.append(QJsonObject{{"event_index", QString::number(event.index)},
                                              {"cycle", event.hasCycle ? QJsonValue(QString::number(event.cycle)) : QJsonValue()},
                                              {"source_line", event.line}, {"raw", event.rawValue},
                                              {"decoded", event.decodedValue}});
    };

    QHash<QString, Variable> actual;
    QStringList order;
    int missingReferenceEvents = 0, numericCompared = 0;
    quint64 unknownDescriptions = 0;
    QJsonArray failures;
    QMap<QString, QJsonObject> errorLevelOnly;
    for(const auto &event : events)
    {
        if(cancelled()) return result;
        if(!actual.contains(event.code)) order.append(event.code);
        actual[event.code].Add(event.rawValue, event.decodedValue, event.description);
        if(event.description.isEmpty() || event.description.startsWith("UNKNOWN:") ||
           event.description.startsWith(QStringLiteral("待确认："))) ++unknownDescriptions;
        const bool hasReference = reference.contains(event.code);
        const Variable normal = reference.value(event.code);
        QJsonObject expected{{"scope", hasReference ? normal.scope : QStringLiteral("UNKNOWN")},
                             {"observed_values", normal.Samples()},
                             {"values_complete", hasReference && normal.valuesComplete && normal.values.size() <= 12}};
        if(normal.numericCount > 0)
            expected.insert("numeric_range", QJsonObject{{"min", normal.low}, {"max", normal.high}});
        const bool failure = event.decodedValue.trimmed() == QStringLiteral("失败") ||
                event.decodedValue.trimmed() == QStringLiteral("不通过") ||
                event.decodedValue.trimmed().compare("failed", Qt::CaseInsensitive) == 0;
        if(!failure && event.level == QStringLiteral("错误")) {
            QJsonObject entry = errorLevelOnly.value(event.code);
            if(entry.isEmpty()) entry = QJsonObject{{"code", event.code}, {"first_event_index", QString::number(event.index)}};
            entry.insert("count", entry.value("count").toInt() + 1);
            errorLevelOnly.insert(event.code, entry);
        }
        if(failure)
        {
            add("EXPLICIT_FAILURE_STATUS", event, QStringLiteral("日志解析值明确记录失败"), "observed_failure", expected);
            if(failures.size() < 30)
                failures.append(QJsonObject{{"event_index", QString::number(event.index)}, {"code", event.code},
                                           {"cycle", event.hasCycle ? QJsonValue(QString::number(event.cycle)) : QJsonValue()},
                                           {"description", event.description}, {"raw", event.rawValue},
                                           {"decoded", event.decodedValue}});
        }
        if(event.code == "0x0A1A") continue;
        if(!hasReference) { ++missingReferenceEvents; continue; }
        double number = 0;
        if(Numeric(event.decodedValue, &number) && normal.numericCount > 0)
        {
            ++numericCompared;
            if(number < normal.low || number > normal.high)
                add("VALUE_OUTSIDE_BASELINE", event, QStringLiteral("变量值超出正常观测范围"), "candidate", expected);
            else if(Discrete(event.description) && normal.numbersComplete && !normal.numbers.isEmpty() &&
                    !normal.numbers.contains(QString::number(number, 'g', 17)))
                add("VALUE_NOT_OBSERVED", event, QStringLiteral("正常样本未见该变量取值"), "candidate", expected);
        }
        else if(!failure && normal.valuesComplete && !normal.values.isEmpty() &&
                !normal.values.contains(Key(event.rawValue, event.decodedValue)))
            add("STATE_VALUE_DIFFERENCE", event, QStringLiteral("变量状态值与正常样本不同"), "candidate", expected);
    }
    // Explicit failures precede numeric candidates; reference gaps are never
    // elevated to confirmed faults. This is review order, not probability.
    std::stable_sort(groups.begin(), groups.end(), [](const Group &a, const Group &b) {
        const auto rank = [](const Group &group) {
            return group.state == "observed_failure" ? 0 : Identity(group.description) ? 3
                   : SelfTestFocus(group.description) || Discrete(group.description) ? 1 : 2;
        };
        return rank(a) < rank(b);
    });
    QJsonArray candidates;
    QJsonArray contextDifferences;
    int candidateCount = 0, contextCount = 0;
    QStringList report;
    report << QStringLiteral("%1 宕机日志：变量值比较完成").arg(input.boardType.isEmpty() ? QString("OPB") : input.boardType)
           << QStringLiteral("读取 %1 条事件；周期只认 0x0A1A，其他记录按原事件顺序比较。根因仍需确认。 ").arg(events.size())
           << QStringLiteral("数值可比较事件 %1 条；缺少正常参照事件 %2 条。")
              .arg(numericCompared).arg(missingReferenceEvents)
           << QStringLiteral("对照：正常范围 / 正常取值 → 当前变量值。") << QString();
    for(int index = 0; index < groups.size(); ++index)
    {
        const Group &group = groups.at(index);
        const bool context = group.state != "observed_failure" && Identity(group.description);
        const int count = context ? ++contextCount : ++candidateCount;
        if(count > (context ? 30 : 80)) continue;
        const QString id = QStringLiteral("%1%2").arg(context ? "C" : "E").arg(count, 3, 10, QChar('0'));
        QJsonObject evidence{{"evidence_id", id}, {"rule", group.rule}, {"code", group.code},
                                      {"description", group.description}, {"title", group.title},
                                      {"state", context ? QStringLiteral("context_difference") : group.state}, {"baseline", group.reference},
                                      {"first_event_index", QString::number(group.first)},
                                      {"last_event_index", QString::number(group.last)},
                                      {"affected_events", group.count}, {"examples", group.examples},
                                      {"interpretation_limit", context
                                           ? QStringLiteral("版本或构建标识变化不等于故障，需结合本日志自检结果。")
                                           : QStringLiteral("取值差异或失败记录可定位核查对象，不能单独确定物理根因。")}};
        if(context) contextDifferences.append(evidence);
        else candidates.append(evidence);
        const QJsonObject sample = group.examples.first().toObject();
        report << QStringLiteral("%1 %2 %3：%4；事件序号 %5；原值 %6，解析值 %7")
                  .arg(id, group.code, group.description, group.title, QString::number(group.first),
                       sample.value("raw").toString(), sample.value("decoded").toString());
        report << QStringLiteral("    正常参照：") + QString::fromUtf8(QJsonDocument(group.reference).toJson(QJsonDocument::Compact));
    }
    QJsonArray comparisons;
    for(const QString &code : order)
    {
        const Variable value = actual.value(code), normal = reference.value(code);
        const bool available = reference.contains(code);
        QJsonObject item{{"code", code}, {"description", value.description},
                         {"observed_values", value.Samples()},
                         {"observed_values_omitted_at_least", qMax(0, value.values.size() - 12)},
                         {"observed_values_complete", value.valuesComplete && value.values.size() <= 12},
                         {"reference_state", available ? "available" : "UNKNOWN"},
                         {"reference_scope", available ? normal.scope : QStringLiteral("UNKNOWN")},
                         {"normal_observation_count", normal.scope == "normal_capture" && available
                              ? QJsonValue(QString::number(normal.count)) : QJsonValue()},
                         {"normal_observed_values", normal.Samples()},
                         {"normal_values_complete", normal.valuesComplete && normal.values.size() <= 12}};
        if(value.numericCount) item.insert("actual_numeric_range", QJsonObject{{"min", value.low}, {"max", value.high}});
        if(normal.numericCount) item.insert("normal_numeric_range", QJsonObject{{"min", normal.low}, {"max", normal.high}});
        if(comparisons.size() < 200) comparisons.append(item);
    }
    QJsonArray tail;
    for(int index = qMax(0, events.size() - 16); index < events.size(); ++index)
    {
        const auto &event = events.at(index);
        tail.append(QJsonObject{{"event_index", QString::number(event.index)}, {"code", event.code},
                                {"cycle", event.hasCycle ? QJsonValue(QString::number(event.cycle)) : QJsonValue()},
                                {"description", event.description}, {"raw", event.rawValue}, {"decoded", event.decodedValue}});
    }
    QJsonArray errorLevelCodes;
    for(auto it = errorLevelOnly.constBegin(); it != errorLevelOnly.constEnd(); ++it) errorLevelCodes.append(it.value());
    QJsonArray unknowns; for(const QString &limit : limits) unknowns.append(limit);
    if(candidateCount == 0) report << QStringLiteral("当前参照未发现候选异常，不能据此断定正常。");
    report << QString() << QStringLiteral("未知与限制：") << limits;
    int cycleCount = 0, unassigned = 0;
    QJsonValue firstCycle, lastCycle;
    for(const auto &event : events)
    {
        if(!event.hasCycle) { ++unassigned; continue; }
        const QString value = QString::number(event.cycle);
        if(lastCycle.isNull() || lastCycle.toString() != value) ++cycleCount;
        if(firstCycle.isNull()) firstCycle = value;
        lastCycle = value;
    }
    report << QStringLiteral("0x0A1A 已确认周期段数：%1；范围：%2 - %3；周期未知事件：%4。")
              .arg(cycleCount).arg(firstCycle.isNull() ? QStringLiteral("未知") : firstCycle.toString(),
                                   lastCycle.isNull() ? QStringLiteral("未知") : lastCycle.toString()).arg(unassigned);
    result.evidence = QJsonObject{
        {"schema_version", "opb-diagnostic-evidence/1"}, {"board_type", input.boardType.isEmpty() ? QString("OPB") : input.boardType},
        {"generated_utc", QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
        {"analysis_mode", "crash_snapshot_values"}, {"root_cause_status", "UNKNOWN"},
        {"cycle_source", "0x0A1A"},
        {"rule_state", "candidate"}, {"source_type", sourceType}, {"source_references", sourceReferences},
        {"version_match", versionMatched ? "matched" : "UNKNOWN"},
        {"baseline_reference", QJsonObject{{"created_utc", baselineCreated},
                                            {"available", QFileInfo(input.baselinePath).isFile()},
                                           {"normal_capture_complete", completeCapture}, {"normal_source_sha256", normalHashes}}},
        {"statistics", QJsonObject{{"event_count", QString::number(events.size())}, {"cycle_segment_count", cycleCount},
                                    {"first_cycle", firstCycle}, {"last_cycle", lastCycle},
                                    {"unassigned_cycle_events", unassigned},
                                    {"numeric_compared_events", numericCompared}, {"reference_missing_events", missingReferenceEvents},
                                    {"unknown_description_events", QString::number(unknownDescriptions)}}},
        {"skipped_rules", QJsonArray{"COUNT_ABOVE_P99", "STABLE_CODE_MISSING", "CYCLE_DISCONTINUITY", "PACKET_DISCONTINUITY"}},
        {"candidate_group_count", candidateCount}, {"omitted_candidate_groups", qMax(0, candidateCount - 80)},
        {"context_differences", contextDifferences}, {"omitted_context_groups", qMax(0, contextCount - 30)},
        {"candidates", candidates}, {"variable_comparisons", comparisons},
        {"omitted_variable_codes", qMax(0, order.size() - 200)}, {"explicit_failures", failures},
        {"sequence_tail", tail}, {"data_quality", QJsonArray()}, {"unknowns", unknowns},
        {"error_level_only_codes", errorLevelCodes},
        {"rca_trace", RcaTrace::Build(events, input)},
        {"export_policy", "parsed_log_events_with_log_basenames_no_absolute_paths"}
    };
    result.summary = report.join('\n'); result.success = true;
    return result;
}
