#include "OpbBaselineAnalyzer.h"
#include "LogCsvReader.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QList>
#include <QPair>
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

namespace {

struct DatabaseConnectionCleanup
{
    QString name;
    ~DatabaseConnectionCleanup() { QSqlDatabase::removeDatabase(name); }
};

struct CycleCodeData
{
    int count = 0;
    QVector<double> numericValues;
    QHash<QString, int> descriptions;
    QHash<QString, int> levels;
};

struct CycleData
{
    quint64 cycleNumber = 0u;
    int packetCount = 0;
    quint64 eventCount = 0u;
    QHash<QString, CycleCodeData> codes;
};

struct EventAggregate
{
    QString code;
    QHash<QString, int> descriptions;
    QHash<QString, int> levels;
    QVector<double> countsPerCycle;
    QVector<double> numericValues;
    quint64 eventCount = 0u;
    int cyclePresenceCount = 0;
};

struct Distribution
{
    int sampleCount = 0;
    double minimum = 0.0;
    double median = 0.0;
    double mad = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double maximum = 0.0;
    double mean = 0.0;
};

static QString NormalizeCode(const QString &text)
{
    bool ok = false;
    const uint value = text.trimmed().toUInt(&ok, 16);
    if(!ok)
    {
        return text.trimmed();
    }

    return QString("0x%1").arg(QString::number(value, 16).toUpper(), 4, QChar('0'));
}

static QString MostFrequent(const QHash<QString, int> &values)
{
    QString result;
    int resultCount = -1;

    QHash<QString, int>::const_iterator it = values.constBegin();
    while(it != values.constEnd())
    {
        if((it.value() > resultCount) ||
           ((it.value() == resultCount) && (it.key() < result)))
        {
            result = it.key();
            resultCount = it.value();
        }
        ++it;
    }

    return result;
}

static double Quantile(const QVector<double> &sortedValues, double probability)
{
    if(sortedValues.isEmpty())
    {
        return 0.0;
    }

    if(sortedValues.size() == 1)
    {
        return sortedValues.first();
    }

    const double position = probability * static_cast<double>(sortedValues.size() - 1);
    const int lowerIndex = static_cast<int>(std::floor(position));
    const int upperIndex = static_cast<int>(std::ceil(position));
    const double fraction = position - static_cast<double>(lowerIndex);

    return sortedValues.at(lowerIndex) * (1.0 - fraction) +
           sortedValues.at(upperIndex) * fraction;
}

static Distribution MakeDistribution(const QVector<double> &inputValues)
{
    Distribution result;
    if(inputValues.isEmpty())
    {
        return result;
    }

    QVector<double> values = inputValues;
    std::sort(values.begin(), values.end());

    result.sampleCount = values.size();
    result.minimum = values.first();
    result.median = Quantile(values, 0.50);
    result.p95 = Quantile(values, 0.95);
    result.p99 = Quantile(values, 0.99);
    result.maximum = values.last();

    double sum = 0.0;
    QVector<double> deviations;
    deviations.reserve(values.size());
    for(int index = 0; index < values.size(); ++index)
    {
        sum += values.at(index);
        deviations.append(std::fabs(values.at(index) - result.median));
    }
    result.mean = sum / static_cast<double>(values.size());

    std::sort(deviations.begin(), deviations.end());
    result.mad = Quantile(deviations, 0.50);
    return result;
}

static int CsvSegmentIndex(const QString &filePath)
{
    const QString fileName = QFileInfo(filePath).fileName();
    const QRegularExpression expression("\\.txt(\\d+)\\.csv$",
                                         QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = expression.match(fileName);
    if(!match.hasMatch())
    {
        return 0;
    }
    return match.captured(1).toInt();
}

static QString CaptureId(const QString &filePath)
{
    const QString fileName = QFileInfo(filePath).fileName();
    const QRegularExpression expression("^(.*\\.txt)\\d+\\.csv$",
                                         QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = expression.match(fileName);
    if(match.hasMatch())
    {
        return match.captured(1).toLower();
    }
    return fileName.toLower();
}

static bool IsEventLevel(const QString &level)
{
    return (level == QStringLiteral("错误")) ||
           (level == QStringLiteral("警告")) ||
           (level == QStringLiteral("提示")) ||
           (level == QStringLiteral("调试"));
}

static bool ExecuteSql(QSqlQuery &query, const QString &sql, QString *errorMessage)
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

static QVariant NullableValue(const Distribution &distribution, double value)
{
    if(distribution.sampleCount == 0)
    {
        return QVariant();
    }
    return QVariant(value);
}

} // namespace

OpbBaselineAnalyzer::BuildResult::BuildResult()
    : success(false),
      cancelled(false),
      totalEventCount(0u),
      baselineEventCount(0u),
      packetCount(0u),
      totalCycleCount(0),
      baselineCycleCount(0),
      excludedCycleCount(0),
      eventCodeCount(0),
      pendingDescriptionCodeCount(0),
      unknownDescriptionEventCount(0),
      baselineCycleStart(0u),
      baselineCycleEnd(0u)
{
}

OpbBaselineAnalyzer::OpbBaselineAnalyzer()
{
}

QStringList OpbBaselineAnalyzer::FindParsedCsvFiles(const QString &sourceLogPath)
{
    const QFileInfo sourceInfo(sourceLogPath);
    QDir directory(sourceInfo.absolutePath());
    const QString pattern = sourceInfo.fileName() + QStringLiteral("*.csv");
    const QFileInfoList files = directory.entryInfoList(QStringList() << pattern,
                                                        QDir::Files,
                                                        QDir::Name);

    QStringList result;
    for(int index = 0; index < files.size(); ++index)
    {
        result.append(files.at(index).absoluteFilePath());
    }

    std::sort(result.begin(), result.end(), [](const QString &left, const QString &right) {
        const int leftIndex = CsvSegmentIndex(left);
        const int rightIndex = CsvSegmentIndex(right);
        if(leftIndex == rightIndex)
        {
            return left < right;
        }
        return leftIndex < rightIndex;
    });
    return result;
}

OpbBaselineAnalyzer::BuildResult OpbBaselineAnalyzer::BuildBaseline(
        const QStringList &csvFilePaths,
        const QString &databasePath,
        const QString &softwareVersion,
        const std::shared_ptr<LogTaskControl> &control, const QString &boardType) const
{
    BuildResult result;
    LogTaskCompletion completion(control);
    const auto progress = [&](int percent, const QString &message) {
        if(control) control->SetProgress(percent, message);
    };
    const auto cancelled = [&]() {
        if(!control || !control->IsCancelled()) return false;
        result.cancelled = true;
        result.errorMessage = QStringLiteral("基线建立已取消，原有基线保持不变");
        return true;
    };
    progress(0, QStringLiteral("准备读取正常日志"));
    if(cancelled()) return result;
    result.databasePath = QFileInfo(databasePath).absoluteFilePath();
    QString boardError;
    const QString detectedBoard = BoardIdentity::fromFiles(csvFilePaths, &boardError, true);
    const QString board = detectedBoard.isEmpty() ? (boardType.isEmpty() ? QString("OPB") : boardType) : detectedBoard;
    if(!boardError.isEmpty() || !BoardIdentity::boards().contains(board) ||
       (!boardType.isEmpty() && !detectedBoard.isEmpty() && boardType != detectedBoard)) {
        result.errorMessage = boardError.isEmpty() ? QStringLiteral("基线板卡与日志板卡不一致") : boardError;
        return result;
    }
    if(QFileInfo(result.databasePath).isFile()) {
        const QString name = QUuid::createUuid().toString();
        QString existingBoard;
        {
            auto existing = QSqlDatabase::addDatabase("QSQLITE", name);
            existing.setDatabaseName(result.databasePath);
            existing.setConnectOptions("QSQLITE_OPEN_READONLY");
            if(existing.open() && existing.tables().contains("opb_baseline_meta")) {
                QSqlQuery query(existing);
                if(query.exec("SELECT value FROM opb_baseline_meta WHERE key='board_type'") && query.next()) existingBoard = query.value(0).toString();
            }
        }
        QSqlDatabase::removeDatabase(name);
        if(!existingBoard.isEmpty() && existingBoard != board) {
            result.errorMessage = QStringLiteral("所选数据库属于 %1，请为 %2 选择独立基线数据库").arg(existingBoard, board);
            return result;
        }
    }

    if(csvFilePaths.isEmpty())
    {
        result.errorMessage = QStringLiteral("未提供OPB解析CSV文件");
        return result;
    }

    QStringList orderedPaths = csvFilePaths;
    std::sort(orderedPaths.begin(), orderedPaths.end(), [](const QString &left, const QString &right) {
        const int leftIndex = CsvSegmentIndex(left);
        const int rightIndex = CsvSegmentIndex(right);
        if(leftIndex == rightIndex)
        {
            return left < right;
        }
        return leftIndex < rightIndex;
    });

    const QString captureId = CaptureId(orderedPaths.first());
    for(int pathIndex = 1; pathIndex < orderedPaths.size(); ++pathIndex)
    {
        if(CaptureId(orderedPaths.at(pathIndex)) != captureId)
        {
            result.errorMessage = QStringLiteral(
                        "第一阶段仅支持同一包正常日志的分段CSV；多包正常日志合并将在下一阶段实现");
            return result;
        }
    }

    QVector<CycleData> cycles;
    int currentCycleIndex = -1;
    bool hasPacketSequence = false;
    quint64 lastPacketSequence = 0u;
    int packetSequenceErrorCount = 0;
    qint64 totalBytes = 0, completedBytes = 0;
    for(const QString &path : orderedPaths) totalBytes += qMax<qint64>(0, QFileInfo(path).size());

    for(int fileIndex = 0; fileIndex < orderedPaths.size(); ++fileIndex)
    {
        if(cancelled()) return result;
        const QString csvPath = orderedPaths.at(fileIndex);
        QFile file(csvPath);
        if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            result.errorMessage = QStringLiteral("无法打开OPB解析文件: ") + csvPath;
            return result;
        }

        QTextStream stream(&file);
        LogCsvReader::Configure(stream, file);
        LogCsvReader csv;
        csv.expectedBoard = board;
        int lineNumber = 0;

        while(!stream.atEnd())
        {
            if(cancelled()) return result;
            const QString line = stream.readLine();
            ++lineNumber;
            if((lineNumber % 1024) == 0)
                // QTextStream::pos() may seek/rebuild the decoder buffer on
                // Windows CRLF files. Device progress is read-only (slightly ahead).
                progress(totalBytes > 0 ? static_cast<int>(55.0 * (completedBytes + file.pos()) / totalBytes) : 0,
                         QStringLiteral("读取 CSV %1/%2，已读 %3 条事件")
                         .arg(fileIndex + 1).arg(orderedPaths.size()).arg(result.totalEventCount));

            if(line.startsWith(QStringLiteral("Cycle Num :"))) continue;

            if(line.startsWith(QStringLiteral("包序号:")))
            {
                bool ok = false;
                const quint64 packetSequence = line.section(':', 1).trimmed().toULongLong(&ok, 10);
                if(!ok)
                {
                    result.errorMessage = QStringLiteral("包序号格式错误: %1:%2")
                            .arg(csvPath).arg(lineNumber);
                    return result;
                }

                if(hasPacketSequence && (packetSequence != (lastPacketSequence + 1u)))
                {
                    ++packetSequenceErrorCount;
                }
                hasPacketSequence = true;
                lastPacketSequence = packetSequence;
                ++result.packetCount;
                if(currentCycleIndex >= 0) ++cycles[currentCycleIndex].packetCount;
                continue;
            }

            QStringList fields;
            if(!csv.Read(line, &fields, &result.errorMessage))
            {
                result.errorMessage = QStringLiteral("OPB日志格式错误: %1:%2：%3")
                        .arg(csvPath).arg(lineNumber).arg(result.errorMessage);
                return result;
            }
            if(fields.isEmpty()) continue;
            if(csv.hasCycle && (currentCycleIndex < 0 || cycles.at(currentCycleIndex).cycleNumber != csv.cycle))
            {
                CycleData cycle; cycle.cycleNumber = csv.cycle; cycles.append(cycle);
                currentCycleIndex = cycles.size() - 1;
            }
            if(csv.hasPacket && (!hasPacketSequence || lastPacketSequence != csv.packet))
            {
                if(hasPacketSequence && csv.packet != lastPacketSequence + 1) ++packetSequenceErrorCount;
                hasPacketSequence = true; lastPacketSequence = csv.packet;
                ++result.packetCount;
                if(currentCycleIndex >= 0) ++cycles[currentCycleIndex].packetCount;
            }

            const QString level = fields.at(0).trimmed();
            if(!IsEventLevel(level))
            {
                result.errorMessage = QStringLiteral("未知日志等级: %1:%2")
                        .arg(csvPath).arg(lineNumber);
                return result;
            }

            if(currentCycleIndex < 0)
            {
                ++result.totalEventCount; // retain preamble count, exclude unassigned events from cycle statistics
                continue;
            }

            const QString code = NormalizeCode(fields.at(1));
            QString description = fields.at(2).trimmed();
            const QString decodedValue = fields.mid(4).join(QStringLiteral(",")).trimmed();

            if(description.isEmpty())
            {
                description = QStringLiteral("UNKNOWN:") + code;
                ++result.unknownDescriptionEventCount;
            }

            CycleData &cycle = cycles[currentCycleIndex];
            CycleCodeData &codeData = cycle.codes[code];
            ++codeData.count;
            ++codeData.descriptions[description];
            ++codeData.levels[level];
            ++cycle.eventCount;
            ++result.totalEventCount;

            bool numericOk = false;
            const double numericValue = decodedValue.toDouble(&numericOk);
            if(numericOk)
            {
                codeData.numericValues.append(numericValue);
            }
        }
        if(file.error() != QFile::NoError)
        {
            result.errorMessage = QStringLiteral("读取正常日志文件失败: ") + csvPath;
            return result;
        }
        completedBytes += file.size();
    }

    progress(55, QStringLiteral("检查周期连续性并统计基线"));
    if(cancelled()) return result;

    if(packetSequenceErrorCount > 0)
    {
        result.errorMessage = QStringLiteral("OPB包序号不连续，异常数量: %1")
                .arg(packetSequenceErrorCount);
        return result;
    }

    if(cycles.isEmpty())
    {
        result.errorMessage = QStringLiteral("未发现 0x0A1A 真实周期号，不能建立正常周期基线");
        return result;
    }

    int bestStartIndex = 0;
    int bestEndIndex = 0;
    int currentStartIndex = 0;

    for(int index = 1; index < cycles.size(); ++index)
    {
        if(cancelled()) return result;
        const quint64 previousCycle = cycles.at(index - 1).cycleNumber;
        const quint64 currentCycle = cycles.at(index).cycleNumber;
        const bool isContinuous = (currentCycle == (previousCycle + 1u)) ||
                ((previousCycle == 0xFFFFFFFFu) && (currentCycle == 0u));

        if(!isContinuous)
        {
            if((index - 1 - currentStartIndex) > (bestEndIndex - bestStartIndex))
            {
                bestStartIndex = currentStartIndex;
                bestEndIndex = index - 1;
            }
            currentStartIndex = index;
        }
    }

    if((cycles.size() - 1 - currentStartIndex) > (bestEndIndex - bestStartIndex))
    {
        bestStartIndex = currentStartIndex;
        bestEndIndex = cycles.size() - 1;
    }

    /* Capture files can start or end in the middle of a cycle.  Exclude the
       two boundary cycles from the longest continuous segment so truncated
       packets are not learned as normal missing events. */
    if((bestEndIndex - bestStartIndex + 1) > 2)
    {
        ++bestStartIndex;
        --bestEndIndex;
    }

    result.totalCycleCount = cycles.size();
    result.baselineCycleCount = bestEndIndex - bestStartIndex + 1;
    result.excludedCycleCount = result.totalCycleCount - result.baselineCycleCount;
    result.baselineCycleStart = cycles.at(bestStartIndex).cycleNumber;
    result.baselineCycleEnd = cycles.at(bestEndIndex).cycleNumber;

    QSet<QString> eventCodes;
    QVector<double> packetCounts;
    QVector<double> eventCounts;
    QHash<QString, EventAggregate> aggregates;

    for(int cycleIndex = bestStartIndex; cycleIndex <= bestEndIndex; ++cycleIndex)
    {
        if(cancelled()) return result;
        if(((cycleIndex - bestStartIndex) % 128) == 0)
            progress(55 + 10 * (cycleIndex - bestStartIndex) / qMax(1, result.baselineCycleCount),
                     QStringLiteral("统计正常周期 %1/%2")
                     .arg(cycleIndex - bestStartIndex).arg(result.baselineCycleCount));
        const CycleData &cycle = cycles.at(cycleIndex);
        packetCounts.append(static_cast<double>(cycle.packetCount));
        eventCounts.append(static_cast<double>(cycle.eventCount));
        result.baselineEventCount += cycle.eventCount;

        QHash<QString, CycleCodeData>::const_iterator codeIt = cycle.codes.constBegin();
        while(codeIt != cycle.codes.constEnd())
        {
            eventCodes.insert(codeIt.key());
            EventAggregate &aggregate = aggregates[codeIt.key()];
            aggregate.code = codeIt.key();
            aggregate.eventCount += static_cast<quint64>(codeIt.value().count);
            ++aggregate.cyclePresenceCount;
            aggregate.numericValues += codeIt.value().numericValues;

            QHash<QString, int>::const_iterator descriptionIt = codeIt.value().descriptions.constBegin();
            while(descriptionIt != codeIt.value().descriptions.constEnd())
            {
                aggregate.descriptions[descriptionIt.key()] += descriptionIt.value();
                ++descriptionIt;
            }

            QHash<QString, int>::const_iterator levelIt = codeIt.value().levels.constBegin();
            while(levelIt != codeIt.value().levels.constEnd())
            {
                aggregate.levels[levelIt.key()] += levelIt.value();
                ++levelIt;
            }
            ++codeIt;
        }
    }

    QStringList sortedCodes = eventCodes.values();
    std::sort(sortedCodes.begin(), sortedCodes.end());

    for(int codeIndex = 0; codeIndex < sortedCodes.size(); ++codeIndex)
    {
        if(cancelled()) return result;
        progress(65 + 10 * codeIndex / qMax(1, sortedCodes.size()),
                 QStringLiteral("整理编码 %1/%2").arg(codeIndex + 1).arg(sortedCodes.size()));
        const QString &code = sortedCodes.at(codeIndex);
        EventAggregate &aggregate = aggregates[code];
        aggregate.countsPerCycle.reserve(result.baselineCycleCount);
        for(int cycleIndex = bestStartIndex; cycleIndex <= bestEndIndex; ++cycleIndex)
        {
            aggregate.countsPerCycle.append(
                        static_cast<double>(cycles.at(cycleIndex).codes.value(code).count));
        }

        const QString description = MostFrequent(aggregate.descriptions);
        if(description.startsWith(QStringLiteral("待确认：")) ||
           description.startsWith(QStringLiteral("UNKNOWN:")))
        {
            ++result.pendingDescriptionCodeCount;
        }
    }
    result.eventCodeCount = sortedCodes.size();
    progress(75, QStringLiteral("开始写入基线数据库"));
    if(cancelled()) return result;

    const QFileInfo databaseInfo(result.databasePath);
    QDir databaseDirectory = databaseInfo.absoluteDir();
    if(!databaseDirectory.exists() && !databaseDirectory.mkpath(QStringLiteral(".")))
    {
        result.errorMessage = QStringLiteral("无法创建基线数据库目录: ") +
                databaseDirectory.absolutePath();
        return result;
    }

    const QString connectionName = QStringLiteral("OpbBaseline_%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    DatabaseConnectionCleanup connectionCleanup{connectionName};
    bool databaseSuccess = false;
    QString databaseError;

    {
        QSqlDatabase database = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"),
                                                          connectionName);
        database.setConnectOptions(QStringLiteral("QSQLITE_BUSY_TIMEOUT=2000"));
        database.setDatabaseName(result.databasePath);
        if(!database.open())
        {
            databaseError = database.lastError().text();
        }
        else
        {
            QSqlQuery query(database);
            databaseSuccess = database.transaction();
            if(!databaseSuccess) databaseError = database.lastError().text();
            databaseSuccess = databaseSuccess && ExecuteSql(query,
                    QStringLiteral("CREATE TABLE IF NOT EXISTS opb_baseline_meta ("
                                   "key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
                    &databaseError) &&
                    ExecuteSql(query,
                    QStringLiteral("CREATE TABLE IF NOT EXISTS opb_baseline_source ("
                                   "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                   "file_path TEXT NOT NULL, file_size INTEGER NOT NULL, "
                                   "modified_utc TEXT NOT NULL)"),
                    &databaseError) &&
                    ExecuteSql(query,
                    QStringLiteral("CREATE TABLE IF NOT EXISTS opb_cycle_metric ("
                                   "metric TEXT PRIMARY KEY, sample_count INTEGER NOT NULL, "
                                   "min REAL NOT NULL, median REAL NOT NULL, mad REAL NOT NULL, "
                                   "p95 REAL NOT NULL, p99 REAL NOT NULL, max REAL NOT NULL, "
                                   "mean REAL NOT NULL)"),
                    &databaseError) &&
                    ExecuteSql(query,
                    QStringLiteral("CREATE TABLE IF NOT EXISTS opb_event_baseline ("
                                   "code TEXT PRIMARY KEY, description TEXT NOT NULL, "
                                   "description_state TEXT NOT NULL, dominant_level TEXT NOT NULL, "
                                   "event_count INTEGER NOT NULL, cycle_presence_count INTEGER NOT NULL, "
                                   "baseline_cycle_count INTEGER NOT NULL, presence_rate REAL NOT NULL, "
                                   "count_min REAL NOT NULL, count_median REAL NOT NULL, "
                                   "count_p95 REAL NOT NULL, count_p99 REAL NOT NULL, "
                                   "count_max REAL NOT NULL, count_mean REAL NOT NULL, "
                                   "numeric_count INTEGER NOT NULL, value_min REAL, "
                                   "value_median REAL, value_mad REAL, value_p95 REAL, "
                                   "value_p99 REAL, value_max REAL, rule_state TEXT NOT NULL)"),
                    &databaseError);

            if(databaseSuccess)
            {
                databaseSuccess = ExecuteSql(query, QStringLiteral("DELETE FROM opb_baseline_meta"),
                                             &databaseError) &&
                        ExecuteSql(query, QStringLiteral("DELETE FROM opb_baseline_source"),
                                   &databaseError) &&
                        ExecuteSql(query, QStringLiteral("DELETE FROM opb_cycle_metric"),
                                   &databaseError) &&
                        ExecuteSql(query, QStringLiteral("DELETE FROM opb_event_baseline"),
                                   &databaseError);
            }

            if(databaseSuccess)
            {
                const QList<QPair<QString, QString> > metadata = {
                    qMakePair(QStringLiteral("schema_version"), QStringLiteral("1")),
                    qMakePair(QStringLiteral("board_type"), board),
                    qMakePair(QStringLiteral("software_version"),
                              softwareVersion.trimmed().isEmpty() ?
                                  QStringLiteral("UNKNOWN") : softwareVersion.trimmed()),
                    qMakePair(QStringLiteral("training_label"), QStringLiteral("normal")),
                    qMakePair(QStringLiteral("cycle_source"), QStringLiteral("0x0A1A")),
                    qMakePair(QStringLiteral("boundary_cycle_policy"),
                              QStringLiteral("exclude_first_and_last")),
                    qMakePair(QStringLiteral("created_utc"),
                              QDateTime::currentDateTimeUtc().toString(Qt::ISODate)),
                    qMakePair(QStringLiteral("source_file_count"),
                              QString::number(orderedPaths.size())),
                    qMakePair(QStringLiteral("source_capture_count"), QStringLiteral("1")),
                    qMakePair(QStringLiteral("total_event_count"),
                              QString::number(result.totalEventCount)),
                    qMakePair(QStringLiteral("baseline_event_count"),
                              QString::number(result.baselineEventCount)),
                    qMakePair(QStringLiteral("packet_count"),
                              QString::number(result.packetCount)),
                    qMakePair(QStringLiteral("total_cycle_count"),
                              QString::number(result.totalCycleCount)),
                    qMakePair(QStringLiteral("baseline_cycle_count"),
                              QString::number(result.baselineCycleCount)),
                    qMakePair(QStringLiteral("baseline_cycle_start"),
                              QString::number(result.baselineCycleStart)),
                    qMakePair(QStringLiteral("baseline_cycle_end"),
                              QString::number(result.baselineCycleEnd)),
                    qMakePair(QStringLiteral("excluded_cycle_count"),
                              QString::number(result.excludedCycleCount)),
                    qMakePair(QStringLiteral("event_code_count"),
                              QString::number(result.eventCodeCount)),
                    qMakePair(QStringLiteral("pending_description_code_count"),
                              QString::number(result.pendingDescriptionCodeCount)),
                    qMakePair(QStringLiteral("unknown_description_event_count"),
                              QString::number(result.unknownDescriptionEventCount))
                };

                query.prepare(QStringLiteral("INSERT INTO opb_baseline_meta(key, value) "
                                             "VALUES(:key, :value)"));
                for(int metadataIndex = 0; metadataIndex < metadata.size(); ++metadataIndex)
                {
                    if(cancelled()) { databaseSuccess = false; break; }
                    query.bindValue(QStringLiteral(":key"), metadata.at(metadataIndex).first);
                    query.bindValue(QStringLiteral(":value"), metadata.at(metadataIndex).second);
                    if(!query.exec())
                    {
                        databaseSuccess = false;
                        databaseError = query.lastError().text();
                        break;
                    }
                }
            }

            if(databaseSuccess)
            {
                query.prepare(QStringLiteral("INSERT INTO opb_baseline_source("
                                             "file_path, file_size, modified_utc) "
                                             "VALUES(:file_path, :file_size, :modified_utc)"));
                for(int pathIndex = 0; pathIndex < orderedPaths.size(); ++pathIndex)
                {
                    if(cancelled()) { databaseSuccess = false; break; }
                    const QFileInfo sourceInfo(orderedPaths.at(pathIndex));
                    query.bindValue(QStringLiteral(":file_path"), sourceInfo.absoluteFilePath());
                    query.bindValue(QStringLiteral(":file_size"), sourceInfo.size());
                    query.bindValue(QStringLiteral(":modified_utc"),
                                    sourceInfo.lastModified().toUTC().toString(Qt::ISODate));
                    if(!query.exec())
                    {
                        databaseSuccess = false;
                        databaseError = query.lastError().text();
                        break;
                    }
                }
            }

            if(databaseSuccess)
            {
                const QList<QPair<QString, Distribution> > cycleMetrics = {
                    qMakePair(QStringLiteral("packet_count_per_cycle"),
                              MakeDistribution(packetCounts)),
                    qMakePair(QStringLiteral("event_count_per_cycle"),
                              MakeDistribution(eventCounts))
                };

                query.prepare(QStringLiteral("INSERT INTO opb_cycle_metric("
                                             "metric, sample_count, min, median, mad, p95, p99, max, mean) "
                                             "VALUES(:metric, :sample_count, :min, :median, :mad, "
                                             ":p95, :p99, :max, :mean)"));
                for(int metricIndex = 0; metricIndex < cycleMetrics.size(); ++metricIndex)
                {
                    if(cancelled()) { databaseSuccess = false; break; }
                    const Distribution &distribution = cycleMetrics.at(metricIndex).second;
                    query.bindValue(QStringLiteral(":metric"), cycleMetrics.at(metricIndex).first);
                    query.bindValue(QStringLiteral(":sample_count"), distribution.sampleCount);
                    query.bindValue(QStringLiteral(":min"), distribution.minimum);
                    query.bindValue(QStringLiteral(":median"), distribution.median);
                    query.bindValue(QStringLiteral(":mad"), distribution.mad);
                    query.bindValue(QStringLiteral(":p95"), distribution.p95);
                    query.bindValue(QStringLiteral(":p99"), distribution.p99);
                    query.bindValue(QStringLiteral(":max"), distribution.maximum);
                    query.bindValue(QStringLiteral(":mean"), distribution.mean);
                    if(!query.exec())
                    {
                        databaseSuccess = false;
                        databaseError = query.lastError().text();
                        break;
                    }
                }
            }

            if(databaseSuccess)
            {
                query.prepare(QStringLiteral("INSERT INTO opb_event_baseline("
                                             "code, description, description_state, dominant_level, "
                                             "event_count, cycle_presence_count, baseline_cycle_count, "
                                             "presence_rate, count_min, count_median, count_p95, count_p99, "
                                             "count_max, count_mean, numeric_count, value_min, value_median, "
                                             "value_mad, value_p95, value_p99, value_max, rule_state) "
                                             "VALUES(:code, :description, :description_state, :dominant_level, "
                                             ":event_count, :cycle_presence_count, :baseline_cycle_count, "
                                             ":presence_rate, :count_min, :count_median, :count_p95, :count_p99, "
                                             ":count_max, :count_mean, :numeric_count, :value_min, :value_median, "
                                             ":value_mad, :value_p95, :value_p99, :value_max, :rule_state)"));

                for(int codeIndex = 0; codeIndex < sortedCodes.size(); ++codeIndex)
                {
                    progress(80 + 18 * codeIndex / qMax(1, sortedCodes.size()),
                             QStringLiteral("写入编码统计 %1/%2").arg(codeIndex + 1).arg(sortedCodes.size()));
                    if(cancelled()) { databaseSuccess = false; break; }
                    const EventAggregate &aggregate = aggregates.value(sortedCodes.at(codeIndex));
                    const QString description = MostFrequent(aggregate.descriptions);
                    const Distribution countDistribution = MakeDistribution(aggregate.countsPerCycle);
                    const Distribution valueDistribution = MakeDistribution(aggregate.numericValues);

                    query.bindValue(QStringLiteral(":code"), aggregate.code);
                    query.bindValue(QStringLiteral(":description"), description);
                    query.bindValue(QStringLiteral(":description_state"),
                                    (description.startsWith(QStringLiteral("待确认：")) ||
                                     description.startsWith(QStringLiteral("UNKNOWN:"))) ?
                                        QStringLiteral("unknown") : QStringLiteral("known"));
                    query.bindValue(QStringLiteral(":dominant_level"), MostFrequent(aggregate.levels));
                    query.bindValue(QStringLiteral(":event_count"),
                                    static_cast<qulonglong>(aggregate.eventCount));
                    query.bindValue(QStringLiteral(":cycle_presence_count"),
                                    aggregate.cyclePresenceCount);
                    query.bindValue(QStringLiteral(":baseline_cycle_count"),
                                    result.baselineCycleCount);
                    query.bindValue(QStringLiteral(":presence_rate"),
                                    static_cast<double>(aggregate.cyclePresenceCount) /
                                    static_cast<double>(result.baselineCycleCount));
                    query.bindValue(QStringLiteral(":count_min"), countDistribution.minimum);
                    query.bindValue(QStringLiteral(":count_median"), countDistribution.median);
                    query.bindValue(QStringLiteral(":count_p95"), countDistribution.p95);
                    query.bindValue(QStringLiteral(":count_p99"), countDistribution.p99);
                    query.bindValue(QStringLiteral(":count_max"), countDistribution.maximum);
                    query.bindValue(QStringLiteral(":count_mean"), countDistribution.mean);
                    query.bindValue(QStringLiteral(":numeric_count"), valueDistribution.sampleCount);
                    query.bindValue(QStringLiteral(":value_min"),
                                    NullableValue(valueDistribution, valueDistribution.minimum));
                    query.bindValue(QStringLiteral(":value_median"),
                                    NullableValue(valueDistribution, valueDistribution.median));
                    query.bindValue(QStringLiteral(":value_mad"),
                                    NullableValue(valueDistribution, valueDistribution.mad));
                    query.bindValue(QStringLiteral(":value_p95"),
                                    NullableValue(valueDistribution, valueDistribution.p95));
                    query.bindValue(QStringLiteral(":value_p99"),
                                    NullableValue(valueDistribution, valueDistribution.p99));
                    query.bindValue(QStringLiteral(":value_max"),
                                    NullableValue(valueDistribution, valueDistribution.maximum));
                    query.bindValue(QStringLiteral(":rule_state"), QStringLiteral("candidate"));

                    if(!query.exec())
                    {
                        databaseSuccess = false;
                        databaseError = query.lastError().text();
                        break;
                    }
                }
            }

            if(databaseSuccess)
            {
                progress(99, QStringLiteral("准备提交基线"));
                if(control && !control->BeginCommit())
                {
                    cancelled();
                    databaseSuccess = false;
                }
            }
            if(databaseSuccess)
            {
                databaseSuccess = database.commit();
                if(!databaseSuccess)
                {
                    databaseError = database.lastError().text();
                }
            }
            if(!databaseSuccess && database.isOpen())
            {
                database.rollback();
            }

            database.close();
        }
    }

    if(!databaseSuccess)
    {
        if(cancelled() || result.cancelled) return result;
        result.errorMessage = QStringLiteral("写入OPB基线数据库失败: ") + databaseError;
        return result;
    }

    result.success = true;
    progress(100, QStringLiteral("正常基线建立完成"));
    return result;
}
