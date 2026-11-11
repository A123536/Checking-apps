#include "OpbDiagnosticAnalyzer.h"
#include "OpbFaultSampleStore.h"
#include "OpbBaselineAnalyzer.h"
#include "LogCsvReader.h"
#include "RcaTrace.h"

#include <QFile>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QTest>
#include <QTextStream>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QUuid>
#include <QVariant>

class DiagnosisTests : public QObject
{
    Q_OBJECT
    QTemporaryDir directory;
    QString baselinePath;
    QString fixturePath;

    QByteArray FileHash(const QString &path)
    {
        QFile file(path);
        if(!file.open(QIODevice::ReadOnly)) return QByteArray();
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(&file);
        return hash.result();
    }
    QVariant Sql(const QString &path, const QString &sql)
    {
        const QString name = QUuid::createUuid().toString();
        QVariant result;
        {
            auto db = QSqlDatabase::addDatabase("QSQLITE", name);
            db.setDatabaseName(path);
            if(db.open())
            {
                QSqlQuery query(db);
                if(query.exec(sql)) result = query.next() ? query.value(0) : QVariant(true);
            }
        }
        QSqlDatabase::removeDatabase(name);
        return result;
    }

    QString Event(const QString &code = "0x0001", const QString &value = "10")
    {
        return QStringLiteral("调试,%1,测试事件,0x00,%2\n").arg(code, value);
    }
    QString Cycle(int cycle, const QString &events, int packet = -1)
    {
        return QStringLiteral("Cycle Num : 999999\n提示,0x0A1A,新周期号,,%1\n包序号: %2\n%3")
                .arg(cycle).arg(packet < 0 ? cycle : packet).arg(events);
    }
    bool Write(const QString &path, const QString &body, const char *codec = "GB18030")
    {
        QFile file(path);
        if(!file.open(QIODevice::WriteOnly)) return false;
        QTextStream out(&file); out.setCodec(codec);
        out << QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n") << body;
        out.flush(); return out.status() == QTextStream::Ok;
    }
    OpbDiagnosticAnalyzer::Result Diagnose(const QString &body)
    {
        if(!Write(fixturePath, body)) return OpbDiagnosticAnalyzer::Result();
        OpbDiagnosticAnalyzer::Input input;
        input.csvPaths << fixturePath; input.baselinePath = baselinePath; input.softwareVersion = "v1";
        return OpbDiagnosticAnalyzer().Analyze(input);
    }
    QJsonObject Finding(const OpbDiagnosticAnalyzer::Result &result, const QString &rule)
    {
        for(const QJsonValue &item : result.evidence.value("candidates").toArray())
            if(item.toObject().value("rule").toString() == rule) return item.toObject();
        return QJsonObject();
    }

private slots:
    void rcaTracePreservesCycleBoundariesBytesAndStoredNames()
    {
        const QString name = directory.filePath("DownLog_OPB_H_A_G_2026.11.04_11.13.02.txt宕机.csv");
        QVERIFY(Write(name, QStringLiteral("调试,0x0F07,计数器,0x00 0x03,0 3\n") +
                      Cycle(1665, Event() + QStringLiteral("提示,0x0A1A,重复周期边界,,1665\n")) + Cycle(1666, QStringLiteral("警告,0x0084,发送自检结果,0xaa,失败\n"))));
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baselinePath; input.csvPaths = QStringList{name};
        const auto result = OpbDiagnosticAnalyzer().Analyze(input); QVERIFY2(result.success, qPrintable(result.errorMessage));
        const auto trace = result.evidence["rca_trace"].toObject();
        const auto events = trace["events"].toArray();
        QCOMPARE(trace["observed_cycle_marker_count"].toInt(), 3);
        QCOMPARE(trace["observed_cycle_segment_count"].toInt(), 2);
        QCOMPARE(trace["cycle_segments"].toArray().size(), 3);
        QCOMPARE(events[0].toObject()["raw"].toString(), QString("0x00 0x03"));
        QVERIFY(events[0].toObject()["cycle"].isNull());
        QVERIFY(events[0].toObject()["source_line"].toInt() > 0);
        const auto identity = trace["sources"].toArray()[0].toObject();
        QCOMPARE(identity["end"].toString(), QString("H"));
        QCOMPARE(identity["system"].toString(), QString("A"));
        QCOMPARE(identity["network"].toString(), QString("G"));
        QCOMPARE(identity["board_type"].toString(), QString("OPB"));
        const auto imported = OpbFaultSampleStore().ImportIncident({name}, directory.filePath("rca-stored.db"), "OPB");
        QVERIFY(imported.success); QVERIFY(QFile::remove(name));
        input.csvPaths.clear(); input.faultDatabasePath = imported.databasePath; input.incidentId = imported.incidentId;
        const auto stored = OpbDiagnosticAnalyzer().Analyze(input); QVERIFY2(stored.success, qPrintable(stored.errorMessage));
        QCOMPARE(stored.evidence["rca_trace"].toObject()["sources"], trace["sources"]);
        QVector<OpbSnapshotEvent> large;
        for(int i = 0; i < 3000; ++i) {
            OpbSnapshotEvent event; event.index = i + 1; event.line = i + 2; event.code = "0x0F07";
            event.rawValue = QString(200, 'a'); large.append(event);
        }
        const auto limited = RcaTrace::Build(large, input);
        QVERIFY(limited["truncated"].toBool());
        QVERIFY(limited["events"].toArray().size() < large.size());
        QVERIFY(QJsonDocument(limited).toJson(QJsonDocument::Compact).size() <= limited["max_bytes"].toInt());
        QCOMPARE(limited["observed_cycle_marker_count"].toInt(), 0);
        QVERIFY(limited["cycle_segments"].toArray()[0].toObject()["cycle"].isNull());
    }

    void fourBoardsUseIsolatedBaselinesAndOptionalReference()
    {
        QSet<qint64> incidents;
        const QString faultDatabase = directory.filePath("four-board-faults.db");
        for(const QString &board : BoardIdentity::boards()) {
            const QString normal = directory.filePath(board + "_normal.txt1.csv");
            const QString baseline = directory.filePath(board + "_baseline.db");
            QString body;
            for(int cycle = 1; cycle <= 6; ++cycle) body += Cycle(cycle, Event());
            QVERIFY(Write(normal, body));
            const auto built = OpbBaselineAnalyzer().BuildBaseline({normal}, baseline, "v1");
            QVERIFY2(built.success, qPrintable(built.errorMessage));
            QCOMPARE(Sql(baseline, "SELECT value FROM opb_baseline_meta WHERE key='board_type'").toString(), board);
            const QString suspect = directory.filePath(board + "_suspect.txt1.csv");
            QVERIFY(Write(suspect, QStringLiteral("警告,0x0084,发送自检结果,0xaa,失败\n")));
            OpbDiagnosticAnalyzer::Input input; input.csvPaths = QStringList{suspect}; input.baselinePath = baseline;
            const auto result = OpbDiagnosticAnalyzer().Analyze(input);
            QVERIFY2(result.success, qPrintable(result.errorMessage));
            QCOMPARE(result.evidence["board_type"].toString(), board);
            const auto imported = OpbFaultSampleStore().ImportIncident({suspect}, faultDatabase, board);
            QVERIFY2(imported.success, qPrintable(imported.errorMessage));
            QVERIFY(!incidents.contains(imported.incidentId)); incidents.insert(imported.incidentId);
            QVERIFY(OpbFaultSampleStore().ImportIncident({suspect}, faultDatabase, board).duplicate);
            input.baselinePath = directory.filePath("missing-" + board + ".db");
            input.allowMissingBaseline = true;
            const auto withoutBaseline = OpbDiagnosticAnalyzer().Analyze(input);
            QVERIFY2(withoutBaseline.success, qPrintable(withoutBaseline.errorMessage));
            QCOMPARE(withoutBaseline.evidence["board_type"].toString(), board);
            QVERIFY(!withoutBaseline.evidence["explicit_failures"].toArray().isEmpty());
            QVERIFY(!withoutBaseline.evidence["baseline_reference"].toObject()["available"].toBool());
            if(board != "OPB") {
                input.baselinePath = baselinePath;
                QVERIFY(!OpbDiagnosticAnalyzer().Analyze(input).success);
                const auto wrongOverwrite = OpbBaselineAnalyzer().BuildBaseline({normal}, baselinePath, "v1");
                QVERIFY(!wrongOverwrite.success);
            }
        }
        QString reason;
        QVERIFY(BoardIdentity::fromFiles({"OPB_a.csv", "IPB_a.csv"}, &reason).isEmpty());
        QVERIFY(!reason.isEmpty());
        QVERIFY(BoardIdentity::fromName("OPB_IPB_a.csv", &reason).isEmpty());
        QCOMPARE(BoardIdentity::fromName("downlog_spb_a.csv"), QString("SPB"));
        const QString conflict = directory.filePath("OPB_conflict.csv");
        QFile conflicting(conflict); QVERIFY(conflicting.open(QIODevice::WriteOnly));
        conflicting.write(QStringLiteral("板卡类型,消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\nIPB,警告,0x0084,自检结果,0xaa,失败\n").toUtf8()); conflicting.close();
        OpbDiagnosticAnalyzer::Input input; input.csvPaths = QStringList{conflict}; input.baselinePath = baselinePath;
        const auto mismatch = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY(!mismatch.success);
        QVERIFY(mismatch.errorMessage.contains(QStringLiteral("板卡")));
    }

    void initTestCase()
    {
        QVERIFY(directory.isValid());
        baselinePath = directory.filePath("baseline.db");
        fixturePath = directory.filePath("suspect.txt1.csv");
        const QString normal = directory.filePath("normal.txt1.csv");
        QString body;
        for(int i = 1; i <= 6; ++i) body += Cycle(i, Event());
        QVERIFY(Write(normal, body));
        const auto baseline = OpbBaselineAnalyzer().BuildBaseline({normal}, baselinePath, "v1");
        QVERIFY2(baseline.success, qPrintable(baseline.errorMessage));
    }

    void normalIsNotDeclaredHealthy()
    {
        const auto result = Diagnose(Cycle(10, Event()) + Cycle(11, Event()) + Cycle(12, Event()));
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("candidates").toArray().size(), 0);
        QCOMPARE(result.evidence.value("root_cause_status").toString(), QString("UNKNOWN"));
        QCOMPARE(result.evidence.value("version_match").toString(), QString("matched"));
    }

    void fourDifferencesHaveCycleEvidence()
    {
        const auto result = Diagnose(Cycle(10, Event()) +
                                    Cycle(11, Event("0x0001", "30") + Event() + Event("0x0002")) +
                                    Cycle(12, Event("0x0002")) + Cycle(13, Event()));
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        for(const QString &rule : QStringList{"NEW_CODE", "COUNT_ABOVE_P99", "VALUE_OUTSIDE_BASELINE", "STABLE_CODE_MISSING"})
        {
            const QJsonObject f = Finding(result, rule);
            QVERIFY2(!f.isEmpty(), qPrintable(rule));
            QVERIFY(!f.value("evidence_id").toString().isEmpty());
            QCOMPARE(f.value("state").toString(), QString("candidate"));
        }
        QCOMPARE(Finding(result, "STABLE_CODE_MISSING").value("first_cycle").toString(), QString("12"));
    }

    void boundariesDoNotCreateMissingOrFrequencyClaims()
    {
        const auto result = Diagnose(Cycle(10, Event("0x0002")) + Cycle(11, Event()) +
                                    Cycle(12, Event() + Event()));
        QVERIFY(result.success);
        QVERIFY(Finding(result, "STABLE_CODE_MISSING").isEmpty());
        QVERIFY(Finding(result, "COUNT_ABOVE_P99").isEmpty());
    }

    void packetGapIsUnknownAndSuppressesMissing()
    {
        const auto result = Diagnose(Cycle(10, Event(), 10) + Cycle(11, Event("0x0002"), 13) +
                                    Cycle(12, Event(), 14));
        QVERIFY(result.success);
        QVERIFY(Finding(result, "STABLE_CODE_MISSING").isEmpty());
        QCOMPARE(result.evidence.value("data_quality").toArray().size(), 1);
        QCOMPARE(result.evidence.value("data_quality").toArray().first().toObject().value("state").toString(), QString("UNKNOWN"));
    }

    void splitCycleAcrossFilesMatchesSingleFile()
    {
        const QString one = Cycle(10, Event()) + Cycle(11, Event() + Event()) + Cycle(12, Event());
        const auto single = Diagnose(one);
        const QString path2 = directory.filePath("suspect.txt2.csv");
        QVERIFY(Write(fixturePath, Cycle(10, Event()) + Cycle(11, Event())));
        QVERIFY(Write(path2, Event() + Cycle(12, Event())));
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = baselinePath; input.csvPaths = QStringList{path2, fixturePath}; input.softwareVersion = "v1";
        const auto split = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(split.success, qPrintable(split.errorMessage));
        QCOMPARE(split.evidence.value("candidates"), single.evidence.value("candidates"));
        QCOMPARE(split.evidence.value("statistics"), single.evidence.value("statistics"));
    }

    void utf8QuotedCsvAndUnknownDescriptions()
    {
        QVERIFY(Write(fixturePath, Cycle(10, QStringLiteral("调试,0x0001,\"描述,带逗号\",0x00,10\n")) +
                      Cycle(11, QStringLiteral("调试,0x0001,,0x00,10\n")) + Cycle(12, Event()), "UTF-8"));
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = baselinePath; input.csvPaths << fixturePath;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("statistics").toObject().value("unknown_description_events").toString(), QString("1"));
        QCOMPARE(result.evidence.value("version_match").toString(), QString("UNKNOWN"));
    }

    void compatibleCsvLayoutsAndEncodings_data()
    {
        QTest::addColumn<QString>("header"); QTest::addColumn<QString>("event");
        QTest::addColumn<QByteArray>("codec"); QTest::addColumn<QString>("description");
        QTest::addColumn<QString>("decoded");
        const QString compact = QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n");
        const QString extended = QStringLiteral("板卡类型,周期号,") + compact;
        QTest::newRow("legacy-seven-header-five-values-gb18030")
                << extended << QStringLiteral("错误,0x002b,\"自检时模拟量回采到的值,0xaa,失败\n")
                << QByteArray("GB18030") << QStringLiteral("\"自检时模拟量回采到的值") << QStringLiteral("失败");
        QTest::newRow("real-seven-columns-utf8-bom")
                << extended << QStringLiteral("OPB,,错误,0x002b,自检结果,0xaa,失败\n")
                << QByteArray("UTF-8") << QStringLiteral("自检结果") << QStringLiteral("失败");
        QTest::newRow("timestamp-quoted-fields-utf16")
                << (QStringLiteral("时间戳,") + compact)
                << QStringLiteral("12:30:00,错误,0x002b,\"自检,\"\"回采\"\"\",0xaa,\"失败,待查\"\n")
                << QByteArray("UTF-16") << QStringLiteral("自检,\"回采\"") << QStringLiteral("失败,待查");
        QTest::newRow("compact-unquoted-value-tail")
                << compact << QStringLiteral("错误,0x002b,自检结果,0xaa,失败,待查\n")
                << QByteArray("GB18030") << QStringLiteral("自检结果") << QStringLiteral("失败,待查");
        QTest::newRow("reordered-columns")
                << QStringLiteral("消息编码,消息类型,消息内容解释,消息编码解释,消息内容(16进制)\n")
                << QStringLiteral("0x002b,错误,失败,自检结果,0xaa\n")
                << QByteArray("UTF-8") << QStringLiteral("自检结果") << QStringLiteral("失败");
    }

    void compatibleCsvLayoutsAndEncodings()
    {
        QFETCH(QString, header); QFETCH(QString, event); QFETCH(QByteArray, codec);
        QFETCH(QString, description); QFETCH(QString, decoded);
        QTemporaryDir temp;
        const QString path = temp.filePath("OPB_compat.txt.csv");
        QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly));
        QTextStream out(&file); out.setCodec(codec.constData());
        out.setGenerateByteOrderMark(codec != "GB18030"); out << header << event; out.flush(); file.close();
        const auto original = FileHash(path);
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baselinePath; input.csvPaths << path;
        const auto direct = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(direct.success, qPrintable(direct.errorMessage));
        QCOMPARE(direct.evidence.value("statistics").toObject().value("event_count").toString(), QString("1"));
        const auto db = temp.filePath("fault.db");
        const auto stored = OpbFaultSampleStore().ImportIncident({path}, db, "OPB");
        QVERIFY2(stored.success, qPrintable(stored.errorMessage)); QCOMPARE(stored.eventCount, quint64(1));
        QCOMPARE(Sql(db, "SELECT description FROM fault_snapshot_event").toString(), description);
        QCOMPARE(Sql(db, "SELECT decoded_value FROM fault_snapshot_event").toString(), decoded);
        QCOMPARE(Sql(db, "SELECT raw_value FROM fault_snapshot_event").toString(), QString("0xaa"));
        input.csvPaths.clear(); input.faultDatabasePath = db; input.incidentId = stored.incidentId;
        const auto replay = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(replay.success, qPrintable(replay.errorMessage));
        QCOMPARE(replay.evidence.value("candidates"), direct.evidence.value("candidates"));
        QCOMPARE(FileHash(path), original);
    }

    void inlineCycleColumnsAreRetainedByAnalysisAndImport()
    {
        QTemporaryDir temp; const QString path = temp.filePath("OPB_inline.csv");
        QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly));
        QTextStream out(&file); out.setCodec("UTF-8");
        out << QStringLiteral("板卡类型,周期号,包序号,消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n");
        for(int i=10; i<=14; ++i)
            out << QStringLiteral("OPB,999999,%1,提示,0x0A1A,新周期号,,%1\nOPB,888888,%1,调试,0x0001,测试,0x00,10\n").arg(i);
        out.flush(); file.close();
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baselinePath; input.csvPaths << path;
        const auto direct = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(direct.success, qPrintable(direct.errorMessage));
        QCOMPARE(direct.evidence.value("analysis_mode").toString(), QString("cyclic_log"));
        QCOMPARE(direct.evidence.value("statistics").toObject().value("event_count").toString(), QString("10"));
        const auto stored = OpbFaultSampleStore().ImportIncident({path}, temp.filePath("fault.db"), "OPB");
        QVERIFY2(stored.success, qPrintable(stored.errorMessage));
        QCOMPARE(stored.logFormat, QString("cyclic")); QCOMPARE(stored.cycleCount, 5);
        QCOMPARE(stored.cycleStart, quint64(10)); QCOMPARE(stored.cycleEnd, quint64(14));
        const auto built = OpbBaselineAnalyzer().BuildBaseline({path}, temp.filePath("normal.db"));
        QVERIFY2(built.success, qPrintable(built.errorMessage)); QCOMPARE(built.totalEventCount, quint64(10));
    }

    void only0A1AEstablishesCyclesAndPreambleStaysUnknown()
    {
        QTemporaryDir temp; const QString path = temp.filePath("OPB_cycles.csv");
        QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly));
        QTextStream out(&file); out.setCodec("UTF-8");
        out << QStringLiteral("板卡类型,周期号,消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n"
                              "Cycle Num : 123456\n"
                              "OPB,123456,调试,0x0001,启动,0x00,10\n"
                              "OPB,888888,提示,0x0a1a,新周期号,0x00 0x00 0x06 0x81,1665\n"
                              "OPB,999999,错误,0x002b,自检结果,0xaa,失败\n"
                              "Cycle Num : 555555\n"
                              "OPB,777777,提示,0x0A1A,新周期号,0x00 0x00 0x06 0x82,1666\n"
                              "OPB,666666,调试,0x0001,运行,0x00,10\n");
        out.flush(); file.close();
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baselinePath; input.csvPaths << path;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        const auto stats = result.evidence.value("statistics").toObject();
        QCOMPARE(stats.value("event_count").toString(), QString("5"));
        QCOMPARE(stats.value("first_cycle").toString(), QString("1665"));
        QCOMPARE(stats.value("last_cycle").toString(), QString("1666"));
        QCOMPARE(stats.value("cycle_segment_count").toInt(), 2);
        QCOMPARE(stats.value("unassigned_cycle_events").toInt(), 1);
        const auto imported = OpbFaultSampleStore().ImportIncident({path}, temp.filePath("fault.db"), "OPB");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));
        QCOMPARE(imported.eventCount, quint64(5)); QCOMPARE(imported.cycleCount, 2);
        QCOMPARE(imported.cycleStart, quint64(1665)); QCOMPARE(imported.cycleEnd, quint64(1666));
        input.csvPaths.clear(); input.faultDatabasePath = imported.databasePath; input.incidentId = imported.incidentId;
        const auto replay = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(replay.success, qPrintable(replay.errorMessage));
        QCOMPARE(replay.evidence.value("statistics"), result.evidence.value("statistics"));
        QVERIFY(Write(path, QStringLiteral("Cycle Num : 123\n调试,0x0001,周期号,0x00,10\n")));
        input.csvPaths = QStringList{path}; input.incidentId = 0;
        const auto noCycle = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY(noCycle.success);
        QVERIFY(noCycle.evidence.value("statistics").toObject().value("first_cycle").isNull());
        const auto rejected = OpbBaselineAnalyzer().BuildBaseline({path}, temp.filePath("not-normal.db"));
        QVERIFY(!rejected.success);
    }

    void multiplePacketsCanBelongToOneTrueCycle()
    {
        QString body;
        for(int i=1; i<=6; ++i)
            body += Cycle(i, Event() + QStringLiteral("包序号: %1\n").arg(i*2) + Event(), i*2-1);
        QTemporaryDir temp; const QString path = temp.filePath("OPB_multi_packet.csv");
        QVERIFY(Write(path, body));
        const auto result = OpbBaselineAnalyzer().BuildBaseline({path}, temp.filePath("normal.db"));
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.totalCycleCount, 6); QCOMPARE(result.packetCount, quint64(12));
    }

    void brokenQuotedValuesAreNotSilentlyAccepted()
    {
        const auto broken = Diagnose(Cycle(10, QStringLiteral("调试,0x0001,测试,0x00,\"10\n")));
        QVERIFY(!broken.success); QVERIFY(broken.evidence.isEmpty());
    }

    void storedIncidentSurvivesCsvRemovalAndDoesNotLeakLabel()
    {
        const QString path = directory.filePath("stored.txt1.csv");
        QVERIFY(Write(path, Cycle(10, Event()) + Cycle(11, Event("0x0001", "30")) + Cycle(12, Event())));
        const QString faultPath = directory.filePath("fault.db");
        const auto imported = OpbFaultSampleStore().ImportIncident({path}, faultPath, "OPB", "secret_cause_label");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));
        QVERIFY(QFile::remove(path));
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = baselinePath; input.faultDatabasePath = faultPath; input.incidentId = imported.incidentId;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QVERIFY(!Finding(result, "VALUE_OUTSIDE_BASELINE").isEmpty());
        const QByteArray json = QJsonDocument(result.evidence).toJson();
        QVERIFY(!json.contains("secret_cause_label"));
        QVERIFY(!json.contains(directory.path().toUtf8()));
    }

    void rejectsMismatchMissingBaselineAndMixedCaptures()
    {
        QVERIFY(Write(fixturePath, Cycle(10, Event())));
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = baselinePath; input.csvPaths << fixturePath; input.softwareVersion = "v2";
        QVERIFY(!OpbDiagnosticAnalyzer().Analyze(input).success);
        const QString missing = directory.filePath("missing.db");
        input.baselinePath = missing;
        QVERIFY(!OpbDiagnosticAnalyzer().Analyze(input).success);
        QVERIFY(!QFile::exists(missing));
        input.baselinePath = baselinePath; input.softwareVersion.clear();
        const QString other = directory.filePath("other.txt1.csv");
        QVERIFY(Write(other, Cycle(11, Event())));
        input.csvPaths << other;
        QVERIFY(!OpbDiagnosticAnalyzer().Analyze(input).success);
        input.csvPaths = QStringList{fixturePath, fixturePath};
        QVERIFY(!OpbDiagnosticAnalyzer().Analyze(input).success);
    }

    void malformedInputAndCancellationProduceNoEvidence()
    {
        const auto malformed = Diagnose(Cycle(10, QStringLiteral("调试,invalid,,0x00,10\n")));
        QVERIFY(!malformed.success); QVERIFY(malformed.evidence.isEmpty());
        const auto headerOnly = Diagnose(QString());
        QVERIFY(!headerOnly.success); QVERIFY(headerOnly.evidence.isEmpty());
        OpbDiagnosticAnalyzer::Input input;
        input.cancelled = std::make_shared<std::atomic_bool>(true);
        const auto cancelled = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY(!cancelled.success); QVERIFY(cancelled.evidence.isEmpty());
        QCOMPARE(cancelled.errorMessage, QStringLiteral("诊断已取消"));
    }

    void baselineCancellationKeepsPreviousDatabase_data()
    {
        QTest::addColumn<int>("percent");
        QTest::newRow("reading") << 55;
        QTest::newRow("writing-after-deleting-old-rows") << 80;
        QTest::newRow("immediately-before-commit") << 99;
    }

    void baselineCancellationKeepsPreviousDatabase()
    {
        QFETCH(int, percent);
        const QString target = directory.filePath(QString("cancelled-baseline-%1.db").arg(percent));
        QVERIFY(QFile::copy(baselinePath, target));
        const QByteArray before = FileHash(target);
        QVERIFY(Write(fixturePath, Cycle(1, Event()) + Cycle(2, Event()) + Cycle(3, Event())));
        std::shared_ptr<LogTaskControl> control;
        control = std::make_shared<LogTaskControl>([&](int progress, const QString &) {
            if(progress >= percent) control->RequestCancel();
        });
        const auto result = OpbBaselineAnalyzer().BuildBaseline({fixturePath}, target, "new-version", control);
        QVERIFY(!result.success); QVERIFY(result.cancelled);
        QCOMPARE(FileHash(target), before);
        QCOMPARE(Sql(target, "PRAGMA integrity_check").toString(), QString("ok"));
        QCOMPARE(Sql(target, "SELECT value FROM opb_baseline_meta WHERE key='software_version'").toString(), QString("v1"));
        QCOMPARE(control->Snapshot().state, LogTaskControl::Finished);
    }

    void faultCancellationRollsBackEventAndSchema_data()
    {
        QTest::addColumn<int>("percent");
        QTest::newRow("fingerprinting") << 10;
        QTest::newRow("inserting-events") << 25;
        QTest::newRow("immediately-before-commit") << 99;
    }

    void faultCancellationRollsBackEventAndSchema()
    {
        QFETCH(int, percent);
        const QString target = directory.filePath(QString("cancelled-fault-%1.db").arg(percent));
        const QString seed = directory.filePath(QString("seed-%1.txt1.csv").arg(percent));
        QVERIFY(Write(seed, Cycle(1, Event())));
        const auto first = OpbFaultSampleStore().ImportIncident({seed}, target, "OPB");
        QVERIFY2(first.success, qPrintable(first.errorMessage));
        const QByteArray before = FileHash(target);
        QString events;
        for(int i = 0; i < 2500; ++i) events += Event("0x0002", "20");
        QVERIFY(Write(fixturePath, Cycle(2, events)));
        std::shared_ptr<LogTaskControl> control;
        control = std::make_shared<LogTaskControl>([&](int progress, const QString &) {
            if(progress >= percent) control->RequestCancel();
        });
        const auto result = OpbFaultSampleStore().ImportIncident({fixturePath}, target, "OPB", QString(), control);
        QVERIFY(!result.success); QVERIFY(result.cancelled);
        QCOMPARE(FileHash(target), before);
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_incident").toInt(), 1);
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_event").toInt(), 2);
        QCOMPARE(Sql(target, "PRAGMA integrity_check").toString(), QString("ok"));

        const QString emptyTarget = directory.filePath(QString("cancelled-new-fault-%1.db").arg(percent));
        std::shared_ptr<LogTaskControl> newControl;
        newControl = std::make_shared<LogTaskControl>([&](int progress, const QString &) {
            if(progress >= percent) newControl->RequestCancel();
        });
        const auto empty = OpbFaultSampleStore().ImportIncident({fixturePath}, emptyTarget, "OPB", QString(), newControl);
        QVERIFY(!empty.success); QVERIFY(empty.cancelled);
        if(QFile::exists(emptyTarget))
            QCOMPARE(Sql(emptyTarget, "SELECT count(*) FROM sqlite_master WHERE type='table'").toInt(), 0);
    }

    void sqlFailureRestoresOldBaseline()
    {
        const QString target = directory.filePath("write-failure.db");
        QVERIFY(QFile::copy(baselinePath, target));
        QVERIFY(Sql(target, "CREATE TRIGGER fail_write BEFORE INSERT ON opb_event_baseline "
                           "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END").isValid());
        const QByteArray before = FileHash(target);
        QVERIFY(Write(fixturePath, Cycle(1, Event()) + Cycle(2, Event()) + Cycle(3, Event())));
        const auto result = OpbBaselineAnalyzer().BuildBaseline({fixturePath}, target, "new-version");
        QVERIFY(!result.success); QVERIFY(!result.cancelled);
        QCOMPARE(FileHash(target), before);
        QCOMPARE(Sql(target, "PRAGMA integrity_check").toString(), QString("ok"));
    }

    void malformedFaultDoesNotLeavePartialIncident()
    {
        const QString target = directory.filePath("malformed-fault.db");
        const QString seed = directory.filePath("malformed-seed.txt1.csv");
        QVERIFY(Write(seed, Cycle(1, Event())));
        QVERIFY(OpbFaultSampleStore().ImportIncident({seed}, target, "OPB").success);
        const QByteArray before = FileHash(target);
        QVERIFY(Write(fixturePath, Cycle(2, Event()) + "broken,row\n"));
        const auto result = OpbFaultSampleStore().ImportIncident({fixturePath}, target, "OPB");
        QVERIFY(!result.success); QVERIFY(!result.cancelled);
        QCOMPARE(FileHash(target), before);
    }

    void commitCannotBeReportedAsCancelledAndProgressIsMonotonic()
    {
        QVERIFY(Write(fixturePath, Cycle(1, Event()) + Cycle(2, Event()) + Cycle(3, Event())));
        int last = -1;
        bool monotonic = true, cancelAccepted = true;
        std::shared_ptr<LogTaskControl> control;
        control = std::make_shared<LogTaskControl>([&](int progress, const QString &) {
            monotonic = monotonic && progress >= last; last = progress;
            if(progress == 100) cancelAccepted = control->RequestCancel();
        });
        const auto result = OpbBaselineAnalyzer().BuildBaseline({fixturePath}, directory.filePath("committed.db"), "v1", control);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QVERIFY(!result.cancelled); QVERIFY(monotonic); QVERIFY(!cancelAccepted);
        QCOMPARE(last, 100);

        auto cancelled = std::make_shared<LogTaskControl>(); cancelled->RequestCancel();
        const QString missing = directory.filePath("cancel-before-start.db");
        const auto notStarted = OpbFaultSampleStore().ImportIncident({fixturePath}, missing, "OPB", QString(), cancelled);
        QVERIFY(notStarted.cancelled); QVERIFY(!QFile::exists(missing));
    }

    void crlfCsvProgressDoesNotChangeTextDecoding()
    {
        QString events;
        for(int i = 0; i < 3000; ++i) events += Event();
        QVERIFY(Write(fixturePath, Cycle(1, events) + Cycle(2, events) + Cycle(3, events) + Cycle(4, events)));
        QFile file(fixturePath); QVERIFY(file.open(QIODevice::ReadOnly));
        QByteArray data = file.readAll(); file.close();
        data.replace("\n", "\r\n");
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
        QCOMPARE(file.write(data), qint64(data.size())); file.close();
        auto control = std::make_shared<LogTaskControl>();
        const auto baseline = OpbBaselineAnalyzer().BuildBaseline(
                    {fixturePath}, directory.filePath("crlf-baseline.db"), QString(), control);
        QVERIFY2(baseline.success, qPrintable(baseline.errorMessage));
        QCOMPARE(baseline.totalEventCount, quint64(12004));
        const auto fault = OpbFaultSampleStore().ImportIncident(
                    {fixturePath}, directory.filePath("crlf-fault.db"), "OPB", QString(),
                    std::make_shared<LogTaskControl>());
        QVERIFY2(fault.success, qPrintable(fault.errorMessage));
        QCOMPARE(fault.eventCount, quint64(12004));
    }

    void snapshotComparesVariableValuesWithoutInventingCycles()
    {
        const auto result = Diagnose(Event("0x0001", "30"));
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QVERIFY(result.evidence.value("statistics").toObject().value("first_cycle").isNull());
        const auto finding = Finding(result, "VALUE_OUTSIDE_BASELINE");
        QVERIFY(!finding.isEmpty());
        QCOMPARE(finding.value("baseline").toObject().value("numeric_range").toObject().value("max").toDouble(), 10.0);
        QCOMPARE(finding.value("examples").toArray().first().toObject().value("decoded").toString(), QString("30"));
        QCOMPARE(finding.value("first_event_index").toString(), QString("1"));
        QVERIFY(!finding.contains("first_cycle"));
        QVERIFY(Finding(result, "COUNT_ABOVE_P99").isEmpty());
        QVERIFY(Finding(result, "STABLE_CODE_MISSING").isEmpty());
    }

    void errorPrintLevelDoesNotInventFailureStatus()
    {
        const auto equal = Diagnose(QStringLiteral("错误,0x0001,队列长度,0x00,10\n"));
        QVERIFY2(equal.success, qPrintable(equal.errorMessage));
        QVERIFY(equal.evidence["explicit_failures"].toArray().isEmpty());
        QVERIFY(equal.evidence["candidates"].toArray().isEmpty());
        QCOMPARE(equal.evidence["error_level_only_codes"].toArray().size(), 1);
        const auto changed = Diagnose(QStringLiteral("错误,0x0001,队列长度,0x00,30\n"));
        QVERIFY(changed.success);
        QVERIFY(Finding(changed, "EXPLICIT_FAILURE_STATUS").isEmpty());
        QVERIFY(!Finding(changed, "VALUE_OUTSIDE_BASELINE").isEmpty());
        const auto failed = Diagnose(QStringLiteral("警告,0x0002,发送自检结果,0xaa,失败\n"));
        QVERIFY(failed.success);
        QCOMPARE(Finding(failed, "EXPLICIT_FAILURE_STATUS")["state"].toString(), QString("observed_failure"));
    }

    void snapshotUsesNormalStartupValuesAndDoesNotFlagMissingReferences()
    {
        const QString normal = directory.filePath("startup-normal.txt1.csv");
        QString body = Cycle(1, Event() + Event("0x0002", "0"));
        for(int i = 2; i <= 6; ++i) body += Cycle(i, Event());
        QVERIFY(Write(normal, body));
        const QString baseline = directory.filePath("startup-normal.db");
        QVERIFY(OpbBaselineAnalyzer().BuildBaseline({normal}, baseline).success);
        QVERIFY(Write(fixturePath, Event("0x0002", "131") + Event("0x0003", "99")));
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baseline; input.csvPaths << fixturePath;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QVERIFY(result.evidence.value("baseline_reference").toObject().value("normal_capture_complete").toBool());
        const auto candidate = Finding(result, "VALUE_OUTSIDE_BASELINE");
        QCOMPARE(candidate.value("code").toString(), QString("0x0002"));
        QCOMPARE(candidate.value("baseline").toObject().value("numeric_range").toObject().value("max").toDouble(), 0.0);
        QCOMPARE(result.evidence.value("statistics").toObject().value("reference_missing_events").toInt(), 1);
        QCOMPARE(result.evidence.value("candidates").toArray().size(), 1);
    }

    void snapshotReferenceUnavailableFallsBackToStoredNumericRange()
    {
        const QString normal = directory.filePath("missing-reference.txt1.csv");
        QVERIFY(Write(normal, Cycle(1, Event()) + Cycle(2, Event()) + Cycle(3, Event())));
        const QString baseline = directory.filePath("missing-reference.db");
        QVERIFY(OpbBaselineAnalyzer().BuildBaseline({normal}, baseline).success);
        QVERIFY(QFile::remove(normal));
        QVERIFY(Write(fixturePath, Event("0x0001", "30")));
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baseline; input.csvPaths << fixturePath;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QVERIFY(!result.evidence.value("baseline_reference").toObject().value("normal_capture_complete").toBool());
        QCOMPARE(Finding(result, "VALUE_OUTSIDE_BASELINE").value("baseline").toObject().value("scope").toString(), QString("steady_state_statistics"));
    }

    void snapshotBuildIdentityIsContextAndInsideRangeTimeIsNotBad()
    {
        const QString normal = directory.filePath("identity-normal.txt1.csv");
        const QString initial = QStringLiteral("调试,0x0002,软件版本号,0x01,1\n调试,0x0003,读取的MD5,,aa\n"
                                               "调试,0x0004,脉冲翻转时间,0x00,10\n调试,0x0004,脉冲翻转时间,0x00,20\n");
        QVERIFY(Write(normal, Cycle(1, Event() + initial) + Cycle(2, Event()) + Cycle(3, Event())));
        const QString baseline = directory.filePath("identity-normal.db");
        QVERIFY(OpbBaselineAnalyzer().BuildBaseline({normal}, baseline).success);
        QVERIFY(Write(fixturePath, QStringLiteral("调试,0x0002,软件版本号,0x02,2\n调试,0x0003,读取的MD5,,bb\n"
                                                 "调试,0x0004,脉冲翻转时间,0x00,15\n")));
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baseline; input.csvPaths << fixturePath;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("candidates").toArray().size(), 0);
        QCOMPARE(result.evidence.value("context_differences").toArray().size(), 2);
    }

    void snapshotImportedAndDiagnosedAfterSourceRemoval()
    {
        const QString path = directory.filePath("snapshot-stored.txt1.csv");
        QVERIFY(Write(path, Event("0x0001", "30") + QStringLiteral("错误,0x002b,上电自检结果,0xaa,失败\n")));
        const QString target = directory.filePath("snapshot-stored.db");
        const auto imported = OpbFaultSampleStore().ImportIncident({path}, target, "OPB");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));
        QCOMPARE(imported.logFormat, QString("snapshot"));
        QCOMPARE(imported.cycleCount, 0);
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_event").toInt(), 0);
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_snapshot_event").toInt(), 2);
        QCOMPARE(Sql(target, "SELECT cycle_start IS NULL AND cycle_end IS NULL FROM fault_incident").toInt(), 1);
        const auto duplicate = OpbFaultSampleStore().ImportIncident({path}, target, "OPB");
        QVERIFY(duplicate.success); QVERIFY(duplicate.duplicate); QCOMPARE(duplicate.logFormat, QString("snapshot"));
        QVERIFY(QFile::remove(path));
        OpbDiagnosticAnalyzer::Input input; input.baselinePath = baselinePath;
        input.faultDatabasePath = target; input.incidentId = imported.incidentId;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QCOMPARE(Finding(result, "EXPLICIT_FAILURE_STATUS").value("state").toString(), QString("observed_failure"));
        QVERIFY(!Finding(result, "VALUE_OUTSIDE_BASELINE").isEmpty());
    }

    void snapshotSchemaUpgradeIsTransactionalAndPreservesCyclicRows()
    {
        const QString seed = directory.filePath("schema-seed.txt1.csv");
        QVERIFY(Write(seed, Cycle(1, Event())));
        const QString target = directory.filePath("schema-upgrade.db");
        QVERIFY(OpbFaultSampleStore().ImportIncident({seed}, target, "OPB").success);
        QVERIFY(Sql(target, "DROP TABLE fault_snapshot_event").isValid());
        QVERIFY(Sql(target, "DROP TABLE fault_incident_format").isValid());
        QVERIFY(Sql(target, "UPDATE fault_schema_meta SET value='1' WHERE key='schema_version'").isValid());
        const auto before = FileHash(target);
        QVERIFY(Write(fixturePath, Event("0x0001", "30")));
        std::shared_ptr<LogTaskControl> control;
        control = std::make_shared<LogTaskControl>([&](int percent, const QString &) {
            if(percent == 99) control->RequestCancel();
        });
        const auto cancelled = OpbFaultSampleStore().ImportIncident({fixturePath}, target, "OPB", QString(), control);
        QVERIFY(cancelled.cancelled); QCOMPARE(FileHash(target), before);
        const auto imported = OpbFaultSampleStore().ImportIncident({fixturePath}, target, "OPB");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_event").toInt(), 2);
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_snapshot_event").toInt(), 1);
        QCOMPARE(Sql(target, "SELECT count(*) FROM fault_incident").toInt(), 2);
        QCOMPARE(Sql(target, "PRAGMA integrity_check").toString(), QString("ok"));
    }

    void preambleBeforeTrueCycleIsPreserved()
    {
        const QString body = Event() + Cycle(1, Event());
        const auto result = Diagnose(body);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("statistics").toObject().value("unassigned_cycle_events").toInt(), 1);
        const auto imported = OpbFaultSampleStore().ImportIncident({fixturePath}, directory.filePath("mixed-format.db"), "OPB");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));
        QCOMPARE(imported.eventCount, quint64(3));
        QCOMPARE(Sql(imported.databasePath, "SELECT count(*) FROM fault_snapshot_event").toInt(), 1);
        QCOMPARE(Sql(imported.databasePath, "SELECT count(*) FROM fault_event").toInt(), 2);
    }
};

QTEST_GUILESS_MAIN(DiagnosisTests)
#include "DiagnosisTests.moc"
