#include "../plugin/SourceQueryInterface.h"
#include <QApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QProcess>
#include <QDir>
#include "../../../NewAnalysis/BoardIdentity.h"
#include <QComboBox>
#include <QLabel>
#include <QFontDatabase>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPluginLoader>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTest>
#include <QTreeWidget>
#include <memory>

class SourceQueryTests : public QObject
{
    Q_OBJECT
private slots:
    void selfCheckReviewIncludesNormalItemsBeyondPrimaryLimit()
    {
        QPluginLoader loader(qEnvironmentVariable("SOURCE_RELATIONS_PLUGIN"));
        auto *plugin = qobject_cast<SourceQueryInterface *>(loader.instance()); QVERIFY(plugin);
        const QString database = qEnvironmentVariable("SOURCE_RELATIONS_DATABASE");
        QJsonArray events;
        int count = 0;
        {
            auto source = QSqlDatabase::addDatabase("QSQLITE", "self-check-scan-fixture");
            source.setDatabaseName(BoardIdentity::sourceDatabase(database, "OPB"));
            source.setConnectOptions("QSQLITE_OPEN_READONLY"); QVERIFY(source.open());
            QSqlQuery query(source);
            QVERIFY(query.exec("SELECT DISTINCT l.code FROM log_sites l JOIN calls c ON c.id=l.call_id JOIN functions f ON f.id=c.function_id JOIN files s ON s.id=f.file_id WHERE l.code IS NOT NULL AND lower(s.path) LIKE '%selfche%' ORDER BY l.code LIMIT 20"));
            while(query.next()) {
                events.append(QJsonObject{{"code", QString("0x%1").arg(query.value(0).toInt(), 4, 16, QChar('0'))},
                                          {"event_index", QString::number(++count)}, {"description", QStringLiteral("自检项")},
                                          {"decoded", QStringLiteral("成功")}});
            }
        }
        QSqlDatabase::removeDatabase("self-check-scan-fixture");
        QVERIFY(count > 12);
        events.append(QJsonObject{{"code", "0xFFFF"}, {"description", QStringLiteral("未解析自检项")}});
        const QJsonObject logs{{"source_lookup_scope", "candidate_codes"}, {"candidates", QJsonArray()},
                              {"rca_trace", QJsonObject{{"events", events}, {"truncated", false}}}};
        const auto result = plugin->collectEvidence(database, logs, {}, "OPB", std::make_shared<std::atomic_bool>(false));
        const auto review = result["self_check_review"].toObject();
        QCOMPARE(review["items"].toArray().size(), count);
        QVERIFY(review["unresolved_self_check_codes"].toArray().contains("0xFFFF"));
        QVERIFY(!review["sources"].toArray().isEmpty());
        QVERIFY(!review["truncated"].toBool());
        QCOMPARE(result["status"].toString(), QString("reference_only"));
        QVERIFY(QJsonDocument(result).toJson(QJsonDocument::Compact).size() <= result["limits"].toObject()["max_bytes"].toInt());
    }

    void refreshesChangedBoardHeaderAutomatically()
    {
        const QString executable = QCoreApplication::applicationDirPath() + "/source_relations/SourceIndexer.exe";
        if(!QFileInfo::exists(executable)) QSKIP("Standalone indexer fixture is required");
        QTemporaryDir temp;
        const QString root = temp.filePath("source"); QVERIFY(QDir().mkpath(root));
        QFile source(root + "/a.c"); QVERIFY(source.open(QIODevice::WriteOnly));
        source.write("#define CODE 0x0084\nvoid same(void) {\n#if SELECT_MODE\nDarkLogPrint(1,&newValue,CODE,1);\n#else\nDarkLogPrint(1,&oldValue,CODE,1);\n#endif\n}\n"); source.close();
        QJsonObject profiles;
        const QStringList boards = BoardIdentity::boards();
        const QStringList macros{"IS_5728_MCP", "IS_570_IPB", "IS_570_OPB", "IS_570_SIG"};
        for(int board = 0; board < boards.size(); ++board) {
            QString header;
            for(int macro = 0; macro < macros.size(); ++macro) header += "#define " + macros[macro] + (macro == board ? " 1\n" : " 0\n");
            header += "#define SELECT_MODE 0\n";
            QFile file(temp.filePath(boards[board] + ".h")); QVERIFY(file.open(QIODevice::WriteOnly)); file.write(header.toUtf8()); file.close();
            profiles.insert(boards[board], QJsonObject{{"configuration_header", file.fileName()}, {"expected_board_macro", macros[board]},
                                                     {"defines", QJsonObject()}, {"closed_world", true}});
        }
        const QString manifest = temp.filePath("profiles.json");
        QFile configuration(manifest); QVERIFY(configuration.open(QIODevice::WriteOnly));
        configuration.write(QJsonDocument(profiles).toJson()); configuration.close();
        const QString database = temp.filePath("calls.OPB.sqlite");
        QProcess builder;
        builder.start(executable, {"--source", root, "--output", database, "--board", "OPB", "--profiles", manifest});
        QVERIFY(builder.waitForFinished(30000)); QCOMPARE(builder.exitCode(), 0);
        QPluginLoader loader(qEnvironmentVariable("SOURCE_RELATIONS_PLUGIN"));
        auto *plugin = qobject_cast<SourceQueryInterface *>(loader.instance()); QVERIFY(plugin);
        const QJsonObject logs{{"candidates", QJsonArray{QJsonObject{{"code", "0x0084"}, {"evidence_id", "E1"}}}}};
        auto cancelled = std::make_shared<std::atomic_bool>(false);
        const auto before = plugin->collectEvidence(database, logs, {}, "OPB", cancelled);
        QVERIFY2(!before["records"].toArray().isEmpty(), qPrintable(before["message"].toString()));
        QCOMPARE(before["records"].toArray()[0].toObject()["data_expression"].toString(), QString("&oldValue"));
        QFile header(temp.filePath("OPB.h")); QVERIFY(header.open(QIODevice::ReadOnly));
        QByteArray changed = header.readAll(); header.close(); changed.replace("SELECT_MODE 0", "SELECT_MODE 1");
        QVERIFY(header.open(QIODevice::WriteOnly)); header.write(changed); header.close();
        const auto after = plugin->collectEvidence(database, logs, {}, "OPB", cancelled);
        QVERIFY2(!after["records"].toArray().isEmpty(), qPrintable(after["message"].toString()));
        QCOMPARE(after["records"].toArray()[0].toObject()["data_expression"].toString(), QString("&newValue"));
        QVERIFY(before["snapshot"].toObject()["configuration_sha256"] != after["snapshot"].toObject()["configuration_sha256"]);
    }

    void collectsBoundedSourceEvidence()
    {
        QPluginLoader loader(qEnvironmentVariable("SOURCE_RELATIONS_PLUGIN"));
        auto *plugin = qobject_cast<SourceQueryInterface *>(loader.instance());
        QVERIFY2(plugin, qPrintable(loader.errorString()));
        const QString database = qEnvironmentVariable("SOURCE_RELATIONS_DATABASE");
        const QJsonObject logs{{"candidates", QJsonArray{QJsonObject{{"evidence_id", "E1"}, {"code", "0x0A1A"}}}}};
        auto cancelled = std::make_shared<std::atomic_bool>(false);
        const auto source = plugin->collectEvidence(database, logs, "different-firmware", "OPB", cancelled);
        QCOMPARE(source["status"].toString(), QString("reference_only"));
        QCOMPARE(source["version_match"].toString(), QString("mismatch"));
        QCOMPARE(source["firmware_correspondence"].toString(), QString("unverified"));
        const auto records = source["records"].toArray();
        QVERIFY(records.size() > 0);
        QVERIFY(records.size() <= 12);
        const auto first = records[0].toObject();
        QVERIFY(first["path"].toString().contains("/"));
        QVERIFY(!first["source_id"].toString().isEmpty());
        QVERIFY(first["log_context"].toObject()["text"].toString().contains("LogPrint"));
        QCOMPARE(first["log_references"].toArray()[0].toObject()["evidence_id"].toString(), QString("E1"));
        QVERIFY(QJsonDocument(source).toJson(QJsonDocument::Compact).size() <= 48000);
        QVERIFY(!source["snapshot"].toObject().contains("source_root"));
        QJsonObject focusedLogs = logs;
        focusedLogs.insert("variable_comparisons", QJsonArray{QJsonObject{{"code", "0x0001"}}});
        focusedLogs.insert("sequence_tail", QJsonArray{QJsonObject{{"code", "0x0002"}}});
        const auto focused = plugin->collectEvidence(database, focusedLogs, {}, "OPB", cancelled);
        QCOMPARE(focused["lookups"].toArray().size(), 1);
        const auto noCandidates = plugin->collectEvidence(database, QJsonObject{{"source_lookup_scope", "candidate_codes"},
                                                                               {"source_lookup_codes", QJsonArray{"0x0A1A"}}}, {}, "OPB", cancelled);
        QVERIFY(noCandidates["lookups"].toArray().isEmpty());
        const QString capture = qEnvironmentVariable("SOURCE_EVIDENCE_CAPTURE");
        if(!capture.isEmpty()) {
            QFile file(capture); QVERIFY(file.open(QIODevice::WriteOnly));
            file.write(QJsonDocument(source).toJson(QJsonDocument::Indented));
        }
        cancelled->store(true);
        QCOMPARE(plugin->collectEvidence(database, logs, {}, {}, cancelled)["status"].toString(), QString("cancelled"));
        cancelled->store(false);
        QTemporaryDir temp;
        QCOMPARE(plugin->collectEvidence(temp.filePath("missing.sqlite"), logs, {}, {}, cancelled)["status"].toString(), QString("unavailable"));
        QFile bad(temp.filePath("invalid.sqlite")); QVERIFY(bad.open(QIODevice::WriteOnly)); bad.write("invalid"); bad.close();
        QCOMPARE(plugin->collectEvidence(bad.fileName(), logs, {}, {}, cancelled)["status"].toString(), QString("unavailable"));
        const QJsonObject unknown{{"candidates", QJsonArray{QJsonObject{{"code", "0xFFFF"}}}}};
        QCOMPARE(plugin->collectEvidence(database, unknown, {}, "OPB", cancelled)["status"].toString(), QString("no_matches"));
        QJsonArray codes;
        for(int index = 0; index < 30; ++index) codes.append(QString("0x%1").arg(index, 4, 16, QChar('0')));
        const auto limited = plugin->collectEvidence(database, QJsonObject{{"source_lookup_codes", codes}}, {}, "OPB", cancelled);
        QCOMPARE(limited["selected_code_count"].toInt(), 12);
        QCOMPARE(limited["omitted_code_count"].toInt(), 18);
        QVERIFY(limited["truncated"].toBool());
        QVERIFY(QJsonDocument(limited).toJson(QJsonDocument::Compact).size() <= 48000);
        for(const QString &board : {QString("ATP"), QString("IPB"), QString("OPB"), QString("SPB")}) {
            const auto isolated = plugin->collectEvidence(database, logs, {}, board, cancelled);
            QCOMPARE(isolated["snapshot"].toObject()["board"].toString(), board);
            QCOMPARE(isolated["snapshot"].toObject()["analysis_mode"].toString(), QString("board_scoped_conditionals"));
            QCOMPARE(isolated["board_match"].toString(), QString("label_match"));
        }
        const QString wrongPath = temp.filePath("wrong.OPB.sqlite");
        QVERIFY(QFile::copy(BoardIdentity::sourceDatabase(database, "OPB"), wrongPath));
        {
            auto wrong = QSqlDatabase::addDatabase("QSQLITE", "wrong-board-fixture");
            wrong.setDatabaseName(wrongPath); QVERIFY(wrong.open());
            QSqlQuery change(wrong);
            QVERIFY(change.exec("UPDATE metadata SET value='IPB' WHERE key='board'"));
        }
        QSqlDatabase::removeDatabase("wrong-board-fixture");
        QCOMPARE(plugin->collectEvidence(wrongPath, logs, {}, "OPB", cancelled)["status"].toString(), QString("unavailable"));
    }

    void loadsQueriesAndShowsSource()
    {
        QTemporaryDir settings;
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settings.path());
        QCoreApplication::setOrganizationName("SourceRelationsTests");
        QCoreApplication::setApplicationName("SourceQueryTests");
        QFontDatabase::addApplicationFont("C:/Windows/Fonts/msyh.ttc");
        QFontDatabase::addApplicationFont("C:/Windows/Fonts/consola.ttf");
        QApplication::setFont(QFont("Microsoft YaHei", 9));
        QPluginLoader loader(qEnvironmentVariable("SOURCE_RELATIONS_PLUGIN"));
        auto *plugin = qobject_cast<SourceQueryInterface *>(loader.instance());
        QVERIFY2(plugin, qPrintable(loader.errorString()));
        std::unique_ptr<QWidget> widget(plugin->createQueryWidget(BoardIdentity::sourceDatabase(qEnvironmentVariable("SOURCE_RELATIONS_DATABASE"), "OPB"), nullptr));
        widget->resize(1200, 780);
        widget->show();
        auto *status = widget->findChild<QLabel *>("sourceIndexStatus");
        QVERIFY(status);
        QVERIFY2(status->text().contains("OPB"), qPrintable(status->text()));
        auto *search = widget->findChild<QLineEdit *>("sourceSearchText");
        auto *button = widget->findChild<QPushButton *>("sourceSearchButton");
        auto *table = widget->findChild<QTableWidget *>("sourceSearchResults");
        auto *tree = widget->findChild<QTreeWidget *>("sourceCallTree");
        auto *source = widget->findChild<QPlainTextEdit *>("sourceSnapshotText");
        QVERIFY(search && button && table && tree && source);
        search->setText("Plat_Main");
        QTest::mouseClick(button, Qt::LeftButton);
        QVERIFY2(table->rowCount() == 1, qPrintable(status->text()));
        QCOMPARE(tree->topLevelItemCount(), 1);
        QVERIFY(source->toPlainText().contains("Plat_Main"));
        QVERIFY(tree->topLevelItem(0)->childCount() > 0);
        auto *mode = widget->findChild<QComboBox *>("sourceSearchMode");
        mode->setCurrentIndex(1);
        search->setText("0x0A1A");
        QTest::mouseClick(button, Qt::LeftButton);
        QVERIFY(table->rowCount() > 0);
        QVERIFY(table->item(0, 0)->text().contains("LOGTYPE_NEWCYCLE"));
        QVERIFY(source->toPlainText().contains("DarkLogPrint"));
        const int numericCount = table->rowCount();
        search->setText("LOGTYPE_NEWCYCLE");
        QTest::mouseClick(button, Qt::LeftButton);
        QCOMPARE(table->rowCount(), numericCount);
        QTest::qWait(80);
        const QString screenshot = qEnvironmentVariable("SOURCE_RELATIONS_SCREENSHOT");
        if(!screenshot.isEmpty()) QVERIFY(widget->grab().save(screenshot));
        search->setText("' OR 1=1 --");
        QTest::mouseClick(button, Qt::LeftButton);
        QCOMPARE(table->rowCount(), 0);
        mode->setCurrentIndex(2);
        search->setText("CommonQueue.h");
        QTest::mouseClick(button, Qt::LeftButton);
        QVERIFY(table->rowCount() > 0);
        QVERIFY(table->item(0, 3)->text().contains("CommonQueue.h"));
        widget->findChild<QLineEdit *>("sourceDatabasePath")->setText(settings.filePath("missing.sqlite"));
        QTest::mouseClick(button, Qt::LeftButton);
        QCOMPARE(table->rowCount(), 0);
        QVERIFY(status->text().contains(QStringLiteral("不存在")));
    }
};

QTEST_MAIN(SourceQueryTests)
#include "SourceQueryTests.moc"
