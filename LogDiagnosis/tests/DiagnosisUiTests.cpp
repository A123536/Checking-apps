#include "DiagnosisPage.h"
#include "MainWindow.h"
#include "DeepSeekClient.h"
#include "LegacyParserAdapter.h"
#include "OpbBaselineAnalyzer.h"
#include "OpbFaultSampleStore.h"

#include <QComboBox>
#include <QCheckBox>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QLineEdit>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QElapsedTimer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QUuid>
#include <QSignalSpy>
#include <QSettings>
#include <QTemporaryDir>
#include <QTabWidget>
#include <QTest>
#include <QTextStream>
#include <QTextCodec>
#include <QTimer>
#include <QTableWidget>
#include <QFontDatabase>
#include <QTcpServer>
#include <QTcpSocket>
#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDir>
#include <QProcess>
#include <QInputDialog>
#include <QtCore/qscopeguard.h>

class LoopbackDeepSeek : public DeepSeekClient
{
    QString m_Url;
public:
    explicit LoopbackDeepSeek(const QString &url) : m_Url(url) {}
    void AnalyzeEvidence(const QString &evidence) override
    {
        SetConfig("local-test-placeholder", "local-test-model", m_Url);
        DeepSeekClient::AnalyzeEvidence(evidence);
    }
};

class SimulatedParser : public LegacyParserAdapter
{
public:
    QStringList outputs;
    bool fail = false;
    bool busy = false;
    bool isolated = false;
    int calls = 0;
    bool IsBusy() const override { return busy; }
    void StartOpbParse(const QString &, const QString &, bool, bool isolatedOutput) override
    {
        ++calls; isolated = isolatedOutput; busy = true;
        QTimer::singleShot(20, this, [this]() {
            busy = false;
            if(fail) emit Signal_ParseFailed(QStringLiteral("测试解析失败"));
            else emit Signal_ParseFinished(true, outputs);
        });
    }
};

class SimulatedDeepSeek : public DeepSeekClient
{
public:
    int calls = 0;
    QString received;
    bool fail = false;
    bool busy = false;
    bool IsBusy() const override { return busy; }
    void AnalyzeEvidence(const QString &evidence) override
    {
        ++calls; received = evidence; busy = true;
        emit Signal_BusyChanged(true);
        QTimer::singleShot(10, this, [this]() {
            busy = false; emit Signal_BusyChanged(false);
            if(fail) emit Signal_RequestFailed(QStringLiteral("测试网络失败"));
            else emit Signal_AnalysisSucceeded(QStringLiteral("模拟 DeepSeek 分析结果：根据基线，根因证据仍不足，UNKNOWN。"));
        });
    }
};

class DiagnosisUiTests : public QObject
{
    Q_OBJECT
    QTemporaryDir m_Settings;
    bool DropFiles(MainWindow &window, const QStringList &paths)
    {
        QMimeData mime;
        QList<QUrl> urls;
        for(const QString &path : paths) urls << QUrl::fromLocalFile(path);
        mime.setUrls(urls);
        QDragEnterEvent enter(QPoint(10, 10), Qt::CopyAction, &mime, Qt::LeftButton, Qt::NoModifier);
        QCoreApplication::sendEvent(&window, &enter);
        if(!enter.isAccepted()) return false;
        QDropEvent drop(QPointF(10, 10), Qt::CopyAction, &mime, Qt::LeftButton, Qt::NoModifier);
        QCoreApplication::sendEvent(&window, &drop);
        return drop.isAccepted();
    }
    QString MakeNormalCsv(QTemporaryDir &temp)
    {
        const QString csv = temp.filePath("OPB_background.txt1.csv");
        QFile file(csv);
        if(!file.open(QIODevice::WriteOnly)) return QString();
        QTextStream out(&file); out.setCodec("GB18030");
        out << QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n");
        for(int cycle = 1; cycle <= 500; ++cycle)
        {
            out << QStringLiteral("Cycle Num : %1\n提示,0x0A1A,新周期号,,%1\n包序号: %1\n").arg(cycle);
            for(int event = 0; event < 40; ++event)
                out << QStringLiteral("调试,0x0001,测试,0x00,10\n");
        }
        out.flush();
        return csv;
    }
    bool Prepare(MainWindow &window, QTemporaryDir &temp, SimulatedParser *parser)
    {
        const QString raw = temp.filePath("OPB_raw.txt");
        QFile file(raw); if(!file.open(QIODevice::WriteOnly)) return false; file.write("test input"); file.close();
        const QString csv = temp.filePath("OPB_raw.txt1.csv");
        file.setFileName(csv);
        if(!file.open(QIODevice::WriteOnly)) return false;
        QTextStream stream(&file); stream.setCodec("GB18030");
        stream << QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n");
        for(int i = 1; i <= 5; ++i)
            stream << QStringLiteral("Cycle Num : %1\n提示,0x0A1A,新周期号,,%1\n包序号: %1\n调试,0x0001,测试,0x00,10\n").arg(i);
        stream.flush(); file.close();
        const auto baseline = OpbBaselineAnalyzer().BuildBaseline({csv}, temp.filePath("normal.db"), "v1");
        if(!baseline.success) return false;
        parser->outputs = QStringList{csv};
        window.findChild<QLineEdit *>("analysisSourceLog")->setText(raw);
        window.findChild<QLineEdit *>("analysisDictionaryPath")->setText(raw);
        window.findChild<QLineEdit *>("analysisBaselinePath")->setText(baseline.databasePath);
        window.findChild<QLineEdit *>("analysisSoftwareVersion")->setText("v1");
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder-not-a-real-key");
        return true;
    }

private slots:
    void sourceBranchesSwitchEvidenceAndKeepIndependentSettings()
    {
        QTemporaryDir branches;
        const QByteArray previousRoot = qgetenv("LOGDIAG_BRANCH_ROOT");
        qputenv("LOGDIAG_BRANCH_ROOT", branches.path().toUtf8());
        auto restore = qScopeGuard([&]() {
            if(previousRoot.isNull()) qunsetenv("LOGDIAG_BRANCH_ROOT");
            else qputenv("LOGDIAG_BRANCH_ROOT", previousRoot);
            QSettings().remove("sourceBranches");
        });
        const auto writeFile = [](const QString &path, const QByteArray &content) {
            QFile file(path);
            return file.open(QIODevice::WriteOnly) && file.write(content) == content.size();
        };
        const QString indexer = QCoreApplication::applicationDirPath() + "/source_relations/SourceIndexer.exe";
        QVERIFY(QFileInfo::exists(indexer));
        const QStringList boards{"ATP", "IPB", "OPB", "SPB"};
        const QStringList macros{"IS_5728_MCP", "IS_570_IPB", "IS_570_OPB", "IS_570_SIG"};
        for(const QString &name : {QString("alpha"), QString("beta")}) {
            const QString directory = branches.filePath(name);
            QVERIFY(QDir().mkpath(directory + "/source"));
            QVERIFY(QDir().mkpath(directory + "/relations"));
            QVERIFY(writeFile(directory + "/source/a.c", ("#define CODE 0x0001\nvoid " + name + "(void) { DarkLogPrint(1, &" + name + "_value, CODE, 1); }\n").toUtf8()));
            QJsonObject profiles;
            for(int board = 0; board < boards.size(); ++board) {
                QByteArray header;
                for(int macro = 0; macro < macros.size(); ++macro)
                    header += ("#define " + macros[macro] + (macro == board ? " 1\n" : " 0\n")).toUtf8();
                QVERIFY(writeFile(directory + '/' + boards[board] + ".h", header));
                profiles.insert(boards[board], QJsonObject{{"configuration_header", boards[board] + ".h"},
                    {"expected_board_macro", macros[board]}, {"defines", QJsonObject()}, {"closed_world", true}});
            }
            QVERIFY(writeFile(directory + "/board_profiles.json", QJsonDocument(profiles).toJson()));
            QProcess builder;
            builder.start(indexer, {"--source", directory + "/source", "--output", directory + "/relations/source.OPB.sqlite",
                                  "--board", "OPB", "--profiles", directory + "/board_profiles.json"});
            QVERIFY(builder.waitForFinished(30000));
            QCOMPARE(builder.exitCode(), 0);
        }
        const QString csv = branches.filePath("OPB_incident.csv");
        QVERIFY(writeFile(csv, QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n错误,0x0001,执行失败,0x01,失败\n").toUtf8()));
        auto *client = new SimulatedDeepSeek;
        {
            MainWindow window(nullptr, new SimulatedParser, client);
            auto *combo = window.findChild<QComboBox *>("sourceBranchCombo"); QVERIFY(combo);
            QCOMPARE(combo->count(), 2);
            QCOMPARE(combo->currentData().toString(), QString("alpha"));
            auto *version = window.findChild<QLineEdit *>("analysisSoftwareVersion");
            auto *baseline = window.findChild<QLineEdit *>("analysisBaselinePath");
            auto *database = window.findChild<QLineEdit *>("analysisSourceDatabasePath");
            QVERIFY(database->isReadOnly());
            window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
            window.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder");
            QVERIFY(DropFiles(window, {csv}));
            auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
            ai->click();
            QVERIFY(!combo->isEnabled());
            QTRY_COMPARE_WITH_TIMEOUT(client->calls, 1, 10000);
            QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
            auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
            QCOMPARE(evidence["source_branch"].toObject()["name"].toString(), QString("alpha"));
            QVERIFY(!evidence["source_evidence"].toObject()["records"].toArray().isEmpty());
            QVERIFY(QJsonDocument(evidence["source_evidence"].toObject()).toJson().contains("alpha_value"));
            version->setText("alpha-version");
            baseline->setText(branches.filePath("alpha-normal.db"));
            combo->setCurrentIndex(combo->findData("beta"));
            QVERIFY(version->text().isEmpty());
            QVERIFY(baseline->text().isEmpty());
            QVERIFY(window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().isEmpty());
            ai->click();
            QTRY_COMPARE_WITH_TIMEOUT(client->calls, 2, 10000);
            QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
            evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
            QCOMPARE(evidence["source_branch"].toObject()["name"].toString(), QString("beta"));
            QVERIFY(QJsonDocument(evidence["source_evidence"].toObject()).toJson().contains("beta_value"));
            combo->setCurrentIndex(combo->findData("alpha"));
            QCOMPARE(version->text(), QString("alpha-version"));
            QCOMPARE(baseline->text(), branches.filePath("alpha-normal.db"));
            combo->setCurrentIndex(combo->findData("beta"));
            window.findChild<QPushButton *>("sourceRelationsButton")->click();
            auto *widget = window.findChild<QWidget *>("sourceQueryWidget"); QVERIFY(widget);
            QCOMPARE(widget->property("sourceRoot").toString(), branches.filePath("beta/source"));
            widget->setProperty("building", true);
            combo->setCurrentIndex(combo->findData("alpha"));
            QCOMPARE(combo->currentData().toString(), QString("beta"));
            widget->setProperty("building", false);
        }
        MainWindow reopened;
        QCOMPARE(reopened.findChild<QComboBox *>("sourceBranchCombo")->currentData().toString(), QString("beta"));
        QVERIFY(QFile::remove(branches.filePath("beta/relations/source.OPB.sqlite")));
        QVERIFY(DropFiles(reopened, {csv}));
        reopened.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder");
        reopened.findChild<QPushButton *>("aiAnalysisButton")->click();
        QVERIFY(reopened.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("重建关系库")));
        reopened.findChild<QPushButton *>("sourceRelationsButton")->click();
        auto *query = reopened.findChild<QWidget *>("sourceQueryWidget"); QVERIFY(query);
        QTimer::singleShot(0, [&]() {
            auto *prompt = query->findChild<QInputDialog *>();
            if(prompt) { prompt->setTextValue("beta-build"); prompt->accept(); }
        });
        query->findChild<QPushButton *>("rebuildSourceDatabaseButton")->click();
        QVERIFY(query->property("building").toBool());
        QTRY_VERIFY_WITH_TIMEOUT(!query->property("building").toBool(), 30000);
        for(const QString &board : boards)
            QVERIFY(QFileInfo(branches.filePath("beta/relations/source." + board + ".sqlite")).isFile());
    }

    void aiRequestLoadsRcaSkillAndReloadsFile()
    {
        QVector<QJsonObject> requests;
        QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost, 0));
        connect(&server, &QTcpServer::newConnection, &server, [&]() {
            auto *socket = server.nextPendingConnection();
            connect(socket, &QTcpSocket::readyRead, &server, [socket, &requests]() {
                QByteArray bytes = socket->property("requestBytes").toByteArray() + socket->readAll();
                socket->setProperty("requestBytes", bytes);
                const int separator = bytes.indexOf("\r\n\r\n");
                if(separator < 0 || socket->property("handled").toBool()) return;
                const auto length = QRegularExpression("Content-Length:\\s*(\\d+)", QRegularExpression::CaseInsensitiveOption)
                    .match(QString::fromLatin1(bytes.left(separator)));
                if(!length.hasMatch() || bytes.size() < separator + 4 + length.captured(1).toInt()) return;
                requests.append(QJsonDocument::fromJson(bytes.mid(separator + 4, length.captured(1).toInt())).object());
                socket->setProperty("handled", true);
                const QByteArray response = "{\"choices\":[{\"message\":{\"content\":\"RCA skill test passed\"}}]}";
                socket->write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                              + QByteArray::number(response.size()) + "\r\n\r\n" + response);
                socket->disconnectFromHost();
            });
        });
        const QString skillPath = QCoreApplication::applicationDirPath() + "/skills/crash-log-rca/SKILL.md";
        QFile skill(skillPath); QVERIFY(skill.open(QIODevice::ReadOnly));
        const QByteArray original = skill.readAll(); skill.close();
        const QString disabled = skillPath + ".disabled";
        auto restore = qScopeGuard([&]() {
            if(QFileInfo::exists(disabled)) QFile::rename(disabled, skillPath);
            QFile file(skillPath); if(file.open(QIODevice::WriteOnly)) file.write(original);
        });
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new LoopbackDeepSeek(QString("http://127.0.0.1:%1").arg(server.serverPort()));
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        QVERIFY(DropFiles(window, parser->outputs));
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton"); ai->click();
        QTRY_COMPARE_WITH_TIMEOUT(requests.size(), 1, 10000);
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        const auto messages = requests[0]["messages"].toArray();
        QCOMPARE(requests[0]["max_tokens"].toInt(), 8192);
        QCOMPARE(requests[0]["temperature"].toDouble(), 0.2);
        QString body = QString::fromUtf8(original); body.replace("\r\n", "\n"); body.remove(QChar(0xfeff));
        body = body.mid(body.indexOf("\n---\n", 4) + 5);
        QVERIFY(messages[0].toObject()["content"].toString().endsWith(body));
        const auto evidence = QJsonDocument::fromJson(messages[1].toObject()["content"].toString().toUtf8()).object();
        QCOMPARE(evidence["analysis_skill"].toObject()["sha256"].toString(),
                 QString::fromLatin1(QCryptographicHash::hash(original, QCryptographicHash::Sha256).toHex()));
        QVERIFY(!evidence["rca_trace"].toObject()["events"].toArray().isEmpty());
        const auto shown = QJsonDocument::fromJson(window.findChild<QPlainTextEdit *>("aiEvidenceInput")->toPlainText().toUtf8()).object();
        QCOMPARE(shown["analysis_skill"], evidence["analysis_skill"]);
        QVERIFY(skill.open(QIODevice::WriteOnly)); skill.write(original + "\nRCA_SKILL_RELOAD_TEST\n"); skill.close();
        ai->click(); QTRY_COMPARE_WITH_TIMEOUT(requests.size(), 2, 10000);
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QVERIFY(requests[1]["messages"].toArray()[0].toObject()["content"].toString().contains("RCA_SKILL_RELOAD_TEST"));
        QVERIFY(QFile::rename(skillPath, disabled));
        ai->click(); QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(requests.size(), 2);
        QVERIFY(window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().contains(QStringLiteral("技能")));
    }

    void detectsFourBoardsWithoutManualSelection()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder-not-a-real-key");
        QVERIFY(!window.findChild<QComboBox *>("analysisBoard"));
        const QString sourceDatabase = qEnvironmentVariable("SOURCE_RELATIONS_DATABASE");
        if(!sourceDatabase.isEmpty()) window.findChild<QLineEdit *>("analysisSourceDatabasePath")->setText(sourceDatabase);
        const QString capture = qEnvironmentVariable("BOARD_UI_CAPTURE");
        if(!capture.isEmpty()) {
            QFontDatabase::addApplicationFont("C:/Windows/Fonts/msyh.ttc");
            QApplication::setFont(QFont("Microsoft YaHei", 9));
            window.resize(1100, 760); window.show();
        }
        int calls = 0;
        QStringList paths;
        for(const QString &board : {QString("ATP"), QString("IPB"), QString("OPB"), QString("SPB")}) {
            const QString path = temp.filePath("DownLog_" + board + "_test.txt1.csv");
            QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly));
            file.write(QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n警告,0x0002,自检结果,0xaa,失败\n").toUtf8()); file.close();
            paths.append(path);
            QVERIFY(DropFiles(window, {path}));
            QVERIFY(window.findChild<QLabel *>("autoBoardLabel")->text().contains(board));
            window.findChild<QLineEdit *>("analysisBaselinePath")->setText(temp.filePath(board + "-missing.db"));
            auto *ai = window.findChild<QPushButton *>("aiAnalysisButton"); ai->click();
            QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
            QCOMPARE(client->calls, ++calls);
            const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
            QCOMPARE(evidence["board_type"].toString(), board);
            if(!sourceDatabase.isEmpty()) QCOMPARE(evidence["source_evidence"].toObject()["snapshot"].toObject()["board"].toString(), board);
            QVERIFY(!evidence["baseline_reference"].toObject()["available"].toBool());
        }
        if(!capture.isEmpty()) { QApplication::processEvents(); QVERIFY(window.grab().save(capture)); }
        QVERIFY(!DropFiles(window, {paths[0], paths[1]}));
        QVERIFY(!window.findChild<QPushButton *>("aiAnalysisButton")->isEnabled());
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("不同板卡")));
    }

    void initTestCase()
    {
        QVERIFY(m_Settings.isValid());
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_Settings.path());
        QCoreApplication::setOrganizationName("LogDiagnosisTests");
        QCoreApplication::setApplicationName("SinglePageAnalysis");
    }

    void sourceQueryPluginOpensFromMainWindow()
    {
        const QString database = qEnvironmentVariable("SOURCE_RELATIONS_DATABASE");
        if(database.isEmpty()) QSKIP("Source query plugin fixture is opt-in");
        QSettings().setValue("sourceRelations/database", database);
        MainWindow window;
        QTemporaryDir input;
        const QString csv = input.filePath("OPB_query.txt1.csv");
        QFile file(csv); QVERIFY(file.open(QIODevice::WriteOnly)); file.write("query fixture"); file.close();
        QVERIFY(DropFiles(window, {csv}));
        auto *button = window.findChild<QPushButton *>("sourceRelationsButton");
        QVERIFY(button);
        button->click();
        auto *dialog = window.findChild<QDialog *>("sourceRelationsDialog");
        QVERIFY(dialog);
        auto *search = dialog->findChild<QLineEdit *>("sourceSearchText");
        auto *run = dialog->findChild<QPushButton *>("sourceSearchButton");
        auto *results = dialog->findChild<QTableWidget *>("sourceSearchResults");
        QVERIFY(search && run && results);
        search->setText("Plat_Main");
        run->click();
        QVERIFY(results->rowCount() > 0);
        dialog->hide();
        button->click();
        QCOMPARE(window.findChildren<QDialog *>("sourceRelationsDialog").size(), 1);
        QSettings().remove("sourceRelations/database");
    }

    void parseAndAiAreSeparateActions()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client);
        QVERIFY(Prepare(window, temp, parser));
        QVERIFY(!window.findChild<QTabWidget *>("workspaceTabs"));
        QCOMPARE(window.findChild<QTabWidget *>("managementTabs")->count(), 2);
        QCOMPARE(client->calls, 0);
        window.resize(1100, 760); window.show();
        auto *start = window.findChild<QPushButton *>("startButton");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        QCOMPARE(start->text(), QStringLiteral("日志解析"));
        QCOMPARE(ai->text(), QStringLiteral("AI 分析"));
        QVERIFY(!ai->isEnabled());
        QTest::mouseClick(start, Qt::LeftButton);
        QVERIFY(!start->isEnabled());
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(parser->calls, 1); QVERIFY(parser->isolated);
        QCOMPARE(client->calls, 0);
        QVERIFY(ai->isEnabled());
        QVERIFY(window.findChild<QPlainTextEdit *>("aiEvidenceInput")->toPlainText().isEmpty());
        ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 1);
        const QJsonObject evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(evidence.value("schema_version").toString(), QString("opb-diagnostic-evidence/1"));
        QCOMPARE(evidence.value("statistics").toObject().value("event_count").toString(), QString("10"));
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
        QVERIFY(window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().contains("UNKNOWN"));
        const QString capture = qEnvironmentVariable("LOGDIAG_UI_CAPTURE");
        if(!capture.isEmpty()) QVERIFY(window.grab().save(capture));
    }

    void aiButtonAutomaticallyAddsSourceEvidence()
    {
        const QString database = qEnvironmentVariable("SOURCE_RELATIONS_DATABASE");
        if(database.isEmpty()) QSKIP("Source relation database fixture is opt-in");
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client);
        QVERIFY(Prepare(window, temp, parser));
        window.findChild<QLineEdit *>("analysisSourceDatabasePath")->setText(database);
        QFile actualCsv(parser->outputs.first());
        QVERIFY(actualCsv.open(QIODevice::ReadOnly));
        QByteArray actualContent = actualCsv.readAll(); actualCsv.close();
        actualContent.replace(",0x00,10", ",0x00,20");
        actualContent = QTextCodec::codecForName("GB18030")->toUnicode(actualContent).toUtf8();
        actualContent += QStringLiteral("警告,0x0002,自检结果,0xaa,失败\n").toUtf8();
        actualCsv.setFileName(temp.filePath("OPB_changed.txt1.csv"));
        QVERIFY(actualCsv.open(QIODevice::WriteOnly)); actualCsv.write(actualContent); actualCsv.close();
        parser->outputs = QStringList{actualCsv.fileName()};
        const QString settingsCapture = qEnvironmentVariable("SOURCE_AI_SETTINGS_CAPTURE");
        if(!settingsCapture.isEmpty()) {
            QFontDatabase::addApplicationFont("C:/Windows/Fonts/msyh.ttc");
            QApplication::setFont(QFont("Microsoft YaHei", 9));
            auto *settings = window.findChild<QDialog *>("analysisSettingsDialog");
            QVERIFY(settings);
            settings->show();
            QApplication::processEvents();
            QVERIFY(settings->grab().save(settingsCapture));
            settings->hide();
        }
        QVERIFY(DropFiles(window, parser->outputs));
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 1);
        const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        const auto source = evidence["source_evidence"].toObject();
        QCOMPARE(source["status"].toString(), QString("reference_only"));
        QVERIFY(!source["records"].toArray().isEmpty());
        QVERIFY(evidence["export_policy"].toString().contains("source_snippets"));
        const QString capture = qEnvironmentVariable("SOURCE_AI_CAPTURE");
        if(!capture.isEmpty()) {
            QFile file(capture); QVERIFY(file.open(QIODevice::WriteOnly)); file.write(client->received.toUtf8());
        }
        window.findChild<QLineEdit *>("analysisSourceDatabasePath")->setText(temp.filePath("missing.sqlite"));
        ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 2);
        const auto fallback = QJsonDocument::fromJson(client->received.toUtf8()).object()["source_evidence"].toObject();
        QCOMPARE(fallback["status"].toString(), QString("unavailable"));
        QVERIFY(fallback["records"].toArray().isEmpty());
        const QString snapshotCsv = temp.filePath("OPB_snapshot_source.txt1.csv");
        QFile snapshot(snapshotCsv);
        QVERIFY(snapshot.open(QIODevice::WriteOnly));
        snapshot.write(QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n错误,0x0002,自检结果,0xaa,失败\n").toUtf8());
        snapshot.close();
        window.findChild<QLineEdit *>("analysisSourceDatabasePath")->setText(database);
        QVERIFY(DropFiles(window, {snapshotCsv}));
        ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 3);
        const auto snapshotEvidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(snapshotEvidence["analysis_mode"].toString(), QString("crash_snapshot_values"));
        QVERIFY(!snapshotEvidence["source_evidence"].toObject()["records"].toArray().isEmpty());
        QString multiple = QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n");
        for(int index = 0; index < 7; ++index)
            multiple += QStringLiteral("警告,0x%1,独立自检结果%2,0xaa,失败\n").arg(0xF800 + index, 4, 16).arg(index);
        multiple += QStringLiteral("调试,0x0001,普通数值,0x00,10\n");
        QVERIFY(snapshot.open(QIODevice::WriteOnly)); snapshot.write(multiple.toUtf8()); snapshot.close();
        QVERIFY(DropFiles(window, {snapshotCsv})); ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 4);
        const auto multipleEvidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(multipleEvidence["candidates"].toArray().size(), 7);
        QCOMPARE(multipleEvidence["ai_evidence_selection"].toObject()["candidate_codes"].toArray().size(), 7);
        QCOMPARE(multipleEvidence["variable_comparisons"].toArray().size(), 7);
        for(const auto &comparison : multipleEvidence["variable_comparisons"].toArray())
            QVERIFY(comparison.toObject()["code"].toString() != "0x0001");
        QCOMPARE(multipleEvidence["supporting_context_variables"].toArray().size(), 1);
        QCOMPARE(multipleEvidence["supporting_context_variables"].toArray()[0].toObject()["code"].toString(), QString("0x0001"));
        QSettings().remove("sourceRelations/database");
    }

    void droppedCsvAnalyzesWithoutParserOrDictionaryAndCanRetry()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        window.findChild<QLineEdit *>("analysisDictionaryPath")->clear();
        QVERIFY(DropFiles(window, parser->outputs));
        auto *parse = window.findChild<QPushButton *>("startButton");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        QVERIFY(!parse->isEnabled()); QVERIFY(ai->isEnabled());
        QCOMPARE(parser->calls, 0); QCOMPARE(client->calls, 0);
        window.findChild<QLineEdit *>("analysisDictionaryPath")->setText(temp.filePath("missing.csv"));
        for(auto *box : window.findChildren<QCheckBox *>())
            if(box->text() == QStringLiteral("同时解析应用日志")) box->setChecked(!box->isChecked());
        QVERIFY(ai->isEnabled());
        client->fail = true; ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 1);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("网络失败")));
        client->fail = false; ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 2); QCOMPARE(parser->calls, 0);
        const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(evidence.value("analysis_mode").toString(), QString("cyclic_log"));
        QCOMPARE(evidence.value("statistics").toObject().value("event_count").toString(), QString("10"));
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
    }

    void droppedCsvSegmentsAreComparedTogetherInOrder()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        const QString first = parser->outputs.first(), second = temp.filePath("OPB_raw.txt2.csv");
        QFile file(first); QVERIFY(file.open(QIODevice::ReadOnly));
        const QByteArray data = file.readAll(); file.close();
        const int split = data.indexOf("Cycle Num : 3"); QVERIFY(split > 0);
        QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate)); file.write(data.left(split)); file.close();
        file.setFileName(second); QVERIFY(file.open(QIODevice::WriteOnly)); file.write(data.mid(split)); file.close();
        QVERIFY(DropFiles(window, {second, first}));
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton"); QVERIFY(ai->isEnabled());
        QVERIFY(window.findChild<QLineEdit *>("analysisSourceLog")->toolTip().contains(first));
        ai->click(); QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 1); QCOMPARE(parser->calls, 0);
        const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(evidence.value("statistics").toObject().value("event_count").toString(), QString("10"));
        QCOMPARE(evidence.value("statistics").toObject().value("first_cycle").toString(), QString("1"));
        QCOMPARE(evidence.value("statistics").toObject().value("last_cycle").toString(), QString("5"));
    }

    void droppedSnapshotCsvNeedsNoCyclesOrDictionary()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        const QString snapshot = temp.filePath(QStringLiteral("DownLog_OPB.txt宕机.CSV"));
        QFile file(snapshot); QVERIFY(file.open(QIODevice::WriteOnly));
        QTextStream out(&file); out.setCodec("GB18030");
        out << QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n"
                              "调试,0x0001,输出值,0x1e,30\n错误,0x002b,上电自检结果,0xaa,失败\n");
        out.flush(); file.close();
        window.findChild<QLineEdit *>("analysisDictionaryPath")->clear();
        QVERIFY(DropFiles(window, {snapshot}));
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton"); ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 1); QCOMPARE(parser->calls, 0);
        const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QCOMPARE(evidence.value("statistics").toObject().value("event_count").toString(), QString("2"));
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
    }

    void switchingBetweenRawAndCsvDoesNotReusePreviousInput()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        const QString raw = window.findChild<QLineEdit *>("analysisSourceLog")->text();
        auto *parse = window.findChild<QPushButton *>("startButton");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000);
        QVERIFY(DropFiles(window, parser->outputs)); QVERIFY(ai->isEnabled());
        QVERIFY(!DropFiles(window, {raw, parser->outputs.first()}));
        QCOMPARE(client->calls, 0);
        QVERIFY(DropFiles(window, {raw})); QVERIFY(parse->isEnabled()); QVERIFY(!ai->isEnabled());
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000); QVERIFY(ai->isEnabled());
        window.findChild<QLineEdit *>("analysisSourceLog")->setText(parser->outputs.first());
        QVERIFY(ai->isEnabled()); QVERIFY(!parse->isEnabled());
        QVERIFY(QFile::remove(parser->outputs.first()));
        ai->click(); QVERIFY(!ai->isEnabled()); QCOMPARE(client->calls, 0);
        QCOMPARE(parser->calls, 2);
    }

    void invalidOrUnrelatedCsvDoesNotRequestAi()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        const QString bad = temp.filePath("OPB_invalid.csv");
        QFile file(bad); QVERIFY(file.open(QIODevice::WriteOnly)); file.write("not a parsed log\n"); file.close();
        QVERIFY(DropFiles(window, {bad}));
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton"); ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 0);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text() != QStringLiteral("分析完成"));
        const QString unrelated = temp.filePath("OPB_other.txt1.csv");
        QVERIFY(QFile::copy(parser->outputs.first(), unrelated));
        QVERIFY(DropFiles(window, {unrelated, parser->outputs.first()}));
        ai->click(); QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 10000);
        QCOMPARE(client->calls, 0); QCOMPARE(parser->calls, 0);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("同一")));
    }

    void parseFailureNeverRequestsDeepSeek()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; parser->fail = true;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click(); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 0);
        QVERIFY(window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().contains(QStringLiteral("测试解析失败")));
        QVERIFY(!window.findChild<QPushButton *>("aiAnalysisButton")->isEnabled());
    }

    void parsingWorksWithoutApiKeyOrBaseline()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        const QString baseline = window.findChild<QLineEdit *>("analysisBaselinePath")->text();
        window.findChild<QLineEdit *>("apiKeyEdit")->clear();
        window.findChild<QLineEdit *>("analysisBaselinePath")->clear();
        auto *parse = window.findChild<QPushButton *>("startButton");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000);
        QCOMPARE(parser->calls, 1); QCOMPARE(client->calls, 0);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("日志解析完成")));
        QVERIFY(ai->isEnabled());
        ai->click(); QCOMPARE(client->calls, 0);
        window.findChild<QLineEdit *>("analysisBaselinePath")->setText(baseline);
        window.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder-not-a-real-key");
        ai->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000);
        QCOMPARE(client->calls, 1); QCOMPARE(parser->calls, 1);
    }

    void parsedResultIsBoundToSourceDictionaryAndOptions()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        auto *parse = window.findChild<QPushButton *>("startButton");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000); QVERIFY(ai->isEnabled());
        QFile raw(window.findChild<QLineEdit *>("analysisSourceLog")->text());
        QVERIFY(raw.open(QIODevice::Append)); raw.write("changed"); raw.close();
        ai->click(); QCOMPARE(client->calls, 0); QVERIFY(!ai->isEnabled());
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000); QVERIFY(ai->isEnabled());
        auto *options = window.findChild<QCheckBox *>();
        // The parser option is identified by its product label, not the key checkbox.
        for(auto *box : window.findChildren<QCheckBox *>())
            if(box->text() == QStringLiteral("同时解析应用日志")) options = box;
        options->setChecked(!options->isChecked()); QVERIFY(!ai->isEnabled());
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000); QVERIFY(ai->isEnabled());
        window.findChild<QLineEdit *>("analysisDictionaryPath")->setText(temp.filePath("different-dictionary.csv"));
        QVERIFY(!ai->isEnabled()); QCOMPARE(client->calls, 0);
    }

    void missingParsedCsvOrReparseFailureCannotReuseOldResult()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser; auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        auto *parse = window.findChild<QPushButton *>("startButton");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000);
        QVERIFY(ai->isEnabled()); parser->fail = true;
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000);
        QVERIFY(!ai->isEnabled()); QCOMPARE(client->calls, 0);
        parser->fail = false;
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 10000);
        QVERIFY(ai->isEnabled()); QVERIFY(QFile::remove(parser->outputs.first()));
        ai->click(); QVERIFY(!ai->isEnabled()); QCOMPARE(client->calls, 0);
    }

    void baselineMismatchStopsBeforeAi()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        window.findChild<QLineEdit *>("analysisSoftwareVersion")->setText("v2");
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click(); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 0);
        window.findChild<QPushButton *>("aiAnalysisButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("版本不匹配")));
    }

    void stopDuringParseDoesNotSendToAi()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click();
        window.findChild<QPushButton *>("stopAnalysisButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 0);
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("解析已停止"));
        QVERIFY(!window.findChild<QPushButton *>("aiAnalysisButton")->isEnabled());
    }

    void aiFailureKeepsLocalEvidenceAndAllowsRetry()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek; client->fail = true;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click(); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        QCOMPARE(client->calls, 0); ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 1);
        QVERIFY(!window.findChild<QPlainTextEdit *>("aiEvidenceInput")->toPlainText().isEmpty());
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("网络失败")));
        client->fail = false;
        ai->click(); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 2);
        QCOMPARE(parser->calls, 1);
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
    }

    void snapshotPipelineAndBackgroundImportNeedNoCycleNumbers()
    {
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client); QVERIFY(Prepare(window, temp, parser));
        const QString snapshot = temp.filePath(QStringLiteral("DownLog_OPB.txt宕机.csv"));
        QFile file(snapshot); QVERIFY(file.open(QIODevice::WriteOnly));
        QTextStream stream(&file); stream.setCodec("GB18030");
        stream << QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n"
                                  "调试,0x0001,输出值,0x1e,30\n错误,0x002b,上电自检结果,0xaa,失败\n");
        stream.flush(); file.close(); parser->outputs = QStringList{snapshot};
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click(); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 0);
        window.findChild<QPushButton *>("aiAnalysisButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 10000);
        QCOMPARE(client->calls, 1);
        const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QVERIFY(evidence.value("statistics").toObject().value("first_cycle").isNull());
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
        window.findChild<QListWidget *>("faultFiles")->addItem(snapshot);
        window.findChild<QLineEdit *>("faultDatabase")->setText(temp.filePath("snapshot-ui.db"));
        auto *add = window.findChild<QPushButton *>("faultImportButton");
        add->click(); QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 10000);
        const QString text = window.findChild<QPlainTextEdit *>("faultResult")->toPlainText();
        QVERIFY2(text.contains(QStringLiteral("无周期号")), qPrintable(text));
        QVERIFY(!text.contains(QStringLiteral("周期范围：0")));
    }

    void managementTasksKeepUiResponsiveWhileDatabaseIsLocked()
    {
        QTemporaryDir temp;
        const QString csv = MakeNormalCsv(temp); QVERIFY(!csv.isEmpty());
        const QString baseline = temp.filePath("background-baseline.db");
        QVERIFY(OpbBaselineAnalyzer().BuildBaseline({csv}, baseline).success);
        MainWindow window(nullptr, new SimulatedParser, new SimulatedDeepSeek);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QListWidget *>("baselineFiles")->addItem(csv);
        window.findChild<QLineEdit *>("baselineDatabase")->setText(baseline);
        auto *build = window.findChild<QPushButton *>("baselineBuildButton");
        auto *cancel = window.findChild<QPushButton *>("cancelBaselineButton");
        int beats = 0;
        QTimer heartbeat; heartbeat.setInterval(1);
        connect(&heartbeat, &QTimer::timeout, [&]() { ++beats; });
        const QString connectionName = QUuid::createUuid().toString();
        {
            auto locked = QSqlDatabase::addDatabase("QSQLITE", connectionName);
            locked.setDatabaseName(baseline); QVERIFY(locked.open());
            QSqlQuery query(locked); QVERIFY(query.exec("BEGIN EXCLUSIVE"));
            bool released = false;
            QTimer::singleShot(150, &window, [&]() { released = query.exec("COMMIT"); });
            heartbeat.start();
            QElapsedTimer elapsed; elapsed.start();
            build->click();
            QVERIFY2(elapsed.elapsed() < 100, "Launching baseline task blocked the UI");
            QVERIFY(!build->isEnabled()); QVERIFY(cancel->isEnabled());
            QVERIFY(!window.findChild<QPushButton *>("startButton")->isEnabled());
            QTRY_VERIFY_WITH_TIMEOUT(build->isEnabled(), 10000);
            heartbeat.stop();
            QVERIFY(released); QVERIFY(beats > 5);
        }
        QSqlDatabase::removeDatabase(connectionName);
        QCOMPARE(window.findChild<QProgressBar *>("baselineProgress")->value(), 100);
        QVERIFY2(window.findChild<QLabel *>("baselineStatus")->text().contains(QStringLiteral("建立完成")),
                 qPrintable(window.findChild<QPlainTextEdit *>("baselineResult")->toPlainText()));
        QCOMPARE(window.findChild<QLineEdit *>("analysisBaselinePath")->text(), baseline);

        const QString fault = temp.filePath("background-fault.db");
        window.findChild<QListWidget *>("faultFiles")->addItem(csv);
        window.findChild<QLineEdit *>("faultDatabase")->setText(fault);
        auto *add = window.findChild<QPushButton *>("faultImportButton");
        beats = 0; heartbeat.start();
        QElapsedTimer elapsed; elapsed.start(); add->click();
        QVERIFY2(elapsed.elapsed() < 100, "Launching fault import blocked the UI");
        QVERIFY(!add->isEnabled());
        QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 10000);
        heartbeat.stop();
        QVERIFY(beats > 0);
        QCOMPARE(window.findChild<QProgressBar *>("faultProgress")->value(), 100);
        QVERIFY(window.findChild<QLabel *>("faultStatus")->text().contains(QStringLiteral("入库完成")));
        add->click(); QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 10000);
        QVERIFY(window.findChild<QLabel *>("faultStatus")->text().contains(QStringLiteral("已存在")));
    }

    void managementTasksCancelAndRecoverControls()
    {
        QTemporaryDir temp;
        const QString csv = MakeNormalCsv(temp); QVERIFY(!csv.isEmpty());
        MainWindow window(nullptr, new SimulatedParser, new SimulatedDeepSeek);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        const QString selectedBaseline = window.findChild<QLineEdit *>("analysisBaselinePath")->text();
        window.findChild<QListWidget *>("baselineFiles")->addItem(csv);
        window.findChild<QLineEdit *>("baselineDatabase")->setText(temp.filePath("cancel-baseline.db"));
        auto *build = window.findChild<QPushButton *>("baselineBuildButton");
        build->click(); window.findChild<QPushButton *>("cancelBaselineButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(build->isEnabled(), 10000);
        QVERIFY(window.findChild<QLabel *>("baselineStatus")->text().contains(QStringLiteral("已取消")));
        QCOMPARE(window.findChild<QLineEdit *>("analysisBaselinePath")->text(), selectedBaseline);
        QVERIFY(window.findChild<QListWidget *>("baselineFiles")->isEnabled());

        window.findChild<QListWidget *>("faultFiles")->addItem(csv);
        window.findChild<QLineEdit *>("faultDatabase")->setText(temp.filePath("cancel-fault.db"));
        auto *add = window.findChild<QPushButton *>("faultImportButton");
        add->click(); window.findChild<QPushButton *>("cancelFaultButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 10000);
        QVERIFY(window.findChild<QLabel *>("faultStatus")->text().contains(QStringLiteral("已取消")));
        QVERIFY(window.findChild<QPushButton *>("startButton")->isEnabled());
        add->click(); QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 10000);
        QCOMPARE(window.findChild<QProgressBar *>("faultProgress")->value(), 100);
    }

    void closingWindowWaitsForBackgroundRollbackWithoutBlockingUi()
    {
        QTemporaryDir temp;
        const QString csv = MakeNormalCsv(temp); QVERIFY(!csv.isEmpty());
        MainWindow window(nullptr, new SimulatedParser, new SimulatedDeepSeek);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QListWidget *>("faultFiles")->addItem(csv);
        window.findChild<QLineEdit *>("faultDatabase")->setText(temp.filePath("close-fault.db"));
        window.show();
        window.findChild<QPushButton *>("faultImportButton")->click();
        QElapsedTimer elapsed; elapsed.start();
        QVERIFY(!window.close());
        QVERIFY(elapsed.elapsed() < 100);
        QTRY_VERIFY_WITH_TIMEOUT(!window.isVisible(), 10000);
        QVERIFY(window.findChild<QLabel *>("faultStatus")->text().contains(QStringLiteral("已取消")));
    }

    void largeManagementRegression()
    {
        const QString csv1 = qEnvironmentVariable("LOGDIAG_BACKGROUND_CSV1");
        const QString csv2 = qEnvironmentVariable("LOGDIAG_BACKGROUND_CSV2");
        if(csv1.isEmpty() || csv2.isEmpty()) QSKIP("Large CSV regression is opt-in");
        QTemporaryDir temp("D:/Qt/build-LogDiagnosis-DiagnosisUiTests/background-XXXXXX");
        QVERIFY(temp.isValid());
        MainWindow window(nullptr, new SimulatedParser, new SimulatedDeepSeek);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        auto *normalFiles = window.findChild<QListWidget *>("baselineFiles");
        normalFiles->addItems({csv1, csv2});
        const QString baseline = temp.filePath("normal.db");
        const QString fault = temp.filePath("fault.db");
        window.findChild<QLineEdit *>("baselineDatabase")->setText(baseline);
        auto *build = window.findChild<QPushButton *>("baselineBuildButton");
        int beats = 0;
        QTimer heartbeat; heartbeat.setInterval(5);
        connect(&heartbeat, &QTimer::timeout, [&]() { ++beats; });
        QElapsedTimer elapsed; elapsed.start(); heartbeat.start();
        build->click(); QTRY_VERIFY_WITH_TIMEOUT(build->isEnabled(), 30000);
        heartbeat.stop();
        qInfo("Large baseline: elapsed=%lldms, UI timer ticks=%d", elapsed.elapsed(), beats);
        QVERIFY(beats > 5);
        QVERIFY2(window.findChild<QLabel *>("baselineStatus")->text().contains(QStringLiteral("建立完成")),
                 qPrintable(window.findChild<QPlainTextEdit *>("baselineResult")->toPlainText()));
        auto *faultFiles = window.findChild<QListWidget *>("faultFiles");
        faultFiles->addItems({csv1, csv2});
        window.findChild<QLineEdit *>("faultDatabase")->setText(fault);
        auto *add = window.findChild<QPushButton *>("faultImportButton");
        beats = 0; elapsed.restart(); heartbeat.start();
        add->click(); QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 30000);
        heartbeat.stop();
        qInfo("Large fault import: elapsed=%lldms, UI timer ticks=%d", elapsed.elapsed(), beats);
        QVERIFY(beats > 5);
        QVERIFY(window.findChild<QLabel *>("faultStatus")->text().contains(QStringLiteral("入库完成")));
        {
            const QString name = QUuid::createUuid().toString();
            {
                auto db = QSqlDatabase::addDatabase("QSQLITE", name); db.setDatabaseName(fault);
                QVERIFY(db.open()); QSqlQuery query(db);
                QVERIFY(query.exec("PRAGMA integrity_check")); QVERIFY(query.next());
                QCOMPARE(query.value(0).toString(), QString("ok"));
                QVERIFY(query.exec("SELECT (SELECT count(*) FROM fault_event) + (SELECT count(*) FROM fault_snapshot_event)")); QVERIFY(query.next());
                QCOMPARE(query.value(0).toLongLong(), qint64(523799));
            }
            QSqlDatabase::removeDatabase(name);
        }
        // Keep all source copies in this temporary directory; the production
        // baseline and fault databases are never used as write targets.
        const QString copy1 = temp.filePath(QFileInfo(csv1).fileName());
        const QString copy2 = temp.filePath(QFileInfo(csv2).fileName());
        QVERIFY(QFile::copy(csv1, copy1)); QVERIFY(QFile::copy(csv2, copy2));
        QFile extra(copy2); QVERIFY(extra.open(QIODevice::Append));
        QTextStream out(&extra); out.setCodec("GB18030");
        out << QStringLiteral("调试,0xFFFF,临时取消测试,0x00,1\n"); out.flush(); extra.close();
        faultFiles->clear(); faultFiles->addItems({copy1, copy2});
        add->click();
        auto *progress = window.findChild<QProgressBar *>("faultProgress");
        QTRY_VERIFY_WITH_TIMEOUT(progress->value() >= 20, 10000);
        QVERIFY(!add->isEnabled());
        window.findChild<QPushButton *>("cancelFaultButton")->click();
        QTRY_VERIFY_WITH_TIMEOUT(add->isEnabled(), 10000);
        QVERIFY(window.findChild<QLabel *>("faultStatus")->text().contains(QStringLiteral("已取消")));
        const QString name = QUuid::createUuid().toString();
        {
            auto db = QSqlDatabase::addDatabase("QSQLITE", name); db.setDatabaseName(fault);
            QVERIFY(db.open()); QSqlQuery query(db);
            QVERIFY(query.exec("SELECT count(*) FROM fault_incident")); QVERIFY(query.next());
            QCOMPARE(query.value(0).toInt(), 1);
            QVERIFY(query.exec("SELECT (SELECT count(*) FROM fault_event) + (SELECT count(*) FROM fault_snapshot_event)")); QVERIFY(query.next());
            QCOMPARE(query.value(0).toLongLong(), qint64(523799));
            QVERIFY(query.exec("PRAGMA integrity_check")); QVERIFY(query.next());
            QCOMPARE(query.value(0).toString(), QString("ok"));
        }
        QSqlDatabase::removeDatabase(name);
    }

    void desktopCrashCsvSimulation()
    {
        const QString csv = qEnvironmentVariable("LOGDIAG_SIM_CSV");
        const QString baseline = qEnvironmentVariable("LOGDIAG_BASELINE");
        const QString evidencePath = qEnvironmentVariable("LOGDIAG_SIM_EVIDENCE");
        if(csv.isEmpty() || baseline.isEmpty()) QSKIP("Desktop CSV simulation is opt-in");
        QTemporaryDir temp;
        auto *parser = new SimulatedParser;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, parser, client);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder-not-a-real-key");
        window.findChild<QLineEdit *>("analysisDictionaryPath")->clear();
        window.findChild<QLineEdit *>("analysisBaselinePath")->setText(baseline);
        window.findChild<QLineEdit *>("analysisSoftwareVersion")->clear();
        if(!qEnvironmentVariable("SOURCE_RELATIONS_DATABASE").isEmpty())
            window.findChild<QLineEdit *>("analysisSourceDatabasePath")->setText(qEnvironmentVariable("SOURCE_RELATIONS_DATABASE"));
        QVERIFY(DropFiles(window, {csv}));
        QCOMPARE(parser->calls, 0); QCOMPARE(client->calls, 0);
        QVERIFY(!window.findChild<QPushButton *>("startButton")->isEnabled());
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        QVERIFY(ai->isEnabled()); ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(ai->isEnabled(), 30000);
        QCOMPARE(client->calls, 1); QCOMPARE(parser->calls, 0);
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
        const auto evidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QCOMPARE(evidence.value("root_cause_status").toString(), QString("UNKNOWN"));
        if(!qEnvironmentVariable("SOURCE_RELATIONS_DATABASE").isEmpty()) {
            QCOMPARE(evidence["source_evidence"].toObject()["snapshot"].toObject()["board"].toString(), QString("OPB"));
            QVERIFY(!evidence["source_evidence"].toObject()["records"].toArray().isEmpty());
        }
        const quint64 count = evidence.value("statistics").toObject().value("event_count").toString().toULongLong();
        QVERIFY(count > 0);
        if(!evidencePath.isEmpty())
        {
            QFile output(evidencePath); QVERIFY(output.open(QIODevice::WriteOnly));
            output.write(QJsonDocument(evidence).toJson(QJsonDocument::Indented)); output.close();
        }
        const QString database = temp.filePath("simulation-fault.db");
        window.findChild<QListWidget *>("faultFiles")->addItem(csv);
        window.findChild<QLineEdit *>("faultDatabase")->setText(database);
        window.findChild<QLineEdit *>("faultCause")->clear();
        auto *import = window.findChild<QPushButton *>("faultImportButton"); import->click();
        QTRY_VERIFY_WITH_TIMEOUT(import->isEnabled(), 30000);
        QVERIFY2(window.findChild<QPlainTextEdit *>("faultResult")->toPlainText().contains(QStringLiteral("0x0A1A")),
                 qPrintable(window.findChild<QPlainTextEdit *>("faultResult")->toPlainText()));
        const auto duplicate = OpbFaultSampleStore().ImportIncident({csv}, database, "OPB");
        QVERIFY2(duplicate.success, qPrintable(duplicate.errorMessage));
        QVERIFY(duplicate.duplicate); QCOMPARE(duplicate.eventCount, count);
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = baseline; input.faultDatabasePath = database; input.incidentId = duplicate.incidentId;
        const auto replay = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(replay.success, qPrintable(replay.errorMessage));
        QCOMPARE(replay.evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QCOMPARE(replay.evidence.value("statistics").toObject().value("event_count").toString(), QString::number(count));
        if(!evidencePath.isEmpty())
        {
            QFile output(evidencePath + ".replay.json"); QVERIFY(output.open(QIODevice::WriteOnly));
            output.write(QJsonDocument(replay.evidence).toJson(QJsonDocument::Indented)); output.close();
        }
        auto normalizedCandidates = [](QJsonArray candidates) {
            for(int i = 0; i < candidates.size(); ++i)
            {
                auto item = candidates.at(i).toObject();
                if(item.value("description").toString().isEmpty())
                    item.insert("description", QStringLiteral("UNKNOWN:") + item.value("code").toString());
                candidates[i] = item;
            }
            return candidates;
        };
        QCOMPARE(normalizedCandidates(replay.evidence.value("candidates").toArray()),
                 normalizedCandidates(evidence.value("candidates").toArray()));
    }

    void realCrashParseDoesNotSendAndItsCsvCanBeImported()
    {
        const QString raw = qEnvironmentVariable("LOGDIAG_RAW");
        const QString dictionary = qEnvironmentVariable("LOGDIAG_DICTIONARY");
        const QString baseline = qEnvironmentVariable("LOGDIAG_BASELINE");
        if(raw.isEmpty() || dictionary.isEmpty() || baseline.isEmpty()) QSKIP("Real crash fixture is opt-in");
        QTemporaryDir temp;
        auto *client = new SimulatedDeepSeek;
        MainWindow window(nullptr, new LegacyParserAdapter, client);
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QLineEdit *>("apiKeyEdit")->clear();
        window.findChild<QLineEdit *>("analysisSourceLog")->setText(raw);
        window.findChild<QLineEdit *>("analysisDictionaryPath")->setText(dictionary);
        auto *parse = window.findChild<QPushButton *>("startButton");
        parse->click(); QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 30000);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("日志解析完成")));
        QCOMPARE(client->calls, 0);
        QStringList paths;
        for(const QString &line : window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().split('\n'))
            if(QFileInfo(line).isFile() && QFileInfo(line).suffix() == "csv") paths.append(line);
        QVERIFY(!paths.isEmpty());
        window.findChild<QLineEdit *>("analysisBaselinePath")->setText(baseline);
        window.findChild<QLineEdit *>("analysisSoftwareVersion")->clear();
        window.findChild<QLineEdit *>("apiKeyEdit")->setText("test-placeholder-not-a-real-key");
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        QVERIFY(ai->isEnabled()); ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(parse->isEnabled(), 30000);
        QCOMPARE(client->calls, 1);
        QCOMPARE(window.findChild<QLabel *>("analysisStage")->text(), QStringLiteral("分析完成"));
        const auto pipelineEvidence = QJsonDocument::fromJson(client->received.toUtf8()).object();
        QCOMPARE(pipelineEvidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        const auto imported = OpbFaultSampleStore().ImportIncident(paths, temp.filePath("real-crash.db"), "OPB");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));
        QCOMPARE(imported.logFormat, QString("snapshot"));
        const quint64 expectedEvents = qEnvironmentVariable("LOGDIAG_EXPECT_EVENTS", "197").toULongLong();
        QCOMPARE(imported.eventCount, expectedEvents);
        QCOMPARE(pipelineEvidence.value("statistics").toObject().value("event_count").toString(), QString::number(expectedEvents));
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = baseline; input.faultDatabasePath = imported.databasePath; input.incidentId = imported.incidentId;
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        QVERIFY2(result.success, qPrintable(result.errorMessage));
        QCOMPARE(result.evidence.value("analysis_mode").toString(), QString("crash_snapshot_values"));
        QCOMPARE(client->calls, 1);
    }

    void liveSeparateParseAndAi()
    {
        if(qEnvironmentVariable("LOGDIAG_LIVE") != "1") QSKIP("Live network test is opt-in");
        MainWindow window;
        window.findChild<QCheckBox *>("rememberApiKey")->setChecked(false);
        window.findChild<QLineEdit *>("analysisSourceLog")->setText(qEnvironmentVariable("LOGDIAG_RAW"));
        window.findChild<QLineEdit *>("analysisDictionaryPath")->setText(qEnvironmentVariable("LOGDIAG_DICTIONARY"));
        window.findChild<QLineEdit *>("analysisBaselinePath")->setText(qEnvironmentVariable("LOGDIAG_BASELINE"));
        window.findChild<QLineEdit *>("analysisSoftwareVersion")->clear();
        QVERIFY2(!window.findChild<QLineEdit *>("apiKeyEdit")->text().trimmed().isEmpty(), "No saved credential");
        auto *start = window.findChild<QPushButton *>("startButton");
        start->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 180000);
        QVERIFY(window.findChild<QLabel *>("analysisStage")->text().contains(QStringLiteral("日志解析完成")));
        auto *ai = window.findChild<QPushButton *>("aiAnalysisButton");
        QVERIFY(ai->isEnabled());
        ai->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(), 180000);
        const QString stage = window.findChild<QLabel *>("analysisStage")->text();
        QVERIFY2(stage == QStringLiteral("分析完成"), qPrintable(stage));
        const QString expectedMode = qEnvironmentVariable("LOGDIAG_EXPECT_MODE");
        if(!expectedMode.isEmpty())
        {
            const auto evidence = QJsonDocument::fromJson(window.findChild<QPlainTextEdit *>("aiEvidenceInput")->toPlainText().toUtf8()).object();
            QCOMPARE(evidence.value("analysis_mode").toString(), expectedMode);
        }
        QVERIFY(!window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().trimmed().isEmpty());
        const QString output = qEnvironmentVariable("LOGDIAG_LIVE_RESULT");
        if(!output.isEmpty())
        {
            QFile result(output); QVERIFY(result.open(QIODevice::WriteOnly));
            result.write(window.findChild<QPlainTextEdit *>("aiResultOutput")->toPlainText().toUtf8());
        }
    }

    void csvAndStoredIncidentFlow()
    {
        QTemporaryDir temp;
        QVERIFY(temp.isValid());
        const QString csv = temp.filePath("test.txt1.csv");
        const QString baseline = temp.filePath("baseline.db");
        QFile file(csv); QVERIFY(file.open(QIODevice::WriteOnly));
        QTextStream out(&file); out.setCodec("GB18030");
        out << QStringLiteral("消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n");
        for(int i = 1; i <= 5; ++i)
            out << QStringLiteral("Cycle Num : %1\n提示,0x0A1A,新周期号,,%1\n包序号: %1\n调试,0x0001,测试,0x00,10\n").arg(i);
        out.flush(); file.close();
        const auto built = OpbBaselineAnalyzer().BuildBaseline({csv}, baseline);
        QVERIFY2(built.success, qPrintable(built.errorMessage));
        const auto imported = OpbFaultSampleStore().ImportIncident({csv}, temp.filePath("fault.db"), "OPB");
        QVERIFY2(imported.success, qPrintable(imported.errorMessage));

        DiagnosisPage page;
        page.resize(1150, 700); page.show();
        page.SetBaselinePath(baseline); page.SetParsedFiles({csv});
        auto *run = page.findChild<QPushButton *>("startButton");
        auto *report = page.findChild<QPlainTextEdit *>("diagnosisReport");
        auto *evidence = page.findChild<QPlainTextEdit *>("diagnosisEvidence");
        QVERIFY(run); QVERIFY(report); QVERIFY(evidence);
        QSignalSpy transfer(&page, &DiagnosisPage::EvidenceReady);
        QTest::mouseClick(run, Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(run->isEnabled(), 10000);
        QVERIFY2(report->toPlainText().contains("UNKNOWN"), qPrintable(report->toPlainText()));
        QVERIFY(QJsonDocument::fromJson(evidence->toPlainText().toUtf8()).isObject());
        QCOMPARE(transfer.count(), 0); // Local diagnosis never automatically transmits.
        QPushButton *send = nullptr;
        for(auto *button : page.findChildren<QPushButton *>())
            if(button->text() == QStringLiteral("送入 AI 分析页")) send = button;
        QVERIFY(send); QVERIFY(send->isEnabled());
        QTest::mouseClick(send, Qt::LeftButton);
        QCOMPARE(transfer.count(), 1);
        QCOMPARE(transfer.at(0).at(0).toString(), evidence->toPlainText());

        page.SetIncident(temp.filePath("fault.db"), imported.incidentId);
        auto *mode = page.findChild<QComboBox *>("diagnosisSourceMode");
        QVERIFY(mode); QCOMPARE(mode->currentIndex(), 1);
        QVERIFY(!send->isEnabled()); // Changing inputs invalidates stale evidence.
        QVERIFY(QFile::remove(csv));
        QTest::mouseClick(run, Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(run->isEnabled(), 10000);
        const auto json = QJsonDocument::fromJson(evidence->toPlainText().toUtf8());
        QCOMPARE(json.object().value("source_type").toString(), QString("stored_incident"));
        QCOMPARE(transfer.count(), 1);
        page.findChild<QLineEdit *>("diagnosisSoftwareVersion")->setText("changed");
        QVERIFY(!send->isEnabled()); QVERIFY(evidence->toPlainText().isEmpty());
    }
};

QTEST_MAIN(DiagnosisUiTests)
#include "DiagnosisUiTests.moc"
