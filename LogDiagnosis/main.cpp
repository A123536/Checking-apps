#include "MainWindow.h"
#include "LegacyParserAdapter.h"
#include "OpbBaselineAnalyzer.h"
#include "OpbFaultSampleStore.h"
#include "OpbDiagnosticAnalyzer.h"

#include <QApplication>
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>
#include <QTextStream>

#include <cstdio>

int main(int argc, char *argv[])
{
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication application(argc, argv);
    QApplication::setApplicationName(QStringLiteral("LogDiagnosis"));
    QApplication::setOrganizationName(QStringLiteral("Local"));

    const QStringList arguments = QApplication::arguments();
    if(arguments.size() >= 5 && arguments.at(1) == QStringLiteral("--diagnose-opb"))
    {
        OpbDiagnosticAnalyzer::Input input;
        input.baselinePath = arguments.at(2);
        input.csvPaths = arguments.mid(4);
        const auto result = OpbDiagnosticAnalyzer().Analyze(input);
        const QJsonObject report = result.success ? result.evidence : QJsonObject{
            {QStringLiteral("error"), result.errorMessage},
            {QStringLiteral("root_cause_status"), QStringLiteral("UNKNOWN")}};
        const QByteArray json = QJsonDocument(report).toJson(QJsonDocument::Indented);
        QSaveFile output(arguments.at(3));
        if(!output.open(QIODevice::WriteOnly) || output.write(json) != json.size() || !output.commit())
            return 2;
        return result.success ? 0 : 1;
    }
    if((arguments.size() >= 4) &&
       (arguments.at(1) == QStringLiteral("--parse-opb")))
    {
        LegacyParserAdapter parser;
        QObject::connect(&parser, &LegacyParserAdapter::Signal_ParseFailed,
                         &application, [&application](const QString &) {
            application.exit(1);
        });
        QObject::connect(&parser, &LegacyParserAdapter::Signal_ParseFinished,
                         &application, [&application](bool success, const QStringList &) {
            application.exit(success ? 0 : 1);
        });
        parser.StartOpbParse(arguments.at(2), arguments.at(3), false);
        return application.exec();
    }

    if((arguments.size() >= 5) &&
       (arguments.at(1) == QStringLiteral("--build-opb-baseline")))
    {
        const QString databasePath = arguments.at(2);
        const QString softwareVersion = arguments.at(3);
        const QStringList csvPaths = arguments.mid(4);
        const OpbBaselineAnalyzer::BuildResult result = OpbBaselineAnalyzer().BuildBaseline(
                    csvPaths, databasePath, softwareVersion);

        QTextStream output(stdout);
        output.setCodec("UTF-8");
        QFile resultFile(databasePath + QStringLiteral(".result.txt"));
        resultFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate);
        QTextStream resultOutput(&resultFile);
        resultOutput.setCodec("UTF-8");
        if(!result.success)
        {
            output << "ERROR: " << result.errorMessage << endl;
            resultOutput << "ERROR: " << result.errorMessage << endl;
            return 1;
        }

        output << "OK\n"
               << "database=" << result.databasePath << "\n"
               << "cycles=" << result.baselineCycleStart << "-"
               << result.baselineCycleEnd << "\n"
               << "cycle_count=" << result.baselineCycleCount << "\n"
               << "event_count=" << result.baselineEventCount << "\n"
               << "event_code_count=" << result.eventCodeCount << "\n"
               << "unknown_code_count=" << result.pendingDescriptionCodeCount << "\n"
               << "unknown_event_count=" << result.unknownDescriptionEventCount
               << endl;
        resultOutput << "OK\n"
                     << "database=" << result.databasePath << "\n"
                     << "cycles=" << result.baselineCycleStart << "-"
                     << result.baselineCycleEnd << "\n"
                     << "cycle_count=" << result.baselineCycleCount << "\n"
                     << "event_count=" << result.baselineEventCount << "\n"
                     << "event_code_count=" << result.eventCodeCount << "\n"
                     << "unknown_code_count=" << result.pendingDescriptionCodeCount << "\n"
                     << "unknown_event_count=" << result.unknownDescriptionEventCount
                     << endl;
        return 0;
    }

    if((arguments.size() >= 6) &&
       (arguments.at(1) == QStringLiteral("--import-opb-fault")))
    {
        const QString databasePath = arguments.at(2);
        const QString boardType = arguments.at(3);
        const QString knownCause = arguments.at(4);
        const QStringList csvPaths = arguments.mid(5);
        const OpbFaultSampleStore::ImportResult result = OpbFaultSampleStore().ImportIncident(
                    csvPaths, databasePath, boardType, knownCause);

        QFile resultFile(databasePath + QStringLiteral(".result.txt"));
        resultFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate);
        QTextStream resultOutput(&resultFile);
        resultOutput.setCodec("UTF-8");
        if(!result.success)
        {
            resultOutput << "ERROR: " << result.errorMessage << endl;
            return 1;
        }
        resultOutput << (result.duplicate ? "DUPLICATE\n" : "OK\n")
                     << "incident_id=" << result.incidentId << "\n"
                     << "database=" << result.databasePath << "\n"
                     << "source_file_count=" << result.sourceFileCount << "\n"
                     << "log_format=" << result.logFormat << "\n"
                     << "cycle_count=" << result.cycleCount << "\n"
                     << "cycles=" << (result.cycleCount == 0
                                      ? QStringLiteral("NONE")
                                      : QStringLiteral("%1-%2").arg(result.cycleStart).arg(result.cycleEnd)) << "\n"
                     << "event_count=" << result.eventCount << "\n"
                     << "unknown_event_count=" << result.unknownDescriptionEventCount
                     << endl;
        return 0;
    }

    MainWindow window;
    window.show();
    return application.exec();
}
