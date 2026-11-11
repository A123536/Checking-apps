#ifndef DIAGNOSISPAGE_H
#define DIAGNOSISPAGE_H

#include "OpbDiagnosticAnalyzer.h"

#include <QFutureWatcher>
#include <QWidget>

class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QStackedWidget;

class DiagnosisPage : public QWidget
{
    Q_OBJECT
public:
    explicit DiagnosisPage(QWidget *parent = nullptr);
    ~DiagnosisPage() override;
    void AddCsvFiles(const QStringList &paths);
    void SetParsedFiles(const QStringList &paths);
    void SetIncident(const QString &databasePath, qint64 incidentId);
    void SetBaselinePath(const QString &path);

signals:
    void EvidenceReady(QString evidence);
    void StatusChanged(QString message, bool busy);

private:
    QComboBox *m_SourceMode;
    QStackedWidget *m_SourceStack;
    QListWidget *m_CsvFiles;
    QLineEdit *m_FaultDatabase;
    QComboBox *m_Incidents;
    QLineEdit *m_BaselineDatabase;
    QLineEdit *m_Version;
    QWidget *m_ConfigPanel;
    QPushButton *m_Run;
    QPushButton *m_Cancel;
    QPushButton *m_Export;
    QPushButton *m_Transfer;
    QProgressBar *m_Progress;
    QLabel *m_Status;
    QPlainTextEdit *m_Report;
    QPlainTextEdit *m_Evidence;
    QFutureWatcher<OpbDiagnosticAnalyzer::Result> m_Watcher;
    std::shared_ptr<std::atomic_bool> m_Cancelled;
    QString m_LastEvidence;

    void ReloadIncidents();
    void InvalidateResult();
    void Run();
};

#endif
