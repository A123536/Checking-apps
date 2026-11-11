#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStringList>
#include <QFutureWatcher>
#include "OpbDiagnosticAnalyzer.h"
#include "OpbBaselineAnalyzer.h"
#include "OpbFaultSampleStore.h"
#include <QVector>

class DeepSeekClient;
class LegacyParserAdapter;
class QCloseEvent;
class QDialog;
class QCheckBox;
class QComboBox;
class QDragEnterEvent;
class QDropEvent;
class QLineEdit;
class QLabel;
class QListWidget;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QTabWidget;
class QTimer;
class SourceQueryInterface;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr,
                        LegacyParserAdapter *parser = nullptr, DeepSeekClient *client = nullptr);
    ~MainWindow() override;

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;
    void closeEvent(QCloseEvent *event) override;

private:
    LegacyParserAdapter *m_Parser;
    DeepSeekClient *m_DeepSeekClient;
    QLabel *m_StatusBadge;
    QDialog *m_SettingsDialog;
    QDialog *m_ManagementDialog;
    QTabWidget *m_ManagementTabs;
    QPushButton *m_SettingsButton;
    QPushButton *m_ManagementButton;
    QPushButton *m_StopButton;
    QLineEdit *m_AnalysisBaselineEdit;
    QLineEdit *m_AnalysisVersionEdit;
    QLineEdit *m_SourceDatabaseEdit;
    SourceQueryInterface *m_SourceQueryPlugin = nullptr;
    QString m_DetectedBoard;
    QLabel *m_AutoBoardLabel;
    QLabel *m_StageLabel;
    QLabel *m_ConfigSummary;
    QPlainTextEdit *m_LocalReportOutput;
    QFutureWatcher<OpbDiagnosticAnalyzer::Result> m_DiagnosticWatcher;
    OpbDiagnosticAnalyzer::Input m_DiagnosticInput;
    std::shared_ptr<std::atomic_bool> m_DiagnosticCancelled;
    bool m_PipelineActive = false;
    enum class Action { None, Parse, Ai };
    Action m_Action = Action::None;
    QStringList m_ParsedCsvPaths;
    QStringList m_InputCsvPaths;
    QString m_ParsedInputSignature;
    QString m_ParseAttemptSignature;
    bool m_StopRequested = false;
    bool m_Closing = false;
    bool m_ManagementTaskActive = false;
    bool m_CloseAfterTasks = false;
    QFutureWatcher<OpbBaselineAnalyzer::BuildResult> m_BaselineWatcher;
    QFutureWatcher<OpbFaultSampleStore::ImportResult> m_FaultWatcher;
    std::shared_ptr<LogTaskControl> m_BaselineTask;
    std::shared_ptr<LogTaskControl> m_FaultTask;
    QTimer *m_TaskProgressTimer;
    QVector<QWidget *> m_ManagementInputs;
    QString m_FaultCauseSnapshot;
    QString m_ManagementBoard;

    QLineEdit *m_SourceLogEdit;
    QLineEdit *m_DictionaryEdit;
    QCheckBox *m_IncludeApplicationLogCheckBox;
    QPushButton *m_StartParseButton;
    QPushButton *m_StartAiButton;
    QProgressBar *m_SingleProgressBar;
    QProgressBar *m_AllProgressBar;
    QPlainTextEdit *m_ParseLogOutput;

    QListWidget *m_BaselineFilesList;
    QLineEdit *m_SoftwareVersionEdit;
    QLineEdit *m_BaselineDatabaseEdit;
    QPushButton *m_BuildBaselineButton;
    QPlainTextEdit *m_BaselineResultOutput;
    QPushButton *m_CancelBaselineButton;
    QProgressBar *m_BaselineProgress;
    QLabel *m_BaselineStatus;

    QListWidget *m_FaultFilesList;
    QLineEdit *m_FaultCauseEdit;
    QLineEdit *m_FaultDatabaseEdit;
    QPushButton *m_AddFaultSampleButton;
    QPlainTextEdit *m_FaultResultOutput;
    QPushButton *m_CancelFaultButton;
    QProgressBar *m_FaultProgress;
    QLabel *m_FaultStatus;

    QLineEdit *m_ApiKeyEdit;
    QCheckBox *m_RememberApiKeyCheckBox;
    QLabel *m_ApiKeyStatusLabel;
    QComboBox *m_ModelComboBox;
    QPushButton *m_TestDeepSeekButton;
    QPlainTextEdit *m_EvidenceInput;
    QPlainTextEdit *m_AiResultOutput;

    QWidget *CreateParserTab();
    QWidget *CreateBaselineTab();
    QWidget *CreateFaultSampleTab();
    QWidget *CreateDeepSeekTab();
    void StartLogParse();
    bool SetInputFiles(const QStringList &paths);
    void StartAnalysis();
    QString CurrentParseSignature() const;
    bool HasCurrentParsedFiles() const;
    void InvalidateParsedResult(const QString &message);
    void RefreshActionButtons();
    void CompareWithBaseline(const QStringList &outputs);
    void SetPipelineBusy(bool busy);
    void FinishAnalysis(const QString &errorMessage = QString());
    void StopAnalysis();
    void SaveSettings();
    void RefreshConfigSummary();
    void StartBaselineTask();
    void StartFaultTask();
    void FinishBaselineTask();
    void FinishFaultTask();
    void SetManagementBusy(bool busy);
    void UpdateManagementProgress();
    void CancelManagementTask(const std::shared_ptr<LogTaskControl> &task, QLabel *status);
    void AddBaselineFiles(const QStringList &paths);
    void AddFaultFiles(const QStringList &paths);
    bool ApplyDeepSeekConfig();
    QString CurrentBoardId() const;
    bool DetectAnalysisBoard(const QStringList &paths);
    SourceQueryInterface *LoadSourceQueryPlugin(QString *errorMessage);
    void SetWorkspaceStatus(const QString &text, bool busy = false);
    void LoadSavedApiKey();
    bool SaveApiKey(QString *errorMessage = nullptr);
    void ClearSavedApiKey();
};

#endif // MAINWINDOW_H
