#include "MainWindow.h"
#include "source_relations/plugin/SourceQueryInterface.h"
#include <QPluginLoader>

#include "DeepSeekClient.h"
#include "LegacyParserAdapter.h"
#include "OpbBaselineAnalyzer.h"
#include "OpbFaultSampleStore.h"
#include "BoardIdentity.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QCloseEvent>
#include <QDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QSaveFile>
#include <QInputDialog>
#include <QDesktopServices>
#include <QTemporaryDir>
#include <QFrame>
#include <QFormLayout>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QJsonDocument>
#include <QJsonArray>
#include <QSet>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSettings>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QtConcurrentRun>
#include <functional>

#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincred.h>
#endif

namespace
{
class CsvDropDialog : public QDialog
{
public:
    CsvDropDialog(QWidget *parent, const std::function<void(const QStringList &)> &handler)
        : QDialog(parent), m_Handler(handler) { setAcceptDrops(true); }
protected:
    void dragEnterEvent(QDragEnterEvent *event) override
    {
        for(const QUrl &url : event->mimeData()->urls())
        {
            const QFileInfo info(url.toLocalFile());
            if(info.isFile() && info.suffix().compare("csv", Qt::CaseInsensitive) == 0)
            {
                event->acceptProposedAction(); return;
            }
        }
        event->ignore();
    }
    void dropEvent(QDropEvent *event) override
    {
        QStringList files;
        for(const QUrl &url : event->mimeData()->urls())
        {
            const QFileInfo info(url.toLocalFile());
            if(info.isFile() && info.suffix().compare("csv", Qt::CaseInsensitive) == 0)
                files << info.absoluteFilePath();
        }
        if(files.isEmpty()) { event->ignore(); return; }
        m_Handler(files); event->acceptProposedAction();
    }
private:
    std::function<void(const QStringList &)> m_Handler;
};

const wchar_t kDeepSeekCredentialTarget[] = L"LogDiagnosis/DeepSeekApiKey";

QString ReadStoredDeepSeekApiKey(QString *errorMessage)
{
#ifdef Q_OS_WIN
    PCREDENTIALW credential = nullptr;
    if(!CredReadW(kDeepSeekCredentialTarget, CRED_TYPE_GENERIC, 0, &credential))
    {
        const DWORD errorCode = GetLastError();
        if(errorCode != ERROR_NOT_FOUND && errorMessage != nullptr)
        {
            *errorMessage = QStringLiteral("读取 Windows 凭据失败，错误码 %1").arg(errorCode);
        }
        return QString();
    }

    const QByteArray value(reinterpret_cast<const char *>(credential->CredentialBlob),
                           static_cast<int>(credential->CredentialBlobSize));
    CredFree(credential);
    return QString::fromUtf8(value);
#else
    if(errorMessage != nullptr)
    {
        *errorMessage = QStringLiteral("当前系统不支持 Windows 凭据管理器");
    }
    return QString();
#endif
}

bool WriteStoredDeepSeekApiKey(const QString &apiKey, QString *errorMessage)
{
#ifdef Q_OS_WIN
    const QByteArray value = apiKey.trimmed().toUtf8();
    CREDENTIALW credential;
    ZeroMemory(&credential, sizeof(credential));
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(kDeepSeekCredentialTarget);
    credential.CredentialBlobSize = static_cast<DWORD>(value.size());
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char *>(value.constData()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<LPWSTR>(L"DeepSeek API Key");
    if(CredWriteW(&credential, 0))
    {
        return true;
    }
    if(errorMessage != nullptr)
    {
        *errorMessage = QStringLiteral("写入 Windows 凭据失败，错误码 %1").arg(GetLastError());
    }
    return false;
#else
    Q_UNUSED(apiKey)
    if(errorMessage != nullptr)
    {
        *errorMessage = QStringLiteral("当前系统不支持 Windows 凭据管理器");
    }
    return false;
#endif
}

bool DeleteStoredDeepSeekApiKey(QString *errorMessage)
{
#ifdef Q_OS_WIN
    if(CredDeleteW(kDeepSeekCredentialTarget, CRED_TYPE_GENERIC, 0))
    {
        return true;
    }
    const DWORD errorCode = GetLastError();
    if(errorCode == ERROR_NOT_FOUND)
    {
        return true;
    }
    if(errorMessage != nullptr)
    {
        *errorMessage = QStringLiteral("删除 Windows 凭据失败，错误码 %1").arg(errorCode);
    }
    return false;
#else
    if(errorMessage != nullptr)
    {
        *errorMessage = QStringLiteral("当前系统不支持 Windows 凭据管理器");
    }
    return false;
#endif
}

QLabel *CreatePanelTitle(const QString &text, QWidget *parent)
{
    QLabel *label = new QLabel(text, parent);
    label->setObjectName(QStringLiteral("panelTitle"));
    return label;
}

QLabel *CreateHint(const QString &text, QWidget *parent)
{
    QLabel *label = new QLabel(text, parent);
    label->setObjectName(QStringLiteral("subtitle"));
    label->setWordWrap(true);
    return label;
}

QFrame *CreatePanel(const QString &objectName, QWidget *parent)
{
    QFrame *panel = new QFrame(parent);
    panel->setObjectName(objectName);
    panel->setFrameShape(QFrame::NoFrame);
    return panel;
}

QJsonObject RelevantAiEvidence(QJsonObject evidence)
{
    // Keep every exported finding and separate cross-check context from findings.
    QSet<QString> relevantCodes;
    QJsonArray codeList;
    for(const QString &key : {QString("explicit_failures"), QString("candidates")}) {
        for(const auto &value : evidence.value(key).toArray()) {
            const QString code = value.toObject().value("code").toString();
            if(!code.isEmpty() && !relevantCodes.contains(code)) {
                relevantCodes.insert(code);
                codeList.append(code);
            }
        }
    }
    const auto comparisons = evidence.value("variable_comparisons").toArray();
    QJsonArray relevantComparisons, supportingContext;
    for(const auto &value : comparisons) {
        const auto comparison = value.toObject();
        if(relevantCodes.contains(comparison.value("code").toString())) {
            relevantComparisons.append(value);
        } else {
            QJsonObject context;
            for(const QString &key : {QString("code"), QString("description"), QString("observed_values"),
                                      QString("observed_values_complete"), QString("normal_observed_values"),
                                      QString("normal_values_complete"), QString("actual_numeric_range"),
                                      QString("normal_numeric_range"), QString("reference_state")})
                if(comparison.contains(key)) context.insert(key, comparison.value(key));
            supportingContext.append(context);
        }
    }
    if(evidence.contains("variable_comparisons")) evidence.insert("variable_comparisons", relevantComparisons);
    evidence.insert("supporting_context_variables", supportingContext);
    const auto context = evidence.take("context_differences").toArray();
    evidence.insert("ai_evidence_selection", QJsonObject{
        {"policy", "preserve_all_exported_findings_separate_context"},
        {"candidate_codes", codeList}, {"context_variable_count", supportingContext.size()},
        {"context_difference_groups", context.size() + evidence.value("omitted_context_groups").toInt()},
        {"context_difference_note", QStringLiteral("版本及构建标识差异作为背景，按version_match及源码快照信息核实。")}});
    evidence.insert("source_lookup_scope", "candidate_codes");
    evidence.insert("source_lookup_codes", codeList);
    return evidence;
}
}

MainWindow::MainWindow(QWidget *parent, LegacyParserAdapter *parser, DeepSeekClient *client)
    : QMainWindow(parent),
      m_Parser(parser ? parser : new LegacyParserAdapter(this)),
      m_DeepSeekClient(client ? client : new DeepSeekClient(this)),
      m_StatusBadge(nullptr),
      m_SettingsDialog(nullptr),
      m_ManagementDialog(nullptr),
      m_RememberApiKeyCheckBox(nullptr),
      m_ApiKeyStatusLabel(nullptr)
{
    m_Parser->setParent(this);
    m_DeepSeekClient->setParent(this);
    setWindowTitle(QStringLiteral("智能日志分析客户端"));
    resize(1100, 760);
    setMinimumSize(900, 640);
    setAcceptDrops(true);

    QWidget *workspace = new QWidget(this);
    workspace->setObjectName(QStringLiteral("analysisWorkspace"));
    QVBoxLayout *workspaceLayout = new QVBoxLayout(workspace);
    workspaceLayout->setContentsMargins(24, 20, 24, 22);
    workspaceLayout->setSpacing(14);
    QHBoxLayout *header = new QHBoxLayout();
    QVBoxLayout *titles = new QVBoxLayout();
    QLabel *title = new QLabel(QStringLiteral("日志分析"), workspace);
    title->setObjectName(QStringLiteral("pageTitle"));
    titles->addWidget(title);
    QLabel *subtitle = CreateHint(QStringLiteral("原始日志先解析；已解析 CSV 可直接进行 AI 分析"), workspace);
    subtitle->setWordWrap(false);
    titles->addWidget(subtitle);
    header->addLayout(titles, 1);
    m_StatusBadge = new QLabel(QStringLiteral("就绪 · 自动识别板卡"), workspace);
    m_StatusBadge->setObjectName(QStringLiteral("analysisAssetsBadge"));
    header->addWidget(m_StatusBadge, 0, Qt::AlignVCenter);
    QPushButton *sourceRelationsButton = new QPushButton(QStringLiteral("源码关系查询"), workspace);
    sourceRelationsButton->setObjectName(QStringLiteral("sourceRelationsButton"));
    header->addWidget(sourceRelationsButton);
    connect(sourceRelationsButton, &QPushButton::clicked, this, [this]() {
        if(CurrentBoardId().isEmpty() && m_SourceBranch.isEmpty()) { m_StageLabel->setText(QStringLiteral("请先导入日志，自动识别板卡后查询对应源码")); return; }
        QDialog *existing = findChild<QDialog *>(QStringLiteral("sourceRelationsDialog"));
        if(existing) {
            auto *queryWidget = existing->findChild<QWidget *>("sourceQueryWidget");
            if(queryWidget) queryWidget->setProperty("expectedBoard", CurrentBoardId());
            auto *path = existing->findChild<QLineEdit *>("sourceDatabasePath");
            if(path) path->setText(BoardIdentity::sourceDatabase(m_SourceDatabaseEdit->text().trimmed(), CurrentBoardId()));
            ConfigureSourceQueryWidget(queryWidget);
            existing->show(); existing->raise(); existing->activateWindow(); return;
        }
        QString errorMessage;
        auto *plugin = LoadSourceQueryPlugin(&errorMessage);
        if(!plugin) {
            QMessageBox::warning(this, QStringLiteral("源码关系查询"),
                                 QStringLiteral("查询插件加载失败。%1").arg(errorMessage));
            return;
        }
        auto *dialog = new QDialog(this);
        dialog->setObjectName(QStringLiteral("sourceRelationsDialog"));
        dialog->setWindowTitle(QStringLiteral("源码关系库查询"));
        dialog->resize(1240, 800);
        auto *dialogLayout = new QVBoxLayout(dialog);
        auto *queryWidget = plugin->createQueryWidget(
            BoardIdentity::sourceDatabase(m_SourceDatabaseEdit->text().trimmed(), CurrentBoardId()), dialog);
        queryWidget->setProperty("expectedBoard", CurrentBoardId());
        ConfigureSourceQueryWidget(queryWidget);
        dialogLayout->addWidget(queryWidget);
        connect(dialog, &QDialog::finished, this, [this](int) {
            if(m_SourceBranch.isEmpty())
                m_SourceDatabaseEdit->setText(QSettings().value("sourceRelations/database", m_SourceDatabaseEdit->text()).toString());
        });
        dialog->show();
    });
    m_ManagementButton = new QPushButton(QStringLiteral("基线与样本管理"), workspace);
    m_ManagementButton->setObjectName(QStringLiteral("managementButton"));
    m_SettingsButton = new QPushButton(QStringLiteral("设置"), workspace);
    m_SettingsButton->setObjectName(QStringLiteral("settingsButton"));
    header->addWidget(m_ManagementButton);
    header->addWidget(m_SettingsButton);
    workspaceLayout->addLayout(header);
    m_BranchesRoot = qEnvironmentVariable("LOGDIAG_BRANCH_ROOT");
    if(m_BranchesRoot.isEmpty())
        m_BranchesRoot = QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../code_branches");
    m_SourceBranchControls = new QWidget(workspace);
    auto *branchRow = new QHBoxLayout(m_SourceBranchControls);
    branchRow->setContentsMargins(0, 0, 0, 0);
    branchRow->addWidget(new QLabel(QStringLiteral("源码分支"), workspace));
    m_SourceBranchCombo = new QComboBox(workspace);
    m_SourceBranchCombo->setObjectName("sourceBranchCombo");
    branchRow->addWidget(m_SourceBranchCombo, 1);
    auto *newBranch = new QPushButton(QStringLiteral("新建分支"), workspace);
    newBranch->setObjectName("createSourceBranchButton");
    auto *refreshBranches = new QPushButton(QStringLiteral("刷新分支"), workspace);
    refreshBranches->setObjectName("refreshSourceBranchesButton");
    auto *openBranch = new QPushButton(QStringLiteral("打开分支目录"), workspace);
    branchRow->addWidget(newBranch);
    branchRow->addWidget(refreshBranches);
    branchRow->addWidget(openBranch);
    workspaceLayout->addWidget(m_SourceBranchControls);
    connect(newBranch, &QPushButton::clicked, this, &MainWindow::CreateSourceBranch);
    connect(refreshBranches, &QPushButton::clicked, this, &MainWindow::RefreshSourceBranches);
    connect(openBranch, &QPushButton::clicked, this, [this]() {
        QDir().mkpath(m_BranchesRoot);
        QDesktopServices::openUrl(QUrl::fromLocalFile(m_SourceBranch.isEmpty() ? m_BranchesRoot : CurrentBranchDirectory()));
    });
    workspaceLayout->addWidget(CreateParserTab(), 1);
    setCentralWidget(workspace);

    m_SettingsDialog = new QDialog(this);
    m_SettingsDialog->setWindowTitle(QStringLiteral("分析设置"));
    m_SettingsDialog->setObjectName(QStringLiteral("analysisSettingsDialog"));
    m_SettingsDialog->resize(760, 620);
    QVBoxLayout *settingsLayout = new QVBoxLayout(m_SettingsDialog);
    settingsLayout->addWidget(CreateDeepSeekTab(), 1);
    QPushButton *closeSettings = new QPushButton(QStringLiteral("保存并关闭"), m_SettingsDialog);
    settingsLayout->addWidget(closeSettings, 0, Qt::AlignRight);
    connect(closeSettings, &QPushButton::clicked, m_SettingsDialog, &QDialog::accept);
    connect(m_SettingsDialog, &QDialog::finished, this, [this](int) { SaveSettings(); RefreshConfigSummary(); });

    m_ManagementDialog = new CsvDropDialog(this, [this](const QStringList &paths) {
        if(m_PipelineActive || m_ManagementTaskActive) return;
        if(m_ManagementTabs->currentIndex() == 1) AddFaultFiles(paths);
        else AddBaselineFiles(paths);
    });
    m_ManagementDialog->setWindowTitle(QStringLiteral("基线与样本管理"));
    m_ManagementDialog->resize(1080, 740);
    m_ManagementTabs = new QTabWidget(m_ManagementDialog);
    m_ManagementTabs->setObjectName(QStringLiteral("managementTabs"));
    m_ManagementTabs->addTab(CreateBaselineTab(), QStringLiteral("正常基线"));
    m_ManagementTabs->addTab(CreateFaultSampleTab(), QStringLiteral("宕机样本"));
    m_BaselineDatabaseEdit->setText(m_AnalysisBaselineEdit->text());
    QVBoxLayout *managementLayout = new QVBoxLayout(m_ManagementDialog);
    managementLayout->addWidget(m_ManagementTabs);
    QPushButton *closeManagement = new QPushButton(QStringLiteral("关闭"), m_ManagementDialog);
    managementLayout->addWidget(closeManagement, 0, Qt::AlignRight);
    connect(closeManagement, &QPushButton::clicked, m_ManagementDialog, &QDialog::accept);
    connect(m_SettingsButton, &QPushButton::clicked, m_SettingsDialog, &QDialog::show);
    connect(m_ManagementButton, &QPushButton::clicked, m_ManagementDialog, &QDialog::show);
    connect(m_ManagementDialog, &QDialog::finished, this, [this](int) { RefreshConfigSummary(); });

    m_TaskProgressTimer = new QTimer(this);
    m_TaskProgressTimer->setInterval(100);
    connect(m_TaskProgressTimer, &QTimer::timeout, this, &MainWindow::UpdateManagementProgress);
    connect(&m_BaselineWatcher, &QFutureWatcher<OpbBaselineAnalyzer::BuildResult>::finished,
            this, &MainWindow::FinishBaselineTask);
    connect(&m_FaultWatcher, &QFutureWatcher<OpbFaultSampleStore::ImportResult>::finished,
            this, &MainWindow::FinishFaultTask);

    setStyleSheet(QStringLiteral(R"(
        QMainWindow, QWidget { background: #F4F6F9; color: #202633; font-family: "Microsoft YaHei UI"; font-size: 13px; }
        QLabel { background: transparent; }
        #pageTitle { font-size: 24px; font-weight: 700; color: #172033; }
        #subtitle, QLabel#subtitle { color: #758096; }
        #analysisAssetsBadge { background: #E9F7F1; color: #147A53; border: 1px solid #CBEBDD; border-radius: 15px; padding: 7px 13px; }
        #analysisAssetsBadge[busy="true"] { background: #FFF5D9; color: #8A6110; border-color: #F1D792; }
        #submissionPanel, #taskPanel, #previewPanel, #agentSidebar { background: white; border: 1px solid #E2E6ED; border-radius: 10px; }
        #panelTitle { font-size: 16px; font-weight: 650; color: #25304A; }
        QTabWidget#workspaceTabs::pane { border: 0; background: transparent; top: -1px; }
        QTabWidget#workspaceTabs QTabBar::tab { background: transparent; color: #6E788B; border: 0; border-bottom: 3px solid transparent; padding: 10px 18px; margin-right: 4px; font-weight: 600; }
        QTabWidget#workspaceTabs QTabBar::tab:selected { color: #315BE8; border-bottom-color: #315BE8; }
        QTabWidget#workspaceTabs QTabBar::tab:hover:!selected { color: #33415C; background: #ECEFF5; }
        QPushButton { background: #FFFFFF; border: 1px solid #D5DAE4; border-radius: 7px; padding: 7px 13px; }
        QPushButton:hover { background: #F0F4FA; border-color: #AEB8C8; }
        QPushButton:disabled { color: #A8AFBC; background: #F2F3F5; }
        QPushButton#startButton, QPushButton[primaryAction="true"] { background: #315BE8; color: white; border-color: #315BE8; font-weight: 600; padding-left: 22px; padding-right: 22px; }
        QPushButton#startButton:hover, QPushButton[primaryAction="true"]:hover { background: #274CD0; }
        QPushButton#startButton:disabled, QPushButton[primaryAction="true"]:disabled { background: #AEB8CF; border-color: #AEB8CF; color: #EEF1F7; }
        QPushButton#dangerButton { color: #B53232; border-color: #E5BABA; }
        QLineEdit, QComboBox { background: #F8F9FB; border: 1px solid #DDE1E8; border-radius: 7px; padding: 6px 10px; min-height: 20px; }
        QLineEdit:focus, QComboBox:focus { border: 1px solid #5377EA; background: white; }
        QWidget#pathRow { background: transparent; }
        QListWidget { background: #FAFBFC; border: 1px solid #E3E6EC; border-radius: 7px; padding: 4px; outline: 0; }
        QListWidget::item { padding: 7px; border-radius: 5px; }
        QListWidget::item:selected { background: #E8EEFF; color: #233B85; }
        QPlainTextEdit { background: #FAFBFC; border: 1px solid #E3E6EC; border-radius: 7px; padding: 8px; color: #5E687A; }
        QProgressBar { background: #E3E7EE; border: 0; border-radius: 3px; min-height: 7px; max-height: 7px; text-align: center; color: transparent; }
        QProgressBar::chunk { background: #315BE8; border-radius: 3px; }
        QSplitter::handle { background: transparent; height: 8px; width: 8px; }
        QCheckBox { spacing: 7px; }
    )"));




    connect(m_Parser, &LegacyParserAdapter::Signal_ProgressChanged, this, [this](int single, int) {
        if(!m_PipelineActive || m_Closing) return;
        m_SingleProgressBar->setValue(qBound(0, single, 100));
        m_AllProgressBar->setValue(qBound(0, single, 100));
    });
    connect(m_Parser, &LegacyParserAdapter::Signal_LogMessage, m_ParseLogOutput, &QPlainTextEdit::appendPlainText);
    connect(m_Parser, &LegacyParserAdapter::Signal_ParseFailed, this, [this](const QString &error) {
        if(m_PipelineActive && m_Action == Action::Parse && !m_Closing) FinishAnalysis(error);
    });
    connect(m_Parser, &LegacyParserAdapter::Signal_ParseFinished, this,
            [this](bool success, const QStringList &outputs) {
        if(!m_PipelineActive || m_Action != Action::Parse || m_Closing) return;
        if(m_StopRequested) { FinishAnalysis(QStringLiteral("解析已停止")); return; }
        if(!success || outputs.isEmpty()) { FinishAnalysis(QStringLiteral("日志解析失败或未生成 CSV")); return; }
        if(CurrentParseSignature() != m_ParseAttemptSignature)
        { FinishAnalysis(QStringLiteral("原始日志或字典在解析期间发生变化，请重新解析")); return; }
        m_ParsedCsvPaths = outputs;
        m_ParsedInputSignature = m_ParseAttemptSignature;
        m_Action = Action::None;
        SetPipelineBusy(false);
        m_AllProgressBar->setRange(0, 100); m_AllProgressBar->setValue(100);
        m_StageLabel->setText(QStringLiteral("日志解析完成，可点击“AI 分析”"));
        m_ParseLogOutput->appendPlainText(QStringLiteral("解析完成，共 %1 个 CSV 文件，等待手动点击 AI 分析").arg(outputs.size()));
        m_AiResultOutput->setPlainText(QStringLiteral("日志解析完成，共生成 %1 个 CSV 文件：\n\n%2\n\n需要分析时，点击上方“AI 分析”。")
                                     .arg(outputs.size()).arg(outputs.join('\n')));
        SetWorkspaceStatus(QStringLiteral("解析完成 · 等待 AI 分析"));
    });
    connect(&m_DiagnosticWatcher, &QFutureWatcher<OpbDiagnosticAnalyzer::Result>::finished, this, [this]() {
        if(m_Closing || !m_PipelineActive) return;
        const auto result = m_DiagnosticWatcher.result();
        if(m_StopRequested) { FinishAnalysis(QStringLiteral("分析已停止")); return; }
        if(!result.success) { FinishAnalysis(result.errorMessage); return; }
        m_LocalReportOutput->setPlainText(result.summary);
        const auto sourceEvidence = result.evidence.value("source_evidence").toObject();
        const QString sourceMessage = sourceEvidence.value("message").toString();
        m_ParseLogOutput->appendPlainText(QStringLiteral("源码关联：%1").arg(sourceMessage));
        m_LocalReportOutput->appendPlainText(QStringLiteral("\n源码关系库\n%1").arg(sourceMessage));
        const QString evidence = QString::fromUtf8(QJsonDocument(result.evidence).toJson(QJsonDocument::Indented));
        m_EvidenceInput->setPlainText(evidence);
        m_ParseLogOutput->appendPlainText(QStringLiteral("日志诊断及源码关联完成，自动请求 DeepSeek 分析"));
        m_StageLabel->setText(QStringLiteral("2 / 2  DeepSeek 正在结合日志与源码证据分析…"));
        m_AllProgressBar->setRange(0, 0);
        SetWorkspaceStatus(QStringLiteral("DeepSeek 分析中"), true);
        m_DeepSeekClient->AnalyzeEvidence(evidence);
    });
    connect(m_DeepSeekClient, &DeepSeekClient::Signal_BusyChanged, this, [this](bool busy) {
        m_TestDeepSeekButton->setEnabled(!busy && !m_PipelineActive);
        RefreshActionButtons();
    });
    connect(m_DeepSeekClient, &DeepSeekClient::Signal_AnalysisInputPrepared, this, [this](const QString &evidence) {
        if(!m_PipelineActive || m_Closing) return;
        m_EvidenceInput->setPlainText(evidence);
        const auto skill = QJsonDocument::fromJson(evidence.toUtf8()).object().value("analysis_skill").toObject();
        m_ParseLogOutput->appendPlainText(QStringLiteral("分析技能已加载 · %1 · SHA256 %2")
                                          .arg(skill.value("name").toString(), skill.value("sha256").toString().left(12)));
    });
    connect(m_DeepSeekClient, &DeepSeekClient::Signal_TestSucceeded, this, [this](const QString &message) {
        m_ApiKeyStatusLabel->setText(QStringLiteral("连接测试成功：") + message);
    });
    connect(m_DeepSeekClient, &DeepSeekClient::Signal_AnalysisSucceeded, this, [this](const QString &content) {
        if(!m_PipelineActive || m_Closing) return;
        if(m_StopRequested) { FinishAnalysis(QStringLiteral("分析已停止")); return; }
        if(content.trimmed().isEmpty()) { FinishAnalysis(QStringLiteral("DeepSeek 未返回有效分析结果")); return; }
        m_AiResultOutput->setPlainText(content);
        FinishAnalysis();
    });
    connect(m_DeepSeekClient, &DeepSeekClient::Signal_RequestFailed, this, [this](const QString &error) {
        if(m_Closing) return;
        if(m_PipelineActive) FinishAnalysis(m_StopRequested ? QStringLiteral("分析已停止") : error);
        else m_ApiKeyStatusLabel->setText(QStringLiteral("连接失败：") + error);
    });
    RefreshSourceBranches();
    connect(m_SourceBranchCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            [this](int) { SelectSourceBranch(); });
    RefreshConfigSummary();
    connect(m_DictionaryEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        if(!m_PipelineActive && m_InputCsvPaths.isEmpty()) InvalidateParsedResult(QStringLiteral("字典已更新，请重新解析日志"));
    });
    connect(m_IncludeApplicationLogCheckBox, &QCheckBox::toggled, this, [this](bool) {
        if(!m_PipelineActive && m_InputCsvPaths.isEmpty()) InvalidateParsedResult(QStringLiteral("解析选项已更新，请重新解析日志"));
    });
    const auto aiSettingsChanged = [this]() {
        if(!m_PipelineActive && HasCurrentParsedFiles())
        {
            m_AiResultOutput->clear(); m_LocalReportOutput->clear(); m_EvidenceInput->clear();
            m_StageLabel->setText(QStringLiteral("分析设置已更新，可重新点击“AI 分析”"));
            RefreshActionButtons();
        }
    };
    connect(m_AnalysisBaselineEdit, &QLineEdit::textChanged, this, aiSettingsChanged);
    connect(m_AnalysisVersionEdit, &QLineEdit::textChanged, this, aiSettingsChanged);
    connect(m_SourceDatabaseEdit, &QLineEdit::textChanged, this, aiSettingsChanged);
    connect(m_ModelComboBox, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, aiSettingsChanged);
    RefreshActionButtons();
}

MainWindow::~MainWindow()
{
    m_Closing = true;
    if(m_DiagnosticCancelled) m_DiagnosticCancelled->store(true);
    disconnect(&m_DiagnosticWatcher, nullptr, this, nullptr);
    disconnect(&m_BaselineWatcher, nullptr, this, nullptr);
    disconnect(&m_FaultWatcher, nullptr, this, nullptr);
    if(m_BaselineTask) m_BaselineTask->RequestCancel();
    if(m_FaultTask) m_FaultTask->RequestCancel();
    m_DiagnosticWatcher.waitForFinished();
    m_BaselineWatcher.waitForFinished();
    m_FaultWatcher.waitForFinished();
}

QWidget *MainWindow::CreateParserTab()
{
    QWidget *page = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(12);

    QFrame *input = CreatePanel(QStringLiteral("submissionPanel"), page);
    QVBoxLayout *inputLayout = new QVBoxLayout(input);
    inputLayout->setContentsMargins(18, 16, 18, 16);
    inputLayout->addWidget(CreatePanelTitle(QStringLiteral("日志文件"), input));
    inputLayout->addWidget(CreateHint(QStringLiteral("原始日志：先点“日志解析”，再点“AI 分析”。已解析 CSV：直接点“AI 分析”；同一日志的多个 CSV 请一起导入。"), input));
    QHBoxLayout *row = new QHBoxLayout();
    m_AutoBoardLabel = new QLabel(QStringLiteral("板卡自动识别"), input);
    m_AutoBoardLabel->setObjectName("autoBoardLabel");
    m_SourceLogEdit = new QLineEdit(input);
    m_SourceLogEdit->setObjectName(QStringLiteral("analysisSourceLog"));
    m_SourceLogEdit->setPlaceholderText(QStringLiteral("拖入一份原始日志，或同一日志的解析 CSV，也可点击浏览"));
    m_SourceLogEdit->setClearButtonEnabled(true);
    m_SourceLogEdit->setAcceptDrops(false);
    QPushButton *browse = new QPushButton(QStringLiteral("浏览…"), input);
    browse->setObjectName(QStringLiteral("browseSourceLog"));
    m_StartParseButton = new QPushButton(QStringLiteral("日志解析"), input);
    m_StartParseButton->setObjectName(QStringLiteral("startButton"));
    m_StartAiButton = new QPushButton(QStringLiteral("AI 分析"), input);
    m_StartAiButton->setObjectName(QStringLiteral("aiAnalysisButton"));
    m_StartAiButton->setProperty("primaryAction", true);
    m_StartAiButton->setEnabled(false);
    m_StopButton = new QPushButton(QStringLiteral("停止"), input);
    m_StopButton->setObjectName(QStringLiteral("stopAnalysisButton"));
    m_StopButton->setEnabled(false);
    row->addWidget(m_AutoBoardLabel);
    row->addWidget(m_SourceLogEdit, 1);
    row->addWidget(browse);
    row->addWidget(m_StartParseButton);
    row->addWidget(m_StartAiButton);
    row->addWidget(m_StopButton);
    inputLayout->addLayout(row);
    m_ConfigSummary = CreateHint(QString(), input);
    inputLayout->addWidget(m_ConfigSummary);
    m_StageLabel = new QLabel(QStringLiteral("等待导入日志"), input);
    m_StageLabel->setObjectName(QStringLiteral("analysisStage"));
    m_StageLabel->setWordWrap(true);
    inputLayout->addWidget(m_StageLabel);
    m_AllProgressBar = new QProgressBar(input);
    m_AllProgressBar->setValue(0);
    inputLayout->addWidget(m_AllProgressBar);
    layout->addWidget(input);

    QFrame *resultPanel = CreatePanel(QStringLiteral("previewPanel"), page);
    QVBoxLayout *resultLayout = new QVBoxLayout(resultPanel);
    resultLayout->setContentsMargins(18, 16, 18, 16);
    resultLayout->addWidget(CreatePanelTitle(QStringLiteral("分析结果"), resultPanel));
    m_AiResultOutput = new QPlainTextEdit(resultPanel);
    m_AiResultOutput->setObjectName(QStringLiteral("aiResultOutput"));
    m_AiResultOutput->setReadOnly(true);
    m_AiResultOutput->setAcceptDrops(false);
    m_AiResultOutput->setPlaceholderText(QStringLiteral("原始日志先解析；已解析 CSV 可直接点击“AI 分析”，结果会显示在这里。"));
    resultLayout->addWidget(m_AiResultOutput, 1);
    QPushButton *showDetails = new QPushButton(QStringLiteral("查看过程与依据"), resultPanel);
    showDetails->setCheckable(true);
    showDetails->setObjectName(QStringLiteral("showAnalysisDetails"));
    resultLayout->addWidget(showDetails, 0, Qt::AlignLeft);
    QWidget *details = new QWidget(resultPanel);
    QVBoxLayout *detailLayout = new QVBoxLayout(details);
    detailLayout->setContentsMargins(0, 0, 0, 0);
    m_SingleProgressBar = new QProgressBar(details);
    m_SingleProgressBar->setValue(0);
    detailLayout->addWidget(m_SingleProgressBar);
    QTabWidget *detailTabs = new QTabWidget(details);
    m_ParseLogOutput = new QPlainTextEdit(detailTabs);
    m_ParseLogOutput->setObjectName(QStringLiteral("analysisProcessLog"));
    m_LocalReportOutput = new QPlainTextEdit(detailTabs);
    m_EvidenceInput = new QPlainTextEdit(detailTabs);
    m_EvidenceInput->setObjectName(QStringLiteral("aiEvidenceInput"));
    for(QPlainTextEdit *edit : {m_ParseLogOutput, m_LocalReportOutput, m_EvidenceInput})
    {
        edit->setReadOnly(true); edit->setAcceptDrops(false);
    }
    detailTabs->addTab(m_ParseLogOutput, QStringLiteral("处理过程"));
    detailTabs->addTab(m_LocalReportOutput, QStringLiteral("基线差异"));
    detailTabs->addTab(m_EvidenceInput, QStringLiteral("AI 分析依据"));
    detailLayout->addWidget(detailTabs);
    details->setMaximumHeight(240);
    details->hide();
    resultLayout->addWidget(details);
    connect(showDetails, &QPushButton::toggled, details, &QWidget::setVisible);
    layout->addWidget(resultPanel, 1);
    connect(browse, &QPushButton::clicked, this, [this]() {
        if(m_PipelineActive) return;
        const QStringList paths = QFileDialog::getOpenFileNames(this, QStringLiteral("选择含板卡名称的原始日志或同一日志的解析 CSV"),
                     QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),
                     QStringLiteral("日志文件 (*.txt *.log *.csv);;所有文件 (*)"));
        if(!paths.isEmpty()) SetInputFiles(paths);
    });
    connect(m_SourceLogEdit, &QLineEdit::textChanged, this, [this](const QString &) {
        if(!m_PipelineActive)
        {
            m_InputCsvPaths.clear();
            const QFileInfo info(m_SourceLogEdit->text().trimmed());
            if(info.isFile() && info.suffix().compare("csv", Qt::CaseInsensitive) == 0)
                m_InputCsvPaths << info.absoluteFilePath();
            m_SourceLogEdit->setToolTip(m_SourceLogEdit->text());
            InvalidateParsedResult(m_InputCsvPaths.isEmpty()
                                   ? QStringLiteral("日志已更新，请点击“日志解析”")
                                   : QStringLiteral("已载入解析 CSV，可直接点击“AI 分析”"));
        }
    });
    connect(m_StartParseButton, &QPushButton::clicked, this, &MainWindow::StartLogParse);
    connect(m_StartAiButton, &QPushButton::clicked, this, &MainWindow::StartAnalysis);
    connect(m_StopButton, &QPushButton::clicked, this, &MainWindow::StopAnalysis);
    return page;
}

QWidget *MainWindow::CreateBaselineTab()
{
    QWidget *page = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 12, 0, 0);
    QSplitter *contentSplitter = new QSplitter(Qt::Horizontal, page);
    contentSplitter->setObjectName(QStringLiteral("contentSplitter"));

    QFrame *samplePanel = CreatePanel(QStringLiteral("submissionPanel"), contentSplitter);
    QVBoxLayout *sampleLayout = new QVBoxLayout(samplePanel);
    sampleLayout->setContentsMargins(18, 16, 18, 18);
    sampleLayout->setSpacing(10);
    sampleLayout->addWidget(CreatePanelTitle(QStringLiteral("正常样本"), samplePanel));
    sampleLayout->addWidget(CreateHint(
                                QStringLiteral("加入同一板卡、已确认正常的解析 CSV，作为基线训练数据。"),
                                samplePanel));
    QHBoxLayout *fileButtonLayout = new QHBoxLayout();
    QPushButton *selectFilesButton = new QPushButton(QStringLiteral("添加解析 CSV"), samplePanel);
    QPushButton *clearFilesButton = new QPushButton(QStringLiteral("清空列表"), samplePanel);
    clearFilesButton->setObjectName(QStringLiteral("dangerButton"));
    fileButtonLayout->addWidget(selectFilesButton);
    fileButtonLayout->addWidget(clearFilesButton);
    fileButtonLayout->addStretch();
    sampleLayout->addLayout(fileButtonLayout);
    m_BaselineFilesList = new QListWidget(samplePanel);
    m_BaselineFilesList->setObjectName(QStringLiteral("baselineFiles"));
    sampleLayout->addWidget(m_BaselineFilesList, 1);

    QFrame *previewPanel = CreatePanel(QStringLiteral("previewPanel"), contentSplitter);
    QVBoxLayout *previewLayout = new QVBoxLayout(previewPanel);
    previewLayout->setContentsMargins(18, 16, 18, 18);
    previewLayout->setSpacing(10);
    previewLayout->addWidget(CreatePanelTitle(QStringLiteral("基线配置与结果"), previewPanel));
    previewLayout->addWidget(CreateHint(
                                 QStringLiteral("设置版本和数据库位置，完成后可直接查看训练统计。"),
                                 previewPanel));

    m_SoftwareVersionEdit = new QLineEdit(previewPanel);
    m_SoftwareVersionEdit->setPlaceholderText(QStringLiteral("未知时可留空，数据库记录为UNKNOWN"));
    m_BaselineDatabaseEdit = new QLineEdit(previewPanel);
    m_BaselineDatabaseEdit->setObjectName(QStringLiteral("baselineDatabase"));

    const QString desktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    m_BaselineDatabaseEdit->setText(
                QDir(desktopPath).filePath(QStringLiteral("LogDiagnosisData/OPB-Baseline.db")));

    QPushButton *selectDatabaseButton = new QPushButton(QStringLiteral("浏览..."), previewPanel);
    m_BuildBaselineButton = new QPushButton(QStringLiteral("建立正常基线"), previewPanel);
    m_BuildBaselineButton->setObjectName(QStringLiteral("baselineBuildButton"));
    m_BuildBaselineButton->setProperty("primaryAction", true);
    m_CancelBaselineButton = new QPushButton(QStringLiteral("取消建立"), previewPanel);
    m_CancelBaselineButton->setObjectName(QStringLiteral("cancelBaselineButton"));
    m_CancelBaselineButton->setEnabled(false);

    QGridLayout *settingsLayout = new QGridLayout();
    settingsLayout->addWidget(new QLabel(QStringLiteral("板卡类型"), previewPanel), 0, 0);
    settingsLayout->addWidget(new QLabel(QStringLiteral("根据正常日志名称自动识别"), previewPanel), 0, 1, 1, 2);
    settingsLayout->addWidget(new QLabel(QStringLiteral("软件版本"), previewPanel), 1, 0);
    settingsLayout->addWidget(m_SoftwareVersionEdit, 1, 1, 1, 2);
    settingsLayout->addWidget(new QLabel(QStringLiteral("基线数据库"), previewPanel), 2, 0);
    settingsLayout->addWidget(m_BaselineDatabaseEdit, 2, 1);
    settingsLayout->addWidget(selectDatabaseButton, 2, 2);
    settingsLayout->addWidget(m_CancelBaselineButton, 3, 1, Qt::AlignRight);
    settingsLayout->addWidget(m_BuildBaselineButton, 3, 2, Qt::AlignRight);
    m_ManagementInputs << selectFilesButton << clearFilesButton << m_BaselineFilesList
                       << m_SoftwareVersionEdit
                       << m_BaselineDatabaseEdit << selectDatabaseButton;

    m_BaselineResultOutput = new QPlainTextEdit(previewPanel);
    m_BaselineResultOutput->setObjectName(QStringLiteral("baselineResult"));
    m_BaselineResultOutput->setReadOnly(true);
    m_BaselineResultOutput->setAcceptDrops(false);
    m_BaselineResultOutput->setPlaceholderText(QStringLiteral("基线统计结果将在这里显示"));
    previewLayout->addLayout(settingsLayout);
    m_BaselineStatus = new QLabel(QStringLiteral("等待建立正常基线"), previewPanel);
    m_BaselineStatus->setObjectName(QStringLiteral("baselineStatus"));
    m_BaselineStatus->setWordWrap(true);
    m_BaselineProgress = new QProgressBar(previewPanel);
    m_BaselineProgress->setObjectName(QStringLiteral("baselineProgress"));
    m_BaselineProgress->setValue(0);
    previewLayout->addWidget(m_BaselineStatus);
    previewLayout->addWidget(m_BaselineProgress);
    previewLayout->addWidget(m_BaselineResultOutput, 1);

    contentSplitter->addWidget(samplePanel);
    contentSplitter->addWidget(previewPanel);
    contentSplitter->setStretchFactor(0, 5);
    contentSplitter->setStretchFactor(1, 5);
    contentSplitter->setSizes(QList<int>() << 520 << 560);
    layout->addWidget(contentSplitter, 1);

    connect(selectFilesButton, &QPushButton::clicked, this, [this]() {
        const QStringList paths = QFileDialog::getOpenFileNames(
                    this, QStringLiteral("选择同一板卡同一包正常日志的分段CSV"),
                    QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),
                    QStringLiteral("CSV文件 (*.csv)"));
        AddBaselineFiles(paths);
    });
    connect(clearFilesButton, &QPushButton::clicked,
            m_BaselineFilesList, &QListWidget::clear);
    connect(selectDatabaseButton, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getSaveFileName(
                    this, QStringLiteral("选择本板卡基线数据库位置"),
                    m_BaselineDatabaseEdit->text(), QStringLiteral("SQLite数据库 (*.db)"));
        if(!path.isEmpty())
        {
            m_BaselineDatabaseEdit->setText(path);
        }
    });
    connect(m_BuildBaselineButton, &QPushButton::clicked, this, &MainWindow::StartBaselineTask);
    connect(m_CancelBaselineButton, &QPushButton::clicked, this, [this]() {
        CancelManagementTask(m_BaselineTask, m_BaselineStatus);
    });

    return page;
}

QWidget *MainWindow::CreateFaultSampleTab()
{
    QWidget *page = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 12, 0, 0);
    QSplitter *contentSplitter = new QSplitter(Qt::Horizontal, page);

    QFrame *filePanel = CreatePanel(QStringLiteral("submissionPanel"), contentSplitter);
    QVBoxLayout *fileLayout = new QVBoxLayout(filePanel);
    fileLayout->setContentsMargins(18, 16, 18, 18);
    fileLayout->setSpacing(10);
    fileLayout->addWidget(CreatePanelTitle(QStringLiteral("宕机日志 CSV 分段"), filePanel));
    fileLayout->addWidget(CreateHint(
                              QStringLiteral("一次可添加多个 CSV，但它们必须由同一份原始宕机日志解析产生。也可直接拖入本页。"),
                              filePanel));
    QHBoxLayout *fileButtonLayout = new QHBoxLayout();
    QPushButton *selectFilesButton = new QPushButton(QStringLiteral("添加解析 CSV"), filePanel);
    QPushButton *clearFilesButton = new QPushButton(QStringLiteral("清空列表"), filePanel);
    clearFilesButton->setObjectName(QStringLiteral("dangerButton"));
    fileButtonLayout->addWidget(selectFilesButton);
    fileButtonLayout->addWidget(clearFilesButton);
    fileButtonLayout->addStretch();
    fileLayout->addLayout(fileButtonLayout);
    m_FaultFilesList = new QListWidget(filePanel);
    m_FaultFilesList->setObjectName(QStringLiteral("faultFiles"));
    fileLayout->addWidget(m_FaultFilesList, 1);

    QFrame *detailPanel = CreatePanel(QStringLiteral("previewPanel"), contentSplitter);
    QVBoxLayout *detailLayout = new QVBoxLayout(detailPanel);
    detailLayout->setContentsMargins(18, 16, 18, 18);
    detailLayout->setSpacing(10);
    detailLayout->addWidget(CreatePanelTitle(QStringLiteral("故障样本信息"), detailPanel));
    detailLayout->addWidget(CreateHint(
                                QStringLiteral("点击添加后，CSV事件会立即导入故障样本数据库；原因标签可以留空。"),
                                detailPanel));

    m_FaultCauseEdit = new QLineEdit(detailPanel);
    m_FaultCauseEdit->setObjectName(QStringLiteral("faultCause"));
    m_FaultCauseEdit->setPlaceholderText(QStringLiteral("可留空，后续确认原因后再补充"));
    m_FaultCauseEdit->setClearButtonEnabled(true);
    m_FaultDatabaseEdit = new QLineEdit(detailPanel);
    m_FaultDatabaseEdit->setObjectName(QStringLiteral("faultDatabase"));
    const QString desktopPath = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    m_FaultDatabaseEdit->setText(
                QDir(desktopPath).filePath(QStringLiteral("LogDiagnosisData/OPB-FaultSamples.db")));
    QPushButton *selectDatabaseButton = new QPushButton(QStringLiteral("浏览..."), detailPanel);
    QWidget *databaseRow = new QWidget(detailPanel);
    databaseRow->setObjectName(QStringLiteral("pathRow"));
    QHBoxLayout *databaseRowLayout = new QHBoxLayout(databaseRow);
    databaseRowLayout->setContentsMargins(0, 0, 0, 0);
    databaseRowLayout->setSpacing(8);
    databaseRowLayout->addWidget(m_FaultDatabaseEdit, 1);
    databaseRowLayout->addWidget(selectDatabaseButton);

    QFormLayout *settingsLayout = new QFormLayout();
    settingsLayout->setVerticalSpacing(12);
    settingsLayout->addRow(QStringLiteral("板卡类型"), new QLabel(QStringLiteral("根据故障日志名称自动识别"), detailPanel));
    settingsLayout->addRow(QStringLiteral("宕机原因标签"), m_FaultCauseEdit);
    settingsLayout->addRow(QStringLiteral("故障样本数据库"), databaseRow);
    detailLayout->addLayout(settingsLayout);

    m_AddFaultSampleButton = new QPushButton(QStringLiteral("添加到故障样本库"), detailPanel);
    m_AddFaultSampleButton->setObjectName(QStringLiteral("faultImportButton"));
    m_AddFaultSampleButton->setProperty("primaryAction", true);
    m_CancelFaultButton = new QPushButton(QStringLiteral("取消入库"), detailPanel);
    m_CancelFaultButton->setObjectName(QStringLiteral("cancelFaultButton"));
    m_CancelFaultButton->setEnabled(false);
    QHBoxLayout *actions = new QHBoxLayout();
    actions->addStretch(); actions->addWidget(m_CancelFaultButton); actions->addWidget(m_AddFaultSampleButton);
    detailLayout->addLayout(actions);
    m_ManagementInputs << selectFilesButton << clearFilesButton << m_FaultFilesList
                       << m_FaultCauseEdit << m_FaultDatabaseEdit << selectDatabaseButton;
    m_FaultStatus = new QLabel(QStringLiteral("等待添加故障样本"), detailPanel);
    m_FaultStatus->setObjectName(QStringLiteral("faultStatus"));
    m_FaultStatus->setWordWrap(true);
    m_FaultProgress = new QProgressBar(detailPanel);
    m_FaultProgress->setObjectName(QStringLiteral("faultProgress"));
    m_FaultProgress->setValue(0);
    detailLayout->addWidget(m_FaultStatus);
    detailLayout->addWidget(m_FaultProgress);
    detailLayout->addWidget(new QLabel(QStringLiteral("入库结果"), detailPanel));
    m_FaultResultOutput = new QPlainTextEdit(detailPanel);
    m_FaultResultOutput->setObjectName(QStringLiteral("faultResult"));
    m_FaultResultOutput->setReadOnly(true);
    m_FaultResultOutput->setAcceptDrops(false);
    m_FaultResultOutput->setPlaceholderText(QStringLiteral("尚未添加宕机样本"));
    detailLayout->addWidget(m_FaultResultOutput, 1);

    contentSplitter->addWidget(filePanel);
    contentSplitter->addWidget(detailPanel);
    contentSplitter->setStretchFactor(0, 5);
    contentSplitter->setStretchFactor(1, 5);
    contentSplitter->setSizes(QList<int>() << 520 << 560);
    layout->addWidget(contentSplitter, 1);

    connect(selectFilesButton, &QPushButton::clicked, this, [this]() {
        const QStringList paths = QFileDialog::getOpenFileNames(
                    this, QStringLiteral("选择同一份宕机日志解析出的CSV分段"),
                    QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),
                    QStringLiteral("CSV文件 (*.csv)"));
        AddFaultFiles(paths);
    });
    connect(clearFilesButton, &QPushButton::clicked,
            m_FaultFilesList, &QListWidget::clear);
    connect(selectDatabaseButton, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getSaveFileName(
                    this, QStringLiteral("选择故障样本数据库位置"),
                    m_FaultDatabaseEdit->text(), QStringLiteral("SQLite数据库 (*.db)"));
        if(!path.isEmpty())
        {
            m_FaultDatabaseEdit->setText(path);
        }
    });
    connect(m_AddFaultSampleButton, &QPushButton::clicked, this, &MainWindow::StartFaultTask);
    connect(m_CancelFaultButton, &QPushButton::clicked, this, [this]() {
        CancelManagementTask(m_FaultTask, m_FaultStatus);
    });

    return page;
}

QWidget *MainWindow::CreateDeepSeekTab()
{
    QWidget *page = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(page);
    layout->addWidget(CreatePanelTitle(QStringLiteral("分析设置"), page));
    layout->addWidget(CreateHint(QStringLiteral("板卡按日志名称自动识别。AI 分析需要 API Key；对应板卡的正常基线用于数值对照，可按需建立。"), page));
    QSettings settings;
    const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    m_DictionaryEdit = new QLineEdit(page);
    m_DictionaryEdit->setObjectName(QStringLiteral("analysisDictionaryPath"));
    m_DictionaryEdit->setText(settings.value(AnalysisSettingKey("analysis/dictionary/OPB"), settings.value(AnalysisSettingKey("analysis/dictionary"),
                    QDir(desktop).filePath(QStringLiteral("OPB/dictionary_PLFM.csv")))).toString());
    m_AnalysisBaselineEdit = new QLineEdit(page);
    m_AnalysisBaselineEdit->setObjectName(QStringLiteral("analysisBaselinePath"));
    QString defaultBaseline = QDir(desktop).filePath(QStringLiteral("LogDiagnosisData/OPB-Baseline.db"));
    // Reuse the verified baseline from the previous desktop build on first upgrade.
    // An explicitly selected user path always takes precedence, even if unavailable.
    const QString previousBaseline = QDir::cleanPath(QDir(QApplication::applicationDirPath()).filePath(
                QStringLiteral("../test-output/OPB-Baseline-OriginalDictionary-3.db")));
    if(!QFileInfo(defaultBaseline).isFile() && QFileInfo(previousBaseline).isFile())
        defaultBaseline = previousBaseline;
    m_AnalysisBaselineEdit->setText(settings.value(AnalysisSettingKey("analysis/baseline/OPB"), settings.value(AnalysisSettingKey("analysis/baseline"), defaultBaseline)).toString());
    m_AnalysisVersionEdit = new QLineEdit(page);
    m_AnalysisVersionEdit->setObjectName(QStringLiteral("analysisSoftwareVersion"));
    m_AnalysisVersionEdit->setText(settings.value(AnalysisSettingKey("analysis/version/OPB"), settings.value(AnalysisSettingKey("analysis/version"))).toString());
    m_AnalysisVersionEdit->setPlaceholderText(QStringLiteral("可留空，未知版本会在依据中注明"));
    m_SourceDatabaseEdit = new QLineEdit(page);
    m_SourceDatabaseEdit->setObjectName(QStringLiteral("analysisSourceDatabasePath"));
    m_SourceDatabaseEdit->setText(settings.value("sourceRelations/database",
        QCoreApplication::applicationDirPath() + "/source_relations/MSCP_MSCP.sqlite").toString());
    m_IncludeApplicationLogCheckBox = new QCheckBox(QStringLiteral("同时解析应用日志"), page);
    m_IncludeApplicationLogCheckBox->setChecked(settings.value("analysis/applicationLogs", false).toBool());

    QFormLayout *form = new QFormLayout();
    const auto pathRow = [this, page](QLineEdit *edit, const QString &title, const QString &filter) {
        QWidget *row = new QWidget(page);
        row->setObjectName(QStringLiteral("pathRow"));
        QHBoxLayout *buttons = new QHBoxLayout(row);
        buttons->setContentsMargins(0, 0, 0, 0);
        QPushButton *browse = new QPushButton(QStringLiteral("浏览…"), row);
        if(edit == m_SourceDatabaseEdit) browse->setObjectName("browseSourceDatabase");
        buttons->addWidget(edit, 1); buttons->addWidget(browse);
        connect(browse, &QPushButton::clicked, this, [this, edit, title, filter]() {
            const QString path = QFileDialog::getOpenFileName(this, title, edit->text(), filter);
            if(!path.isEmpty()) edit->setText(path);
        });
        return row;
    };
    form->addRow(QStringLiteral("原始 PLFM 字典"), pathRow(m_DictionaryEdit, QStringLiteral("选择原始 PLFM 字典"), QStringLiteral("CSV (*.csv)")));
    form->addRow(QStringLiteral("本板卡正常基线"), pathRow(m_AnalysisBaselineEdit, QStringLiteral("选择本板卡正常基线"), QStringLiteral("SQLite (*.db)")));
    form->addRow(QStringLiteral("日志软件版本"), m_AnalysisVersionEdit);
    form->addRow(QStringLiteral("源码关系库"), pathRow(m_SourceDatabaseEdit, QStringLiteral("选择源码关系库"), QStringLiteral("SQLite (*.sqlite *.db)")));
    form->addRow(QString(), CreateHint(QStringLiteral("点击 AI 分析后自动查询此库，相关源码片段和相对路径会随日志证据发送给 DeepSeek。版本未知或不匹配时会注明。"), page));
    form->addRow(QString(), m_IncludeApplicationLogCheckBox);
    QLineEdit *url = new QLineEdit(QStringLiteral("https://api.deepseek.com"), page);
    url->setReadOnly(true);
    m_ModelComboBox = new QComboBox(page);
    m_ModelComboBox->addItems({QStringLiteral("deepseek-flash"), QStringLiteral("deepseek-v4-pro")});
    const int model = m_ModelComboBox->findText(settings.value("deepseek/model", "deepseek-flash").toString());
    if(model >= 0) m_ModelComboBox->setCurrentIndex(model);
    m_ApiKeyEdit = new QLineEdit(page);
    m_ApiKeyEdit->setObjectName(QStringLiteral("apiKeyEdit"));
    m_ApiKeyEdit->setEchoMode(QLineEdit::Password);
    m_ApiKeyEdit->setPlaceholderText(QStringLiteral("填写或修改 DeepSeek API Key"));
    m_RememberApiKeyCheckBox = new QCheckBox(QStringLiteral("保存 API Key，下次自动载入"), page);
    m_RememberApiKeyCheckBox->setObjectName(QStringLiteral("rememberApiKey"));
    m_RememberApiKeyCheckBox->setChecked(true);
    m_ApiKeyStatusLabel = CreateHint(QStringLiteral("尚未保存 API Key"), page);
    m_TestDeepSeekButton = new QPushButton(QStringLiteral("测试连接"), page);
    QPushButton *saveKey = new QPushButton(QStringLiteral("保存 / 更新 Key"), page);
    QPushButton *clearKey = new QPushButton(QStringLiteral("清除已保存 Key"), page);
    form->addRow(QStringLiteral("API 地址"), url);
    form->addRow(QStringLiteral("模型"), m_ModelComboBox);
    form->addRow(QStringLiteral("API Key"), m_ApiKeyEdit);
    form->addRow(QString(), m_RememberApiKeyCheckBox);
    layout->addLayout(form);
    QHBoxLayout *keyButtons = new QHBoxLayout();
    keyButtons->addWidget(m_TestDeepSeekButton); keyButtons->addWidget(saveKey); keyButtons->addWidget(clearKey);
    layout->addLayout(keyButtons);
    layout->addWidget(m_ApiKeyStatusLabel);
    layout->addWidget(CreateHint(QStringLiteral("API Key 保存在当前 Windows 用户的凭据管理器。AI 分析会发送日志诊断结果及关系库检索出的限量源码片段。"), page));
    layout->addStretch();
    LoadSavedApiKey();
    connect(saveKey, &QPushButton::clicked, this, [this]() {
        QString error;
        if(!SaveApiKey(&error)) m_ApiKeyStatusLabel->setText(error);
    });
    connect(clearKey, &QPushButton::clicked, this, &MainWindow::ClearSavedApiKey);
    connect(m_TestDeepSeekButton, &QPushButton::clicked, this, [this]() {
        if(!m_PipelineActive && ApplyDeepSeekConfig()) m_DeepSeekClient->TestConnection();
    });
    return page;
}

void MainWindow::SetManagementBusy(bool busy)
{
    m_ManagementTaskActive = busy;
    m_SourceBranchControls->setEnabled(!busy && !m_PipelineActive);
    for(QWidget *input : m_ManagementInputs) input->setEnabled(!busy);
    m_BuildBaselineButton->setEnabled(!busy && !m_PipelineActive);
    m_AddFaultSampleButton->setEnabled(!busy && !m_PipelineActive);
    m_CancelBaselineButton->setEnabled(busy && m_BaselineTask &&
                                       m_BaselineTask->Snapshot().state == LogTaskControl::Running);
    m_CancelFaultButton->setEnabled(busy && m_FaultTask &&
                                    m_FaultTask->Snapshot().state == LogTaskControl::Running);
    RefreshActionButtons();
    m_SettingsButton->setEnabled(!busy && !m_PipelineActive && !m_CloseAfterTasks);
    m_SettingsDialog->setEnabled(!busy && !m_PipelineActive && !m_CloseAfterTasks);
    if(busy) m_TaskProgressTimer->start();
    else m_TaskProgressTimer->stop();
}

void MainWindow::UpdateManagementProgress()
{
    const auto update = [](const std::shared_ptr<LogTaskControl> &task,
                           QProgressBar *bar, QLabel *status, QPushButton *cancel) {
        if(!task) return;
        const auto snapshot = task->Snapshot();
        bar->setValue(snapshot.percent);
        if(snapshot.state == LogTaskControl::CancelRequested)
            status->setText(QStringLiteral("正在取消，等待本次操作回滚…"));
        else if(snapshot.state == LogTaskControl::Committing)
            status->setText(QStringLiteral("正在完成保存，请稍候…"));
        else status->setText(QStringLiteral("%1% · %2").arg(snapshot.percent).arg(snapshot.message));
        cancel->setEnabled(snapshot.state == LogTaskControl::Running);
    };
    if(m_BaselineWatcher.isRunning()) update(m_BaselineTask, m_BaselineProgress, m_BaselineStatus, m_CancelBaselineButton);
    if(m_FaultWatcher.isRunning()) update(m_FaultTask, m_FaultProgress, m_FaultStatus, m_CancelFaultButton);
}

void MainWindow::CancelManagementTask(const std::shared_ptr<LogTaskControl> &task, QLabel *status)
{
    if(!task || !m_ManagementTaskActive) return;
    if(task->RequestCancel()) status->setText(QStringLiteral("正在取消，等待本次操作回滚…"));
    else status->setText(QStringLiteral("正在完成保存，结果稍后更新…"));
    m_CancelBaselineButton->setEnabled(false);
    m_CancelFaultButton->setEnabled(false);
}

void MainWindow::StartBaselineTask()
{
    if(m_ManagementTaskActive || m_PipelineActive || m_CloseAfterTasks) return;
    QStringList paths;
    for(int index = 0; index < m_BaselineFilesList->count(); ++index)
        paths.append(m_BaselineFilesList->item(index)->text());
    QString databasePath = m_BaselineDatabaseEdit->text().trimmed();
    const QString version = m_SoftwareVersionEdit->text();
    QString boardError;
    const QString board = BoardIdentity::fromFiles(paths, &boardError);
    if(board.isEmpty() || paths.isEmpty() || databasePath.isEmpty())
    {
        m_BaselineStatus->setText(boardError.isEmpty() ? QStringLiteral("请选择同一板卡正常日志 CSV 和基线数据库位置") : boardError);
        return;
    }
    if(board != "OPB" && QFileInfo(databasePath).fileName() == "OPB-Baseline.db") {
        databasePath = QFileInfo(databasePath).absolutePath() + '/' + board + "-Baseline.db";
        m_BaselineDatabaseEdit->setText(databasePath);
    }
    m_ManagementBoard = board;
    m_BaselineTask = std::make_shared<LogTaskControl>();
    m_FaultTask.reset();
    m_BaselineProgress->setValue(0);
    m_BaselineResultOutput->clear();
    m_BaselineStatus->setText(QStringLiteral("正在后台建立基线…"));
    SetManagementBusy(true);
    SetWorkspaceStatus(QStringLiteral("正常基线建立中"), true);
    const auto control = m_BaselineTask;
    m_BaselineWatcher.setFuture(QtConcurrent::run([paths, databasePath, version, control, board]() {
        try { return OpbBaselineAnalyzer().BuildBaseline(paths, databasePath, version, control, board); }
        catch(...)
        {
            control->Finish();
            OpbBaselineAnalyzer::BuildResult result;
            result.errorMessage = QStringLiteral("后台建立基线发生异常，请检查输入和磁盘空间后重试");
            return result;
        }
    }));
}

void MainWindow::StartFaultTask()
{
    if(m_ManagementTaskActive || m_PipelineActive || m_CloseAfterTasks) return;
    QStringList paths;
    for(int index = 0; index < m_FaultFilesList->count(); ++index)
        paths.append(m_FaultFilesList->item(index)->text());
    const QString databasePath = m_FaultDatabaseEdit->text().trimmed();
    QString boardError;
    const QString board = BoardIdentity::fromFiles(paths, &boardError);
    const QString cause = m_FaultCauseEdit->text().trimmed();
    if(board.isEmpty() || paths.isEmpty() || databasePath.isEmpty())
    {
        m_FaultStatus->setText(boardError.isEmpty() ? QStringLiteral("请选择同一板卡宕机日志 CSV 和故障数据库位置") : boardError);
        return;
    }
    m_FaultTask = std::make_shared<LogTaskControl>();
    m_ManagementBoard = board;
    m_BaselineTask.reset();
    m_FaultCauseSnapshot = cause;
    m_FaultProgress->setValue(0);
    m_FaultResultOutput->clear();
    m_FaultStatus->setText(QStringLiteral("正在后台导入故障样本…"));
    SetManagementBusy(true);
    SetWorkspaceStatus(QStringLiteral("故障样本入库中"), true);
    const auto control = m_FaultTask;
    m_FaultWatcher.setFuture(QtConcurrent::run([paths, databasePath, board, cause, control]() {
        try { return OpbFaultSampleStore().ImportIncident(paths, databasePath, board, cause, control); }
        catch(...)
        {
            control->Finish();
            OpbFaultSampleStore::ImportResult result;
            result.errorMessage = QStringLiteral("后台故障入库发生异常，请检查输入和磁盘空间后重试");
            return result;
        }
    }));
}

void MainWindow::FinishBaselineTask()
{
    if(m_Closing && !m_CloseAfterTasks) return;
    const auto result = m_BaselineWatcher.result();
    SetManagementBusy(false);
    if(!result.success)
    {
        m_BaselineStatus->setText(result.cancelled ? QStringLiteral("已取消，原有基线保持不变")
                                                  : QStringLiteral("基线建立失败"));
        m_BaselineResultOutput->setPlainText(result.errorMessage);
        if(m_BaselineTask) m_BaselineProgress->setValue(m_BaselineTask->Snapshot().percent);
        SetWorkspaceStatus(m_BaselineStatus->text());
    }
    else
    {
        m_BaselineStatus->setText(QStringLiteral("100% · 正常基线建立完成"));
        m_BaselineProgress->setValue(100);
        QSettings().setValue(AnalysisSettingKey("analysis/baseline/" + m_ManagementBoard), result.databasePath);
        if(m_ManagementBoard == m_DetectedBoard || (m_DetectedBoard.isEmpty() && m_ManagementBoard == "OPB"))
            m_AnalysisBaselineEdit->setText(result.databasePath);
        SaveSettings();
        RefreshConfigSummary();
        SetWorkspaceStatus(QStringLiteral("正常基线已更新"));
        m_BaselineResultOutput->setPlainText(QStringLiteral(
                    "板卡：%1\n"
                    "正常基线建立完成\n"
                    "数据库：%2\n"
                    "训练周期：%3 - %4\n"
                    "训练周期数：%5\n"
                    "训练事件数：%6\n"
                    "稳定阶段编码数：%7\n"
                    "UNKNOWN编码数：%8\n"
                    "UNKNOWN事件数：%9")
                    .arg(m_ManagementBoard)
                    .arg(result.databasePath)
                    .arg(result.baselineCycleStart)
                    .arg(result.baselineCycleEnd)
                    .arg(result.baselineCycleCount)
                    .arg(result.baselineEventCount)
                    .arg(result.eventCodeCount)
                    .arg(result.pendingDescriptionCodeCount)
                    .arg(result.unknownDescriptionEventCount));
    }
    if(m_CloseAfterTasks) QTimer::singleShot(0, this, &QWidget::close);
}

void MainWindow::FinishFaultTask()
{
    if(m_Closing && !m_CloseAfterTasks) return;
    const auto result = m_FaultWatcher.result();
    SetManagementBusy(false);
    if(!result.success)
    {
        m_FaultStatus->setText(result.cancelled ? QStringLiteral("已取消，本次样本未保存")
                                               : QStringLiteral("故障样本入库失败"));
        m_FaultResultOutput->setPlainText(result.errorMessage);
        if(m_FaultTask) m_FaultProgress->setValue(m_FaultTask->Snapshot().percent);
        SetWorkspaceStatus(m_FaultStatus->text());
    }
    else if(result.duplicate)
    {
        m_FaultStatus->setText(QStringLiteral("样本已存在，未重复导入"));
        m_FaultProgress->setValue(100);
        m_FaultResultOutput->setPlainText(QStringLiteral(
            "所选 CSV 已存在，未重复导入。\n事件编号：%1\n数据库：%2")
            .arg(result.incidentId).arg(result.databasePath));
        SetWorkspaceStatus(QStringLiteral("故障样本已存在"));
    }
    else
    {
        m_FaultStatus->setText(QStringLiteral("100% · 故障样本入库完成"));
        m_FaultProgress->setValue(100);
        SetWorkspaceStatus(QStringLiteral("故障样本已入库"));
        m_FaultResultOutput->setPlainText(QStringLiteral(
                    "宕机样本添加完成\n"
                    "事件编号：%1\n"
                    "板卡：%2\n"
                    "原因标签：%3\n"
                    "数据库：%4\n"
                    "CSV分段数：%5\n"
                    "周期范围：%6%7\n"
                    "周期数：%8\n"
                    "事件数：%9\n"
                    "UNKNOWN事件数：%10")
                    .arg(result.incidentId)
                    .arg(m_ManagementBoard)
                    .arg(m_FaultCauseSnapshot.isEmpty()
                         ? QStringLiteral("未填写") : m_FaultCauseSnapshot)
                    .arg(result.databasePath)
                    .arg(result.sourceFileCount)
                    .arg(result.cycleCount == 0 ? QStringLiteral("无周期号（未出现 0x0A1A，按事件顺序保存）") : QString::number(result.cycleStart))
                    .arg(result.cycleCount == 0 ? QString() : QStringLiteral(" - %1（来源 0x0A1A）").arg(result.cycleEnd))
                    .arg(QString::number(result.cycleCount))
                    .arg(result.eventCount)
                    .arg(result.unknownDescriptionEventCount));
    }
    if(m_CloseAfterTasks) QTimer::singleShot(0, this, &QWidget::close);
}

void MainWindow::AddBaselineFiles(const QStringList &paths)
{
    if(m_ManagementTaskActive) return;
    for(int pathIndex = 0; pathIndex < paths.size(); ++pathIndex)
    {
        const QString absolutePath = QFileInfo(paths.at(pathIndex)).absoluteFilePath();
        if(m_BaselineFilesList->findItems(absolutePath, Qt::MatchExactly).isEmpty())
        {
            m_BaselineFilesList->addItem(absolutePath);
        }
    }
}

void MainWindow::AddFaultFiles(const QStringList &paths)
{
    if(m_ManagementTaskActive) return;
    for(int pathIndex = 0; pathIndex < paths.size(); ++pathIndex)
    {
        const QFileInfo fileInfo(paths.at(pathIndex));
        if(!fileInfo.isFile() ||
           fileInfo.suffix().compare(QStringLiteral("csv"), Qt::CaseInsensitive) != 0)
        {
            continue;
        }
        const QString absolutePath = fileInfo.absoluteFilePath();
        if(m_FaultFilesList->findItems(absolutePath, Qt::MatchExactly).isEmpty())
        {
            m_FaultFilesList->addItem(absolutePath);
        }
    }
}

bool MainWindow::ApplyDeepSeekConfig()
{
    if(m_ApiKeyEdit->text().trimmed().isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("DeepSeek"),
                             QStringLiteral("请填写DeepSeek API Key"));
        return false;
    }

    if(m_RememberApiKeyCheckBox->isChecked())
    {
        QString errorMessage;
        if(!SaveApiKey(&errorMessage))
        {
            QMessageBox::critical(this, QStringLiteral("保存 API Key 失败"), errorMessage);
            return false;
        }
    }

    m_DeepSeekClient->SetConfig(m_ApiKeyEdit->text(),
                                m_ModelComboBox->currentText(),
                                QStringLiteral("https://api.deepseek.com"));
    return true;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    const QList<QUrl> urls = event->mimeData()->urls();
    if(m_PipelineActive) { event->ignore(); return; }
    for(int index = 0; index < urls.size(); ++index)
    {
        const QString path = urls.at(index).toLocalFile();
        if(!path.isEmpty() && QFileInfo(path).isFile())
        {
            event->acceptProposedAction();
            return;
        }
    }
    event->ignore();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    if(m_PipelineActive) { event->ignore(); return; }
    const QList<QUrl> urls = event->mimeData()->urls();
    QStringList files;
    for(const QUrl &url : urls)
    {
        if(!url.isLocalFile()) { event->ignore(); return; }
        files << url.toLocalFile();
    }
    if(!SetInputFiles(files)) { event->ignore(); return; }
    event->acceptProposedAction();
}

bool MainWindow::SetInputFiles(const QStringList &paths)
{
    if(m_PipelineActive || paths.isEmpty()) return false;
    QStringList files;
    bool allCsv = true;
    for(const QString &path : paths)
    {
        const QFileInfo info(path);
        if(!info.isFile())
        {
            m_StageLabel->setText(QStringLiteral("请选择存在的日志文件或解析 CSV"));
            return false;
        }
        allCsv = allCsv && info.suffix().compare("csv", Qt::CaseInsensitive) == 0;
        if(!files.contains(info.absoluteFilePath())) files << info.absoluteFilePath();
    }
    if(!allCsv && files.size() != 1)
    {
        m_StageLabel->setText(QStringLiteral("请导入一份原始日志，或同一日志的多个 CSV；不能混合导入。"));
        return false;
    }
    if(!DetectAnalysisBoard(files)) {
        const QString reason = m_StageLabel->text();
        m_InputCsvPaths.clear(); m_ParsedCsvPaths.clear(); m_ParsedInputSignature.clear();
        m_SourceLogEdit->clear();
        m_AutoBoardLabel->setText(QStringLiteral("板卡未确认"));
        m_StageLabel->setText(reason);
        RefreshActionButtons();
        return false;
    }
    const QSignalBlocker blocker(m_SourceLogEdit);
    m_InputCsvPaths = allCsv ? files : QStringList();
    m_SourceLogEdit->setText(files.join(QStringLiteral(" ; ")));
    m_SourceLogEdit->setToolTip(files.join('\n'));
    const QString message = allCsv
            ? QStringLiteral("已载入 %1 个解析 CSV，可直接点击“AI 分析”").arg(files.size())
            : QStringLiteral("原始日志已载入，请点击“日志解析”");
    InvalidateParsedResult(message);
    SetWorkspaceStatus(allCsv ? QStringLiteral("CSV 已载入 · 等待 AI 分析")
                              : QStringLiteral("等待日志解析"));
    return true;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    m_Closing = true;
    m_StopRequested = true;
    if(m_DiagnosticCancelled) m_DiagnosticCancelled->store(true);
    m_DeepSeekClient->Cancel();
    if(m_ManagementTaskActive)
    {
        m_CloseAfterTasks = true;
        if(m_BaselineTask) m_BaselineTask->RequestCancel();
        if(m_FaultTask) m_FaultTask->RequestCancel();
        centralWidget()->setEnabled(false);
        m_ManagementDialog->setEnabled(false);
        m_SettingsDialog->setEnabled(false);
        SetWorkspaceStatus(QStringLiteral("正在结束后台任务后关闭"), true);
        event->ignore();
        return;
    }
    QMainWindow::closeEvent(event);
}

QString MainWindow::AnalysisSettingKey(const QString &key) const
{
    return m_SourceBranch.isEmpty() ? key : "sourceBranches/" + m_SourceBranch + '/' + key;
}

QString MainWindow::CurrentBranchDirectory() const
{
    return m_SourceBranch.isEmpty() ? QString() : QDir(m_BranchesRoot).filePath(m_SourceBranch);
}

void MainWindow::RefreshSourceBranches()
{
    if(m_PipelineActive || m_ManagementTaskActive) return;
    auto *queryWidget = findChild<QWidget *>("sourceQueryWidget");
    if(queryWidget && queryWidget->property("building").toBool()) return;
    const QString selected = m_SourceBranch.isEmpty()
        ? QSettings().value("sourceBranches/current").toString() : m_SourceBranch;
    {
        QSignalBlocker blocker(m_SourceBranchCombo);
        m_SourceBranchCombo->clear();
        const QDir root(m_BranchesRoot);
        for(const auto &directory : root.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name)) {
            if(directory.isSymLink()) continue;
            if(QFileInfo(directory.filePath() + "/source").isDir() &&
               QFileInfo(directory.filePath() + "/board_profiles.json").isFile())
                m_SourceBranchCombo->addItem(directory.fileName(), directory.fileName());
        }
        if(m_SourceBranchCombo->count() == 0)
            m_SourceBranchCombo->addItem(QStringLiteral("尚未添加源码分支"), QString());
        const int previous = m_SourceBranchCombo->findData(selected);
        if(previous >= 0) m_SourceBranchCombo->setCurrentIndex(previous);
    }
    SelectSourceBranch();
}

void MainWindow::LoadBranchBoardSettings()
{
    if(m_SourceBranch.isEmpty()) return;
    QSettings settings;
    const QString board = m_DetectedBoard.isEmpty() ? "OPB" : m_DetectedBoard;
    const QString directory = CurrentBranchDirectory();
    const QString dataDirectory = directory + "/data";
    QDir().mkpath(dataDirectory);
    const QString dictionary = directory + "/board_config/" + board + "/dictionary_PLFM.csv";
    const QString baselineKey = "analysis/baseline/" + board;
    const QString versionKey = "analysis/version/" + board;
    // Import the original branch's saved baseline once through the scoped fallback.
    const QString legacyBaseline = m_SourceBranch == "MSCP_MSCP"
        ? settings.value(baselineKey, board == "OPB" ? settings.value("analysis/baseline") : QVariant()).toString() : QString();
    const QString legacyVersion = m_SourceBranch == "MSCP_MSCP"
        ? settings.value(versionKey, board == "OPB" ? settings.value("analysis/version") : QVariant()).toString() : QString();
    m_AnalysisBaselineEdit->setText(settings.value(AnalysisSettingKey(baselineKey), legacyBaseline).toString());
    m_AnalysisVersionEdit->setText(settings.value(AnalysisSettingKey(versionKey), legacyVersion).toString());
    m_DictionaryEdit->setText(settings.value(AnalysisSettingKey("analysis/dictionary/" + board), dictionary).toString());
    m_SourceDatabaseEdit->setText(directory + "/relations/source." + board + ".sqlite");
    m_BaselineDatabaseEdit->setText(m_AnalysisBaselineEdit->text().isEmpty()
        ? dataDirectory + '/' + board + "-Baseline.db" : m_AnalysisBaselineEdit->text());
    m_FaultDatabaseEdit->setText(dataDirectory + '/' + board + "-FaultSamples.db");
}

void MainWindow::SelectSourceBranch()
{
    const QString selected = m_SourceBranchCombo->currentData().toString();
    if(selected == m_SourceBranch) return;
    auto *queryWidget = findChild<QWidget *>("sourceQueryWidget");
    if(m_PipelineActive || m_ManagementTaskActive || (queryWidget && queryWidget->property("building").toBool())) {
        QSignalBlocker blocker(m_SourceBranchCombo);
        m_SourceBranchCombo->setCurrentIndex(m_SourceBranchCombo->findData(m_SourceBranch));
        m_StageLabel->setText(QStringLiteral("请等待当前任务结束后切换源码分支"));
        return;
    }
    SaveSettings();
    auto *dialog = findChild<QDialog *>("sourceRelationsDialog");
    if(dialog) delete dialog;
    m_SourceBranch = selected;
    QSettings().setValue("sourceBranches/current", selected);
    m_SourceDatabaseEdit->setReadOnly(!selected.isEmpty());
    auto *browse = findChild<QPushButton *>("browseSourceDatabase");
    if(browse) browse->setEnabled(selected.isEmpty());
    if(selected.isEmpty()) {
        m_SourceDatabaseEdit->setText(QSettings().value("sourceRelations/database").toString());
        m_AnalysisBaselineEdit->clear();
        m_AnalysisVersionEdit->clear();
        m_DictionaryEdit->clear();
    } else LoadBranchBoardSettings();
    m_BaselineFilesList->clear();
    m_FaultFilesList->clear();
    m_BaselineResultOutput->clear();
    m_FaultResultOutput->clear();
    m_AiResultOutput->clear();
    m_LocalReportOutput->clear();
    m_EvidenceInput->clear();
    if(m_InputCsvPaths.isEmpty()) InvalidateParsedResult(QStringLiteral("源码分支已切换，请使用对应字典重新解析原始日志"));
    else m_StageLabel->setText(QStringLiteral("源码分支已切换为 %1，可使用当前 CSV 重新分析").arg(selected));
    RefreshConfigSummary();
    RefreshActionButtons();
}

void MainWindow::ConfigureSourceQueryWidget(QWidget *widget)
{
    if(!widget || m_SourceBranch.isEmpty()) return;
    const QString directory = CurrentBranchDirectory();
    widget->setProperty("sourceRoot", directory + "/source");
    widget->setProperty("profilesPath", directory + "/board_profiles.json");
    widget->setProperty("sourceBranch", m_SourceBranch);
    widget->setProperty("expectedBoard", m_DetectedBoard.isEmpty() ? "OPB" : m_DetectedBoard);
    auto *path = widget->findChild<QLineEdit *>("sourceDatabasePath");
    if(path) { path->setText(m_SourceDatabaseEdit->text()); path->setReadOnly(true); }
    auto *browse = widget->findChild<QPushButton *>("browseSourceDatabase");
    if(browse) browse->setEnabled(false);
}

void MainWindow::CreateSourceBranch()
{
    if(m_PipelineActive || m_ManagementTaskActive) return;
    auto *queryWidget = findChild<QWidget *>("sourceQueryWidget");
    if(queryWidget && queryWidget->property("building").toBool()) return;
    bool accepted = false;
    const QString name = QInputDialog::getText(this, QStringLiteral("新建源码分支"),
        QStringLiteral("输入分支名称"), QLineEdit::Normal, QString(), &accepted).trimmed();
    if(!accepted || name.isEmpty()) return;
    if(name == "." || name == ".." || name.contains(QRegularExpression("[<>:\"/\\\\|?*]")) || name.endsWith('.') || name.endsWith(' ')) {
        m_StageLabel->setText(QStringLiteral("分支名称包含无效的文件夹字符"));
        return;
    }
    const QString destination = QDir(m_BranchesRoot).filePath(name);
    if(QFileInfo::exists(destination)) {
        m_StageLabel->setText(QStringLiteral("同名分支目录已存在，请点击“刷新分支”"));
        return;
    }
    QFile manifest(QCoreApplication::applicationDirPath() + "/source_relations/board_profiles.json");
    if(!manifest.open(QIODevice::ReadOnly)) { m_StageLabel->setText(QStringLiteral("无法读取板卡配置模板")); return; }
    QJsonObject profiles = QJsonDocument::fromJson(manifest.readAll()).object();
    if(profiles.size() != BoardIdentity::boards().size()) { m_StageLabel->setText(QStringLiteral("板卡配置模板无效")); return; }
    if(!QDir().mkpath(m_BranchesRoot)) { m_StageLabel->setText(QStringLiteral("无法创建分支存储目录")); return; }
    QTemporaryDir pending(QDir(m_BranchesRoot).filePath(".creating-XXXXXX"));
    if(!pending.isValid()) { m_StageLabel->setText(QStringLiteral("无法创建分支临时目录")); return; }
    const QString directory = pending.path();
    if(!QDir().mkpath(directory + "/source") || !QDir().mkpath(directory + "/relations") || !QDir().mkpath(directory + "/data")) {
        m_StageLabel->setText(QStringLiteral("无法创建分支目录")); return;
    }
    for(const QString &board : BoardIdentity::boards()) {
        const QString target = directory + "/board_config/" + board;
        QString original = QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../board_config/" + board + "/PROJECT_OR_BOARD_PTCL.h");
        if(!QFileInfo::exists(original)) original = QCoreApplication::applicationDirPath() + "/source_relations/config/" + board + "/PROJECT_OR_BOARD_PTCL.h";
        if(!QDir().mkpath(target) || !QFile::copy(original, target + "/PROJECT_OR_BOARD_PTCL.h")) {
            m_StageLabel->setText(QStringLiteral("无法为 %1 复制板卡配置，请检查分支目录").arg(board)); return;
        }
        QJsonObject profile = profiles[board].toObject();
        profile.insert("configuration_header", "board_config/" + board + "/PROJECT_OR_BOARD_PTCL.h");
        profile.remove("fallback_header");
        profile.remove("ignore_includes");
        profiles.insert(board, profile);
    }
    QSaveFile output(directory + "/board_profiles.json");
    const QByteArray contents = QJsonDocument(profiles).toJson(QJsonDocument::Indented);
    if(!output.open(QIODevice::WriteOnly) || output.write(contents) != contents.size() || !output.commit()) {
        m_StageLabel->setText(QStringLiteral("无法保存分支配置清单")); return;
    }
    if(!QDir().rename(directory, destination)) { m_StageLabel->setText(QStringLiteral("无法保存新分支目录")); return; }
    pending.setAutoRemove(false);
    RefreshSourceBranches();
    m_SourceBranchCombo->setCurrentIndex(m_SourceBranchCombo->findData(name));
    QDesktopServices::openUrl(QUrl::fromLocalFile(destination));
    m_StageLabel->setText(QStringLiteral("分支已创建。请将完整源码放入 source，核对 board_config，并在“源码关系查询”中重建关系库"));
}

void MainWindow::SaveSettings()
{
    QSettings settings;
    if(m_DetectedBoard.isEmpty() || m_DetectedBoard == "OPB") {
        settings.setValue(AnalysisSettingKey("analysis/dictionary"), m_DictionaryEdit->text().trimmed());
        settings.setValue(AnalysisSettingKey("analysis/baseline"), m_AnalysisBaselineEdit->text().trimmed());
        settings.setValue(AnalysisSettingKey("analysis/version"), m_AnalysisVersionEdit->text().trimmed());
    }
    const QString board = m_DetectedBoard.isEmpty() ? "OPB" : m_DetectedBoard;
    if(!m_SourceBranch.isEmpty() || !m_DetectedBoard.isEmpty()) {
        settings.setValue(AnalysisSettingKey("analysis/dictionary/" + board), m_DictionaryEdit->text().trimmed());
        settings.setValue(AnalysisSettingKey("analysis/baseline/" + board), m_AnalysisBaselineEdit->text().trimmed());
        settings.setValue(AnalysisSettingKey("analysis/version/" + board), m_AnalysisVersionEdit->text().trimmed());
    }
    if(m_SourceBranch.isEmpty()) settings.setValue("sourceRelations/database", m_SourceDatabaseEdit->text().trimmed());
    settings.setValue("analysis/applicationLogs", m_IncludeApplicationLogCheckBox->isChecked());
    settings.setValue("deepseek/model", m_ModelComboBox->currentText());
    if(m_RememberApiKeyCheckBox->isChecked() && !m_ApiKeyEdit->text().trimmed().isEmpty())
    {
        QString error;
        if(!SaveApiKey(&error)) m_ApiKeyStatusLabel->setText(error);
    }
}

void MainWindow::RefreshConfigSummary()
{
    const QFileInfo baseline(m_AnalysisBaselineEdit->text().trimmed());
    m_ConfigSummary->setText(QStringLiteral("正常基线：%1  ·  模型：%2  ·  API Key：%3")
                            .arg(baseline.isFile() ? baseline.fileName() : QStringLiteral("未配置，使用日志和源码"),
                                 m_ModelComboBox->currentText(),
                                 m_ApiKeyEdit->text().trimmed().isEmpty() ? QStringLiteral("未配置") : QStringLiteral("已配置")));
}

void MainWindow::SetPipelineBusy(bool busy)
{
    m_PipelineActive = busy;
    m_SourceBranchControls->setEnabled(!busy && !m_ManagementTaskActive);
    RefreshActionButtons();
    m_StopButton->setEnabled(busy);
    m_SourceLogEdit->setEnabled(!busy);
    m_SettingsButton->setEnabled(!busy);
    m_ManagementButton->setEnabled(!busy);
    m_SettingsDialog->setEnabled(!busy);
    auto *sourceButton = findChild<QPushButton *>(QStringLiteral("sourceRelationsButton"));
    if(sourceButton) sourceButton->setEnabled(!busy);
    auto *sourceDialog = findChild<QDialog *>(QStringLiteral("sourceRelationsDialog"));
    if(sourceDialog) sourceDialog->setEnabled(!busy);
    m_ManagementDialog->setEnabled(!busy);
    m_TestDeepSeekButton->setEnabled(!busy && !m_DeepSeekClient->IsBusy());
    auto *browse = findChild<QPushButton *>(QStringLiteral("browseSourceLog"));
    if(browse) browse->setEnabled(!busy);
}

QString MainWindow::CurrentParseSignature() const
{
    const auto fileIdentity = [](const QString &path) {
        const QFileInfo info(path.trimmed());
        return QJsonObject{{"path", info.absoluteFilePath()}, {"exists", info.isFile()},
                           {"size", QString::number(info.size())},
                           {"modified_ms", QString::number(info.lastModified().toMSecsSinceEpoch())}};
    };
    const QJsonObject identity{{"source", fileIdentity(m_SourceLogEdit->text())},
                               {"dictionary", fileIdentity(m_DictionaryEdit->text())},
                               {"board", CurrentBoardId()},
                               {"application_logs", m_IncludeApplicationLogCheckBox->isChecked()}};
    return QString::fromLatin1(QCryptographicHash::hash(
                  QJsonDocument(identity).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
}

bool MainWindow::HasCurrentParsedFiles() const
{
    if(!m_InputCsvPaths.isEmpty())
    {
        for(const QString &path : m_InputCsvPaths)
            if(!QFileInfo(path).isFile()) return false;
        return true;
    }
    if(m_ParsedCsvPaths.isEmpty() || m_ParsedInputSignature != CurrentParseSignature()) return false;
    for(const QString &path : m_ParsedCsvPaths)
        if(!QFileInfo(path).isFile()) return false;
    return true;
}

void MainWindow::RefreshActionButtons()
{
    const bool available = !m_PipelineActive && !m_ManagementTaskActive && !m_CloseAfterTasks &&
                           !m_Closing && !m_DeepSeekClient->IsBusy();
    m_StartParseButton->setEnabled(available && !m_Parser->IsBusy() && m_InputCsvPaths.isEmpty());
    m_StartAiButton->setEnabled(available && HasCurrentParsedFiles());
    m_StopButton->setEnabled(m_PipelineActive && !m_StopRequested && !m_Closing);
    auto *sourceButton = findChild<QPushButton *>(QStringLiteral("sourceRelationsButton"));
    if(sourceButton) sourceButton->setEnabled(available && (!m_SourceBranch.isEmpty() || (!m_DetectedBoard.isEmpty() && !m_SourceLogEdit->text().isEmpty())));
}

void MainWindow::InvalidateParsedResult(const QString &message)
{
    m_ParsedCsvPaths.clear();
    m_ParsedInputSignature.clear();
    m_AiResultOutput->clear(); m_LocalReportOutput->clear(); m_EvidenceInput->clear();
    m_ParseLogOutput->clear();
    m_AllProgressBar->setRange(0, 100); m_AllProgressBar->setValue(0);
    m_SingleProgressBar->setValue(0);
    m_StageLabel->setText(message);
    RefreshActionButtons();
}

void MainWindow::StartLogParse()
{
    if(m_PipelineActive || m_ManagementTaskActive || m_CloseAfterTasks || m_DeepSeekClient->IsBusy()) return;
    if(!m_InputCsvPaths.isEmpty()) return;
    m_StopRequested = false;
    InvalidateParsedResult(QStringLiteral("准备解析日志"));
    m_Action = Action::Parse;
    const QFileInfo source(m_SourceLogEdit->text().trimmed());
    if(!source.isFile() || source.suffix().compare("csv", Qt::CaseInsensitive) == 0)
    { FinishAnalysis(QStringLiteral("请先拖入或浏览选择原始暗文日志")); return; }
    if(!DetectAnalysisBoard({source.absoluteFilePath()})) { m_Action = Action::None; return; }
    if(!QFileInfo(m_DictionaryEdit->text().trimmed()).isFile())
    {
        FinishAnalysis(QStringLiteral("请在设置中选择原始 PLFM 字典"));
        m_SettingsDialog->show();
        return;
    }
    SaveSettings();
    m_ParseAttemptSignature = CurrentParseSignature();
    RefreshConfigSummary();
    SetPipelineBusy(true);
    m_StageLabel->setText(QStringLiteral("正在解析日志…"));
    SetWorkspaceStatus(QStringLiteral("日志解析中"), true);
    m_Parser->StartOpbParse(source.absoluteFilePath(), m_DictionaryEdit->text().trimmed(),
                           m_IncludeApplicationLogCheckBox->isChecked(), true);
}

void MainWindow::StartAnalysis()
{
    if(m_PipelineActive || m_ManagementTaskActive || m_CloseAfterTasks || m_DeepSeekClient->IsBusy()) return;
    m_StopRequested = false;
    if(!HasCurrentParsedFiles())
    {
        InvalidateParsedResult(m_InputCsvPaths.isEmpty()
                               ? QStringLiteral("请先完成日志解析；文件或字典变更后需要重新解析")
                               : QStringLiteral("解析 CSV 已不存在，请重新导入文件"));
        return;
    }
    m_Action = Action::Ai;
    const QStringList inputPaths = m_InputCsvPaths.isEmpty() ? m_ParsedCsvPaths : m_InputCsvPaths;
    if(!DetectAnalysisBoard(inputPaths)) { m_Action = Action::None; return; }
    if(!m_SourceBranch.isEmpty() && !QFileInfo(BoardIdentity::sourceDatabase(m_SourceDatabaseEdit->text(), CurrentBoardId())).isFile()) {
        FinishAnalysis(QStringLiteral("当前分支尚无 %1 关系库，请打开“源码关系查询”并点击“重建关系库”").arg(CurrentBoardId()));
        return;
    }
    if(m_ApiKeyEdit->text().trimmed().isEmpty())
    {
        FinishAnalysis(QStringLiteral("请在设置中填写 API Key；已解析的 CSV 会保留"));
        m_SettingsDialog->show();
        return;
    }
    if(!ApplyDeepSeekConfig()) { m_Action = Action::None; return; }
    SaveSettings();
    RefreshConfigSummary();
    m_AiResultOutput->clear(); m_LocalReportOutput->clear(); m_EvidenceInput->clear();
    m_AllProgressBar->setRange(0, 100); m_AllProgressBar->setValue(0);
    m_DiagnosticInput = OpbDiagnosticAnalyzer::Input();
    m_DiagnosticInput.baselinePath = m_AnalysisBaselineEdit->text().trimmed();
    m_DiagnosticInput.softwareVersion = m_AnalysisVersionEdit->text().trimmed();
    m_DiagnosticInput.boardType = CurrentBoardId();
    m_DiagnosticInput.allowMissingBaseline = true;
    SetPipelineBusy(true);
    CompareWithBaseline(m_InputCsvPaths.isEmpty() ? m_ParsedCsvPaths : m_InputCsvPaths);
}

void MainWindow::CompareWithBaseline(const QStringList &outputs)
{
    m_DiagnosticCancelled = std::make_shared<std::atomic_bool>(false);
    m_DiagnosticInput.cancelled = m_DiagnosticCancelled;
    m_DiagnosticInput.csvPaths = outputs;
    m_StageLabel->setText(QStringLiteral("1 / 2  正在比较日志并关联源码关系库…"));
    m_AllProgressBar->setRange(0, 100); m_AllProgressBar->setValue(45);
    SetWorkspaceStatus(QStringLiteral("基线比较中"), true);
    const auto input = m_DiagnosticInput;
    const QString sourceDatabase = m_SourceDatabaseEdit->text().trimmed();
    const QString sourceBranch = m_SourceBranch;
    const QString sourceRoot = CurrentBranchDirectory() + "/source";
    const QString board = CurrentBoardId();
    SourceQueryInterface *plugin = LoadSourceQueryPlugin(nullptr);
    m_DiagnosticWatcher.setFuture(QtConcurrent::run([input, sourceDatabase, sourceBranch, sourceRoot, board, plugin]() {
        auto result = OpbDiagnosticAnalyzer().Analyze(input);
        if(!result.success || (input.cancelled && input.cancelled->load())) return result;
        result.evidence = RelevantAiEvidence(result.evidence);
        if(!sourceBranch.isEmpty())
            result.evidence.insert("source_branch", QJsonObject{{"name", sourceBranch}, {"source_root", sourceRoot}});
        QJsonObject sourceEvidence;
        if(plugin) sourceEvidence = plugin->collectEvidence(sourceDatabase, result.evidence, input.softwareVersion, board, input.cancelled);
        else sourceEvidence = QJsonObject{{"schema_version", "source-evidence/1"}, {"status", "unavailable"},
                                         {"records", QJsonArray()}, {"message", QStringLiteral("源码查询插件不可用，当前分析缺少源码证据")}};
        result.evidence.insert("source_evidence", sourceEvidence);
        if(sourceEvidence["status"].toString() == "branch_mismatch") {
            result.success = false;
            result.errorMessage = sourceEvidence["message"].toString();
            return result;
        }
        if(!sourceEvidence.value("records").toArray().isEmpty())
            result.evidence.insert("export_policy", "parsed_logs_and_bounded_source_snippets_with_relative_paths");
        return result;
    }));
}

SourceQueryInterface *MainWindow::LoadSourceQueryPlugin(QString *errorMessage)
{
    if(m_SourceQueryPlugin) return m_SourceQueryPlugin;
    auto *loader = new QPluginLoader(QCoreApplication::applicationDirPath() + "/plugins/SourceRelations.dll", this);
    loader->setLoadHints(QLibrary::PreventUnloadHint);
    QObject *instance = loader->instance();
    m_SourceQueryPlugin = qobject_cast<SourceQueryInterface *>(instance);
    if(!m_SourceQueryPlugin) {
        if(errorMessage) *errorMessage = instance ? QStringLiteral("插件接口版本不兼容，请更新源码查询插件") : loader->errorString();
        delete loader;
    }
    return m_SourceQueryPlugin;
}

void MainWindow::StopAnalysis()
{
    if(!m_PipelineActive) return;
    m_StopRequested = true;
    m_StopButton->setEnabled(false);
    if(m_DiagnosticCancelled) m_DiagnosticCancelled->store(true);
    if(m_DeepSeekClient->IsBusy()) m_DeepSeekClient->Cancel();
    m_StageLabel->setText(m_Parser->IsBusy()
                         ? QStringLiteral("正在等待当前解析文件写完后停止…")
                         : QStringLiteral("正在停止分析…"));
}

void MainWindow::FinishAnalysis(const QString &errorMessage)
{
    const bool parsing = m_Action == Action::Parse;
    m_Action = Action::None;
    SetPipelineBusy(false);
    m_AllProgressBar->setRange(0, 100);
    if(errorMessage.isEmpty())
    {
        m_AllProgressBar->setValue(100);
        m_StageLabel->setText(QStringLiteral("分析完成"));
        SetWorkspaceStatus(QStringLiteral("分析完成"));
    }
    else
    {
        m_StageLabel->setText(errorMessage);
        m_ParseLogOutput->appendPlainText(errorMessage);
        m_AiResultOutput->setPlainText(errorMessage + QStringLiteral("\n\n可展开“查看过程与依据”了解已完成的步骤。"));
        SetWorkspaceStatus(m_StopRequested ? (parsing ? QStringLiteral("解析已停止") : QStringLiteral("分析已停止"))
                                          : (parsing ? QStringLiteral("解析未完成") : QStringLiteral("分析未完成")));
    }
}

void MainWindow::LoadSavedApiKey()
{
    QString errorMessage;
    const QString apiKey = ReadStoredDeepSeekApiKey(&errorMessage);
    if(!apiKey.isEmpty())
    {
        m_ApiKeyEdit->setText(apiKey);
        m_ApiKeyStatusLabel->setText(QStringLiteral("已从 Windows 凭据管理器自动载入"));
        return;
    }
    if(!errorMessage.isEmpty())
    {
        m_ApiKeyStatusLabel->setText(errorMessage);
    }
}

bool MainWindow::SaveApiKey(QString *errorMessage)
{
    const QString apiKey = m_ApiKeyEdit->text().trimmed();
    if(apiKey.isEmpty())
    {
        if(errorMessage != nullptr)
        {
            *errorMessage = QStringLiteral("请先填写 DeepSeek API Key");
        }
        return false;
    }
    if(!WriteStoredDeepSeekApiKey(apiKey, errorMessage))
    {
        return false;
    }
    m_ApiKeyStatusLabel->setText(QStringLiteral("已保存到 Windows 凭据管理器"));
    return true;
}

void MainWindow::ClearSavedApiKey()
{
    QString errorMessage;
    if(!DeleteStoredDeepSeekApiKey(&errorMessage))
    {
        QMessageBox::critical(this, QStringLiteral("清除 API Key 失败"), errorMessage);
        return;
    }
    m_ApiKeyEdit->clear();
    m_ApiKeyStatusLabel->setText(QStringLiteral("尚未保存 API Key"));
    QMessageBox::information(this, QStringLiteral("DeepSeek"),
                             QStringLiteral("已清除 Windows 凭据中保存的 API Key"));
}

QString MainWindow::CurrentBoardId() const
{
    return m_DetectedBoard;
}

bool MainWindow::DetectAnalysisBoard(const QStringList &paths)
{
    QString error;
    const QString board = BoardIdentity::fromFiles(paths, &error);
    if(board.isEmpty()) {
        m_StageLabel->setText(error);
        return false;
    }
    if(board != m_DetectedBoard) {
        QSettings settings;
        if(!m_DetectedBoard.isEmpty()) {
            settings.setValue(AnalysisSettingKey("analysis/baseline/" + m_DetectedBoard), m_AnalysisBaselineEdit->text().trimmed());
            settings.setValue(AnalysisSettingKey("analysis/dictionary/" + m_DetectedBoard), m_DictionaryEdit->text().trimmed());
            settings.setValue(AnalysisSettingKey("analysis/version/" + m_DetectedBoard), m_AnalysisVersionEdit->text().trimmed());
        }
        if(m_SourceBranch.isEmpty() && (!m_DetectedBoard.isEmpty() || board != "OPB")) {
            const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
            const QString fallback = board == "OPB" ? settings.value(AnalysisSettingKey("analysis/baseline")).toString()
                : QDir(desktop).filePath("LogDiagnosisData/" + board + "-Baseline.db");
            m_AnalysisBaselineEdit->setText(settings.value(AnalysisSettingKey("analysis/baseline/" + board), fallback).toString());
            m_DictionaryEdit->setText(settings.value(AnalysisSettingKey("analysis/dictionary/" + board),
                settings.value(AnalysisSettingKey("analysis/dictionary"), m_DictionaryEdit->text())).toString());
            m_AnalysisVersionEdit->setText(settings.value(AnalysisSettingKey("analysis/version/" + board),
                board == "OPB" ? settings.value(AnalysisSettingKey("analysis/version")) : QVariant(QString())).toString());
        }
        m_DetectedBoard = board;
        if(!m_SourceBranch.isEmpty()) LoadBranchBoardSettings();
    }
    m_AutoBoardLabel->setText(QStringLiteral("自动识别 · %1").arg(board));
    auto *sourceDialog = findChild<QDialog *>(QStringLiteral("sourceRelationsDialog"));
    if(sourceDialog) {
        auto *queryWidget = sourceDialog->findChild<QWidget *>("sourceQueryWidget");
        if(queryWidget) queryWidget->setProperty("expectedBoard", board);
        auto *path = sourceDialog->findChild<QLineEdit *>("sourceDatabasePath");
        if(path) path->setText(BoardIdentity::sourceDatabase(m_SourceDatabaseEdit->text().trimmed(), board));
    }
    return true;
}

void MainWindow::SetWorkspaceStatus(const QString &text, bool busy)
{
    if(m_StatusBadge == nullptr)
    {
        return;
    }
    m_StatusBadge->setText(text);
    m_StatusBadge->setProperty("busy", busy);
    m_StatusBadge->style()->unpolish(m_StatusBadge);
    m_StatusBadge->style()->polish(m_StatusBadge);
}
