#include "DiagnosisPage.h"

#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFrame>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSplitter>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QTabWidget>
#include <QUuid>
#include <QVBoxLayout>
#include <QtConcurrentRun>

namespace
{
QLabel *Hint(const QString &text, QWidget *parent)
{
    QLabel *label = new QLabel(text, parent);
    label->setObjectName(QStringLiteral("subtitle"));
    label->setWordWrap(true);
    return label;
}

QLabel *Title(const QString &text, QWidget *parent)
{
    QLabel *label = new QLabel(text, parent);
    label->setObjectName(QStringLiteral("panelTitle"));
    return label;
}
}

DiagnosisPage::DiagnosisPage(QWidget *parent) : QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 12, 0, 0);
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);
    m_ConfigPanel = new QFrame(splitter);
    m_ConfigPanel->setObjectName(QStringLiteral("submissionPanel"));
    QVBoxLayout *config = new QVBoxLayout(m_ConfigPanel);
    config->setContentsMargins(18, 16, 18, 18);
    config->setSpacing(10);
    config->addWidget(Title(QStringLiteral("OPB 自动诊断"), m_ConfigPanel));
    config->addWidget(Hint(QStringLiteral("选择一份日志的全部 CSV 分段，或选择已入库事件，与正常基线进行本地比较。"), m_ConfigPanel));

    m_SourceMode = new QComboBox(m_ConfigPanel);
    m_SourceMode->setObjectName(QStringLiteral("diagnosisSourceMode"));
    m_SourceMode->addItems({QStringLiteral("解析后的 CSV"), QStringLiteral("故障样本库中的事件")});
    config->addWidget(m_SourceMode);
    m_SourceStack = new QStackedWidget(m_ConfigPanel);
    QWidget *csvPage = new QWidget(m_SourceStack);
    QVBoxLayout *csvLayout = new QVBoxLayout(csvPage);
    csvLayout->setContentsMargins(0, 0, 0, 0);
    QHBoxLayout *fileButtons = new QHBoxLayout();
    QPushButton *addFiles = new QPushButton(QStringLiteral("添加 CSV"), csvPage);
    QPushButton *clearFiles = new QPushButton(QStringLiteral("清空"), csvPage);
    fileButtons->addWidget(addFiles); fileButtons->addWidget(clearFiles); fileButtons->addStretch();
    csvLayout->addLayout(fileButtons);
    m_CsvFiles = new QListWidget(csvPage);
    m_CsvFiles->setObjectName(QStringLiteral("diagnosisCsvFiles"));
    m_CsvFiles->setAcceptDrops(false);
    csvLayout->addWidget(m_CsvFiles, 1);
    csvLayout->addWidget(Hint(QStringLiteral("支持拖入多个 CSV，点击“本地诊断”后开始。"), csvPage));
    m_SourceStack->addWidget(csvPage);

    QWidget *incidentPage = new QWidget(m_SourceStack);
    QVBoxLayout *incidentLayout = new QVBoxLayout(incidentPage);
    incidentLayout->setContentsMargins(0, 0, 0, 0);
    m_FaultDatabase = new QLineEdit(incidentPage);
    const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    m_FaultDatabase->setText(QDir(desktop).filePath(QStringLiteral("LogDiagnosisData/OPB-FaultSamples.db")));
    m_FaultDatabase->setObjectName(QStringLiteral("diagnosisFaultDatabase"));
    QPushButton *browseFault = new QPushButton(QStringLiteral("选择故障库"), incidentPage);
    QPushButton *refresh = new QPushButton(QStringLiteral("刷新事件"), incidentPage);
    m_Incidents = new QComboBox(incidentPage);
    m_Incidents->setObjectName(QStringLiteral("diagnosisIncident"));
    incidentLayout->addWidget(m_FaultDatabase);
    QHBoxLayout *databaseButtons = new QHBoxLayout();
    databaseButtons->addWidget(browseFault); databaseButtons->addWidget(refresh);
    incidentLayout->addLayout(databaseButtons);
    incidentLayout->addWidget(m_Incidents);
    incidentLayout->addWidget(Hint(QStringLiteral("读取已保存事件即可诊断，原 CSV 移动后仍可使用；已知原因标签不参与候选推断。"), incidentPage));
    incidentLayout->addStretch();
    m_SourceStack->addWidget(incidentPage);
    config->addWidget(m_SourceStack, 1);

    m_BaselineDatabase = new QLineEdit(m_ConfigPanel);
    m_BaselineDatabase->setObjectName(QStringLiteral("diagnosisBaselineDatabase"));
    m_BaselineDatabase->setText(QDir(desktop).filePath(QStringLiteral("LogDiagnosisData/OPB-Baseline.db")));
    QPushButton *browseBaseline = new QPushButton(QStringLiteral("选择正常基线"), m_ConfigPanel);
    m_Version = new QLineEdit(m_ConfigPanel);
    m_Version->setObjectName(QStringLiteral("diagnosisSoftwareVersion"));
    m_Version->setPlaceholderText(QStringLiteral("可留空；未知版本会在报告中注明"));
    QFormLayout *form = new QFormLayout();
    form->addRow(QStringLiteral("正常基线"), m_BaselineDatabase);
    form->addRow(QString(), browseBaseline);
    form->addRow(QStringLiteral("日志软件版本"), m_Version);
    config->addLayout(form);

    QFrame *resultPanel = new QFrame(splitter);
    resultPanel->setObjectName(QStringLiteral("previewPanel"));
    QVBoxLayout *resultLayout = new QVBoxLayout(resultPanel);
    resultLayout->setContentsMargins(18, 16, 18, 18);
    resultLayout->addWidget(Title(QStringLiteral("本地结果与诊断证据"), resultPanel));
    resultLayout->addWidget(Hint(QStringLiteral("比较结果是候选异常，根因需结合实际确认。生成证据后可送入 AI 页预览，再手动发送。"), resultPanel));
    QHBoxLayout *actions = new QHBoxLayout();
    m_Run = new QPushButton(QStringLiteral("本地诊断"), resultPanel);
    m_Run->setObjectName(QStringLiteral("startButton"));
    m_Cancel = new QPushButton(QStringLiteral("取消"), resultPanel);
    m_Cancel->setEnabled(false);
    m_Export = new QPushButton(QStringLiteral("导出证据 JSON"), resultPanel);
    m_Transfer = new QPushButton(QStringLiteral("送入 AI 分析页"), resultPanel);
    m_Export->setEnabled(false); m_Transfer->setEnabled(false);
    actions->addWidget(m_Run); actions->addWidget(m_Cancel); actions->addStretch();
    resultLayout->addLayout(actions);
    m_Status = new QLabel(QStringLiteral("等待选择诊断数据"), resultPanel);
    m_Status->setWordWrap(true);
    resultLayout->addWidget(m_Status);
    m_Progress = new QProgressBar(resultPanel);
    m_Progress->setRange(0, 100); m_Progress->setValue(0);
    resultLayout->addWidget(m_Progress);
    QTabWidget *results = new QTabWidget(resultPanel);
    m_Report = new QPlainTextEdit(results);
    m_Report->setObjectName(QStringLiteral("diagnosisReport"));
    m_Report->setReadOnly(true); m_Report->setAcceptDrops(false);
    m_Evidence = new QPlainTextEdit(results);
    m_Evidence->setObjectName(QStringLiteral("diagnosisEvidence"));
    m_Evidence->setReadOnly(true); m_Evidence->setAcceptDrops(false);
    results->addTab(m_Report, QStringLiteral("差异报告"));
    results->addTab(m_Evidence, QStringLiteral("将交给 AI 的证据"));
    resultLayout->addWidget(results, 1);
    QHBoxLayout *exportActions = new QHBoxLayout();
    exportActions->addWidget(m_Export); exportActions->addWidget(m_Transfer);
    resultLayout->addLayout(exportActions);
    splitter->addWidget(m_ConfigPanel); splitter->addWidget(resultPanel);
    splitter->setStretchFactor(0, 4); splitter->setStretchFactor(1, 6);
    splitter->setSizes({420, 660});
    layout->addWidget(splitter);

    connect(m_SourceMode, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, [this](int index) {
        m_SourceStack->setCurrentIndex(index); InvalidateResult();
        if(index == 1) ReloadIncidents();
    });
    connect(addFiles, &QPushButton::clicked, this, [this, desktop]() {
        AddCsvFiles(QFileDialog::getOpenFileNames(this, QStringLiteral("选择同一日志的全部 CSV 分段"),
                                                 desktop, QStringLiteral("CSV (*.csv)")));
    });
    connect(clearFiles, &QPushButton::clicked, this, [this]() {
        m_CsvFiles->clear(); InvalidateResult();
    });
    connect(browseBaseline, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择 OPB 正常基线"),
                                                          m_BaselineDatabase->text(), QStringLiteral("SQLite (*.db)"));
        if(!path.isEmpty()) m_BaselineDatabase->setText(path);
    });
    connect(browseFault, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择 OPB 故障样本库"),
                                                          m_FaultDatabase->text(), QStringLiteral("SQLite (*.db)"));
        if(!path.isEmpty()) { m_FaultDatabase->setText(path); ReloadIncidents(); }
    });
    connect(refresh, &QPushButton::clicked, this, &DiagnosisPage::ReloadIncidents);
    connect(m_BaselineDatabase, &QLineEdit::textChanged, this, &DiagnosisPage::InvalidateResult);
    connect(m_Version, &QLineEdit::textChanged, this, &DiagnosisPage::InvalidateResult);
    connect(m_FaultDatabase, &QLineEdit::textChanged, this, [this]() {
        m_Incidents->clear(); InvalidateResult();
    });
    connect(m_Incidents, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
            this, [this](int) { InvalidateResult(); });
    connect(m_Run, &QPushButton::clicked, this, &DiagnosisPage::Run);
    connect(m_Cancel, &QPushButton::clicked, this, [this]() {
        if(m_Cancelled) m_Cancelled->store(true);
        m_Status->setText(QStringLiteral("正在取消诊断…")); m_Cancel->setEnabled(false);
    });
    connect(&m_Watcher, &QFutureWatcher<OpbDiagnosticAnalyzer::Result>::finished, this, [this]() {
        const OpbDiagnosticAnalyzer::Result result = m_Watcher.result();
        const bool wasCancelled = m_Cancelled && m_Cancelled->load();
        m_ConfigPanel->setEnabled(true); m_Run->setEnabled(true); m_Cancel->setEnabled(false);
        m_Progress->setRange(0, 100); m_Progress->setValue(result.success && !wasCancelled ? 100 : 0);
        if(!result.success || wasCancelled)
        {
            const QString message = wasCancelled ? QStringLiteral("诊断已取消") : result.errorMessage;
            m_Status->setText(message); m_Report->setPlainText(message);
            emit StatusChanged(message, false);
            return;
        }
        m_LastEvidence = QString::fromUtf8(QJsonDocument(result.evidence).toJson(QJsonDocument::Indented));
        m_Report->setPlainText(result.summary); m_Evidence->setPlainText(m_LastEvidence);
        m_Status->setText(QStringLiteral("本地诊断完成，尚未向 AI 发送数据"));
        m_Export->setEnabled(true); m_Transfer->setEnabled(true);
        emit StatusChanged(QStringLiteral("本地诊断完成 · 根因待确认"), false);
    });
    connect(m_Transfer, &QPushButton::clicked, this, [this]() {
        if(!m_LastEvidence.isEmpty()) emit EvidenceReady(m_LastEvidence);
    });
    connect(m_Export, &QPushButton::clicked, this, [this]() {
        const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("导出诊断证据"),
                                                          QStringLiteral("incident-evidence.json"), QStringLiteral("JSON (*.json)"));
        if(path.isEmpty()) return;
        QSaveFile file(path);
        const QByteArray data = m_LastEvidence.toUtf8();
        if(!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit())
            QMessageBox::critical(this, QStringLiteral("导出失败"), file.errorString());
        else m_Status->setText(QStringLiteral("证据已导出：") + path);
    });
}

DiagnosisPage::~DiagnosisPage()
{
    if(m_Cancelled) m_Cancelled->store(true);
    // The worker owns value-copied inputs and its own DB connections, never UI pointers.
    m_Watcher.waitForFinished();
}

void DiagnosisPage::InvalidateResult()
{
    m_LastEvidence.clear(); m_Report->clear(); m_Evidence->clear();
    m_Export->setEnabled(false); m_Transfer->setEnabled(false);
    m_Progress->setRange(0, 100); m_Progress->setValue(0);
    m_Status->setText(QStringLiteral("输入已更新，等待本地诊断"));
}

void DiagnosisPage::AddCsvFiles(const QStringList &paths)
{
    if(m_Watcher.isRunning()) return;
    bool added = false;
    for(const QString &path : paths)
    {
        const QFileInfo info(path);
        if(info.isFile() && info.suffix().compare("csv", Qt::CaseInsensitive) == 0 &&
           m_CsvFiles->findItems(info.absoluteFilePath(), Qt::MatchExactly).isEmpty())
        {
            m_CsvFiles->addItem(info.absoluteFilePath()); added = true;
        }
    }
    if(added) { m_SourceMode->setCurrentIndex(0); InvalidateResult(); }
}

void DiagnosisPage::SetParsedFiles(const QStringList &paths)
{
    if(m_Watcher.isRunning() || paths.isEmpty()) return;
    m_CsvFiles->clear(); AddCsvFiles(paths);
}

void DiagnosisPage::SetBaselinePath(const QString &path)
{
    if(!m_Watcher.isRunning()) m_BaselineDatabase->setText(path);
}

void DiagnosisPage::SetIncident(const QString &databasePath, qint64 incidentId)
{
    if(m_Watcher.isRunning()) return;
    m_FaultDatabase->setText(databasePath); m_SourceMode->setCurrentIndex(1); ReloadIncidents();
    const int index = m_Incidents->findData(incidentId);
    if(index >= 0) m_Incidents->setCurrentIndex(index);
}

void DiagnosisPage::ReloadIncidents()
{
    const qint64 selected = m_Incidents->currentData().toLongLong();
    m_Incidents->clear();
    if(!QFileInfo(m_FaultDatabase->text()).isFile())
    {
        m_Status->setText(QStringLiteral("故障库尚未建立，可先在宕机样本页添加日志")); return;
    }
    const QString name = QUuid::createUuid().toString();
    QString error;
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), name);
        db.setConnectOptions(QStringLiteral("QSQLITE_OPEN_READONLY"));
        db.setDatabaseName(m_FaultDatabase->text());
        if(!db.open()) error = QStringLiteral("无法打开故障样本库");
        else
        {
            QSqlQuery query(db);
            if(!query.exec(QStringLiteral("SELECT id, created_utc, event_count FROM fault_incident "
                                          "WHERE board_type='OPB' ORDER BY id DESC")))
                error = QStringLiteral("所选文件不是有效的故障样本库");
            else while(query.next())
                m_Incidents->addItem(QStringLiteral("事件 %1 · %2 · %3 条")
                                    .arg(query.value(0).toString(), query.value(1).toString(), query.value(2).toString()),
                                    query.value(0).toLongLong());
        }
    }
    QSqlDatabase::removeDatabase(name);
    const int index = m_Incidents->findData(selected);
    if(index >= 0) m_Incidents->setCurrentIndex(index);
    if(!error.isEmpty()) m_Status->setText(error);
    else if(m_Incidents->count() == 0) m_Status->setText(QStringLiteral("故障库中尚无 OPB 事件"));
}

void DiagnosisPage::Run()
{
    if(m_Watcher.isRunning()) return;
    OpbDiagnosticAnalyzer::Input input;
    input.baselinePath = m_BaselineDatabase->text().trimmed();
    input.softwareVersion = m_Version->text();
    if(m_SourceMode->currentIndex() == 0)
    {
        for(int index = 0; index < m_CsvFiles->count(); ++index)
            input.csvPaths.append(m_CsvFiles->item(index)->text());
        if(input.csvPaths.isEmpty()) { m_Status->setText(QStringLiteral("请先添加 CSV")); return; }
    }
    else
    {
        input.faultDatabasePath = m_FaultDatabase->text().trimmed();
        input.incidentId = m_Incidents->currentData().toLongLong();
        if(input.incidentId <= 0) { m_Status->setText(QStringLiteral("请先选择故障事件")); return; }
    }
    InvalidateResult();
    m_Cancelled = std::make_shared<std::atomic_bool>(false);
    input.cancelled = m_Cancelled;
    m_ConfigPanel->setEnabled(false); m_Run->setEnabled(false); m_Cancel->setEnabled(true);
    m_Progress->setRange(0, 0); m_Status->setText(QStringLiteral("正在本地读取日志并比较基线…"));
    emit StatusChanged(QStringLiteral("正在执行 OPB 本地诊断"), true);
    m_Watcher.setFuture(QtConcurrent::run([input]() { return OpbDiagnosticAnalyzer().Analyze(input); }));
}
