#include "SourceQueryWidget.h"
#include "../../NewAnalysis/BoardIdentity.h"
#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QDirIterator>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QTableWidget>
#include <QTextBlock>
#include <QTextCursor>
#include <QTimer>
#include <QTreeWidget>
#include <QUuid>
#include <QVBoxLayout>

namespace {
QString relationLabel(const QString &value)
{
    if(value == "candidate") return QStringLiteral("间接／歧义候选");
    if(value == "source_direct") return QStringLiteral("源码直接调用");
    if(value == "macro") return QStringLiteral("宏调用，未展开");
    if(value == "external") return QStringLiteral("外部声明");
    if(value == "indirect") return QStringLiteral("间接调用，目标未知");
    return QStringLiteral("目标未解析");
}

QString escapeLike(QString value)
{
    value.replace("!", "!!");
    value.replace("%", "!%");
    value.replace("_", "!_");
    return value;
}
}

SourceQueryWidget::SourceQueryWidget(const QString &databasePath, QWidget *parent)
    : QWidget(parent), m_Process(new QProcess(this))
{
    setObjectName(QStringLiteral("sourceQueryWidget"));
    setProperty("expectedBoard", BoardIdentity::fromName(databasePath));
    QVBoxLayout *layout = new QVBoxLayout(this);
    QLabel *notice = new QLabel(QStringLiteral("板卡源码快照查询 · 使用对应目录配置头文件 · 其他板卡分支已排除"), this);
    notice->setWordWrap(true);
    layout->addWidget(notice);
    QHBoxLayout *databaseRow = new QHBoxLayout;
    m_Path = new QLineEdit(this);
    m_Path->setObjectName("sourceDatabasePath");
    m_Path->setText(databasePath);
    m_Browse = new QPushButton(QStringLiteral("选择关系库"), this);
    m_Browse->setObjectName("browseSourceDatabase");
    m_Rebuild = new QPushButton(QStringLiteral("重建关系库"), this);
    m_Rebuild->setObjectName("rebuildSourceDatabaseButton");
    m_Cancel = new QPushButton(QStringLiteral("取消建库"), this);
    m_Cancel->setEnabled(false);
    databaseRow->addWidget(m_Path, 1);
    databaseRow->addWidget(m_Browse);
    databaseRow->addWidget(m_Rebuild);
    databaseRow->addWidget(m_Cancel);
    layout->addLayout(databaseRow);
    m_Status = new QLabel(this);
    m_Status->setObjectName("sourceIndexStatus");
    m_Status->setWordWrap(true);
    layout->addWidget(m_Status);
    QHBoxLayout *searchRow = new QHBoxLayout;
    m_Mode = new QComboBox(this);
    m_Mode->setObjectName("sourceSearchMode");
    m_Mode->addItems({QStringLiteral("函数名"), QStringLiteral("日志编码／宏名"), QStringLiteral("解析问题")});
    m_Search = new QLineEdit(this);
    m_Search->setObjectName("sourceSearchText");
    m_Search->setPlaceholderText(QStringLiteral("例如 Plat_Main、0x0A1A、LOGTYPE_NEWCYCLE"));
    QPushButton *searchButton = new QPushButton(QStringLiteral("查询"), this);
    searchButton->setObjectName("sourceSearchButton");
    m_Direction = new QComboBox(this);
    m_Direction->addItems({QStringLiteral("向下查看被调用者"), QStringLiteral("向上查看调用者")});
    m_Depth = new QSpinBox(this);
    m_Depth->setRange(1, 5);
    m_Depth->setValue(2);
    m_Depth->setPrefix(QStringLiteral("深度 "));
    searchRow->addWidget(m_Mode);
    searchRow->addWidget(m_Search, 1);
    searchRow->addWidget(searchButton);
    searchRow->addWidget(m_Direction);
    searchRow->addWidget(m_Depth);
    layout->addLayout(searchRow);
    m_Results = new QTableWidget(0, 4, this);
    m_Results->setObjectName("sourceSearchResults");
    m_Results->setHorizontalHeaderLabels({QStringLiteral("函数／日志"), QStringLiteral("源码位置"), QStringLiteral("条件编译"), QStringLiteral("解析状态")});
    m_Results->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_Results->setSelectionMode(QAbstractItemView::SingleSelection);
    m_Results->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_Results->setWordWrap(false);
    m_Results->horizontalHeader()->setStretchLastSection(true);
    m_Results->setColumnWidth(0, 260);
    m_Results->setColumnWidth(1, 350);
    m_Tree = new QTreeWidget(this);
    m_Tree->setObjectName("sourceCallTree");
    m_Tree->setHeaderLabels({QStringLiteral("调用关系"), QStringLiteral("类型／位置")});
    m_Tree->setColumnWidth(0, 290);
    m_Source = new QPlainTextEdit(this);
    m_Source->setObjectName("sourceSnapshotText");
    m_Source->setReadOnly(true);
    m_Source->setLineWrapMode(QPlainTextEdit::NoWrap);
    QFont sourceFont("Consolas");
    sourceFont.setStyleHint(QFont::Monospace);
    m_Source->setFont(sourceFont);
    QSplitter *details = new QSplitter(Qt::Horizontal, this);
    details->addWidget(m_Tree);
    details->addWidget(m_Source);
    details->setStretchFactor(1, 2);
    details->setSizes({450, 750});
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(m_Results);
    splitter->addWidget(details);
    splitter->setStretchFactor(1, 3);
    layout->addWidget(splitter, 1);
    m_BuildLog = new QPlainTextEdit(this);
    m_BuildLog->setReadOnly(true);
    m_BuildLog->setMaximumBlockCount(1500);
    m_BuildLog->setMaximumHeight(110);
    m_BuildLog->hide();
    layout->addWidget(m_BuildLog);
    connect(m_Browse, &QPushButton::clicked, this, [this]() {
        QString path = QFileDialog::getOpenFileName(this, QStringLiteral("选择源码关系库"), m_Path->text(), "SQLite (*.sqlite *.db)");
        if(!path.isEmpty()) { m_Path->setText(path); search(); }
    });
    connect(m_Path, &QLineEdit::textChanged, this, [this]() {
        m_Results->setRowCount(0);
        m_Tree->clear();
        m_Source->clear();
        m_Status->setText(QStringLiteral("关系库路径已更改，请重新查询"));
    });
    connect(searchButton, &QPushButton::clicked, this, &SourceQueryWidget::search);
    connect(m_Search, &QLineEdit::returnPressed, this, &SourceQueryWidget::search);
    connect(m_Results, &QTableWidget::itemSelectionChanged, this, &SourceQueryWidget::selectResult);
    connect(m_Direction, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { selectResult(); });
    connect(m_Depth, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) { selectResult(); });
    connect(m_Tree, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem *item, int) {
        if(item->data(0, Qt::UserRole).isValid())
            showSource(item->data(0, Qt::UserRole).toLongLong(), item->data(0, Qt::UserRole + 1).toInt());
    });
    connect(m_Rebuild, &QPushButton::clicked, this, &SourceQueryWidget::rebuild);
    connect(m_Cancel, &QPushButton::clicked, this, [this]() {
        m_CancelRequested = true;
        m_Cancel->setEnabled(false);
        QFile cancel(m_CancelPath);
        if(cancel.open(QIODevice::WriteOnly)) cancel.close();
    });
    m_Process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_Process, &QProcess::readyReadStandardOutput, this, [this]() {
        m_BuildLog->appendPlainText(QString::fromUtf8(m_Process->readAllStandardOutput()));
    });
    connect(m_Process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus status) {
        setBuilding(false);
        if(!m_CancelPath.isEmpty()) QFile::remove(m_CancelPath);
        if(m_CancelRequested) m_Status->setText(QStringLiteral("建库已取消，现有关系库仍可查询"));
        else if(code == 0 && status == QProcess::NormalExit) search();
        else m_Status->setText(QStringLiteral("建库失败，请查看下方输出。现有关系库仍可查询"));
    });
    connect(m_Process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if(error == QProcess::FailedToStart) {
            setBuilding(false);
            m_Status->setText(QStringLiteral("建库工具启动失败。%1").arg(m_Process->errorString()));
        }
    });
    validateDatabase();
}

SourceQueryWidget::~SourceQueryWidget()
{
    if(m_Process->state() != QProcess::NotRunning) {
        QFile cancel(m_CancelPath);
        if(cancel.open(QIODevice::WriteOnly)) cancel.close();
        if(!m_Process->waitForFinished(3000)) {
            m_Process->kill();
            m_Process->waitForFinished(1000);
        }
    }
    if(!m_CancelPath.isEmpty()) QFile::remove(m_CancelPath);
}

QVector<QVariantMap> SourceQueryWidget::query(const QString &sql, const QVariantList &parameters)
{
    QVector<QVariantMap> rows;
    m_Error.clear();
    if(!QFileInfo(m_Path->text()).isFile()) {
        m_Error = QStringLiteral("关系库文件不存在，请选择文件或重建关系库");
        return rows;
    }
    const QString connection = QUuid::createUuid().toString();
    {
        QSqlDatabase database = QSqlDatabase::addDatabase("QSQLITE", connection);
        database.setDatabaseName(m_Path->text());
        database.setConnectOptions("QSQLITE_OPEN_READONLY");
        if(!database.open()) m_Error = database.lastError().text();
        else {
            QSqlQuery request(database);
            if(!request.prepare(sql)) m_Error = request.lastError().text();
            else {
                for(const QVariant &value : parameters) request.addBindValue(value);
                if(!request.exec()) m_Error = request.lastError().text();
                else while(request.next()) {
                    QVariantMap row;
                    const QSqlRecord record = request.record();
                    for(int column = 0; column < record.count(); ++column)
                        row.insert(record.fieldName(column), request.value(column));
                    rows.append(row);
                }
            }
        }
        database.close();
    }
    QSqlDatabase::removeDatabase(connection);
    return rows;
}

bool SourceQueryWidget::validateDatabase()
{
    const auto rows = query("SELECT key,value FROM metadata");
    QVariantMap metadata;
    for(const auto &row : rows) metadata.insert(row["key"].toString(), row["value"]);
    if(!m_Error.isEmpty() || metadata["format"] != "logdiagnosis-source-relations" || metadata["schema_version"] != "1") {
        m_Status->setText(QStringLiteral("无法使用此关系库。%1").arg(m_Error.isEmpty() ? QStringLiteral("格式或版本不支持") : m_Error));
        return false;
    }
    const QString expectedBoard = property("expectedBoard").toString();
    if(!expectedBoard.isEmpty() && metadata["board"].toString() != expectedBoard) {
        m_Status->setText(QStringLiteral("所选源码库属于 %1，与当前日志板卡 %2 不一致").arg(metadata["board"].toString(), expectedBoard));
        return false;
    }
    const QJsonObject summary = QJsonDocument::fromJson(metadata["summary"].toString().toUtf8()).object();
    const int unknownMacros = QJsonDocument::fromJson(metadata["unresolved_configuration"].toString().toUtf8()).array().size();
    m_Status->setText(QStringLiteral("板卡 %1 · 未确认宏 %2 · ").arg(metadata["board"].toString()).arg(unknownMacros) + QStringLiteral("版本 %1 · 函数 %2 · 调用点 %3 · 日志点 %4 · 含解析问题的文件 %5 · 快照 %6")
                      .arg(metadata["software_version"].toString()).arg(summary["functions"].toInt())
                      .arg(summary["calls"].toInt()).arg(summary["log_sites"].toInt())
                      .arg(summary["parse_error_files"].toInt()).arg(metadata["snapshot_id"].toString().left(8)));
    m_Status->setToolTip(metadata["source_root"].toString() + "\n" + metadata["source_hash"].toString());
    QSettings().setValue("sourceRelations/database", m_Path->text());
    return true;
}

void SourceQueryWidget::search()
{
    m_Results->setRowCount(0);
    m_Tree->clear();
    m_Source->clear();
    if(!validateDatabase()) return;
    const QString searchText = m_Search->text().trimmed();
    QVector<QVariantMap> rows;
    if(m_Mode->currentIndex() == 0) {
        rows = query("SELECT f.id,f.file_id,f.name,f.line,f.condition,f.has_errors,s.path FROM functions f JOIN files s ON s.id=f.file_id WHERE f.name LIKE ? ESCAPE '!' ORDER BY f.name,s.path,f.line LIMIT 501",
                     {"%" + escapeLike(searchText) + "%"});
    } else if(m_Mode->currentIndex() == 1) {
        bool numeric = false;
        const qlonglong code = searchText.toLongLong(&numeric, searchText.startsWith("0x", Qt::CaseInsensitive) ? 16 : 10);
        const QString clause = numeric ? "l.code=?" : "l.code_expression LIKE ? ESCAPE '!'";
        rows = query("SELECT f.id,f.file_id,f.name,c.line,c.condition,c.has_errors,s.path,l.code,l.code_expression,l.data_expression,l.length_expression FROM log_sites l JOIN calls c ON c.id=l.call_id JOIN functions f ON f.id=c.function_id JOIN files s ON s.id=f.file_id WHERE " + clause + " ORDER BY s.path,c.line LIMIT 501",
                     {numeric ? QVariant(code) : QVariant("%" + escapeLike(searchText) + "%")});
    } else {
        const QString pattern = "%" + escapeLike(searchText) + "%";
        rows = query("SELECT NULL AS id,d.file_id,d.kind AS name,d.line,'' AS condition,0 AS has_errors,s.path,d.message AS diagnostic_message FROM diagnostics d JOIN files s ON s.id=d.file_id WHERE d.kind LIKE ? ESCAPE '!' OR d.message LIKE ? ESCAPE '!' OR s.path LIKE ? ESCAPE '!' ORDER BY s.path,d.line LIMIT 501",
                     {pattern, pattern, pattern});
    }
    if(!m_Error.isEmpty()) { m_Status->setText(m_Error); return; }
    const bool limited = rows.size() > 500;
    if(limited) rows.resize(500);
    m_Results->setRowCount(rows.size());
    for(int number = 0; number < rows.size(); ++number) {
        const auto &row = rows[number];
        QString label = row["name"].toString();
        if(row.contains("code_expression")) label += " · " + row["code_expression"].toString();
        const QString state = row.contains("diagnostic_message") ? row["diagnostic_message"].toString() :
                              (row["has_errors"].toBool() ? QStringLiteral("语法恢复结果，需核查") : QStringLiteral("源码语法索引"));
        const QStringList values = {label, row["path"].toString() + ":" + row["line"].toString(), row["condition"].toString(), state};
        for(int column = 0; column < values.size(); ++column) {
            auto *item = new QTableWidgetItem(values[column]);
            item->setToolTip(values[column]);
            m_Results->setItem(number, column, item);
        }
        m_Results->item(number, 0)->setData(Qt::UserRole, row);
    }
    m_Status->setText(m_Status->text() + QStringLiteral(" · 查询结果 %1%2").arg(rows.size()).arg(limited ? QStringLiteral("，已截断，请缩小关键词") : QString()));
    if(!rows.isEmpty()) m_Results->selectRow(0);
}

void SourceQueryWidget::selectResult()
{
    m_Tree->clear();
    const int selected = m_Results->currentRow();
    if(selected < 0 || !m_Results->item(selected, 0)) return;
    const QVariantMap row = m_Results->item(selected, 0)->data(Qt::UserRole).toMap();
    auto *root = new QTreeWidgetItem(m_Tree, {row["name"].toString(), row["path"].toString()});
    root->setData(0, Qt::UserRole, row["file_id"]);
    root->setData(0, Qt::UserRole + 1, row["line"]);
    int remaining = 300;
    if(!row["id"].isNull()) addRelations(root, row["id"].toLongLong(), m_Depth->value(), {}, remaining);
    if(remaining == 0) new QTreeWidgetItem(root, {QStringLiteral("已达到 300 个节点上限，请减小深度")});
    m_Tree->expandToDepth(0);
    showSource(row["file_id"].toLongLong(), row["line"].toInt());
}

void SourceQueryWidget::addRelations(QTreeWidgetItem *parent, qint64 functionId, int depth,
                                   QList<qint64> ancestors, int &remaining)
{
    if(depth == 0 || remaining == 0) return;
    ancestors.append(functionId);
    QString sql;
    if(m_Direction->currentIndex() == 0) {
        sql = "SELECT t.id,t.name AS target,c.name,c.kind,c.condition,c.line,c.file_id,c.path,e.resolution,e.evidence FROM call_details c LEFT JOIN edges e ON e.call_id=c.id LEFT JOIN functions t ON t.id=e.target_id WHERE c.function_id=? ORDER BY c.line,t.name LIMIT 301";
    } else {
        sql = "SELECT c.function_id AS id,c.caller AS target,c.name,c.kind,c.condition,c.line,c.file_id,c.path,e.resolution,e.evidence FROM edges e JOIN call_details c ON c.id=e.call_id WHERE e.target_id=? ORDER BY c.path,c.line LIMIT 301";
    }
    const auto rows = query(sql, {functionId});
    if(!m_Error.isEmpty()) { new QTreeWidgetItem(parent, {m_Error}); return; }
    for(const auto &row : rows) {
        if(remaining == 0) return;
        --remaining;
        const qint64 targetId = row["id"].toLongLong();
        const bool cycle = targetId && ancestors.contains(targetId);
        const QString label = row["target"].isNull() ? row["name"].toString() : row["target"].toString();
        const QString kind = row["resolution"].isNull() ? row["kind"].toString() : row["resolution"].toString();
        auto *item = new QTreeWidgetItem(parent, {label + (cycle ? QStringLiteral(" ↩ 递归／循环") : ""),
                                                  relationLabel(kind) + " · " + row["path"].toString() + ":" + row["line"].toString()});
        item->setData(0, Qt::UserRole, row["file_id"]);
        item->setData(0, Qt::UserRole + 1, row["line"]);
        item->setToolTip(0, row["evidence"].toString() + "\n" + row["condition"].toString());
        if(targetId && !cycle) addRelations(item, targetId, depth - 1, ancestors, remaining);
    }
}

void SourceQueryWidget::showSource(qint64 fileId, int line)
{
    const auto rows = query("SELECT path,content FROM files WHERE id=?", {fileId});
    if(rows.isEmpty()) { m_Source->setPlainText(m_Error); return; }
    const QStringList lines = rows[0]["content"].toString().split('\n');
    QStringList numbered;
    for(int number = 0; number < lines.size(); ++number)
        numbered.append(QString("%1  %2").arg(number + 1, 5).arg(lines[number]));
    m_Source->setPlainText(numbered.join('\n'));
    QTextCursor cursor(m_Source->document()->findBlockByNumber(qMax(0, line - 1)));
    cursor.select(QTextCursor::LineUnderCursor);
    m_Source->setTextCursor(cursor);
    m_Source->centerCursor();
    m_Source->setToolTip(rows[0]["path"].toString() + QStringLiteral(" · 建库时保存的源码快照"));
}

void SourceQueryWidget::setBuilding(bool busy)
{
    setProperty("building", busy);
    m_Rebuild->setEnabled(!busy);
    m_Browse->setEnabled(!busy && property("sourceBranch").toString().isEmpty());
    m_Cancel->setEnabled(busy);
    m_Path->setReadOnly(busy || !property("sourceBranch").toString().isEmpty());
}

void SourceQueryWidget::rebuild()
{
    const QString executable = QCoreApplication::applicationDirPath() + "/source_relations/SourceIndexer.exe";
    if(!QFileInfo::exists(executable)) {
        QMessageBox::warning(this, QStringLiteral("源码关系库"), QStringLiteral("缺少建库工具。%1").arg(executable));
        return;
    }
    QString source = property("sourceRoot").toString();
    if(source.isEmpty()) {
        const auto metadata = query("SELECT value FROM metadata WHERE key='source_root'");
        source = QFileDialog::getExistingDirectory(this, QStringLiteral("选择 C/H 源码目录"), metadata.isEmpty() ? QString() : metadata[0]["value"].toString());
    }
    if(source.isEmpty()) return;
    QDirIterator sources(source, {"*.c", "*.h", "*.C", "*.H"}, QDir::Files, QDirIterator::Subdirectories);
    if(!sources.hasNext()) { m_Status->setText(QStringLiteral("当前分支 source 目录中没有 C/H 源码，请先放入完整源码")); return; }
    const QString profiles = property("profilesPath").toString();
    if(!profiles.isEmpty() && !QFileInfo(profiles).isFile()) { m_Status->setText(QStringLiteral("当前分支缺少 board_profiles.json")); return; }
    bool accepted = false;
    const QString version = QInputDialog::getText(this, QStringLiteral("源码版本"), QStringLiteral("输入此次快照的软件版本或标记"), QLineEdit::Normal, property("sourceBranch").toString(), &accepted);
    if(!accepted) return;
    QString output = m_Path->text().trimmed();
    if(output.isEmpty()) {
        output = QFileDialog::getSaveFileName(this, QStringLiteral("保存关系库"), QString(), "SQLite (*.sqlite)");
        if(output.isEmpty()) return;
        m_Path->setText(output);
    }
    m_CancelRequested = false;
    m_BuildLog->clear();
    m_BuildLog->show();
    m_Status->setText(QStringLiteral("正在建立源码关系库…"));
    m_CancelPath = QDir(QFileInfo(output).absolutePath()).filePath(".source-index-" + QUuid::createUuid().toString(QUuid::WithoutBraces) + ".cancel");
    setBuilding(true);
    QStringList arguments{"--source", source, "--output", output, "--all-boards", "--version", version, "--cancel-file", m_CancelPath};
    if(!profiles.isEmpty()) arguments << "--profiles" << profiles;
    m_Process->start(executable, arguments);
}
