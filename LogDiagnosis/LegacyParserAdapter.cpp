#include "LegacyParserAdapter.h"

#include "OpbBaselineAnalyzer.h"
#include "ReadThread.h"
#include "readword.h"
#include "BoardIdentity.h"

#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDir>
#include <QStandardPaths>
#include <QTextStream>
#include <QUuid>

LegacyParserAdapter::LegacyParserAdapter(QObject *parent)
    : QObject(parent),
      m_ReadDictionaryThread(nullptr),
      m_ReadWordThread(nullptr),
      m_SingleFileProgress(0),
      m_AllFileProgress(0),
      m_Busy(false)
{
}

LegacyParserAdapter::~LegacyParserAdapter()
{
    if((m_ReadDictionaryThread != nullptr) && m_ReadDictionaryThread->isRunning())
    {
        m_ReadDictionaryThread->wait();
    }
    if((m_ReadWordThread != nullptr) && m_ReadWordThread->isRunning())
    {
        m_ReadWordThread->wait();
    }
    CleanupThreads();
}

bool LegacyParserAdapter::IsBusy() const
{
    return m_Busy;
}

void LegacyParserAdapter::StartOpbParse(const QString &sourceFilePath,
                                        const QString &plfmDictionaryPath,
                                        bool includeApplicationLogs, bool isolatedOutput)
{
    if(m_Busy)
    {
        emit Signal_ParseFailed(QStringLiteral("已有日志解析任务正在执行"));
        return;
    }

    const QFileInfo sourceInfo(sourceFilePath);
    if(!sourceInfo.exists() || !sourceInfo.isFile())
    {
        emit Signal_ParseFailed(QStringLiteral("原始日志不存在"));
        return;
    }

    QString boardError;
    const QString board = BoardIdentity::fromFiles({sourceFilePath}, &boardError);
    if(board.isEmpty())
    {
        emit Signal_ParseFailed(boardError);
        return;
    }

    CleanupThreads();
    m_SourceFilePath = sourceInfo.absoluteFilePath();
    if(isolatedOutput)
    {
        const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        const QString runPath = QDir(desktop).filePath(QStringLiteral("LogDiagnosisData/ParsedLogs/%1-%2")
                               .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")),
                                    QUuid::createUuid().toString(QUuid::WithoutBraces)));
        const QString runSource = QDir(runPath).filePath(sourceInfo.fileName());
        if(!QDir().mkpath(runPath) || !QFile::copy(sourceInfo.absoluteFilePath(), runSource))
        {
            emit Signal_ParseFailed(QStringLiteral("无法创建本次解析工作目录，请检查桌面目录权限和磁盘空间"));
            return;
        }
        m_SourceFilePath = runSource;
        emit Signal_LogMessage(QStringLiteral("本次解析目录：%1").arg(runPath));
    }
    m_SingleFileProgress = 0;
    m_AllFileProgress = 0;
    m_Busy = true;

    m_ReadDictionaryThread = new ReadThread(this);
    m_ReadWordThread = new ReadWord();
    m_ReadWordThread->setParent(this);
    m_ReadDictionaryThread->m_CCBLogDic.t_LogDicObjectNum = 0u;
    m_ReadDictionaryThread->m_PLFMLogDic.t_LogDicObjectNum = 0u;
    m_ReadDictionaryThread->m_RCDLogDic.t_LogDicObjectNum = 0u;

    QString dictionaryError;
    if(!LoadPlfmDictionary(plfmDictionaryPath, &dictionaryError))
    {
        m_Busy = false;
        CleanupThreads();
        emit Signal_ParseFailed(dictionaryError);
        return;
    }

    m_ReadWordThread->t_FileList = QStringList() << m_SourceFilePath;
    m_ReadWordThread->m_u64CutFileNum = 50u * 10000u;
    m_ReadWordThread->m_AnalysisAppLogSwitch = includeApplicationLogs;
    m_ReadWordThread->m_SpecialConfigSwitch = false;
    m_ReadWordThread->m_CCBTimeStampSwitch = false;

    connect(m_ReadDictionaryThread, &ReadThread::Signal_ReadDicOver, this, [this]() {
        emit Signal_LogMessage(QStringLiteral("PLFM字典已载入，开始解析自动识别的板卡日志"));
        m_ReadWordThread->start();
    });

    connect(m_ReadDictionaryThread, &ReadThread::Signal_MessageBoxShow,
            this, [this](bool, const QString &message) {
        emit Signal_LogMessage(message);
    });

    connect(m_ReadWordThread, &ReadWord::Signal_OnceFileBarSetValue,
            this, [this](int value, const QString &) {
        m_SingleFileProgress = value;
        emit Signal_ProgressChanged(m_SingleFileProgress, m_AllFileProgress);
    });

    connect(m_ReadWordThread, &ReadWord::Signal_AllFileBarSetValue,
            this, [this](int value, const QString &) {
        m_AllFileProgress = value;
        emit Signal_ProgressChanged(m_SingleFileProgress, m_AllFileProgress);
    });

    connect(m_ReadWordThread, &ReadWord::Signal_BrowserLogShow,
            this, &LegacyParserAdapter::Signal_LogMessage);

    connect(m_ReadWordThread, &ReadWord::Signal_MessageBoxShow,
            this, [this](bool, const QString &message) {
        emit Signal_LogMessage(message);
    });

    connect(m_ReadWordThread, &ReadWord::Signal_AnalysisOver,
            this, [this](bool success) {
        m_ReadWordThread->wait();
        const QStringList outputs = OpbBaselineAnalyzer::FindParsedCsvFiles(m_SourceFilePath);
        m_Busy = false;
        emit Signal_ParseFinished(success, outputs);
    });

    emit Signal_LogMessage(QStringLiteral("开始读取原始PLFM字典"));
    m_ReadDictionaryThread->start();
}

bool LegacyParserAdapter::LoadPlfmDictionary(const QString &dictionaryPath,
                                             QString *errorMessage)
{
    QFile file(dictionaryPath);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        if(errorMessage != nullptr)
        {
            *errorMessage = QStringLiteral("无法打开原始PLFM字典: ") + dictionaryPath;
        }
        return false;
    }

    QTextStream stream(&file);
    stream.setCodec("UTF-8");
    if(!stream.atEnd())
    {
        stream.readLine();
    }

    STRU_LOG_DIC &dictionary = m_ReadDictionaryThread->m_PLFMLogDic;
    dictionary.t_LogDicObjectNum = 0u;

    while(!stream.atEnd())
    {
        const QString line = stream.readLine();
        const QStringList fields = line.split(',');
        if(fields.size() < 4)
        {
            continue;
        }

        if(dictionary.t_LogDicObjectNum >= LOG_CODE_MAX_NUM)
        {
            if(errorMessage != nullptr)
            {
                *errorMessage = QStringLiteral("PLFM字典记录数量超过程序上限%1")
                        .arg(LOG_CODE_MAX_NUM);
            }
            return false;
        }

        STRU_LOG_DIC_OBJ &item = dictionary.t_LogDicObject[dictionary.t_LogDicObjectNum];
        item.t_StrLogCode = fields.at(0).trimmed();
        item.t_StrLogCodeInfo = fields.at(1).trimmed();
        item.t_StrLogData = fields.at(2).trimmed();
        item.t_StrLogDataInfo = fields.at(3).trimmed();
        ++dictionary.t_LogDicObjectNum;
    }

    if(dictionary.t_LogDicObjectNum == 0u)
    {
        if(errorMessage != nullptr)
        {
            *errorMessage = QStringLiteral("原始PLFM字典没有有效记录");
        }
        return false;
    }

    emit Signal_LogMessage(QStringLiteral("读取PLFM字典%1条")
                           .arg(dictionary.t_LogDicObjectNum));
    return true;
}

void LegacyParserAdapter::CleanupThreads()
{
    if((m_ReadDictionaryThread != nullptr) && !m_ReadDictionaryThread->isRunning())
    {
        delete m_ReadDictionaryThread;
        m_ReadDictionaryThread = nullptr;
    }

    if((m_ReadWordThread != nullptr) && !m_ReadWordThread->isRunning())
    {
        delete m_ReadWordThread;
        m_ReadWordThread = nullptr;
    }
}
