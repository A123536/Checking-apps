#include "readword.h"
#include "BoardIdentity.h"
#include <QDir>
#include <QDateTime>

QString fileTarget;//目标文件地址
QString onePlaintext;//文本字符串
uint32_t Periodnumber=0;  //周期号
static int filename_count = 1;

extern t_dictionaries dictionarArrInfo_PLFM[CODEINFOANDTYMAX];
extern t_dictionaries dictionarArrInfo_CCB[CODEINFOANDTYMAX];
extern t_dictionaries dictionarArrInfo_RCD[CODEINFOANDTYMAX];

ReadWord::ReadWord()
{
    mycommon = new common();
    m_ErrorLogFilePath = QDir::currentPath() + "/ErrorData";
}

ReadWord::~ReadWord()
{
    ;
}

void ReadWord::Log_Printf(const char *message, ...)
{
//    va_list ap;
//    va_start(ap, message);

//    QString result = QString::vasprintf(message, ap);
//    qDebug()<<result;
//    va_end(ap);

//    //emit Signal_BrowserLogShow(result);
}

void ReadWord::run()
{
    const QString &t_srcFileName = fileTarget;
    QString t_FileName;
    t_FileName = t_srcFileName;
    t_FileName = t_FileName.remove(0, t_FileName.lastIndexOf('/') + 1);
    uint16_t t_u16FileNumBarValue = 0u;
    bool t_RetValue = false;
    for(uint16_t index = 0u; index < t_FileList.count(); index++)
    {
        /* 所有文件的进度 */
        t_u16FileNumBarValue = (index * 100) / t_FileList.count();
        emit Signal_AllFileBarSetValue(t_u16FileNumBarValue, ProgressBar_Init);

        fileTarget = t_FileList.at(index);
        if(fileTarget.contains("CCB", Qt::CaseInsensitive))
        {
            m_AnalysisDic = dictionarArrInfo_CCB;
        }
        else if(fileTarget.contains("RCD", Qt::CaseInsensitive))
        {
            m_AnalysisDic = dictionarArrInfo_RCD;
        }
        else
        {
            m_AnalysisDic = dictionarArrInfo_PLFM;
        }

        m_CurrentBoardType = GetBoardTypeFromFilePath(fileTarget);
        m_LogFilePathBeforeAnalysis = fileTarget;
        m_SpecialAttentionFilePath = QDir::currentPath() + "/" + m_CurrentBoardType + ".log";
        t_RetValue = MainAnslysis(fileTarget);
    }
    if(t_RetValue)
    {
        emit Signal_AllFileBarSetValue(100, ProgressBar_Success);
    }
    else
    {
        emit Signal_AllFileBarSetValue(100, ProgressBar_Fail);
    }
    if(m_SpecialConfigFileInitFlag)
    {
        m_SpecialAttentionFile->close();
    }
    Signal_AnalysisOver(t_RetValue);
    quit();
}

bool ReadWord::MainAnslysis(const QString &t_srcFileName)
{
    QFile file(t_srcFileName);
    QString t_FileName;
    QByteArray  t_allData;
    uint8_t *dataBuf;
    uint64_t t_allDataLen;
    uint32_t t_logType = 0u;
    t_FileName = t_srcFileName;
    t_FileName = t_FileName.remove(0, t_FileName.lastIndexOf('/') + 1);
    bool t_RetValue = false;
    m_SpecialConfigFileInitFlag = false;
    if(!file.open(QIODevice::ReadOnly))
    {
        qDebug() << "Open Log File Error, FileName : " <<t_FileName;
        return false;
    }
    else
    {
        qDebug() << "Open Log File Success, FileName : " <<t_FileName;
    }

    t_allData = file.readAll();                      /* 读出日志文件全部数据 */
    t_allDataLen = t_allData.size();                 /* 获取日志文件的大小 */

    dataBuf = new  uint8_t[t_allDataLen];            /* 将数据拷贝到Buf */
    memcpy(dataBuf,t_allData,t_allDataLen);

    file.close();

    t_logType = mycommon->LongFromChar(&dataBuf[0]);

    if(DARK_LOG_TYPE == t_logType || t_FileName.contains("Abnormal"))                   /* 暗文日志 */
    {
        t_RetValue = DarkLogAnslysis(&dataBuf[0], t_allDataLen);
    }
    else                                             /* 宕机日志 */
    {
        if(t_FileName.contains("CIPH"))              /* SD卡暗文日志 */
        {
            t_RetValue = SDLOG_Analysis(&dataBuf[0], t_allDataLen);
        }
        else
        {
            t_RetValue = DownLogAnalysis(&dataBuf[0], t_allDataLen, t_allData, t_srcFileName);
        }
    }

    delete dataBuf;

    return t_RetValue;
}

void ReadWord::SpecialAtticationLogFileInit()
{
    QString t_StrFilePath = m_SpecialAttentionFilePath;
    m_SpecialAttentionFile = new QFile();
    m_SpecialAttentionFile->setFileName(t_StrFilePath);

    if(m_SpecialAttentionFile->open(QFile::ReadWrite | QFile::Append))
    {

    }
    else
    {
        qDebug()<<"SpecialAtticationLogFileInit Error";
    }
}

void ReadWord::SpecialAtticationLogOutPut(STRU_LOG_MESSAGE * t_LogMessage)
{
    if(!m_SpecialConfigFileInitFlag)
    {
        SpecialAtticationLogFileInit();
        m_SpecialConfigFileInitFlag = true;
    }
    QTextStream currentFileStream(m_SpecialAttentionFile);
    QString t_StrLogMessage = m_LogFilePathAfterAnalysis + "\n" + t_LogMessage->t_StrMessageCode + "," + t_LogMessage->t_StrMessageCodeType + "," + t_LogMessage->t_StrMessageData + "," + t_LogMessage->t_StrMessageDataInfo + "\n";
    currentFileStream<<t_StrLogMessage;
}

bool ReadWord::DarkLogAnslysis(uint8_t * buf, uint64_t bufLen)
{
    QString t_tableHead = "消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n";
    QString currentFileName;                        /* 当前输出文件名 */
    QFile currentFile;                              /* 当前输出文件 */
    QTextStream currentFileStream(&currentFile);    /* 输出文件流 */

    uint64_t t_dataBufLen = 0u;                     /* 容器长度 */
    uint64_t t_dataBufIndex = 0u;                   /* 容器索引 */
    uint32_t t_logType = 0u;                        /* 日志类型 */
    uint16_t t_currentPackLen = 0u;                 /* 当前包暗文日志的长度 */
    uint16_t t_boardType = 0u;                      /* 板卡类型 */
    uint16_t t_currentLine = 0u;                    /* 当前文件行数 */
    static uint64_t s_currentFileLine = 1u;

    bool t_RunFlag = true;
    uint16_t t_u16PackLen = 0u;
    uint32_t t_u32PackNum = 0u;                     /* 包序列号 */
    uint8_t  t_u8Flag     = 0u;                     /* 起始结束符 */
    uint8_t t_tmpBuf[1024 *2];                      /* 单包暗文日志暂存Buf */
    uint16_t t_u16TempBufLen = 0u;                  /* 单包暗文日志暂存Buf长度 */
    uint16_t t_u16CurrentAnalysisPackNum = 0u;      /* 当前已解包数，控制进度条速度 */
    bool t_RetValue = true;                         /* 函数返回值 */
    STRU_LOG_MESSAGE t_LogMessage;                  /* 日志消息 */
    QString t_OneLineStr;                           /* 一行日志的字符 */
    QString t_OneFileStr;                           /* 一个日志文件的所有字符 */
    if((buf == NULL) || (bufLen == 0u))             /* 入参防空 */
    {
        ;
    }
    else
    {
        /* 创建第一个文件 */
        currentFileStream.setCodec("GB18030");          /* 设置字节编码，防止中文乱码 */
        currentFileName = MakeNewFileName();            /* 获取新文件名 */
        currentFile.setFileName(currentFileName);       /* 文件名绑定文件 */
        if(currentFile.open(QFile::ReadWrite | QFile::Truncate))    /* 以读写方式，覆盖写入打开文件 */
        {
            qDebug()<<currentFileName << "open success";
        }
        else
        {
            qDebug()<<currentFileName << "open error";
        }

        if(m_CCBTimeStampSwitch)
        {
            t_tableHead = "时间戳,消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n";
        }
        currentFileStream<<t_tableHead;                 /* 文件写入表头 */

        memset(t_tmpBuf, 0, sizeof(t_tmpBuf));          /* 单包暂存Buf清空 */

        QVector<uint8_t>  dataBuf(bufLen);              /* 全部数据转入容器类 */
        for (uint32_t i = 0; i < bufLen; i++)
        {
            dataBuf[i] = buf[i];
        }

        t_dataBufLen = bufLen;                          /* 容器长度赋值 */

        while(t_RunFlag && (t_dataBufLen > t_dataBufIndex))
        {
            t_logType = mycommon->LongFromChar(&dataBuf[t_dataBufIndex]);
            if(DARK_LOG_TYPE == t_logType)              /* 本包数据为暗文日志 */
            {
                t_dataBufIndex = t_dataBufIndex + 4u;
                t_u16PackLen = mycommon->ShortFromChar(&dataBuf[t_dataBufIndex]);       /* 包长度 */
                t_dataBufIndex += 2u;
#if (DEBUG_SWITCH == 1u)
                qDebug("t_u16PackLen = 0x%04x", t_u16PackLen);
#endif
                t_boardType = mycommon->ShortFromChar(&dataBuf[t_dataBufIndex]);        /* 板卡ID */
                t_dataBufIndex += 2u;
#if (DEBUG_SWITCH == 1u)
                qDebug("t_boardType = 0x%04x", t_boardType);
#endif
                t_u8Flag = dataBuf[t_dataBufIndex];                                     /* 起始符 */
                t_dataBufIndex += 1u;
#if (DEBUG_SWITCH == 1u)
                qDebug("t_u8Flag = 0x%02x", t_u8Flag);
#endif
                /* 包头校验-0xff */
                if(0xffu == t_u8Flag)
                {
                    t_u32PackNum = mycommon->LongFromChar(&dataBuf[t_dataBufIndex]);        /* 序列号 */
                    t_dataBufIndex += 4u;
                    t_OneLineStr.append("包序号: " + QString::number(t_u32PackNum, 10) + "\n");
#if (DEBUG_SWITCH == 1u)
                    qDebug("t_u32PackNum = 0x%08x", t_u32PackNum);
#endif
                    t_currentPackLen = mycommon->ShortFromChar(&dataBuf[t_dataBufIndex]);   /* 包长度 */
                    t_dataBufIndex += 2u;
#if (DEBUG_SWITCH == 1u)
                    qDebug("t_currentPackLen = 0x%04x", t_currentPackLen);
#endif
                    /* 包长度校验 */
                    if(t_u16PackLen != (t_currentPackLen + 2u))
                    {
                        qDebug("Pack len error\r\n");
                    }
                    else
                    {
                        /* 包尾校验-0xfe */
                        t_u8Flag = dataBuf[t_dataBufIndex + t_currentPackLen - 1u - 2u - 4u - 1u];          /* 结束符 */
#if (DEBUG_SWITCH == 1u)
                        qDebug("t_u8Flag = 0x%02x", t_u8Flag);
#endif
                        if(0xfeu == t_u8Flag)
                        {
                            /* CCB 和 RCD 日志包不带周期号信息 */
                            if(("CCB" == m_CurrentBoardType) || ("RCD" == m_CurrentBoardType))
                            {
                                t_u16TempBufLen = t_currentPackLen - 1u - 4u - 2u - 1u;
                            }
                            else
                            {
                                t_dataBufIndex += 6u; // skip redundant packet-header metadata
                                // Packet-header metadata is not an OPB execution cycle.
                                // Only the decoded 0x0A1A event establishes that cycle.

                                t_u16TempBufLen = t_currentPackLen - 1u - 4u - 2u - 2u - 4u - 1u;
                            }
                            memcpy(t_tmpBuf, &dataBuf[t_dataBufIndex], t_u16TempBufLen);
                            t_currentLine = AnlaysisOncePackDarkLog(t_tmpBuf, t_u16TempBufLen, &t_LogMessage, &t_OneLineStr);  /* 解包执行 */
                            if(0xffffu == t_currentLine)
                            {
                                qDebug("AnlaysisOncePackDarkLog Error\r\n");
                                t_RetValue = false;
                                t_RunFlag = 0u;
                                ErrorLogOutPut(m_LogFilePathBeforeAnalysis, t_dataBufIndex, t_tmpBuf, t_u16TempBufLen);
                            }
                            else
                            {
                                t_OneFileStr.append(t_OneLineStr);
                                t_OneLineStr.clear();
                                s_currentFileLine = s_currentFileLine + t_currentLine;
                            }
                            t_dataBufIndex += t_u16TempBufLen + 1u;
                        }
                        else
                        {
                            qDebug("No 0xFE\r\n");
                        }
                    }
                }
                else
                {
                    qDebug("No 0xFF\r\n");
                }
            }
            else if(currentFileName.contains("Abnormal"))
            {
                /* 板卡ID */
                t_dataBufIndex += 2u;
                /* CPU-ID */
                t_dataBufIndex += 1u;
                /* 日志类型（后续可能有明文） */
                t_dataBufIndex += 1u;
                /* 运行阶段 */
                t_dataBufIndex += 1u;
                /* 数据长度 */
                t_u16TempBufLen = mycommon->ShortFromChar(&dataBuf[t_dataBufIndex]);
                t_dataBufIndex += 2u;
                /* 数据内容 */
                memcpy(t_tmpBuf, &dataBuf[t_dataBufIndex], t_u16TempBufLen);
                t_currentLine = AnlaysisOncePackDarkLog(t_tmpBuf, t_u16TempBufLen, &t_LogMessage, &t_OneLineStr);  /* 解包执行 */
                if(0xffffu == t_currentLine)
                {
                    Log_Printf("AnlaysisOncePackDarkLog Error\r\n");
                    t_RetValue = false;
                    t_RunFlag = 0u;
                    ErrorLogOutPut(m_LogFilePathBeforeAnalysis, t_dataBufIndex, t_tmpBuf, t_u16TempBufLen);
                }
                else
                {
                    t_OneFileStr.append(t_OneLineStr);
                    t_OneLineStr.clear();
                    s_currentFileLine = s_currentFileLine + t_currentLine;
                }
                t_dataBufIndex += t_u16TempBufLen;
            }
            else
            {
                t_dataBufIndex = t_dataBufIndex + 4u;
                qDebug("No 0x7F\r\n");
            }
#if (DEBUG_SWITCH == 1u)
            qDebug()<<"t_dataBufIndex = "<<t_dataBufIndex;
#endif
            /* 解n包数据后发送进度，控制进度条的速度，避免界面过于卡顿 */
            if(PROGRESS_BAR_SPEED == t_u16CurrentAnalysisPackNum)
            {
                emit Signal_OnceFileBarSetValue(((t_dataBufIndex * 100) / t_dataBufLen), ProgressBar_Init);
                t_u16CurrentAnalysisPackNum = 0u;
            }
            t_u16CurrentAnalysisPackNum += 1u;

            if(t_OneFileStr.size() > 0)
            {
                if(m_u64CutFileNum <= s_currentFileLine)
                {
                    currentFile.close();

                    currentFileName = MakeNewFileName();
                    currentFile.setFileName(currentFileName);
                    if(currentFile.open(QFile::ReadWrite | QFile::Truncate))
                    {
                        qDebug("%s open success\r\n", currentFileName.toStdString());
                    }
                    else
                    {
                        qDebug("%s open error\r\n", currentFileName.toStdString());
                    }
                    currentFileStream<<t_tableHead;

                    currentFileStream<<t_OneFileStr;
                    s_currentFileLine = 1u;
                }
                else
                {
                    currentFileStream<<t_OneFileStr;
                }
                t_OneFileStr.clear();
            }
            else
            {
                ;
            }
        }
        qDebug("Analysis Over\r\n");
    }

    /*剩余不足200数据*/
    if(t_OneFileStr.size() > 0)
    {
        currentFileStream<<t_OneFileStr;
        t_OneFileStr.clear();
        currentFile.close();
    }
    else
    {
        currentFile.close();
    }
    s_currentFileLine = 1u;
    filename_count = 1;

    if(t_RetValue)
    {
        emit Signal_OnceFileBarSetValue(100, ProgressBar_Success);
    }
    else
    {
        emit Signal_OnceFileBarSetValue(100, ProgressBar_Fail);
    }

    return t_RetValue;
}
bool ReadWord::SDLOG_Analysis(uint8_t * buf, uint64_t bufLen)
{
    bool t_RetValue = true;
    QString t_tableHead = "消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n";
    QString currentFileName;                        /* 当前输出文件名 */
    QFile currentFile;                              /* 当前输出文件 */
    QTextStream currentFileStream(&currentFile);    /* 输出文件流 */
    uint16_t t_currentLine = 0u;                    /* 当前文件行数 */
    static uint64_t s_currentFileLine = 1u;
    STRU_LOG_MESSAGE t_LogMessage;                  /* 日志消息 */
    QString t_OneLineStr;                           /* 一行日志的字符 */
    QString t_OneFileStr;                           /* 一个日志文件的所有字符 */
    uint8_t t_u8AfterConvertLogBuf[1024 * 1024];
    uint32_t t_u32AfterConvertLogBufLen = 0u;
    currentFileStream.setCodec("GB18030");          /* 设置字节编码，防止中文乱码 */
    currentFileName = MakeNewFileName();
    currentFile.setFileName(currentFileName);       /* 文件名绑定文件 */
    if(currentFile.open(QFile::ReadWrite | QFile::Truncate))    /* 以读写方式，覆盖写入打开文件 */
    {
        qDebug()<<currentFileName<<"open success";
    }
    else
    {
        qDebug()<<currentFileName<<"open error";
    }
    uint32_t t_u32SrcBufSize = bufLen;
    SDLOG_Convert(buf, t_u32SrcBufSize, t_u8AfterConvertLogBuf, &t_u32AfterConvertLogBufLen);
    currentFileStream<<t_tableHead;
    t_currentLine = AnlaysisOncePackDarkLog(t_u8AfterConvertLogBuf, t_u32AfterConvertLogBufLen, &t_LogMessage, &t_OneLineStr);
    t_OneFileStr.append(t_OneLineStr);
    if(0xffffu == t_currentLine)
    {
        qDebug()<<"AnlaysisOncePackDarkLog error";
        t_RetValue = false;
        ErrorLogOutPut(m_LogFilePathBeforeAnalysis, 0, t_u8AfterConvertLogBuf, t_u32AfterConvertLogBufLen);
    }
    s_currentFileLine = s_currentFileLine + t_currentLine + 1u;
    if(t_OneFileStr.size() > 0)
    {
        currentFileStream<<t_OneFileStr;
        t_OneFileStr.clear();
    }
    currentFile.close();

    return t_RetValue;
}
/* 宕机日志
参数: uint8_t * buf: 存放数组(int型)(包含帧头)
     uint64_t bufLen: 数组长度
     QByteArray allData:存放数组(QByteArray型)   用于宕机-明文
     const QString &FilePath:文件路径   用于宕机-明文
*/
bool ReadWord::DownLogAnalysis(uint8_t * buf, uint64_t bufLen, QByteArray allData, const QString &FilePath)
{
    uint16_t t_boardType = 0u;                      /* 板卡类型 */

    uint8_t t_tmpBuf[1024 *2];                      /* 单包暗文日志暂存Buf */
    uint64_t t_dataBufLen = 0u;                     /* 容器长度 */
    QString t_tableHead = "消息类型,消息编码,消息编码解释,消息内容(16进制),消息内容解释\n";
    uint8_t *t_clearTxt;
    uint8_t *t_darkTxt;
    uint8_t t_clearFlag = 0;
    uint8_t t_darkFlag = 0;
    uint64_t t_clearLen = 0;
    uint64_t t_darkLen = 0;

    bool t_RetValue = true;
    uint64_t index = 0;
    uint64_t i_all = 0u;
    uint32_t bordId = 0u;
    uint16_t cpuId = 0u;
    uint16_t type = 0u;
    uint16_t stage = 0u;
    uint32_t len = 0u;
    uint16_t t_currentLine = 0u;                    /* 当前文件行数 */
    static uint64_t s_currentFileLine = 1u;
    STRU_LOG_MESSAGE t_LogMessage;                  /* 日志消息 */
    QString t_OneLineStr;                           /* 一行日志的字符 */
    QString t_OneFileStr;                           /* 一个日志文件的所有字符 */
    QString t_StrFilePath = FilePath;
    t_clearTxt = new  uint8_t[bufLen];
    t_darkTxt = new  uint8_t[bufLen];


    if(fileTarget != nullptr)
    {

    }
    else
    {
        qDebug()<<"输出地址失败";
    }
    while(index < bufLen)
    {
        qDebug() << buf[3 + index] << "buf[3+index]-----------" << endl;
        bordId = mycommon->ShortFromChar(&buf[index]);
        cpuId = buf[index+2];
        type = buf[index+3];
        stage = buf[index+4];
        len = mycommon->ShortFromChar(&buf[index+5]);


        qDebug() << "len = " << len;
        if(buf[3 + index] == 85)           //宕机文档之明文 0x55
        {
            memcpy(&t_clearTxt[t_clearLen], &buf[index+7], len);
            index = index + len + 7;
            t_clearFlag = 1u;
            t_clearLen = t_clearLen + len;
        }
        else if(buf[3 + index] == 170)      //宕机文档之暗文 0xAA
        {
            memcpy(&t_darkTxt[t_darkLen], &buf[index+7], len);
            index = index + len + 7;
            t_darkFlag = 1u;
            t_darkLen = t_darkLen + len;
        }
    }

    if(buf[4] == 0x55)
    {
        t_StrFilePath.append("上电");
    }
    else if(buf[4] == 0xaa)
    {
        t_StrFilePath.append("宕机");
    }
    else
    {
        ;
    }

    if(1u == t_clearFlag)
    {
        QFile txtFile(t_StrFilePath + ".txt");  //创建txt文档
        /* 往txt文件里写入数据*/
        if(!txtFile.open(QFile::ReadWrite | QIODevice::Text | QIODevice::Append))   // QFile::Append
        {
            qDebug() << "写入失败";
            emit Signal_MessageBoxShow(false, "文件写入失败");
            return false;
        }
        txtFile.write((char *)t_clearTxt, t_clearLen);
        txtFile.close();
    }
    if(1u == t_darkFlag)
    {
        QString currentFileName;                        /* 当前输出文件名 */
        QFile currentFile;                              /* 当前输出文件 */
        QTextStream currentFileStream(&currentFile);    /* 输出文件流 */
        m_LogFilePathAfterAnalysis = t_StrFilePath;
        currentFileStream.setCodec("GB18030");          /* 设置字节编码，防止中文乱码 */
        currentFileName = t_StrFilePath + ".csv";    /* 获取新文件名 */
        currentFile.setFileName(currentFileName);       /* 文件名绑定文件 */
        if(currentFile.open(QFile::ReadWrite | QFile::Truncate))    /* 以读写方式，覆盖写入打开文件 */
        {
            qDebug()<<currentFileName<<"open success";
        }
        else
        {
            qDebug()<<currentFileName<<"open error";
        }
        currentFileStream<<t_tableHead;
        t_currentLine = AnlaysisOncePackDarkLog(t_darkTxt,t_darkLen, &t_LogMessage, &t_OneLineStr);
        t_OneFileStr.append(t_OneLineStr);
        if(0xffffu == t_currentLine)
        {
            qDebug()<<"AnlaysisOncePackDarkLog error";
            t_RetValue = false;
            ErrorLogOutPut(m_LogFilePathBeforeAnalysis, 0, t_darkTxt, t_darkLen);
        }
        s_currentFileLine = s_currentFileLine + t_currentLine + 1u;
        if(t_OneFileStr.size() > 0)
        {
            currentFileStream<<t_OneFileStr;
            t_OneFileStr.clear();
        }
        currentFile.close();
    }

    filename_count = 1;
    //QMessageBox::information(NULL, "解析结果", "解析完成");
    qDebug()<<"Success";
    if(t_RetValue)
    {
        emit Signal_OnceFileBarSetValue(100, ProgressBar_Success);
    }
    else
    {
        emit Signal_OnceFileBarSetValue(100, ProgressBar_Fail);
    }
    return t_RetValue;
}

/* 创建新文件写入，解决EXCLE最大显示 */
QString ReadWord::MakeNewFileName()
{
    QString fileName = fileTarget;

    //fileName = fileName + QString::number(filename_count);
    fileName = fileName + QString::number(filename_count) + ".csv";

    filename_count++;

    qDebug()<< fileName;

    DeleteSameNameFile(fileName);

    m_LogFilePathAfterAnalysis = fileName;

    return fileName;
}

void ReadWord::DeleteSameNameFile(QString filePath)
{
    QFileInfo myFileInfo(filePath);
    if(myFileInfo.exists())
    {
        qDebug()<< filePath << "is exists";
        qDebug()<<QFile::remove(filePath);
    }
}

QString ReadWord::GetLogLevel(uint8_t t_u8LogLevel)
{
    QString t_RetValue;
    switch(t_u8LogLevel)
    {
        case 0:t_RetValue = "错误";break;
        case 1:t_RetValue = "警告";break;
        case 2:t_RetValue = "提示";break;
        case 3:t_RetValue = "调试";break;
        default:t_RetValue = "未知";break;
    }
    return t_RetValue;
}

bool ReadWord::AnlaysisOnceDarkLog(uint8_t *t_u8DataBuf, uint16_t t_u16DataBufLen, STRU_LOG_MESSAGE * t_LogMessage, uint16_t t_LogLen)
{
    bool t_RetValue = false;
    uint16_t t_u16LogMessageCode = 0u;      /* 日志编码             例: 0xce01 */
    uint16_t t_u16DataBufIndex = 0u;    /* t_u8DataBuf的索引 */
    uint16_t t_u16LogCodeLen = 0u;
    t_u16LogCodeLen = t_LogLen;

    t_u16LogMessageCode = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
    t_u16DataBufIndex += 2u;
    t_u16LogMessageCode = t_u16LogMessageCode & 0x3FFF;
    //qDebug("0x%04x, len = %d", t_u16LogMessageCode, t_u16DataBufLen - 2);
    switch (t_u16LogCodeLen)
    {
        case 1u:
        {
            if(NOESCAPE == m_AnalysisDic[t_u16LogMessageCode].specialDeal[0])
            {
                t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
                t_LogMessage->t_StrMessageData     = U8HexConvertStr2(t_u8DataBuf[2]);
                t_LogMessage->t_StrMessageDataInfo = QString::number(t_u8DataBuf[2], 10);
                t_RetValue = true;
            }
            else if(SCAPE == m_AnalysisDic[t_u16LogMessageCode].specialDeal[0])
            {
                for(uint16_t index = 0u; index <= m_AnalysisDic[t_u16LogMessageCode].atValueNum; index++)
                {
                    if(t_u8DataBuf[2] == m_AnalysisDic[t_u16LogMessageCode].value_MSCT_u8[index])
                    {
                        t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
                        t_LogMessage->t_StrMessageData     = U8HexConvertStr2(t_u8DataBuf[2]);
                        t_LogMessage->t_StrMessageDataInfo = m_AnalysisDic[t_u16LogMessageCode].info_MSCT[index];
                        t_RetValue = true;
                    }
                }
                if(false == t_RetValue)
                {
                    t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
                    t_LogMessage->t_StrMessageData     = U8HexConvertStr2(t_u8DataBuf[2]);
                    t_LogMessage->t_StrMessageDataInfo = "未知";
                    t_RetValue = true;
                }
            }
            else
            {
                t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
                uint16_t t_u16LogMessageData = t_u8DataBuf[2];
                t_LogMessage->t_StrMessageData = U8HexConvertStr2(t_u16LogMessageData);
                t_LogMessage->t_StrMessageDataInfo = QString::number(t_u16LogMessageData, 10);
                t_RetValue = true;
            }
            break;
        }
        case 2u:
        {
            t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
            uint16_t t_u16LogMessageData = mycommon->ShortFromChar(&t_u8DataBuf[2]);
            QString t_StrMessageData;
            for(uint16_t index = 0u; index < 2u; index++)
            {
                t_StrMessageData.append(U8HexConvertStr2(t_u8DataBuf[2 + index]) + " ");
            }
            t_LogMessage->t_StrMessageData = t_StrMessageData;
            t_LogMessage->t_StrMessageDataInfo = QString::number(t_u16LogMessageData, 10);
            t_RetValue = true;
            break;
        }
        case 4u:
        {
            t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
            uint32_t t_u32LogMessageData = mycommon->LongFromChar(&t_u8DataBuf[2]);
            QString t_StrMessageData;
            for(uint16_t index = 0u; index < 4u; index++)
            {
                t_StrMessageData.append(U8HexConvertStr2(t_u8DataBuf[2 + index]) + " ");
            }
            t_LogMessage->t_StrMessageData = t_StrMessageData;
            t_LogMessage->t_StrMessageDataInfo = QString::number(t_u32LogMessageData, 10);
            t_RetValue = true;
            break;
        }
        case 0xffffu:
        {
            t_LogMessage->t_StrMessageCodeType = m_AnalysisDic[t_u16LogMessageCode].interpret_MSCT;
            QString t_StrMessageDataInfo;
            for(uint16_t index = 0u; index < t_u16DataBufLen - 2u; index++)
            {
                t_StrMessageDataInfo.append(U8HexConvertStr2(t_u8DataBuf[2 + 2 + index]) + " ");
            }
            /* 通控/记录板对IP这类字段的特殊处理 */
            if(("CCB" == m_CurrentBoardType) || ("RCD" == m_CurrentBoardType))
            {
                if(t_LogMessage->t_StrMessageCodeType.contains("ip", Qt::CaseInsensitive))
                {
                    t_LogMessage->t_StrMessageData = arrayToIPv4String(&t_u8DataBuf[2 + 2], 4u);
                }
                else
                {
                    t_LogMessage->t_StrMessageData = "";
                }
            }
            else
            {
                t_LogMessage->t_StrMessageData = "";
            }
            t_LogMessage->t_StrMessageDataInfo = t_StrMessageDataInfo;
            t_RetValue = true;
            break;
        }
        case 0xfffeu:
        {
            t_LogMessage->t_StrMessageCodeType = "明文日志";
            QString t_StrMessageDataInfo;
            for(uint16_t index = 0u; index < t_u16DataBufLen - 2u; index++)
            {
                t_StrMessageDataInfo.append(t_u8DataBuf[2 + 2 + index]);
            }
            t_LogMessage->t_StrMessageData     = "";
            /* 2026-04-08 去除明文日志删除末尾0的逻辑 */
            t_LogMessage->t_StrMessageDataInfo = t_StrMessageDataInfo;
            // t_LogMessage->t_StrMessageDataInfo = removeTrailingZeros(t_StrMessageDataInfo);
            t_RetValue = true;
            break;
        }
        default:t_RetValue = false;break;
    }

    return t_RetValue;
}

/* FF-FE的数据不包含FF、FE */
uint16_t ReadWord::AnlaysisOncePackDarkLog(uint8_t *t_u8DataBuf, uint16_t t_u16DataBufLen, STRU_LOG_MESSAGE * t_LogMessage, QString * t_StrOnePackInfo)
{
    uint8_t  t_u8RunFlag = 1u;          /* 运行标志位，异常时置0退出循环 */
    uint16_t t_u16RetValue = 0u;        /* 返回值，解析过后的日志行数，出错时返回0xffffu */
    uint16_t t_u16DataBufIndex = 0u;    /* t_u8DataBuf的索引 */
    QString t_StrTempOnePackInfo = "";
    bool t_AnalysisFlag = false;
    bool t_BoolRetValue = false;
    uint16_t t_u16LogMessageCodeAndLevel = 0u;  /* 日志编码             例: 0xce01 */
    uint16_t t_u16LogMessageCode         = 0u;  /* 日志编码去除日志等级   例: 0x0e01 */
    uint8_t  t_u8LogMessageLevel         = 0u;  /* 日志级别 */
    uint8_t  t_u8LogMessageInfoBuf[ONCE_LOG_MAX_LEN];       /* 日志信息暂存Buf 单字节 双字节 四字节 数组 */
    uint16_t t_u16LogMessageInfoBufLen   = 0u;              /* 日志信息暂存Buf长度 */
    uint16_t t_LogLenType = 0u;

    while(t_u8RunFlag && (t_u16DataBufIndex < t_u16DataBufLen))
    {
        /* 日志编码获取 */
        if(m_CCBTimeStampSwitch)
        {
            /* RCD 目前和 CCB 的时间戳前缀结构更接近，按同一套逻辑处理，
               只有真正不带时间戳的协议才放到非 CCB 分支。 */
            if("CCB" == m_CurrentBoardType)
            {
                uint16_t t_u16Year = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
                t_u16DataBufIndex += 2u;
                uint8_t t_u8Month = t_u8DataBuf[t_u16DataBufIndex];
                t_u16DataBufIndex += 1u;
                uint8_t t_u8Day = t_u8DataBuf[t_u16DataBufIndex];
                t_u16DataBufIndex += 1u;
                uint8_t t_u8Hour = t_u8DataBuf[t_u16DataBufIndex];
                t_u16DataBufIndex += 1u;
                uint8_t t_u8Min = t_u8DataBuf[t_u16DataBufIndex];
                t_u16DataBufIndex += 1u;
                uint8_t t_u8Sec = t_u8DataBuf[t_u16DataBufIndex];
                t_u16DataBufIndex += 1u;
                uint32_t t_u32USec = mycommon->LongFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
                t_u16DataBufIndex += 4u;
//                qDebug()<<t_u8Hour << t_u8Min << t_u8Sec << t_u32USec;
                QDateTime dateTime(QDate(t_u16Year, t_u8Month, t_u8Day), QTime(t_u8Hour, t_u8Min, t_u8Sec));
                QString t_StrTimeStamp = dateTime.toString("[yyyy-MM-dd HH:mm:ss:") + U32ConvertStr6(t_u32USec) + "]";
                t_StrTempOnePackInfo.append(t_StrTimeStamp + ",");
            }
        }
        t_u16LogMessageCodeAndLevel = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
        t_u16DataBufIndex += 2u;
        //qDebug("0x%04x", t_u16LogMessageCodeAndLevel);
        t_u16LogMessageCode = t_u16LogMessageCodeAndLevel & 0x3FFF;
        t_LogMessage->t_StrMessageCode = U16HexConvertStr4(t_u16LogMessageCode);
        /* 日志级别解析 */
        t_u8LogMessageLevel = ((t_u16LogMessageCodeAndLevel & 0xC000) >> 14);
        t_LogMessage->t_StrMessageLevel = GetLogLevel(t_u8LogMessageLevel);
#if 0
        if((0x0A59 == t_u16LogMessageCode) || (0x0A5A == t_u16LogMessageCode) || (0x0525 == t_u16LogMessageCode))
        {
            emit Signal_MessageBoxShow(false, "Error Code");
        }
#endif
        /* 日志解析 */
        if((0 < t_u16LogMessageCode) && (t_u16LogMessageCode <= SINGLEBYTEMAX))
        {
            /* 单字节 */
            t_LogLenType = 1u;
            t_u16LogMessageInfoBufLen = 1u;
            memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 2u], t_u16LogMessageInfoBufLen + 2u);
            t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
            t_AnalysisFlag = true;
        }
        else if((SINGLEBYTEMAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= DOUBLEBYTEMAX))
        {
            /* 双字节 */
            t_LogLenType = 2u;
            t_u16LogMessageInfoBufLen = 2u;
            memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 2u], t_u16LogMessageInfoBufLen + 2u);
            t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
            t_AnalysisFlag = true;
        }
        else if((DOUBLEBYTEMAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= FOURBYTE_MAX))
        {
            /* 四字节 */
            t_LogLenType = 4u;
            t_u16LogMessageInfoBufLen = 4u;
            memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 2u], t_u16LogMessageInfoBufLen + 2u);
            t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
            t_AnalysisFlag = true;
        }
        else if((FOURBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= ARRBYTE_MAX))
        {
            /* 数组类型 */
            t_LogLenType = 0xffffu;
            t_u16LogMessageInfoBufLen = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
            t_u16DataBufIndex += 2u;
            memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 4u], t_u16LogMessageInfoBufLen + 2u + 2u);
            t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
            t_AnalysisFlag = true;
        }
        else if(0x0000 == t_u16LogMessageCode)
        {
            /* 明文数组类型 */
            t_LogLenType = 0xffffeu;
            t_u16LogMessageInfoBufLen = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
            t_u16DataBufIndex += 2u;
            memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 4u], t_u16LogMessageInfoBufLen + 2u + 2u);
            t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
            t_AnalysisFlag = true;
        }
        else
        {
            /* 非平台日志 */
            if(m_AnalysisAppLogSwitch)
            {
                if((APP_SINGLEBYTE_MIN <= t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_SINGLEBYTE_MAX))
                {
                    t_LogLenType = 1u;
                    t_u16LogMessageInfoBufLen = 1u;
                    memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 2u], t_u16LogMessageInfoBufLen + 2u);
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = true;
                    /* 单字节 */
                }
                else if((APP_SINGLEBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_DOUBLEBYTE_MAX))
                {
                    t_LogLenType = 2u;
                    t_u16LogMessageInfoBufLen = 2u;
                    memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 2u], t_u16LogMessageInfoBufLen + 2u);
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = true;
                    /* 双字节 */
                }
                else if((APP_DOUBLEBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_FOURBYTE_MAX))
                {
                    t_LogLenType = 4u;
                    t_u16LogMessageInfoBufLen = 4u;
                    memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 2u], t_u16LogMessageInfoBufLen + 2u);
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = true;
                    /* 四字节 */
                }
                else if((APP_FOURBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_ARRBYTE_MAX))
                {
                    t_LogLenType = 0xffffu;
                    t_u16LogMessageInfoBufLen = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
                    t_u16DataBufIndex += 2u;
                    memcpy(t_u8LogMessageInfoBuf, &t_u8DataBuf[t_u16DataBufIndex - 4u], t_u16LogMessageInfoBufLen + 2u + 2u);
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = true;
                    /* 数组类型 */
                }
                else
                {
                    /* 非平台、应用日志 */
                    qDebug("t_u16LogMessageCodeAndLevel = 0x%04x, t_isAnalysisAppLog = %d, t_u16LogMessageCode = 0x%04x", t_u16LogMessageCodeAndLevel, m_AnalysisAppLogSwitch, t_u16LogMessageCode);
                    emit Signal_MessageBoxShow(false, "遇到无效信息编码，无法解析！");
                    t_AnalysisFlag = false;
                    t_u16RetValue = 0xffffu;
                    t_u8RunFlag = 0u;
                }
            }
            else
            {
                /* 非平台日志 */
                if((APP_SINGLEBYTE_MIN <= t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_SINGLEBYTE_MAX))
                {
                    t_u16LogMessageInfoBufLen = 1u;
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = false;
                    /* 单字节 */
                }
                else if((APP_SINGLEBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_DOUBLEBYTE_MAX))
                {
                    t_u16LogMessageInfoBufLen = 2u;
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = false;
                    /* 双字节 */
                }
                else if((APP_DOUBLEBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_FOURBYTE_MAX))
                {
                    t_u16LogMessageInfoBufLen = 4u;
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = false;
                    /* 四字节 */
                }
                else if((APP_FOURBYTE_MAX < t_u16LogMessageCode) && (t_u16LogMessageCode <= APP_ARRBYTE_MAX))
                {
                    t_u16LogMessageInfoBufLen = mycommon->ShortFromChar(&t_u8DataBuf[t_u16DataBufIndex]);
                    t_u16DataBufIndex += 2u;
                    t_u16DataBufIndex += t_u16LogMessageInfoBufLen;
                    t_AnalysisFlag = false;
                    /* 数组类型 */
                }
                else
                {
                    /* 非平台、应用日志 */
                    qDebug("t_u16LogMessageCodeAndLevel = 0x%04x, t_isAnalysisAppLog = %d, t_u16LogMessageCode = 0x%04x", t_u16LogMessageCodeAndLevel, m_AnalysisAppLogSwitch, t_u16LogMessageCode);
                    emit Signal_MessageBoxShow(false, "遇到无效信息编码，无法解析！");
                    t_AnalysisFlag = false;
                    t_u16RetValue = 0xffffu;
                    t_u8RunFlag = 0u;
                }
            }
        }
        if(t_AnalysisFlag)
        {
            t_BoolRetValue = AnlaysisOnceDarkLog(t_u8LogMessageInfoBuf, t_u16LogMessageInfoBufLen + 2u, t_LogMessage, t_LogLenType);
            if(t_BoolRetValue)
            {
                t_u16RetValue += 1u;
                if(m_SpecialConfigSwitch)
                {
                    SpecialAttentionJudge(t_LogMessage);
                }
                t_StrTempOnePackInfo.append(t_LogMessage->t_StrMessageLevel);
                t_StrTempOnePackInfo.append(",");
                t_StrTempOnePackInfo.append(t_LogMessage->t_StrMessageCode);
                t_StrTempOnePackInfo.append(",");
                t_StrTempOnePackInfo.append(t_LogMessage->t_StrMessageCodeType);
                t_StrTempOnePackInfo.append(",");
                t_StrTempOnePackInfo.append(t_LogMessage->t_StrMessageData);
                t_StrTempOnePackInfo.append(",");
                t_StrTempOnePackInfo.append(t_LogMessage->t_StrMessageDataInfo);
                t_StrTempOnePackInfo.append("\n");
            }
            else
            {
                //qDebug()<<"AnlaysisOnceDarkLog Error";
            }
        }
        else
        {
            //qDebug()<<"t_AnalysisFlag False";
        }
    }
    t_StrOnePackInfo->append(t_StrTempOnePackInfo);
    return t_u16RetValue;
}

void ReadWord::SpecialAttentionJudge(STRU_LOG_MESSAGE * t_LogMessage)
{
    bool t_isCodeAndBoardTypeSuccess = false;
    bool t_isLogTimeSuccess = false;

    for(uint16_t index = 0u; index < m_SpecialAttentionLogList.count(); index++)
    {
        /* 编码匹配 */
        if(t_LogMessage->t_StrMessageCode.contains(m_SpecialAttentionLogList.at(index).t_StrMessageCode, Qt::CaseInsensitive))
        {
            /* 文件类型 */
            if("ALL" == m_SpecialAttentionLogList.at(index).t_StrBoardType)
            {
                t_isCodeAndBoardTypeSuccess = true;
            }
            else
            {
                if(m_CurrentBoardType == m_SpecialAttentionLogList.at(index).t_StrBoardType)
                {
                    t_isCodeAndBoardTypeSuccess = true;
                }
                else
                {
                    t_isCodeAndBoardTypeSuccess = false;
                }
            }

            /* 日志时间 */
            if("ALL" == m_SpecialAttentionLogList.at(index).t_StrLogTime)
            {
                t_isLogTimeSuccess = true;
            }
            else
            {
                QFileInfo t_FileInfo(m_LogFilePathBeforeAnalysis);
                QString t_FileName = t_FileInfo.fileName();
                //qDebug()<<"t_FileName "<<t_FileName;
                if(t_FileName.contains(m_SpecialAttentionLogList.at(index).t_StrLogTime))
                {
                    t_isLogTimeSuccess = true;
                }
                else
                {
                    t_isLogTimeSuccess = false;
                }
            }
            //qDebug()<<t_isCodeAndBoardTypeSuccess << t_isLogTimeSuccess;
            if(t_isCodeAndBoardTypeSuccess && t_isLogTimeSuccess)
            {
                if("日志编码" == m_SpecialAttentionLogList.at(index).t_StrVerifyMode)
                {
                    SpecialAtticationLogOutPut(t_LogMessage);
                }
                else if("日志编码+取值" == m_SpecialAttentionLogList.at(index).t_StrVerifyMode)
                {
                    if(t_LogMessage->t_StrMessageData == m_SpecialAttentionLogList.at(index).t_StrMessageData)
                    {
                        SpecialAtticationLogOutPut(t_LogMessage);
                    }
                    else
                    {
                        ;
                    }
                }
                else
                {
                    ;
                }
            }
            else
            {
                ;/* 不需要验证 */
            }
        }
    }
}

QString ReadWord::GetBoardTypeFromFilePath(QString t_StrFilePath)
{
    const QString autoBoard = BoardIdentity::fromName(t_StrFilePath);
    if(!autoBoard.isEmpty()) return autoBoard;
    QFileInfo t_FileInfo(t_StrFilePath);
    QString t_StrFileName = t_FileInfo.fileName();
    QString t_RetValue;
    if(t_StrFileName.contains("ATP"))
    {
        t_RetValue = "ATP";
    }
    else if(t_StrFileName.contains("ATO"))
    {
        t_RetValue = "ATO";
    }
    else if(t_StrFileName.contains("CCB"))
    {
        t_RetValue = "CCB";
    }
    else if(t_StrFileName.contains("RCD"))
    {
        t_RetValue = "RCD";
    }
    else if(t_StrFileName.contains("IPB"))
    {
        t_RetValue = "IPB";
    }
    else if(t_StrFileName.contains("OPB"))
    {
        t_RetValue = "OPB";
    }
    else if(t_StrFileName.contains("SPB"))
    {
        t_RetValue = "SPB";
    }
    else
    {
        ;
    }
    return t_RetValue;
}

QString ReadWord::U32ConvertStr8(uint32_t t_u32Data)
{
    char Buf[20];
    sprintf(Buf,"%08d",t_u32Data);
    QString hexStr = QString::fromUtf8(Buf);
    return hexStr;
}

QString ReadWord::U32ConvertStr6(uint32_t t_u32Data)
{
    char Buf[20];
    sprintf(Buf,"%06d",t_u32Data);
    QString hexStr = QString::fromUtf8(Buf);
    return hexStr;
}

QString ReadWord::U16HexConvertStr4(uint16_t t_u16HexData)
{
    char Buf[20];
    sprintf(Buf,"0x%04x",t_u16HexData);
    QString hexStr = QString::fromUtf8(Buf);
    return hexStr;
}

QString ReadWord::U8HexConvertStr2(uint8_t t_u8HexData)
{
    char Buf[20];
    sprintf(Buf,"0x%02x",t_u8HexData);
    QString hexStr = QString::fromUtf8(Buf);
    return hexStr;
}

void ReadWord::ErrorLogOutPut(QString t_SrcFilePath, uint64_t t_u64Index, uint8_t * t_u8DataBuf, uint16_t t_u16DataBufLen)
{
    QFile t_File(m_ErrorLogFilePath);

    if(t_File.open(QIODevice::WriteOnly | QIODevice::Append))
    {
        QTextStream t_TextStream(&t_File);
        t_TextStream<<t_SrcFilePath;
        t_File.close();
        if(t_File.open(QIODevice::WriteOnly | QIODevice::Append))
        {
            QDataStream t_DataStream(&t_File);
            t_DataStream << 0xffffffff;
            t_DataStream << t_u64Index;
            t_DataStream << 0xeeeeeeee;
            for(uint16_t index = 0u; index < t_u16DataBufLen; index++)
            {
                t_DataStream << t_u8DataBuf[index];
            }
            t_DataStream << 0xffffffff;
            t_File.close();
        }
        else
        {
            ;
        }
    }
    else
    {
        ;
    }
}



void ReadWord::SDLOG_Convert(uint8_t * t_u8SrcBuf, uint32_t t_u32SrcBufLen, uint8_t * t_u8DestBuf, uint32_t * t_u32DestBufLen)
{
    uint16_t t_u16LogLen = 0u;
    uint32_t t_u32SrcBufIndex = 0u;
    uint32_t t_u32DestBufIndex = 0u;
    while(t_u32SrcBufIndex < t_u32SrcBufLen)
    {
        t_u16LogLen = mycommon->ShortFromChar(&t_u8SrcBuf[t_u32SrcBufIndex]);
        t_u32SrcBufIndex += 2u;
        memcpy(&t_u8DestBuf[t_u32DestBufIndex], &t_u8SrcBuf[t_u32SrcBufIndex], t_u16LogLen);
        t_u32DestBufIndex += t_u16LogLen;
        t_u32SrcBufIndex  += t_u16LogLen;
    }
    *t_u32DestBufLen = t_u32DestBufIndex;
}

QString ReadWord::removeTrailingZeros(const QString &str)
{
    QString result = str;
    while (result.endsWith('0')) {
        result.chop(1);  // 移除末尾的一个字符
    }
    return result;
}

QString ReadWord::arrayToIPv4String(const uint8_t* data, uint16_t length)
{
    if (length != 4 || data == nullptr) {
        return QString();  // 确保输入是4字节且数据有效
    }

    // 使用字符串格式化来生成IP地址字符串
    char ipStr[16];  // IPv4地址的最大长度为15字符 (xxx.xxx.xxx.xxx)
    snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);

    return QString(ipStr);  // 转换为 QString 返回
}
