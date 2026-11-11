#ifndef READWORD_H
#define READWORD_H

#include <QObject>
#include <QThread>
#include "Common/common.h"
#include <QDebug>
#include <QFileInfo>
#include <QSemaphore>
#include "SqlDataBase.h"

#define DARK_LOG_TYPE   (0x000000007fu)
#define SINGLEBYTEMAX   0x0500
#define DOUBLEBYTEMAX   0x0A00
#define FOURBYTE_MAX    0x0F00
#define ARRBYTE_MAX     0x1400

#define APP_SINGLEBYTE_MIN 0x2000   /* 2024-7-30 修改为 0x2000 应用修改了单字节的范围 */
#define APP_SINGLEBYTE_MAX 0x2500
#define APP_DOUBLEBYTE_MAX 0x2a00
#define APP_FOURBYTE_MAX   0x2f00
#define APP_ARRBYTE_MAX    0x3400

#define ONCE_LOG_MAX_LEN   (1024u)
#define DARKLOG_CYCLE 0X55
#define DARKLOG_ABORT 0XAA

#define DEBUG_SWITCH  (0)

#define PROGRESS_BAR_SPEED (80)

#define ProgressBar_Init "QProgressBar::chunk {background-color: rgb(255, 170, 0);border-radius:6px;}\
                          QProgressBar{background: rgb(170, 170, 127);text-align: center;border-radius:6px;}"
#define ProgressBar_Success "QProgressBar::chunk {background-color: rgb(0, 255, 0);border-radius:6px;}\
                          QProgressBar{background: rgb(170, 170, 127);text-align: center;border-radius:6px;}"
#define ProgressBar_Fail "QProgressBar::chunk {background-color: rgb(255, 0, 0);border-radius:6px;}\
                          QProgressBar{background: rgb(170, 170, 127);text-align: center;border-radius:6px;}"

extern QString fileTarget;

#define BOARD_NUM 48
#define BUF_LEN   1024 * 20

class ReadWord : public QThread
{
    Q_OBJECT
public:
    ReadWord();
    ~ReadWord();

public:
    t_dictionaries * m_AnalysisDic;                     /* 本次解析使用的字典 */
    uint64_t m_u64CutFileNum;                           /* 文件分割分辨率 */
    QList<STRU_SPECIAL_ATTICATION> m_SpecialAttentionLogList;      /* 特殊关注日志 */
    QString m_CurrentBoardType;                         /* 当前解析的板卡类型 */
    QStringList t_FileList;                             /* 所有待解析的文件 */
    QStringList m_TimeList;                             /* 日志时间 */
    bool m_AnalysisAppLogSwitch = false;                /* 解析应用日志开关 */
    bool m_SpecialConfigSwitch = false;                 /* 特殊关注项开关 */
    bool m_SpecialConfigFileInitFlag = false;           /* 特殊日志文件初始化标志 */
    bool m_CCBTimeStampSwitch = false;                  /* 通控日志时间戳开关 */
    QFile *m_SpecialAttentionFile;                      /* 特殊关注项存储文件 */
    QString m_SpecialAttentionFilePath;                 /* 特殊关注项存储文件路径 */
    QString m_LogFilePathBeforeAnalysis;                /* 当前解析前文件的路径 */
    QString m_LogFilePathAfterAnalysis;                 /* 当前解析后文件的路径 */
    QString m_ErrorLogFilePath;                         /* 错误日志输出文件路径 */

    void Log_Printf(const char *message, ...);
    bool MainAnslysis(const QString &t_srcFileName);    /* 解析线程主任务 */
    QString GetLogLevel(uint8_t t_u8LogLevel);          /* 获取日志级别 */
    bool AnlaysisOnceDarkLog(uint8_t *t_u8DataBuf, uint16_t t_u16DataBufLen, STRU_LOG_MESSAGE * t_LogMessage, uint16_t t_LogLen);                                      /* 单个暗文日志解析 */
    uint16_t AnlaysisOncePackDarkLog(uint8_t *t_u8DataBuf, uint16_t t_u16DataBufLen, STRU_LOG_MESSAGE * t_LogMessage, QString * t_StrOnePackInfo);  /* 单包暗文日志解析 */
    QString MakeNewFileName();                                          /* 创建一个新文件名 */
    void DeleteSameNameFile(QString filePath);                          /* 删除同名文件 */
    void SpecialAtticationLogFileInit();                                /* 特殊关注项日志存储文件初始化 */
    void SpecialAtticationLogOutPut(STRU_LOG_MESSAGE * t_LogMessage);   /* 特殊关注项日志输出到特殊关注项日志存储文件 */
    bool DarkLogAnslysis(uint8_t * buf, uint64_t bufLen);               /* 暗文日志解析任务*/
    bool DownLogAnalysis(uint8_t * buf, uint64_t bufLen, QByteArray allData, const QString &FilePath);      /* 宕机日志解析任务 */
    void ErrorLogOutPut(QString t_SrcFilePath, uint64_t t_u64Index, uint8_t * t_u8DataBuf, uint16_t t_u16DataBufLen);   /* 错误日志输出到文件 */
    void SpecialAttentionJudge(STRU_LOG_MESSAGE * t_LogMessage);
    QString GetBoardTypeFromFilePath(QString t_StrFilePath);
    QString U32ConvertStr8(uint32_t t_u32Data);
    QString U32ConvertStr6(uint32_t t_u32Data);
    QString U16HexConvertStr4(uint16_t t_u16HexData);
    QString U8HexConvertStr2(uint8_t t_u8HexData);
    bool SDLOG_Analysis(uint8_t * buf, uint64_t bufLen);
    void SDLOG_Convert(uint8_t * t_u8SrcBuf, uint32_t t_u32SrcBufLen, uint8_t * t_u8DestBuf, uint32_t * t_u32DestBufLen);
    QString removeTrailingZeros(const QString &str);
    QString arrayToIPv4String(const uint8_t* data, uint16_t length);
private:
    common *mycommon;       /* 公共库对象 */

protected:
    void run();

signals:
    void Signal_OnceFileBarSetValue(int value,const QString& styleSheet);       /* 设置单文件进 信号 */
    void Signal_AllFileBarSetValue(int value, const QString& styleSheet);       /* 设置所有文件的进度 信号 */
    void Signal_AnalysisOver(bool);                                             /* 解析结束 信号 */
    void Signal_MessageBoxShow(bool mode, const QString &message);              /* 显示弹窗信号 */
    void Signal_BrowserLogShow(QString t_LogStr);                               /* 日志显示信号 */
};

#endif // READWORD_H