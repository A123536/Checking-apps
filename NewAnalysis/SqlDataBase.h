#ifndef SQLDATABASE_H
#define SQLDATABASE_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QDebug>

#define LOG_CODE_MAX_NUM  1500
#define SCAPE          0xEF //转义
#define NOESCAPE       0x01 //不转义

#define VALUENUM 15  //目前认为相同编码对应的值最大为10
#define CODEINFOANDTYMAX 65535    //类型&信息编码最大值  0xffff

typedef struct  Dictionaries
{
    uint8_t  specialDeal[VALUENUM];
    uint8_t  value_MSCT_u8[VALUENUM]; //暗文值，针对单字节
    uint8_t  atValueNum;
    QString  info_MSCT[VALUENUM];      //信息
    QString  interpret_MSCT;      //说明
}t_dictionaries;

typedef QList<t_dictionaries>  dictionarlist;

typedef struct{
    QString t_StrMessageCode;
    QString t_StrMessageCodeType;
    QString t_StrMessageData;
    QString t_StrVerifyMode;
    QString t_StrBoardType;
    QString t_StrLogTime;
}STRU_SPECIAL_ATTICATION;

typedef struct{
    uint16_t t_u16SpecialAtticatonNum;
    STRU_SPECIAL_ATTICATION t_SpecialAtticaton[LOG_CODE_MAX_NUM];
}STRU_SPECIAL_CONFIG;

typedef struct{
    QString t_StrMessageLevel;      /* 日志等级 */
    QString t_StrMessageCode;       /* 日志编码 */
    QString t_StrMessageCodeType;   /* 日志编码类型 */
    QString t_StrMessageData;       /* 日志数据 */
    QString t_StrMessageDataInfo;   /* 日志数据信息 */
}STRU_LOG_MESSAGE;

typedef struct{
    QString t_StrLogCode;           /* 日志编码 */
    QString t_StrLogCodeInfo;       /* 日志编码说明 */
    QString t_StrLogData;           /* 日志取值 */
    QString t_StrLogDataInfo;       /* 日志取值说明 */
}STRU_LOG_DIC_OBJ;

typedef struct{
    STRU_LOG_DIC_OBJ t_LogDicObject[LOG_CODE_MAX_NUM];
    uint16_t t_LogDicObjectNum;
}STRU_LOG_DIC;

class SqlDataBase : public QObject
{
    Q_OBJECT
public:
    explicit SqlDataBase(QObject *parent = nullptr);
    QSqlDatabase t_DataBase;
    QString Make_DBFileName();
    void Open_DataBase(QString t_StrDataBaseFileName);
    void Close_DataBase();
    void Create_SpecialConfigTable();
    void Search_SpecialConfigTable(STRU_SPECIAL_CONFIG * t_SpecialConfig);
    void Insert_SpecialConfigTable(STRU_SPECIAL_ATTICATION * t_SpecialConfig);
    void Delete_SpecialConfigTable(STRU_SPECIAL_ATTICATION * t_SpecialConfig);
    bool Update_SpecialConfigTable(STRU_SPECIAL_ATTICATION * t_SpecialConfig);
    /* CCB 字典 */
    void Create_DarkLogDicCCBTable();
    void Search_DarkLogDicCCBTable(STRU_LOG_DIC * t_DarkLogDic);
    /* PLFM 字典 */
    void Create_DarkLogDicPLFMTable();
    void Search_DarkLogDicPLFMTable(STRU_LOG_DIC * t_DarkLogDic);
    /* RCD 字典 */
    void Create_DarkLogDicRCDTable();
    void Search_DarkLogDicRCDTable(STRU_LOG_DIC * t_DarkLogDic);
signals:
    void Signal_BrowserLogShow(QString t_LogStr);                               /* 日志显示信号 */
};

#endif // SQLDATABASE_H