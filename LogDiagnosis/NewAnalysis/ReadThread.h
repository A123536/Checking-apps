#ifndef READTHREAD_H
#define READTHREAD_H

#include <QObject>
#include <QThread>
#include <QDebug>
#include "SqlDataBase.h"

class ReadThread : public QThread
{
    Q_OBJECT
public:
    explicit ReadThread(QObject *parent = nullptr);
    void stopThread();
    QString t_StrPLFMDicPath;
    QString t_StrCCBDicPath;
    QString t_StrRCDDicPath;
    STRU_LOG_DIC m_CCBLogDic;
    STRU_LOG_DIC m_PLFMLogDic;
    STRU_LOG_DIC m_RCDLogDic;
protected:
    void run();

private:
    bool m_stop;
    bool m_readDic = true;

    void Dic_Convert(STRU_LOG_DIC t_DarkLogDicInPut, t_dictionaries * t_DarkLogDicOutPut);
signals:
    void Signal_ReadDicOver();
    void Signal_MessageBoxShow(bool mode, const QString &message);
};

#endif // READTHREAD_H
