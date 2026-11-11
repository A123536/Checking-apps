/*
 * @Author: Black Warrior
 * @date: 2026-09-22 09:32:23
 * @LastEditors: DESKTOP-AHNMJ6D\BlackWarrior
 * @LastEditTime: 2026-09-23 17:12:21
 * @FilePath: \NewAnalysis\ReadThread.cpp
 * @Description:
 *
 * Copyright (c) by Traffic Control Technology Co., Ltd, All Rights Reserved (2026).
 */
#include "ReadThread.h"

t_dictionaries dictionarArrInfo_PLFM[CODEINFOANDTYMAX];
t_dictionaries dictionarArrInfo_CCB[CODEINFOANDTYMAX];
t_dictionaries dictionarArrInfo_RCD[CODEINFOANDTYMAX];

ReadThread::ReadThread(QObject *parent) : QThread(parent)
{

}

void ReadThread::stopThread()
{
    m_stop = true;
}

void ReadThread::run()
{
    Dic_Convert(m_CCBLogDic, dictionarArrInfo_CCB);
    Dic_Convert(m_PLFMLogDic, dictionarArrInfo_PLFM);
    Dic_Convert(m_RCDLogDic, dictionarArrInfo_RCD);

    emit Signal_ReadDicOver();
}

void ReadThread::Dic_Convert(STRU_LOG_DIC t_DarkLogDicInPut, t_dictionaries * t_DarkLogDicOutPut)
{
    bool t_RetValue;
    uint16_t t_u16CurrentLogCodeDataIndex = 0u;     /* 当前日志编码取值索引，一个编码多种取值的情况 */
    uint16_t t_u16LogCodeIndex = 0u;                /* 日志编码索引，映射字典表 */
    uint16_t t_u16LastLogCodeIndex = 0u;            /* 上一个日志编码索引 */

    qDebug()<<t_DarkLogDicInPut.t_LogDicObjectNum;
    for(uint16_t index = 0u; index < t_DarkLogDicInPut.t_LogDicObjectNum; index++)
    {
        t_u16LogCodeIndex = t_DarkLogDicInPut.t_LogDicObject[index].t_StrLogCode.toUShort(&t_RetValue, 16);
        /* 判断是否为相同的日志编码，不同的取值 */
        if(t_u16LastLogCodeIndex == t_u16LogCodeIndex)
        {
            t_u16CurrentLogCodeDataIndex += 1u;
        }
        else
        {
            t_u16CurrentLogCodeDataIndex = 0u;
        }

        t_DarkLogDicOutPut[t_u16LogCodeIndex].interpret_MSCT = t_DarkLogDicInPut.t_LogDicObject[index].t_StrLogCodeInfo;

        if("value" == t_DarkLogDicInPut.t_LogDicObject[index].t_StrLogData)
        {
            /* 不需要转义 */
            t_DarkLogDicOutPut[t_u16LogCodeIndex].specialDeal[t_u16CurrentLogCodeDataIndex] = NOESCAPE;
        }
        else
        {
            /* 需要转义 */
            t_DarkLogDicOutPut[t_u16LogCodeIndex].specialDeal[t_u16CurrentLogCodeDataIndex] = SCAPE;
            t_DarkLogDicOutPut[t_u16LogCodeIndex].value_MSCT_u8[t_u16CurrentLogCodeDataIndex] = t_DarkLogDicInPut.t_LogDicObject[index].t_StrLogData.toUShort(&t_RetValue, 16);
            t_DarkLogDicOutPut[t_u16LogCodeIndex].info_MSCT[t_u16CurrentLogCodeDataIndex] = t_DarkLogDicInPut.t_LogDicObject[index].t_StrLogDataInfo;
        }
        t_DarkLogDicOutPut[t_u16LogCodeIndex].atValueNum = t_u16CurrentLogCodeDataIndex;

        t_u16LastLogCodeIndex = t_u16LogCodeIndex;
    }
}
