#ifndef LOGCSVREADER_H
#define LOGCSVREADER_H

#include <QFile>
#include <QRegularExpression>
#include <QStringList>
#include <QTextCodec>
#include <QTextStream>
#include "BoardIdentity.h"

// Shared by diagnosis, normal references, baseline building and fault storage.
// Old exports can have an extended header followed by compact five-column rows.
class LogCsvReader
{
public:
    bool hasCycle = false, hasPacket = false;
    quint64 cycle = 0, packet = 0;
    QString boardType;
    QString expectedBoard;

    static void Configure(QTextStream &stream, QFile &file)
    {
        const QByteArray prefix = file.peek(4096);
        QTextCodec::ConverterState state;
        QTextCodec::codecForName("UTF-8")->toUnicode(prefix.constData(), prefix.size(), &state);
        stream.setCodec(state.invalidChars == 0 ? "UTF-8" : "GB18030");
        stream.setAutoDetectUnicode(true); // UTF-8 / UTF-16 BOMs take precedence.
    }

    static bool IsLevel(const QString &value)
    {
        static const QStringList levels{QStringLiteral("错误"), QStringLiteral("警告"),
                                        QStringLiteral("提示"), QStringLiteral("调试")};
        return levels.contains(value.trimmed());
    }

    static bool IsCode(const QString &value)
    {
        static const QRegularExpression pattern(QStringLiteral("^(?:0[xX])?[0-9a-fA-F]{1,8}$"));
        return pattern.match(value.trimmed()).hasMatch();
    }

    // Read a single physical record. Empty fields means a header or blank line.
    // Return canonical level, code, description, raw value, decoded value.
    bool Read(const QString &line, QStringList *fields, QString *error)
    {
        fields->clear(); hasCycle = false; hasPacket = false;
        if(line.trimmed().isEmpty()) return true;
        if(line.trimmed().startsWith("Cycle Num :")) return true; // legacy display redundancy
        QStringList values;
        if(!Split(line, &values))
        {
            // The legacy exporter writes literal dictionary quotes without CSV
            // escaping. Recover only an identifiable event with an unclosed
            // description quote and a valid raw byte field. Preserve the quote.
            values = line.split(',');
            const int start = IsLevel(values.value(0)) ? 0 : m_Level;
            const int code = start == 0 ? 1 : m_Code;
            const int description = start == 0 ? 2 : m_Description;
            const int raw = start == 0 ? 3 : m_Raw;
            static const QRegularExpression bytes(QStringLiteral("^(?:0[xX][0-9a-fA-F]+\\s*)*$"));
            if(start < 0 || description < 0 || raw < 0 || !IsLevel(values.value(start)) ||
               !IsCode(values.value(code)) || !values.value(description).startsWith('"') ||
               values.value(description).count('"') != 1 || values.size() <= raw + 1 ||
               !bytes.match(values.value(raw).trimmed()).hasMatch())
                return Fail(error, QStringLiteral("无法识别 CSV 引号或列结构"));
        }
        for(QString &value : values) value = value.trimmed();
        if(values.contains(QStringLiteral("消息类型")) && values.contains(QStringLiteral("消息编码")))
        {
            m_Level = values.indexOf(QStringLiteral("消息类型"));
            m_Code = values.indexOf(QStringLiteral("消息编码"));
            m_Description = values.indexOf(QStringLiteral("消息编码解释"));
            m_Raw = values.indexOf(QStringLiteral("消息内容(16进制)"));
            m_Decoded = values.indexOf(QStringLiteral("消息内容解释"));
            m_Cycle = values.indexOf(QStringLiteral("周期号"));
            m_Packet = values.indexOf(QStringLiteral("包序号"));
            m_Board = values.indexOf(QStringLiteral("板卡类型"));
            if(m_Description < 0 || m_Raw < 0 || m_Decoded < 0)
                return Fail(error, QStringLiteral("CSV 表头缺少描述或内容列"));
            return true;
        }
        const bool compact = IsLevel(values.value(0)) && IsCode(values.value(1));
        const int level = compact ? 0 : m_Level, code = compact ? 1 : m_Code;
        const int description = compact ? 2 : m_Description, raw = compact ? 3 : m_Raw;
        const int decoded = compact ? 4 : m_Decoded;
        if(level < 0 || code < 0 || description < 0 || raw < 0 || decoded < 0 ||
           qMax(qMax(level, code), qMax(description, qMax(raw, decoded))) >= values.size() ||
           !IsLevel(values.value(level)) || !IsCode(values.value(code)))
            return Fail(error, QStringLiteral("事件编码、日志等级或列数无效"));
        if(!compact)
        {
            const QString board = values.value(m_Board).trimmed();
            if(!board.isEmpty()) {
                const QString identified = BoardIdentity::fromName(board);
                if(identified.isEmpty()) return Fail(error, QStringLiteral("CSV 板卡类型无法识别"));
                if((!boardType.isEmpty() && boardType != identified) || (!expectedBoard.isEmpty() && expectedBoard != identified))
                    return Fail(error, QStringLiteral("CSV 板卡类型与日志或任务不一致"));
                boardType = identified;
            }
            if(!ReadNumber(values.value(m_Packet), &hasPacket, &packet))
                return Fail(error, QStringLiteral("CSV 包序号无效"));
        }
        *fields = QStringList{values.at(level), values.at(code), values.at(description), values.at(raw),
                              decoded == values.size() - 1 ? values.at(decoded) : values.mid(decoded).join(',')};
        // Extra unquoted commas belong to the legacy decoded-value tail only
        // when it is the last declared column (including compact rows).
        if(!compact && decoded < values.size() - 1 && decoded != LastColumn())
            (*fields)[4] = values.at(decoded);
        if(!CycleNumber(fields->at(1), fields->at(3), fields->at(4), &hasCycle, &cycle, error)) return false;
        return true;
    }

    static bool CycleNumber(const QString &code, const QString &raw, const QString &decoded,
                            bool *present, quint64 *number, QString *error)
    {
        bool ok = false;
        *present = code.trimmed().toUInt(&ok, 16) == 0x0A1A && ok;
        if(!*present) return true;
        const QStringList bytes = raw.trimmed().split(QRegularExpression("\\s+"), QString::SkipEmptyParts);
        if(bytes.size() == 4)
        {
            quint64 value = 0;
            for(const QString &byte : bytes)
            {
                const uint b = byte.toUInt(&ok, 16);
                if(!ok || b > 255) return Fail(error, QStringLiteral("0x0A1A 周期号原始字节无效"));
                value = (value << 8) | b;
            }
            *number = value; // raw bytes are authoritative, independent of dictionary text
            return true;
        }
        bool numeric = false;
        *number = decoded.trimmed().toULongLong(&numeric);
        if(!raw.trimmed().isEmpty() || !numeric || *number > 0xFFFFFFFFULL)
            return Fail(error, QStringLiteral("0x0A1A 周期号需要四字节原始值或有效解析值"));
        return true;
    }

private:
    int m_Level = -1, m_Code = -1, m_Description = -1, m_Raw = -1, m_Decoded = -1;
    int m_Cycle = -1, m_Packet = -1, m_Board = -1;
    int LastColumn() const
    {
        return qMax(qMax(m_Level, m_Code), qMax(qMax(m_Description, m_Raw),
                    qMax(qMax(m_Decoded, m_Cycle), qMax(m_Packet, m_Board))));
    }
    static bool Fail(QString *error, const QString &message)
    { if(error) *error = message; return false; }
    static bool ReadNumber(const QString &value, bool *present, quint64 *number)
    {
        *present = !value.trimmed().isEmpty();
        if(!*present) return true;
        static const QRegularExpression digits(QStringLiteral("^[0-9]+$"));
        bool ok = false; *number = value.toULongLong(&ok);
        return ok && digits.match(value).hasMatch();
    }
    static bool Split(const QString &line, QStringList *fields)
    {
        QString value; bool quoted = false, closed = false;
        for(int i = 0; i < line.size(); ++i)
        {
            const QChar ch = line.at(i);
            if(quoted)
            {
                if(ch == '"' && i + 1 < line.size() && line.at(i + 1) == '"') { value += ch; ++i; }
                else if(ch == '"') { quoted = false; closed = true; }
                else value += ch;
            }
            else if(ch == ',') { fields->append(value); value.clear(); closed = false; }
            else if(ch == '"' && value.trimmed().isEmpty() && !closed) { value.clear(); quoted = true; }
            else
            {
                if(closed && !ch.isSpace()) return false;
                value += ch;
            }
        }
        if(quoted) return false;
        fields->append(value); return true;
    }
};

#endif
