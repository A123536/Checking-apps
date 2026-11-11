#ifndef LEGACYPARSERADAPTER_H
#define LEGACYPARSERADAPTER_H

#include <QObject>
#include <QString>
#include <QStringList>

class ReadThread;
class ReadWord;

class LegacyParserAdapter : public QObject
{
    Q_OBJECT
public:
    explicit LegacyParserAdapter(QObject *parent = nullptr);
    ~LegacyParserAdapter();

    virtual bool IsBusy() const;
    virtual void StartOpbParse(const QString &sourceFilePath,
                       const QString &plfmDictionaryPath,
                       bool includeApplicationLogs, bool isolatedOutput = false);

signals:
    void Signal_ProgressChanged(int singleFileValue, int allFileValue);
    void Signal_LogMessage(QString message);
    void Signal_ParseFinished(bool success, QStringList outputCsvFiles);
    void Signal_ParseFailed(QString message);

private:
    ReadThread *m_ReadDictionaryThread;
    ReadWord *m_ReadWordThread;
    QString m_SourceFilePath;
    int m_SingleFileProgress;
    int m_AllFileProgress;
    bool m_Busy;

    bool LoadPlfmDictionary(const QString &dictionaryPath, QString *errorMessage);
    void CleanupThreads();
};

#endif // LEGACYPARSERADAPTER_H
