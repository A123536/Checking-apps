#ifndef DEEPSEEKCLIENT_H
#define DEEPSEEKCLIENT_H

#include <QObject>
#include <QPointer>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;

class DeepSeekClient : public QObject
{
    Q_OBJECT
public:
    explicit DeepSeekClient(QObject *parent = nullptr);

    void SetConfig(const QString &apiKey,
                   const QString &model,
                   const QString &baseUrl = QStringLiteral("https://api.deepseek.com"));

    virtual bool IsBusy() const;
    void TestConnection();
    virtual void AnalyzeEvidence(const QString &evidence);
    void Cancel();

signals:
    void Signal_AnalysisInputPrepared(QString evidence);
    void Signal_BusyChanged(bool busy);
    void Signal_TestSucceeded(QString message);
    void Signal_AnalysisSucceeded(QString content);
    void Signal_RequestFailed(QString message);

private:
    enum RequestPurpose
    {
        Purpose_None = 0,
        Purpose_Test,
        Purpose_Analysis
    };

    QNetworkAccessManager *m_NetworkManager;
    QPointer<QNetworkReply> m_CurrentReply;
    QString m_ApiKey;
    QString m_Model;
    QString m_BaseUrl;
    RequestPurpose m_RequestPurpose;

    void SendChatRequest(const QString &systemPrompt,
                         const QString &userPrompt,
                         int maxTokens,
                         RequestPurpose purpose);
    void HandleReply();
    void SetBusy(bool busy);
};

#endif // DEEPSEEKCLIENT_H
