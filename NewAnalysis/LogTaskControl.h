#ifndef LOGTASKCONTROL_H
#define LOGTASKCONTROL_H

#include <QString>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

// No UI or database objects cross threads. The optional progress callback runs
// on the worker thread; the desktop UI polls Snapshot on its own event loop.
class LogTaskControl
{
public:
    enum State { Running, CancelRequested, Committing, Finished };
    struct Progress { int percent; QString message; State state; };
    explicit LogTaskControl(const std::function<void(int, const QString &)> &observer = {})
        : m_Observer(observer) {}

    bool RequestCancel()
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        if(m_State != Running && m_State != CancelRequested) return false;
        m_State = CancelRequested;
        m_Cancelled.store(true);
        return true;
    }
    bool IsCancelled() const { return m_Cancelled.load(); }
    bool BeginCommit()
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        if(m_State != Running) return false;
        m_State = Committing;
        return true;
    }
    void SetProgress(int percent, const QString &message)
    {
        int current;
        {
            std::lock_guard<std::mutex> lock(m_Mutex);
            m_Percent = qMax(m_Percent, qBound(0, percent, 100));
            m_Message = message;
            current = m_Percent;
        }
        if(m_Observer) m_Observer(current, message);
    }
    Progress Snapshot() const
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        return {m_Percent, m_Message, m_State};
    }
    void Finish()
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        m_State = Finished;
    }
private:
    mutable std::mutex m_Mutex;
    std::atomic_bool m_Cancelled{false};
    State m_State = Running;
    int m_Percent = 0;
    QString m_Message;
    std::function<void(int, const QString &)> m_Observer;
};

class LogTaskCompletion
{
public:
    explicit LogTaskCompletion(const std::shared_ptr<LogTaskControl> &control) : m_Control(control) {}
    ~LogTaskCompletion() { if(m_Control) m_Control->Finish(); }
private:
    std::shared_ptr<LogTaskControl> m_Control;
};

#endif
