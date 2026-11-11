#ifndef SOURCEQUERYWIDGET_H
#define SOURCEQUERYWIDGET_H
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <QProcess>

class QLineEdit;
class QLabel;
class QTableWidget;
class QTreeWidget;
class QTreeWidgetItem;
class QPlainTextEdit;
class QComboBox;
class QSpinBox;
class QPushButton;

class SourceQueryWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SourceQueryWidget(const QString &databasePath, QWidget *parent = nullptr);
    ~SourceQueryWidget() override;
private:
    QLineEdit *m_Path;
    QLineEdit *m_Search;
    QLabel *m_Status;
    QTableWidget *m_Results;
    QTreeWidget *m_Tree;
    QPlainTextEdit *m_Source;
    QPlainTextEdit *m_BuildLog;
    QComboBox *m_Mode;
    QComboBox *m_Direction;
    QSpinBox *m_Depth;
    QPushButton *m_Rebuild;
    QPushButton *m_Browse;
    QPushButton *m_Cancel;
    QProcess *m_Process;
    QString m_Error;
    QString m_CancelPath;
    bool m_CancelRequested = false;
    QVector<QVariantMap> query(const QString &sql, const QVariantList &parameters = {});
    bool validateDatabase();
    void search();
    void selectResult();
    void showSource(qint64 fileId, int line);
    void addRelations(QTreeWidgetItem *parent, qint64 functionId, int depth,
                      QList<qint64> ancestors, int &remaining);
    void rebuild();
    void setBuilding(bool busy);
};
#endif
