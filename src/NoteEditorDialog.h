#pragma once

#include <QDialog>
#include <QString>

#include <functional>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

class NoteEditorDialog : public QDialog
{
    Q_OBJECT

public:
    struct Data
    {
        QString title;
        QString body;
        QString classification = QStringLiteral("C");
    };

    using ContentLoader = std::function<bool(QString *body, QString *error)>;
    using SaveAuthorizer = std::function<bool(const Data &data, QString *error)>;

    explicit NoteEditorDialog(QWidget *parent = nullptr);
    NoteEditorDialog(const Data &data, QWidget *parent = nullptr);
    NoteEditorDialog(const Data &data, ContentLoader loader, QWidget *parent = nullptr);

    void setTopSecretAvailable(bool available);
    void setSaveAuthorizer(SaveAuthorizer authorizer);

    Data data() const;

    void reject() override;

private slots:
    void save();
    void revealContent();

private:
    void buildUi(bool editing);
    void setError(const QString &message);

    QLineEdit *m_titleEdit = nullptr;
    QPlainTextEdit *m_bodyEdit = nullptr;
    QComboBox *m_classificationCombo = nullptr;
    QLabel *m_topSecretHint = nullptr;
    QLabel *m_lockHint = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_revealButton = nullptr;
    QPushButton *m_saveButton = nullptr;
    ContentLoader m_contentLoader;
    SaveAuthorizer m_saveAuthorizer;
    bool m_contentRevealed = true;
};
