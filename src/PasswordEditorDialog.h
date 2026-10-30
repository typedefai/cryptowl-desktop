#pragma once

#include <QDialog>
#include <QString>

#include <functional>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

class PasswordEditorDialog : public QDialog
{
    Q_OBJECT

public:
    struct Data
    {
        QString title;
        QString username;
        QString url;
        QString password;
        QString notes;
        QString classification = QStringLiteral("S");
    };

    using SecretLoader =
        std::function<bool(QString *password, QString *notes, QString *error)>;
    using SaveAuthorizer = std::function<bool(const Data &data, QString *error)>;

    explicit PasswordEditorDialog(QWidget *parent = nullptr);
    PasswordEditorDialog(const Data &data, QWidget *parent = nullptr);
    PasswordEditorDialog(const Data &data, SecretLoader loader,
                         QWidget *parent = nullptr);

    void setTopSecretAvailable(bool available);
    void setSaveAuthorizer(SaveAuthorizer authorizer);

    Data data() const;

    void reject() override;

private slots:
    void save();

private:
    void buildUi(bool editing);
    void setError(const QString &message);
    bool revealSecretFields();

    QLineEdit *m_titleEdit = nullptr;
    QLineEdit *m_usernameEdit = nullptr;
    QLineEdit *m_urlEdit = nullptr;
    QLineEdit *m_passwordEdit = nullptr;
    QCheckBox *m_showPassword = nullptr;
    QPlainTextEdit *m_notesEdit = nullptr;
    QComboBox *m_classificationCombo = nullptr;
    QLabel *m_topSecretHint = nullptr;
    QLabel *m_lockHint = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_saveButton = nullptr;
    SecretLoader m_secretLoader;
    SaveAuthorizer m_saveAuthorizer;
    bool m_secretRevealed = true;
};
