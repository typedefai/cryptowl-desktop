#pragma once

#include <QDialog>
#include <QString>

class QCheckBox;
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
    };

    explicit PasswordEditorDialog(QWidget *parent = nullptr);
    PasswordEditorDialog(const Data &data, QWidget *parent = nullptr);

    Data data() const;

    void reject() override;

private slots:
    void save();

private:
    void buildUi(bool editing);
    void setError(const QString &message);

    QLineEdit *m_titleEdit = nullptr;
    QLineEdit *m_usernameEdit = nullptr;
    QLineEdit *m_urlEdit = nullptr;
    QLineEdit *m_passwordEdit = nullptr;
    QCheckBox *m_showPassword = nullptr;
    QPlainTextEdit *m_notesEdit = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_saveButton = nullptr;
};
