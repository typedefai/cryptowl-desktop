#pragma once

#include <QDialog>
#include <QString>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;

class SecretAccessDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SecretAccessDialog(QWidget *parent = nullptr);

    QString takePassword();

    void reject() override;

private slots:
    void acceptAccess();

private:
    void setError(const QString &message);

    QLineEdit *m_passwordEdit = nullptr;
    QCheckBox *m_showPassword = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_unlockButton = nullptr;
};
