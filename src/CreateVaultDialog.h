#pragma once

#include <QDialog>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;

class CreateVaultDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateVaultDialog(QString vaultName, QWidget *parent = nullptr);

    QString password() const;

    void reject() override;

private slots:
    void tryCreate();

private:
    void setError(const QString &message);

    QString m_vaultName;
    QLineEdit *m_passwordEdit = nullptr;
    QLineEdit *m_confirmEdit = nullptr;
    QCheckBox *m_showPassword = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_createButton = nullptr;
};
