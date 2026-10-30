#pragma once

#include "crypto/ProtectedValue.h"

#include <QDialog>
#include <QString>

struct sqlite3;

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class TopSecretService;

class TopSecretUnlockDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TopSecretUnlockDialog(TopSecretService *service,
                                   QWidget *parent = nullptr);

    cryptowl::crypto::ProtectedValue takeTopSecretKek();

    void reject() override;

private slots:
    void tryUnlock();

private:
    void setError(const QString &message);
    void setBusy(bool busy);

    TopSecretService *m_service = nullptr;
    QLineEdit *m_passwordEdit = nullptr;
    QCheckBox *m_showPassword = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_unlockButton = nullptr;
    cryptowl::crypto::ProtectedValue m_topSecretKek;
};

class TopSecretSetupDialog : public QDialog
{
    Q_OBJECT

public:
    TopSecretSetupDialog(QString vaultPath, sqlite3 *database,
                         QWidget *parent = nullptr);

    void reject() override;

private slots:
    void trySetup();

private:
    void setError(const QString &message);
    void setBusy(bool busy);

    QString m_vaultPath;
    sqlite3 *m_database = nullptr;
    QLineEdit *m_masterPasswordEdit = nullptr;
    QLineEdit *m_secondaryPasswordEdit = nullptr;
    QLineEdit *m_confirmEdit = nullptr;
    QCheckBox *m_showPasswords = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_setupButton = nullptr;
};
