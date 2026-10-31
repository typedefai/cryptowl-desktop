#pragma once

#include "crypto/ProtectedValue.h"

#include <QDialog>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;

class UnlockVaultDialog : public QDialog
{
    Q_OBJECT

public:
    explicit UnlockVaultDialog(QString vaultPath, QWidget *parent = nullptr,
                               bool migrateDeviceSecret = true);

    cryptowl::crypto::ProtectedValue takeVaultKey();
    cryptowl::crypto::ProtectedValue takeSmk();
    bool rememberSecretAccess() const;

    void reject() override;

private slots:
    void tryUnlock();

private:
    void setError(const QString &message);
    void setBusy(bool busy);

    QString m_vaultPath;
    bool m_migrateDeviceSecret = true;
    QLineEdit *m_passwordEdit = nullptr;
    QCheckBox *m_showPassword = nullptr;
    QCheckBox *m_rememberSecret = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_unlockButton = nullptr;
    cryptowl::crypto::ProtectedValue m_vaultKey;
    cryptowl::crypto::ProtectedValue m_smk;
};
