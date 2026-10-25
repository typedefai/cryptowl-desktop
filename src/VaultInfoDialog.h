#pragma once

#include <QDialog>
#include <QString>

class VaultInfoDialog : public QDialog
{
    Q_OBJECT

public:
    explicit VaultInfoDialog(const QString &vaultPath, bool unlocked,
                            QWidget *parent = nullptr);

private:
    QString buildHtml() const;

    QString m_vaultPath;
    bool m_unlocked = false;
};
