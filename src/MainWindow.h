#pragma once

#include "RecentVaultsStore.h"
#include "crypto/ProtectedValue.h"

#include <QMainWindow>

#include <map>

class WelcomePage;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

private slots:
    void createVault();
    void openVault();
    void openVaultAt(QString path);
    void unlockVault(const QString &path);
    void lockVault(const QString &path);
    void showAbout();

private:
    void createMenus();

    RecentVaultsStore m_recentVaults;
    WelcomePage *m_welcome = nullptr;
    std::map<QString, cryptowl::crypto::ProtectedValue> m_unlockedVaults;
};
