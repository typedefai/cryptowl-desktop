#pragma once

#include "RecentVaultsStore.h"

#include <QMainWindow>

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
};
