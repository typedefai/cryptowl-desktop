#pragma once

#include "RecentVaultsStore.h"

#include <QHash>
#include <QMainWindow>

#include <map>
#include <memory>

class QAction;
class QLineEdit;
class QStackedWidget;
class QTabWidget;
class VaultView;
class WelcomePage;

namespace cryptowl::vault {
class VaultSession;
}

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
    void closeVaultTab(int index);
    void showVaultInfo();
    void showAbout();

private:
    void createActions();
    void createMenus();
    void createToolBar();
    void showVault(const QString &path);
    VaultView *currentVaultView() const;
    void updateWorkspaceActions();
    void onVaultTabChanged(int index);
    void filterCurrentVault(const QString &text);
    void lockCurrentVault();

    RecentVaultsStore m_recentVaults;
    WelcomePage *m_welcome = nullptr;
    QStackedWidget *m_centerStack = nullptr;
    QTabWidget *m_vaultTabs = nullptr;
    QHash<QString, VaultView *> m_vaultViews;
    std::map<QString, std::shared_ptr<cryptowl::vault::VaultSession>> m_sessions;

    QAction *m_newVaultAction = nullptr;
    QAction *m_openVaultAction = nullptr;
    QAction *m_lockVaultAction = nullptr;
    QAction *m_vaultInfoAction = nullptr;
    QAction *m_addEntryAction = nullptr;
    QAction *m_editEntryAction = nullptr;
    QAction *m_deleteEntryAction = nullptr;
    QAction *m_copyUsernameAction = nullptr;
    QAction *m_detailsAction = nullptr;
    QAction *m_iconsAction = nullptr;
    QLineEdit *m_searchEdit = nullptr;
};
