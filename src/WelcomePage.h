#pragma once

#include <QWidget>

class QLabel;
class QListWidget;
class QPushButton;
class QStackedWidget;
class QToolButton;
class RecentVaultsStore;

class WelcomePage : public QWidget
{
    Q_OBJECT

public:
    explicit WelcomePage(RecentVaultsStore *recentVaults, QWidget *parent = nullptr);

    void refreshRecentVaults();
    void selectMostRecentVault();

signals:
    void createVaultRequested();
    void openVaultRequested();
    void openVaultPathRequested(const QString &path);
    void unlockVaultRequested(const QString &path);
    void lockVaultRequested(const QString &path);

private:
    QWidget *createVaultListPane();
    QWidget *createEmptyDetailPane();
    QWidget *createVaultDetailPane();
    QString currentVaultPath() const;
    void updateVaultDetail();
    void removeSelectedVault();

    RecentVaultsStore *m_recentVaults = nullptr;
    QListWidget *m_vaultList = nullptr;
    QLabel *m_emptyListLabel = nullptr;
    QToolButton *m_addVaultButton = nullptr;
    QStackedWidget *m_detailStack = nullptr;
    QWidget *m_emptyDetailPane = nullptr;
    QWidget *m_vaultDetailPane = nullptr;
    QLabel *m_vaultName = nullptr;
    QLabel *m_vaultPath = nullptr;
    QLabel *m_vaultStatus = nullptr;
    QPushButton *m_unlockButton = nullptr;
    QPushButton *m_lockButton = nullptr;
    QPushButton *m_removeButton = nullptr;
};
