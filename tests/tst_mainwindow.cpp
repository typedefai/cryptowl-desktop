#include "MainWindow.h"
#include "RecentVaultsStore.h"
#include "VaultDirectory.h"
#include "WelcomePage.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QListWidget>
#include <QMenuBar>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QTemporaryDir>
#include <QtTest>

class TestMainWindow : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();

    void hasAppTitle();
    void hasFileMenu();
    void startsWithoutVault();
    void startsOnVaultHome();
    void recognizesVaultDirectories();
    void welcomePageHasStartActions();
    void welcomePageListsRecentVaults();
    void selectingVaultShowsDetails();
    void doubleClickingVaultMovesItToFront();
    void removingSelectedVaultUpdatesList();
    void unlockButtonReportsNotImplemented();

private:
    QString vaultPath(const QString &name) const
    {
        return QFileInfo(m_settingsDir.filePath(name)).canonicalFilePath();
    }

    QTemporaryDir m_settingsDir;
};

void TestMainWindow::initTestCase()
{
    QCoreApplication::setOrganizationName(QStringLiteral("typedefai"));
    QCoreApplication::setApplicationName(QStringLiteral("CryptOwl Desktop Test"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_settingsDir.path());
}

void TestMainWindow::init()
{
    QSettings().clear();

    for (const QString &name : {QStringLiteral("vault-a"), QStringLiteral("vault-b")}) {
        const QString path = m_settingsDir.filePath(name);
        QDir().mkpath(path);
        QFile meta(QDir(path).filePath(QStringLiteral("vault.meta")));
        if (!meta.open(QIODevice::WriteOnly))
            qFatal("Failed to create test vault marker");
    }
}

void TestMainWindow::hasAppTitle()
{
    MainWindow window;
    QCOMPARE(window.windowTitle(), QStringLiteral("CryptOwl Desktop"));
}

void TestMainWindow::hasFileMenu()
{
    MainWindow window;
    const QList<QAction *> actions = window.menuBar()->actions();
    QVERIFY(!actions.isEmpty());
    QCOMPARE(actions.constFirst()->text(), QStringLiteral("&File"));
}

void TestMainWindow::startsWithoutVault()
{
    MainWindow window;
    QCOMPARE(window.statusBar()->currentMessage(), QStringLiteral("Ready"));
}

void TestMainWindow::startsOnVaultHome()
{
    MainWindow window;
    QVERIFY(qobject_cast<WelcomePage *>(window.centralWidget()));
}

void TestMainWindow::recognizesVaultDirectories()
{
    QVERIFY(isVaultDirectory(vaultPath(QStringLiteral("vault-a"))));
    QVERIFY(!isVaultDirectory(m_settingsDir.path()));
}

void TestMainWindow::welcomePageHasStartActions()
{
    MainWindow window;
    auto *create = window.findChild<QPushButton *>(QStringLiteral("welcomeCreateVault"));
    QVERIFY(create);
    QCOMPARE(create->text(), QStringLiteral("Create new vault…"));

    auto *open = window.findChild<QPushButton *>(QStringLiteral("welcomeOpenVault"));
    QVERIFY(open);
    QCOMPARE(open->text(), QStringLiteral("Open vault…"));
}

void TestMainWindow::welcomePageListsRecentVaults()
{
    RecentVaultsStore store;
    store.add(m_settingsDir.filePath(QStringLiteral("vault-a")));
    store.add(m_settingsDir.filePath(QStringLiteral("vault-b")));

    MainWindow window;
    auto *list = window.findChild<QListWidget *>(QStringLiteral("vaultList"));
    QVERIFY(list);
    QCOMPARE(list->count(), 2);
    QCOMPARE(list->item(0)->text(), QStringLiteral("vault-b"));
    QCOMPARE(list->item(1)->text(), QStringLiteral("vault-a"));
}

void TestMainWindow::selectingVaultShowsDetails()
{
    RecentVaultsStore store;
    store.add(m_settingsDir.filePath(QStringLiteral("vault-a")));
    store.add(m_settingsDir.filePath(QStringLiteral("vault-b")));

    MainWindow window;
    auto *list = window.findChild<QListWidget *>(QStringLiteral("vaultList"));
    QVERIFY(list);
    list->setCurrentRow(0);

    auto *name = window.findChild<QLabel *>(QStringLiteral("vaultName"));
    QVERIFY(name);
    QCOMPARE(name->text(), QStringLiteral("vault-b"));

    auto *path = window.findChild<QLabel *>(QStringLiteral("vaultPath"));
    QVERIFY(path);
    QVERIFY(path->text().endsWith(QStringLiteral("vault-b")));

    auto *status = window.findChild<QLabel *>(QStringLiteral("vaultStatus"));
    QVERIFY(status);
    QCOMPARE(status->text(), QStringLiteral("Locked"));

    auto *unlock = window.findChild<QPushButton *>(QStringLiteral("vaultUnlock"));
    QVERIFY(unlock);
    QVERIFY(unlock->isEnabled());

    auto *lock = window.findChild<QPushButton *>(QStringLiteral("vaultLock"));
    QVERIFY(lock);
    QVERIFY(!lock->isEnabled());
}

void TestMainWindow::doubleClickingVaultMovesItToFront()
{
    const QString pathA = vaultPath(QStringLiteral("vault-a"));
    const QString pathB = vaultPath(QStringLiteral("vault-b"));
    RecentVaultsStore store;
    store.add(pathA);
    store.add(pathB);
    QCOMPARE(store.paths().constFirst(), pathB);

    MainWindow window;
    window.show();
    QVERIFY(QTest::qWaitForWindowExposed(&window));

    auto *list = window.findChild<QListWidget *>(QStringLiteral("vaultList"));
    QVERIFY(list);
    QListWidgetItem *item = list->item(1);
    QVERIFY(item);
    const QPoint itemCenter = list->visualItemRect(item).center();
    QTest::mouseClick(list->viewport(), Qt::LeftButton, Qt::NoModifier, itemCenter);
    QTest::mouseDClick(list->viewport(), Qt::LeftButton, Qt::NoModifier, itemCenter);

    QTRY_COMPARE(store.paths().constFirst(), pathA);
    QTRY_VERIFY(window.statusBar()->currentMessage().contains(QStringLiteral("vault-a")));
}

void TestMainWindow::removingSelectedVaultUpdatesList()
{
    RecentVaultsStore store;
    store.add(m_settingsDir.filePath(QStringLiteral("vault-a")));

    MainWindow window;
    auto *list = window.findChild<QListWidget *>(QStringLiteral("vaultList"));
    QVERIFY(list);
    QCOMPARE(list->count(), 1);

    auto *remove = window.findChild<QPushButton *>(QStringLiteral("vaultRemove"));
    QVERIFY(remove);
    remove->click();

    QTRY_COMPARE(list->count(), 0);
    QVERIFY(store.paths().isEmpty());
}

void TestMainWindow::unlockButtonReportsNotImplemented()
{
    RecentVaultsStore store;
    store.add(m_settingsDir.filePath(QStringLiteral("vault-a")));

    MainWindow window;
    auto *unlock = window.findChild<QPushButton *>(QStringLiteral("vaultUnlock"));
    QVERIFY(unlock);
    QVERIFY(unlock->isEnabled());
    unlock->click();

    QVERIFY(window.statusBar()->currentMessage().contains(QStringLiteral("not implemented")));
}

QTEST_MAIN(TestMainWindow)
#include "tst_mainwindow.moc"
