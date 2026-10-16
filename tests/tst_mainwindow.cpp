#include "MainWindow.h"

#include <QMenuBar>
#include <QStatusBar>
#include <QtTest>

class TestMainWindow : public QObject
{
    Q_OBJECT

private slots:
    void hasAppTitle();
    void hasFileMenu();
    void startsWithoutVault();
};

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

QTEST_MAIN(TestMainWindow)
#include "tst_mainwindow.moc"
