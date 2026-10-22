#include "MainWindow.h"

#include "WelcomePage.h"

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QStatusBar>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("CryptOwl Desktop"));
    resize(650, 498); // Match Cryptomator's current main-window size.

    m_welcome = new WelcomePage(&m_recentVaults, this);
    connect(m_welcome, &WelcomePage::createVaultRequested, this, &MainWindow::createVault);
    connect(m_welcome, &WelcomePage::openVaultRequested, this, &MainWindow::openVault);
    connect(m_welcome, &WelcomePage::openVaultPathRequested, this, &MainWindow::openVaultAt);
    connect(m_welcome, &WelcomePage::unlockVaultRequested, this, &MainWindow::unlockVault);
    connect(m_welcome, &WelcomePage::lockVaultRequested, this, &MainWindow::lockVault);
    setCentralWidget(m_welcome);

#ifdef Q_OS_MACOS
    // Keep the menu inside the window, matching the classic Windows layout.
    menuBar()->setNativeMenuBar(false);
#endif

    createMenus();
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createMenus()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));

    QAction *newAction = fileMenu->addAction(tr("&New vault…"));
    newAction->setShortcut(QKeySequence::New);
    connect(newAction, &QAction::triggered, this, &MainWindow::createVault);

    QAction *openAction = fileMenu->addAction(tr("&Open vault…"));
    openAction->setShortcut(QKeySequence::Open);
    connect(openAction, &QAction::triggered, this, &MainWindow::openVault);

    fileMenu->addSeparator();

    QAction *quitAction = fileMenu->addAction(tr("E&xit"));
    quitAction->setShortcut(QKeySequence::Quit);
    connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));

    QAction *aboutAction = helpMenu->addAction(tr("&About"));
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);
}

void MainWindow::createVault()
{
    const QString dir = QFileDialog::getExistingDirectory(
        this, tr("Choose an empty folder for the new vault"));
    if (dir.isEmpty())
        return;

    statusBar()->showMessage(tr("Vault creation is not implemented yet: %1").arg(dir));
}

void MainWindow::openVault()
{
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Open vault folder"));
    if (dir.isEmpty())
        return;

    openVaultAt(dir);
}

void MainWindow::openVaultAt(QString path)
{
    m_recentVaults.add(path);
    statusBar()->showMessage(tr("Selected vault folder: %1").arg(path));
    m_welcome->refreshRecentVaults();
    m_welcome->selectMostRecentVault();
}

void MainWindow::unlockVault(const QString &path)
{
    statusBar()->showMessage(tr("Vault unlock is not implemented yet: %1").arg(path));
}

void MainWindow::lockVault(const QString &path)
{
    statusBar()->showMessage(tr("Vault lock is not implemented yet: %1").arg(path));
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, tr("About CryptOwl Desktop"),
                       tr("<b>CryptOwl Desktop</b> %1<br><br>"
                          "Local-first encrypted vault: notes, passwords, photos and videos.<br>"
                          "No plaintext data at rest.")
                           .arg(QCoreApplication::applicationVersion()));
}
