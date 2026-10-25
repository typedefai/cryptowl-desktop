#include "MainWindow.h"

#include "CreateVaultDialog.h"
#include "UnlockVaultDialog.h"
#include "VaultCreator.h"
#include "VaultDirectory.h"
#include "VaultPathDialog.h"
#include "WelcomePage.h"

#include <QAction>
#include <QApplication>
#include <QDialog>
#include <QFileInfo>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QStatusBar>

#include <exception>
#include <utility>

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
    VaultPathDialog pathDialog(VaultPathDialog::Mode::Create, this);
    if (pathDialog.exec() != QDialog::Accepted)
        return;

    const QString dir = pathDialog.path();
    const QString vaultName = QFileInfo(dir).fileName();
    if (vaultName.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid vault folder"),
                             tr("Choose a named folder for the new vault."));
        return;
    }

    CreateVaultDialog dialog(vaultName, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    QString password = dialog.password();
    QApplication::setOverrideCursor(Qt::WaitCursor);
    VaultCreator::Result created;
    try {
        created = VaultCreator::create(dir, password);
    } catch (const std::exception &error) {
        created.error = QString::fromUtf8(error.what());
    }
    QApplication::restoreOverrideCursor();
    password.fill(QLatin1Char('\0'));

    if (!created.ok) {
        QMessageBox::critical(this, tr("Could not create vault"), created.error);
        return;
    }

    m_recentVaults.add(dir);
    m_welcome->refreshRecentVaults();
    m_welcome->selectMostRecentVault();
    statusBar()->showMessage(tr("Vault created: %1").arg(dir));
}

void MainWindow::openVault()
{
    VaultPathDialog dialog(VaultPathDialog::Mode::Open, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    openVaultAt(dialog.path());
}

void MainWindow::openVaultAt(QString path)
{
    if (!isVaultDirectory(path)) {
        QMessageBox::warning(
            this, tr("Not a CryptOwl vault"),
            tr("The selected folder is not a CryptOwl vault.\n\n"
               "Choose a vault folder that contains a vault.meta file."));
        return;
    }

    m_recentVaults.add(path);
    statusBar()->showMessage(tr("Selected vault folder: %1").arg(path));
    m_welcome->refreshRecentVaults();
    m_welcome->selectMostRecentVault();
}

void MainWindow::unlockVault(const QString &path)
{
    UnlockVaultDialog dialog(path, this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    auto vaultKey = dialog.takeVaultKey();
    if (vaultKey.empty()) {
        statusBar()->showMessage(tr("Vault unlock failed: %1").arg(path));
        return;
    }

    m_unlockedVaults[path] = std::move(vaultKey);
    m_welcome->setVaultUnlocked(path, true);
    statusBar()->showMessage(tr("Vault unlocked: %1").arg(path));
}

void MainWindow::lockVault(const QString &path)
{
    m_unlockedVaults.erase(path);
    m_welcome->setVaultUnlocked(path, false);
    statusBar()->showMessage(tr("Vault locked: %1").arg(path));
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, tr("About CryptOwl Desktop"),
                       tr("<b>CryptOwl Desktop</b> %1<br><br>"
                          "Local-first encrypted vault: notes, passwords, photos and videos.<br>"
                          "No plaintext data at rest.")
                           .arg(QCoreApplication::applicationVersion()));
}
