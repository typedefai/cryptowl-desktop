#include "MainWindow.h"

#include <QAction>
#include <QApplication>
#include <QFileDialog>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QStatusBar>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("CryptOwl Desktop"));
    resize(1024, 700);

    m_placeholder = new QLabel(tr("No vault open — use File ▸ Open vault…"), this);
    m_placeholder->setAlignment(Qt::AlignCenter);
    setCentralWidget(m_placeholder);

    createMenus();
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createMenus()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));

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

void MainWindow::openVault()
{
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Open vault folder"));
    if (dir.isEmpty())
        return;

    statusBar()->showMessage(tr("Selected vault folder: %1").arg(dir));
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, tr("About CryptOwl Desktop"),
                       tr("<b>CryptOwl Desktop</b> %1<br><br>"
                          "Local-first encrypted vault: notes, passwords, photos and videos.<br>"
                          "No plaintext data at rest.")
                           .arg(QCoreApplication::applicationVersion()));
}
