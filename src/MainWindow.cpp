#include "MainWindow.h"

#include "CreateVaultDialog.h"
#include "UnlockVaultDialog.h"
#include "VaultCreator.h"
#include "VaultDirectory.h"
#include "VaultPathDialog.h"
#include "VaultView.h"
#include "WelcomePage.h"

#include <QAction>
#include <QApplication>
#include <QDialog>
#include <QDir>
#include <QFileInfo>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QToolBar>

#include <exception>
#include <utility>

namespace {

QString canonicalVaultPath(const QString &path)
{
    const QFileInfo info(path);
    const QString canonical = info.canonicalFilePath();
    return canonical.isEmpty() ? QDir::cleanPath(info.absoluteFilePath()) : canonical;
}

} // namespace

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

    m_centerStack = new QStackedWidget(this);
    m_centerStack->addWidget(m_welcome);

    m_vaultTabs = new QTabWidget(m_centerStack);
    m_vaultTabs->setObjectName(QStringLiteral("vaultTabs"));
    m_vaultTabs->setTabsClosable(true);
    m_vaultTabs->setMovable(true);
    m_centerStack->addWidget(m_vaultTabs);
    m_centerStack->setCurrentWidget(m_welcome);
    setCentralWidget(m_centerStack);

    connect(m_vaultTabs, &QTabWidget::currentChanged, this,
            &MainWindow::onVaultTabChanged);
    connect(m_vaultTabs, &QTabWidget::tabCloseRequested, this,
            &MainWindow::closeVaultTab);

#ifdef Q_OS_MACOS
    // Keep the menu inside the window, matching the classic Windows layout.
    menuBar()->setNativeMenuBar(false);
#endif

    createActions();
    createMenus();
    createToolBar();
    updateWorkspaceActions();
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::createActions()
{
    m_newVaultAction = new QAction(
        style()->standardIcon(QStyle::SP_FileDialogNewFolder), tr("&New vault…"), this);
    m_newVaultAction->setShortcut(QKeySequence::New);
    connect(m_newVaultAction, &QAction::triggered, this, &MainWindow::createVault);

    m_openVaultAction = new QAction(
        style()->standardIcon(QStyle::SP_DirOpenIcon), tr("&Open vault…"), this);
    m_openVaultAction->setShortcut(QKeySequence::Open);
    connect(m_openVaultAction, &QAction::triggered, this, &MainWindow::openVault);

    m_lockVaultAction = new QAction(
        style()->standardIcon(QStyle::SP_DialogCloseButton), tr("&Lock vault"), this);
    connect(m_lockVaultAction, &QAction::triggered, this, &MainWindow::lockCurrentVault);

    m_addEntryAction = new QAction(
        style()->standardIcon(QStyle::SP_FileIcon), tr("&Add entry…"), this);
    connect(m_addEntryAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->addEntry();
    });

    m_editEntryAction = new QAction(
        style()->standardIcon(QStyle::SP_FileDialogDetailedView), tr("&Edit entry…"), this);
    connect(m_editEntryAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->editSelectedEntry();
    });

    m_deleteEntryAction = new QAction(
        style()->standardIcon(QStyle::SP_TrashIcon), tr("&Delete entry"), this);
    connect(m_deleteEntryAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->deleteSelectedEntry();
    });

    m_copyPasswordAction = new QAction(tr("Copy &password"), this);
    connect(m_copyPasswordAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->copySelectedPassword();
    });

    m_copyUsernameAction = new QAction(tr("Copy user &name"), this);
    connect(m_copyUsernameAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->copySelectedUsername();
    });

    m_detailsAction = new QAction(
        style()->standardIcon(QStyle::SP_FileDialogDetailedView), tr("&Details"), this);
    connect(m_detailsAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->showDetails();
    });

    m_iconsAction = new QAction(
        style()->standardIcon(QStyle::SP_FileDialogListView), tr("&Icons"), this);
    connect(m_iconsAction, &QAction::triggered, this, [this] {
        if (auto *view = currentVaultView())
            view->showIcons();
    });
}

void MainWindow::createMenus()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(m_newVaultAction);
    fileMenu->addAction(m_openVaultAction);
    fileMenu->addSeparator();
    fileMenu->addAction(m_lockVaultAction);
    fileMenu->addSeparator();

    QAction *quitAction = fileMenu->addAction(tr("E&xit"));
    quitAction->setShortcut(QKeySequence::Quit);
    connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);

    QMenu *editMenu = menuBar()->addMenu(tr("&Edit"));
    editMenu->addAction(m_addEntryAction);
    editMenu->addAction(m_editEntryAction);
    editMenu->addAction(m_deleteEntryAction);
    editMenu->addSeparator();
    editMenu->addAction(m_copyPasswordAction);
    editMenu->addAction(m_copyUsernameAction);

    QMenu *viewMenu = menuBar()->addMenu(tr("&View"));
    viewMenu->addAction(m_detailsAction);
    viewMenu->addAction(m_iconsAction);

    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    QAction *aboutAction = helpMenu->addAction(tr("&About"));
    connect(aboutAction, &QAction::triggered, this, &MainWindow::showAbout);
}

void MainWindow::createToolBar()
{
    auto *toolBar = addToolBar(tr("Main"));
    toolBar->setObjectName(QStringLiteral("mainToolBar"));
    toolBar->setMovable(false);
    toolBar->addAction(m_newVaultAction);
    toolBar->addAction(m_openVaultAction);
    toolBar->addSeparator();
    toolBar->addAction(m_addEntryAction);
    toolBar->addAction(m_editEntryAction);
    toolBar->addAction(m_deleteEntryAction);
    toolBar->addSeparator();
    toolBar->addAction(m_detailsAction);
    toolBar->addAction(m_iconsAction);
    toolBar->addSeparator();

    m_searchEdit = new QLineEdit(toolBar);
    m_searchEdit->setObjectName(QStringLiteral("vaultSearch"));
    m_searchEdit->setPlaceholderText(tr("Search"));
    m_searchEdit->setClearButtonEnabled(true);
    m_searchEdit->setMaximumWidth(220);
    connect(m_searchEdit, &QLineEdit::textChanged, this, &MainWindow::filterCurrentVault);
    toolBar->addWidget(m_searchEdit);
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

    const QString path = dialog.path();
    openVaultAt(path);
    if (m_vaultViews.contains(canonicalVaultPath(path)))
        showVault(path);
    else
        unlockVault(path);
}

void MainWindow::openVaultAt(QString path)
{
    path = canonicalVaultPath(path);
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

void MainWindow::unlockVault(const QString &rawPath)
{
    const QString path = canonicalVaultPath(rawPath);
    if (auto *view = m_vaultViews.value(path)) {
        m_centerStack->setCurrentWidget(m_vaultTabs);
        m_vaultTabs->setCurrentWidget(view);
        return;
    }

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
    showVault(path);
    statusBar()->showMessage(tr("Vault unlocked: %1").arg(path));
}

void MainWindow::lockVault(const QString &rawPath)
{
    const QString path = canonicalVaultPath(rawPath);
    m_unlockedVaults.erase(path);
    m_welcome->setVaultUnlocked(path, false);

    if (auto *view = m_vaultViews.take(path)) {
        const int index = m_vaultTabs->indexOf(view);
        if (index >= 0)
            m_vaultTabs->removeTab(index);
        view->deleteLater();
    }

    if (m_vaultTabs->count() == 0)
        m_centerStack->setCurrentWidget(m_welcome);
    updateWorkspaceActions();
    statusBar()->showMessage(tr("Vault locked: %1").arg(path));
}

void MainWindow::closeVaultTab(int index)
{
    auto *view = qobject_cast<VaultView *>(m_vaultTabs->widget(index));
    if (view)
        lockVault(view->vaultPath());
}

void MainWindow::showVault(const QString &rawPath)
{
    const QString path = canonicalVaultPath(rawPath);
    if (auto *view = m_vaultViews.value(path)) {
        m_centerStack->setCurrentWidget(m_vaultTabs);
        m_vaultTabs->setCurrentWidget(view);
        return;
    }

    auto *view = new VaultView(path, m_vaultTabs);
    connect(view, &VaultView::statusMessage, this,
            [this](const QString &message) { statusBar()->showMessage(message); });

    const QString name = QFileInfo(path).fileName();
    const int index = m_vaultTabs->addTab(view, name.isEmpty() ? path : name);
    m_vaultTabs->setTabToolTip(index, path);
    m_vaultViews.insert(path, view);

    m_centerStack->setCurrentWidget(m_vaultTabs);
    m_vaultTabs->setCurrentIndex(index);
    updateWorkspaceActions();
    statusBar()->showMessage(tr("Vault open: %1").arg(path));
}

VaultView *MainWindow::currentVaultView() const
{
    return qobject_cast<VaultView *>(m_vaultTabs->currentWidget());
}

void MainWindow::updateWorkspaceActions()
{
    const bool hasVault = currentVaultView() != nullptr;
    const QList<QAction *> actions = {
        m_lockVaultAction, m_addEntryAction, m_editEntryAction, m_deleteEntryAction,
        m_copyPasswordAction, m_copyUsernameAction, m_detailsAction, m_iconsAction,
    };
    for (QAction *action : actions)
        action->setEnabled(hasVault);

    m_searchEdit->setEnabled(hasVault);
    if (!hasVault)
        m_searchEdit->clear();
}

void MainWindow::onVaultTabChanged(int)
{
    updateWorkspaceActions();
    if (auto *view = currentVaultView()) {
        m_searchEdit->clear();
        statusBar()->showMessage(tr("Vault: %1").arg(view->vaultPath()));
    }
}

void MainWindow::filterCurrentVault(const QString &text)
{
    if (auto *view = currentVaultView())
        view->setFilter(text);
}

void MainWindow::lockCurrentVault()
{
    if (auto *view = currentVaultView())
        lockVault(view->vaultPath());
}

void MainWindow::showAbout()
{
    QMessageBox::about(this, tr("About CryptOwl Desktop"),
                       tr("<b>CryptOwl Desktop</b> %1<br><br>"
                          "Local-first encrypted vault: notes, passwords, photos and videos.<br>"
                          "No plaintext data at rest.")
                           .arg(QCoreApplication::applicationVersion()));
}
