#include "VaultPathDialog.h"

#include "VaultDirectory.h"

#include <QColor>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QStandardPaths>
#include <QVBoxLayout>

namespace {

bool isEmptyDirectory(const QString &path)
{
    const QFileInfo info(path);
    return info.isDir()
        && QDir(path).entryList(QDir::AllEntries | QDir::NoDotAndDotDot).isEmpty();
}

} // namespace

VaultPathDialog::VaultPathDialog(Mode mode, QWidget *parent)
    : QDialog(parent)
    , m_mode(mode)
{
    const bool openMode = m_mode == Mode::Open;
    setWindowTitle(openMode ? tr("Open vault") : tr("Create vault"));
    setModal(true);
    setMinimumWidth(520);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(8);

    auto *heading = new QLabel(openMode ? tr("Open a vault") : tr("Create a vault"), this);
    QFont headingFont = heading->font();
    headingFont.setBold(true);
    heading->setFont(headingFont);

    auto *hint = new QLabel(
        openMode ? tr("Enter the path of a CryptOwl vault folder, or browse to select it.")
                 : tr("Enter a folder path, or browse to select it. If the folder does "
                      "not exist it will be created; otherwise it must be empty."),
        this);
    hint->setWordWrap(true);

    m_pathEdit = new QLineEdit(this);
    m_pathEdit->setObjectName(QStringLiteral("vaultPath"));
    m_pathEdit->setClearButtonEnabled(true);
    m_pathEdit->setPlaceholderText(openMode ? tr("/path/to/vault")
                                            : tr("/path/to/empty-folder"));

    QString initialPath =
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (initialPath.isEmpty())
        initialPath = QDir::homePath();
    setPath(initialPath);

    m_browseButton = new QPushButton(tr("Browse…"), this);
    m_browseButton->setObjectName(QStringLiteral("vaultBrowse"));
    connect(m_browseButton, &QPushButton::clicked, this, &VaultPathDialog::browse);

    auto *pathRow = new QHBoxLayout;
    pathRow->setContentsMargins(0, 0, 0, 0);
    pathRow->setSpacing(6);
    pathRow->addWidget(m_pathEdit, 1);
    pathRow->addWidget(m_browseButton);

    auto *pathLabel = new QLabel(tr("Vault folder:"), this);

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("vaultPathError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_acceptButton = buttons->button(QDialogButtonBox::Ok);
    m_acceptButton->setText(openMode ? tr("Open") : tr("Create"));
    m_acceptButton->setDefault(true);

    connect(buttons, &QDialogButtonBox::accepted, this, &VaultPathDialog::tryAccept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    layout->addWidget(heading);
    layout->addWidget(hint);
    layout->addSpacing(4);
    layout->addWidget(pathLabel);
    layout->addLayout(pathRow);
    layout->addWidget(m_errorLabel);
    layout->addWidget(buttons);

    m_pathEdit->setFocus();
}

QString VaultPathDialog::path() const
{
    QString value = m_pathEdit->text().trimmed();
    if (value.isEmpty())
        return {};

    value = QDir::fromNativeSeparators(value);
    if (value == QStringLiteral("~"))
        value = QDir::homePath();
    else if (value.startsWith(QStringLiteral("~/")))
        value = QDir::homePath() + value.mid(1);

    value = QDir::cleanPath(value);
    if (QDir::isRelativePath(value))
        value = QDir::current().absoluteFilePath(value);
    return value;
}

void VaultPathDialog::setPath(const QString &path)
{
    m_pathEdit->setText(QDir::toNativeSeparators(path));
}

void VaultPathDialog::browse()
{
    QString start = path();
    if (!QFileInfo(start).isDir())
        start = QDir::homePath();

    const QString selected = QFileDialog::getExistingDirectory(
        this, m_mode == Mode::Open ? tr("Select vault folder")
                                   : tr("Select empty vault folder"),
        start);
    if (!selected.isEmpty())
        setPath(selected);
}

void VaultPathDialog::tryAccept()
{
    const QString selected = path();
    if (selected.isEmpty()) {
        setError(tr("Enter a vault folder path."));
        return;
    }

    const QFileInfo info(selected);
    if (m_mode == Mode::Open) {
        if (!info.exists()) {
            setError(tr("The selected folder does not exist."));
            return;
        }
        if (!info.isDir()) {
            setError(tr("The selected path is not a folder."));
            return;
        }
        if (!isVaultDirectory(selected)) {
            setError(tr("This is not a CryptOwl vault. Choose a folder containing "
                        "vault.meta."));
            return;
        }
    } else {
        if (info.exists()) {
            if (!info.isDir()) {
                setError(tr("The selected path is not a folder."));
                return;
            }
            if (!isEmptyDirectory(selected)) {
                setError(tr("The selected folder is not empty. Choose another folder "
                            "or enter a new folder path."));
                return;
            }
        } else {
            const QFileInfo parent(info.absolutePath());
            if (!parent.exists()) {
                setError(tr("The parent folder does not exist."));
                return;
            }
            if (!parent.isDir()) {
                setError(tr("The parent path is not a folder."));
                return;
            }
        }
    }

    setError(QString());
    accept();
}

void VaultPathDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
