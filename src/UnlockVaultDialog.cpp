#include "UnlockVaultDialog.h"

#include "VaultUnlocker.h"

#include <QApplication>
#include <QCheckBox>
#include <QColor>
#include <QDialogButtonBox>
#include <QEventLoop>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QVBoxLayout>

#include <utility>

UnlockVaultDialog::UnlockVaultDialog(QString vaultPath, QWidget *parent)
    : QDialog(parent)
    , m_vaultPath(std::move(vaultPath))
{
    const QString name = QFileInfo(m_vaultPath).fileName();
    setWindowTitle(tr("Unlock %1").arg(name));
    setModal(true);
    setMinimumWidth(380);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(8);

    auto *heading = new QLabel(
        tr("Unlock <b>%1</b>").arg(name.toHtmlEscaped()), this);
    heading->setTextFormat(Qt::RichText);

    auto *prompt = new QLabel(tr("Enter the master password:"), this);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setObjectName(QStringLiteral("vaultPassword"));
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText(tr("Master password"));

    m_showPassword = new QCheckBox(tr("Show password"), this);
    connect(m_showPassword, &QCheckBox::toggled, this, [this](bool checked) {
        m_passwordEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("vaultError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_unlockButton = buttons->button(QDialogButtonBox::Ok);
    m_unlockButton->setText(tr("Unlock"));
    m_unlockButton->setDefault(true);

    connect(buttons, &QDialogButtonBox::accepted, this, &UnlockVaultDialog::tryUnlock);
    connect(buttons, &QDialogButtonBox::rejected, this, &UnlockVaultDialog::reject);
    connect(m_passwordEdit, &QLineEdit::returnPressed, this,
            &UnlockVaultDialog::tryUnlock);

    layout->addWidget(heading);
    layout->addWidget(prompt);
    layout->addWidget(m_passwordEdit);
    layout->addWidget(m_showPassword);
    layout->addWidget(m_errorLabel);
    layout->addWidget(buttons);

    m_passwordEdit->setFocus();
}

cryptowl::crypto::ProtectedValue UnlockVaultDialog::takeVaultKey()
{
    return std::move(m_vaultKey);
}

void UnlockVaultDialog::reject()
{
    m_passwordEdit->clear();
    m_vaultKey.clear();
    QDialog::reject();
}

void UnlockVaultDialog::tryUnlock()
{
    if (!m_unlockButton->isEnabled())
        return;

    QString password = m_passwordEdit->text();
    if (password.isEmpty()) {
        setError(tr("Enter the master password."));
        return;
    }

    setError(QString());
    setBusy(true);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);

    auto result = VaultUnlocker::unlock(m_vaultPath, password);
    password.fill(QLatin1Char('\0'));

    QApplication::restoreOverrideCursor();
    setBusy(false);

    if (!result.ok) {
        setError(result.error.isEmpty() ? tr("Could not unlock vault.") : result.error);
        m_passwordEdit->selectAll();
        m_passwordEdit->setFocus();
        return;
    }

    m_vaultKey = std::move(result.vaultKey);
    m_passwordEdit->clear();
    accept();
}

void UnlockVaultDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}

void UnlockVaultDialog::setBusy(bool busy)
{
    m_passwordEdit->setEnabled(!busy);
    m_showPassword->setEnabled(!busy);
    m_unlockButton->setEnabled(!busy);
}
