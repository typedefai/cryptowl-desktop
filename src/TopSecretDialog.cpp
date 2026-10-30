#include "TopSecretDialog.h"

#include "TopSecretService.h"
#include "VaultUnlocker.h"

#include "crypto/Bytes.h"

#include <QApplication>
#include <QCheckBox>
#include <QColor>
#include <QDialogButtonBox>
#include <QEventLoop>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QVBoxLayout>

#include <span>
#include <utility>

namespace {

void wipe(QString &value)
{
    value.fill(QLatin1Char('\0'));
}

void wipe(QByteArray &value)
{
    value.fill('\0');
}

} // namespace

TopSecretUnlockDialog::TopSecretUnlockDialog(TopSecretService *service,
                                             QWidget *parent)
    : QDialog(parent)
    , m_service(service)
{
    setWindowTitle(tr("Unlock Top Secret"));
    setModal(true);
    setMinimumWidth(400);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(8);

    auto *heading = new QLabel(
        tr("<b>Top Secret content</b><br>"
           "Enter the secondary password to decrypt this item."),
        this);
    heading->setTextFormat(Qt::RichText);
    heading->setWordWrap(true);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setObjectName(QStringLiteral("topSecretPassword"));
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText(tr("Secondary password"));

    m_showPassword = new QCheckBox(tr("Show password"), this);
    m_showPassword->setObjectName(QStringLiteral("topSecretShow"));
    connect(m_showPassword, &QCheckBox::toggled, this, [this](bool checked) {
        m_passwordEdit->setEchoMode(checked ? QLineEdit::Normal
                                            : QLineEdit::Password);
    });

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("topSecretError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_unlockButton = buttons->button(QDialogButtonBox::Ok);
    m_unlockButton->setObjectName(QStringLiteral("topSecretUnlock"));
    m_unlockButton->setText(tr("Unlock"));
    m_unlockButton->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this,
            &TopSecretUnlockDialog::tryUnlock);
    connect(buttons, &QDialogButtonBox::rejected, this,
            &TopSecretUnlockDialog::reject);
    connect(m_passwordEdit, &QLineEdit::returnPressed, this,
            &TopSecretUnlockDialog::tryUnlock);

    layout->addWidget(heading);
    layout->addWidget(m_passwordEdit);
    layout->addWidget(m_showPassword);
    layout->addWidget(m_errorLabel);
    layout->addWidget(buttons);

    m_passwordEdit->setFocus();
}

cryptowl::crypto::ProtectedValue TopSecretUnlockDialog::takeTopSecretKek()
{
    return std::move(m_topSecretKek);
}

void TopSecretUnlockDialog::reject()
{
    m_passwordEdit->clear();
    m_topSecretKek.clear();
    QDialog::reject();
}

void TopSecretUnlockDialog::tryUnlock()
{
    if (!m_unlockButton->isEnabled())
        return;
    if (!m_service) {
        setError(tr("Top Secret is not available."));
        return;
    }

    QString password = m_passwordEdit->text();
    if (password.isEmpty()) {
        setError(tr("Enter the secondary password."));
        return;
    }

    setError(QString());
    setBusy(true);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);

    QByteArray passwordUtf8 = password.toUtf8();
    wipe(password);
    const auto passwordSpan = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(passwordUtf8.constData()),
        static_cast<std::size_t>(passwordUtf8.size()));
    QString error;
    const bool unlocked = m_service->unlock(passwordSpan, &m_topSecretKek, &error);
    wipe(passwordUtf8);

    QApplication::restoreOverrideCursor();
    setBusy(false);

    if (!unlocked) {
        setError(error.isEmpty() ? tr("Could not unlock Top Secret.") : error);
        m_passwordEdit->selectAll();
        m_passwordEdit->setFocus();
        return;
    }

    m_passwordEdit->clear();
    accept();
}

void TopSecretUnlockDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}

void TopSecretUnlockDialog::setBusy(bool busy)
{
    m_passwordEdit->setEnabled(!busy);
    m_showPassword->setEnabled(!busy);
    m_unlockButton->setEnabled(!busy);
}

TopSecretSetupDialog::TopSecretSetupDialog(QString vaultPath, sqlite3 *database,
                                           QWidget *parent)
    : QDialog(parent)
    , m_vaultPath(std::move(vaultPath))
    , m_database(database)
{
    setWindowTitle(tr("Set up Top Secret"));
    setModal(true);
    setMinimumWidth(460);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(10);

    auto *heading = new QLabel(tr("<b>Enable Top Secret (T tier)</b>"), this);
    heading->setTextFormat(Qt::RichText);

    auto *warning = new QLabel(
        tr("Top Secret adds a second password on top of the vault password. "
           "It is required every time T content is revealed or saved. "
           "There is no recovery if it is forgotten. Item titles and other "
           "metadata remain visible, and on desktop there is no biometric "
           "factor — T is a second password, not two-factor authentication."),
        this);
    warning->setWordWrap(true);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    m_masterPasswordEdit = new QLineEdit(this);
    m_masterPasswordEdit->setObjectName(QStringLiteral("topSecretMasterPassword"));
    m_masterPasswordEdit->setEchoMode(QLineEdit::Password);
    m_masterPasswordEdit->setPlaceholderText(tr("Re-enter the vault master password"));

    m_secondaryPasswordEdit = new QLineEdit(this);
    m_secondaryPasswordEdit->setObjectName(QStringLiteral("topSecretSecondaryPassword"));
    m_secondaryPasswordEdit->setEchoMode(QLineEdit::Password);
    m_secondaryPasswordEdit->setPlaceholderText(tr("At least 8 characters"));

    m_confirmEdit = new QLineEdit(this);
    m_confirmEdit->setObjectName(QStringLiteral("topSecretConfirm"));
    m_confirmEdit->setEchoMode(QLineEdit::Password);
    m_confirmEdit->setPlaceholderText(tr("Repeat the secondary password"));

    m_showPasswords = new QCheckBox(tr("Show passwords"), this);
    m_showPasswords->setObjectName(QStringLiteral("topSecretShowPasswords"));
    connect(m_showPasswords, &QCheckBox::toggled, this, [this](bool checked) {
        const auto mode = checked ? QLineEdit::Normal : QLineEdit::Password;
        m_masterPasswordEdit->setEchoMode(mode);
        m_secondaryPasswordEdit->setEchoMode(mode);
        m_confirmEdit->setEchoMode(mode);
    });

    form->addRow(tr("Master password:"), m_masterPasswordEdit);
    form->addRow(tr("Secondary password:"), m_secondaryPasswordEdit);
    form->addRow(tr("Confirm:"), m_confirmEdit);
    layout->addWidget(heading);
    layout->addWidget(warning);
    layout->addLayout(form);
    layout->addWidget(m_showPasswords);

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("topSecretSetupError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();
    layout->addWidget(m_errorLabel);

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_setupButton = buttons->button(QDialogButtonBox::Ok);
    m_setupButton->setObjectName(QStringLiteral("topSecretSetup"));
    m_setupButton->setText(tr("Enable Top Secret"));
    m_setupButton->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this,
            &TopSecretSetupDialog::trySetup);
    connect(buttons, &QDialogButtonBox::rejected, this,
            &TopSecretSetupDialog::reject);
    layout->addWidget(buttons);

    m_masterPasswordEdit->setFocus();
}

void TopSecretSetupDialog::reject()
{
    m_masterPasswordEdit->clear();
    m_secondaryPasswordEdit->clear();
    m_confirmEdit->clear();
    QDialog::reject();
}

void TopSecretSetupDialog::trySetup()
{
    if (!m_setupButton->isEnabled())
        return;

    QString master = m_masterPasswordEdit->text();
    QString secondary = m_secondaryPasswordEdit->text();
    const QString confirm = m_confirmEdit->text();
    if (master.isEmpty()) {
        setError(tr("Re-enter the vault master password."));
        m_masterPasswordEdit->setFocus();
        return;
    }
    if (secondary.size() < 8) {
        setError(tr("Use at least 8 characters for the secondary password."));
        m_secondaryPasswordEdit->setFocus();
        return;
    }
    if (secondary != confirm) {
        setError(tr("The secondary passwords do not match."));
        m_confirmEdit->selectAll();
        m_confirmEdit->setFocus();
        return;
    }

    setError(QString());
    setBusy(true);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);

    auto unlock = VaultUnlocker::unlock(m_vaultPath, master, false);
    if (!unlock.ok) {
        QApplication::restoreOverrideCursor();
        setBusy(false);
        wipe(master);
        wipe(secondary);
        setError(unlock.error.isEmpty() ? tr("Could not verify the master password.")
                                        : unlock.error);
        m_masterPasswordEdit->selectAll();
        m_masterPasswordEdit->setFocus();
        return;
    }

    QByteArray secondaryUtf8 = secondary.toUtf8();
    wipe(master);
    wipe(secondary);
    const auto secondarySpan = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(secondaryUtf8.constData()),
        static_cast<std::size_t>(secondaryUtf8.size()));
    QString error;
    TopSecretService service(m_vaultPath, m_database);
    const bool configured = service.setup(unlock.smk.span(), secondarySpan, &error);
    wipe(secondaryUtf8);

    QApplication::restoreOverrideCursor();
    setBusy(false);

    if (!configured) {
        setError(error.isEmpty() ? tr("Could not set up Top Secret.") : error);
        return;
    }

    m_masterPasswordEdit->clear();
    m_secondaryPasswordEdit->clear();
    m_confirmEdit->clear();
    accept();
}

void TopSecretSetupDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}

void TopSecretSetupDialog::setBusy(bool busy)
{
    m_masterPasswordEdit->setEnabled(!busy);
    m_secondaryPasswordEdit->setEnabled(!busy);
    m_confirmEdit->setEnabled(!busy);
    m_showPasswords->setEnabled(!busy);
    m_setupButton->setEnabled(!busy);
}
