#include "CreateVaultDialog.h"

#include <QCheckBox>
#include <QColor>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QVBoxLayout>

#include <utility>

CreateVaultDialog::CreateVaultDialog(QString vaultName, QWidget *parent)
    : QDialog(parent)
    , m_vaultName(std::move(vaultName))
{
    setWindowTitle(tr("Create %1").arg(m_vaultName));
    setModal(true);
    setMinimumWidth(420);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(8);

    auto *heading =
        new QLabel(tr("Create <b>%1</b>").arg(m_vaultName.toHtmlEscaped()), this);
    heading->setTextFormat(Qt::RichText);

    auto *note = new QLabel(
        tr("Choose a master password. It cannot be recovered if you forget it."), this);
    note->setWordWrap(true);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setObjectName(QStringLiteral("vaultPassword"));
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText(tr("Master password"));

    m_confirmEdit = new QLineEdit(this);
    m_confirmEdit->setObjectName(QStringLiteral("vaultPasswordConfirm"));
    m_confirmEdit->setEchoMode(QLineEdit::Password);
    m_confirmEdit->setPlaceholderText(tr("Confirm master password"));

    m_showPassword = new QCheckBox(tr("Show passwords"), this);
    connect(m_showPassword, &QCheckBox::toggled, this, [this](bool checked) {
        const auto mode = checked ? QLineEdit::Normal : QLineEdit::Password;
        m_passwordEdit->setEchoMode(mode);
        m_confirmEdit->setEchoMode(mode);
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
    m_createButton = buttons->button(QDialogButtonBox::Ok);
    m_createButton->setText(tr("Create"));
    m_createButton->setDefault(true);

    connect(buttons, &QDialogButtonBox::accepted, this, &CreateVaultDialog::tryCreate);
    connect(buttons, &QDialogButtonBox::rejected, this, &CreateVaultDialog::reject);
    connect(m_confirmEdit, &QLineEdit::returnPressed, this, &CreateVaultDialog::tryCreate);

    layout->addWidget(heading);
    layout->addWidget(note);
    layout->addSpacing(4);
    layout->addWidget(m_passwordEdit);
    layout->addWidget(m_confirmEdit);
    layout->addWidget(m_showPassword);
    layout->addWidget(m_errorLabel);
    layout->addWidget(buttons);

    m_passwordEdit->setFocus();
}

QString CreateVaultDialog::password() const
{
    return m_passwordEdit->text();
}

void CreateVaultDialog::reject()
{
    m_passwordEdit->clear();
    m_confirmEdit->clear();
    QDialog::reject();
}

void CreateVaultDialog::tryCreate()
{
    if (!m_createButton->isEnabled())
        return;

    if (m_passwordEdit->text().isEmpty()) {
        setError(tr("Enter a master password."));
        return;
    }
    if (m_passwordEdit->text() != m_confirmEdit->text()) {
        setError(tr("The passwords do not match."));
        m_confirmEdit->selectAll();
        m_confirmEdit->setFocus();
        return;
    }

    setError(QString());
    accept();
}

void CreateVaultDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
