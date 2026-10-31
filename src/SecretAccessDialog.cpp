#include "SecretAccessDialog.h"

#include <QCheckBox>
#include <QColor>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QVBoxLayout>

SecretAccessDialog::SecretAccessDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Unlock Secret access"));
    setModal(true);
    setMinimumWidth(420);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(8);

    auto *heading = new QLabel(
        tr("<b>Secret-tier access</b><br>"
           "Enter the master password for this access. It is not stored."),
        this);
    heading->setTextFormat(Qt::RichText);
    heading->setWordWrap(true);

    m_passwordEdit = new QLineEdit(this);
    m_passwordEdit->setObjectName(QStringLiteral("secretAccessPassword"));
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    m_passwordEdit->setPlaceholderText(tr("Master password"));

    m_showPassword = new QCheckBox(tr("Show password"), this);
    m_showPassword->setObjectName(QStringLiteral("secretAccessShow"));
    connect(m_showPassword, &QCheckBox::toggled, this, [this](bool checked) {
        m_passwordEdit->setEchoMode(checked ? QLineEdit::Normal
                                            : QLineEdit::Password);
    });

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("secretAccessError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_unlockButton = buttons->button(QDialogButtonBox::Ok);
    m_unlockButton->setObjectName(QStringLiteral("secretAccessUnlock"));
    m_unlockButton->setText(tr("Unlock"));
    m_unlockButton->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this,
            &SecretAccessDialog::acceptAccess);
    connect(buttons, &QDialogButtonBox::rejected, this,
            &SecretAccessDialog::reject);
    connect(m_passwordEdit, &QLineEdit::returnPressed, this,
            &SecretAccessDialog::acceptAccess);

    layout->addWidget(heading);
    layout->addWidget(m_passwordEdit);
    layout->addWidget(m_showPassword);
    layout->addWidget(m_errorLabel);
    layout->addWidget(buttons);

    m_passwordEdit->setFocus();
}

QString SecretAccessDialog::takePassword()
{
    QString password = m_passwordEdit->text();
    m_passwordEdit->clear();
    return password;
}

void SecretAccessDialog::reject()
{
    m_passwordEdit->clear();
    QDialog::reject();
}

void SecretAccessDialog::acceptAccess()
{
    if (m_passwordEdit->text().isEmpty()) {
        setError(tr("Enter the master password."));
        return;
    }
    setError(QString());
    accept();
}

void SecretAccessDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
