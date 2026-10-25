#include "PasswordEditorDialog.h"

#include <QCheckBox>
#include <QColor>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

PasswordEditorDialog::PasswordEditorDialog(QWidget *parent)
    : QDialog(parent)
{
    buildUi(false);
}

PasswordEditorDialog::PasswordEditorDialog(const Data &data, QWidget *parent)
    : QDialog(parent)
{
    buildUi(true);
    m_titleEdit->setText(data.title);
    m_usernameEdit->setText(data.username);
    m_urlEdit->setText(data.url);
    m_passwordEdit->setText(data.password);
    m_notesEdit->setPlainText(data.notes);
    m_titleEdit->selectAll();
    m_titleEdit->setFocus();
}

PasswordEditorDialog::Data PasswordEditorDialog::data() const
{
    Data result;
    result.title = m_titleEdit->text().trimmed();
    result.username = m_usernameEdit->text().trimmed();
    result.url = m_urlEdit->text().trimmed();
    result.password = m_passwordEdit->text();
    result.notes = m_notesEdit->toPlainText();
    return result;
}

void PasswordEditorDialog::buildUi(bool editing)
{
    setWindowTitle(editing ? tr("Edit password") : tr("New password"));
    setModal(true);
    setMinimumWidth(440);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(10);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    m_titleEdit = new QLineEdit(this);
    m_titleEdit->setObjectName(QStringLiteral("passwordTitle"));
    m_titleEdit->setPlaceholderText(tr("Required"));

    m_usernameEdit = new QLineEdit(this);
    m_usernameEdit->setObjectName(QStringLiteral("passwordUsername"));

    m_urlEdit = new QLineEdit(this);
    m_urlEdit->setObjectName(QStringLiteral("passwordUrl"));
    m_urlEdit->setPlaceholderText(QStringLiteral("https://"));

    auto *passwordRow = new QWidget(this);
    auto *passwordLayout = new QVBoxLayout(passwordRow);
    passwordLayout->setContentsMargins(0, 0, 0, 0);
    passwordLayout->setSpacing(4);

    m_passwordEdit = new QLineEdit(passwordRow);
    m_passwordEdit->setObjectName(QStringLiteral("passwordSecret"));
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    passwordLayout->addWidget(m_passwordEdit);

    m_showPassword = new QCheckBox(tr("Show password"), passwordRow);
    m_showPassword->setObjectName(QStringLiteral("passwordShow"));
    connect(m_showPassword, &QCheckBox::toggled, this, [this](bool checked) {
        m_passwordEdit->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });
    passwordLayout->addWidget(m_showPassword);

    m_notesEdit = new QPlainTextEdit(this);
    m_notesEdit->setObjectName(QStringLiteral("passwordNotes"));
    m_notesEdit->setMinimumHeight(90);

    form->addRow(tr("Title:"), m_titleEdit);
    form->addRow(tr("User name:"), m_usernameEdit);
    form->addRow(tr("URL:"), m_urlEdit);
    form->addRow(tr("Password:"), passwordRow);
    form->addRow(tr("Notes:"), m_notesEdit);
    layout->addLayout(form);

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("passwordError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();
    layout->addWidget(m_errorLabel);

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    m_saveButton = buttons->button(QDialogButtonBox::Save);
    m_saveButton->setText(tr("Save"));
    m_saveButton->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this, &PasswordEditorDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &PasswordEditorDialog::reject);
    layout->addWidget(buttons);

    m_titleEdit->setFocus();
}

void PasswordEditorDialog::save()
{
    if (m_titleEdit->text().trimmed().isEmpty()) {
        setError(tr("Enter a title for this password."));
        m_titleEdit->setFocus();
        return;
    }

    setError(QString());
    m_passwordEdit->setEchoMode(QLineEdit::Password);
    accept();
}

void PasswordEditorDialog::reject()
{
    m_passwordEdit->clear();
    QDialog::reject();
}

void PasswordEditorDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
