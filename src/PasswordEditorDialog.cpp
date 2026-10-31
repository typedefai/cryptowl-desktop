#include "PasswordEditorDialog.h"

#include "EncryptedContentWidget.h"

#include <QColor>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QStandardItemModel>
#include <QVBoxLayout>

#include <utility>

PasswordEditorDialog::PasswordEditorDialog(QWidget *parent)
    : QDialog(parent)
{
    buildUi(false);
    m_passwordWidget->setContent(QString(), true);
    m_notesWidget->setContent(QString());
    updateSaveButton();
}

PasswordEditorDialog::PasswordEditorDialog(const Data &data, QWidget *parent)
    : PasswordEditorDialog(data, SecretLoader(), parent)
{
}

PasswordEditorDialog::PasswordEditorDialog(const Data &data, SecretLoader loader,
                                           QWidget *parent)
    : QDialog(parent)
    , m_secretLoader(std::move(loader))
{
    buildUi(true);
    m_titleEdit->setText(data.title);
    m_usernameEdit->setText(data.username);
    m_urlEdit->setText(data.url);
    const int classificationIndex =
        m_classificationCombo->findData(data.classification);
    m_classificationCombo->setCurrentIndex(classificationIndex >= 0
                                               ? classificationIndex
                                               : 0);

    if (m_secretLoader) {
        m_passwordWidget->setLoader([this](QString *password, QString *error) {
            QString notes;
            if (!m_secretLoader(password, &notes, error))
                return false;
            notes.fill(QChar('\0'));
            return true;
        });
        m_notesWidget->setLoader([this](QString *notes, QString *error) {
            QString password;
            if (!m_secretLoader(&password, notes, error))
                return false;
            password.fill(QChar('\0'));
            return true;
        });
    } else {
        m_passwordWidget->setContent(data.password, true);
        m_notesWidget->setContent(data.notes);
    }
    if (m_confirmEdit)
        m_confirmEdit->setText(data.password);
    updateSaveButton();

    m_titleEdit->selectAll();
    m_titleEdit->setFocus();
}

PasswordEditorDialog::Data PasswordEditorDialog::data() const
{
    Data result;
    result.title = m_titleEdit->text().trimmed();
    result.username = m_usernameEdit->text().trimmed();
    result.url = m_urlEdit->text().trimmed();
    result.password = m_passwordWidget->content();
    result.notes = m_notesWidget->content();
    result.classification = m_classificationCombo->currentData().toString();
    if (result.classification.isEmpty())
        result.classification = QStringLiteral("S");
    return result;
}

void PasswordEditorDialog::setTopSecretAvailable(bool available)
{
    const int index = m_classificationCombo->findData(QStringLiteral("T"));
    if (index < 0)
        return;
    if (auto *model =
            qobject_cast<QStandardItemModel *>(m_classificationCombo->model())) {
        if (auto *item = model->item(index))
            item->setEnabled(available);
    }
    if (m_topSecretHint)
        m_topSecretHint->setVisible(!available);
}

void PasswordEditorDialog::setSaveAuthorizer(SaveAuthorizer authorizer)
{
    m_saveAuthorizer = std::move(authorizer);
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

    m_passwordWidget =
        new EncryptedContentWidget(EncryptedContentWidget::Mode::SingleLine, this);
    m_passwordWidget->setObjectName(QStringLiteral("passwordSecretWidget"));
    m_passwordWidget->setPlaceholderText(tr("Password"));

    m_notesWidget =
        new EncryptedContentWidget(EncryptedContentWidget::Mode::MultiLine, this);
    m_notesWidget->setObjectName(QStringLiteral("passwordNotesWidget"));
    m_notesWidget->setPlaceholderText(tr("Notes"));

    m_classificationCombo = new QComboBox(this);
    m_classificationCombo->setObjectName(QStringLiteral("passwordClassification"));
    m_classificationCombo->addItem(tr("Secret (S)"), QStringLiteral("S"));
    m_classificationCombo->addItem(tr("Top Secret (T)"), QStringLiteral("T"));

    m_confirmEdit = new QLineEdit(this);
    m_confirmEdit->setObjectName(QStringLiteral("passwordConfirm"));
    m_confirmEdit->setEchoMode(QLineEdit::Password);
    m_confirmEdit->setPlaceholderText(tr("Re-enter password"));

    form->addRow(tr("Title:"), m_titleEdit);
    form->addRow(tr("User name:"), m_usernameEdit);
    form->addRow(tr("URL:"), m_urlEdit);
    form->addRow(tr("Password:"), m_passwordWidget);
    form->addRow(tr("Confirm password:"), m_confirmEdit);
    form->addRow(tr("Notes:"), m_notesWidget);
    form->addRow(tr("Confidentiality:"), m_classificationCombo);
    layout->addLayout(form);

    auto *classificationHelp = new QLabel(
        tr("Secret passwords use the vault's item key. "
           "Top Secret passwords require the secondary password for every "
           "access."),
        this);
    classificationHelp->setWordWrap(true);
    layout->addWidget(classificationHelp);

    m_topSecretHint = new QLabel(
        tr("Top Secret is not set up yet. Use File → Set up Top Secret… first."),
        this);
    m_topSecretHint->setObjectName(QStringLiteral("passwordTopSecretHint"));
    m_topSecretHint->setWordWrap(true);
    m_topSecretHint->hide();
    layout->addWidget(m_topSecretHint);

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
    m_saveButton->setObjectName(QStringLiteral("passwordSave"));
    m_saveButton->setText(tr("Save"));
    m_saveButton->setDefault(true);
    m_saveButton->setEnabled(false);
    connect(buttons, &QDialogButtonBox::accepted, this, &PasswordEditorDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &PasswordEditorDialog::reject);
    layout->addWidget(buttons);

    connect(m_passwordWidget, &EncryptedContentWidget::revealed, this,
            &PasswordEditorDialog::updateSaveButton);
    connect(m_passwordWidget, &EncryptedContentWidget::hidden, this,
            &PasswordEditorDialog::updateSaveButton);
    connect(m_passwordWidget, &EncryptedContentWidget::errorOccurred, this,
            &PasswordEditorDialog::setError);
    connect(m_notesWidget, &EncryptedContentWidget::revealed, this,
            &PasswordEditorDialog::updateSaveButton);
    connect(m_notesWidget, &EncryptedContentWidget::hidden, this,
            &PasswordEditorDialog::updateSaveButton);
    connect(m_notesWidget, &EncryptedContentWidget::errorOccurred, this,
            &PasswordEditorDialog::setError);

    m_titleEdit->setFocus();
}

void PasswordEditorDialog::updateSaveButton()
{
    m_saveButton->setEnabled(m_passwordWidget->isLoaded()
                             && m_notesWidget->isLoaded());
}

void PasswordEditorDialog::save()
{
    if (!m_passwordWidget->isLoaded() || !m_notesWidget->isLoaded()) {
        setError(tr("Show the password and notes before saving."));
        return;
    }
    if (m_titleEdit->text().trimmed().isEmpty()) {
        setError(tr("Enter a title for this password."));
        m_titleEdit->setFocus();
        return;
    }
    if (m_confirmEdit
        && m_confirmEdit->text() != m_passwordWidget->content()) {
        setError(tr("Passwords do not match."));
        m_confirmEdit->setFocus();
        m_confirmEdit->selectAll();
        return;
    }

    const Data current = data();
    if (m_saveAuthorizer) {
        QString error;
        if (!m_saveAuthorizer(current, &error)) {
            setError(error.isEmpty() ? tr("This save was not authorized.") : error);
            return;
        }
    }

    setError(QString());
    if (m_confirmEdit)
        m_confirmEdit->clear();
    accept();
}

void PasswordEditorDialog::reject()
{
    m_passwordWidget->setContent(QString(), true);
    m_notesWidget->setContent(QString());
    if (m_confirmEdit)
        m_confirmEdit->clear();
    QDialog::reject();
}

void PasswordEditorDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
