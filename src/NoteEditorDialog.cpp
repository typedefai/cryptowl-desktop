#include "NoteEditorDialog.h"

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

NoteEditorDialog::NoteEditorDialog(QWidget *parent)
    : QDialog(parent)
{
    buildUi(false);
    m_bodyWidget->setContent(QString());
    updateSaveButton();
}

NoteEditorDialog::NoteEditorDialog(const Data &data, QWidget *parent)
    : NoteEditorDialog(data, ContentLoader(), parent)
{
}

NoteEditorDialog::NoteEditorDialog(const Data &data, ContentLoader loader,
                                   QWidget *parent)
    : QDialog(parent)
{
    buildUi(true);
    m_titleEdit->setText(data.title);
    const int index = m_classificationCombo->findData(data.classification);
    m_classificationCombo->setCurrentIndex(index >= 0 ? index : 0);

    if (loader)
        m_bodyWidget->setLoader(std::move(loader));
    else
        m_bodyWidget->setContent(data.body);
    updateSaveButton();

    m_titleEdit->selectAll();
    m_titleEdit->setFocus();
}

NoteEditorDialog::Data NoteEditorDialog::data() const
{
    Data result;
    result.title = m_titleEdit->text().trimmed();
    result.body = m_bodyWidget->content();
    result.classification = m_classificationCombo->currentData().toString();
    if (result.classification.isEmpty())
        result.classification = QStringLiteral("C");
    return result;
}

void NoteEditorDialog::setTopSecretAvailable(bool available)
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

void NoteEditorDialog::setSaveAuthorizer(SaveAuthorizer authorizer)
{
    m_saveAuthorizer = std::move(authorizer);
}

void NoteEditorDialog::buildUi(bool editing)
{
    setWindowTitle(editing ? tr("Edit note") : tr("New note"));
    setModal(true);
    setMinimumSize(520, 460);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(10);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    m_titleEdit = new QLineEdit(this);
    m_titleEdit->setObjectName(QStringLiteral("noteTitle"));
    m_titleEdit->setPlaceholderText(tr("Required"));

    m_bodyWidget =
        new EncryptedContentWidget(EncryptedContentWidget::Mode::MultiLine, this);
    m_bodyWidget->setObjectName(QStringLiteral("noteBodyWidget"));
    m_bodyWidget->setPlaceholderText(tr("Write your note…"));

    m_classificationCombo = new QComboBox(this);
    m_classificationCombo->setObjectName(QStringLiteral("noteClassification"));
    m_classificationCombo->addItem(tr("Confidential (C)"), QStringLiteral("C"));
    m_classificationCombo->addItem(tr("Secret (S)"), QStringLiteral("S"));
    m_classificationCombo->addItem(tr("Top Secret (T)"), QStringLiteral("T"));

    form->addRow(tr("Title:"), m_titleEdit);
    form->addRow(tr("Note:"), m_bodyWidget);
    form->addRow(tr("Confidentiality:"), m_classificationCombo);
    layout->addLayout(form);

    auto *classificationHelp = new QLabel(
        tr("Confidential notes are protected by the vault database. "
           "Secret notes add a per-item encryption key. "
           "Top Secret notes require the secondary password for every access."),
        this);
    classificationHelp->setWordWrap(true);
    layout->addWidget(classificationHelp);

    m_topSecretHint = new QLabel(
        tr("Top Secret is not set up yet. Use File → Set up Top Secret… first."),
        this);
    m_topSecretHint->setObjectName(QStringLiteral("noteTopSecretHint"));
    m_topSecretHint->setWordWrap(true);
    m_topSecretHint->hide();
    layout->addWidget(m_topSecretHint);

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("noteError"));
    m_errorLabel->setWordWrap(true);
    QPalette errorPalette = m_errorLabel->palette();
    errorPalette.setColor(QPalette::WindowText, QColor(160, 0, 0));
    m_errorLabel->setPalette(errorPalette);
    m_errorLabel->hide();
    layout->addWidget(m_errorLabel);

    auto *buttons =
        new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    m_saveButton = buttons->button(QDialogButtonBox::Save);
    m_saveButton->setObjectName(QStringLiteral("noteSave"));
    m_saveButton->setText(tr("Save"));
    m_saveButton->setDefault(true);
    m_saveButton->setEnabled(false);
    connect(buttons, &QDialogButtonBox::accepted, this, &NoteEditorDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &NoteEditorDialog::reject);
    layout->addWidget(buttons);

    connect(m_bodyWidget, &EncryptedContentWidget::revealed, this,
            &NoteEditorDialog::updateSaveButton);
    connect(m_bodyWidget, &EncryptedContentWidget::hidden, this,
            &NoteEditorDialog::updateSaveButton);
    connect(m_bodyWidget, &EncryptedContentWidget::errorOccurred, this,
            &NoteEditorDialog::setError);

    m_titleEdit->setFocus();
}

void NoteEditorDialog::updateSaveButton()
{
    m_saveButton->setEnabled(m_bodyWidget->isLoaded());
}

void NoteEditorDialog::save()
{
    if (!m_bodyWidget->isLoaded()) {
        setError(tr("Show the content before saving."));
        return;
    }
    if (m_titleEdit->text().trimmed().isEmpty()) {
        setError(tr("Enter a title for this note."));
        m_titleEdit->setFocus();
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
    accept();
}

void NoteEditorDialog::reject()
{
    m_bodyWidget->setContent(QString());
    QDialog::reject();
}

void NoteEditorDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
