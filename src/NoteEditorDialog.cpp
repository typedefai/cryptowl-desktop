#include "NoteEditorDialog.h"

#include <QColor>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

NoteEditorDialog::NoteEditorDialog(QWidget *parent)
    : QDialog(parent)
{
    buildUi(false);
}

NoteEditorDialog::NoteEditorDialog(const Data &data, QWidget *parent)
    : QDialog(parent)
{
    buildUi(true);
    m_titleEdit->setText(data.title);
    m_bodyEdit->setPlainText(data.body);
    const int index = m_classificationCombo->findData(data.classification);
    m_classificationCombo->setCurrentIndex(index >= 0 ? index : 0);
    m_titleEdit->selectAll();
    m_titleEdit->setFocus();
}

NoteEditorDialog::Data NoteEditorDialog::data() const
{
    Data result;
    result.title = m_titleEdit->text().trimmed();
    result.body = m_bodyEdit->toPlainText();
    result.classification = m_classificationCombo->currentData().toString();
    if (result.classification.isEmpty())
        result.classification = QStringLiteral("C");
    return result;
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

    m_bodyEdit = new QPlainTextEdit(this);
    m_bodyEdit->setObjectName(QStringLiteral("noteBody"));
    m_bodyEdit->setPlaceholderText(tr("Write your note…"));

    m_classificationCombo = new QComboBox(this);
    m_classificationCombo->setObjectName(QStringLiteral("noteClassification"));
    m_classificationCombo->addItem(tr("Confidential (C)"), QStringLiteral("C"));
    m_classificationCombo->addItem(tr("Secret (S)"), QStringLiteral("S"));

    form->addRow(tr("Title:"), m_titleEdit);
    form->addRow(tr("Note:"), m_bodyEdit);
    form->addRow(tr("Confidentiality:"), m_classificationCombo);
    layout->addLayout(form);

    auto *classificationHelp = new QLabel(
        tr("Confidential notes are protected by the vault database. "
           "Secret notes add a per-item encryption key."),
        this);
    classificationHelp->setWordWrap(true);
    layout->addWidget(classificationHelp);

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
    QPushButton *saveButton = buttons->button(QDialogButtonBox::Save);
    saveButton->setText(tr("Save"));
    saveButton->setDefault(true);
    connect(buttons, &QDialogButtonBox::accepted, this, &NoteEditorDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &NoteEditorDialog::reject);
    layout->addWidget(buttons);

    m_titleEdit->setFocus();
}

void NoteEditorDialog::save()
{
    if (m_titleEdit->text().trimmed().isEmpty()) {
        setError(tr("Enter a title for this note."));
        m_titleEdit->setFocus();
        return;
    }

    setError(QString());
    accept();
}

void NoteEditorDialog::reject()
{
    m_bodyEdit->clear();
    QDialog::reject();
}

void NoteEditorDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
