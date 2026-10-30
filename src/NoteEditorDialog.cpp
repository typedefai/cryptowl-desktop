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
#include <QStandardItemModel>
#include <QVBoxLayout>

#include <utility>

NoteEditorDialog::NoteEditorDialog(QWidget *parent)
    : QDialog(parent)
{
    buildUi(false);
}

NoteEditorDialog::NoteEditorDialog(const Data &data, QWidget *parent)
    : NoteEditorDialog(data, ContentLoader(), parent)
{
}

NoteEditorDialog::NoteEditorDialog(const Data &data, ContentLoader loader,
                                   QWidget *parent)
    : QDialog(parent)
    , m_contentLoader(std::move(loader))
{
    buildUi(true);
    m_titleEdit->setText(data.title);
    const int index = m_classificationCombo->findData(data.classification);
    m_classificationCombo->setCurrentIndex(index >= 0 ? index : 0);

    if (m_contentLoader) {
        m_contentRevealed = false;
        m_bodyEdit->setPlainText(QStringLiteral(
            "••••••••••••••••••••••••••••••••\n"
            "••••••••••••••••••••••••••••••••\n"
            "••••••••••••••••••••••••••••••••"));
        m_bodyEdit->setReadOnly(true);
        m_lockHint->show();
        m_revealButton->show();
        m_saveButton->setEnabled(false);
    } else {
        m_contentRevealed = true;
        m_bodyEdit->setPlainText(data.body);
        m_lockHint->hide();
        m_revealButton->hide();
        m_saveButton->setEnabled(true);
    }

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

    m_bodyEdit = new QPlainTextEdit(this);
    m_bodyEdit->setObjectName(QStringLiteral("noteBody"));
    m_bodyEdit->setPlaceholderText(tr("Write your note…"));

    m_classificationCombo = new QComboBox(this);
    m_classificationCombo->setObjectName(QStringLiteral("noteClassification"));
    m_classificationCombo->addItem(tr("Confidential (C)"), QStringLiteral("C"));
    m_classificationCombo->addItem(tr("Secret (S)"), QStringLiteral("S"));
    m_classificationCombo->addItem(tr("Top Secret (T)"), QStringLiteral("T"));

    form->addRow(tr("Title:"), m_titleEdit);
    form->addRow(tr("Note:"), m_bodyEdit);
    form->addRow(tr("Confidentiality:"), m_classificationCombo);
    layout->addLayout(form);

    m_lockHint = new QLabel(
        tr("Content is hidden. Click Show content to reveal it."), this);
    m_lockHint->setObjectName(QStringLiteral("noteLockHint"));
    m_lockHint->setWordWrap(true);
    m_lockHint->hide();
    layout->addWidget(m_lockHint);

    m_revealButton = new QPushButton(tr("Show content"), this);
    m_revealButton->setObjectName(QStringLiteral("noteReveal"));
    m_revealButton->hide();
    connect(m_revealButton, &QPushButton::clicked, this,
            &NoteEditorDialog::revealContent);
    layout->addWidget(m_revealButton, 0, Qt::AlignLeft);

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
    connect(buttons, &QDialogButtonBox::accepted, this, &NoteEditorDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &NoteEditorDialog::reject);
    layout->addWidget(buttons);

    m_titleEdit->setFocus();
}

void NoteEditorDialog::revealContent()
{
    if (m_contentRevealed || !m_contentLoader)
        return;

    QString body;
    QString error;
    if (!m_contentLoader(&body, &error)) {
        setError(error.isEmpty() ? tr("Could not decrypt this note.") : error);
        return;
    }

    m_bodyEdit->setPlainText(body);
    body.fill(QChar('\0'));
    m_bodyEdit->setReadOnly(false);
    m_bodyEdit->setPlaceholderText(tr("Write your note…"));
    m_bodyEdit->setFocus();
    m_contentRevealed = true;
    m_lockHint->hide();
    m_revealButton->hide();
    m_saveButton->setEnabled(true);
    setError(QString());
}

void NoteEditorDialog::save()
{
    if (!m_contentRevealed) {
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
    m_bodyEdit->clear();
    QDialog::reject();
}

void NoteEditorDialog::setError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
