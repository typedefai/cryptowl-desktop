#include "PasswordViewDialog.h"

#include "EncryptedContentWidget.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

PasswordViewDialog::PasswordViewDialog(const Data &data, SecretLoader loader,
                                       QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("View password"));
    setModal(true);
    setMinimumWidth(440);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(10);

    auto *heading = new QLabel(this);
    heading->setObjectName(QStringLiteral("passwordViewTitle"));
    heading->setTextFormat(Qt::RichText);
    heading->setText(QStringLiteral("<b>%1</b>")
                         .arg(data.title.toHtmlEscaped()));
    layout->addWidget(heading);

    auto *form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    const auto valueLabel = [this](const QString &text,
                                   const QString &objectName) {
        auto *label = new QLabel(text.isEmpty() ? QStringLiteral("—")
                                                : text.toHtmlEscaped(),
                                 this);
        label->setObjectName(objectName);
        label->setTextFormat(Qt::RichText);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setWordWrap(true);
        return label;
    };

    form->addRow(tr("User name:"),
                 valueLabel(data.username, QStringLiteral("passwordViewUsername")));
    form->addRow(tr("URL:"),
                 valueLabel(data.url, QStringLiteral("passwordViewUrl")));

    auto *classification = new QLabel(this);
    classification->setObjectName(QStringLiteral("passwordViewClassification"));
    if (data.classification == QLatin1String("T"))
        classification->setText(tr("Top Secret (T)"));
    else if (data.classification == QLatin1String("S"))
        classification->setText(tr("Secret (S)"));
    else
        classification->setText(tr("Confidential (C)"));
    form->addRow(tr("Confidentiality:"), classification);

    m_passwordWidget =
        new EncryptedContentWidget(EncryptedContentWidget::Mode::SingleLine, this);
    m_passwordWidget->setObjectName(QStringLiteral("passwordSecretWidget"));
    m_passwordWidget->setPlaceholderText(tr("Password"));
    m_passwordWidget->setReadOnly(true);
    form->addRow(tr("Password:"), m_passwordWidget);

    m_notesWidget =
        new EncryptedContentWidget(EncryptedContentWidget::Mode::MultiLine, this);
    m_notesWidget->setObjectName(QStringLiteral("passwordNotesWidget"));
    m_notesWidget->setPlaceholderText(tr("Notes"));
    m_notesWidget->setReadOnly(true);
    form->addRow(tr("Notes:"), m_notesWidget);

    if (loader) {
        m_passwordWidget->setLoader(
            [loader](QString *password, QString *error) {
                QString notes;
                if (!loader(password, &notes, error))
                    return false;
                notes.fill(QChar('\0'));
                return true;
            });
        m_notesWidget->setLoader([loader](QString *notes, QString *error) {
            QString password;
            if (!loader(&password, notes, error))
                return false;
            password.fill(QChar('\0'));
            return true;
        });
    } else {
        m_passwordWidget->setContent(data.password, true);
        m_notesWidget->setContent(data.notes);
    }

    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    auto *closeButton = buttons->button(QDialogButtonBox::Close);
    closeButton->setObjectName(QStringLiteral("passwordViewClose"));
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);

    setFocus();
}
