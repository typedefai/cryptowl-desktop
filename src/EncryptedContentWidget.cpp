#include "EncryptedContentWidget.h"

#include <QClipboard>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <utility>

namespace {

constexpr const char *kSingleLineMask = "••••••••••••";
constexpr const char *kMultiLineMask =
    "••••••••••••••••••••••••••••••••\n"
    "••••••••••••••••••••••••••••••••\n"
    "••••••••••••••••••••••••••••••••";

} // namespace

EncryptedContentWidget::EncryptedContentWidget(Mode mode, QWidget *parent)
    : QWidget(parent)
    , m_mode(mode)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(4);

    auto *controls = new QHBoxLayout;
    controls->setContentsMargins(0, 0, 0, 0);
    controls->setSpacing(4);

    m_eyeButton = new QToolButton(this);
    m_eyeButton->setObjectName(QStringLiteral("secretEye"));
    m_eyeButton->setAccessibleName(tr("Show or hide content"));
    m_eyeButton->setAutoRaise(true);
    m_eyeButton->setCheckable(true);
    m_eyeButton->setIconSize(QSize(18, 18));
    m_eyeButton->setIcon(eyeIcon(false));
    connect(m_eyeButton, &QToolButton::clicked, this, [this](bool checked) {
        if (checked)
            reveal();
        else
            hideContent();
        m_eyeButton->setChecked(m_visible);
        updateControls();
    });
    controls->addWidget(m_eyeButton);

    m_statusLabel = new QLabel(this);
    m_statusLabel->setObjectName(QStringLiteral("secretStatus"));
    m_statusLabel->setVisible(false);
    controls->addWidget(m_statusLabel);
    controls->addStretch(1);

    m_copyButton = new QToolButton(this);
    m_copyButton->setObjectName(QStringLiteral("secretCopy"));
    m_copyButton->setAccessibleName(tr("Copy content"));
    m_copyButton->setAutoRaise(true);
    m_copyButton->setText(tr("Copy"));
    m_copyButton->setToolTip(tr("Copy the content to the clipboard"));
    connect(m_copyButton, &QToolButton::clicked, this, [this] {
        if (!m_loaded)
            return;
        QGuiApplication::clipboard()->setText(content());
        m_copyButton->setText(tr("Copied"));
        QTimer::singleShot(1200, this, [this] { m_copyButton->setText(tr("Copy")); });
        emit copied();
    });
    controls->addWidget(m_copyButton);

    layout->addLayout(controls);

    if (m_mode == Mode::SingleLine) {
        m_lineEdit = new QLineEdit(this);
        m_lineEdit->setObjectName(QStringLiteral("secretLineEdit"));
        m_lineEdit->setEchoMode(QLineEdit::Password);
        m_lineEdit->setReadOnly(true);
        layout->addWidget(m_lineEdit);
    } else {
        m_textEdit = new QPlainTextEdit(this);
        m_textEdit->setObjectName(QStringLiteral("secretTextEdit"));
        m_textEdit->setMinimumHeight(90);
        m_textEdit->setReadOnly(true);
        layout->addWidget(m_textEdit);
    }

    updateControls();
}

void EncryptedContentWidget::setLoader(Loader loader)
{
    m_loader = std::move(loader);
    m_loaded = false;
    m_visible = false;
    m_draftMasked = false;
    showMaskedState();
    updateControls();
}

void EncryptedContentWidget::setContent(const QString &content, bool maskSingleLine)
{
    m_loader = {};
    m_loaded = true;
    m_draftMasked = m_mode == Mode::SingleLine && maskSingleLine;
    m_visible = !m_draftMasked;

    if (m_lineEdit) {
        m_lineEdit->setEchoMode(m_visible ? QLineEdit::Normal
                                         : QLineEdit::Password);
        m_lineEdit->setText(content);
        m_lineEdit->setReadOnly(m_readOnly);
    } else if (m_textEdit) {
        m_textEdit->setPlainText(content);
        m_textEdit->setReadOnly(m_readOnly);
    }
    updateControls();
}

void EncryptedContentWidget::setReadOnly(bool readOnly)
{
    m_readOnly = readOnly;
    if (m_lineEdit)
        m_lineEdit->setReadOnly(m_readOnly || (m_loader && !m_visible));
    if (m_textEdit)
        m_textEdit->setReadOnly(m_readOnly || (m_loader && !m_visible));
}

void EncryptedContentWidget::setPlaceholderText(const QString &text)
{
    if (m_lineEdit)
        m_lineEdit->setPlaceholderText(text);
    else if (m_textEdit)
        m_textEdit->setPlaceholderText(text);
}

QString EncryptedContentWidget::content() const
{
    if (!m_loaded)
        return {};
    if (m_lineEdit)
        return m_lineEdit->text();
    return m_textEdit ? m_textEdit->toPlainText() : QString();
}

bool EncryptedContentWidget::isLoaded() const
{
    return m_loaded;
}

bool EncryptedContentWidget::isVisible() const
{
    return m_visible;
}

void EncryptedContentWidget::reveal()
{
    if (m_visible)
        return;

    if (m_loader) {
        QString content;
        QString error;
        const bool ok = m_loader(&content, &error);
        if (!ok) {
            emit errorOccurred(error.isEmpty() ? tr("Could not decrypt content.")
                                               : error);
            m_eyeButton->setChecked(false);
            updateControls();
            return;
        }
        m_loaded = true;
        m_visible = true;
        setFieldValue(content);
        content.fill(QChar('\0'));
        m_eyeButton->setChecked(true);
        updateControls();
        emit revealed();
        return;
    }

    m_visible = true;
    if (m_lineEdit) {
        m_lineEdit->setEchoMode(QLineEdit::Normal);
        m_lineEdit->setReadOnly(m_readOnly);
    } else if (m_textEdit) {
        m_textEdit->setReadOnly(m_readOnly);
    }
    m_eyeButton->setChecked(true);
    updateControls();
    emit revealed();
}

void EncryptedContentWidget::hideContent()
{
    if (m_loader) {
        m_loaded = false;
        m_visible = false;
        showMaskedState();
        m_eyeButton->setChecked(false);
        updateControls();
        emit hidden();
        return;
    }

    if (m_lineEdit && m_draftMasked) {
        m_visible = false;
        m_lineEdit->setEchoMode(QLineEdit::Password);
        m_eyeButton->setChecked(false);
        updateControls();
        emit hidden();
    }
}

void EncryptedContentWidget::updateControls()
{
    const bool canShow = m_loader || (m_mode == Mode::SingleLine && m_draftMasked);
    m_eyeButton->setVisible(canShow);
    m_eyeButton->setChecked(m_visible);
    m_eyeButton->setIcon(eyeIcon(m_visible));
    m_eyeButton->setToolTip(
        m_visible ? tr("Hide content")
                  : (m_loader ? tr("Show and decrypt content")
                              : tr("Show content")));
    m_copyButton->setEnabled(m_loaded);

    if (m_loader) {
        m_statusLabel->setText(
            m_visible ? tr("Decrypted for this view")
                      : tr("Hidden — click the eye to decrypt"));
        m_statusLabel->setVisible(true);
    } else if (m_mode == Mode::SingleLine && m_draftMasked) {
        m_statusLabel->setText(m_visible ? tr("Shown") : tr("Masked"));
        m_statusLabel->setVisible(true);
    } else {
        m_statusLabel->setVisible(false);
    }
}

void EncryptedContentWidget::showMaskedState()
{
    if (m_lineEdit) {
        m_lineEdit->setEchoMode(QLineEdit::Password);
        m_lineEdit->setText(QString::fromUtf8(kSingleLineMask));
        m_lineEdit->setReadOnly(true);
    } else if (m_textEdit) {
        m_textEdit->setPlainText(QString::fromUtf8(kMultiLineMask));
        m_textEdit->setReadOnly(true);
    }
}

void EncryptedContentWidget::setFieldValue(const QString &value)
{
    if (m_lineEdit) {
        m_lineEdit->setEchoMode(QLineEdit::Normal);
        m_lineEdit->setText(value);
        m_lineEdit->setReadOnly(m_readOnly);
    } else if (m_textEdit) {
        m_textEdit->setPlainText(value);
        m_textEdit->setReadOnly(m_readOnly);
    }
}

QIcon EncryptedContentWidget::eyeIcon(bool open) const
{
    QPixmap pixmap(18, 18);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    QPen pen(palette().color(QPalette::WindowText));
    pen.setWidthF(1.4);
    painter.setPen(pen);
    painter.drawEllipse(QRectF(2.0, 5.0, 14.0, 8.0));
    if (open) {
        painter.setBrush(pen.color());
        painter.drawEllipse(QPointF(9.0, 9.0), 2.2, 2.2);
    } else {
        painter.drawLine(QPointF(3.0, 15.0), QPointF(15.0, 3.0));
    }
    return QIcon(pixmap);
}
