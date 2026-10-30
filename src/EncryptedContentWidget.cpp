#include "EncryptedContentWidget.h"

#include <QClipboard>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QLineEdit>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStackedLayout>
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
    : QFrame(parent)
    , m_mode(mode)
{
    setFrameShape(QFrame::StyledPanel);
    setFrameShadow(QFrame::Plain);
    setLineWidth(1);
    setSizePolicy(QSizePolicy::Expanding,
                  m_mode == Mode::SingleLine ? QSizePolicy::Fixed
                                             : QSizePolicy::Expanding);

    m_stack = new QStackedLayout(this);
    m_stack->setContentsMargins(0, 0, 0, 0);

    m_unlockButton = new QPushButton(eyeIcon(false), tr("(click to unlock)"), this);
    m_unlockButton->setObjectName(QStringLiteral("secretUnlock"));
    m_unlockButton->setFlat(true);
    m_unlockButton->setCursor(Qt::PointingHandCursor);
    m_unlockButton->setSizePolicy(
        QSizePolicy::Expanding, m_mode == Mode::SingleLine ? QSizePolicy::Fixed
                                                           : QSizePolicy::Expanding);
    m_unlockButton->setIconSize(QSize(18, 18));
    m_unlockButton->setMinimumHeight(m_mode == Mode::SingleLine ? 34 : 90);
    if (m_mode == Mode::SingleLine)
        m_unlockButton->setMaximumHeight(34);
    connect(m_unlockButton, &QPushButton::clicked, this,
            &EncryptedContentWidget::reveal);
    m_stack->addWidget(m_unlockButton);

    m_contentPage = new QWidget(this);
    m_contentPage->setMinimumHeight(m_mode == Mode::SingleLine ? 34 : 90);
    m_contentPage->setSizePolicy(
        QSizePolicy::Expanding, m_mode == Mode::SingleLine ? QSizePolicy::Fixed
                                                           : QSizePolicy::Expanding);
    if (m_mode == Mode::SingleLine)
        m_contentPage->setMaximumHeight(34);
    auto *pageLayout = new QHBoxLayout(m_contentPage);
    pageLayout->setContentsMargins(2, 2, 2, 2);
    pageLayout->setSpacing(2);

    m_eyeButton = new QToolButton(m_contentPage);
    m_eyeButton->setObjectName(QStringLiteral("secretEye"));
    m_eyeButton->setAccessibleName(tr("Show or hide content"));
    m_eyeButton->setAutoRaise(true);
    m_eyeButton->setIconSize(QSize(16, 16));
    m_eyeButton->setIcon(eyeIcon(false));
    connect(m_eyeButton, &QToolButton::clicked, this, [this] {
        if (m_visible)
            hideContent();
        else
            reveal();
    });

    m_copyButton = new QToolButton(m_contentPage);
    m_copyButton->setObjectName(QStringLiteral("secretCopy"));
    m_copyButton->setAccessibleName(tr("Copy content"));
    m_copyButton->setAutoRaise(true);
    m_copyButton->setIconSize(QSize(16, 16));
    m_copyButton->setIcon(copyIcon());
    m_copyButton->setToolTip(tr("Copy the content to the clipboard"));
    connect(m_copyButton, &QToolButton::clicked, this, [this] {
        if (!m_loaded)
            return;
        QGuiApplication::clipboard()->setText(content());
        m_copyButton->setToolTip(tr("Copied to clipboard"));
        QTimer::singleShot(1200, this,
                           [this] { m_copyButton->setToolTip(tr("Copy the content to the clipboard")); });
        emit copied();
    });

    if (m_mode == Mode::SingleLine) {
        m_lineEdit = new QLineEdit(m_contentPage);
        m_lineEdit->setObjectName(QStringLiteral("secretLineEdit"));
        m_lineEdit->setFrame(false);
        m_lineEdit->setEchoMode(QLineEdit::Password);
        m_lineEdit->setReadOnly(true);
        pageLayout->addWidget(m_lineEdit, 1);
        pageLayout->addWidget(m_eyeButton, 0, Qt::AlignVCenter);
        pageLayout->addWidget(m_copyButton, 0, Qt::AlignVCenter);
    } else {
        m_textEdit = new QPlainTextEdit(m_contentPage);
        m_textEdit->setObjectName(QStringLiteral("secretTextEdit"));
        m_textEdit->setFrameShape(QFrame::NoFrame);
        m_textEdit->setMinimumHeight(90);
        m_textEdit->setReadOnly(true);
        pageLayout->addWidget(m_textEdit, 1);

        auto *buttons = new QVBoxLayout;
        buttons->setContentsMargins(0, 0, 0, 0);
        buttons->setSpacing(2);
        buttons->addWidget(m_eyeButton);
        buttons->addWidget(m_copyButton);
        buttons->addStretch(1);
        pageLayout->addLayout(buttons);
    }

    m_stack->addWidget(m_contentPage);
    updateControls();
}

void EncryptedContentWidget::setLoader(Loader loader)
{
    m_loader = std::move(loader);
    m_loaded = false;
    m_visible = false;
    m_draftMasked = false;
    showMaskedState();
    showUnlockPage();
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
    showContentPage();
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

bool EncryptedContentWidget::isContentVisible() const
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
            updateControls();
            return;
        }
        m_loaded = true;
        m_visible = true;
        setFieldValue(content);
        content.fill(QChar('\0'));
        showContentPage();
        updateControls();
        if (m_lineEdit)
            m_lineEdit->setFocus();
        else if (m_textEdit)
            m_textEdit->setFocus();
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
    updateControls();
    emit revealed();
}

void EncryptedContentWidget::hideContent()
{
    if (m_loader) {
        m_loaded = false;
        m_visible = false;
        showMaskedState();
        showUnlockPage();
        updateControls();
        emit hidden();
        return;
    }

    if (m_lineEdit && m_draftMasked) {
        m_visible = false;
        m_lineEdit->setEchoMode(QLineEdit::Password);
        updateControls();
        emit hidden();
    }
}

void EncryptedContentWidget::updateControls()
{
    if (m_loader && !m_loaded)
        showUnlockPage();
    else
        showContentPage();

    const bool canToggle = m_loader
        || (m_mode == Mode::SingleLine && m_draftMasked);
    m_eyeButton->setVisible(canToggle);
    m_eyeButton->setIcon(eyeIcon(m_visible));
    m_eyeButton->setToolTip(
        m_visible ? tr("Hide and clear content")
                  : (m_loader ? tr("Show and decrypt content")
                              : tr("Show password")));
    m_copyButton->setEnabled(m_loaded);
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

void EncryptedContentWidget::showUnlockPage()
{
    m_stack->setCurrentWidget(m_unlockButton);
}

void EncryptedContentWidget::showContentPage()
{
    m_stack->setCurrentWidget(m_contentPage);
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

QIcon EncryptedContentWidget::copyIcon() const
{
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    QPen pen(palette().color(QPalette::WindowText));
    pen.setWidthF(1.2);
    painter.setPen(pen);
    painter.drawRoundedRect(QRectF(5.0, 2.5, 8.0, 10.0), 1.0, 1.0);
    painter.drawRoundedRect(QRectF(2.5, 5.0, 8.0, 10.0), 1.0, 1.0);
    return QIcon(pixmap);
}
