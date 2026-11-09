#include "DiffDialog.h"

#include "TextDiff.h"

#include <QDialogButtonBox>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLabel>
#include <QPushButton>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace {

QString tierLabel(const QString &tier)
{
    if (tier == QLatin1String("C"))
        return QObject::tr("C — Confidential");
    if (tier == QLatin1String("S"))
        return QObject::tr("S — Secret");
    if (tier == QLatin1String("T"))
        return QObject::tr("T — Top Secret");
    return tier;
}

QString formattedPayload(const QString &payload, bool jsonPayload)
{
    if (!jsonPayload)
        return payload;
    QJsonParseError error;
    const QJsonDocument document =
        QJsonDocument::fromJson(payload.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || document.isNull())
        return payload;
    return QString::fromUtf8(document.toJson(QJsonDocument::Indented));
}

QString escapedLine(const QString &line)
{
    return line.toHtmlEscaped();
}

} // namespace

DiffDialog::DiffDialog(const QString &beforeLabel, const QString &afterLabel,
                       const QString &beforeTier, const QString &afterTier,
                       const QString &beforeTitle, const QString &afterTitle,
                       const QString &beforePayload, const QString &afterPayload,
                       bool jsonPayload, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Compare versions"));
    setModal(true);
    setMinimumSize(760, 560);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    auto *heading = new QLabel(this);
    heading->setObjectName(QStringLiteral("diffHeading"));
    heading->setTextFormat(Qt::RichText);
    heading->setText(
        tr("<b>%1 → %2</b>").arg(beforeLabel.toHtmlEscaped(),
                                  afterLabel.toHtmlEscaped()));
    layout->addWidget(heading);

    QString metadata;
    if (beforeTitle != afterTitle) {
        metadata += tr("<p><b>Title:</b> %1 → %2</p>")
                        .arg(beforeTitle.toHtmlEscaped(),
                             afterTitle.toHtmlEscaped());
    }
    if (beforeTier != afterTier) {
        metadata += tr("<p><b>Security level:</b> %1 → %2</p>")
                        .arg(tierLabel(beforeTier).toHtmlEscaped(),
                             tierLabel(afterTier).toHtmlEscaped());
    }
    if (!metadata.isEmpty()) {
        auto *metaLabel = new QLabel(metadata, this);
        metaLabel->setTextFormat(Qt::RichText);
        metaLabel->setWordWrap(true);
        layout->addWidget(metaLabel);
    }

    const QStringList beforeLines =
        formattedPayload(beforePayload, jsonPayload).split(
            QLatin1Char('\n'), Qt::KeepEmptyParts);
    const QStringList afterLines =
        formattedPayload(afterPayload, jsonPayload).split(
            QLatin1Char('\n'), Qt::KeepEmptyParts);

    std::vector<DiffLine> lines;
    QString diffHtml;
    if (!diffLines(beforeLines, afterLines, &lines)) {
        diffHtml = tr("<p><i>This content is too large to diff line by line.</i></p>");
    } else {
        bool hasChange = false;
        diffHtml = QStringLiteral(
            "<pre style=\"font-family: Menlo, Consolas, monospace; "
            "font-size: 12px; line-height: 1.35; white-space: pre-wrap;\">");
        for (const DiffLine &line : lines) {
            QString prefix;
            QString color;
            switch (line.kind) {
            case DiffLineKind::Added:
                prefix = QStringLiteral("+ ");
                color = QStringLiteral("#137333");
                hasChange = true;
                break;
            case DiffLineKind::Removed:
                prefix = QStringLiteral("- ");
                color = QStringLiteral("#a50e0e");
                hasChange = true;
                break;
            case DiffLineKind::Equal:
                prefix = QStringLiteral("  ");
                break;
            }
            if (line.kind == DiffLineKind::Equal) {
                diffHtml += escapedLine(prefix + line.text) + QLatin1Char('\n');
            } else {
                diffHtml += QStringLiteral("<span style=\"color:%1\">%2</span>\n")
                                .arg(color, escapedLine(prefix + line.text));
            }
        }
        diffHtml += QStringLiteral("</pre>");
        if (!hasChange)
            diffHtml.prepend(tr("<p><i>No content changes.</i></p>"));
    }

    auto *view = new QTextBrowser(this);
    view->setObjectName(QStringLiteral("diffView"));
    view->setOpenExternalLinks(false);
    view->setHtml(diffHtml);
    layout->addWidget(view, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    layout->addWidget(buttons);
}
