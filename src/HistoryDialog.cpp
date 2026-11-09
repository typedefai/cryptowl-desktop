#include "HistoryDialog.h"

#include "DiffDialog.h"

#include <QDateTime>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <utility>

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

QString dateText(qint64 milliseconds)
{
    if (milliseconds <= 0)
        return QStringLiteral("—");
    return QDateTime::fromMSecsSinceEpoch(milliseconds)
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

} // namespace

HistoryDialog::HistoryDialog(
    const QString &itemTitle, const QString &currentTier,
    std::vector<cryptowl::vault::ItemVersionSummary> versions,
    VersionLoader versionLoader, CurrentLoader currentLoader,
    RestoreAction restoreAction, bool jsonPayload, QWidget *parent)
    : QDialog(parent)
    , m_itemTitle(itemTitle)
    , m_currentTier(currentTier)
    , m_versions(std::move(versions))
    , m_versionLoader(std::move(versionLoader))
    , m_currentLoader(std::move(currentLoader))
    , m_restoreAction(std::move(restoreAction))
    , m_jsonPayload(jsonPayload)
{
    setWindowTitle(tr("History — %1").arg(itemTitle));
    setModal(true);
    setMinimumSize(720, 500);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    auto *heading = new QLabel(this);
    heading->setTextFormat(Qt::RichText);
    heading->setText(
        tr("<b>%1</b><br>Current security level: %2")
            .arg(itemTitle.toHtmlEscaped(),
                 tierLabel(currentTier).toHtmlEscaped()));
    layout->addWidget(heading);

    m_tree = new QTreeWidget(this);
    m_tree->setObjectName(QStringLiteral("historyVersions"));
    m_tree->setColumnCount(4);
    m_tree->setHeaderLabels(
        {tr("Version"), tr("When"), tr("Security level"), tr("Title")});
    m_tree->setRootIsDecorated(false);
    m_tree->setAlternatingRowColors(true);
    m_tree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_tree->header()->setSectionResizeMode(3, QHeaderView::Stretch);
    layout->addWidget(m_tree, 1);

    for (const auto &version : m_versions) {
        auto *item = new QTreeWidgetItem(m_tree);
        item->setText(0, QString::number(version.seq));
        item->setText(1, dateText(version.createdAt));
        item->setText(2, tierLabel(QString::fromStdString(version.classification)));
        item->setText(3, QString::fromStdString(version.title));
        item->setData(0, Qt::UserRole, version.seq);
    }
    if (m_tree->topLevelItemCount() > 1)
        m_tree->setCurrentItem(m_tree->topLevelItem(1));
    else if (m_tree->topLevelItemCount() == 1)
        m_tree->setCurrentItem(m_tree->topLevelItem(0));

    auto *buttons = new QHBoxLayout;
    m_diffButton = new QPushButton(tr("Compare with current"), this);
    m_diffButton->setObjectName(QStringLiteral("historyDiff"));
    connect(m_diffButton, &QPushButton::clicked, this,
            &HistoryDialog::compareSelected);
    buttons->addWidget(m_diffButton);

    m_restoreButton = new QPushButton(tr("Restore this version"), this);
    m_restoreButton->setObjectName(QStringLiteral("historyRestore"));
    connect(m_restoreButton, &QPushButton::clicked, this,
            &HistoryDialog::restoreSelected);
    buttons->addWidget(m_restoreButton);
    buttons->addStretch(1);

    auto *closeButtons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(closeButtons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    closeButtons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    buttons->addWidget(closeButtons);
    layout->addLayout(buttons);

    connect(m_tree, &QTreeWidget::itemSelectionChanged, this,
            &HistoryDialog::updateButtons);
    updateButtons();
}

const cryptowl::vault::ItemVersionSummary *HistoryDialog::selectedVersion() const
{
    const QTreeWidgetItem *item = m_tree->currentItem();
    if (!item)
        return nullptr;
    const int seq = item->data(0, Qt::UserRole).toInt();
    for (const auto &version : m_versions) {
        if (version.seq == seq)
            return &version;
    }
    return nullptr;
}

void HistoryDialog::updateButtons()
{
    const bool selected = selectedVersion() != nullptr;
    m_diffButton->setEnabled(selected);
    m_restoreButton->setEnabled(selected);
}

void HistoryDialog::compareSelected()
{
    const auto *version = selectedVersion();
    if (!version)
        return;

    QString beforePayload;
    QString afterPayload;
    QString error;
    if (!m_versionLoader(version->seq, &beforePayload, &error)) {
        if (!error.isEmpty())
            QMessageBox::warning(this, tr("Could not load version"), error);
        return;
    }
    if (!m_currentLoader(&afterPayload, &error)) {
        beforePayload.fill(QChar('\0'));
        if (!error.isEmpty())
            QMessageBox::warning(this, tr("Could not load current item"), error);
        return;
    }

    DiffDialog dialog(
        tr("Version %1").arg(version->seq), tr("Current"),
        QString::fromStdString(version->classification), m_currentTier,
        QString::fromStdString(version->title), m_itemTitle,
        beforePayload, afterPayload, m_jsonPayload, this);
    beforePayload.fill(QChar('\0'));
    afterPayload.fill(QChar('\0'));
    dialog.exec();
}

void HistoryDialog::restoreSelected()
{
    const auto *version = selectedVersion();
    if (!version)
        return;

    const QString versionTier =
        tierLabel(QString::fromStdString(version->classification));
    const QString currentTier = tierLabel(m_currentTier);
    if (QMessageBox::question(
            this, tr("Restore version"),
            tr("Restore version %1 from %2?\n\n"
               "This replaces the current content with that snapshot and "
               "records a new version. Security level: %3 → %4.")
                .arg(version->seq)
                .arg(dateText(version->createdAt))
                .arg(currentTier, versionTier))
        != QMessageBox::Yes) {
        return;
    }

    QString error;
    if (!m_restoreAction(version->seq, &error)) {
        if (!error.isEmpty())
            QMessageBox::warning(this, tr("Could not restore version"), error);
        return;
    }
    accept();
}
