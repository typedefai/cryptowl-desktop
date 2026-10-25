#include "VaultView.h"

#include <QAbstractItemView>
#include <QAction>
#include <QClipboard>
#include <QDateTime>
#include <QFont>
#include <QGuiApplication>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QListView>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStringList>
#include <QStyle>
#include <QTextBrowser>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <utility>

VaultView::VaultView(QString vaultPath, QWidget *parent)
    : QWidget(parent)
    , m_vaultPath(std::move(vaultPath))
{
    setObjectName(QStringLiteral("vaultView"));

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto *splitter = new QSplitter(Qt::Horizontal, this);
    splitter->setChildrenCollapsible(false);
    splitter->addWidget(createStructurePane());

    auto *rightSplitter = new QSplitter(Qt::Vertical, this);
    rightSplitter->setChildrenCollapsible(false);
    rightSplitter->addWidget(createContentPane());

    m_info = new QTextBrowser(rightSplitter);
    m_info->setObjectName(QStringLiteral("vaultInfo"));
    m_info->setOpenExternalLinks(false);
    m_info->setFrameShape(QFrame::StyledPanel);
    rightSplitter->addWidget(m_info);
    rightSplitter->setSizes({320, 120});
    splitter->addWidget(rightSplitter);
    splitter->setSizes({210, 500});

    layout->addWidget(splitter);

    populateMockData();
    refreshLists();
}

QString VaultView::vaultPath() const
{
    return m_vaultPath;
}

QWidget *VaultView::createStructurePane()
{
    auto *pane = new QWidget(this);
    pane->setMinimumWidth(180);

    auto *layout = new QVBoxLayout(pane);
    layout->setContentsMargins(4, 4, 4, 4);

    auto *header = new QLabel(tr("Vault"), pane);
    QFont headerFont = header->font();
    headerFont.setBold(true);
    header->setFont(headerFont);
    layout->addWidget(header);

    m_structure = new QTreeWidget(pane);
    m_structure->setObjectName(QStringLiteral("vaultStructure"));
    m_structure->setHeaderHidden(true);
    m_structure->setMinimumWidth(180);
    connect(m_structure, &QTreeWidget::currentItemChanged, this,
            [this](QTreeWidgetItem *current, QTreeWidgetItem *) {
                m_currentGroup = current ? current->data(0, Qt::UserRole).toInt() : -1;
                refreshLists();
            });
    layout->addWidget(m_structure, 1);
    return pane;
}

QWidget *VaultView::createContentPane()
{
    auto *pane = new QWidget(this);

    auto *layout = new QVBoxLayout(pane);
    layout->setContentsMargins(4, 4, 4, 4);

    m_contentStack = new QStackedWidget(pane);
    m_contentStack->setObjectName(QStringLiteral("vaultContentStack"));

    m_details = new QTreeWidget(m_contentStack);
    m_details->setObjectName(QStringLiteral("vaultDetails"));
    m_details->setColumnCount(4);
    m_details->setHeaderLabels(
        {tr("Title"), tr("User name"), tr("URL"), tr("Modified")});
    m_details->setRootIsDecorated(false);
    m_details->setAlternatingRowColors(true);
    m_details->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_details->setSelectionMode(QAbstractItemView::SingleSelection);
    for (int column = 0; column < m_details->columnCount(); ++column)
        m_details->header()->setSectionResizeMode(column, QHeaderView::Stretch);
    m_details->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_details, &QTreeWidget::itemSelectionChanged, this, &VaultView::updateInfo);
    connect(m_details, &QTreeWidget::itemDoubleClicked, this,
            [this](QTreeWidgetItem *, int) { editSelectedEntry(); });
    connect(m_details, &QTreeWidget::customContextMenuRequested, this,
            [this](const QPoint &pos) { showContextMenu(m_details, pos); });

    m_icons = new QListWidget(m_contentStack);
    m_icons->setObjectName(QStringLiteral("vaultIcons"));
    m_icons->setViewMode(QListView::IconMode);
    m_icons->setIconSize(QSize(32, 32));
    m_icons->setGridSize(QSize(120, 82));
    m_icons->setResizeMode(QListView::Adjust);
    m_icons->setMovement(QListView::Static);
    m_icons->setWordWrap(true);
    m_icons->setSelectionMode(QAbstractItemView::SingleSelection);
    m_icons->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_icons, &QListWidget::itemSelectionChanged, this, &VaultView::updateInfo);
    connect(m_icons, &QListWidget::itemDoubleClicked, this,
            [this](QListWidgetItem *) { editSelectedEntry(); });
    connect(m_icons, &QListWidget::customContextMenuRequested, this,
            [this](const QPoint &pos) { showContextMenu(m_icons, pos); });

    m_contentStack->addWidget(m_details);
    m_contentStack->addWidget(m_icons);
    layout->addWidget(m_contentStack);
    return pane;
}

void VaultView::populateMockData()
{
    m_groups = {
        {tr("General"),
         {{tr("Example Entry"), tr("demo-user"), tr("mock-password-1"),
           tr("https://example.com"), tr("Replace this mock entry with real data."),
           QStringLiteral("2026-10-25 09:15")},
          {tr("Recovery Codes"), tr("backup"), tr("mock-recovery-codes"), QString(),
           tr("Store recovery codes offline."), QStringLiteral("2026-10-24 18:42")}}},
        {tr("Internet"),
         {{tr("GitHub"), tr("riguz"), tr("mock-github-password"),
           tr("https://github.com"), tr("Development account."),
           QStringLiteral("2026-10-25 08:05")},
          {tr("Amazon"), tr("shopper@example.com"), tr("mock-amazon-password"),
           tr("https://amazon.com"), tr("Shopping account."),
           QStringLiteral("2026-10-23 20:11")},
          {tr("Cloud Console"), tr("admin"), tr("mock-cloud-password"),
           tr("https://console.example.com"), tr("Infrastructure console."),
           QStringLiteral("2026-10-22 14:30")}}},
        {tr("Email"),
         {{tr("Proton Mail"), tr("private@example.com"), tr("mock-mail-password"),
           tr("https://mail.proton.me"), tr("Personal email."),
           QStringLiteral("2026-10-25 07:50")},
          {tr("Work Mail"), tr("employee@example.com"), tr("mock-work-password"),
           tr("https://mail.example.com"), tr("Work account."),
           QStringLiteral("2026-10-21 11:20")}}},
        {tr("Work"),
         {{tr("VPN"), tr("employee"), tr("mock-vpn-password"), QString(),
           tr("Corporate VPN credentials."), QStringLiteral("2026-10-20 16:45")},
          {tr("Git Server"), tr("developer"), tr("mock-git-password"),
           tr("https://git.example.com"), tr("Internal Git server."),
           QStringLiteral("2026-10-19 10:05")}}},
        {tr("Finance"),
         {{tr("Bank"), tr("account-holder"), tr("mock-bank-password"),
           tr("https://bank.example.com"), tr("Primary bank account."),
           QStringLiteral("2026-10-18 09:30")},
          {tr("Brokerage"), tr("investor"), tr("mock-broker-password"),
           tr("https://broker.example.com"), tr("Investment account."),
           QStringLiteral("2026-10-17 15:12")}}},
        {tr("Wi-Fi"),
         {{tr("Home Wi-Fi"), QString(), tr("mock-wifi-password"), QString(),
           tr("Home network."), QStringLiteral("2026-10-16 22:00")},
          {tr("Office Wi-Fi"), QString(), tr("mock-office-wifi"), QString(),
           tr("Office guest network."), QStringLiteral("2026-10-15 12:00")}}},
        {tr("Notes"),
         {{tr("Passport"), QString(), QString(), QString(),
           tr("Passport details and renewal date."), QStringLiteral("2026-10-14 09:00")},
          {tr("Insurance"), QString(), QString(), QString(),
           tr("Insurance policy reference."), QStringLiteral("2026-10-13 17:30")}}},
    };

    m_structure->clear();
    auto *allItems = new QTreeWidgetItem(m_structure, {tr("All Items")});
    allItems->setData(0, Qt::UserRole, -1);

    for (int i = 0; i < m_groups.size(); ++i) {
        auto *item = new QTreeWidgetItem(
            allItems,
            {tr("%1 (%2)").arg(m_groups.at(i).name).arg(m_groups.at(i).entries.size())});
        item->setData(0, Qt::UserRole, i);
    }

    allItems->setExpanded(true);
    m_structure->setCurrentItem(allItems);
}

void VaultView::refreshLists()
{
    if (QTreeWidgetItem *allItems = m_structure->topLevelItem(0)) {
        for (int i = 0; i < m_groups.size() && i < allItems->childCount(); ++i) {
            allItems->child(i)->setText(
                0, tr("%1 (%2)").arg(m_groups.at(i).name).arg(m_groups.at(i).entries.size()));
        }
    }

    m_details->clear();
    m_icons->clear();

    for (int groupIndex = 0; groupIndex < m_groups.size(); ++groupIndex) {
        if (m_currentGroup >= 0 && m_currentGroup != groupIndex)
            continue;

        const Group &group = m_groups.at(groupIndex);
        for (int entryIndex = 0; entryIndex < group.entries.size(); ++entryIndex) {
            const Entry &entry = group.entries.at(entryIndex);
            if (!m_filter.isEmpty()) {
                const QString needle = m_filter.toCaseFolded();
                const QString haystack =
                    QStringList{entry.title, entry.username, entry.url, entry.notes}
                        .join(QLatin1Char(' '))
                        .toCaseFolded();
                if (!haystack.contains(needle))
                    continue;
            }

            auto *detail = new QTreeWidgetItem(
                m_details, {entry.title, entry.username, entry.url, entry.modified});
            detail->setData(0, Qt::UserRole, groupIndex);
            detail->setData(0, Qt::UserRole + 1, entryIndex);

            auto *icon = new QListWidgetItem(
                style()->standardIcon(QStyle::SP_FileIcon), entry.title, m_icons);
            icon->setData(Qt::UserRole, groupIndex);
            icon->setData(Qt::UserRole + 1, entryIndex);
            icon->setToolTip(entry.username.isEmpty()
                                 ? entry.title
                                 : tr("%1\n%2").arg(entry.title, entry.username));
        }
    }

    updateInfo();
}

void VaultView::updateInfo()
{
    const auto selection = selectedEntry();
    if (!selection) {
        m_info->setHtml(tr("<i>Select an entry to see details.</i>"));
        return;
    }

    const int groupIndex = selection->first;
    const int entryIndex = selection->second;
    const Group &group = m_groups.at(groupIndex);
    const Entry &entry = group.entries.at(entryIndex);

    QString notes = entry.notes.toHtmlEscaped();
    notes.replace(QLatin1Char('\n'), QStringLiteral("<br>"));

    m_info->setHtml(
        tr("<h3>%1</h3>"
           "<table cellspacing=\"4\">"
           "<tr><td><b>Group</b></td><td>%2</td></tr>"
           "<tr><td><b>User name</b></td><td>%3</td></tr>"
           "<tr><td><b>Password</b></td><td>••••••••</td></tr>"
           "<tr><td><b>URL</b></td><td>%4</td></tr>"
           "<tr><td><b>Modified</b></td><td>%5</td></tr>"
           "</table><p>%6</p>")
            .arg(entry.title.toHtmlEscaped(), group.name.toHtmlEscaped(),
                 entry.username.toHtmlEscaped(), entry.url.toHtmlEscaped(),
                 entry.modified.toHtmlEscaped(), notes));

    emit statusMessage(tr("Selected: %1").arg(entry.title));
}

void VaultView::setFilter(const QString &filter)
{
    m_filter = filter;
    refreshLists();
}

void VaultView::showDetails()
{
    const auto selection = selectedEntry();
    m_contentStack->setCurrentWidget(m_details);
    if (selection)
        selectEntry(selection->first, selection->second);
    else
        updateInfo();
    emit statusMessage(tr("Details view"));
}

void VaultView::showIcons()
{
    const auto selection = selectedEntry();
    m_contentStack->setCurrentWidget(m_icons);
    if (selection)
        selectEntry(selection->first, selection->second);
    else
        updateInfo();
    emit statusMessage(tr("Icons view"));
}

void VaultView::showContextMenu(QAbstractItemView *view, const QPoint &pos)
{
    const QModelIndex index = view->indexAt(pos);
    if (index.isValid())
        view->setCurrentIndex(index);

    const auto selection = selectedEntry();

    QMenu menu(this);
    QAction *addAction = menu.addAction(tr("New Entry…"));
    menu.addSeparator();
    QAction *editAction = menu.addAction(tr("Edit Entry…"));
    QAction *copyPasswordAction = menu.addAction(tr("Copy Password"));
    QAction *copyUsernameAction = menu.addAction(tr("Copy User Name"));
    menu.addSeparator();
    QAction *deleteAction = menu.addAction(tr("Delete Entry"));

    const bool hasSelection = selection.has_value();
    editAction->setEnabled(hasSelection);
    copyPasswordAction->setEnabled(hasSelection);
    copyUsernameAction->setEnabled(hasSelection);
    deleteAction->setEnabled(hasSelection);

    QAction *chosen = menu.exec(view->viewport()->mapToGlobal(pos));
    if (chosen == addAction)
        addEntry();
    else if (chosen == editAction)
        editSelectedEntry();
    else if (chosen == copyPasswordAction)
        copySelectedPassword();
    else if (chosen == copyUsernameAction)
        copySelectedUsername();
    else if (chosen == deleteAction)
        deleteSelectedEntry();
}

std::optional<QPair<int, int>> VaultView::selectedEntry() const
{
    if (m_contentStack->currentWidget() == m_details) {
        const QTreeWidgetItem *item = m_details->currentItem();
        if (!item || !item->isSelected())
            return std::nullopt;
        return QPair<int, int>{item->data(0, Qt::UserRole).toInt(),
                               item->data(0, Qt::UserRole + 1).toInt()};
    }

    const QListWidgetItem *item = m_icons->currentItem();
    if (!item || !item->isSelected())
        return std::nullopt;
    return QPair<int, int>{item->data(Qt::UserRole).toInt(),
                           item->data(Qt::UserRole + 1).toInt()};
}

void VaultView::selectEntry(int groupIndex, int entryIndex)
{
    if (groupIndex < 0 || groupIndex >= m_groups.size())
        return;
    if (entryIndex < 0 || entryIndex >= m_groups.at(groupIndex).entries.size())
        return;

    if (m_contentStack->currentWidget() == m_icons) {
        for (int i = 0; i < m_icons->count(); ++i) {
            QListWidgetItem *item = m_icons->item(i);
            if (item->data(Qt::UserRole).toInt() == groupIndex
                && item->data(Qt::UserRole + 1).toInt() == entryIndex) {
                m_icons->setCurrentItem(item);
                m_icons->scrollToItem(item);
                return;
            }
        }
    }

    for (int i = 0; i < m_details->topLevelItemCount(); ++i) {
        QTreeWidgetItem *item = m_details->topLevelItem(i);
        if (item->data(0, Qt::UserRole).toInt() == groupIndex
            && item->data(0, Qt::UserRole + 1).toInt() == entryIndex) {
            m_details->setCurrentItem(item);
            m_details->scrollToItem(item);
            return;
        }
    }
}

void VaultView::addEntry()
{
    if (m_groups.isEmpty())
        return;

    const int groupIndex = m_currentGroup >= 0 ? m_currentGroup : 0;
    bool accepted = false;
    const QString title = QInputDialog::getText(
        this, tr("New Entry"), tr("Title:"), QLineEdit::Normal, tr("New Entry"),
        &accepted);
    if (!accepted || title.trimmed().isEmpty())
        return;

    Entry entry;
    entry.title = title.trimmed();
    entry.username = tr("new-user");
    entry.password = tr("mock-password");
    entry.url = QStringLiteral("https://example.com");
    entry.notes = tr("Mock entry created from the toolbar.");
    entry.modified = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"));

    m_groups[groupIndex].entries.append(entry);
    refreshLists();

    const int entryIndex = m_groups.at(groupIndex).entries.size() - 1;
    selectEntry(groupIndex, entryIndex);
    emit statusMessage(tr("Created mock entry: %1").arg(entry.title));
}

void VaultView::editSelectedEntry()
{
    const auto selection = selectedEntry();
    if (!selection)
        return;

    const auto [groupIndex, entryIndex] = *selection;
    Entry &entry = m_groups[groupIndex].entries[entryIndex];

    bool accepted = false;
    const QString title = QInputDialog::getText(
        this, tr("Edit Entry"), tr("Title:"), QLineEdit::Normal, entry.title,
        &accepted);
    if (!accepted || title.trimmed().isEmpty())
        return;

    entry.title = title.trimmed();
    entry.modified = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"));
    refreshLists();
    selectEntry(groupIndex, entryIndex);
    emit statusMessage(tr("Updated mock entry: %1").arg(entry.title));
}

void VaultView::deleteSelectedEntry()
{
    const auto selection = selectedEntry();
    if (!selection)
        return;

    const auto [groupIndex, entryIndex] = *selection;
    const Entry entry = m_groups[groupIndex].entries.at(entryIndex);
    if (QMessageBox::question(this, tr("Delete Entry"),
                              tr("Delete “%1”?").arg(entry.title))
        != QMessageBox::Yes) {
        return;
    }

    m_groups[groupIndex].entries.removeAt(entryIndex);
    refreshLists();
    emit statusMessage(tr("Deleted mock entry: %1").arg(entry.title));
}

void VaultView::copySelectedPassword()
{
    const auto selection = selectedEntry();
    if (!selection)
        return;

    const Entry &entry = m_groups[selection->first].entries.at(selection->second);
    QGuiApplication::clipboard()->setText(entry.password);
    emit statusMessage(tr("Password copied (mock): %1").arg(entry.title));
}

void VaultView::copySelectedUsername()
{
    const auto selection = selectedEntry();
    if (!selection)
        return;

    const Entry &entry = m_groups[selection->first].entries.at(selection->second);
    QGuiApplication::clipboard()->setText(entry.username);
    emit statusMessage(tr("User name copied (mock): %1").arg(entry.title));
}
