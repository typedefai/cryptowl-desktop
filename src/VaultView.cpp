#include "VaultView.h"

#include "NoteEditorDialog.h"
#include "PasswordEditorDialog.h"
#include "vault/ItemRepository.h"
#include "vault/VaultSession.h"

#include <QAbstractItemView>
#include <QAction>
#include <QClipboard>
#include <QDateTime>
#include <QFont>
#include <QGuiApplication>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
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

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace {

using cryptowl::vault::ItemRecord;
using cryptowl::vault::ItemSummary;
using cryptowl::vault::ItemUpdate;
using cryptowl::vault::NewItem;

constexpr const char *kPasswordType = "password";
constexpr const char *kNoteType = "plain";

QString escapedOrDash(const QString &text)
{
    return text.isEmpty() ? QStringLiteral("—") : text.toHtmlEscaped();
}

QJsonObject parseJsonObject(const std::string &value)
{
    const QJsonDocument document =
        QJsonDocument::fromJson(QByteArray::fromStdString(value));
    return document.isObject() ? document.object() : QJsonObject();
}

QString jsonString(const QJsonObject &object, const QString &key)
{
    return object.value(key).toString();
}

QByteArray passwordMeta(const PasswordEditorDialog::Data &data)
{
    QJsonObject meta;
    meta[QStringLiteral("username")] = data.username;
    meta[QStringLiteral("url")] = data.url;
    return QJsonDocument(meta).toJson(QJsonDocument::Compact);
}

QByteArray passwordPayload(const PasswordEditorDialog::Data &data)
{
    QJsonObject payload;
    payload[QStringLiteral("username")] = data.username;
    payload[QStringLiteral("url")] = data.url;
    payload[QStringLiteral("secret")] = data.password;
    payload[QStringLiteral("notes")] = data.notes;
    return QJsonDocument(payload).toJson(QJsonDocument::Compact);
}

QString updatedText(qint64 milliseconds)
{
    if (milliseconds <= 0)
        return QStringLiteral("—");
    return QDateTime::fromMSecsSinceEpoch(milliseconds)
        .toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

QString listDateText(qint64 milliseconds)
{
    if (milliseconds <= 0)
        return QStringLiteral("—");
    return QDateTime::fromMSecsSinceEpoch(milliseconds)
        .toString(QStringLiteral("yyyy-MM-dd"));
}

void wipe(QString &value)
{
    value.fill(QLatin1Char('\0'));
}

void wipe(QByteArray &value)
{
    value.fill('\0');
}

void wipe(std::string &value)
{
    std::fill(value.begin(), value.end(), '\0');
}

} // namespace

VaultView::VaultView(QString vaultPath,
                     std::shared_ptr<cryptowl::vault::VaultSession> session,
                     QWidget *parent)
    : QWidget(parent)
    , m_vaultPath(std::move(vaultPath))
    , m_session(std::move(session))
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
    m_info->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    rightSplitter->addWidget(m_info);
    rightSplitter->setSizes({320, 120});
    splitter->addWidget(rightSplitter);
    splitter->setSizes({210, 500});

    layout->addWidget(splitter);

    if (auto *allItems = m_structure->topLevelItem(0))
        m_structure->setCurrentItem(allItems);

    reload();
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

    auto *allItems = new QTreeWidgetItem(m_structure, {tr("All Items")});
    allItems->setData(0, Qt::UserRole, QString());

    auto *passwords = new QTreeWidgetItem(allItems, {tr("Passwords")});
    passwords->setData(0, Qt::UserRole, QString::fromLatin1(kPasswordType));

    auto *notes = new QTreeWidgetItem(allItems, {tr("Notes")});
    notes->setData(0, Qt::UserRole, QString::fromLatin1(kNoteType));
    allItems->setExpanded(true);

    connect(m_structure, &QTreeWidget::currentItemChanged, this,
            [this](QTreeWidgetItem *current, QTreeWidgetItem *) {
                m_currentType =
                    current ? current->data(0, Qt::UserRole).toString() : QString();
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
        {tr("Title"), tr("Type"), tr("Summary"), tr("Modified")});
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
    m_icons->setGridSize(QSize(130, 84));
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

void VaultView::reload(const QString &selectId)
{
    m_rows.clear();
    m_loadError.clear();

    if (!m_session) {
        updateGroupCounts();
        refreshLists();
        return;
    }

    std::vector<ItemSummary> items;
    std::string error;
    if (!m_session->items().list(std::string(), &items, &error)) {
        m_loadError = QString::fromStdString(error);
        updateGroupCounts();
        refreshLists();
        return;
    }

    for (const ItemSummary &item : items) {
        ItemRow row;
        row.id = QString::fromStdString(item.id);
        row.type = QString::fromStdString(item.type);
        row.title = QString::fromStdString(item.title);
        row.classification = QString::fromStdString(item.classification);
        row.updatedAt = item.updatedAt;

        const QJsonObject meta = parseJsonObject(item.meta);
        row.username = jsonString(meta, QStringLiteral("username"));
        row.url = jsonString(meta, QStringLiteral("url"));
        m_rows.push_back(std::move(row));
    }

    updateGroupCounts();
    refreshLists(selectId);
}

void VaultView::selectTypeFilter(const QString &type)
{
    m_currentType = type;
    if (auto *allItems = m_structure->topLevelItem(0)) {
        if (type.isEmpty()) {
            m_structure->setCurrentItem(allItems);
        } else {
            for (int i = 0; i < allItems->childCount(); ++i) {
                QTreeWidgetItem *child = allItems->child(i);
                if (child->data(0, Qt::UserRole).toString() == type) {
                    m_structure->setCurrentItem(child);
                    break;
                }
            }
        }
    }
    refreshLists();
}

void VaultView::refreshLists(const QString &selectId)
{
    m_details->clear();
    m_icons->clear();

    QString needle = m_filter;
    needle = needle.trimmed().toCaseFolded();

    for (const ItemRow &row : m_rows) {
        if (!m_currentType.isEmpty() && row.type != m_currentType)
            continue;
        if (!needle.isEmpty()) {
            const QString haystack =
                QStringList{row.title, row.username, row.url}.join(QLatin1Char(' '))
                    .toCaseFolded();
            if (!haystack.contains(needle))
                continue;
        }

        auto *detail =
            new QTreeWidgetItem(m_details,
                                {row.title, typeLabel(row), summaryText(row),
                                 listDateText(row.updatedAt)});
        detail->setData(0, Qt::UserRole, row.id);
        detail->setToolTip(0, row.title);
        detail->setToolTip(1, typeLabel(row));
        detail->setToolTip(2, summaryText(row));
        detail->setToolTip(3, updatedText(row.updatedAt));

        auto *icon = new QListWidgetItem(
            style()->standardIcon(QStyle::SP_FileIcon), row.title, m_icons);
        icon->setData(Qt::UserRole, row.id);
        icon->setToolTip(tr("%1\n%2").arg(typeLabel(row), summaryText(row)));
    }

    if (!selectId.isEmpty())
        selectItem(selectId);
    updateInfo();
}

void VaultView::updateGroupCounts()
{
    auto *allItems = m_structure ? m_structure->topLevelItem(0) : nullptr;
    if (!allItems || allItems->childCount() < 2)
        return;

    int passwords = 0;
    int notes = 0;
    for (const ItemRow &row : m_rows) {
        if (row.type == QLatin1String(kPasswordType))
            ++passwords;
        else if (row.type == QLatin1String(kNoteType))
            ++notes;
    }
    allItems->child(0)->setText(0, tr("Passwords (%1)").arg(passwords));
    allItems->child(1)->setText(0, tr("Notes (%1)").arg(notes));
}

QString VaultView::typeLabel(const ItemRow &row) const
{
    if (row.type == QLatin1String(kPasswordType))
        return tr("Password");
    if (row.type == QLatin1String(kNoteType))
        return tr("Note");
    return row.type;
}

QString VaultView::summaryText(const ItemRow &row) const
{
    if (row.type == QLatin1String(kPasswordType)) {
        if (!row.username.isEmpty())
            return row.username;
        if (!row.url.isEmpty())
            return row.url;
        return QStringLiteral("—");
    }
    if (row.type == QLatin1String(kNoteType)) {
        if (row.classification == QLatin1String("S"))
            return tr("Secret");
        if (row.classification == QLatin1String("T"))
            return tr("Top Secret");
        return tr("Confidential");
    }
    return row.classification;
}

QString VaultView::classificationLabel(const QString &classification) const
{
    if (classification == QLatin1String("C"))
        return tr("C — Confidential");
    if (classification == QLatin1String("S"))
        return tr("S — Secret");
    if (classification == QLatin1String("T"))
        return tr("T — Top Secret");
    return classification;
}

void VaultView::updateInfo()
{
    if (!m_loadError.isEmpty()) {
        m_info->setHtml(tr("<b>Could not load items:</b> %1")
                            .arg(m_loadError.toHtmlEscaped()));
        return;
    }
    if (!m_session) {
        m_info->setHtml(tr("<i>Vault data is unavailable.</i>"));
        return;
    }

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row) {
        if (m_rows.isEmpty()) {
            m_info->setHtml(
                tr("<i>No items yet. Use <b>New password…</b> or "
                   "<b>New note…</b> to create one.</i>"));
        } else if (!m_filter.trimmed().isEmpty() || !m_currentType.isEmpty()) {
            m_info->setHtml(tr("<i>No items match the current view.</i>"));
        } else {
            m_info->setHtml(tr("<i>Select an item to see details.</i>"));
        }
        return;
    }

    if (row->type == QLatin1String(kNoteType)) {
        ItemRecord record;
        std::string error;
        QString body;
        if (m_session->items().get(row->id.toStdString(), &record, &error)) {
            QString noteText = QString::fromStdString(record.payload);
            body = noteText.left(4000).toHtmlEscaped();
            body.replace(QLatin1Char('\n'), QStringLiteral("<br>"));
            if (noteText.size() > 4000)
                body += QStringLiteral("<br>…");
            wipe(record.payload);
            wipe(noteText);
        } else {
            body = tr("<i>Could not read this note.</i>");
        }

        if (body.isEmpty())
            body = tr("<i>No content yet.</i>");

        m_info->setHtml(
            tr("<h3>%1</h3>"
               "<table cellspacing=\"4\">"
               "<tr><td><b>Type</b></td><td>Note</td></tr>"
               "<tr><td><b>Classification</b></td><td>%2</td></tr>"
               "<tr><td><b>Modified</b></td><td>%3</td></tr>"
               "</table><h4>Note</h4><p>%4</p>")
                .arg(row->title.toHtmlEscaped(),
                     classificationLabel(row->classification).toHtmlEscaped(),
                     updatedText(row->updatedAt), body));
        emit statusMessage(tr("Selected: %1").arg(row->title));
        return;
    }

    m_info->setHtml(
        tr("<h3>%1</h3>"
           "<table cellspacing=\"4\">"
           "<tr><td><b>Type</b></td><td>Password</td></tr>"
           "<tr><td><b>User name</b></td><td>%2</td></tr>"
           "<tr><td><b>Password</b></td><td>••••••••</td></tr>"
           "<tr><td><b>URL</b></td><td>%3</td></tr>"
           "<tr><td><b>Classification</b></td><td>%4</td></tr>"
           "<tr><td><b>Modified</b></td><td>%5</td></tr>"
           "</table><p><i>Use Edit to reveal or change the password.</i></p>")
            .arg(row->title.toHtmlEscaped(), escapedOrDash(row->username),
                 escapedOrDash(row->url),
                 classificationLabel(row->classification).toHtmlEscaped(),
                 updatedText(row->updatedAt)));

    emit statusMessage(tr("Selected: %1").arg(row->title));
}

void VaultView::setFilter(const QString &filter)
{
    m_filter = filter;
    refreshLists(selectedId());
}

void VaultView::showDetails()
{
    const QString id = selectedId();
    m_contentStack->setCurrentWidget(m_details);
    if (!id.isEmpty())
        selectItem(id);
    updateInfo();
    emit statusMessage(tr("Details view"));
}

void VaultView::showIcons()
{
    const QString id = selectedId();
    m_contentStack->setCurrentWidget(m_icons);
    if (!id.isEmpty())
        selectItem(id);
    updateInfo();
    emit statusMessage(tr("Icons view"));
}

void VaultView::showContextMenu(QAbstractItemView *view, const QPoint &pos)
{
    const QModelIndex index = view->indexAt(pos);
    if (index.isValid())
        view->setCurrentIndex(index);

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    const bool hasSelection = row != nullptr;
    const bool isPassword = row && row->type == QLatin1String(kPasswordType);

    QMenu menu(this);
    QAction *addPasswordAction = menu.addAction(tr("New password…"));
    QAction *addNoteAction = menu.addAction(tr("New note…"));
    menu.addSeparator();
    QAction *editAction = menu.addAction(tr("Edit…"));
    QAction *copyUsernameAction = menu.addAction(tr("Copy user name"));
    menu.addSeparator();
    QAction *deleteAction = menu.addAction(tr("Delete"));

    editAction->setEnabled(hasSelection);
    copyUsernameAction->setEnabled(isPassword);
    deleteAction->setEnabled(hasSelection);

    QAction *chosen = menu.exec(view->viewport()->mapToGlobal(pos));
    if (chosen == addPasswordAction)
        addEntry();
    else if (chosen == addNoteAction)
        addNote();
    else if (chosen == editAction)
        editSelectedEntry();
    else if (chosen == copyUsernameAction)
        copySelectedUsername();
    else if (chosen == deleteAction)
        deleteSelectedEntry();
}

QString VaultView::selectedId() const
{
    if (!m_contentStack || !m_details || !m_icons)
        return {};

    if (m_contentStack->currentWidget() == m_details) {
        const QTreeWidgetItem *item = m_details->currentItem();
        if (!item || !item->isSelected())
            return {};
        return item->data(0, Qt::UserRole).toString();
    }

    const QListWidgetItem *item = m_icons->currentItem();
    if (!item || !item->isSelected())
        return {};
    return item->data(Qt::UserRole).toString();
}

const VaultView::ItemRow *VaultView::rowForId(const QString &id) const
{
    for (const ItemRow &row : m_rows) {
        if (row.id == id)
            return &row;
    }
    return nullptr;
}

void VaultView::selectItem(const QString &id)
{
    if (id.isEmpty())
        return;

    if (m_contentStack->currentWidget() == m_icons) {
        for (int i = 0; i < m_icons->count(); ++i) {
            QListWidgetItem *item = m_icons->item(i);
            if (item->data(Qt::UserRole).toString() == id) {
                m_icons->setCurrentItem(item);
                m_icons->scrollToItem(item);
                return;
            }
        }
        return;
    }

    for (int i = 0; i < m_details->topLevelItemCount(); ++i) {
        QTreeWidgetItem *item = m_details->topLevelItem(i);
        if (item->data(0, Qt::UserRole).toString() == id) {
            m_details->setCurrentItem(item);
            m_details->scrollToItem(item);
            return;
        }
    }
}

void VaultView::addEntry()
{
    if (!m_session)
        return;

    PasswordEditorDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    PasswordEditorDialog::Data data = dialog.data();
    QByteArray meta = passwordMeta(data);
    QByteArray payload = passwordPayload(data);

    NewItem item;
    item.type = kPasswordType;
    item.classification = "S";
    item.title = data.title.toStdString();
    item.meta = meta.toStdString();
    item.payload = payload.toStdString();

    std::string id;
    std::string error;
    const bool created = m_session->items().create(item, &id, &error);

    wipe(item.payload);
    wipe(data.password);
    wipe(payload);

    if (!created) {
        QMessageBox::critical(this, tr("Could not save password"),
                              QString::fromStdString(error));
        return;
    }

    if (!m_currentType.isEmpty())
        selectTypeFilter(QString::fromLatin1(kPasswordType));
    reload(QString::fromStdString(id));
    emit statusMessage(tr("Created password: %1").arg(data.title));
}

void VaultView::addNote()
{
    if (!m_session)
        return;

    NoteEditorDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    NoteEditorDialog::Data data = dialog.data();
    if (data.classification != QLatin1String("S"))
        data.classification = QStringLiteral("C");

    NewItem item;
    item.type = kNoteType;
    item.classification = data.classification.toStdString();
    item.title = data.title.toStdString();
    item.meta = "{}";
    item.payload = data.body.toStdString();

    std::string id;
    std::string error;
    const bool created = m_session->items().create(item, &id, &error);

    wipe(item.payload);
    wipe(data.body);

    if (!created) {
        QMessageBox::critical(this, tr("Could not save note"),
                              QString::fromStdString(error));
        return;
    }

    if (!m_currentType.isEmpty())
        selectTypeFilter(QString::fromLatin1(kNoteType));
    reload(QString::fromStdString(id));
    emit statusMessage(tr("Created note: %1").arg(data.title));
}

void VaultView::editSelectedEntry()
{
    if (!m_session)
        return;

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row)
        return;

    if (row->type == QLatin1String(kNoteType))
        editSelectedNote();
    else if (row->type == QLatin1String(kPasswordType))
        editSelectedPassword();
}

void VaultView::editSelectedPassword()
{
    const QString id = selectedId();
    if (id.isEmpty())
        return;

    ItemRecord record;
    std::string error;
    if (!m_session->items().get(id.toStdString(), &record, &error)) {
        QMessageBox::critical(this, tr("Could not read password"),
                              QString::fromStdString(error));
        return;
    }

    const QJsonObject payload = parseJsonObject(record.payload);
    const QJsonObject meta = parseJsonObject(record.meta);

    PasswordEditorDialog::Data data;
    data.title = QString::fromStdString(record.title);
    data.username = jsonString(payload, QStringLiteral("username"));
    if (data.username.isEmpty())
        data.username = jsonString(meta, QStringLiteral("username"));
    data.url = jsonString(payload, QStringLiteral("url"));
    if (data.url.isEmpty())
        data.url = jsonString(meta, QStringLiteral("url"));
    data.password = jsonString(payload, QStringLiteral("secret"));
    data.notes = jsonString(payload, QStringLiteral("notes"));
    wipe(record.payload);

    PasswordEditorDialog dialog(data, this);
    wipe(data.password);
    if (dialog.exec() != QDialog::Accepted)
        return;

    data = dialog.data();
    QByteArray metaJson = passwordMeta(data);
    QByteArray payloadJson = passwordPayload(data);

    ItemUpdate update;
    update.title = data.title.toStdString();
    update.classification = "S";
    update.meta = metaJson.toStdString();
    update.payload = payloadJson.toStdString();

    const bool updated = m_session->items().update(id.toStdString(), update, &error);

    wipe(update.payload);
    wipe(data.password);
    wipe(payloadJson);

    if (!updated) {
        QMessageBox::critical(this, tr("Could not update password"),
                              QString::fromStdString(error));
        return;
    }

    reload(id);
    emit statusMessage(tr("Updated password: %1").arg(data.title));
}

void VaultView::editSelectedNote()
{
    const QString id = selectedId();
    if (id.isEmpty())
        return;

    ItemRecord record;
    std::string error;
    if (!m_session->items().get(id.toStdString(), &record, &error)) {
        QMessageBox::critical(this, tr("Could not read note"),
                              QString::fromStdString(error));
        return;
    }

    NoteEditorDialog::Data data;
    data.title = QString::fromStdString(record.title);
    data.body = QString::fromStdString(record.payload);
    data.classification = QString::fromStdString(record.classification);
    if (data.classification != QLatin1String("S"))
        data.classification = QStringLiteral("C");
    wipe(record.payload);

    NoteEditorDialog dialog(data, this);
    wipe(data.body);
    if (dialog.exec() != QDialog::Accepted)
        return;

    data = dialog.data();
    if (data.classification != QLatin1String("S"))
        data.classification = QStringLiteral("C");

    ItemUpdate update;
    update.title = data.title.toStdString();
    update.classification = data.classification.toStdString();
    update.meta = "{}";
    update.payload = data.body.toStdString();

    const bool updated = m_session->items().update(id.toStdString(), update, &error);

    wipe(update.payload);
    wipe(data.body);

    if (!updated) {
        QMessageBox::critical(this, tr("Could not update note"),
                              QString::fromStdString(error));
        return;
    }

    reload(id);
    emit statusMessage(tr("Updated note: %1").arg(data.title));
}

void VaultView::deleteSelectedEntry()
{
    if (!m_session)
        return;

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row)
        return;

    const QString title = row->title;
    const QString type = row->type;
    if (QMessageBox::question(this, tr("Delete item"),
                              tr("Delete “%1”?").arg(title))
        != QMessageBox::Yes) {
        return;
    }

    std::string error;
    if (!m_session->items().softDelete(id.toStdString(), &error)) {
        QMessageBox::critical(this, tr("Could not delete item"),
                              QString::fromStdString(error));
        return;
    }

    reload();
    if (type == QLatin1String(kNoteType))
        emit statusMessage(tr("Deleted note: %1").arg(title));
    else
        emit statusMessage(tr("Deleted password: %1").arg(title));
}

void VaultView::copySelectedUsername()
{
    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row || row->type != QLatin1String(kPasswordType))
        return;

    if (row->username.isEmpty()) {
        emit statusMessage(tr("This password has no user name."));
        return;
    }

    QGuiApplication::clipboard()->setText(row->username);
    emit statusMessage(tr("User name copied: %1").arg(row->title));
}
