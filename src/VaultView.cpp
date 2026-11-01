#include "VaultView.h"

#include "NoteEditorDialog.h"
#include "PasswordEditorDialog.h"
#include "PasswordViewDialog.h"
#include "SecretAccessDialog.h"
#include "TopSecretDialog.h"
#include "TopSecretService.h"
#include "VaultUnlocker.h"
#include "crypto/ProtectedValue.h"
#include "vault/ItemRepository.h"
#include "vault/VaultSession.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QEventLoop>
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
using cryptowl::vault::ItemRepository;
using cryptowl::vault::ItemSummary;
using cryptowl::vault::ItemUpdate;
using cryptowl::vault::NewItem;
using cryptowl::vault::VaultSession;

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
            [this](QTreeWidgetItem *, int) { viewSelectedEntry(); });
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
            [this](QListWidgetItem *) { viewSelectedEntry(); });
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
        QString hint;
        if (row->classification == QLatin1String("T")) {
            hint = tr("<p><i>Top Secret note content is available in the "
                      "editor; the secondary password is required.</i></p>");
        } else if (row->classification == QLatin1String("S")) {
            hint = tr("<p><i>Secret note content is available in the "
                      "editor.</i></p>");
        } else {
            hint = tr("<p><i>Open the note editor to view its content.</i></p>");
        }

        m_info->setHtml(
            tr("<h3>%1</h3>"
               "<table cellspacing=\"4\">"
               "<tr><td><b>Type</b></td><td>Note</td></tr>"
               "<tr><td><b>Classification</b></td><td>%2</td></tr>"
               "<tr><td><b>Modified</b></td><td>%3</td></tr>"
               "</table>%4")
                .arg(row->title.toHtmlEscaped(),
                     classificationLabel(row->classification).toHtmlEscaped(),
                     updatedText(row->updatedAt), hint));
        emit statusMessage(tr("Selected: %1").arg(row->title));
        return;
    }

    QString hint;
    if (row->classification == QLatin1String("T")) {
        hint = tr("<p><i>Top Secret password content is available in the "
                  "editor; the secondary password is required.</i></p>");
    } else {
        hint = tr("<p><i>Open the editor to view or change the password and "
                  "notes.</i></p>");
    }

    m_info->setHtml(
        tr("<h3>%1</h3>"
           "<table cellspacing=\"4\">"
           "<tr><td><b>Type</b></td><td>Password</td></tr>"
           "<tr><td><b>User name</b></td><td>%2</td></tr>"
           "<tr><td><b>URL</b></td><td>%3</td></tr>"
           "<tr><td><b>Classification</b></td><td>%4</td></tr>"
           "<tr><td><b>Modified</b></td><td>%5</td></tr>"
           "</table>%6")
            .arg(row->title.toHtmlEscaped(), escapedOrDash(row->username),
                 escapedOrDash(row->url),
                 classificationLabel(row->classification).toHtmlEscaped(),
                 updatedText(row->updatedAt), hint));

    emit statusMessage(tr("Selected: %1").arg(row->title));
}

bool VaultView::openSecretSession(
    std::unique_ptr<cryptowl::vault::VaultSession> *session, QString *error)
{
    // Per-access S unlock: the main session intentionally has no KEK. Re-enter
    // the master password, derive a temporary session, and destroy it after the
    // operation. "Remember Secret access" uses the main session instead.
    if (session)
        session->reset();
    if (!m_session) {
        if (error)
            *error = tr("Vault data is unavailable.");
        return false;
    }
    if (m_session->hasKek())
        return true;

    while (true) {
        QWidget *promptParent = QApplication::activeModalWidget();
        if (!promptParent)
            promptParent = this;
        SecretAccessDialog dialog(promptParent);
        if (dialog.exec() != QDialog::Accepted) {
            if (error)
                error->clear();
            return false;
        }

        QString password = dialog.takePassword();
        QApplication::setOverrideCursor(Qt::WaitCursor);
        QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        auto unlocked = VaultUnlocker::unlock(m_vaultPath, password, false);
        password.fill(QLatin1Char('\0'));
        QApplication::restoreOverrideCursor();

        if (!unlocked.ok) {
            QMessageBox::warning(
                promptParent, tr("Secret access"),
                unlocked.error.isEmpty()
                    ? tr("Could not verify the master password.")
                    : unlocked.error);
            continue;
        }

        std::string sessionError;
        auto temporary = VaultSession::open(
            QDir(m_vaultPath).filePath(QStringLiteral("vault.db"))
                .toUtf8()
                .toStdString(),
            std::move(unlocked.vaultKey), std::move(unlocked.smk),
            &sessionError, true);
        if (!temporary) {
            if (error) {
                *error = sessionError.empty()
                    ? tr("Could not open a Secret access session.")
                    : QString::fromStdString(sessionError);
            }
            return false;
        }
        if (session)
            *session = std::move(temporary);
        return true;
    }
}

bool VaultView::withSecretItems(
    const std::function<bool(cryptowl::vault::ItemRepository &,
                             std::string *)> &operation,
    std::string *error)
{
    if (!m_session) {
        if (error)
            *error = "vault data is unavailable";
        return false;
    }
    if (m_session->hasKek())
        return operation(m_session->items(), error);

    std::unique_ptr<cryptowl::vault::VaultSession> temporary;
    QString promptError;
    if (!openSecretSession(&temporary, &promptError)) {
        if (error)
            *error = promptError.isEmpty()
                ? "Secret access was canceled"
                : promptError.toStdString();
        return false;
    }
    if (temporary)
        return operation(temporary->items(), error);
    return operation(m_session->items(), error);
}

bool VaultView::topSecretConfigured() const
{
    if (!m_session)
        return false;
    TopSecretService service(m_vaultPath, m_session->handle());
    return service.isConfigured();
}

bool VaultView::authorizeTopSecret(
    cryptowl::crypto::ProtectedValue *topSecretKek, QString *error)
{
    if (!m_session) {
        if (error)
            *error = tr("Vault data is unavailable.");
        return false;
    }

    TopSecretService service(m_vaultPath, m_session->handle());
    QString configError;
    if (!service.isConfigured(&configError)) {
        if (error) {
            *error = configError.isEmpty() ? tr("Top Secret is not set up.")
                                           : configError;
        }
        return false;
    }

    TopSecretUnlockDialog dialog(&service, this);
    if (dialog.exec() != QDialog::Accepted) {
        if (error)
            error->clear();
        return false;
    }

    if (!topSecretKek) {
        if (error)
            *error = tr("Top Secret key is unavailable.");
        return false;
    }
    *topSecretKek = dialog.takeTopSecretKek();
    if (topSecretKek->size() != 32) {
        if (error)
            *error = tr("Top Secret key is unavailable.");
        return false;
    }
    return true;
}

void VaultView::setupTopSecret()
{
    if (!m_session)
        return;

    TopSecretService service(m_vaultPath, m_session->handle());
    QString error;
    if (service.isConfigured(&error)) {
        QMessageBox::information(this, tr("Top Secret"),
                                 tr("Top Secret is already set up."));
        return;
    }
    if (!error.isEmpty()) {
        QMessageBox::warning(this, tr("Top Secret"), error);
        return;
    }

    TopSecretSetupDialog dialog(m_vaultPath, m_session->handle(), this);
    if (dialog.exec() != QDialog::Accepted)
        return;

    emit statusMessage(tr("Top Secret enabled"));
    updateInfo();
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
    QAction *viewAction = menu.addAction(tr("View…"));
    QAction *editAction = menu.addAction(tr("Edit…"));
    QAction *copyUsernameAction = menu.addAction(tr("Copy user name"));
    menu.addSeparator();
    QAction *deleteAction = menu.addAction(tr("Delete"));

    viewAction->setEnabled(isPassword);
    editAction->setEnabled(hasSelection);
    copyUsernameAction->setEnabled(isPassword);
    deleteAction->setEnabled(hasSelection);

    QAction *chosen = menu.exec(view->viewport()->mapToGlobal(pos));
    if (chosen == addPasswordAction)
        addEntry();
    else if (chosen == addNoteAction)
        addNote();
    else if (chosen == viewAction)
        viewSelectedEntry();
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
    dialog.setTopSecretAvailable(topSecretConfigured());
    cryptowl::crypto::ProtectedValue topSecretKek;
    std::unique_ptr<cryptowl::vault::VaultSession> secretSession;
    dialog.setSaveAuthorizer(
        [this, &topSecretKek,
         &secretSession](const PasswordEditorDialog::Data &data,
                         QString *error) {
            if (data.classification == QLatin1String("S")
                && m_session && !m_session->hasKek()) {
                QString secretError;
                if (!openSecretSession(&secretSession, &secretError)) {
                    if (error) {
                        *error = secretError.isEmpty()
                            ? tr("Secret access was canceled.")
                            : secretError;
                    }
                    return false;
                }
            }
            if (data.classification != QLatin1String("T"))
                return true;
            return authorizeTopSecret(&topSecretKek, error);
        });
    if (dialog.exec() != QDialog::Accepted)
        return;

    PasswordEditorDialog::Data data = dialog.data();
    const bool topSecret = data.classification == QLatin1String("T");
    const bool secret = data.classification == QLatin1String("S");
    QByteArray meta = passwordMeta(data);
    QByteArray payload = passwordPayload(data);

    NewItem item;
    item.type = kPasswordType;
    item.classification = topSecret ? "T" : "S";
    item.title = data.title.toStdString();
    item.meta = meta.toStdString();
    item.payload = payload.toStdString();

    std::string id;
    std::string error;
    ItemRepository &repository =
        (secret && secretSession) ? secretSession->items() : m_session->items();
    const bool created =
        topSecret
        ? repository.create(item, topSecretKek.span(), &id, &error)
        : repository.create(item, &id, &error);
    topSecretKek.clear();
    secretSession.reset();

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
    dialog.setTopSecretAvailable(topSecretConfigured());
    cryptowl::crypto::ProtectedValue topSecretKek;
    std::unique_ptr<cryptowl::vault::VaultSession> secretSession;
    dialog.setSaveAuthorizer(
        [this, &topSecretKek,
         &secretSession](const NoteEditorDialog::Data &data,
                         QString *error) {
            if (data.classification == QLatin1String("S")
                && m_session && !m_session->hasKek()) {
                QString secretError;
                if (!openSecretSession(&secretSession, &secretError)) {
                    if (error) {
                        *error = secretError.isEmpty()
                            ? tr("Secret access was canceled.")
                            : secretError;
                    }
                    return false;
                }
            }
            if (data.classification != QLatin1String("T"))
                return true;
            return authorizeTopSecret(&topSecretKek, error);
        });
    if (dialog.exec() != QDialog::Accepted)
        return;

    NoteEditorDialog::Data data = dialog.data();
    if (data.classification != QLatin1String("S")
        && data.classification != QLatin1String("T")) {
        data.classification = QStringLiteral("C");
    }

    const bool topSecret = data.classification == QLatin1String("T");
    const bool secret = data.classification == QLatin1String("S");
    NewItem item;
    item.type = kNoteType;
    item.classification = data.classification.toStdString();
    item.title = data.title.toStdString();
    item.meta = "{}";
    item.payload = data.body.toStdString();

    std::string id;
    std::string error;
    ItemRepository &repository =
        (secret && secretSession) ? secretSession->items() : m_session->items();
    const bool created =
        topSecret
        ? repository.create(item, topSecretKek.span(), &id, &error)
        : repository.create(item, &id, &error);
    topSecretKek.clear();
    secretSession.reset();

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

void VaultView::viewSelectedEntry()
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
        viewSelectedPassword();
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

bool VaultView::readPasswordItem(const QString &id,
                                 const QString &classification,
                                 ItemRecord *record, QString *error)
{
    if (!m_session) {
        if (error)
            *error = tr("Vault data is unavailable.");
        return false;
    }
    if (!record) {
        if (error)
            *error = tr("Password destination is unavailable.");
        return false;
    }

    std::string recordError;
    if (classification == QLatin1String("T")) {
        cryptowl::crypto::ProtectedValue topSecretKek;
        if (!authorizeTopSecret(&topSecretKek, error))
            return false;
        if (!m_session->items().get(id.toStdString(), topSecretKek.span(),
                                    record, &recordError)) {
            if (error)
                *error = QString::fromStdString(recordError);
            return false;
        }
        return true;
    }
    if (classification == QLatin1String("S")) {
        const bool ok = withSecretItems(
            [&id, record](ItemRepository &repository, std::string *innerError) {
                return repository.get(id.toStdString(), record, innerError);
            },
            &recordError);
        if (!ok && error)
            *error = QString::fromStdString(recordError);
        return ok;
    }
    if (!m_session->items().get(id.toStdString(), record, &recordError)) {
        if (error)
            *error = QString::fromStdString(recordError);
        return false;
    }
    return true;
}

void VaultView::viewSelectedPassword()
{
    if (!m_session)
        return;

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row || row->type != QLatin1String(kPasswordType))
        return;

    PasswordViewDialog::Data data;
    data.title = row->title;
    data.username = row->username;
    data.url = row->url;
    data.classification = row->classification;

    PasswordViewDialog::SecretLoader loader;
    if (row->classification == QLatin1String("S")
        || row->classification == QLatin1String("T")) {
        const QString classification = row->classification;
        loader = [this, id, classification](QString *password, QString *notes,
                                            QString *error) {
            ItemRecord record;
            if (!readPasswordItem(id, classification, &record, error))
                return false;
            const QJsonObject payload = parseJsonObject(record.payload);
            *password = jsonString(payload, QStringLiteral("secret"));
            *notes = jsonString(payload, QStringLiteral("notes"));
            wipe(record.payload);
            return true;
        };
    } else {
        ItemRecord record;
        QString recordError;
        if (!readPasswordItem(id, row->classification, &record, &recordError)) {
            QMessageBox::critical(this, tr("Could not read password"),
                                  recordError);
            return;
        }
        const QJsonObject payload = parseJsonObject(record.payload);
        data.password = jsonString(payload, QStringLiteral("secret"));
        data.notes = jsonString(payload, QStringLiteral("notes"));
        wipe(record.payload);
    }

    PasswordViewDialog dialog(data, std::move(loader), this);
    wipe(data.password);
    wipe(data.notes);
    if (dialog.exec() == QDialog::Accepted)
        editSelectedPassword();
}

void VaultView::editSelectedPassword()
{
    if (!m_session)
        return;

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row || row->type != QLatin1String(kPasswordType))
        return;

    const bool wasTopSecret = row->classification == QLatin1String("T");
    const bool wasSecret = row->classification == QLatin1String("S");
    ItemRecord record;
    QString loadError;
    if (!readPasswordItem(id, row->classification, &record, &loadError)) {
        if (!loadError.isEmpty()
            && !loadError.contains(QStringLiteral("canceled"),
                                   Qt::CaseInsensitive)) {
            QMessageBox::critical(this, tr("Could not read password"),
                                  loadError);
        }
        return;
    }

    const QJsonObject payload = parseJsonObject(record.payload);
    PasswordEditorDialog::Data data;
    data.title = row->title;
    data.username = row->username;
    data.url = row->url;
    data.classification = wasTopSecret ? QStringLiteral("T")
                                       : QStringLiteral("S");
    data.password = jsonString(payload, QStringLiteral("secret"));
    data.notes = jsonString(payload, QStringLiteral("notes"));
    wipe(record.payload);

    PasswordEditorDialog dialog(data, this);
    wipe(data.password);
    wipe(data.notes);
    dialog.setTopSecretAvailable(topSecretConfigured());
    cryptowl::crypto::ProtectedValue saveKek;
    std::unique_ptr<cryptowl::vault::VaultSession> secretSession;
    dialog.setSaveAuthorizer(
        [this, wasTopSecret, wasSecret, &saveKek,
         &secretSession](const PasswordEditorDialog::Data &data, QString *error) {
            const bool needsSecretAccess =
                wasSecret || data.classification == QLatin1String("S");
            if (needsSecretAccess && m_session && !m_session->hasKek()) {
                QString secretError;
                if (!openSecretSession(&secretSession, &secretError)) {
                    if (error) {
                        *error = secretError.isEmpty()
                            ? tr("Secret access was canceled.")
                            : secretError;
                    }
                    return false;
                }
            }
            if (!wasTopSecret && data.classification != QLatin1String("T"))
                return true;
            return authorizeTopSecret(&saveKek, error);
        });
    if (dialog.exec() != QDialog::Accepted)
        return;

    std::string error;
    data = dialog.data();
    const bool desiredTopSecret = data.classification == QLatin1String("T");
    const bool desiredSecret = data.classification == QLatin1String("S");
    QByteArray metaJson = passwordMeta(data);
    QByteArray payloadJson = passwordPayload(data);

    ItemUpdate update;
    update.title = data.title.toStdString();
    update.classification = desiredTopSecret ? "T" : "S";
    update.meta = metaJson.toStdString();
    update.payload = payloadJson.toStdString();

    ItemRepository &repository =
        (desiredSecret && secretSession) ? secretSession->items()
                                         : m_session->items();
    const bool updated =
        (wasTopSecret || desiredTopSecret)
        ? repository.update(id.toStdString(), update, saveKek.span(), &error)
        : repository.update(id.toStdString(), update, &error);
    saveKek.clear();
    secretSession.reset();

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
    if (!m_session)
        return;

    const QString id = selectedId();
    const ItemRow *row = id.isEmpty() ? nullptr : rowForId(id);
    if (!row || row->type != QLatin1String(kNoteType))
        return;

    const bool wasTopSecret = row->classification == QLatin1String("T");
    const bool wasSecret = row->classification == QLatin1String("S");
    NoteEditorDialog::Data data;
    data.title = row->title;
    if (wasTopSecret)
        data.classification = QStringLiteral("T");
    else if (row->classification == QLatin1String("S"))
        data.classification = QStringLiteral("S");
    else
        data.classification = QStringLiteral("C");

    NoteEditorDialog::ContentLoader loader;
    if (wasTopSecret) {
        loader = [this, id](QString *body, QString *error) {
            cryptowl::crypto::ProtectedValue topSecretKek;
            if (!authorizeTopSecret(&topSecretKek, error))
                return false;
            ItemRecord record;
            std::string recordError;
            if (!m_session->items().get(id.toStdString(), topSecretKek.span(),
                                        &record, &recordError)) {
                if (error)
                    *error = QString::fromStdString(recordError);
                return false;
            }
            *body = QString::fromStdString(record.payload);
            wipe(record.payload);
            return true;
        };
    } else if (row->classification == QLatin1String("S")) {
        loader = [this, id](QString *body, QString *error) {
            std::string recordError;
            const bool ok = withSecretItems(
                [this, id, body](ItemRepository &repository,
                                 std::string *innerError) {
                    ItemRecord record;
                    if (!repository.get(id.toStdString(), &record, innerError))
                        return false;
                    *body = QString::fromStdString(record.payload);
                    wipe(record.payload);
                    return true;
                },
                &recordError);
            if (!ok && error)
                *error = QString::fromStdString(recordError);
            return ok;
        };
    } else {
        ItemRecord record;
        std::string recordError;
        if (!m_session->items().get(id.toStdString(), &record, &recordError)) {
            QMessageBox::critical(this, tr("Could not read note"),
                                  QString::fromStdString(recordError));
            return;
        }
        data.body = QString::fromStdString(record.payload);
        wipe(record.payload);
    }

    NoteEditorDialog dialog(data, std::move(loader), this);
    dialog.setTopSecretAvailable(topSecretConfigured());
    cryptowl::crypto::ProtectedValue saveKek;
    std::unique_ptr<cryptowl::vault::VaultSession> secretSession;
    dialog.setSaveAuthorizer(
        [this, wasTopSecret, wasSecret, &saveKek,
         &secretSession](const NoteEditorDialog::Data &data, QString *error) {
            const bool needsSecretAccess =
                wasSecret || data.classification == QLatin1String("S");
            if (needsSecretAccess && m_session && !m_session->hasKek()) {
                QString secretError;
                if (!openSecretSession(&secretSession, &secretError)) {
                    if (error) {
                        *error = secretError.isEmpty()
                            ? tr("Secret access was canceled.")
                            : secretError;
                    }
                    return false;
                }
            }
            if (!wasTopSecret && data.classification != QLatin1String("T"))
                return true;
            return authorizeTopSecret(&saveKek, error);
        });
    wipe(data.body);
    if (dialog.exec() != QDialog::Accepted)
        return;

    std::string error;
    data = dialog.data();
    if (data.classification != QLatin1String("S")
        && data.classification != QLatin1String("T")) {
        data.classification = QStringLiteral("C");
    }
    const bool desiredTopSecret = data.classification == QLatin1String("T");
    const bool desiredSecret = data.classification == QLatin1String("S");

    ItemUpdate update;
    update.title = data.title.toStdString();
    update.classification = data.classification.toStdString();
    update.meta = "{}";
    update.payload = data.body.toStdString();

    ItemRepository &repository =
        (desiredSecret && secretSession) ? secretSession->items()
                                         : m_session->items();
    const bool updated =
        (wasTopSecret || desiredTopSecret)
        ? repository.update(id.toStdString(), update, saveKek.span(), &error)
        : repository.update(id.toStdString(), update, &error);
    saveKek.clear();
    secretSession.reset();

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
