#pragma once

#include <QList>
#include <QString>
#include <QWidget>

#include <functional>
#include <memory>
#include <string>

class QAbstractItemView;
class QListWidget;
class QPoint;
class QStackedWidget;
class QTextBrowser;
class QTreeWidget;

namespace cryptowl::crypto {
class ProtectedValue;
}

namespace cryptowl::vault {
struct ItemRecord;
class ItemRepository;
class VaultSession;
}

class VaultView : public QWidget
{
    Q_OBJECT

public:
    explicit VaultView(
        QString vaultPath,
        std::shared_ptr<cryptowl::vault::VaultSession> session,
        QWidget *parent = nullptr);

    QString vaultPath() const;

    void setFilter(const QString &filter);
    void showDetails();
    void showIcons();
    void addEntry();
    void addNote();
    void importPhoto();
    void importVideo();
    void viewSelectedEntry();
    void editSelectedEntry();
    void deleteSelectedEntry();
    void copySelectedUsername();
    void setupTopSecret();

signals:
    void statusMessage(const QString &message);

private:
    struct ItemRow
    {
        QString id;
        QString type;
        QString title;
        QString username;
        QString url;
        QString classification;
        QString meta;
        qint64 updatedAt = 0;
    };

    QWidget *createStructurePane();
    QWidget *createContentPane();
    void reload(const QString &selectId = QString());
    void refreshLists(const QString &selectId = QString());
    void selectTypeFilter(const QString &type);
    void updateInfo();
    void updateGroupCounts();
    void showContextMenu(QAbstractItemView *view, const QPoint &pos);
    void viewSelectedPassword();
    void viewSelectedPhoto();
    void viewSelectedVideo();
    void editSelectedPassword();
    void editSelectedNote();
    bool importMedia(bool video);
    bool readPasswordItem(const QString &id, const QString &classification,
                          cryptowl::vault::ItemRecord *record, QString *error);
    bool openSecretSession(
        std::unique_ptr<cryptowl::vault::VaultSession> *session,
        QString *error);
    bool withSecretItems(
        const std::function<bool(cryptowl::vault::ItemRepository &,
                                 std::string *)> &operation,
        std::string *error);
    bool topSecretConfigured() const;
    bool authorizeTopSecret(cryptowl::crypto::ProtectedValue *topSecretKek,
                            QString *error);
    QString selectedId() const;
    void selectItem(const QString &id);
    const ItemRow *rowForId(const QString &id) const;
    QString typeLabel(const ItemRow &row) const;
    QString summaryText(const ItemRow &row) const;
    QString classificationLabel(const QString &classification) const;

    QString m_vaultPath;
    std::shared_ptr<cryptowl::vault::VaultSession> m_session;
    QList<ItemRow> m_rows;
    QString m_currentType;
    QString m_filter;
    QString m_loadError;
    QTreeWidget *m_structure = nullptr;
    QStackedWidget *m_contentStack = nullptr;
    QTreeWidget *m_details = nullptr;
    QListWidget *m_icons = nullptr;
    QTextBrowser *m_info = nullptr;
};
