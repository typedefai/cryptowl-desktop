#pragma once

#include <QList>
#include <QString>
#include <QWidget>

#include <memory>

class QAbstractItemView;
class QListWidget;
class QPoint;
class QStackedWidget;
class QTextBrowser;
class QTreeWidget;

namespace cryptowl::vault {
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
    void editSelectedEntry();
    void deleteSelectedEntry();
    void copySelectedUsername();

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
    void editSelectedPassword();
    void editSelectedNote();
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
