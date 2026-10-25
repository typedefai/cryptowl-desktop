#pragma once

#include <QList>
#include <QPair>
#include <QString>
#include <QWidget>

#include <optional>

class QAbstractItemView;
class QListWidget;
class QPoint;
class QStackedWidget;
class QTextBrowser;
class QTreeWidget;

class VaultView : public QWidget
{
    Q_OBJECT

public:
    explicit VaultView(QString vaultPath, QWidget *parent = nullptr);

    QString vaultPath() const;

    void setFilter(const QString &filter);
    void showDetails();
    void showIcons();
    void addEntry();
    void editSelectedEntry();
    void deleteSelectedEntry();
    void copySelectedPassword();
    void copySelectedUsername();

signals:
    void statusMessage(const QString &message);

private:
    struct Entry
    {
        QString title;
        QString username;
        QString password;
        QString url;
        QString notes;
        QString modified;
    };

    struct Group
    {
        QString name;
        QList<Entry> entries;
    };

    QWidget *createStructurePane();
    QWidget *createContentPane();
    void populateMockData();
    void refreshLists();
    void updateInfo();
    void showContextMenu(QAbstractItemView *view, const QPoint &pos);
    void selectEntry(int groupIndex, int entryIndex);
    std::optional<QPair<int, int>> selectedEntry() const;

    QString m_vaultPath;
    QString m_filter;
    int m_currentGroup = -1;
    QList<Group> m_groups;
    QTreeWidget *m_structure = nullptr;
    QStackedWidget *m_contentStack = nullptr;
    QTreeWidget *m_details = nullptr;
    QListWidget *m_icons = nullptr;
    QTextBrowser *m_info = nullptr;
};
