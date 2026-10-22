#include "RecentVaultsStore.h"

#include <QDir>
#include <QFileInfo>
#include <QSettings>

namespace {

const QString kRecentVaultsKey = QStringLiteral("welcome/recentVaults");

QString normalizedPath(const QString &path)
{
    const QFileInfo info(path);
    const QString canonical = info.canonicalFilePath();
    return canonical.isEmpty() ? QDir::cleanPath(info.absoluteFilePath()) : canonical;
}

} // namespace

QStringList RecentVaultsStore::paths() const
{
    QSettings settings;
    return settings.value(kRecentVaultsKey).toStringList();
}

void RecentVaultsStore::add(const QString &path)
{
    const QString normalized = normalizedPath(path);
    if (normalized.isEmpty())
        return;

    QStringList list = paths();
    list.removeAll(normalized);
    list.prepend(normalized);
    while (list.size() > kMaxEntries)
        list.removeLast();

    QSettings settings;
    settings.setValue(kRecentVaultsKey, list);
}

void RecentVaultsStore::remove(const QString &path)
{
    QStringList list = paths();
    if (list.removeAll(normalizedPath(path)) == 0)
        return;

    QSettings settings;
    settings.setValue(kRecentVaultsKey, list);
}
