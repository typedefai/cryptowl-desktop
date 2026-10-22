#pragma once

#include <QString>
#include <QStringList>

class RecentVaultsStore
{
public:
    static constexpr int kMaxEntries = 10;

    QStringList paths() const;
    void add(const QString &path);
    void remove(const QString &path);
};
