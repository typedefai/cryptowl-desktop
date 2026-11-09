#pragma once

#include <QString>
#include <QStringList>

#include <vector>

enum class DiffLineKind
{
    Equal,
    Added,
    Removed,
};

struct DiffLine
{
    DiffLineKind kind = DiffLineKind::Equal;
    QString text;
};

// Line-based LCS diff. Returns false for inputs too large to diff safely.
bool diffLines(const QStringList &before, const QStringList &after,
               std::vector<DiffLine> *lines);
