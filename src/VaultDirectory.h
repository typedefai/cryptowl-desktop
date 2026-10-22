#pragma once

#include <QDir>
#include <QFileInfo>
#include <QString>

inline bool isVaultDirectory(const QString &path)
{
    const QFileInfo directory(path);
    return directory.isDir()
        && QFileInfo(QDir(directory.filePath()).filePath(QStringLiteral("vault.meta"))).isFile();
}
