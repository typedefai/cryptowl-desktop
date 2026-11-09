#include "MediaMountManager.h"

#include "vfs/FuseMount.h"
#include "vault/VaultSession.h"
#include "vault/VirtualMediaFs.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

#include <filesystem>
#include <system_error>

MediaMountManager::MediaMountManager() = default;

MediaMountManager::~MediaMountManager()
{
    unmount();
}

bool MediaMountManager::isAvailable()
{
    return FuseMount::isAvailable();
}

bool MediaMountManager::mount(
    const QString &vaultPath,
    const std::shared_ptr<cryptowl::vault::VaultSession> &session,
    QString *error)
{
    if (!session) {
        if (error)
            *error = QStringLiteral("The vault is not unlocked.");
        return false;
    }
    if (isMounted() && hasVault(vaultPath)) {
        if (error)
            *error = QStringLiteral("The media drive is already mounted at %1.")
                         .arg(m_mountPoint);
        return false;
    }
    if (isMounted()) {
        QString unmountError;
        if (!unmount(&unmountError)) {
            if (error)
                *error = unmountError;
            return false;
        }
    }

    if (!FuseMount::isAvailable()) {
        if (error)
            *error = QStringLiteral(
                "Native FUSE support is not available in this build or no "
                "FUSE driver is installed.");
        return false;
    }

    const QString vaultName = QFileInfo(vaultPath).fileName();
    const QString hash = QString::fromLatin1(
        QCryptographicHash::hash(vaultPath.toUtf8(), QCryptographicHash::Sha256)
            .toHex()
            .left(8));
    const QString mountRoot = QDir(
        QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation))
                                  .filePath(QStringLiteral("mounts"));
    const QString mountPoint = QDir(mountRoot)
                                   .filePath(QStringLiteral("%1-%2")
                                                 .arg(vaultName.isEmpty()
                                                          ? QStringLiteral("vault")
                                                          : vaultName,
                                                      hash));
    if (!QDir().mkpath(mountPoint)) {
        if (error)
            *error = QStringLiteral("Could not create the mount directory: %1")
                         .arg(mountPoint);
        return false;
    }
#ifndef _WIN32
    std::error_code ec;
    std::filesystem::permissions(
        mountPoint.toStdString(), std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, ec);
#endif

    auto fs = std::make_unique<cryptowl::vault::VirtualMediaFs>(*session);
    std::string fsError;
    fs->refresh(&fsError);
    if (!fsError.empty()) {
        QDir().rmdir(mountPoint);
        if (error)
            *error = QString::fromStdString(fsError);
        return false;
    }

    auto fuse = std::make_unique<FuseMount>();
    QString mountError;
    if (!fuse->mount(mountPoint, fs.get(), &mountError)) {
        QDir().rmdir(mountPoint);
        if (error)
            *error = mountError;
        return false;
    }

    m_session = session;
    m_fs = std::move(fs);
    m_fuse = std::move(fuse);
    m_vaultPath = vaultPath;
    m_mountPoint = mountPoint;
    return true;
}

bool MediaMountManager::unmount(QString *error)
{
    if (m_fuse) {
        QString unmountError;
        if (!m_fuse->unmount(&unmountError)) {
            if (error)
                *error = unmountError;
            return false;
        }
    }
    m_fuse.reset();
    m_fs.reset();
    m_session.reset();
    if (!m_mountPoint.isEmpty())
        QDir().rmdir(m_mountPoint);
    m_mountPoint.clear();
    m_vaultPath.clear();
    return true;
}

bool MediaMountManager::isMounted() const
{
    return m_fuse && m_fuse->isMounted();
}

bool MediaMountManager::hasVault(const QString &vaultPath) const
{
    return isMounted() && m_vaultPath == vaultPath;
}

QString MediaMountManager::mountPoint() const
{
    return m_mountPoint;
}
