#pragma once

#include <QString>

#include <memory>

namespace cryptowl::vault {
class VaultSession;
class VirtualMediaFs;
}

class FuseMount;

class MediaMountManager
{
public:
    MediaMountManager();
    ~MediaMountManager();

    MediaMountManager(const MediaMountManager &) = delete;
    MediaMountManager &operator=(const MediaMountManager &) = delete;

    static bool isAvailable();

    bool mount(const QString &vaultPath,
               const std::shared_ptr<cryptowl::vault::VaultSession> &session,
               QString *error = nullptr);
    bool unmount(QString *error = nullptr);
    bool isMounted() const;
    bool hasVault(const QString &vaultPath) const;
    QString mountPoint() const;

private:
    std::shared_ptr<cryptowl::vault::VaultSession> m_session;
    std::unique_ptr<cryptowl::vault::VirtualMediaFs> m_fs;
    std::unique_ptr<FuseMount> m_fuse;
    QString m_vaultPath;
    QString m_mountPoint;
};
