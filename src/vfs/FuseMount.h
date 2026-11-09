#pragma once

#include <QString>

#include <memory>

namespace cryptowl::vault {
class VirtualMediaFs;
}

class FuseMount
{
public:
    FuseMount();
    ~FuseMount();

    FuseMount(const FuseMount &) = delete;
    FuseMount &operator=(const FuseMount &) = delete;

    static bool isAvailable();

    bool mount(const QString &mountPoint, cryptowl::vault::VirtualMediaFs *fs,
               QString *error = nullptr);
    bool unmount(QString *error = nullptr);
    bool isMounted() const;
    QString mountPoint() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
