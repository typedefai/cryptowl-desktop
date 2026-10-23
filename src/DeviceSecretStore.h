#pragma once

#include "crypto/ProtectedValue.h"

#include <QString>

#include <span>

class DeviceSecretStore
{
public:
    struct LoadResult
    {
        bool ok = false;
        bool fromLegacy = false;
        QString error;
        cryptowl::crypto::ProtectedValue secret;
    };

    static bool isAvailable();
    static LoadResult load(const QString &vaultPath, const QString &vaultId,
                           std::span<const std::uint8_t> argon2Salt);
    static bool store(const QString &vaultId, std::span<const std::uint8_t> argon2Salt,
                      std::span<const std::uint8_t> secret, QString *error = nullptr);
    static bool removeLegacyFile(const QString &vaultPath, QString *error = nullptr);
    static bool remove(const QString &vaultId, std::span<const std::uint8_t> argon2Salt,
                       QString *error = nullptr);
};
