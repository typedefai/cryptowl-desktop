#pragma once

#include "crypto/ProtectedValue.h"

#include <QString>

#include <cstdint>

class VaultUnlocker
{
public:
    struct Result
    {
        bool ok = false;
        QString error;
        QString warning;
        std::uint64_t embedMaxBytes = 512 * 1024;
        cryptowl::crypto::ProtectedValue vaultKey;
        cryptowl::crypto::ProtectedValue smk;
    };

    static Result unlock(const QString &vaultPath, const QString &password,
                         bool migrateDeviceSecret = true);
};
