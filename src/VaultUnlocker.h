#pragma once

#include "crypto/ProtectedValue.h"

#include <QString>

class VaultUnlocker
{
public:
    struct Result
    {
        bool ok = false;
        QString error;
        QString warning;
        cryptowl::crypto::ProtectedValue vaultKey;
    };

    static Result unlock(const QString &vaultPath, const QString &password,
                         bool migrateDeviceSecret = true);
};
