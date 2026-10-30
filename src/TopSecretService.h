#pragma once

#include "crypto/ProtectedValue.h"

#include <QString>

#include <cstdint>
#include <span>

struct sqlite3;

class TopSecretService
{
public:
    TopSecretService(QString vaultPath, sqlite3 *database);

    bool isConfigured(QString *error = nullptr) const;
    bool setup(std::span<const std::uint8_t> smk,
               std::span<const std::uint8_t> secondaryPassword,
               QString *error = nullptr);
    bool unlock(std::span<const std::uint8_t> secondaryPassword,
                cryptowl::crypto::ProtectedValue *topSecretKek,
                QString *error = nullptr) const;

private:
    QString m_vaultPath;
    sqlite3 *m_database = nullptr;
};
