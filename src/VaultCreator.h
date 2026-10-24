#pragma once

#include <QString>

#include <cstdint>
#include <functional>
#include <span>

class VaultCreator
{
public:
    struct Result
    {
        bool ok = false;
        QString error;
        QString vaultId;
    };

    using SecretWriter = std::function<bool(
        const QString &vaultId, std::span<const std::uint8_t> argon2Salt,
        std::span<const std::uint8_t> deviceSecret, QString *error)>;

    static Result create(const QString &vaultPath, const QString &password,
                         const SecretWriter &secretWriter = {});
};
