#pragma once

#include "crypto/ProtectedValue.h"
#include "vault/VaultDatabase.h"

#include <memory>
#include <string>

namespace cryptowl::vault {

class ItemRepository;

class VaultSession
{
public:
    static std::unique_ptr<VaultSession> open(const std::string &databasePath,
                                              crypto::ProtectedValue vaultKey,
                                              crypto::ProtectedValue smk,
                                              std::string *error = nullptr);

    ~VaultSession();
    VaultSession(const VaultSession &) = delete;
    VaultSession &operator=(const VaultSession &) = delete;

    ItemRepository &items();
    const ItemRepository &items() const;

    sqlite3 *handle() const
    {
        return m_database.handle();
    }

private:
    VaultSession() = default;

    VaultDatabase m_database;
    crypto::ProtectedValue m_vaultKey;
    crypto::ProtectedValue m_kek;
    std::unique_ptr<ItemRepository> m_items;
};

} // namespace cryptowl::vault
