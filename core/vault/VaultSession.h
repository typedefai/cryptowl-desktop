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
    // With rememberKek=false the KEK is neither unwrapped nor cached; S-tier
    // operations must use a temporary session opened for that access. The
    // master password / SMK is never retained by the session.
    static std::unique_ptr<VaultSession> open(const std::string &databasePath,
                                              crypto::ProtectedValue vaultKey,
                                              crypto::ProtectedValue smk,
                                              std::string *error = nullptr,
                                              bool rememberKek = false);

    ~VaultSession();
    VaultSession(const VaultSession &) = delete;
    VaultSession &operator=(const VaultSession &) = delete;

    ItemRepository &items();
    const ItemRepository &items() const;

    bool hasKek() const
    {
        return !m_kek.empty();
    }

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
