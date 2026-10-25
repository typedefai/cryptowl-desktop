#pragma once

#include "crypto/ProtectedValue.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace cryptowl::vault {

class VaultDatabase;

struct ItemSummary
{
    std::string id;
    std::string type;
    std::string title;
    std::string classification;
    std::string meta;
    std::int64_t updatedAt = 0;
    bool pinned = false;
};

struct ItemRecord
{
    std::string id;
    std::string type;
    std::string title;
    std::string classification;
    std::string parentId;
    std::string meta;
    std::string payload;
    std::int64_t createdAt = 0;
    std::int64_t updatedAt = 0;
};

struct NewItem
{
    std::string type;
    std::string classification;
    std::string title;
    std::string meta;
    std::string payload;
    std::string parentId;
};

struct ItemUpdate
{
    std::string title;
    std::string meta;
    std::string payload;
};

class ItemRepository
{
public:
    ItemRepository(VaultDatabase &database, std::span<const std::uint8_t> kek,
                   std::span<const std::uint8_t> vaultKey);

    bool list(const std::string &type, std::vector<ItemSummary> *items,
              std::string *error = nullptr) const;
    bool get(const std::string &id, ItemRecord *item,
             std::string *error = nullptr) const;
    bool create(const NewItem &item, std::string *id,
                std::string *error = nullptr);
    bool update(const std::string &id, const ItemUpdate &item,
                std::string *error = nullptr);
    bool softDelete(const std::string &id, std::string *error = nullptr);

private:
    VaultDatabase &m_database;
    std::span<const std::uint8_t> m_kek;
    crypto::ProtectedValue m_hfk;
};

} // namespace cryptowl::vault
