#pragma once

#include <cstdint>
#include <span>
#include <string>

struct sqlite3;

namespace cryptowl::vault {

class VaultDatabase
{
public:
    VaultDatabase() = default;
    ~VaultDatabase();

    VaultDatabase(const VaultDatabase &) = delete;
    VaultDatabase &operator=(const VaultDatabase &) = delete;
    VaultDatabase(VaultDatabase &&other) noexcept;
    VaultDatabase &operator=(VaultDatabase &&other) noexcept;

    bool open(const std::string &path, std::span<const std::uint8_t> vaultKey,
              std::string *error = nullptr);
    void close();

    sqlite3 *handle() const
    {
        return m_handle;
    }

    static bool create(const std::string &path, std::span<const std::uint8_t> vaultKey,
                       std::string *error = nullptr);
    static bool verify(const std::string &path, std::span<const std::uint8_t> vaultKey,
                       std::string *error = nullptr);
    static std::string cipherVersion();

private:
    bool openWithFlags(const std::string &path, int flags,
                       std::span<const std::uint8_t> vaultKey, std::string *error);
    bool execute(const std::string &sql, std::string *error);

    sqlite3 *m_handle = nullptr;
};

} // namespace cryptowl::vault
