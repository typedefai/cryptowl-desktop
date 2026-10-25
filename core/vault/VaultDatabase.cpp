#include "vault/VaultDatabase.h"

#include "crypto/Bytes.h"
#include "vault/Schema.h"

#include <sqlite3.h>

#include <cstdlib>
#include <filesystem>
#include <string>
#include <utility>

extern "C" char *sqlcipher_version(void);

namespace cryptowl::vault {

namespace {

void setError(std::string *error, const char *message)
{
    if (error)
        *error = message ? message : "database error";
}

std::string rawKeyPragma(std::span<const std::uint8_t> vaultKey)
{
    return "PRAGMA key = \"x'" + cryptowl::crypto::toHex(vaultKey) + "'\";";
}

std::filesystem::path pathFromUtf8(const std::string &path)
{
    return std::filesystem::path(std::u8string(
        reinterpret_cast<const char8_t *>(path.data()), path.size()));
}

bool prepareKey(sqlite3 *handle, std::span<const std::uint8_t> vaultKey,
                std::string *error)
{
    if (vaultKey.size() != 32) {
        setError(error, "vault key must be 32 bytes");
        return false;
    }

    const std::string pragma = rawKeyPragma(vaultKey);
    char *message = nullptr;
    const int rc = sqlite3_exec(handle, pragma.c_str(), nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        setError(error, message ? message : sqlite3_errmsg(handle));
        sqlite3_free(message);
        return false;
    }
    return true;
}

bool hasSchema(sqlite3 *db, std::string *error)
{
    static constexpr const char *kSql =
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN "
        "('t_wrapped_key','t_data_encrypt_key','t_encrypted_data','t_item',"
        "'t_file','t_item_version');";

    int count = 0;
    char *message = nullptr;
    const int rc = sqlite3_exec(
        db, kSql,
        [](void *context, int, char **values, char **) {
            if (values && values[0])
                *static_cast<int *>(context) = std::atoi(values[0]);
            return 0;
        },
        &count, &message);

    if (rc != SQLITE_OK) {
        setError(error, message ? message : sqlite3_errmsg(db));
        sqlite3_free(message);
        return false;
    }
    if (count != 6) {
        setError(error, "vault database schema is incomplete");
        return false;
    }
    return true;
}

} // namespace

VaultDatabase::~VaultDatabase()
{
    close();
}

VaultDatabase::VaultDatabase(VaultDatabase &&other) noexcept
    : m_handle(std::exchange(other.m_handle, nullptr))
{
}

VaultDatabase &VaultDatabase::operator=(VaultDatabase &&other) noexcept
{
    if (this != &other) {
        close();
        m_handle = std::exchange(other.m_handle, nullptr);
    }
    return *this;
}

void VaultDatabase::close()
{
    if (m_handle) {
        sqlite3_close(m_handle);
        m_handle = nullptr;
    }
}

bool VaultDatabase::openWithFlags(const std::string &path, int flags,
                                  std::span<const std::uint8_t> vaultKey,
                                  std::string *error)
{
    close();

    const int rc = sqlite3_open_v2(path.c_str(), &m_handle, flags, nullptr);
    if (rc != SQLITE_OK) {
        setError(error, m_handle ? sqlite3_errmsg(m_handle)
                                 : "could not open database");
        close();
        return false;
    }
    if (!prepareKey(m_handle, vaultKey, error)) {
        close();
        return false;
    }
    sqlite3_busy_timeout(m_handle, 5000);
    return true;
}

bool VaultDatabase::execute(const std::string &sql, std::string *error)
{
    char *message = nullptr;
    const int rc = sqlite3_exec(m_handle, sql.c_str(), nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        setError(error, message ? message : sqlite3_errmsg(m_handle));
        sqlite3_free(message);
        return false;
    }
    return true;
}

bool VaultDatabase::open(const std::string &path,
                         std::span<const std::uint8_t> vaultKey,
                         std::string *error)
{
    if (!openWithFlags(path, SQLITE_OPEN_READWRITE, vaultKey, error))
        return false;

    if (!execute("PRAGMA foreign_keys = ON;", error)
        || !execute("PRAGMA secure_delete = ON;", error)
        || !hasSchema(m_handle, error)) {
        close();
        return false;
    }
    return true;
}

bool VaultDatabase::create(const std::string &path,
                           std::span<const std::uint8_t> vaultKey,
                           std::string *error)
{
    std::error_code ec;
    const std::filesystem::path fsPath = pathFromUtf8(path);
    if (std::filesystem::exists(fsPath, ec)) {
        setError(error, "vault database already exists");
        return false;
    }

    VaultDatabase db;
    if (!db.openWithFlags(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                          vaultKey, error)) {
        std::filesystem::remove(fsPath, ec);
        return false;
    }
    if (!db.execute("PRAGMA foreign_keys = ON;", error)
        || !db.execute("PRAGMA secure_delete = ON;", error)
        || !db.execute(std::string(schemaSql()), error)
        || !hasSchema(db.handle(), error)) {
        db.close();
        std::filesystem::remove(fsPath, ec);
        return false;
    }
    return true;
}

bool VaultDatabase::verify(const std::string &path,
                           std::span<const std::uint8_t> vaultKey,
                           std::string *error)
{
    VaultDatabase db;
    if (!db.openWithFlags(path, SQLITE_OPEN_READONLY, vaultKey, error))
        return false;
    return hasSchema(db.handle(), error);
}

std::string VaultDatabase::cipherVersion()
{
    const char *version = sqlcipher_version();
    return version ? version : std::string();
}

} // namespace cryptowl::vault
