#include "vault/VaultSession.h"

#include "crypto/AesGcm.h"
#include "crypto/Bytes.h"
#include "crypto/Random.h"
#include "vault/ItemRepository.h"

#include <sqlite3.h>

#include <chrono>
#include <exception>
#include <string>
#include <utility>

namespace cryptowl::vault {

namespace {

using cryptowl::crypto::Bytes;
using cryptowl::crypto::GcmCiphertext;
using cryptowl::crypto::ProtectedValue;

constexpr const char *kKekId = "kek:smk";

void setError(std::string *error, const char *message)
{
    if (error)
        *error = message ? message : "vault session error";
}

void setDatabaseError(std::string *error, sqlite3 *db)
{
    setError(error, db ? sqlite3_errmsg(db) : "database is not open");
}

std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

class Statement
{
public:
    Statement(sqlite3 *db, const char *sql, std::string *error)
        : m_db(db)
    {
        if (sqlite3_prepare_v2(db, sql, -1, &m_statement, nullptr) != SQLITE_OK) {
            setDatabaseError(error, db);
            m_statement = nullptr;
        }
    }

    ~Statement()
    {
        if (m_statement)
            sqlite3_finalize(m_statement);
    }

    Statement(const Statement &) = delete;
    Statement &operator=(const Statement &) = delete;

    bool ok() const
    {
        return m_statement != nullptr;
    }

    sqlite3_stmt *get() const
    {
        return m_statement;
    }

    int step(std::string *error) const
    {
        const int rc = sqlite3_step(m_statement);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            setDatabaseError(error, m_db);
            return rc;
        }
        return rc;
    }

private:
    sqlite3 *m_db = nullptr;
    sqlite3_stmt *m_statement = nullptr;
};

bool bindText(sqlite3_stmt *statement, int index, const std::string &value,
              std::string *error)
{
    if (sqlite3_bind_text(statement, index, value.data(),
                          static_cast<int>(value.size()), SQLITE_TRANSIENT)
        != SQLITE_OK) {
        setDatabaseError(error, sqlite3_db_handle(statement));
        return false;
    }
    return true;
}

bool bindBlob(sqlite3_stmt *statement, int index,
              std::span<const std::uint8_t> value, std::string *error)
{
    const void *data = value.empty() ? static_cast<const void *>("")
                                     : static_cast<const void *>(value.data());
    if (sqlite3_bind_blob(statement, index, data, static_cast<int>(value.size()),
                          SQLITE_TRANSIENT)
        != SQLITE_OK) {
        setDatabaseError(error, sqlite3_db_handle(statement));
        return false;
    }
    return true;
}

Bytes columnBytes(sqlite3_stmt *statement, int index)
{
    const void *data = sqlite3_column_blob(statement, index);
    const int size = sqlite3_column_bytes(statement, index);
    if (!data || size <= 0)
        return {};
    return Bytes(static_cast<const std::uint8_t *>(data),
                 static_cast<const std::uint8_t *>(data) + size);
}

std::string columnText(sqlite3_stmt *statement, int index)
{
    const unsigned char *text = sqlite3_column_text(statement, index);
    if (!text)
        return {};
    const int size = sqlite3_column_bytes(statement, index);
    return std::string(reinterpret_cast<const char *>(text),
                       static_cast<std::size_t>(size));
}

bool storeKek(VaultDatabase &database, std::span<const std::uint8_t> smk,
              ProtectedValue *kek, std::string *error)
{
    const auto wrappingKey = smk.first(32);
    const Bytes nonce = cryptowl::crypto::randomBytes(12);
    GcmCiphertext wrapped;
    try {
        wrapped = cryptowl::crypto::aesGcmEncrypt(
            wrappingKey, nonce, cryptowl::crypto::bytesOf(kKekId), kek->span(),
            "kek.wrap.smk");
    } catch (const std::exception &) {
        setError(error, "could not wrap the vault key encryption key");
        return false;
    }

    static constexpr const char *kInsertSql =
        "INSERT INTO t_wrapped_key "
        "(id, role, wrapper, algorithm, ciphertext, nonce, auth_tag, "
        " created_at, updated_at) "
        "VALUES (?, 'kek', 'smk', 'AES-256-GCM', ?, ?, ?, ?, ?);";
    static constexpr const char *kUpdateSql =
        "UPDATE t_wrapped_key SET role = 'kek', wrapper = 'smk', "
        "algorithm = 'AES-256-GCM', ciphertext = ?, nonce = ?, auth_tag = ?, "
        "updated_at = ?, deleted_at = NULL WHERE id = ?;";

    const std::int64_t timestamp = nowMillis();

    {
        Statement existing(database.handle(),
                           "SELECT id FROM t_wrapped_key WHERE id = ?;", error);
        if (!existing.ok()
            || !bindText(existing.get(), 1, std::string(kKekId), error))
            return false;
        const int rc = existing.step(error);
        if (rc == SQLITE_ROW) {
            Statement update(database.handle(), kUpdateSql, error);
            if (!update.ok()
                || !bindBlob(update.get(), 1, wrapped.ciphertext, error)
                || !bindBlob(update.get(), 2, nonce, error)
                || !bindBlob(update.get(), 3, wrapped.tag, error)
                || sqlite3_bind_int64(update.get(), 4, timestamp) != SQLITE_OK
                || !bindText(update.get(), 5, std::string(kKekId), error)
                || update.step(error) != SQLITE_DONE) {
                return false;
            }
            return true;
        }
        if (rc != SQLITE_DONE)
            return false;
    }

    Statement insert(database.handle(), kInsertSql, error);
    if (!insert.ok() || !bindText(insert.get(), 1, std::string(kKekId), error)
        || !bindBlob(insert.get(), 2, wrapped.ciphertext, error)
        || !bindBlob(insert.get(), 3, nonce, error)
        || !bindBlob(insert.get(), 4, wrapped.tag, error)
        || sqlite3_bind_int64(insert.get(), 5, timestamp) != SQLITE_OK
        || sqlite3_bind_int64(insert.get(), 6, timestamp) != SQLITE_OK
        || insert.step(error) != SQLITE_DONE) {
        return false;
    }
    return true;
}

bool loadOrCreateKek(VaultDatabase &database, std::span<const std::uint8_t> smk,
                     ProtectedValue *kek, std::string *error)
{
    if (smk.size() != 64) {
        setError(error, "invalid stretched master key");
        return false;
    }
    if (!database.handle()) {
        setError(error, "database is not open");
        return false;
    }

    static constexpr const char *kSql =
        "SELECT role, wrapper, algorithm, ciphertext, nonce, auth_tag, deleted_at "
        "FROM t_wrapped_key WHERE id = ?;";
    std::string role;
    std::string wrapper;
    std::string algorithm;
    Bytes ciphertext;
    Bytes nonce;
    Bytes tag;
    bool present = false;
    bool deleted = false;

    {
        Statement statement(database.handle(), kSql, error);
        if (!statement.ok() || !bindText(statement.get(), 1, std::string(kKekId), error))
            return false;
        const int rc = statement.step(error);
        if (rc == SQLITE_ROW) {
            present = true;
            role = columnText(statement.get(), 0);
            wrapper = columnText(statement.get(), 1);
            algorithm = columnText(statement.get(), 2);
            ciphertext = columnBytes(statement.get(), 3);
            nonce = columnBytes(statement.get(), 4);
            tag = columnBytes(statement.get(), 5);
            deleted = sqlite3_column_type(statement.get(), 6) != SQLITE_NULL;
        } else if (rc != SQLITE_DONE) {
            return false;
        }
    }

    if (present && !deleted) {
        if (role != "kek" || wrapper != "smk" || algorithm != "AES-256-GCM"
            || ciphertext.size() != 32 || nonce.size() != 12 || tag.size() != 16) {
            setError(error, "invalid wrapped key encryption key");
            return false;
        }
        try {
            Bytes plaintext = cryptowl::crypto::aesGcmDecrypt(
                smk.first(32), nonce, cryptowl::crypto::bytesOf(kKekId), ciphertext,
                tag, "kek.unwrap.smk");
            if (plaintext.size() != 32) {
                cryptowl::crypto::secureWipe(plaintext);
                setError(error, "invalid key encryption key");
                return false;
            }
            *kek = ProtectedValue(std::move(plaintext));
            return true;
        } catch (const std::exception &) {
            setError(error, "could not unwrap the vault key encryption key");
            return false;
        }
    }

    *kek = ProtectedValue(cryptowl::crypto::randomBytes(32));
    return storeKek(database, smk, kek, error);
}

} // namespace

VaultSession::~VaultSession() = default;

std::unique_ptr<VaultSession> VaultSession::open(const std::string &databasePath,
                                                 ProtectedValue vaultKey,
                                                 ProtectedValue smk,
                                                 std::string *error)
{
    if (vaultKey.size() != 32) {
        setError(error, "vault key must be 32 bytes");
        return nullptr;
    }
    if (smk.size() != 64) {
        setError(error, "stretched master key must be 64 bytes");
        return nullptr;
    }

    auto session = std::unique_ptr<VaultSession>(new VaultSession());
    if (!session->m_database.open(databasePath, vaultKey.span(), error))
        return nullptr;

    ProtectedValue kek;
    if (!loadOrCreateKek(session->m_database, smk.span(), &kek, error))
        return nullptr;

    session->m_vaultKey = std::move(vaultKey);
    session->m_kek = std::move(kek);
    session->m_items = std::make_unique<ItemRepository>(
        session->m_database, session->m_kek.span(), session->m_vaultKey.span());
    return session;
}

ItemRepository &VaultSession::items()
{
    return *m_items;
}

const ItemRepository &VaultSession::items() const
{
    return *m_items;
}

} // namespace cryptowl::vault
