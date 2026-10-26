#include "vault/ItemRepository.h"

#include "crypto/AesGcm.h"
#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"
#include "crypto/Hash.h"
#include "crypto/Random.h"
#include "crypto/Trace.h"
#include "vault/VaultDatabase.h"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <exception>
#include <string>
#include <utility>
#include <vector>

namespace cryptowl::vault {

namespace {

using cryptowl::crypto::Bytes;
using cryptowl::crypto::GcmCiphertext;
using cryptowl::crypto::ProtectedValue;

constexpr int kMaxBlobBytes = 64 * 1024 * 1024;

void setError(std::string *error, const std::string &message)
{
    if (error)
        *error = message;
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

std::string uuidV4()
{
    Bytes bytes = cryptowl::crypto::randomBytes(16);
    bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3f) | 0x80);

    char value[37];
    std::snprintf(value, sizeof(value),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                  "%02x%02x%02x%02x%02x%02x",
                  static_cast<unsigned>(bytes[0]), static_cast<unsigned>(bytes[1]),
                  static_cast<unsigned>(bytes[2]), static_cast<unsigned>(bytes[3]),
                  static_cast<unsigned>(bytes[4]), static_cast<unsigned>(bytes[5]),
                  static_cast<unsigned>(bytes[6]), static_cast<unsigned>(bytes[7]),
                  static_cast<unsigned>(bytes[8]), static_cast<unsigned>(bytes[9]),
                  static_cast<unsigned>(bytes[10]), static_cast<unsigned>(bytes[11]),
                  static_cast<unsigned>(bytes[12]), static_cast<unsigned>(bytes[13]),
                  static_cast<unsigned>(bytes[14]), static_cast<unsigned>(bytes[15]));
    return std::string(value);
}

bool execute(sqlite3 *db, const char *sql, std::string *error)
{
    char *message = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        setError(error, message ? message : sqlite3_errmsg(db));
        sqlite3_free(message);
        return false;
    }
    return true;
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
    if (!data || size <= 0 || size > kMaxBlobBytes)
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

bool loadDek(sqlite3 *db, const std::string &dekId,
             std::span<const std::uint8_t> kek, ProtectedValue *dek,
             std::string *error)
{
    static constexpr const char *kSql =
        "SELECT algorithm, ciphertext, nonce, auth_tag "
        "FROM t_data_encrypt_key WHERE id = ?;";
    Statement statement(db, kSql, error);
    if (!statement.ok())
        return false;
    if (!bindText(statement.get(), 1, dekId, error))
        return false;
    const int rc = statement.step(error);
    if (rc == SQLITE_DONE) {
        setError(error, "encrypted item key was not found");
        return false;
    }
    if (rc != SQLITE_ROW)
        return false;
    if (columnText(statement.get(), 0) != "AES-256-GCM") {
        setError(error, "unsupported item key algorithm");
        return false;
    }

    const Bytes ciphertext = columnBytes(statement.get(), 1);
    const Bytes nonce = columnBytes(statement.get(), 2);
    const Bytes tag = columnBytes(statement.get(), 3);
    if (ciphertext.size() != 32 || nonce.size() != 12 || tag.size() != 16) {
        setError(error, "invalid wrapped item key");
        return false;
    }

    try {
        Bytes plaintext = cryptowl::crypto::aesGcmDecrypt(
            kek, nonce, cryptowl::crypto::bytesOf(dekId), ciphertext, tag,
            "dek.unwrap.kek");
        if (plaintext.size() != 32) {
            cryptowl::crypto::secureWipe(plaintext);
            setError(error, "invalid unwrapped item key");
            return false;
        }
        *dek = ProtectedValue(std::move(plaintext));
        return true;
    } catch (const std::exception &) {
        setError(error, "could not unwrap item key");
        return false;
    }
}

bool insertDek(sqlite3 *db, const std::string &dekId,
               std::span<const std::uint8_t> kek, std::span<const std::uint8_t> dek,
               std::int64_t timestamp, std::string *error)
{
    const Bytes nonce = cryptowl::crypto::randomBytes(12);
    GcmCiphertext wrapped;
    try {
        wrapped = cryptowl::crypto::aesGcmEncrypt(
            kek, nonce, cryptowl::crypto::bytesOf(dekId), dek, "dek.wrap.kek");
    } catch (const std::exception &) {
        setError(error, "could not wrap item key");
        return false;
    }

    static constexpr const char *kSql =
        "INSERT INTO t_data_encrypt_key "
        "(id, algorithm, ciphertext, nonce, auth_tag, created_at, updated_at) "
        "VALUES (?, 'AES-256-GCM', ?, ?, ?, ?, ?);";
    Statement statement(db, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, dekId, error)
        || !bindBlob(statement.get(), 2, wrapped.ciphertext, error)
        || !bindBlob(statement.get(), 3, nonce, error)
        || !bindBlob(statement.get(), 4, wrapped.tag, error)
        || sqlite3_bind_int64(statement.get(), 5, timestamp) != SQLITE_OK
        || sqlite3_bind_int64(statement.get(), 6, timestamp) != SQLITE_OK) {
        return false;
    }
    if (statement.step(error) != SQLITE_DONE) {
        setDatabaseError(error, db);
        return false;
    }
    return true;
}

struct EncryptedData
{
    Bytes content;
    Bytes nonce;
    Bytes tag;
};

bool encryptPayload(std::span<const std::uint8_t> dek, const std::string &dataId,
                    const std::string &payload, EncryptedData *encrypted,
                    std::string *error)
{
    const Bytes nonce = cryptowl::crypto::randomBytes(12);
    try {
        const GcmCiphertext ciphertext = cryptowl::crypto::aesGcmEncrypt(
            dek, nonce, cryptowl::crypto::bytesOf(dataId),
            cryptowl::crypto::bytesOf(payload), "payload.encrypt.dek");
        encrypted->content = ciphertext.ciphertext;
        encrypted->tag = ciphertext.tag;
        encrypted->nonce = nonce;
        return true;
    } catch (const std::exception &) {
        setError(error, "could not encrypt item");
        return false;
    }
}

bool insertEncryptedData(sqlite3 *db, const std::string &dataId,
                         const std::string &dekId, const EncryptedData &encrypted,
                         std::int64_t timestamp, std::string *error)
{
    static constexpr const char *kSql =
        "INSERT INTO t_encrypted_data "
        "(id, dek_id, algorithm, content, nonce, auth_tag, created_at, updated_at) "
        "VALUES (?, ?, 'AES-256-GCM', ?, ?, ?, ?, ?);";
    Statement statement(db, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, dataId, error)
        || !bindText(statement.get(), 2, dekId, error)
        || !bindBlob(statement.get(), 3, encrypted.content, error)
        || !bindBlob(statement.get(), 4, encrypted.nonce, error)
        || !bindBlob(statement.get(), 5, encrypted.tag, error)
        || sqlite3_bind_int64(statement.get(), 6, timestamp) != SQLITE_OK
        || sqlite3_bind_int64(statement.get(), 7, timestamp) != SQLITE_OK) {
        return false;
    }
    if (statement.step(error) != SQLITE_DONE) {
        setDatabaseError(error, db);
        return false;
    }
    return true;
}

bool insertItem(sqlite3 *db, const std::string &itemId, const NewItem &item,
                const std::string &content, const std::string &dataId,
                std::int64_t timestamp, std::string *error)
{
    static constexpr const char *kSql =
        "INSERT INTO t_item "
        "(id, type, title, classification, parent_id, pinned, content, "
        " encrypted_data_id, meta, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?);";
    Statement statement(db, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, itemId, error)
        || !bindText(statement.get(), 2, item.type, error)
        || !bindText(statement.get(), 3, item.title, error)
        || !bindText(statement.get(), 4, item.classification, error)) {
        return false;
    }

    if (item.parentId.empty()) {
        if (sqlite3_bind_null(statement.get(), 5) != SQLITE_OK)
            return false;
    } else if (!bindText(statement.get(), 5, item.parentId, error)) {
        return false;
    }

    if (dataId.empty()) {
        if (!bindText(statement.get(), 6, content, error)
            || sqlite3_bind_null(statement.get(), 7) != SQLITE_OK) {
            return false;
        }
    } else {
        if (sqlite3_bind_null(statement.get(), 6) != SQLITE_OK
            || !bindText(statement.get(), 7, dataId, error)) {
            return false;
        }
    }

    if (!bindText(statement.get(), 8, item.meta, error)
        || sqlite3_bind_int64(statement.get(), 9, timestamp) != SQLITE_OK
        || sqlite3_bind_int64(statement.get(), 10, timestamp) != SQLITE_OK) {
        return false;
    }
    if (statement.step(error) != SQLITE_DONE) {
        setDatabaseError(error, db);
        return false;
    }
    return true;
}

bool insertVersion(sqlite3 *db, const std::string &itemId, int seq,
                   const std::string &classification, const std::string &title,
                   const std::string &content, const std::string &dataId,
                   const std::string &meta, const std::string &fingerprint,
                   std::int64_t timestamp, std::string *error)
{
    static constexpr const char *kSql =
        "INSERT INTO t_item_version "
        "(id, item_id, seq, classification, title, content, encrypted_data_id, "
        " meta, message, fingerprint, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?);";
    Statement statement(db, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, uuidV4(), error)
        || !bindText(statement.get(), 2, itemId, error)
        || sqlite3_bind_int(statement.get(), 3, seq) != SQLITE_OK
        || !bindText(statement.get(), 4, classification, error)
        || !bindText(statement.get(), 5, title, error)) {
        return false;
    }

    if (dataId.empty()) {
        if (!bindText(statement.get(), 6, content, error)
            || sqlite3_bind_null(statement.get(), 7) != SQLITE_OK) {
            return false;
        }
    } else {
        if (sqlite3_bind_null(statement.get(), 6) != SQLITE_OK
            || !bindText(statement.get(), 7, dataId, error)) {
            return false;
        }
    }

    if (!bindText(statement.get(), 8, meta, error)
        || !bindText(statement.get(), 9, fingerprint, error)
        || sqlite3_bind_int64(statement.get(), 10, timestamp) != SQLITE_OK) {
        return false;
    }
    if (statement.step(error) != SQLITE_DONE) {
        setDatabaseError(error, db);
        return false;
    }
    return true;
}

bool latestVersion(sqlite3 *db, const std::string &itemId, int *seq,
                   std::string *fingerprint, std::string *error)
{
    static constexpr const char *kSql =
        "SELECT seq, fingerprint FROM t_item_version "
        "WHERE item_id = ? ORDER BY seq DESC LIMIT 1;";
    Statement statement(db, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, itemId, error))
        return false;

    *seq = 0;
    fingerprint->clear();
    const int rc = statement.step(error);
    if (rc == SQLITE_DONE)
        return true;
    if (rc != SQLITE_ROW)
        return false;

    *seq = sqlite3_column_int(statement.get(), 0);
    *fingerprint = columnText(statement.get(), 1);
    return true;
}

std::string fingerprint(const ProtectedValue &hfk, const std::string &title,
                        const std::string &classification,
                        const std::string &payload)
{
    std::string message;
    message.reserve(title.size() + classification.size() + payload.size() + 2);
    message.append(title);
    message.push_back('\0');
    message.append(classification);
    message.push_back('\0');
    message.append(payload);

    const Bytes digest = cryptowl::crypto::hmacSha256(
        hfk.span(), cryptowl::crypto::bytesOf(message));
    std::fill(message.begin(), message.end(), '\0');
    return cryptowl::crypto::crockford32Encode(digest);
}

} // namespace

ItemRepository::ItemRepository(VaultDatabase &database,
                               std::span<const std::uint8_t> kek,
                               std::span<const std::uint8_t> vaultKey)
    : m_database(database)
    , m_kek(kek)
    , m_hfk(cryptowl::crypto::hkdfSha256(
          vaultKey, std::span<const std::uint8_t>(), cryptowl::crypto::bytesOf("fingerprint"),
          32))
{
}

bool ItemRepository::list(const std::string &type,
                          std::vector<ItemSummary> *items,
                          std::string *error) const
{
    if (items)
        items->clear();
    if (!items) {
        setError(error, "list destination is null");
        return false;
    }
    if (!m_database.handle()) {
        setError(error, "database is not open");
        return false;
    }

    static constexpr const char *kSqlWithType =
        "SELECT id, type, title, classification, meta, pinned, updated_at "
        "FROM t_item WHERE type = ? AND deleted_at IS NULL "
        "ORDER BY updated_at DESC, title COLLATE NOCASE;";
    static constexpr const char *kSqlAllTypes =
        "SELECT id, type, title, classification, meta, pinned, updated_at "
        "FROM t_item WHERE deleted_at IS NULL "
        "ORDER BY updated_at DESC, title COLLATE NOCASE;";
    Statement statement(m_database.handle(),
                        type.empty() ? kSqlAllTypes : kSqlWithType, error);
    if (!statement.ok())
        return false;
    if (!type.empty() && !bindText(statement.get(), 1, type, error))
        return false;

    while (true) {
        const int rc = statement.step(error);
        if (rc == SQLITE_DONE)
            return true;
        if (rc != SQLITE_ROW)
            return false;

        ItemSummary item;
        item.id = columnText(statement.get(), 0);
        item.type = columnText(statement.get(), 1);
        item.title = columnText(statement.get(), 2);
        item.classification = columnText(statement.get(), 3);
        item.meta = columnText(statement.get(), 4);
        item.pinned = sqlite3_column_int(statement.get(), 5) != 0;
        item.updatedAt = sqlite3_column_int64(statement.get(), 6);
        items->push_back(std::move(item));
    }
}

bool ItemRepository::get(const std::string &id, ItemRecord *item,
                         std::string *error) const
{
    if (!item) {
        setError(error, "item destination is null");
        return false;
    }
    if (!m_database.handle()) {
        setError(error, "database is not open");
        return false;
    }

    static constexpr const char *kSql =
        "SELECT i.id, i.type, i.title, i.classification, i.parent_id, i.meta, "
        "       i.created_at, i.updated_at, i.content, e.id, e.dek_id, e.content, "
        "       e.nonce, e.auth_tag "
        "FROM t_item i "
        "LEFT JOIN t_encrypted_data e "
        "  ON e.id = i.encrypted_data_id AND e.deleted_at IS NULL "
        "WHERE i.id = ? AND i.deleted_at IS NULL;";
    Statement statement(m_database.handle(), kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, id, error))
        return false;

    const int rc = statement.step(error);
    if (rc == SQLITE_DONE) {
        setError(error, "item was not found");
        return false;
    }
    if (rc != SQLITE_ROW)
        return false;

    ItemRecord record;
    record.id = columnText(statement.get(), 0);
    record.type = columnText(statement.get(), 1);
    record.title = columnText(statement.get(), 2);
    record.classification = columnText(statement.get(), 3);
    record.parentId = columnText(statement.get(), 4);
    record.meta = columnText(statement.get(), 5);
    record.createdAt = sqlite3_column_int64(statement.get(), 6);
    record.updatedAt = sqlite3_column_int64(statement.get(), 7);

    if (record.classification == "C") {
        record.payload = columnText(statement.get(), 8);
        CRYPTOWL_TRACE_SECRET_TEXT(
            "item.read.data", "id=" + record.id + " data_id=- dek_id=-");
    } else if (record.classification == "S") {
        const std::string dataId = columnText(statement.get(), 9);
        const std::string dekId = columnText(statement.get(), 10);
        const Bytes content = columnBytes(statement.get(), 11);
        const Bytes nonce = columnBytes(statement.get(), 12);
        const Bytes tag = columnBytes(statement.get(), 13);
        if (dataId.empty() || dekId.empty() || nonce.size() != 12
            || tag.size() != 16) {
            setError(error, "encrypted item data is invalid");
            return false;
        }

        CRYPTOWL_TRACE_SECRET_TEXT(
            "item.read.data",
            "id=" + record.id + " data_id=" + dataId + " dek_id=" + dekId);

        ProtectedValue dek;
        if (!loadDek(m_database.handle(), dekId, m_kek, &dek, error))
            return false;
        CRYPTOWL_TRACE_SECRET("item.dek", dek.span());

        try {
            Bytes plaintext = cryptowl::crypto::aesGcmDecrypt(
                dek.span(), nonce, cryptowl::crypto::bytesOf(dataId), content, tag,
                "payload.decrypt.dek");
            record.payload.assign(reinterpret_cast<const char *>(plaintext.data()),
                                  plaintext.size());
            std::fill(plaintext.begin(), plaintext.end(), std::uint8_t{0});
        } catch (const std::exception &) {
            setError(error, "could not decrypt item");
            return false;
        }
    } else {
        setError(error, "unsupported item classification");
        return false;
    }

    CRYPTOWL_TRACE_SECRET_TEXT(
        "item.read",
        "id=" + record.id + " type=" + record.type + " classification="
            + record.classification + " title=" + record.title);
    CRYPTOWL_TRACE_SECRET_TEXT("item.payload", record.payload);
    CRYPTOWL_TRACE_SECRET("item.payload.hex",
                          cryptowl::crypto::bytesOf(record.payload));

    *item = std::move(record);
    return true;
}

bool ItemRepository::create(const NewItem &item, std::string *id,
                            std::string *error)
{
    if (id)
        id->clear();
    if (!id) {
        setError(error, "item id destination is null");
        return false;
    }
    if (!m_database.handle()) {
        setError(error, "database is not open");
        return false;
    }
    if (m_kek.size() != 32) {
        setError(error, "vault key encryption key is unavailable");
        return false;
    }
    if (item.type.empty() || item.title.empty()) {
        setError(error, "item type and title are required");
        return false;
    }
    if (item.classification != "C" && item.classification != "S") {
        setError(error, "unsupported item classification");
        return false;
    }
    const bool secret = item.classification == "S";
    if (secret && m_kek.size() != 32) {
        setError(error, "vault key encryption key is unavailable");
        return false;
    }

    const std::string itemId = uuidV4();
    std::string dekId;
    std::string dataId;
    ProtectedValue dek;
    EncryptedData encrypted;

    CRYPTOWL_TRACE_SECRET_TEXT(
        "item.create",
        "id=" + itemId + " type=" + item.type + " classification="
            + item.classification + " title=" + item.title);
    CRYPTOWL_TRACE_SECRET_TEXT("item.payload", item.payload);

    if (secret) {
        dekId = uuidV4();
        dataId = uuidV4();
        dek = ProtectedValue(cryptowl::crypto::randomBytes(32));
        if (!encryptPayload(dek.span(), dataId, item.payload, &encrypted, error))
            return false;
    }

    CRYPTOWL_TRACE_SECRET_TEXT(
        "item.create.data",
        "id=" + itemId + " data_id=" + dataId + " dek_id=" + dekId);
    if (secret) {
        CRYPTOWL_TRACE_SECRET("item.dek", dek.span());
    } else {
        CRYPTOWL_TRACE_SECRET("item.payload.hex",
                              cryptowl::crypto::bytesOf(item.payload));
    }

    const std::int64_t timestamp = nowMillis();
    if (!execute(m_database.handle(), "BEGIN IMMEDIATE;", error))
        return false;

    const auto rollback = [this] {
        std::string ignored;
        execute(m_database.handle(), "ROLLBACK;", &ignored);
    };

    if ((secret
         && (!insertDek(m_database.handle(), dekId, m_kek, dek.span(), timestamp,
                        error)
             || !insertEncryptedData(m_database.handle(), dataId, dekId, encrypted,
                                     timestamp, error)))
        || !insertItem(m_database.handle(), itemId, item,
                       secret ? std::string() : item.payload, dataId, timestamp,
                       error)
        || !insertVersion(m_database.handle(), itemId, 1, item.classification,
                          item.title, secret ? std::string() : item.payload, dataId,
                          item.meta,
                          fingerprint(m_hfk, item.title, item.classification,
                                      item.payload),
                          timestamp, error)) {
        rollback();
        return false;
    }

    if (!execute(m_database.handle(), "COMMIT;", error)) {
        rollback();
        return false;
    }

    *id = itemId;
    return true;
}

bool ItemRepository::update(const std::string &id, const ItemUpdate &item,
                            std::string *error)
{
    if (!m_database.handle()) {
        setError(error, "database is not open");
        return false;
    }
    if (item.title.empty()) {
        setError(error, "item title is required");
        return false;
    }

    if (!execute(m_database.handle(), "BEGIN IMMEDIATE;", error))
        return false;

    const auto rollback = [this] {
        std::string ignored;
        execute(m_database.handle(), "ROLLBACK;", &ignored);
    };

    static constexpr const char *kSql =
        "SELECT i.classification, i.content, i.encrypted_data_id, e.dek_id "
        "FROM t_item i "
        "LEFT JOIN t_encrypted_data e "
        "  ON e.id = i.encrypted_data_id AND e.deleted_at IS NULL "
        "WHERE i.id = ? AND i.deleted_at IS NULL;";
    std::string currentClassification;
    std::string currentDataId;
    std::string currentDekId;
    {
        Statement statement(m_database.handle(), kSql, error);
        if (!statement.ok() || !bindText(statement.get(), 1, id, error)) {
            rollback();
            return false;
        }
        const int rc = statement.step(error);
        if (rc == SQLITE_DONE) {
            rollback();
            setError(error, "item was not found");
            return false;
        }
        if (rc != SQLITE_ROW) {
            rollback();
            return false;
        }

        currentClassification = columnText(statement.get(), 0);
        currentDataId = columnText(statement.get(), 2);
        currentDekId = columnText(statement.get(), 3);
    }

    if (currentClassification != "C" && currentClassification != "S") {
        rollback();
        setError(error, "unsupported item classification");
        return false;
    }
    if (currentClassification == "S"
        && (currentDataId.empty() || currentDekId.empty())) {
        rollback();
        setError(error, "encrypted item data is invalid");
        return false;
    }

    const std::string desiredClassification =
        item.classification.empty() ? currentClassification : item.classification;
    if (desiredClassification != "C" && desiredClassification != "S") {
        rollback();
        setError(error, "unsupported item classification");
        return false;
    }
    const bool desiredSecret = desiredClassification == "S";
    if (desiredSecret && m_kek.size() != 32) {
        rollback();
        setError(error, "vault key encryption key is unavailable");
        return false;
    }

    CRYPTOWL_TRACE_SECRET_TEXT(
        "item.update",
        "id=" + id + " classification=" + desiredClassification + " title="
            + item.title);
    CRYPTOWL_TRACE_SECRET_TEXT("item.payload", item.payload);

    const std::string newFingerprint =
        fingerprint(m_hfk, item.title, desiredClassification, item.payload);
    int seq = 0;
    std::string previousFingerprint;
    if (!latestVersion(m_database.handle(), id, &seq, &previousFingerprint, error)) {
        rollback();
        return false;
    }
    if (seq > 0 && previousFingerprint == newFingerprint) {
        if (!execute(m_database.handle(), "COMMIT;", error)) {
            rollback();
            return false;
        }
        return true;
    }

    const std::int64_t timestamp = nowMillis();
    std::string dekId;
    std::string dataId;
    std::string content;
    ProtectedValue dek;
    EncryptedData encrypted;

    if (desiredSecret) {
        if (currentClassification == "S") {
            dekId = currentDekId;
            if (!loadDek(m_database.handle(), dekId, m_kek, &dek, error)) {
                rollback();
                return false;
            }
        } else {
            dekId = uuidV4();
            dek = ProtectedValue(cryptowl::crypto::randomBytes(32));
            if (!insertDek(m_database.handle(), dekId, m_kek, dek.span(), timestamp,
                           error)) {
                rollback();
                return false;
            }
        }

        dataId = uuidV4();
        if (!encryptPayload(dek.span(), dataId, item.payload, &encrypted, error)
            || !insertEncryptedData(m_database.handle(), dataId, dekId, encrypted,
                                    timestamp, error)) {
            rollback();
            return false;
        }
    } else {
        content = item.payload;
    }

    CRYPTOWL_TRACE_SECRET_TEXT(
        "item.update.data",
        "id=" + id + " data_id=" + dataId + " dek_id=" + dekId);
    if (desiredSecret) {
        CRYPTOWL_TRACE_SECRET("item.dek", dek.span());
    } else {
        CRYPTOWL_TRACE_SECRET("item.payload.hex",
                              cryptowl::crypto::bytesOf(content));
    }

    static constexpr const char *kUpdateSql =
        "UPDATE t_item SET title = ?, classification = ?, content = ?, "
        "encrypted_data_id = ?, meta = ?, updated_at = ? "
        "WHERE id = ? AND deleted_at IS NULL;";
    {
        Statement updateStatement(m_database.handle(), kUpdateSql, error);
        if (!updateStatement.ok()
            || !bindText(updateStatement.get(), 1, item.title, error)
            || !bindText(updateStatement.get(), 2, desiredClassification, error)) {
            rollback();
            return false;
        }

        if (desiredSecret) {
            if (sqlite3_bind_null(updateStatement.get(), 3) != SQLITE_OK
                || !bindText(updateStatement.get(), 4, dataId, error)) {
                rollback();
                return false;
            }
        } else {
            if (!bindText(updateStatement.get(), 3, content, error)
                || sqlite3_bind_null(updateStatement.get(), 4) != SQLITE_OK) {
                rollback();
                return false;
            }
        }

        if (!bindText(updateStatement.get(), 5, item.meta, error)
            || sqlite3_bind_int64(updateStatement.get(), 6, timestamp) != SQLITE_OK
            || !bindText(updateStatement.get(), 7, id, error)
            || updateStatement.step(error) != SQLITE_DONE
            || sqlite3_changes(m_database.handle()) != 1) {
            rollback();
            setError(error, "could not update item");
            return false;
        }
    }

    if (!insertVersion(m_database.handle(), id, seq + 1, desiredClassification,
                       item.title, content, dataId, item.meta, newFingerprint,
                       timestamp, error)) {
        rollback();
        return false;
    }

    if (!execute(m_database.handle(), "COMMIT;", error)) {
        rollback();
        return false;
    }
    return true;
}

bool ItemRepository::softDelete(const std::string &id, std::string *error)
{
    if (!m_database.handle()) {
        setError(error, "database is not open");
        return false;
    }

    static constexpr const char *kSql =
        "UPDATE t_item SET deleted_at = ?, updated_at = ? "
        "WHERE id = ? AND deleted_at IS NULL;";
    const std::int64_t timestamp = nowMillis();
    Statement statement(m_database.handle(), kSql, error);
    if (!statement.ok()
        || sqlite3_bind_int64(statement.get(), 1, timestamp) != SQLITE_OK
        || sqlite3_bind_int64(statement.get(), 2, timestamp) != SQLITE_OK
        || !bindText(statement.get(), 3, id, error)
        || statement.step(error) != SQLITE_DONE) {
        return false;
    }
    if (sqlite3_changes(m_database.handle()) != 1) {
        setError(error, "item was not found");
        return false;
    }
    return true;
}

} // namespace cryptowl::vault
