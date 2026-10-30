#include "TopSecretService.h"

#include "crypto/AesGcm.h"
#include "crypto/Argon2.h"
#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"
#include "crypto/Errors.h"
#include "crypto/Hash.h"
#include "crypto/Random.h"
#include "crypto/Trace.h"

#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDevice>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QSaveFile>
#include <QString>

#include <sqlite3.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace {

using namespace cryptowl::crypto;

constexpr const char *kTopSecretKekId = "top_secret_kek:ts_kek";
constexpr qint64 kMaxMetaBytes = 1024 * 1024;
constexpr int kMaxKdfMemoryKib = 256 * 1024;
constexpr int kMaxKdfIterations = 16;
constexpr int kMaxKdfParallelism = 16;
constexpr int kMaxBlobBytes = 1024 * 1024;

void setError(QString *error, const QString &message)
{
    if (error)
        *error = message;
}

void setDatabaseError(QString *error, sqlite3 *database)
{
    setError(error, QString::fromUtf8(sqlite3_errmsg(database)));
}

class Statement
{
public:
    Statement(sqlite3 *database, const char *sql, QString *error)
        : m_database(database)
    {
        const int rc = sqlite3_prepare_v2(database, sql, -1, &m_statement, nullptr);
        if (rc != SQLITE_OK) {
            m_statement = nullptr;
            setDatabaseError(error, database);
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

    int step(QString *error)
    {
        const int rc = sqlite3_step(m_statement);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE)
            setDatabaseError(error, m_database);
        return rc;
    }

private:
    sqlite3 *m_database = nullptr;
    sqlite3_stmt *m_statement = nullptr;
};

bool execute(sqlite3 *database, const char *sql, QString *error)
{
    char *message = nullptr;
    const int rc = sqlite3_exec(database, sql, nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        setError(error, QString::fromUtf8(message ? message : sqlite3_errmsg(database)));
        sqlite3_free(message);
        return false;
    }
    return true;
}

bool bindText(sqlite3_stmt *statement, int index, const std::string &value,
              QString *error)
{
    const int rc = sqlite3_bind_text(statement, index, value.data(),
                                     static_cast<int>(value.size()),
                                     SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        setError(error, QStringLiteral("Could not bind database text."));
        return false;
    }
    return true;
}

bool bindBlob(sqlite3_stmt *statement, int index,
              std::span<const std::uint8_t> value, QString *error)
{
    const int rc = sqlite3_bind_blob(statement, index, value.data(),
                                     static_cast<int>(value.size()),
                                     SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        setError(error, QStringLiteral("Could not bind database blob."));
        return false;
    }
    return true;
}

std::string columnText(sqlite3_stmt *statement, int index)
{
    const unsigned char *text = sqlite3_column_text(statement, index);
    if (!text)
        return {};
    return std::string(reinterpret_cast<const char *>(text),
                       static_cast<std::size_t>(sqlite3_column_bytes(statement, index)));
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

QString encode(std::span<const std::uint8_t> bytes)
{
    return QString::fromStdString(crockford32Encode(bytes));
}

bool readMeta(const QString &vaultPath, QJsonObject *meta, QString *error)
{
    QFile file(QDir(vaultPath).filePath(QStringLiteral("vault.meta")));
    if (!file.open(QIODevice::ReadOnly)) {
        setError(error, QStringLiteral("Cannot read vault.meta."));
        return false;
    }
    if (file.size() > kMaxMetaBytes) {
        setError(error, QStringLiteral("vault.meta is too large."));
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        setError(error, QStringLiteral("vault.meta is not valid JSON."));
        return false;
    }

    *meta = document.object();
    const int version = meta->value(QStringLiteral("version")).toInt(-1);
    if (version < 2 || version > 3) {
        setError(error, QStringLiteral("Unsupported vault format version."));
        return false;
    }
    if (meta->value(QStringLiteral("vault_id")).toString().isEmpty()) {
        setError(error, QStringLiteral("Missing or invalid vault_id."));
        return false;
    }
    return true;
}

bool writeMeta(const QString &vaultPath, const QJsonObject &meta, QString *error)
{
    QSaveFile file(QDir(vaultPath).filePath(QStringLiteral("vault.meta")));
    if (!file.open(QIODevice::WriteOnly)) {
        setError(error, file.errorString());
        return false;
    }
    const QByteArray data = QJsonDocument(meta).toJson(QJsonDocument::Compact);
    if (file.write(data) != data.size()) {
        setError(error, file.errorString());
        file.cancelWriting();
        return false;
    }
#ifndef Q_OS_WIN
    if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        setError(error, QStringLiteral("Could not restrict vault.meta permissions."));
        file.cancelWriting();
        return false;
    }
#endif
    if (!file.commit()) {
        setError(error, file.errorString());
        return false;
    }
    return true;
}

bool readKdf(const QJsonObject &meta, Argon2Params *params, QString *error)
{
    const QJsonObject kdf = meta.value(QStringLiteral("kdf")).toObject();
    if (kdf.value(QStringLiteral("algorithm")).toString()
        != QStringLiteral("argon2id")) {
        setError(error, QStringLiteral("Unsupported password KDF."));
        return false;
    }
    const int memoryKib = kdf.value(QStringLiteral("m_kib")).toInt(0);
    const int iterations = kdf.value(QStringLiteral("t")).toInt(0);
    const int parallelism = kdf.value(QStringLiteral("p")).toInt(0);
    if (memoryKib <= 0 || memoryKib > kMaxKdfMemoryKib || iterations <= 0
        || iterations > kMaxKdfIterations || parallelism <= 0
        || parallelism > kMaxKdfParallelism) {
        setError(error, QStringLiteral("Invalid Argon2 parameters."));
        return false;
    }
    params->memoryKib = static_cast<std::uint32_t>(memoryKib);
    params->iterations = static_cast<std::uint32_t>(iterations);
    params->parallelism = static_cast<std::uint32_t>(parallelism);
    return true;
}

bool readSecondarySalt(const QJsonObject &meta, Bytes *salt, QString *error)
{
    const QJsonObject salts = meta.value(QStringLiteral("salts")).toObject();
    const QString encoded = salts.value(QStringLiteral("secondary")).toString();
    if (encoded.isEmpty()) {
        setError(error, QStringLiteral("Top Secret is not set up."));
        return false;
    }
    try {
        *salt = crockford32Decode(encoded.toStdString());
    } catch (const std::exception &) {
        setError(error, QStringLiteral("Invalid secondary salt."));
        return false;
    }
    if (salt->size() != 32) {
        setError(error, QStringLiteral("Invalid secondary salt."));
        return false;
    }
    return true;
}

bool topSecretKekExists(sqlite3 *database, QString *error)
{
    if (!database) {
        setError(error, QStringLiteral("Vault database is not open."));
        return false;
    }
    static constexpr const char *kSql =
        "SELECT role, wrapper FROM t_wrapped_key WHERE id = ? "
        "AND deleted_at IS NULL;";
    Statement statement(database, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, kTopSecretKekId, error))
        return false;
    const int rc = statement.step(error);
    if (rc == SQLITE_DONE)
        return false;
    if (rc != SQLITE_ROW)
        return false;
    return columnText(statement.get(), 0) == "top_secret_kek"
        && columnText(statement.get(), 1) == "ts_kek";
}

} // namespace

TopSecretService::TopSecretService(QString vaultPath, sqlite3 *database)
    : m_vaultPath(std::move(vaultPath))
    , m_database(database)
{
}

bool TopSecretService::isConfigured(QString *error) const
{
    if (!m_database) {
        setError(error, QStringLiteral("Vault database is not open."));
        return false;
    }

    QJsonObject meta;
    if (!readMeta(m_vaultPath, &meta, error))
        return false;
    const QJsonObject salts = meta.value(QStringLiteral("salts")).toObject();
    if (salts.value(QStringLiteral("secondary")).toString().isEmpty())
        return false;

    QString queryError;
    if (!topSecretKekExists(m_database, &queryError)) {
        if (!queryError.isEmpty())
            setError(error, queryError);
        return false;
    }
    return true;
}

bool TopSecretService::setup(std::span<const std::uint8_t> smk,
                             std::span<const std::uint8_t> secondaryPassword,
                             QString *error)
{
    CRYPTOWL_TRACE_NOTE("set up Top Secret (secondary password)");
    if (!m_database) {
        setError(error, QStringLiteral("Vault database is not open."));
        return false;
    }
    if (smk.size() != 64) {
        setError(error, QStringLiteral("Invalid stretched master key."));
        return false;
    }
    if (secondaryPassword.empty()) {
        setError(error, QStringLiteral("The secondary password must not be empty."));
        return false;
    }

    QJsonObject meta;
    if (!readMeta(m_vaultPath, &meta, error))
        return false;
    if (meta.value(QStringLiteral("version")).toInt(-1) != 3) {
        setError(error, QStringLiteral("Top Secret requires vault format version 3."));
        return false;
    }
    if (isConfigured(nullptr)) {
        setError(error, QStringLiteral("Top Secret is already set up."));
        return false;
    }

    Argon2Params params;
    if (!readKdf(meta, &params, error))
        return false;

    const Bytes secondarySalt = randomBytes(32);
    CRYPTOWL_TRACE_NOTE(
        "derive TS-KEK = Argon2id(secondary_password, secondary_salt)");
    ProtectedValue tsKek;
    ProtectedValue topSecretKek;
    GcmCiphertext wrapped;
    const Bytes nonce = randomBytes(12);
    try {
        tsKek = ProtectedValue(argon2id(secondaryPassword, secondarySalt, params));
        topSecretKek = ProtectedValue(randomBytes(32));
        CRYPTOWL_TRACE_NOTE("wrap TopSecretKEK with TS-KEK");
        wrapped = aesGcmEncrypt(tsKek.span(), nonce,
                                bytesOf(std::string_view(kTopSecretKekId)),
                                topSecretKek.span(),
                                "top_secret_kek.wrap.ts_kek");
    } catch (const std::exception &) {
        setError(error, QStringLiteral("Could not set up Top Secret."));
        return false;
    }

    CRYPTOWL_TRACE_SECRET("top_secret.secondary_salt", secondarySalt);
    CRYPTOWL_TRACE_SECRET("top_secret.ts_kek", tsKek.span());
    CRYPTOWL_TRACE_SECRET("top_secret.kek", topSecretKek.span());

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (!execute(m_database, "BEGIN IMMEDIATE;", error))
        return false;
    const auto rollback = [this] {
        QString ignored;
        execute(m_database, "ROLLBACK;", &ignored);
    };

    static constexpr const char *kInsertSql =
        "INSERT OR REPLACE INTO t_wrapped_key "
        "(id, role, wrapper, algorithm, ciphertext, nonce, auth_tag, "
        " created_at, updated_at, deleted_at) "
        "VALUES (?, 'top_secret_kek', 'ts_kek', 'AES-256-GCM', ?, ?, ?, ?, ?, "
        "NULL);";
    CRYPTOWL_TRACE_NOTE("store wrapped TopSecretKEK in t_wrapped_key");
    {
        Statement statement(m_database, kInsertSql, error);
        if (!statement.ok()
            || !bindText(statement.get(), 1, kTopSecretKekId, error)
            || !bindBlob(statement.get(), 2, wrapped.ciphertext, error)
            || !bindBlob(statement.get(), 3, nonce, error)
            || !bindBlob(statement.get(), 4, wrapped.tag, error)
            || sqlite3_bind_int64(statement.get(), 5, now) != SQLITE_OK
            || sqlite3_bind_int64(statement.get(), 6, now) != SQLITE_OK
            || statement.step(error) != SQLITE_DONE) {
            rollback();
            return false;
        }
    }

    QJsonObject salts = meta.value(QStringLiteral("salts")).toObject();
    salts[QStringLiteral("secondary")] = encode(secondarySalt);
    meta[QStringLiteral("salts")] = salts;
    meta[QStringLiteral("updated_at")] = static_cast<double>(now);
    meta.remove(QStringLiteral("mac"));
    CRYPTOWL_TRACE_NOTE("update vault.meta and re-sign MAC");
    const QByteArray canonical = QJsonDocument(meta).toJson(QJsonDocument::Compact);
    const Bytes mac = hmacSha256(
        smk.subspan(32, 32),
        bytesOf(std::string_view(canonical.constData(),
                                 static_cast<std::size_t>(canonical.size()))));
    QJsonObject macObject;
    macObject[QStringLiteral("algorithm")] = QStringLiteral("HMAC-SHA256");
    macObject[QStringLiteral("value")] = encode(mac);
    meta[QStringLiteral("mac")] = macObject;

    if (!writeMeta(m_vaultPath, meta, error)) {
        rollback();
        return false;
    }
    if (!execute(m_database, "COMMIT;", error)) {
        rollback();
        return false;
    }
    return true;
}

bool TopSecretService::unlock(std::span<const std::uint8_t> secondaryPassword,
                              cryptowl::crypto::ProtectedValue *topSecretKek,
                              QString *error) const
{
    if (!m_database) {
        setError(error, QStringLiteral("Vault database is not open."));
        return false;
    }
    if (!topSecretKek) {
        setError(error, QStringLiteral("Top Secret key destination is null."));
        return false;
    }

    CRYPTOWL_TRACE_NOTE("unlock Top Secret with secondary password");
    QJsonObject meta;
    if (!readMeta(m_vaultPath, &meta, error))
        return false;
    Bytes secondarySalt;
    if (!readSecondarySalt(meta, &secondarySalt, error))
        return false;

    Argon2Params params;
    if (!readKdf(meta, &params, error))
        return false;

    ProtectedValue tsKek;
    try {
        CRYPTOWL_TRACE_NOTE(
            "derive TS-KEK = Argon2id(secondary_password, secondary_salt)");
        tsKek = ProtectedValue(argon2id(secondaryPassword, secondarySalt, params));
    } catch (const std::exception &) {
        setError(error, QStringLiteral("Could not derive the Top Secret key."));
        return false;
    }

    static constexpr const char *kSql =
        "SELECT role, wrapper, algorithm, ciphertext, nonce, auth_tag "
        "FROM t_wrapped_key WHERE id = ? AND deleted_at IS NULL;";
    Statement statement(m_database, kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, kTopSecretKekId, error))
        return false;
    const int rc = statement.step(error);
    if (rc == SQLITE_DONE) {
        setError(error, QStringLiteral("Top Secret is not set up."));
        return false;
    }
    if (rc != SQLITE_ROW)
        return false;
    if (columnText(statement.get(), 0) != "top_secret_kek"
        || columnText(statement.get(), 1) != "ts_kek"
        || columnText(statement.get(), 2) != "AES-256-GCM") {
        setError(error, QStringLiteral("Invalid Top Secret key metadata."));
        return false;
    }

    const Bytes ciphertext = columnBytes(statement.get(), 3);
    const Bytes nonce = columnBytes(statement.get(), 4);
    const Bytes tag = columnBytes(statement.get(), 5);
    if (ciphertext.size() != 32 || nonce.size() != 12 || tag.size() != 16) {
        setError(error, QStringLiteral("Invalid Top Secret key data."));
        return false;
    }

    try {
        CRYPTOWL_TRACE_NOTE("unwrap TopSecretKEK with TS-KEK");
        Bytes plaintext = aesGcmDecrypt(
            tsKek.span(), nonce, bytesOf(std::string_view(kTopSecretKekId)),
            ciphertext, tag, "top_secret_kek.unwrap.ts_kek");
        if (plaintext.size() != 32) {
            secureWipe(plaintext);
            setError(error, QStringLiteral("Invalid Top Secret key length."));
            return false;
        }
        *topSecretKek = ProtectedValue(std::move(plaintext));
        return true;
    } catch (const AuthenticationError &) {
        setError(error,
                 QStringLiteral("Incorrect secondary password or corrupted "
                                "Top Secret key."));
        return false;
    } catch (const std::exception &) {
        setError(error, QStringLiteral("Could not unlock Top Secret."));
        return false;
    }
}
