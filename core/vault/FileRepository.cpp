#include "vault/FileRepository.h"

#include "crypto/Hash.h"
#include "crypto/Random.h"
#include "vault/VaultDatabase.h"

#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace cryptowl::vault {

namespace {

using crypto::Bytes;
using crypto::ProtectedValue;
using crypto::bytesOf;

constexpr std::size_t kMaxBlobBytes = 64 * 1024 * 1024;

void setError(std::string *error, std::string message)
{
    if (error)
        *error = std::move(message);
}

void setDatabaseError(std::string *error, sqlite3 *database)
{
    setError(error, database ? sqlite3_errmsg(database)
                             : "database is not open");
}

bool execute(sqlite3 *database, const char *sql, std::string *error)
{
    char *message = nullptr;
    const int rc = sqlite3_exec(database, sql, nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        setError(error, message ? message : sqlite3_errmsg(database));
        sqlite3_free(message);
        return false;
    }
    return true;
}

class Statement
{
public:
    Statement(sqlite3 *database, const char *sql, std::string *error)
        : m_database(database)
    {
        const int rc = sqlite3_prepare_v2(database, sql, -1, &m_statement, nullptr);
        if (rc != SQLITE_OK) {
            setDatabaseError(error, database);
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
            setDatabaseError(error, m_database);
            return rc;
        }
        return rc;
    }

private:
    sqlite3 *m_database = nullptr;
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
    if (!data || size <= 0 || size > static_cast<int>(kMaxBlobBytes))
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

std::int64_t nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string uuidV4()
{
    Bytes bytes = crypto::randomBytes(16);
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

bool readWholeFile(const std::string &path, Bytes *data, std::string *error)
{
    std::error_code fileError;
    const std::uint64_t size = std::filesystem::file_size(path, fileError);
    if (fileError) {
        setError(error, "could not stat source file: " + fileError.message());
        return false;
    }
    if (size > std::numeric_limits<std::size_t>::max()) {
        setError(error, "source file is too large for embedded storage");
        return false;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        setError(error, "could not open source file");
        return false;
    }
    data->resize(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char *>(data->data()),
                  static_cast<std::streamsize>(size));
        if (file.gcount() != static_cast<std::streamsize>(size)) {
            crypto::secureWipe(*data);
            setError(error, "could not read source file");
            return false;
        }
    }
    return true;
}

FileStorage storageFromText(const std::string &value)
{
    return value == "external" ? FileStorage::External : FileStorage::Embedded;
}

const char *storageText(FileStorage storage)
{
    return storage == FileStorage::External ? "external" : "embedded";
}

} // namespace

FileRepository::FileRepository(VaultDatabase &database,
                               std::string attachmentsDir,
                               std::span<const std::uint8_t> vaultKey,
                               std::uint64_t embedMaxBytes)
    : m_database(database)
    , m_attachmentsDir(std::move(attachmentsDir))
    , m_embedMaxBytes(embedMaxBytes)
{
    if (vaultKey.size() != 32)
        throw std::invalid_argument("file repository requires a 32-byte vault key");
    m_fek = ProtectedValue(crypto::hkdfSha256(
        vaultKey, std::span<const std::uint8_t>(), bytesOf("file"), 32));
}

bool FileRepository::import(const ImportFile &file, std::string *id,
                            std::string *error)
{
    if (id)
        id->clear();
    if (!id) {
        setError(error, "file id destination is null");
        return false;
    }
    if (!m_database.handle()) {
        setError(error, "database is not open");
        return false;
    }
    if (file.itemId.empty() || file.sourcePath.empty()) {
        setError(error, "item and source file are required");
        return false;
    }

    std::error_code fileError;
    const std::uint64_t size = std::filesystem::file_size(file.sourcePath, fileError);
    if (fileError) {
        setError(error, "could not stat source file: " + fileError.message());
        return false;
    }
    if (size > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        setError(error, "source file is too large");
        return false;
    }

    FileRecord record;
    record.id = uuidV4();
    record.itemId = file.itemId;
    record.name = file.name;
    record.mimeType = file.mimeType;
    record.sizeBytes = size;
    record.storage = size <= m_embedMaxBytes ? FileStorage::Embedded
                                              : FileStorage::External;
    record.createdAt = nowMillis();
    record.updatedAt = record.createdAt;

    if (!file.thumbnailPlaintext.empty()) {
        record.thumbnail = crypto::encryptEmbedded(
            m_fek.span(), record.id + ":thumb", file.thumbnailPlaintext, error);
        if (record.thumbnail.empty())
            return false;
    }

    std::filesystem::path externalPath;
    if (record.storage == FileStorage::Embedded) {
        Bytes plaintext;
        if (!readWholeFile(file.sourcePath, &plaintext, error))
            return false;
        record.content = crypto::encryptEmbedded(
            m_fek.span(), record.id, plaintext, error);
        crypto::secureWipe(plaintext);
        if (record.content.empty())
            return false;
    } else {
        externalPath = std::filesystem::path(m_attachmentsDir) / record.id;
        std::filesystem::path tempPath = externalPath;
        tempPath += ".tmp";
        std::filesystem::remove(tempPath, fileError);
        if (!std::filesystem::create_directories(m_attachmentsDir, fileError)
            && fileError) {
            setError(error, "could not create attachments directory: "
                                + fileError.message());
            return false;
        }
#ifndef _WIN32
        std::filesystem::permissions(
            m_attachmentsDir,
            std::filesystem::perms::owner_all,
            std::filesystem::perm_options::replace, fileError);
        fileError.clear();
#endif
        if (!crypto::encryptChunkedFile(m_fek.span(), record.id,
                                        file.sourcePath,
                                        tempPath.string(), size, error)) {
            std::filesystem::remove(tempPath, fileError);
            return false;
        }
        std::filesystem::rename(tempPath, externalPath, fileError);
        if (fileError) {
            std::filesystem::remove(tempPath, fileError);
            setError(error, "could not finalize encrypted file: "
                                + fileError.message());
            return false;
        }
        record.externalName = record.id;
    }

    if (!insert(record, error)) {
        if (record.storage == FileStorage::External) {
            std::filesystem::remove(externalPath, fileError);
        }
        return false;
    }

    *id = record.id;
    return true;
}

bool FileRepository::insert(const FileRecord &file, std::string *error)
{
    if (!execute(m_database.handle(), "BEGIN IMMEDIATE;", error))
        return false;

    const auto rollback = [this] {
        std::string ignored;
        execute(m_database.handle(), "ROLLBACK;", &ignored);
    };

    static constexpr const char *kSql =
        "INSERT INTO t_file "
        "(id, item_id, name, mime_type, size_bytes, storage, content, thumbnail, "
        " external_name, created_at, updated_at, deleted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);";
    Statement statement(m_database.handle(), kSql, error);
    if (!statement.ok()
        || !bindText(statement.get(), 1, file.id, error)
        || !bindText(statement.get(), 2, file.itemId, error)
        || !bindText(statement.get(), 3, file.name, error)
        || !bindText(statement.get(), 4, file.mimeType, error)
        || sqlite3_bind_int64(statement.get(), 5,
                              static_cast<sqlite3_int64>(file.sizeBytes))
            != SQLITE_OK
        || !bindText(statement.get(), 6, storageText(file.storage), error)) {
        rollback();
        return false;
    }

    if (file.storage == FileStorage::Embedded) {
        if (!bindBlob(statement.get(), 7, file.content, error)
            || sqlite3_bind_null(statement.get(), 9) != SQLITE_OK) {
            rollback();
            return false;
        }
    } else {
        if (sqlite3_bind_null(statement.get(), 7) != SQLITE_OK
            || !bindText(statement.get(), 9, file.externalName, error)) {
            rollback();
            return false;
        }
    }

    if (file.thumbnail.empty()) {
        if (sqlite3_bind_null(statement.get(), 8) != SQLITE_OK) {
            rollback();
            setDatabaseError(error, m_database.handle());
            return false;
        }
    } else if (!bindBlob(statement.get(), 8, file.thumbnail, error)) {
        rollback();
        return false;
    }

    if (sqlite3_bind_int64(statement.get(), 10, file.createdAt) != SQLITE_OK
        || sqlite3_bind_int64(statement.get(), 11, file.updatedAt) != SQLITE_OK) {
        rollback();
        setDatabaseError(error, m_database.handle());
        return false;
    }

    if (statement.step(error) != SQLITE_DONE) {
        rollback();
        return false;
    }
    if (!execute(m_database.handle(), "COMMIT;", error)) {
        rollback();
        return false;
    }
    return true;
}

bool FileRepository::listForItem(const std::string &itemId,
                                 std::vector<FileRecord> *files,
                                 std::string *error) const
{
    if (!files) {
        setError(error, "file list destination is null");
        return false;
    }
    files->clear();
    static constexpr const char *kSql =
        "SELECT id, item_id, name, mime_type, size_bytes, storage, external_name, "
        "       thumbnail, created_at, updated_at "
        "FROM t_file WHERE item_id = ? AND deleted_at IS NULL "
        "ORDER BY created_at, id;";
    Statement statement(m_database.handle(), kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, itemId, error))
        return false;

    while (true) {
        const int rc = statement.step(error);
        if (rc == SQLITE_DONE)
            return true;
        if (rc != SQLITE_ROW)
            return false;

        FileRecord file;
        file.id = columnText(statement.get(), 0);
        file.itemId = columnText(statement.get(), 1);
        file.name = columnText(statement.get(), 2);
        file.mimeType = columnText(statement.get(), 3);
        file.sizeBytes = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 4));
        file.storage = storageFromText(columnText(statement.get(), 5));
        file.externalName = columnText(statement.get(), 6);
        file.thumbnail = columnBytes(statement.get(), 7);
        file.createdAt = sqlite3_column_int64(statement.get(), 8);
        file.updatedAt = sqlite3_column_int64(statement.get(), 9);
        files->push_back(std::move(file));
    }
}

bool FileRepository::get(const std::string &id, FileRecord *file,
                         std::string *error) const
{
    if (!file) {
        setError(error, "file destination is null");
        return false;
    }
    static constexpr const char *kSql =
        "SELECT id, item_id, name, mime_type, size_bytes, storage, external_name, "
        "       content, thumbnail, created_at, updated_at "
        "FROM t_file WHERE id = ? AND deleted_at IS NULL;";
    Statement statement(m_database.handle(), kSql, error);
    if (!statement.ok() || !bindText(statement.get(), 1, id, error))
        return false;
    const int rc = statement.step(error);
    if (rc == SQLITE_DONE) {
        setError(error, "file was not found");
        return false;
    }
    if (rc != SQLITE_ROW)
        return false;

    file->id = columnText(statement.get(), 0);
    file->itemId = columnText(statement.get(), 1);
    file->name = columnText(statement.get(), 2);
    file->mimeType = columnText(statement.get(), 3);
    file->sizeBytes = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.get(), 4));
    file->storage = storageFromText(columnText(statement.get(), 5));
    file->externalName = columnText(statement.get(), 6);
    file->content = columnBytes(statement.get(), 7);
    file->thumbnail = columnBytes(statement.get(), 8);
    file->createdAt = sqlite3_column_int64(statement.get(), 9);
    file->updatedAt = sqlite3_column_int64(statement.get(), 10);
    return true;
}

bool FileRepository::softDelete(const std::string &id, std::string *error)
{
    static constexpr const char *kSql =
        "UPDATE t_file SET deleted_at = ?, updated_at = ? "
        "WHERE id = ? AND deleted_at IS NULL;";
    Statement statement(m_database.handle(), kSql, error);
    if (!statement.ok())
        return false;
    const std::int64_t now = nowMillis();
    if (sqlite3_bind_int64(statement.get(), 1, now) != SQLITE_OK
        || sqlite3_bind_int64(statement.get(), 2, now) != SQLITE_OK
        || !bindText(statement.get(), 3, id, error)) {
        setDatabaseError(error, m_database.handle());
        return false;
    }
    if (statement.step(error) != SQLITE_DONE)
        return false;
    return sqlite3_changes(m_database.handle()) > 0;
}

bool FileRepository::decryptThumbnail(const FileRecord &file,
                                      Bytes *plaintext,
                                      std::string *error) const
{
    if (!plaintext) {
        setError(error, "thumbnail destination is null");
        return false;
    }
    plaintext->clear();
    if (file.thumbnail.empty())
        return true;
    if (error)
        error->clear();
    *plaintext = crypto::decryptEmbedded(m_fek.span(), file.id + ":thumb",
                                         file.thumbnail, error);
    if (error)
        return error->empty();
    return !plaintext->empty();
}

std::string FileRepository::externalPath(const FileRecord &file) const
{
    return (std::filesystem::path(m_attachmentsDir)
            / (file.externalName.empty() ? file.id : file.externalName))
        .string();
}

std::unique_ptr<crypto::FileReader> FileRepository::openRead(
    const std::string &id, std::string *error) const
{
    FileRecord file;
    if (!get(id, &file, error))
        return nullptr;

    if (file.storage == FileStorage::External) {
        return crypto::ChunkedFileReader::open(
            m_fek.span(), file.id, externalPath(file), file.sizeBytes, error);
    }

    Bytes plaintext = crypto::decryptEmbedded(m_fek.span(), file.id,
                                              file.content, error);
    if (plaintext.empty() && file.sizeBytes != 0)
        return nullptr;
    return std::make_unique<crypto::MemoryFileReader>(std::move(plaintext));
}

} // namespace cryptowl::vault
