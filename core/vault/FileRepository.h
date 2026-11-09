#pragma once

#include "crypto/Bytes.h"
#include "crypto/FileEnvelope.h"
#include "crypto/ProtectedValue.h"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

struct sqlite3;

namespace cryptowl::vault {

class VaultDatabase;

constexpr std::uint64_t kDefaultEmbedMaxBytes = 512 * 1024;

enum class FileStorage
{
    Embedded,
    External,
};

struct FileRecord
{
    std::string id;
    std::string itemId;
    std::string name;
    std::string mimeType;
    std::uint64_t sizeBytes = 0;
    FileStorage storage = FileStorage::Embedded;
    std::string externalName;
    crypto::Bytes content;
    crypto::Bytes thumbnail;
    std::int64_t createdAt = 0;
    std::int64_t updatedAt = 0;
};

struct ImportFile
{
    std::string itemId;
    std::string name;
    std::string mimeType;
    std::string sourcePath;
    crypto::Bytes thumbnailPlaintext;
};

class FileRepository
{
public:
    FileRepository(VaultDatabase &database, std::string attachmentsDir,
                   std::span<const std::uint8_t> vaultKey,
                   std::uint64_t embedMaxBytes = kDefaultEmbedMaxBytes);

    bool import(const ImportFile &file, std::string *id,
                std::string *error = nullptr);

    bool listForItem(const std::string &itemId,
                     std::vector<FileRecord> *files,
                     std::string *error = nullptr) const;
    bool get(const std::string &id, FileRecord *file,
             std::string *error = nullptr) const;
    bool softDelete(const std::string &id, std::string *error = nullptr);
    bool decryptThumbnail(const FileRecord &file, crypto::Bytes *plaintext,
                          std::string *error = nullptr) const;

    std::unique_ptr<crypto::FileReader> openRead(
        const std::string &id, std::string *error = nullptr) const;

    std::uint64_t embedMaxBytes() const
    {
        return m_embedMaxBytes;
    }

private:
    bool insert(const FileRecord &file, std::string *error);
    std::string externalPath(const FileRecord &file) const;

    VaultDatabase &m_database;
    std::string m_attachmentsDir;
    crypto::ProtectedValue m_fek;
    std::uint64_t m_embedMaxBytes = kDefaultEmbedMaxBytes;
};

} // namespace cryptowl::vault
