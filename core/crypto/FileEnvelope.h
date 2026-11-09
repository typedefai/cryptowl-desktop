#pragma once

#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"

#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

namespace cryptowl::crypto {

constexpr std::uint32_t kFileChunkSize = 64 * 1024;

// Whole-file envelope used for embedded t_file.content rows.
Bytes encryptEmbedded(std::span<const std::uint8_t> key,
                      std::string_view fileId,
                      std::span<const std::uint8_t> plaintext,
                      std::string *error = nullptr);

Bytes decryptEmbedded(std::span<const std::uint8_t> key,
                      std::string_view fileId,
                      std::span<const std::uint8_t> envelope,
                      std::string *error = nullptr);

// Streams sourcePath into a CWO1 chunked envelope at destinationPath. The
// caller is responsible for using a temporary destination and renaming it.
bool encryptChunkedFile(std::span<const std::uint8_t> key,
                        std::string_view fileId,
                        const std::string &sourcePath,
                        const std::string &destinationPath,
                        std::uint64_t plaintextSize,
                        std::string *error = nullptr);

class FileReader
{
public:
    virtual ~FileReader() = default;

    virtual std::uint64_t size() const = 0;
    virtual std::size_t read(std::uint64_t offset,
                             std::span<std::uint8_t> buffer,
                             std::string *error = nullptr) = 0;
};

class MemoryFileReader : public FileReader
{
public:
    explicit MemoryFileReader(Bytes plaintext);
    ~MemoryFileReader() override;

    std::uint64_t size() const override
    {
        return m_plaintext.size();
    }

    std::size_t read(std::uint64_t offset, std::span<std::uint8_t> buffer,
                     std::string *error = nullptr) override;

private:
    Bytes m_plaintext;
};

class ChunkedFileReader : public FileReader
{
public:
    ~ChunkedFileReader() override;
    ChunkedFileReader(const ChunkedFileReader &) = delete;
    ChunkedFileReader &operator=(const ChunkedFileReader &) = delete;

    static std::unique_ptr<ChunkedFileReader> open(
        std::span<const std::uint8_t> key, std::string_view fileId,
        const std::string &path, std::uint64_t plaintextSize,
        std::string *error = nullptr);

    std::uint64_t size() const override
    {
        return m_plaintextSize;
    }

    // Copies plaintext bytes starting at offset. Returns the number of bytes
    // copied, or 0 on error (with *error set).
    std::size_t read(std::uint64_t offset, std::span<std::uint8_t> buffer,
                     std::string *error = nullptr) override;

private:
    ChunkedFileReader() = default;

    bool openFile(std::span<const std::uint8_t> key, std::string_view fileId,
                  const std::string &path, std::uint64_t plaintextSize,
                  std::string *error);
    bool readChunk(std::uint64_t index, Bytes *plaintext, std::string *error);

    ProtectedValue m_key;
    std::string m_fileId;
    std::string m_path;
    std::uint64_t m_plaintextSize = 0;
    std::uint64_t m_chunkCount = 0;
    std::uint32_t m_chunkSize = 0;
    Bytes m_ivPrefix;
    std::ifstream m_file;
    mutable std::mutex m_mutex;
};

} // namespace cryptowl::crypto
