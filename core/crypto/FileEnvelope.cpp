#include "crypto/FileEnvelope.h"

#include "crypto/AesGcm.h"
#include "crypto/Random.h"
#include "crypto/Trace.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace cryptowl::crypto {

namespace {

constexpr std::size_t kKeyLength = 32;
constexpr std::size_t kNonceLength = 12;
constexpr std::size_t kTagLength = 16;
constexpr std::size_t kHeaderLength = 22;
constexpr std::array<std::uint8_t, 4> kMagic = {'C', 'W', 'O', '1'};
constexpr std::uint16_t kFormatVersion = 1;

void setError(std::string *error, std::string message)
{
    if (error)
        *error = std::move(message);
}

void appendBe16(Bytes *out, std::uint16_t value)
{
    out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<std::uint8_t>(value & 0xff));
}

void appendBe32(Bytes *out, std::uint32_t value)
{
    for (int shift = 24; shift >= 0; shift -= 8)
        out->push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

void appendBe64(Bytes *out, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
        out->push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

std::uint16_t readBe16(const std::uint8_t *data)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8)
                                     | static_cast<std::uint16_t>(data[1]));
}

std::uint32_t readBe32(const std::uint8_t *data)
{
    return (static_cast<std::uint32_t>(data[0]) << 24)
        | (static_cast<std::uint32_t>(data[1]) << 16)
        | (static_cast<std::uint32_t>(data[2]) << 8)
        | static_cast<std::uint32_t>(data[3]);
}

std::uint64_t readBe64(const std::uint8_t *data)
{
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
        value = (value << 8) | static_cast<std::uint64_t>(data[i]);
    return value;
}

Bytes makeNonce(std::uint64_t chunkIndex, std::span<const std::uint8_t> ivPrefix)
{
    Bytes nonce;
    nonce.reserve(kNonceLength);
    appendBe64(&nonce, chunkIndex);
    nonce.insert(nonce.end(), ivPrefix.begin(), ivPrefix.end());
    return nonce;
}

bool validKey(std::span<const std::uint8_t> key, std::string *error)
{
    if (key.size() != kKeyLength) {
        setError(error, "file key must be 32 bytes");
        return false;
    }
    return true;
}

std::uint64_t chunkCountFor(std::uint64_t plaintextSize)
{
    if (plaintextSize == 0)
        return 0;
    return (plaintextSize + kFileChunkSize - 1) / kFileChunkSize;
}

std::uint64_t expectedChunkLength(std::uint64_t plaintextSize,
                                  std::uint64_t index)
{
    const std::uint64_t start = index * kFileChunkSize;
    return std::min<std::uint64_t>(kFileChunkSize, plaintextSize - start);
}

std::uint64_t expectedFileLength(std::uint64_t plaintextSize,
                                 std::uint64_t chunkCount)
{
    if (chunkCount == 0)
        return kHeaderLength;
    const std::uint64_t fullChunks = chunkCount - 1;
    const std::uint64_t lastSize =
        plaintextSize - fullChunks * kFileChunkSize;
    return kHeaderLength + fullChunks * (kFileChunkSize + kTagLength)
        + lastSize + kTagLength;
}

bool readExact(std::istream &stream, std::uint8_t *data, std::size_t size,
               std::string *error)
{
    stream.read(reinterpret_cast<char *>(data), static_cast<std::streamsize>(size));
    if (stream.gcount() != static_cast<std::streamsize>(size)) {
        setError(error, "truncated encrypted file");
        return false;
    }
    return true;
}

} // namespace

Bytes encryptEmbedded(std::span<const std::uint8_t> key,
                      std::string_view fileId,
                      std::span<const std::uint8_t> plaintext,
                      std::string *error)
{
    if (!validKey(key, error))
        return {};
    try {
        const Bytes nonce = randomBytes(kNonceLength);
        const GcmCiphertext encrypted =
            aesGcmEncrypt(key, nonce, bytesOf(fileId), plaintext,
                          "file.encrypt.embedded");
        Bytes envelope;
        envelope.reserve(nonce.size() + encrypted.ciphertext.size()
                         + encrypted.tag.size());
        envelope.insert(envelope.end(), nonce.begin(), nonce.end());
        envelope.insert(envelope.end(), encrypted.ciphertext.begin(),
                        encrypted.ciphertext.end());
        envelope.insert(envelope.end(), encrypted.tag.begin(), encrypted.tag.end());
        return envelope;
    } catch (const std::exception &e) {
        setError(error, std::string("could not encrypt file: ") + e.what());
        return {};
    }
}

Bytes decryptEmbedded(std::span<const std::uint8_t> key,
                      std::string_view fileId,
                      std::span<const std::uint8_t> envelope,
                      std::string *error)
{
    if (!validKey(key, error))
        return {};
    if (envelope.size() < kNonceLength + kTagLength) {
        setError(error, "embedded file envelope is truncated");
        return {};
    }
    try {
        const auto nonce = envelope.first(kNonceLength);
        const auto tag = envelope.last(kTagLength);
        const auto ciphertext = envelope.subspan(
            kNonceLength, envelope.size() - kNonceLength - kTagLength);
        return aesGcmDecrypt(key, nonce, bytesOf(fileId), ciphertext, tag,
                             "file.decrypt.embedded");
    } catch (const std::exception &e) {
        setError(error, std::string("could not decrypt file: ") + e.what());
        return {};
    }
}

bool encryptChunkedFile(std::span<const std::uint8_t> key,
                        std::string_view fileId,
                        const std::string &sourcePath,
                        const std::string &destinationPath,
                        std::uint64_t plaintextSize,
                        std::string *error)
{
    if (!validKey(key, error))
        return false;

    std::error_code fileError;
    const std::uint64_t actualSize =
        std::filesystem::file_size(sourcePath, fileError);
    if (fileError) {
        setError(error, "could not stat source file: " + fileError.message());
        return false;
    }
    if (actualSize != plaintextSize) {
        setError(error, "source file size changed during import");
        return false;
    }

    const std::uint64_t chunkCount = chunkCountFor(plaintextSize);
    const Bytes ivPrefix = randomBytes(4);

    Bytes header;
    header.reserve(kHeaderLength);
    header.insert(header.end(), kMagic.begin(), kMagic.end());
    appendBe16(&header, kFormatVersion);
    appendBe32(&header, kFileChunkSize);
    appendBe64(&header, chunkCount);
    header.insert(header.end(), ivPrefix.begin(), ivPrefix.end());

    std::ifstream source(sourcePath, std::ios::binary);
    if (!source) {
        setError(error, "could not open source file");
        return false;
    }

    std::ofstream destination(destinationPath,
                              std::ios::binary | std::ios::trunc);
    if (!destination) {
        setError(error, "could not create encrypted file");
        return false;
    }
    destination.write(reinterpret_cast<const char *>(header.data()),
                      static_cast<std::streamsize>(header.size()));
    if (!destination) {
        setError(error, "could not write encrypted file header");
        return false;
    }

    Bytes chunk(kFileChunkSize);
    for (std::uint64_t index = 0; index < chunkCount; ++index) {
        const std::uint64_t length =
            expectedChunkLength(plaintextSize, index);
        source.read(reinterpret_cast<char *>(chunk.data()),
                    static_cast<std::streamsize>(length));
        if (source.gcount() != static_cast<std::streamsize>(length)) {
            destination.close();
            std::filesystem::remove(destinationPath, fileError);
            secureWipe(chunk);
            setError(error, "source file changed during import");
            return false;
        }

        try {
            const Bytes nonce = makeNonce(index, ivPrefix);
            const GcmCiphertext encrypted =
                aesGcmEncrypt(key, nonce, bytesOf(fileId),
                              std::span<const std::uint8_t>(chunk.data(), length),
                              "file.encrypt.chunk");
            destination.write(
                reinterpret_cast<const char *>(encrypted.ciphertext.data()),
                static_cast<std::streamsize>(encrypted.ciphertext.size()));
            destination.write(
                reinterpret_cast<const char *>(encrypted.tag.data()),
                static_cast<std::streamsize>(encrypted.tag.size()));
            if (!destination) {
                throw std::runtime_error("could not write encrypted chunk");
            }
        } catch (const std::exception &e) {
            destination.close();
            std::filesystem::remove(destinationPath, fileError);
            setError(error, std::string("could not encrypt file: ") + e.what());
            secureWipe(chunk);
            return false;
        }
    }

    destination.flush();
    if (!destination) {
        destination.close();
        std::filesystem::remove(destinationPath, fileError);
        setError(error, "could not flush encrypted file");
        return false;
    }
    secureWipe(chunk);
    return true;
}

MemoryFileReader::MemoryFileReader(Bytes plaintext)
    : m_plaintext(std::move(plaintext))
{
}

MemoryFileReader::~MemoryFileReader()
{
    secureWipe(m_plaintext);
}

std::size_t MemoryFileReader::read(std::uint64_t offset,
                                   std::span<std::uint8_t> buffer,
                                   std::string *error)
{
    (void)error;
    if (offset >= m_plaintext.size() || buffer.empty())
        return 0;
    const std::size_t available =
        m_plaintext.size() - static_cast<std::size_t>(offset);
    const std::size_t amount = std::min(buffer.size(), available);
    std::copy_n(m_plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                amount, buffer.begin());
    return amount;
}

ChunkedFileReader::~ChunkedFileReader() = default;

std::unique_ptr<ChunkedFileReader> ChunkedFileReader::open(
    std::span<const std::uint8_t> key, std::string_view fileId,
    const std::string &path, std::uint64_t plaintextSize, std::string *error)
{
    auto reader = std::unique_ptr<ChunkedFileReader>(new ChunkedFileReader());
    if (!reader->openFile(key, fileId, path, plaintextSize, error))
        return nullptr;
    return reader;
}

bool ChunkedFileReader::openFile(std::span<const std::uint8_t> key,
                                 std::string_view fileId,
                                 const std::string &path,
                                 std::uint64_t plaintextSize,
                                 std::string *error)
{
    if (!validKey(key, error))
        return false;

    std::error_code fileError;
    const std::uint64_t actualSize =
        std::filesystem::file_size(path, fileError);
    if (fileError) {
        setError(error, "could not stat encrypted file: " + fileError.message());
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        setError(error, "could not open encrypted file");
        return false;
    }

    Bytes header(kHeaderLength);
    if (!readExact(file, header.data(), header.size(), error))
        return false;
    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin())) {
        setError(error, "encrypted file has an invalid magic");
        return false;
    }
    const std::uint16_t version = readBe16(header.data() + 4);
    const std::uint32_t chunkSize = readBe32(header.data() + 6);
    const std::uint64_t chunkCount = readBe64(header.data() + 10);
    if (version != kFormatVersion) {
        setError(error, "unsupported encrypted file version");
        return false;
    }
    if (chunkSize != kFileChunkSize) {
        setError(error, "unsupported encrypted file chunk size");
        return false;
    }
    if (chunkCount != chunkCountFor(plaintextSize)) {
        setError(error, "encrypted file chunk count does not match its size");
        return false;
    }
    if (actualSize != expectedFileLength(plaintextSize, chunkCount)) {
        setError(error, "encrypted file length is invalid");
        return false;
    }

    m_key = ProtectedValue(Bytes(key.begin(), key.end()));
    m_fileId.assign(fileId);
    m_path = path;
    m_plaintextSize = plaintextSize;
    m_chunkCount = chunkCount;
    m_chunkSize = chunkSize;
    m_ivPrefix.assign(header.begin() + 18, header.end());
    m_file = std::move(file);
    return true;
}

bool ChunkedFileReader::readChunk(std::uint64_t index, Bytes *plaintext,
                                  std::string *error)
{
    if (index >= m_chunkCount) {
        setError(error, "encrypted file chunk index is out of range");
        return false;
    }
    const std::uint64_t length = expectedChunkLength(m_plaintextSize, index);
    const std::uint64_t offset =
        kHeaderLength + index * (m_chunkSize + kTagLength);

    Bytes ciphertext(length);
    Bytes tag(kTagLength);
    m_file.clear();
    m_file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!m_file) {
        setError(error, "could not seek encrypted file");
        return false;
    }
    if (!readExact(m_file, ciphertext.data(), ciphertext.size(), error)) {
        secureWipe(ciphertext);
        return false;
    }
    if (!readExact(m_file, tag.data(), tag.size(), error)) {
        secureWipe(ciphertext);
        return false;
    }

    try {
        const Bytes nonce = makeNonce(index, m_ivPrefix);
        *plaintext = aesGcmDecrypt(m_key.span(), nonce, bytesOf(m_fileId),
                                   ciphertext, tag, "file.decrypt.chunk");
        secureWipe(ciphertext);
        return true;
    } catch (const std::exception &e) {
        secureWipe(ciphertext);
        setError(error, std::string("could not decrypt file chunk: ") + e.what());
        return false;
    }
}

std::size_t ChunkedFileReader::read(std::uint64_t offset,
                                    std::span<std::uint8_t> buffer,
                                    std::string *error)
{
    if (offset >= m_plaintextSize || buffer.empty())
        return 0;

    const std::lock_guard<std::mutex> lock(m_mutex);
    const std::uint64_t available = m_plaintextSize - offset;
    const std::size_t requested = static_cast<std::size_t>(
        std::min<std::uint64_t>(available, buffer.size()));
    std::size_t copied = 0;

    while (copied < requested) {
        const std::uint64_t position = offset + copied;
        const std::uint64_t index = position / m_chunkSize;
        const std::uint64_t chunkStart = index * m_chunkSize;
        const std::uint64_t inChunk = position - chunkStart;

        Bytes plaintext;
        if (!readChunk(index, &plaintext, error))
            return 0;
        if (plaintext.size() <= inChunk) {
            secureWipe(plaintext);
            setError(error, "encrypted file chunk is truncated");
            return 0;
        }

        const std::size_t amount = static_cast<std::size_t>(
            std::min<std::uint64_t>(requested - copied,
                                    plaintext.size() - inChunk));
        std::copy_n(plaintext.begin() + static_cast<std::ptrdiff_t>(inChunk),
                    amount, buffer.begin() + static_cast<std::ptrdiff_t>(copied));
        secureWipe(plaintext);
        copied += amount;
    }
    return copied;
}

} // namespace cryptowl::crypto
