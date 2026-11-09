#include "crypto/Bytes.h"
#include "crypto/FileEnvelope.h"

#include <QTemporaryDir>
#include <QtTest>

#include <fstream>
#include <memory>
#include <string>
#include <vector>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ChunkedFileReader;
using cryptowl::crypto::decryptEmbedded;
using cryptowl::crypto::encryptChunkedFile;
using cryptowl::crypto::encryptEmbedded;
using cryptowl::crypto::kFileChunkSize;

namespace {

const Bytes kKey(32, 0x42);
const std::string kFileId = "file-1234";

Bytes makeData(std::size_t size)
{
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<std::uint8_t>((i * 37 + 11) & 0xff);
    return data;
}

QString writeSource(const QTemporaryDir &dir, const Bytes &data)
{
    const QString path = dir.filePath(QStringLiteral("source.bin"));
    std::ofstream out(path.toStdString(), std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
    out.close();
    return path;
}

Bytes readAll(ChunkedFileReader &reader, std::string *error)
{
    Bytes output(static_cast<std::size_t>(reader.size()));
    const std::size_t read = reader.read(0, output, error);
    if (read != output.size())
        output.clear();
    return output;
}

} // namespace

class TestFileEnvelope : public QObject
{
    Q_OBJECT

private slots:
    void embeddedRoundTrip();
    void embeddedRejectsTamper();
    void chunkedRoundTrip();
    void chunkedRandomAccess();
    void chunkedRejectsWrongFileId();
    void chunkedRejectsBadLength();
    void chunkedRejectsTruncatedFile();
};

void TestFileEnvelope::embeddedRoundTrip()
{
    for (const std::size_t size : {std::size_t(0), std::size_t(1),
                                   std::size_t(12), std::size_t(512 * 1024)}) {
        const Bytes plaintext = makeData(size);
        std::string error;
        const Bytes envelope =
            encryptEmbedded(kKey, kFileId, plaintext, &error);
        QVERIFY2(!envelope.empty() || size == 0, error.c_str());
        QVERIFY2(envelope.size() == size + 28, error.c_str());

        const Bytes decrypted =
            decryptEmbedded(kKey, kFileId, envelope, &error);
        QVERIFY2(error.empty(), error.c_str());
        QVERIFY(decrypted == plaintext);
    }
}

void TestFileEnvelope::embeddedRejectsTamper()
{
    const Bytes plaintext = makeData(1024);
    std::string error;
    Bytes envelope = encryptEmbedded(kKey, kFileId, plaintext, &error);
    QVERIFY2(error.empty(), error.c_str());
    QVERIFY(!envelope.empty());
    envelope[20] ^= 0x01;

    const Bytes decrypted =
        decryptEmbedded(kKey, kFileId, envelope, &error);
    QVERIFY(decrypted.empty());
    QVERIFY(!error.empty());
}

void TestFileEnvelope::chunkedRoundTrip()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    for (const std::size_t size : {std::size_t(0), std::size_t(1),
                                   std::size_t(kFileChunkSize - 1),
                                   std::size_t(kFileChunkSize),
                                   std::size_t(kFileChunkSize + 1),
                                   std::size_t(kFileChunkSize * 3 + 17)}) {
        const Bytes plaintext = makeData(size);
        const QString source = writeSource(dir, plaintext);
        const QString destination =
            dir.filePath(QStringLiteral("encrypted.cwo"));

        std::string error;
        QVERIFY2(encryptChunkedFile(kKey, kFileId, source.toStdString(),
                                    destination.toStdString(), plaintext.size(),
                                    &error),
                 error.c_str());

        auto reader = ChunkedFileReader::open(
            kKey, kFileId, destination.toStdString(), plaintext.size(), &error);
        QVERIFY2(reader != nullptr, error.c_str());
        QCOMPARE(reader->size(), static_cast<std::uint64_t>(plaintext.size()));
        const Bytes decrypted = readAll(*reader, &error);
        QVERIFY2(error.empty(), error.c_str());
        QVERIFY(decrypted == plaintext);
    }
}

void TestFileEnvelope::chunkedRandomAccess()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    const Bytes plaintext = makeData(kFileChunkSize * 4 + 123);
    const QString source = writeSource(dir, plaintext);
    const QString destination =
        dir.filePath(QStringLiteral("encrypted.cwo"));

    std::string error;
    QVERIFY2(encryptChunkedFile(kKey, kFileId, source.toStdString(),
                                destination.toStdString(), plaintext.size(),
                                &error),
             error.c_str());
    auto reader = ChunkedFileReader::open(
        kKey, kFileId, destination.toStdString(), plaintext.size(), &error);
    QVERIFY2(reader != nullptr, error.c_str());

    const std::vector<std::pair<std::uint64_t, std::size_t>> reads = {
        {0, 31},
        {kFileChunkSize - 7, 32},
        {kFileChunkSize * 2, kFileChunkSize + 11},
        {static_cast<std::uint64_t>(plaintext.size()) - 5, 5},
        {static_cast<std::uint64_t>(plaintext.size()), 10},
    };
    for (const auto &[offset, length] : reads) {
        Bytes buffer(length);
        const std::size_t read = reader->read(offset, buffer, &error);
        QVERIFY2(error.empty(), error.c_str());
        const std::size_t expected =
            offset >= plaintext.size()
            ? 0
            : std::min<std::size_t>(length, plaintext.size() - offset);
        QCOMPARE(read, expected);
        QVERIFY(Bytes(buffer.begin(), buffer.begin() + expected)
                == Bytes(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                         plaintext.begin()
                             + static_cast<std::ptrdiff_t>(offset + expected)));
    }
}

void TestFileEnvelope::chunkedRejectsWrongFileId()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const Bytes plaintext = makeData(1000);
    const QString source = writeSource(dir, plaintext);
    const QString destination =
        dir.filePath(QStringLiteral("encrypted.cwo"));

    std::string error;
    QVERIFY2(encryptChunkedFile(kKey, kFileId, source.toStdString(),
                                destination.toStdString(), plaintext.size(),
                                &error),
             error.c_str());
    auto reader = ChunkedFileReader::open(
        kKey, "different-file", destination.toStdString(), plaintext.size(),
        &error);
    QVERIFY2(reader != nullptr, error.c_str());

    Bytes output(plaintext.size());
    QCOMPARE(reader->read(0, output, &error), std::size_t(0));
    QVERIFY(!error.empty());
}

void TestFileEnvelope::chunkedRejectsBadLength()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const Bytes plaintext = makeData(1000);
    const QString source = writeSource(dir, plaintext);
    const QString destination =
        dir.filePath(QStringLiteral("encrypted.cwo"));

    std::string error;
    QVERIFY2(encryptChunkedFile(kKey, kFileId, source.toStdString(),
                                destination.toStdString(), plaintext.size(),
                                &error),
             error.c_str());
    auto reader = ChunkedFileReader::open(
        kKey, kFileId, destination.toStdString(), plaintext.size() + 1, &error);
    QVERIFY(reader == nullptr);
    QVERIFY(!error.empty());
}

void TestFileEnvelope::chunkedRejectsTruncatedFile()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const Bytes plaintext = makeData(kFileChunkSize + 10);
    const QString source = writeSource(dir, plaintext);
    const QString destination =
        dir.filePath(QStringLiteral("encrypted.cwo"));

    std::string error;
    QVERIFY2(encryptChunkedFile(kKey, kFileId, source.toStdString(),
                                destination.toStdString(), plaintext.size(),
                                &error),
             error.c_str());

    QFile file(destination);
    QVERIFY(file.open(QIODevice::ReadWrite));
    QVERIFY(file.resize(file.size() - 1));
    file.close();

    auto reader = ChunkedFileReader::open(
        kKey, kFileId, destination.toStdString(), plaintext.size(), &error);
    QVERIFY(reader == nullptr);
    QVERIFY(!error.empty());
}

QTEST_APPLESS_MAIN(TestFileEnvelope)
#include "tst_fileenvelope.moc"
