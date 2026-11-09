#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/FileRepository.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"

#include <QTemporaryDir>
#include <QtTest>

#include <fstream>
#include <memory>
#include <string>
#include <vector>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::FileRecord;
using cryptowl::vault::FileRepository;
using cryptowl::vault::FileStorage;
using cryptowl::vault::ImportFile;
using cryptowl::vault::ItemRepository;
using cryptowl::vault::NewItem;
using cryptowl::vault::VaultDatabase;
using cryptowl::vault::VaultSession;

namespace {

const Bytes kVaultKey(32, 0x44);
const Bytes kSmk(64, 0x33);

std::unique_ptr<VaultSession> openSession(const QString &databasePath,
                                          std::uint64_t embedMaxBytes,
                                          std::string *error)
{
    return VaultSession::open(databasePath.toStdString(),
                              ProtectedValue(Bytes(kVaultKey)),
                              ProtectedValue(Bytes(kSmk)), error, true,
                              embedMaxBytes);
}

QString writeSource(const QTemporaryDir &dir, const QString &name,
                    const Bytes &data)
{
    const QString path = dir.filePath(name);
    std::ofstream out(path.toStdString(), std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
    out.close();
    return path;
}

Bytes makeData(std::size_t size)
{
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<std::uint8_t>((i * 29 + 7) & 0xff);
    return data;
}

Bytes readAll(cryptowl::crypto::FileReader &reader, std::string *error)
{
    Bytes data(static_cast<std::size_t>(reader.size()));
    const std::size_t count = reader.read(0, data, error);
    if (count != data.size())
        data.clear();
    return data;
}

std::string createPhoto(ItemRepository &items)
{
    NewItem item;
    item.type = "photo";
    item.classification = "C";
    item.title = "Photo";
    item.meta = "{}";
    item.payload = "";
    std::string id;
    std::string error;
    if (!items.create(item, &id, &error))
        return {};
    return id;
}

} // namespace

class TestFileRepository : public QObject
{
    Q_OBJECT

private slots:
    void embeddedAndExternalRoundTrip();
    void decryptsThumbnail();
    void softDeleteHidesFile();
};

void TestFileRepository::embeddedAndExternalRoundTrip()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, 64, &error);
    QVERIFY2(session != nullptr, error.c_str());
    const std::string itemId = createPhoto(session->items());
    QVERIFY2(!itemId.empty(), error.c_str());

    const Bytes small = makeData(64);
    const QString smallPath = writeSource(dir, QStringLiteral("small.bin"), small);
    ImportFile smallFile;
    smallFile.itemId = itemId;
    smallFile.name = "small.bin";
    smallFile.mimeType = "application/octet-stream";
    smallFile.sourcePath = smallPath.toStdString();
    std::string smallId;
    QVERIFY2(session->files().import(smallFile, &smallId, &error),
             error.c_str());
    FileRecord smallRecord;
    QVERIFY2(session->files().get(smallId, &smallRecord, &error), error.c_str());
    QCOMPARE(smallRecord.storage, FileStorage::Embedded);
    QCOMPARE(smallRecord.sizeBytes, static_cast<std::uint64_t>(small.size()));

    auto smallReader = session->files().openRead(smallId, &error);
    QVERIFY2(smallReader != nullptr, error.c_str());
    QVERIFY(readAll(*smallReader, &error) == small);
    QVERIFY2(error.empty(), error.c_str());

    const Bytes large = makeData(257);
    const QString largePath = writeSource(dir, QStringLiteral("large.bin"), large);
    ImportFile largeFile = smallFile;
    largeFile.name = "large.bin";
    largeFile.sourcePath = largePath.toStdString();
    std::string largeId;
    QVERIFY2(session->files().import(largeFile, &largeId, &error), error.c_str());
    FileRecord largeRecord;
    QVERIFY2(session->files().get(largeId, &largeRecord, &error), error.c_str());
    QCOMPARE(largeRecord.storage, FileStorage::External);
    QCOMPARE(largeRecord.sizeBytes, static_cast<std::uint64_t>(large.size()));

    auto largeReader = session->files().openRead(largeId, &error);
    QVERIFY2(largeReader != nullptr, error.c_str());
    QVERIFY(readAll(*largeReader, &error) == large);
    QVERIFY2(error.empty(), error.c_str());

    std::vector<FileRecord> files;
    QVERIFY2(session->files().listForItem(itemId, &files, &error), error.c_str());
    QCOMPARE(files.size(), std::size_t(2));
}

void TestFileRepository::decryptsThumbnail()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, 1024, &error);
    QVERIFY2(session != nullptr, error.c_str());
    const std::string itemId = createPhoto(session->items());
    QVERIFY(!itemId.empty());

    const Bytes source = makeData(10);
    const Bytes thumbnail = makeData(31);
    const QString path = writeSource(dir, QStringLiteral("image.bin"), source);
    ImportFile file;
    file.itemId = itemId;
    file.name = "image.bin";
    file.mimeType = "image/png";
    file.sourcePath = path.toStdString();
    file.thumbnailPlaintext = thumbnail;
    std::string id;
    QVERIFY2(session->files().import(file, &id, &error), error.c_str());

    FileRecord record;
    QVERIFY2(session->files().get(id, &record, &error), error.c_str());
    QVERIFY(!record.thumbnail.empty());
    Bytes plaintext;
    QVERIFY2(session->files().decryptThumbnail(record, &plaintext, &error),
             error.c_str());
    QVERIFY(plaintext == thumbnail);
}

void TestFileRepository::softDeleteHidesFile()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, 1024, &error);
    QVERIFY2(session != nullptr, error.c_str());
    const std::string itemId = createPhoto(session->items());
    QVERIFY(!itemId.empty());

    const Bytes source = makeData(10);
    const QString path = writeSource(dir, QStringLiteral("image.bin"), source);
    ImportFile file;
    file.itemId = itemId;
    file.name = "image.bin";
    file.mimeType = "image/png";
    file.sourcePath = path.toStdString();
    std::string id;
    QVERIFY2(session->files().import(file, &id, &error), error.c_str());

    QVERIFY2(session->files().softDelete(id, &error), error.c_str());
    std::vector<FileRecord> files;
    QVERIFY2(session->files().listForItem(itemId, &files, &error), error.c_str());
    QVERIFY(files.empty());
    QVERIFY(!session->files().get(id, &files.emplace_back(), &error));
}

QTEST_APPLESS_MAIN(TestFileRepository)
#include "tst_filerepository.moc"
