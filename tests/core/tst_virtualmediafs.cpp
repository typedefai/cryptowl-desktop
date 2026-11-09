#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/FileRepository.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"
#include "vault/VirtualMediaFs.h"

#include <QTemporaryDir>
#include <QtTest>

#include <fstream>
#include <memory>
#include <string>
#include <vector>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::FileRepository;
using cryptowl::vault::ImportFile;
using cryptowl::vault::ItemRepository;
using cryptowl::vault::NewItem;
using cryptowl::vault::VaultDatabase;
using cryptowl::vault::VaultSession;
using cryptowl::vault::VfsEntry;
using cryptowl::vault::VfsEntryKind;
using cryptowl::vault::VirtualMediaFs;

namespace {

const Bytes kVaultKey(32, 0x44);
const Bytes kSmk(64, 0x33);

std::unique_ptr<VaultSession> openSession(const QString &databasePath,
                                          std::string *error)
{
    return VaultSession::open(databasePath.toStdString(),
                              ProtectedValue(Bytes(kVaultKey)),
                              ProtectedValue(Bytes(kSmk)), error, true, 1024);
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
        data[i] = static_cast<std::uint8_t>((i * 17 + 5) & 0xff);
    return data;
}

std::string createMediaItem(ItemRepository &items, const std::string &type,
                            const std::string &title)
{
    NewItem item;
    item.type = type;
    item.classification = "C";
    item.title = title;
    item.meta = "{}";
    std::string id;
    std::string error;
    if (!items.create(item, &id, &error))
        return {};
    return id;
}

bool addFile(FileRepository &files, const std::string &itemId,
             const QString &path, const QString &name, const QString &mime)
{
    ImportFile file;
    file.itemId = itemId;
    file.name = name.toStdString();
    file.mimeType = mime.toStdString();
    file.sourcePath = path.toStdString();
    std::string id;
    std::string error;
    return files.import(file, &id, &error);
}

} // namespace

class TestVirtualMediaFs : public QObject
{
    Q_OBJECT

private slots:
    void listsAndReadsMedia();
    void rejectsUnsafeOrMissingPaths();
    void hidesNonConfidentialMedia();
};

void TestVirtualMediaFs::listsAndReadsMedia()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, &error);
    QVERIFY2(session != nullptr, error.c_str());

    const std::string photoId =
        createMediaItem(session->items(), "photo", "Sunset");
    QVERIFY(!photoId.empty());
    const Bytes photoData = makeData(23);
    const QString photoPath =
        writeSource(dir, QStringLiteral("sunset.png"), photoData);
    QVERIFY(addFile(session->files(), photoId, photoPath,
                    QStringLiteral("sunset.png"), QStringLiteral("image/png")));

    const std::string videoId =
        createMediaItem(session->items(), "video", "Trip");
    QVERIFY(!videoId.empty());
    const Bytes videoData = makeData(100);
    const QString videoPath =
        writeSource(dir, QStringLiteral("trip.mp4"), videoData);
    QVERIFY(addFile(session->files(), videoId, videoPath,
                    QStringLiteral("trip.mp4"), QStringLiteral("video/mp4")));

    VirtualMediaFs fs(*session);
    fs.refresh(&error);
    QVERIFY2(error.empty(), error.c_str());

    std::vector<VfsEntry> root;
    QVERIFY2(fs.list("/", &root, &error), error.c_str());
    QCOMPARE(root.size(), std::size_t(2));
    QCOMPARE(root[0].name, std::string("Photos"));
    QCOMPARE(root[1].name, std::string("Videos"));

    std::vector<VfsEntry> photos;
    QVERIFY2(fs.list("/Photos", &photos, &error), error.c_str());
    QCOMPARE(photos.size(), std::size_t(1));
    QCOMPARE(photos[0].kind, VfsEntryKind::File);
    QCOMPARE(photos[0].name, std::string("Sunset.png"));

    auto reader = fs.open(photos[0].path, &error);
    QVERIFY2(reader != nullptr, error.c_str());
    Bytes output(static_cast<std::size_t>(reader->size()));
    QCOMPARE(reader->read(0, output, &error), output.size());
    QVERIFY(output == photoData);
}

void TestVirtualMediaFs::rejectsUnsafeOrMissingPaths()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, &error);
    QVERIFY2(session != nullptr, error.c_str());
    VirtualMediaFs fs(*session);
    fs.refresh(&error);

    VfsEntry entry;
    QVERIFY(!fs.stat("/", nullptr, &error));
    QVERIFY(!fs.stat("/missing", &entry, &error));
    QVERIFY(!fs.stat("/Photos/../Videos", &entry, &error));
    QVERIFY(!fs.open("/Photos", &error));
}

void TestVirtualMediaFs::hidesNonConfidentialMedia()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, &error);
    QVERIFY2(session != nullptr, error.c_str());

    NewItem item;
    item.type = "photo";
    item.classification = "S";
    item.title = "Secret";
    item.meta = "{}";
    item.payload = "{}";
    std::string itemId;
    QVERIFY2(session->items().create(item, &itemId, &error), error.c_str());

    VirtualMediaFs fs(*session);
    fs.refresh(&error);
    std::vector<VfsEntry> entries;
    QVERIFY2(fs.list("/Photos", &entries, &error), error.c_str());
    QVERIFY(entries.empty());
}

QTEST_APPLESS_MAIN(TestVirtualMediaFs)
#include "tst_virtualmediafs.moc"
