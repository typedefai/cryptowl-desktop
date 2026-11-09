#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/FileRepository.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"
#include "vault/VirtualMediaFs.h"
#include "vfs/FuseMount.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

#include <algorithm>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#ifndef Q_OS_WIN
#include <fcntl.h>
#include <unistd.h>
#endif

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::ImportFile;
using cryptowl::vault::NewItem;
using cryptowl::vault::VaultDatabase;
using cryptowl::vault::VaultSession;
using cryptowl::vault::VirtualMediaFs;

namespace {

const Bytes kVaultKey(32, 0x44);
const Bytes kSmk(64, 0x33);

Bytes makeData(std::size_t size)
{
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i)
        data[i] = static_cast<std::uint8_t>((i * 13 + 3) & 0xff);
    return data;
}

} // namespace

class TestFuseMount : public QObject
{
    Q_OBJECT

private slots:
    void mountsAndReadsMedia();
};

void TestFuseMount::mountsAndReadsMedia()
{
    if (!FuseMount::isAvailable())
        QSKIP("FUSE backend was not built.");

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = VaultSession::open(
        databasePath.toStdString(), ProtectedValue(Bytes(kVaultKey)),
        ProtectedValue(Bytes(kSmk)), &error, true, 1024);
    QVERIFY2(session != nullptr, error.c_str());

    NewItem item;
    item.type = "photo";
    item.classification = "C";
    item.title = "Fuse Photo";
    item.meta = "{}";
    std::string itemId;
    QVERIFY2(session->items().create(item, &itemId, &error), error.c_str());

    const Bytes plaintext = makeData(137);
    const QString sourcePath = dir.filePath(QStringLiteral("photo.bin"));
    {
        std::ofstream source(sourcePath.toStdString(), std::ios::binary);
        source.write(reinterpret_cast<const char *>(plaintext.data()),
                     static_cast<std::streamsize>(plaintext.size()));
    }

    ImportFile file;
    file.itemId = itemId;
    file.name = "photo.png";
    file.mimeType = "image/png";
    file.sourcePath = sourcePath.toStdString();
    std::string fileId;
    QVERIFY2(session->files().import(file, &fileId, &error), error.c_str());

    VirtualMediaFs fs(*session);
    fs.refresh(&error);
    QVERIFY2(error.empty(), error.c_str());
    std::vector<cryptowl::vault::VfsEntry> entries;
    QVERIFY2(fs.list("/Photos", &entries, &error), error.c_str());
    QCOMPARE(entries.size(), std::size_t(1));

    QTemporaryDir mountDir;
    QVERIFY(mountDir.isValid());
    FuseMount mount;
    QString mountError;
    QVERIFY2(mount.mount(mountDir.path(), &fs, &mountError),
             qPrintable(mountError));
    QVERIFY(mount.isMounted());
    QTest::qWait(500);

    QDir root(mountDir.path());
    const QStringList rootEntries =
        root.entryList(QDir::AllEntries | QDir::NoDotAndDotDot);
    const QStringList photoEntries =
        QDir(mountDir.filePath(QStringLiteral("Photos")))
            .entryList(QDir::AllEntries | QDir::NoDotAndDotDot);

    const QString mountedPath = mountDir.filePath(
        QString::fromStdString(entries.front().path.substr(1)));
    QFile mountedFile(mountedPath);
    const bool opened = mountedFile.open(QIODevice::ReadOnly);
    const QString openError = mountedFile.errorString();
    QByteArray mountedData;
    if (opened)
        mountedData = mountedFile.readAll();
    mountedFile.close();

#ifndef Q_OS_WIN
    const int directoryFd =
        ::open(mountDir.filePath(QStringLiteral("Photos")).toUtf8().constData(),
               O_RDONLY);
#endif
    QString unmountError;
    QVERIFY2(mount.unmount(&unmountError), qPrintable(unmountError));
#ifndef Q_OS_WIN
    if (directoryFd >= 0)
        ::close(directoryFd);
#endif
    QVERIFY2(opened, qPrintable(openError));
    QVERIFY(!rootEntries.isEmpty());
    QVERIFY(!photoEntries.isEmpty());
    QCOMPARE(mountedData.size(), static_cast<int>(plaintext.size()));
    QVERIFY(std::equal(plaintext.begin(), plaintext.end(),
                       reinterpret_cast<const std::uint8_t *>(
                           mountedData.constData())));
    QVERIFY(!mount.isMounted());
}

QTEST_APPLESS_MAIN(TestFuseMount)
#include "tst_fusemount.moc"
