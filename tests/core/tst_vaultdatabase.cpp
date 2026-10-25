#include "crypto/Bytes.h"
#include "vault/VaultDatabase.h"

#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>

using namespace cryptowl::crypto;
using cryptowl::vault::VaultDatabase;

class TestVaultDatabase : public QObject
{
    Q_OBJECT

private slots:
    void createsEncryptedDatabase();
    void verifiesWithCorrectKey();
    void rejectsWrongKey();
    void rejectsExistingDatabase();
    void reportsCipherVersion();
};

void TestVaultDatabase::createsEncryptedDatabase()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("vault.db"));
    const Bytes key(32, 0x44);

    std::string error;
    QVERIFY2(VaultDatabase::create(path.toStdString(), key, &error), error.c_str());
    QVERIFY(QFileInfo::exists(path));

    QFile file(path);
    QVERIFY(file.open(QIODevice::ReadOnly));
    const QByteArray header = file.read(16);
    QCOMPARE(header.size(), 16);
    QVERIFY(header != QByteArrayLiteral("SQLite format 3\0"));
}

void TestVaultDatabase::verifiesWithCorrectKey()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("vault.db"));
    const Bytes key(32, 0x44);

    std::string error;
    QVERIFY2(VaultDatabase::create(path.toStdString(), key, &error), error.c_str());
    QVERIFY2(VaultDatabase::verify(path.toStdString(), key, &error), error.c_str());
}

void TestVaultDatabase::rejectsWrongKey()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("vault.db"));
    const Bytes key(32, 0x44);
    const Bytes wrongKey(32, 0x55);

    std::string error;
    QVERIFY2(VaultDatabase::create(path.toStdString(), key, &error), error.c_str());
    QVERIFY(!VaultDatabase::verify(path.toStdString(), wrongKey, &error));
    QVERIFY(!error.empty());
}

void TestVaultDatabase::rejectsExistingDatabase()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath(QStringLiteral("vault.db"));
    const Bytes key(32, 0x44);

    std::string error;
    QVERIFY2(VaultDatabase::create(path.toStdString(), key, &error), error.c_str());
    QVERIFY(!VaultDatabase::create(path.toStdString(), key, &error));
}

void TestVaultDatabase::reportsCipherVersion()
{
    QVERIFY(!VaultDatabase::cipherVersion().empty());
}

QTEST_APPLESS_MAIN(TestVaultDatabase)
#include "tst_vaultdatabase.moc"
