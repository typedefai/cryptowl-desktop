#include "VaultCreator.h"
#include "VaultUnlocker.h"

#include "crypto/Bytes.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QtTest>

using namespace cryptowl::crypto;

namespace {

constexpr std::string_view kPassword = "correct horse battery staple";

bool writeFile(const QString &path, const QByteArray &data)
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(data) == data.size();
}

} // namespace

class TestVaultCreator : public QObject
{
    Q_OBJECT

private slots:
    void createsUnlockableVault();
    void cleansUpWhenSecretStorageFails();
    void rejectsNonEmptyFolder();
};

void TestVaultCreator::createsUnlockableVault()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("personal"));
    QVERIFY(QDir().mkpath(vault));

    Bytes capturedSecret;
    const auto result = VaultCreator::create(
        vault, QString::fromLatin1(kPassword),
        [&capturedSecret](const QString &, std::span<const std::uint8_t>,
                          std::span<const std::uint8_t> secret, QString *) {
            capturedSecret.assign(secret.begin(), secret.end());
            return true;
        });
    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.vaultId, QStringLiteral("personal"));

    QVERIFY(QFileInfo::exists(QDir(vault).filePath(QStringLiteral("vault.meta"))));
    QVERIFY(QFileInfo::exists(QDir(vault).filePath(QStringLiteral("config.json"))));
    QVERIFY(QFileInfo::exists(QDir(vault).filePath(QStringLiteral("config.sig"))));
    QVERIFY(!QFileInfo::exists(QDir(vault).filePath(QStringLiteral("device_secret"))));
    QCOMPARE(capturedSecret.size(), std::size_t(32));

    QFile metaFile(QDir(vault).filePath(QStringLiteral("vault.meta")));
    QVERIFY(metaFile.open(QIODevice::ReadOnly));
    const QJsonObject meta = QJsonDocument::fromJson(metaFile.readAll()).object();
    QCOMPARE(meta.value(QStringLiteral("version")).toInt(), 3);
    QCOMPARE(meta.value(QStringLiteral("vault_id")).toString(), QStringLiteral("personal"));
    QVERIFY(meta.contains(QStringLiteral("mac")));

    QFile configFile(QDir(vault).filePath(QStringLiteral("config.json")));
    QVERIFY(configFile.open(QIODevice::ReadOnly));
    QCOMPARE(configFile.readAll(), QByteArrayLiteral("{\"name\":\"personal\"}"));

    QVERIFY(writeFile(QDir(vault).filePath(QStringLiteral("device_secret")),
                      QByteArray(reinterpret_cast<const char *>(capturedSecret.data()),
                                 static_cast<int>(capturedSecret.size()))));

    const auto unlocked =
        VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY2(unlocked.ok, qPrintable(unlocked.error));
}

void TestVaultCreator::cleansUpWhenSecretStorageFails()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("personal"));
    QVERIFY(QDir().mkpath(vault));

    const auto result = VaultCreator::create(
        vault, QString::fromLatin1(kPassword),
        [](const QString &, std::span<const std::uint8_t>,
           std::span<const std::uint8_t>, QString *error) {
            if (error)
                *error = QStringLiteral("keychain unavailable");
            return false;
        });
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("device secret")));
    QVERIFY(!QFileInfo::exists(QDir(vault).filePath(QStringLiteral("vault.meta"))));
    QVERIFY(!QFileInfo::exists(QDir(vault).filePath(QStringLiteral("config.json"))));
    QVERIFY(!QFileInfo::exists(QDir(vault).filePath(QStringLiteral("config.sig"))));
}

void TestVaultCreator::rejectsNonEmptyFolder()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("personal"));
    QVERIFY(QDir().mkpath(vault));
    QVERIFY(writeFile(QDir(vault).filePath(QStringLiteral("existing.txt")),
                      QByteArrayLiteral("not empty")));

    const auto result = VaultCreator::create(
        vault, QString::fromLatin1(kPassword),
        [](const QString &, std::span<const std::uint8_t>,
           std::span<const std::uint8_t>, QString *) { return true; });
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("empty")));
    QVERIFY(!QFileInfo::exists(QDir(vault).filePath(QStringLiteral("vault.meta"))));
}

QTEST_GUILESS_MAIN(TestVaultCreator)
#include "tst_vaultcreator.moc"
