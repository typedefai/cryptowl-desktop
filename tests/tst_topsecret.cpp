#include "TopSecretService.h"
#include "VaultCreator.h"
#include "VaultUnlocker.h"

#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QtTest>

#include <span>
#include <string>
#include <string_view>
#include <utility>

using namespace cryptowl::crypto;

namespace {

constexpr std::string_view kPassword = "correct horse battery staple";
constexpr std::string_view kSecondary = "secondary-password";

bool writeFile(const QString &path, std::span<const std::uint8_t> data)
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly)
        && file.write(reinterpret_cast<const char *>(data.data()),
                      static_cast<qint64>(data.size()))
            == static_cast<qint64>(data.size());
}

} // namespace

class TestTopSecret : public QObject
{
    Q_OBJECT

private slots:
    void setupUnlockAndUseTopSecret();
};

void TestTopSecret::setupUnlockAndUseTopSecret()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("personal"));
    QVERIFY(QDir().mkpath(vault));

    Bytes deviceSecret;
    const auto created = VaultCreator::create(
        vault, QString::fromLatin1(kPassword),
        [&deviceSecret](const QString &, std::span<const std::uint8_t>,
                        std::span<const std::uint8_t> secret, QString *) {
            deviceSecret.assign(secret.begin(), secret.end());
            return true;
        });
    QVERIFY2(created.ok, qPrintable(created.error));
    QVERIFY(writeFile(QDir(vault).filePath(QStringLiteral("device_secret")),
                      deviceSecret));

    auto unlocked = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword),
                                          false);
    QVERIFY2(unlocked.ok, qPrintable(unlocked.error));

    const QString databasePath = QDir(vault).filePath(QStringLiteral("vault.db"));
    std::string dbError;
    cryptowl::vault::VaultDatabase database;
    QVERIFY2(database.open(databasePath.toStdString(), unlocked.vaultKey.span(),
                           &dbError),
             dbError.c_str());

    TopSecretService service(vault, database.handle());
    QVERIFY(!service.isConfigured());

    QString error;
    QVERIFY2(service.setup(unlocked.smk.span(), bytesOf(kSecondary), &error),
             qPrintable(error));
    QVERIFY(service.isConfigured());

    QFile metaFile(QDir(vault).filePath(QStringLiteral("vault.meta")));
    QVERIFY(metaFile.open(QIODevice::ReadOnly));
    const QJsonObject meta =
        QJsonDocument::fromJson(metaFile.readAll()).object();
    QVERIFY(!meta.value(QStringLiteral("salts"))
                 .toObject()
                 .value(QStringLiteral("secondary"))
                 .toString()
                 .isEmpty());

    const auto stillUnlocks =
        VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY2(stillUnlocks.ok, qPrintable(stillUnlocks.error));

    ProtectedValue topSecretKek;
    QVERIFY2(service.unlock(bytesOf(kSecondary), &topSecretKek, &error),
             qPrintable(error));
    QCOMPARE(topSecretKek.size(), std::size_t(32));

    ProtectedValue wrongKek;
    QVERIFY(!service.unlock(bytesOf("wrong secondary"), &wrongKek, &error));
    QVERIFY(wrongKek.empty());

    QVERIFY(!service.setup(unlocked.smk.span(), bytesOf(kSecondary), &error));
    QVERIFY(error.contains(QStringLiteral("already")));

    auto sessionUnlock =
        VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY2(sessionUnlock.ok, qPrintable(sessionUnlock.error));
    auto session = cryptowl::vault::VaultSession::open(
        databasePath.toStdString(), std::move(sessionUnlock.vaultKey),
        std::move(sessionUnlock.smk), &dbError, false);
    QVERIFY2(session != nullptr, dbError.c_str());
    QVERIFY(!session->hasKek());

    cryptowl::vault::NewItem item;
    item.type = "plain";
    item.classification = "T";
    item.title = "Top note";
    item.meta = "{}";
    item.payload = "top secret body";
    std::string id;
    std::string itemError;
    QVERIFY2(!session->items().create(item, &id, &itemError),
             "T creation must require a key");
    QVERIFY2(session->items().create(item, topSecretKek.span(), &id, &itemError),
             itemError.c_str());

    cryptowl::vault::ItemRecord record;
    QVERIFY(!session->items().get(id, &record, &itemError));
    QVERIFY(itemError.find("locked") != std::string::npos);
    QVERIFY2(session->items().get(id, topSecretKek.span(), &record, &itemError),
             itemError.c_str());
    QCOMPARE(QString::fromStdString(record.payload),
             QStringLiteral("top secret body"));
}

QTEST_MAIN(TestTopSecret)
#include "tst_topsecret.moc"
