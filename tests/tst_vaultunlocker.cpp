#include "CreateVaultDialog.h"
#include "DeviceSecretStore.h"
#include "UnlockVaultDialog.h"
#include "VaultUnlocker.h"

#include "crypto/AesGcm.h"
#include "crypto/Argon2.h"
#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"
#include "crypto/Hash.h"

#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QUuid>
#include <QtTest>

using namespace cryptowl::crypto;

namespace {

const Bytes kDeviceSecret(32, 0x11);
constexpr std::string_view kPassword = "correct horse battery staple";
const Bytes kArgon2Salt(32, 0x22);
const Bytes kHkdfSalt(32, 0x33);
const Bytes kVaultKey(32, 0x44);
const Bytes kNonce(12, 0x55);
const QString kVaultId = QStringLiteral("personal");

QString encode(std::span<const std::uint8_t> bytes)
{
    return QString::fromStdString(crockford32Encode(bytes));
}

bool writeFile(const QString &path, const QByteArray &data)
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(data) == data.size();
}

QJsonObject makeMeta(int memoryKib = 19456, const QString &vaultId = kVaultId)
{
    const Bytes passwordKey = hmacSha256(kDeviceSecret, bytesOf(kPassword));
    const Bytes tmk = argon2id(passwordKey, kArgon2Salt);
    const Bytes smk = hkdfSha256(tmk, kHkdfSalt, bytesOf(vaultId.toStdString()), 64);
    const std::span<const std::uint8_t> wrappingKey(smk.data(), 32);
    const GcmCiphertext wrapped =
        aesGcmEncrypt(wrappingKey, kNonce, bytesOf("vault_key:smk"), kVaultKey);

    QJsonObject kdf;
    kdf[QStringLiteral("algorithm")] = QStringLiteral("argon2id");
    kdf[QStringLiteral("m_kib")] = memoryKib;
    kdf[QStringLiteral("t")] = 2;
    kdf[QStringLiteral("p")] = 1;

    QJsonObject salts;
    salts[QStringLiteral("argon2")] = encode(kArgon2Salt);
    salts[QStringLiteral("hkdf")] = encode(kHkdfSalt);

    QJsonObject wrappedKey;
    wrappedKey[QStringLiteral("id")] = QStringLiteral("vault_key:smk");
    wrappedKey[QStringLiteral("role")] = QStringLiteral("vault_key");
    wrappedKey[QStringLiteral("wrapper")] = QStringLiteral("smk");
    wrappedKey[QStringLiteral("algorithm")] = QStringLiteral("AES-256-GCM");
    wrappedKey[QStringLiteral("ciphertext")] = encode(wrapped.ciphertext);
    wrappedKey[QStringLiteral("nonce")] = encode(kNonce);
    wrappedKey[QStringLiteral("auth_tag")] = encode(wrapped.tag);

    QJsonArray wrappedKeys;
    wrappedKeys.append(wrappedKey);

    QJsonObject meta;
    meta[QStringLiteral("version")] = 3;
    meta[QStringLiteral("vault_id")] = vaultId;
    meta[QStringLiteral("created_at")] = 1780000000000.0;
    meta[QStringLiteral("updated_at")] = 1780000000000.0;
    meta[QStringLiteral("kdf")] = kdf;
    meta[QStringLiteral("salts")] = salts;
    meta[QStringLiteral("wrapped_keys")] = wrappedKeys;

    const QByteArray canonical = QJsonDocument(meta).toJson(QJsonDocument::Compact);
    const std::span<const std::uint8_t> macKey(smk.data() + 32, 32);
    const Bytes mac = hmacSha256(
        macKey, bytesOf(std::string_view(canonical.constData(),
                                         static_cast<std::size_t>(canonical.size()))));

    QJsonObject macObject;
    macObject[QStringLiteral("algorithm")] = QStringLiteral("HMAC-SHA256");
    macObject[QStringLiteral("value")] = encode(mac);
    meta[QStringLiteral("mac")] = macObject;
    return meta;
}

QString createVault(const QString &root, int memoryKib = 19456, bool hexSecret = false,
                    const QString &vaultId = kVaultId)
{
    const QString path = QDir(root).filePath(vaultId);
    if (!QDir().mkpath(path))
        return {};
    if (!writeFile(QDir(path).filePath(QStringLiteral("vault.meta")),
                   QJsonDocument(makeMeta(memoryKib, vaultId))
                       .toJson(QJsonDocument::Indented))) {
        return {};
    }

    const QByteArray secret = hexSecret
        ? QByteArray::fromStdString(toHex(kDeviceSecret))
        : QByteArray(reinterpret_cast<const char *>(kDeviceSecret.data()),
                     static_cast<int>(kDeviceSecret.size()));
    if (!writeFile(QDir(path).filePath(QStringLiteral("device_secret")), secret))
        return {};
    return path;
}

} // namespace

class TestVaultUnlocker : public QObject
{
    Q_OBJECT

private slots:
    void unlocksWithCorrectPassword();
    void rejectsWrongPassword();
    void rejectsTamperedMetadata();
    void rejectsMissingDeviceSecret();
    void acceptsHexEncodedDeviceSecret();
    void rejectsOversizedKdfParameters();
    void migratesLegacySecretToKeychain();
    void unlockDialogAcceptsCorrectPassword();
    void unlockDialogRejectsWrongPassword();
    void createDialogRequiresMatchingPasswords();
};

void TestVaultUnlocker::unlocksWithCorrectPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(QString::fromStdString(toHex(result.vaultKey.span())),
             QString::fromStdString(toHex(kVaultKey)));
    QCOMPARE(result.smk.size(), std::size_t(64));
}

void TestVaultUnlocker::rejectsWrongPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QStringLiteral("wrong password"), false);
    QVERIFY(!result.ok);
    QVERIFY(!result.error.isEmpty());
}

void TestVaultUnlocker::rejectsTamperedMetadata()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    const QString metaPath = QDir(vault).filePath(QStringLiteral("vault.meta"));
    QFile metaFile(metaPath);
    QVERIFY(metaFile.open(QIODevice::ReadOnly));
    QJsonObject meta = QJsonDocument::fromJson(metaFile.readAll()).object();
    metaFile.close();
    meta[QStringLiteral("created_at")] = 1.0;
    QVERIFY(writeFile(metaPath, QJsonDocument(meta).toJson(QJsonDocument::Compact)));

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("corrupted"), Qt::CaseInsensitive));
}

void TestVaultUnlocker::rejectsMissingDeviceSecret()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());
    QVERIFY(QFile::remove(QDir(vault).filePath(QStringLiteral("device_secret"))));

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("Device secret")));
}

void TestVaultUnlocker::acceptsHexEncodedDeviceSecret()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path(), 19456, true);
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(QString::fromStdString(toHex(result.vaultKey.span())),
             QString::fromStdString(toHex(kVaultKey)));
}

void TestVaultUnlocker::rejectsOversizedKdfParameters()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path(), 1024 * 1024);
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("Argon2")));
}

void TestVaultUnlocker::migratesLegacySecretToKeychain()
{
    if (!DeviceSecretStore::isAvailable())
        QSKIP("No secure keychain backend is available.");
    if (QGuiApplication::platformName() == QLatin1String("offscreen"))
        QSKIP("QtKeychain requires the native event loop; skipped offscreen.");

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vaultId =
        QStringLiteral("cryptowl-test-%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    const QString vault = createVault(dir.path(), 19456, false, vaultId);
    QVERIFY(!vault.isEmpty());

    struct KeychainCleanup
    {
        QString vaultId;
        ~KeychainCleanup()
        {
            QString error;
            DeviceSecretStore::remove(vaultId, kArgon2Salt, &error);
        }
    } cleanup{vaultId};

    const auto first =
        VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), true);
    QVERIFY2(first.ok, qPrintable(first.error));
    QVERIFY2(first.warning.isEmpty(), qPrintable(first.warning));
    QVERIFY(!QFileInfo::exists(QDir(vault).filePath(QStringLiteral("device_secret"))));

    const auto second =
        VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword), false);
    QVERIFY2(second.ok, qPrintable(second.error));
    QCOMPARE(QString::fromStdString(toHex(second.vaultKey.span())),
             QString::fromStdString(toHex(kVaultKey)));

    QString removeError;
    QVERIFY2(DeviceSecretStore::remove(vaultId, kArgon2Salt, &removeError),
             qPrintable(removeError));
}

void TestVaultUnlocker::unlockDialogAcceptsCorrectPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    UnlockVaultDialog dialog(vault, nullptr, false);
    auto *passwordEdit = dialog.findChild<QLineEdit *>(QStringLiteral("vaultPassword"));
    QVERIFY(passwordEdit);
    passwordEdit->setText(QString::fromLatin1(kPassword));

    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryUnlock", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));

    const auto key = dialog.takeVaultKey();
    QCOMPARE(QString::fromStdString(toHex(key.span())),
             QString::fromStdString(toHex(kVaultKey)));
    const auto smk = dialog.takeSmk();
    QCOMPARE(smk.size(), std::size_t(64));
}

void TestVaultUnlocker::unlockDialogRejectsWrongPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    UnlockVaultDialog dialog(vault, nullptr, false);
    auto *passwordEdit = dialog.findChild<QLineEdit *>(QStringLiteral("vaultPassword"));
    QVERIFY(passwordEdit);
    passwordEdit->setText(QStringLiteral("wrong password"));

    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryUnlock", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));
    QVERIFY(dialog.takeVaultKey().empty());

    auto *error = dialog.findChild<QLabel *>(QStringLiteral("vaultError"));
    QVERIFY(error);
    QVERIFY(!error->text().isEmpty());
}

void TestVaultUnlocker::createDialogRequiresMatchingPasswords()
{
    CreateVaultDialog dialog(QStringLiteral("personal"));
    auto *password = dialog.findChild<QLineEdit *>(QStringLiteral("vaultPassword"));
    auto *confirm = dialog.findChild<QLineEdit *>(QStringLiteral("vaultPasswordConfirm"));
    auto *error = dialog.findChild<QLabel *>(QStringLiteral("vaultError"));
    QVERIFY(password);
    QVERIFY(confirm);
    QVERIFY(error);

    password->setText(QStringLiteral("one"));
    confirm->setText(QStringLiteral("two"));
    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryCreate", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));
    QVERIFY(!error->text().isEmpty());

    confirm->setText(QStringLiteral("one"));
    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryCreate", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
    QCOMPARE(dialog.password(), QStringLiteral("one"));
}

QTEST_MAIN(TestVaultUnlocker)
#include "tst_vaultunlocker.moc"
