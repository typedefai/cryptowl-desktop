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
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
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

QJsonObject makeMeta(int memoryKib = 19456)
{
    const Bytes passwordKey = hmacSha256(kDeviceSecret, bytesOf(kPassword));
    const Bytes tmk = argon2id(passwordKey, kArgon2Salt);
    const Bytes smk = hkdfSha256(tmk, kHkdfSalt, bytesOf(kVaultId.toStdString()), 64);
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
    meta[QStringLiteral("vault_id")] = kVaultId;
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

QString createVault(const QString &root, int memoryKib = 19456)
{
    const QString path = QDir(root).filePath(kVaultId);
    if (!QDir().mkpath(path))
        return {};
    if (!writeFile(QDir(path).filePath(QStringLiteral("vault.meta")),
                   QJsonDocument(makeMeta(memoryKib)).toJson(QJsonDocument::Indented))) {
        return {};
    }
    if (!writeFile(QDir(path).filePath(QStringLiteral("device_secret")),
                   QByteArray(reinterpret_cast<const char *>(kDeviceSecret.data()),
                              static_cast<int>(kDeviceSecret.size())))) {
        return {};
    }
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
    void rejectsOversizedKdfParameters();
    void unlockDialogAcceptsCorrectPassword();
    void unlockDialogRejectsWrongPassword();
};

void TestVaultUnlocker::unlocksWithCorrectPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword));
    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(QString::fromStdString(toHex(result.vaultKey.span())),
             QString::fromStdString(toHex(kVaultKey)));
}

void TestVaultUnlocker::rejectsWrongPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QStringLiteral("wrong password"));
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

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword));
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

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword));
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("device_secret")));
}

void TestVaultUnlocker::rejectsOversizedKdfParameters()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path(), 1024 * 1024);
    QVERIFY(!vault.isEmpty());

    const auto result = VaultUnlocker::unlock(vault, QString::fromLatin1(kPassword));
    QVERIFY(!result.ok);
    QVERIFY(result.error.contains(QStringLiteral("Argon2")));
}

void TestVaultUnlocker::unlockDialogAcceptsCorrectPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    UnlockVaultDialog dialog(vault);
    auto *passwordEdit = dialog.findChild<QLineEdit *>(QStringLiteral("vaultPassword"));
    QVERIFY(passwordEdit);
    passwordEdit->setText(QString::fromLatin1(kPassword));

    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryUnlock", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));

    const auto key = dialog.takeVaultKey();
    QCOMPARE(QString::fromStdString(toHex(key.span())),
             QString::fromStdString(toHex(kVaultKey)));
}

void TestVaultUnlocker::unlockDialogRejectsWrongPassword()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = createVault(dir.path());
    QVERIFY(!vault.isEmpty());

    UnlockVaultDialog dialog(vault);
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

QTEST_MAIN(TestVaultUnlocker)
#include "tst_vaultunlocker.moc"
