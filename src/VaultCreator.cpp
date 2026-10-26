#include "VaultCreator.h"

#include "DeviceSecretStore.h"

#include "crypto/AesGcm.h"
#include "crypto/Argon2.h"
#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"
#include "crypto/Hash.h"
#include "crypto/Random.h"
#include "vault/VaultDatabase.h"

#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace cryptowl::crypto;

constexpr int kKdfMemoryKib = 19456;
constexpr int kKdfIterations = 2;
constexpr int kKdfParallelism = 1;

struct ByteArrayWiper
{
    QByteArray &value;

    ~ByteArrayWiper()
    {
        value.fill('\0');
    }
};

VaultCreator::Result failure(const QString &message)
{
    VaultCreator::Result result;
    result.error = message;
    return result;
}

QString encode(std::span<const std::uint8_t> bytes)
{
    return QString::fromStdString(crockford32Encode(bytes));
}

bool writeFile(const QString &path, const QByteArray &data, QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        if (error)
            *error = file.errorString();
        return false;
    }
    if (file.write(data) != data.size()) {
        if (error)
            *error = file.errorString();
        file.cancelWriting();
        return false;
    }
#ifndef Q_OS_WIN
    if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        if (error)
            *error = QStringLiteral("Could not restrict vault file permissions.");
        file.cancelWriting();
        return false;
    }
#endif

    if (!file.commit()) {
        if (error)
            *error = file.errorString();
        return false;
    }
    return true;
}

void removeFiles(const std::vector<QString> &paths)
{
    for (const QString &path : paths)
        QFile::remove(path);
}

} // namespace

VaultCreator::Result VaultCreator::create(const QString &vaultPath,
                                          const QString &password,
                                          const SecretWriter &secretWriter)
{
    const QFileInfo directory(vaultPath);
    if (directory.exists()) {
        if (!directory.isDir())
            return failure(QStringLiteral("The vault path is not a folder."));

        const QStringList existing =
            QDir(vaultPath).entryList(QDir::AllEntries | QDir::NoDotAndDotDot);
        if (!existing.isEmpty())
            return failure(QStringLiteral("The vault folder must be empty."));
    } else {
        const QFileInfo parent(directory.absolutePath());
        if (!parent.exists())
            return failure(QStringLiteral("The parent folder does not exist."));
        if (!parent.isDir())
            return failure(QStringLiteral("The parent path is not a folder."));
    }

    const QString vaultId = directory.fileName();
    if (vaultId.isEmpty())
        return failure(QStringLiteral("The vault folder must have a name."));
    if (password.isEmpty())
        return failure(QStringLiteral("The master password must not be empty."));

    Bytes argon2Salt = randomBytes(32);
    Bytes hkdfSalt = randomBytes(32);
    ProtectedValue deviceSecret(randomBytes(32));
    ProtectedValue vaultKey(randomBytes(32));
    const Bytes nonce = randomBytes(12);

    QByteArray passwordUtf8 = password.toUtf8();
    ByteArrayWiper passwordWiper{passwordUtf8};
    const QByteArray vaultIdUtf8 = vaultId.toUtf8();

    const auto passwordSpan = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(passwordUtf8.constData()),
        static_cast<std::size_t>(passwordUtf8.size()));

    ProtectedValue passwordKey(hmacSha256(deviceSecret.span(), passwordSpan));

    Argon2Params params;
    params.memoryKib = kKdfMemoryKib;
    params.iterations = kKdfIterations;
    params.parallelism = kKdfParallelism;
    ProtectedValue tmk(argon2id(passwordKey.span(), argon2Salt, params));
    ProtectedValue smk(hkdfSha256(
        tmk.span(), hkdfSalt,
        bytesOf(std::string_view(vaultIdUtf8.constData(),
                                 static_cast<std::size_t>(vaultIdUtf8.size()))),
        64));
    if (smk.size() != 64)
        return failure(QStringLiteral("Could not derive the vault key."));

    const auto wrappingKey = std::span<const std::uint8_t>(smk.span().data(), 32);
    const auto macKey = std::span<const std::uint8_t>(smk.span().data() + 32, 32);
    const GcmCiphertext wrapped = aesGcmEncrypt(
        wrappingKey, nonce, bytesOf("vault_key:smk"), vaultKey.span(),
        "vault_key.wrap.smk");

    QJsonObject kdf;
    kdf[QStringLiteral("algorithm")] = QStringLiteral("argon2id");
    kdf[QStringLiteral("m_kib")] = kKdfMemoryKib;
    kdf[QStringLiteral("t")] = kKdfIterations;
    kdf[QStringLiteral("p")] = kKdfParallelism;

    QJsonObject salts;
    salts[QStringLiteral("argon2")] = encode(argon2Salt);
    salts[QStringLiteral("hkdf")] = encode(hkdfSalt);

    QJsonObject wrappedKey;
    wrappedKey[QStringLiteral("id")] = QStringLiteral("vault_key:smk");
    wrappedKey[QStringLiteral("role")] = QStringLiteral("vault_key");
    wrappedKey[QStringLiteral("wrapper")] = QStringLiteral("smk");
    wrappedKey[QStringLiteral("algorithm")] = QStringLiteral("AES-256-GCM");
    wrappedKey[QStringLiteral("ciphertext")] = encode(wrapped.ciphertext);
    wrappedKey[QStringLiteral("nonce")] = encode(nonce);
    wrappedKey[QStringLiteral("auth_tag")] = encode(wrapped.tag);

    QJsonArray wrappedKeys;
    wrappedKeys.append(wrappedKey);

    const double now = static_cast<double>(QDateTime::currentMSecsSinceEpoch());
    QJsonObject meta;
    meta[QStringLiteral("version")] = 3;
    meta[QStringLiteral("vault_id")] = vaultId;
    meta[QStringLiteral("created_at")] = now;
    meta[QStringLiteral("updated_at")] = now;
    meta[QStringLiteral("kdf")] = kdf;
    meta[QStringLiteral("salts")] = salts;
    meta[QStringLiteral("wrapped_keys")] = wrappedKeys;

    const QByteArray canonicalMeta = QJsonDocument(meta).toJson(QJsonDocument::Compact);
    const Bytes metaMac = hmacSha256(
        macKey, bytesOf(std::string_view(canonicalMeta.constData(),
                                         static_cast<std::size_t>(canonicalMeta.size()))));

    QJsonObject macObject;
    macObject[QStringLiteral("algorithm")] = QStringLiteral("HMAC-SHA256");
    macObject[QStringLiteral("value")] = encode(metaMac);
    meta[QStringLiteral("mac")] = macObject;

    QJsonObject config;
    config[QStringLiteral("name")] = vaultId;
    const QByteArray configJson = QJsonDocument(config).toJson(QJsonDocument::Compact);
    const Bytes configMac = hmacSha256(
        macKey, bytesOf(std::string_view(configJson.constData(),
                                         static_cast<std::size_t>(configJson.size()))));

    const std::vector<QString> paths = {
        QDir(vaultPath).filePath(QStringLiteral("config.json")),
        QDir(vaultPath).filePath(QStringLiteral("config.sig")),
        QDir(vaultPath).filePath(QStringLiteral("vault.meta")),
    };

    bool createdDirectory = false;
    if (!directory.exists()) {
        if (!QDir().mkpath(vaultPath))
            return failure(QStringLiteral("Could not create the vault folder."));
        createdDirectory = true;
    }

    std::vector<QString> created;
    auto failAndCleanup = [&](const QString &message) {
        removeFiles(created);
        if (createdDirectory)
            QDir().rmdir(vaultPath);
        return failure(message);
    };

    QString writeError;
    if (!writeFile(paths[0], configJson, &writeError)) {
        return failAndCleanup(
            QStringLiteral("Could not write config.json: %1").arg(writeError));
    }
    created.push_back(paths[0]);

    if (!writeFile(paths[1], encode(configMac).toUtf8(), &writeError))
        return failAndCleanup(QStringLiteral("Could not write config.sig: %1").arg(writeError));
    created.push_back(paths[1]);

    if (!writeFile(paths[2], QJsonDocument(meta).toJson(QJsonDocument::Compact),
                   &writeError)) {
        return failAndCleanup(QStringLiteral("Could not write vault.meta: %1").arg(writeError));
    }
    created.push_back(paths[2]);

    const QString databasePath = QDir(vaultPath).filePath(QStringLiteral("vault.db"));
    created.push_back(databasePath);
    std::string databaseError;
    if (!cryptowl::vault::VaultDatabase::create(
            databasePath.toUtf8().toStdString(), vaultKey.span(), &databaseError)) {
        return failAndCleanup(QStringLiteral("Could not create vault.db: %1")
                                  .arg(QString::fromStdString(databaseError)));
    }

#ifndef Q_OS_WIN
    if (!QFile::setPermissions(databasePath,
                               QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        return failAndCleanup(
            QStringLiteral("Could not restrict vault.db permissions."));
    }
#endif

    SecretWriter writer = secretWriter;
    if (!writer) {
        writer = [](const QString &id, std::span<const std::uint8_t> salt,
                    std::span<const std::uint8_t> secret, QString *error) {
            return DeviceSecretStore::store(id, salt, secret, error);
        };
    }

    QString secretError;
    if (!writer(vaultId, argon2Salt, deviceSecret.span(), &secretError)) {
        return failAndCleanup(QStringLiteral("Could not store the device secret: %1")
                                  .arg(secretError));
    }

    Result result;
    result.ok = true;
    result.vaultId = vaultId;
    return result;
}
