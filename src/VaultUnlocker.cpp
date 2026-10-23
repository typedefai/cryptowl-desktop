#include "VaultUnlocker.h"

#include "crypto/AesGcm.h"
#include "crypto/Argon2.h"
#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"
#include "crypto/Errors.h"
#include "crypto/Hash.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>

#include <span>
#include <stdexcept>
#include <string_view>

namespace {

using namespace cryptowl::crypto;

constexpr qint64 kMaxMetaBytes = 1024 * 1024;
constexpr int kMaxKdfMemoryKib = 256 * 1024;
constexpr int kMaxKdfIterations = 16;
constexpr int kMaxKdfParallelism = 16;

struct ByteArrayWiper
{
    QByteArray &value;

    ~ByteArrayWiper()
    {
        value.fill('\0');
    }
};

VaultUnlocker::Result failure(const QString &message)
{
    VaultUnlocker::Result result;
    result.error = message;
    return result;
}

Bytes decodeBase32(const QJsonValue &value, const QString &name)
{
    const QString encoded = value.toString();
    if (encoded.isEmpty())
        throw std::runtime_error(QStringLiteral("Missing %1.").arg(name).toStdString());

    try {
        return crockford32Decode(encoded.toStdString());
    } catch (const std::exception &) {
        throw std::runtime_error(QStringLiteral("Invalid %1.").arg(name).toStdString());
    }
}

bool constantTimeEquals(std::span<const std::uint8_t> left,
                        std::span<const std::uint8_t> right)
{
    if (left.size() != right.size())
        return false;

    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i)
        difference |= static_cast<std::uint8_t>(left[i] ^ right[i]);
    return difference == 0;
}

} // namespace

VaultUnlocker::Result VaultUnlocker::unlock(const QString &vaultPath, const QString &password)
{
    try {
        QFile metaFile(QDir(vaultPath).filePath(QStringLiteral("vault.meta")));
        if (!metaFile.open(QIODevice::ReadOnly))
            return failure(QStringLiteral("Cannot read vault.meta."));
        if (metaFile.size() > kMaxMetaBytes)
            return failure(QStringLiteral("vault.meta is too large."));

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(metaFile.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
            return failure(QStringLiteral("vault.meta is not valid JSON."));

        const QJsonObject meta = document.object();
        const int version = meta.value(QStringLiteral("version")).toInt(-1);
        if (version < 2 || version > 3)
            return failure(QStringLiteral("Unsupported vault format version."));

        const QString vaultId = meta.value(QStringLiteral("vault_id")).toString();
        if (vaultId.isEmpty())
            return failure(QStringLiteral("Missing or invalid vault_id."));

        const QJsonObject kdf = meta.value(QStringLiteral("kdf")).toObject();
        if (kdf.value(QStringLiteral("algorithm")).toString() != QStringLiteral("argon2id"))
            return failure(QStringLiteral("Unsupported password KDF."));

        const int memoryKib = kdf.value(QStringLiteral("m_kib")).toInt(0);
        const int iterations = kdf.value(QStringLiteral("t")).toInt(0);
        const int parallelism = kdf.value(QStringLiteral("p")).toInt(0);
        if (memoryKib <= 0 || memoryKib > kMaxKdfMemoryKib || iterations <= 0
            || iterations > kMaxKdfIterations || parallelism <= 0
            || parallelism > kMaxKdfParallelism) {
            return failure(QStringLiteral("Invalid Argon2 parameters."));
        }

        const QJsonObject salts = meta.value(QStringLiteral("salts")).toObject();
        const Bytes argon2Salt = decodeBase32(salts.value(QStringLiteral("argon2")),
                                              QStringLiteral("argon2 salt"));
        const Bytes hkdfSalt = decodeBase32(salts.value(QStringLiteral("hkdf")),
                                            QStringLiteral("hkdf salt"));
        if (argon2Salt.size() != 32 || hkdfSalt.size() != 32)
            return failure(QStringLiteral("Invalid vault salts."));

        QJsonObject wrapped;
        for (const QJsonValue &value : meta.value(QStringLiteral("wrapped_keys")).toArray()) {
            const QJsonObject candidate = value.toObject();
            if (candidate.value(QStringLiteral("id")).toString()
                == QStringLiteral("vault_key:smk")) {
                wrapped = candidate;
                break;
            }
        }
        if (wrapped.isEmpty())
            return failure(QStringLiteral("No password-wrapped vault key found."));
        if (wrapped.value(QStringLiteral("role")).toString() != QStringLiteral("vault_key")
            || wrapped.value(QStringLiteral("wrapper")).toString() != QStringLiteral("smk")
            || wrapped.value(QStringLiteral("algorithm")).toString()
                != QStringLiteral("AES-256-GCM")) {
            return failure(QStringLiteral("Unsupported wrapped vault key."));
        }

        const QString wrappedId = wrapped.value(QStringLiteral("id")).toString();
        const Bytes ciphertext = decodeBase32(wrapped.value(QStringLiteral("ciphertext")),
                                              QStringLiteral("wrapped key ciphertext"));
        const Bytes nonce = decodeBase32(wrapped.value(QStringLiteral("nonce")),
                                         QStringLiteral("wrapped key nonce"));
        const Bytes tag = decodeBase32(wrapped.value(QStringLiteral("auth_tag")),
                                       QStringLiteral("wrapped key tag"));
        if (ciphertext.size() != 32 || nonce.size() != 12 || tag.size() != 16)
            return failure(QStringLiteral("Invalid wrapped vault key data."));

        const QJsonObject mac = meta.value(QStringLiteral("mac")).toObject();
        if (mac.value(QStringLiteral("algorithm")).toString() != QStringLiteral("HMAC-SHA256"))
            return failure(QStringLiteral("Missing or invalid vault.meta MAC."));
        const Bytes expectedMac = decodeBase32(mac.value(QStringLiteral("value")),
                                               QStringLiteral("vault.meta MAC"));
        if (expectedMac.size() != 32)
            return failure(QStringLiteral("Invalid vault.meta MAC."));

        QFile deviceSecretFile(QDir(vaultPath).filePath(QStringLiteral("device_secret")));
        if (!deviceSecretFile.open(QIODevice::ReadOnly))
            return failure(QStringLiteral("Cannot read device_secret."));
        if (deviceSecretFile.size() != 32)
            return failure(QStringLiteral("device_secret must be exactly 32 bytes."));
        QByteArray deviceSecret = deviceSecretFile.readAll();
        ByteArrayWiper deviceSecretWiper{deviceSecret};
        if (deviceSecret.size() != 32)
            return failure(QStringLiteral("device_secret must be exactly 32 bytes."));

        QByteArray passwordUtf8 = password.toUtf8();
        ByteArrayWiper passwordWiper{passwordUtf8};
        const QByteArray vaultIdUtf8 = vaultId.toUtf8();

        const auto deviceSecretSpan = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(deviceSecret.constData()),
            static_cast<std::size_t>(deviceSecret.size()));
        const auto passwordSpan = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(passwordUtf8.constData()),
            static_cast<std::size_t>(passwordUtf8.size()));

        ProtectedValue passwordKey(hmacSha256(deviceSecretSpan, passwordSpan));

        Argon2Params params;
        params.memoryKib = static_cast<std::uint32_t>(memoryKib);
        params.iterations = static_cast<std::uint32_t>(iterations);
        params.parallelism = static_cast<std::uint32_t>(parallelism);
        ProtectedValue tmk(argon2id(passwordKey.span(), argon2Salt, params));

        ProtectedValue smk(hkdfSha256(
            tmk.span(), hkdfSalt,
            bytesOf(std::string_view(vaultIdUtf8.constData(),
                                     static_cast<std::size_t>(vaultIdUtf8.size()))),
            64));
        if (smk.size() != 64)
            return failure(QStringLiteral("Invalid stretched master key."));

        const auto macKey = std::span<const std::uint8_t>(smk.span().data() + 32, 32);

        QJsonObject metaForMac = meta;
        metaForMac.remove(QStringLiteral("mac"));
        const QByteArray canonical = QJsonDocument(metaForMac).toJson(QJsonDocument::Compact);
        const Bytes actualMac = hmacSha256(
            macKey, bytesOf(std::string_view(canonical.constData(),
                                             static_cast<std::size_t>(canonical.size()))));
        if (!constantTimeEquals(actualMac, expectedMac))
            return failure(
                QStringLiteral("Incorrect password or corrupted vault metadata."));

        const auto wrappingKey = std::span<const std::uint8_t>(smk.span().data(), 32);
        Bytes vaultKeyBytes = aesGcmDecrypt(
            wrappingKey, nonce, bytesOf(wrappedId.toStdString()), ciphertext, tag);
        if (vaultKeyBytes.size() != 32) {
            secureWipe(vaultKeyBytes);
            return failure(QStringLiteral("Invalid vault key length."));
        }

        Result result;
        result.ok = true;
        result.vaultKey = ProtectedValue(std::move(vaultKeyBytes));
        return result;
    } catch (const AuthenticationError &) {
        return failure(QStringLiteral("Incorrect password or corrupted vault."));
    } catch (const std::exception &error) {
        return failure(QStringLiteral("Could not unlock vault: %1")
                           .arg(QString::fromUtf8(error.what())));
    }
}
