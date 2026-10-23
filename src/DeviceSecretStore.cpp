#include "DeviceSecretStore.h"

#include "crypto/Bytes.h"

#include <QByteArray>
#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QString>

#include <qtkeychain/keychain.h>

#include <algorithm>
#include <cctype>
#include <string_view>
#include <utility>

namespace {

using namespace cryptowl::crypto;

const QString kKeychainService = QStringLiteral("com.typedefai.cryptowl.desktop");

struct LegacyResult
{
    bool exists = false;
    bool ok = false;
    QString error;
    ProtectedValue secret;
};

struct ByteArrayWiper
{
    QByteArray &value;

    ~ByteArrayWiper()
    {
        value.fill('\0');
    }
};

QString legacyPath(const QString &vaultPath)
{
    return QDir(vaultPath).filePath(QStringLiteral("device_secret"));
}

LegacyResult readLegacySecret(const QString &vaultPath)
{
    const QString path = legacyPath(vaultPath);
    const QFileInfo info(path);

    LegacyResult result;
    result.exists = info.exists();
    if (!result.exists)
        return result;

    if (!info.isFile()) {
        result.error = QStringLiteral("device_secret is not a regular file.");
        return result;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        result.error = QStringLiteral("Cannot read device_secret.");
        return result;
    }
    if (file.size() > 1024) {
        result.error = QStringLiteral("device_secret is too large.");
        return result;
    }

    QByteArray data = file.readAll();
    ByteArrayWiper dataWiper{data};

    if (data.size() == 32) {
        result.ok = true;
        result.secret = ProtectedValue(Bytes(data.begin(), data.end()));
        return result;
    }

    QByteArray text = data.trimmed();
    ByteArrayWiper textWiper{text};
    const bool isHex = text.size() == 64
        && std::all_of(text.cbegin(), text.cend(), [](char character) {
               return std::isxdigit(static_cast<unsigned char>(character)) != 0;
           });
    if (!isHex) {
        result.error =
            QStringLiteral("device_secret must be 32 raw bytes or 64 hex characters.");
        return result;
    }

    result.ok = true;
    result.secret = ProtectedValue(
        fromHex(std::string_view(text.constData(), static_cast<std::size_t>(text.size()))));
    return result;
}

QString accountName(const QString &vaultId, std::span<const std::uint8_t> argon2Salt)
{
    return vaultId + QLatin1Char(':') + QString::fromStdString(toHex(argon2Salt));
}

bool runJob(QKeychain::Job &job, QString *error)
{
    job.setAutoDelete(false);

    QEventLoop loop;
    QObject::connect(&job, &QKeychain::Job::finished, &loop, &QEventLoop::quit);
    job.start();
    loop.exec();

    if (job.error() == QKeychain::NoError)
        return true;

    if (error) {
        const QString detail = job.errorString();
        *error = detail.isEmpty() ? QStringLiteral("Secure storage operation failed.")
                                  : detail;
    }
    return false;
}

} // namespace

bool DeviceSecretStore::isAvailable()
{
    // QtKeychain's macOS backend relies on the native event loop. The
    // offscreen platform used by the headless tests does not service it.
    if (QGuiApplication::instance()
        && QGuiApplication::platformName() == QLatin1String("offscreen")) {
        return false;
    }
    return QKeychain::isAvailable();
}

DeviceSecretStore::LoadResult DeviceSecretStore::load(
    const QString &vaultPath, const QString &vaultId,
    std::span<const std::uint8_t> argon2Salt)
{
    LegacyResult legacy = readLegacySecret(vaultPath);
    if (legacy.exists) {
        LoadResult result;
        result.ok = legacy.ok;
        result.fromLegacy = true;
        result.error = legacy.error;
        result.secret = std::move(legacy.secret);
        return result;
    }

    if (!isAvailable()) {
        LoadResult result;
        result.error = QStringLiteral(
            "Device secret not found. Secure device storage is not available on this system.");
        return result;
    }

    QKeychain::ReadPasswordJob job(kKeychainService);
    job.setKey(accountName(vaultId, argon2Salt));
    QString error;
    if (!runJob(job, &error)) {
        LoadResult result;
        if (job.error() == QKeychain::EntryNotFound)
            result.error = QStringLiteral("Device secret not found in secure storage.");
        else
            result.error = QStringLiteral("Secure storage read failed: %1").arg(error);
        return result;
    }

    const QByteArray data = job.binaryData();
    if (data.size() != 32) {
        LoadResult result;
        result.error = QStringLiteral("Secure storage device secret has an invalid length.");
        return result;
    }

    Bytes secretBytes(reinterpret_cast<const std::uint8_t *>(data.constData()),
                      reinterpret_cast<const std::uint8_t *>(data.constData())
                          + data.size());

    LoadResult result;
    result.ok = true;
    result.secret = ProtectedValue(std::move(secretBytes));
    return result;
}

bool DeviceSecretStore::store(const QString &vaultId,
                              std::span<const std::uint8_t> argon2Salt,
                              std::span<const std::uint8_t> secret, QString *error)
{
    if (!isAvailable()) {
        if (error)
            *error = QStringLiteral(
                "Secure device storage is not available on this system.");
        return false;
    }
    if (secret.size() != 32) {
        if (error)
            *error = QStringLiteral("Device secret must be 32 bytes.");
        return false;
    }

    QKeychain::WritePasswordJob job(kKeychainService);
    job.setKey(accountName(vaultId, argon2Salt));
    job.setBinaryData(QByteArray(reinterpret_cast<const char *>(secret.data()),
                                 static_cast<int>(secret.size())));
    return runJob(job, error);
}

bool DeviceSecretStore::removeLegacyFile(const QString &vaultPath, QString *error)
{
    const QString path = legacyPath(vaultPath);
    if (!QFileInfo::exists(path))
        return true;

    QFile file(path);
    if (file.remove())
        return true;

    if (error)
        *error = file.errorString();
    return false;
}

bool DeviceSecretStore::remove(const QString &vaultId,
                               std::span<const std::uint8_t> argon2Salt, QString *error)
{
    if (!isAvailable()) {
        if (error)
            *error = QStringLiteral(
                "Secure device storage is not available on this system.");
        return false;
    }

    QKeychain::DeletePasswordJob job(kKeychainService);
    job.setKey(accountName(vaultId, argon2Salt));
    QString jobError;
    if (runJob(job, &jobError)) {
        return true;
    }
    if (job.error() == QKeychain::EntryNotFound)
        return true;

    if (error)
        *error = QStringLiteral("Secure storage delete failed: %1").arg(jobError);
    return false;
}
