#include "DeviceSecretStore.h"

#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <algorithm>
#include <cctype>
#include <string_view>
#include <utility>

#ifdef Q_OS_MACOS
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace {

using namespace cryptowl::crypto;

#ifdef Q_OS_MACOS
constexpr char kKeychainService[] = "com.typedefai.cryptowl.desktop";
#endif

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

#ifdef Q_OS_MACOS

QString accountName(const QString &vaultId, std::span<const std::uint8_t> argon2Salt)
{
    return vaultId + QLatin1Char(':')
        + QString::fromStdString(toHex(argon2Salt));
}

QString keychainError(OSStatus status)
{
    CFStringRef message = SecCopyErrorMessageString(status, nullptr);
    const QString text = message ? QString::fromCFString(message) : QString::number(status);
    if (message)
        CFRelease(message);
    return text;
}

CFStringRef makeCFString(const QString &text)
{
    const QByteArray utf8 = text.toUtf8();
    return CFStringCreateWithBytes(kCFAllocatorDefault,
                                   reinterpret_cast<const UInt8 *>(utf8.constData()),
                                   utf8.size(), kCFStringEncodingUTF8, false);
}

bool loadFromKeychain(const QString &account, ProtectedValue &secret, QString *error)
{
    const QString service = QString::fromLatin1(kKeychainService);
    CFStringRef serviceRef = makeCFString(service);
    CFStringRef accountRef = makeCFString(account);
    if (!serviceRef || !accountRef) {
        if (serviceRef)
            CFRelease(serviceRef);
        if (accountRef)
            CFRelease(accountRef);
        if (error)
            *error = QStringLiteral("Could not create Keychain query.");
        return false;
    }

    const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount,
                          kSecReturnData, kSecMatchLimit};
    const void *values[] = {kSecClassGenericPassword, serviceRef, accountRef,
                            kCFBooleanTrue, kSecMatchLimitOne};
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 5, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CFTypeRef result = nullptr;
    const OSStatus status = query ? SecItemCopyMatching(query, &result)
                                  : errSecParam;
    if (query)
        CFRelease(query);
    CFRelease(serviceRef);
    CFRelease(accountRef);

    if (status == errSecItemNotFound) {
        if (error)
            *error = QStringLiteral("Device secret not found in Keychain.");
        return false;
    }
    if (status != errSecSuccess) {
        if (error)
            *error = QStringLiteral("Keychain read failed: %1").arg(keychainError(status));
        return false;
    }
    if (!result || CFGetTypeID(result) != CFDataGetTypeID()) {
        if (result)
            CFRelease(result);
        if (error)
            *error = QStringLiteral("Keychain returned invalid device secret data.");
        return false;
    }

    CFDataRef data = static_cast<CFDataRef>(result);
    const CFIndex length = CFDataGetLength(data);
    if (length != 32) {
        CFRelease(result);
        if (error)
            *error = QStringLiteral("Keychain device secret has an invalid length.");
        return false;
    }

    const UInt8 *bytes = CFDataGetBytePtr(data);
    Bytes secretBytes(bytes, bytes + length);
    CFRelease(result);
    secret = ProtectedValue(std::move(secretBytes));
    return true;
}

bool storeToKeychain(const QString &account, std::span<const std::uint8_t> secret,
                     QString *error)
{
    const QString service = QString::fromLatin1(kKeychainService);
    CFStringRef serviceRef = makeCFString(service);
    CFStringRef accountRef = makeCFString(account);
    CFDataRef valueRef =
        CFDataCreate(kCFAllocatorDefault, secret.data(),
                     static_cast<CFIndex>(secret.size()));
    if (!serviceRef || !accountRef || !valueRef) {
        if (serviceRef)
            CFRelease(serviceRef);
        if (accountRef)
            CFRelease(accountRef);
        if (valueRef)
            CFRelease(valueRef);
        if (error)
            *error = QStringLiteral("Could not create Keychain item.");
        return false;
    }

    const void *addKeys[] = {kSecClass, kSecAttrService, kSecAttrAccount,
                             kSecValueData, kSecAttrAccessible,
                             kSecAttrSynchronizable};
    const void *addValues[] = {kSecClassGenericPassword, serviceRef, accountRef,
                               valueRef, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                               kCFBooleanFalse};
    CFDictionaryRef addQuery = CFDictionaryCreate(
        kCFAllocatorDefault, addKeys, addValues, 6, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    OSStatus status = addQuery ? SecItemAdd(addQuery, nullptr) : errSecParam;
    if (addQuery)
        CFRelease(addQuery);

    if (status == errSecDuplicateItem) {
        const void *queryKeys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
        const void *queryValues[] = {kSecClassGenericPassword, serviceRef, accountRef};
        CFDictionaryRef query = CFDictionaryCreate(
            kCFAllocatorDefault, queryKeys, queryValues, 3,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        const void *updateKeys[] = {kSecValueData};
        const void *updateValues[] = {valueRef};
        CFDictionaryRef update = CFDictionaryCreate(
            kCFAllocatorDefault, updateKeys, updateValues, 1,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        status = (query && update) ? SecItemUpdate(query, update) : errSecParam;
        if (query)
            CFRelease(query);
        if (update)
            CFRelease(update);
    }

    CFRelease(valueRef);
    CFRelease(serviceRef);
    CFRelease(accountRef);

    if (status != errSecSuccess) {
        if (error)
            *error = QStringLiteral("Keychain write failed: %1").arg(keychainError(status));
        return false;
    }
    return true;
}

bool removeFromKeychain(const QString &account, QString *error)
{
    CFStringRef serviceRef = makeCFString(QString::fromLatin1(kKeychainService));
    CFStringRef accountRef = makeCFString(account);
    if (!serviceRef || !accountRef) {
        if (serviceRef)
            CFRelease(serviceRef);
        if (accountRef)
            CFRelease(accountRef);
        if (error)
            *error = QStringLiteral("Could not create Keychain query.");
        return false;
    }

    const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
    const void *values[] = {kSecClassGenericPassword, serviceRef, accountRef};
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    const OSStatus status = query ? SecItemDelete(query) : errSecParam;
    if (query)
        CFRelease(query);
    CFRelease(serviceRef);
    CFRelease(accountRef);

    if (status == errSecSuccess || status == errSecItemNotFound)
        return true;

    if (error)
        *error = QStringLiteral("Keychain delete failed: %1").arg(keychainError(status));
    return false;
}

#endif // Q_OS_MACOS

} // namespace

bool DeviceSecretStore::isAvailable()
{
#ifdef Q_OS_MACOS
    return true;
#else
    return false;
#endif
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

#ifdef Q_OS_MACOS
    ProtectedValue secret;
    QString error;
    if (!loadFromKeychain(accountName(vaultId, argon2Salt), secret, &error)) {
        LoadResult result;
        result.error = error;
        return result;
    }

    LoadResult result;
    result.ok = true;
    result.secret = std::move(secret);
    return result;
#else
    Q_UNUSED(vaultId)
    Q_UNUSED(argon2Salt)
    LoadResult result;
    result.error = QStringLiteral("Device secret not found. Secure device storage is "
                                  "not available on this platform.");
    return result;
#endif
}

bool DeviceSecretStore::store(const QString &vaultId,
                              std::span<const std::uint8_t> argon2Salt,
                              std::span<const std::uint8_t> secret, QString *error)
{
#ifdef Q_OS_MACOS
    if (secret.size() != 32) {
        if (error)
            *error = QStringLiteral("Device secret must be 32 bytes.");
        return false;
    }
    return storeToKeychain(accountName(vaultId, argon2Salt), secret, error);
#else
    Q_UNUSED(vaultId)
    Q_UNUSED(argon2Salt)
    Q_UNUSED(secret)
    if (error)
        *error = QStringLiteral("Secure device storage is not available on this platform.");
    return false;
#endif
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
#ifdef Q_OS_MACOS
    return removeFromKeychain(accountName(vaultId, argon2Salt), error);
#else
    Q_UNUSED(vaultId)
    Q_UNUSED(argon2Salt)
    Q_UNUSED(error)
    return true;
#endif
}
