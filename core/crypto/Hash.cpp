#include "crypto/Hash.h"

#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <stdexcept>

namespace cryptowl::crypto {

Bytes sha256(std::span<const std::uint8_t> data)
{
    Bytes digest(32);
    if (mbedtls_sha256(data.data(), data.size(), digest.data(), 0) != 0)
        throw std::runtime_error("SHA-256 failure");
    return digest;
}

Bytes hmacSha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    Bytes mac(32);
    if (mbedtls_md_hmac(info, key.data(), key.size(), message.data(), message.size(),
                        mac.data())
        != 0)
        throw std::runtime_error("HMAC-SHA256 failure");
    return mac;
}

Bytes hkdfSha256(std::span<const std::uint8_t> ikm,
                 std::span<const std::uint8_t> salt,
                 std::span<const std::uint8_t> info,
                 std::size_t length)
{
    constexpr std::size_t kHashLength = 32;
    if (length == 0 || length > 255 * kHashLength)
        throw std::invalid_argument("invalid HKDF output length");

    Bytes effectiveSalt;
    if (salt.empty())
        effectiveSalt.assign(kHashLength, 0);
    else
        effectiveSalt.assign(salt.begin(), salt.end());

    Bytes prk = hmacSha256(effectiveSalt, ikm);
    secureWipe(effectiveSalt);

    Bytes okm;
    okm.reserve(length);
    Bytes block;
    for (std::uint8_t counter = 1; okm.size() < length; ++counter) {
        Bytes input;
        input.reserve(block.size() + info.size() + 1);
        input.insert(input.end(), block.begin(), block.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        secureWipe(block);
        block = hmacSha256(prk, input);
        secureWipe(input);
        okm.insert(okm.end(), block.begin(), block.end());
    }

    secureWipe(prk);
    secureWipe(block);
    okm.resize(length);
    return okm;
}

}
