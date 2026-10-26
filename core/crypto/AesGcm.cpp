#include "crypto/AesGcm.h"

#include "crypto/Errors.h"
#include "crypto/Trace.h"

#include <mbedtls/gcm.h>

#include <stdexcept>

namespace cryptowl::crypto {

namespace {

constexpr std::size_t kKeyLength = 32;
constexpr std::size_t kNonceLength = 12;
constexpr std::size_t kTagLength = 16;

void validateKeyAndNonce(std::span<const std::uint8_t> key,
                         std::span<const std::uint8_t> nonce)
{
    if (key.size() != kKeyLength)
        throw std::invalid_argument("AES-256-GCM key must be 32 bytes");
    if (nonce.size() != kNonceLength)
        throw std::invalid_argument("AES-256-GCM nonce must be 12 bytes");
}

class GcmContext
{
public:
    GcmContext()
    {
        mbedtls_gcm_init(&m_context);
    }

    ~GcmContext()
    {
        mbedtls_gcm_free(&m_context);
    }

    GcmContext(const GcmContext &) = delete;
    GcmContext &operator=(const GcmContext &) = delete;

    mbedtls_gcm_context *get()
    {
        return &m_context;
    }

private:
    mbedtls_gcm_context m_context{};
};

int setKey(mbedtls_gcm_context *context, std::span<const std::uint8_t> key)
{
    return mbedtls_gcm_setkey(context, MBEDTLS_CIPHER_ID_AES, key.data(),
                              static_cast<unsigned int>(key.size() * 8));
}

}

GcmCiphertext aesGcmEncrypt(std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> plaintext,
                            std::string_view context)
{
    validateKeyAndNonce(key, nonce);

    GcmContext gcm;
    if (setKey(gcm.get(), key) != 0) {
        CRYPTOWL_TRACE_CRYPTO_EVENT("encrypt", context, aad.size(),
                                    plaintext.size(), 0, false);
        CRYPTOWL_TRACE_AEAD_SECRETS(
            "encrypt", context, key, nonce, aad, plaintext,
            std::span<const std::uint8_t>(), std::span<const std::uint8_t>(),
            false);
        throw std::runtime_error("AES-GCM setkey failed");
    }

    GcmCiphertext out;
    out.ciphertext.resize(plaintext.size());
    out.tag.resize(kTagLength);

    const int rc = mbedtls_gcm_crypt_and_tag(gcm.get(), MBEDTLS_GCM_ENCRYPT,
                                             plaintext.size(), nonce.data(),
                                             nonce.size(), aad.data(), aad.size(),
                                             plaintext.data(), out.ciphertext.data(),
                                             out.tag.size(), out.tag.data());
    if (rc != 0) {
        CRYPTOWL_TRACE_CRYPTO_EVENT("encrypt", context, aad.size(),
                                    plaintext.size(), 0, false);
        CRYPTOWL_TRACE_AEAD_SECRETS(
            "encrypt", context, key, nonce, aad, plaintext,
            std::span<const std::uint8_t>(), std::span<const std::uint8_t>(),
            false);
        throw std::runtime_error("AES-GCM encryption failed");
    }

    CRYPTOWL_TRACE_CRYPTO_EVENT("encrypt", context, aad.size(),
                                plaintext.size(), out.ciphertext.size(), true);
    CRYPTOWL_TRACE_AEAD_SECRETS("encrypt", context, key, nonce, aad, plaintext,
                                out.ciphertext, out.tag, true);
    return out;
}

Bytes aesGcmDecrypt(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> nonce,
                    std::span<const std::uint8_t> aad,
                    std::span<const std::uint8_t> ciphertext,
                    std::span<const std::uint8_t> tag,
                    std::string_view context)
{
    validateKeyAndNonce(key, nonce);
    if (tag.size() != kTagLength) {
        CRYPTOWL_TRACE_CRYPTO_EVENT("decrypt", context, aad.size(),
                                    ciphertext.size(), 0, false);
        CRYPTOWL_TRACE_AEAD_SECRETS(
            "decrypt", context, key, nonce, aad, ciphertext,
            std::span<const std::uint8_t>(), tag, false);
        throw std::invalid_argument("AES-256-GCM tag must be 16 bytes");
    }

    GcmContext gcm;
    if (setKey(gcm.get(), key) != 0) {
        CRYPTOWL_TRACE_CRYPTO_EVENT("decrypt", context, aad.size(),
                                    ciphertext.size(), 0, false);
        CRYPTOWL_TRACE_AEAD_SECRETS(
            "decrypt", context, key, nonce, aad, ciphertext,
            std::span<const std::uint8_t>(), tag, false);
        throw std::runtime_error("AES-GCM setkey failed");
    }

    Bytes plaintext(ciphertext.size());
    const int rc = mbedtls_gcm_auth_decrypt(
        gcm.get(), ciphertext.size(), nonce.data(), nonce.size(), aad.data(),
        aad.size(), tag.data(), tag.size(), ciphertext.data(), plaintext.data());

    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        secureWipe(plaintext);
        CRYPTOWL_TRACE_CRYPTO_EVENT("decrypt", context, aad.size(),
                                    ciphertext.size(), 0, false);
        CRYPTOWL_TRACE_AEAD_SECRETS(
            "decrypt", context, key, nonce, aad, ciphertext,
            std::span<const std::uint8_t>(), tag, false);
        throw AuthenticationError();
    }
    if (rc != 0) {
        secureWipe(plaintext);
        CRYPTOWL_TRACE_CRYPTO_EVENT("decrypt", context, aad.size(),
                                    ciphertext.size(), 0, false);
        CRYPTOWL_TRACE_AEAD_SECRETS(
            "decrypt", context, key, nonce, aad, ciphertext,
            std::span<const std::uint8_t>(), tag, false);
        throw std::runtime_error("AES-GCM decryption failed");
    }

    CRYPTOWL_TRACE_CRYPTO_EVENT("decrypt", context, aad.size(), ciphertext.size(),
                                plaintext.size(), true);
    CRYPTOWL_TRACE_AEAD_SECRETS("decrypt", context, key, nonce, aad, ciphertext,
                                plaintext, tag, true);
    return plaintext;
}

}
