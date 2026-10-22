#include "crypto/AesGcm.h"

#include "crypto/Errors.h"

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
                            std::span<const std::uint8_t> plaintext)
{
    validateKeyAndNonce(key, nonce);

    GcmContext context;
    if (setKey(context.get(), key) != 0)
        throw std::runtime_error("AES-GCM setkey failed");

    GcmCiphertext out;
    out.ciphertext.resize(plaintext.size());
    out.tag.resize(kTagLength);

    const int rc = mbedtls_gcm_crypt_and_tag(context.get(), MBEDTLS_GCM_ENCRYPT,
                                             plaintext.size(), nonce.data(), nonce.size(),
                                             aad.data(), aad.size(), plaintext.data(),
                                             out.ciphertext.data(), out.tag.size(),
                                             out.tag.data());
    if (rc != 0)
        throw std::runtime_error("AES-GCM encryption failed");

    return out;
}

Bytes aesGcmDecrypt(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> nonce,
                    std::span<const std::uint8_t> aad,
                    std::span<const std::uint8_t> ciphertext,
                    std::span<const std::uint8_t> tag)
{
    validateKeyAndNonce(key, nonce);
    if (tag.size() != kTagLength)
        throw std::invalid_argument("AES-256-GCM tag must be 16 bytes");

    GcmContext context;
    if (setKey(context.get(), key) != 0)
        throw std::runtime_error("AES-GCM setkey failed");

    Bytes plaintext(ciphertext.size());
    const int rc = mbedtls_gcm_auth_decrypt(
        context.get(), ciphertext.size(), nonce.data(), nonce.size(), aad.data(),
        aad.size(), tag.data(), tag.size(), ciphertext.data(), plaintext.data());

    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        secureWipe(plaintext);
        throw AuthenticationError();
    }
    if (rc != 0) {
        secureWipe(plaintext);
        throw std::runtime_error("AES-GCM decryption failed");
    }

    return plaintext;
}

}
