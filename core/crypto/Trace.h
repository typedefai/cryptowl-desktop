#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#if defined(CRYPTOWL_TRACE_CRYPTO) && CRYPTOWL_TRACE_CRYPTO

namespace cryptowl::crypto {

// Metadata-only trace for AEAD operations. Never pass key material,
// plaintext, ciphertext, nonces, tags, or AAD contents here.
void traceCrypto(std::string_view operation, std::string_view context,
                 std::size_t aadBytes, std::size_t inputBytes,
                 std::size_t outputBytes, bool success);

} // namespace cryptowl::crypto

#define CRYPTOWL_TRACE_CRYPTO_EVENT(...) \
    ::cryptowl::crypto::traceCrypto(__VA_ARGS__)

#else

#define CRYPTOWL_TRACE_CRYPTO_EVENT(...) ((void)0)

#endif

#if defined(CRYPTOWL_TRACE_SECRETS) && CRYPTOWL_TRACE_SECRETS

namespace cryptowl::crypto {

// Insecure diagnostic dump. Only compiled into an explicitly enabled
// CRYPTOWL_TRACE_SECRETS cross-verification build; never ship that build.
void traceSecret(std::string_view label, std::span<const std::uint8_t> bytes,
                 std::size_t maxBytes = 4096);
void traceSecretText(std::string_view label, std::string_view text,
                     std::size_t maxBytes = 4096);
void traceAeadSecrets(std::string_view operation, std::string_view context,
                      std::span<const std::uint8_t> key,
                      std::span<const std::uint8_t> nonce,
                      std::span<const std::uint8_t> aad,
                      std::span<const std::uint8_t> input,
                      std::span<const std::uint8_t> output,
                      std::span<const std::uint8_t> tag, bool success);
void traceSqlCipher(std::string_view databasePath,
                    std::span<const std::uint8_t> rawKey);

} // namespace cryptowl::crypto

#define CRYPTOWL_TRACE_SECRET(...) \
    ::cryptowl::crypto::traceSecret(__VA_ARGS__)
#define CRYPTOWL_TRACE_SECRET_TEXT(...) \
    ::cryptowl::crypto::traceSecretText(__VA_ARGS__)
#define CRYPTOWL_TRACE_AEAD_SECRETS(...) \
    ::cryptowl::crypto::traceAeadSecrets(__VA_ARGS__)
#define CRYPTOWL_TRACE_SQLCIPHER(...) \
    ::cryptowl::crypto::traceSqlCipher(__VA_ARGS__)

#else

#define CRYPTOWL_TRACE_SECRET(...) ((void)0)
#define CRYPTOWL_TRACE_SECRET_TEXT(...) ((void)0)
#define CRYPTOWL_TRACE_AEAD_SECRETS(...) ((void)0)
#define CRYPTOWL_TRACE_SQLCIPHER(...) ((void)0)

#endif
