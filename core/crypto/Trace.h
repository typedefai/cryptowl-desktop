#pragma once

#include <cstddef>
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
