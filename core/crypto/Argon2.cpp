#include "crypto/Argon2.h"

#include <argon2.h>

#include <limits>
#include <stdexcept>
#include <string>

namespace cryptowl::crypto {

Bytes argon2id(std::span<const std::uint8_t> password,
               std::span<const std::uint8_t> salt,
               const Argon2Params &params,
               std::size_t hashLength)
{
    if (password.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument("password too long");
    if (hashLength == 0)
        throw std::invalid_argument("hash length must be positive");

    Bytes output(hashLength);
    const int rc = argon2_hash(
        static_cast<std::uint32_t>(params.iterations),
        static_cast<std::uint32_t>(params.memoryKib),
        static_cast<std::uint32_t>(params.parallelism), password.data(), password.size(),
        salt.data(), salt.size(), output.data(), output.size(), nullptr, 0, Argon2_id,
        ARGON2_VERSION_NUMBER);
    if (rc != ARGON2_OK) {
        secureWipe(output);
        throw std::runtime_error(std::string("argon2id failed: ") + argon2_error_message(rc));
    }

    return output;
}

}
