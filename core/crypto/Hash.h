#pragma once

#include "crypto/Bytes.h"

#include <cstddef>
#include <span>

namespace cryptowl::crypto {

Bytes sha256(std::span<const std::uint8_t> data);

Bytes hmacSha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> message);

Bytes hkdfSha256(std::span<const std::uint8_t> ikm,
                 std::span<const std::uint8_t> salt,
                 std::span<const std::uint8_t> info,
                 std::size_t length);

}
