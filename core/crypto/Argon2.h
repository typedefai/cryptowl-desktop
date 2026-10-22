#pragma once

#include "crypto/Bytes.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace cryptowl::crypto {

struct Argon2Params
{
    std::uint32_t memoryKib = 19456;
    std::uint32_t iterations = 2;
    std::uint32_t parallelism = 1;
};

Bytes argon2id(std::span<const std::uint8_t> password,
               std::span<const std::uint8_t> salt,
               const Argon2Params &params = {},
               std::size_t hashLength = 32);

}
