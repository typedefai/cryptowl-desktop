#pragma once

#include "crypto/Bytes.h"

#include <span>

namespace cryptowl::crypto {

struct GcmCiphertext
{
    Bytes ciphertext;
    Bytes tag;
};

GcmCiphertext aesGcmEncrypt(std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> plaintext);

Bytes aesGcmDecrypt(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> nonce,
                    std::span<const std::uint8_t> aad,
                    std::span<const std::uint8_t> ciphertext,
                    std::span<const std::uint8_t> tag);

}
