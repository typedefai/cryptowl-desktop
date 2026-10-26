#pragma once

#include "crypto/Bytes.h"

#include <span>
#include <string_view>

namespace cryptowl::crypto {

struct GcmCiphertext
{
    Bytes ciphertext;
    Bytes tag;
};

GcmCiphertext aesGcmEncrypt(std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> nonce,
                            std::span<const std::uint8_t> aad,
                            std::span<const std::uint8_t> plaintext,
                            std::string_view context = {});

Bytes aesGcmDecrypt(std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t> nonce,
                    std::span<const std::uint8_t> aad,
                    std::span<const std::uint8_t> ciphertext,
                    std::span<const std::uint8_t> tag,
                    std::string_view context = {});

}
