#include "crypto/Bytes.h"

#include <mbedtls/platform_util.h>

#include <stdexcept>

namespace cryptowl::crypto {

std::span<const std::uint8_t> bytesOf(std::string_view text)
{
    return {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()};
}

namespace {

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

}

Bytes fromHex(std::string_view hex)
{
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("hex string must have an even number of digits");

    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hexValue(hex[i]);
        const int lo = hexValue(hex[i + 1]);
        if (hi < 0 || lo < 0)
            throw std::invalid_argument("invalid hex digit");
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string toHex(std::span<const std::uint8_t> bytes)
{
    static constexpr char kDigits[] = "0123456789abcdef";

    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::uint8_t byte : bytes) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0F]);
    }
    return out;
}

void secureWipe(Bytes &bytes)
{
    if (!bytes.empty())
        mbedtls_platform_zeroize(bytes.data(), bytes.size());
    bytes.clear();
}

}
