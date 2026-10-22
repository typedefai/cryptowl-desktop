#include "crypto/Crockford32.h"

#include <cctype>
#include <stdexcept>
#include <string>

namespace cryptowl::crypto {

namespace {

constexpr std::string_view kAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
constexpr std::size_t kGroupSize = 5;

int charValue(char c)
{
    char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (upper == 'I' || upper == 'L')
        upper = '1';
    else if (upper == 'O')
        upper = '0';

    const std::size_t index = kAlphabet.find(upper);
    if (index == std::string_view::npos)
        throw std::invalid_argument(std::string("invalid Crockford Base32 character: ") + c);
    return static_cast<int>(index);
}

}

std::string crockford32Encode(std::span<const std::uint8_t> data)
{
    std::string chars;
    chars.reserve(data.size() * 8 / 5 + 1);

    std::uint32_t buffer = 0;
    int bits = 0;
    for (const std::uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            chars.push_back(kAlphabet[(buffer >> bits) & 0x1F]);
        }
    }
    if (bits > 0)
        chars.push_back(kAlphabet[(buffer << (5 - bits)) & 0x1F]);

    std::string out;
    out.reserve(chars.size() + chars.size() / kGroupSize);
    for (std::size_t i = 0; i < chars.size(); ++i) {
        if (i > 0 && i % kGroupSize == 0)
            out.push_back('-');
        out.push_back(chars[i]);
    }
    return out;
}

std::vector<std::uint8_t> crockford32Decode(std::string_view encoded)
{
    std::vector<std::uint8_t> out;
    out.reserve(encoded.size() * 5 / 8);

    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char c : encoded) {
        if (c == '-')
            continue;
        buffer = (buffer << 5) | static_cast<std::uint32_t>(charValue(c));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

}
