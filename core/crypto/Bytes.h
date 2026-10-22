#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cryptowl::crypto {

using Bytes = std::vector<std::uint8_t>;

std::span<const std::uint8_t> bytesOf(std::string_view text);

Bytes fromHex(std::string_view hex);
std::string toHex(std::span<const std::uint8_t> bytes);

void secureWipe(Bytes &bytes);

}
