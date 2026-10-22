#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cryptowl::crypto {

std::string crockford32Encode(std::span<const std::uint8_t> data);
std::vector<std::uint8_t> crockford32Decode(std::string_view encoded);

}
