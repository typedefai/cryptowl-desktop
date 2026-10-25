#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace cryptowl::vault {

class VaultDatabase
{
public:
    static bool create(const std::string &path, std::span<const std::uint8_t> vaultKey,
                       std::string *error = nullptr);
    static bool verify(const std::string &path, std::span<const std::uint8_t> vaultKey,
                       std::string *error = nullptr);
};

}
