#pragma once

#include "crypto/Bytes.h"

#include <cstddef>
#include <span>

namespace cryptowl::crypto {

class ProtectedValue
{
public:
    ProtectedValue() = default;
    explicit ProtectedValue(Bytes bytes);
    ~ProtectedValue();

    ProtectedValue(const ProtectedValue &) = delete;
    ProtectedValue &operator=(const ProtectedValue &) = delete;
    ProtectedValue(ProtectedValue &&other) noexcept;
    ProtectedValue &operator=(ProtectedValue &&other) noexcept;

    std::size_t size() const;
    bool empty() const;
    std::span<const std::uint8_t> span() const;

    void clear();

private:
    Bytes m_bytes;
};

}
