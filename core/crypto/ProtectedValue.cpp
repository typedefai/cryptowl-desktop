#include "crypto/ProtectedValue.h"

#include <utility>

namespace cryptowl::crypto {

ProtectedValue::ProtectedValue(Bytes bytes)
    : m_bytes(std::move(bytes))
{
}

ProtectedValue::~ProtectedValue()
{
    clear();
}

ProtectedValue::ProtectedValue(ProtectedValue &&other) noexcept
    : m_bytes(std::move(other.m_bytes))
{
    other.m_bytes.clear();
}

ProtectedValue &ProtectedValue::operator=(ProtectedValue &&other) noexcept
{
    if (this != &other) {
        clear();
        m_bytes = std::move(other.m_bytes);
        other.m_bytes.clear();
    }
    return *this;
}

std::size_t ProtectedValue::size() const
{
    return m_bytes.size();
}

bool ProtectedValue::empty() const
{
    return m_bytes.empty();
}

std::span<const std::uint8_t> ProtectedValue::span() const
{
    return m_bytes;
}

void ProtectedValue::clear()
{
    secureWipe(m_bytes);
}

}
