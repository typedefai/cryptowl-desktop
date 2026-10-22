#pragma once

#include "crypto/Bytes.h"

#include <cstddef>

namespace cryptowl::crypto {

Bytes randomBytes(std::size_t count);

}
