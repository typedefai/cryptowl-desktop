#pragma once

#include <stdexcept>

namespace cryptowl::crypto {

class AuthenticationError : public std::runtime_error
{
public:
    AuthenticationError()
        : std::runtime_error("authentication failed (invalid tag or tampered data)")
    {
    }
};

}
