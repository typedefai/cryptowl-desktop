#include "crypto/Trace.h"

#if defined(CRYPTOWL_TRACE_CRYPTO) && CRYPTOWL_TRACE_CRYPTO

#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace cryptowl::crypto {

void traceCrypto(std::string_view operation, std::string_view context,
                 std::size_t aadBytes, std::size_t inputBytes,
                 std::size_t outputBytes, bool success)
{
    if (context.empty())
        context = std::string_view("aes-gcm");

    char line[512];
    const int written = std::snprintf(
        line, sizeof(line),
        "[cryptowl:crypto] op=%.*s context=%.*s aad=%zu in=%zu out=%zu "
        "status=%s\n",
        static_cast<int>(operation.size()), operation.data(),
        static_cast<int>(context.size()), context.data(), aadBytes, inputBytes,
        outputBytes, success ? "ok" : "failed");
    if (written <= 0)
        return;

#if defined(_WIN32)
    OutputDebugStringA(line);
#else
    std::fputs(line, stderr);
    std::fflush(stderr);
#endif
}

} // namespace cryptowl::crypto

#endif
