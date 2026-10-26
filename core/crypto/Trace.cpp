#include "crypto/Trace.h"

#include "crypto/Bytes.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace cryptowl::crypto {

namespace {

void writeLine(std::string_view line)
{
#if defined(_WIN32)
    const std::string terminated(line);
    OutputDebugStringA(terminated.c_str());
#else
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
#endif
}

#if defined(CRYPTOWL_TRACE_SECRETS) && CRYPTOWL_TRACE_SECRETS

bool secretTraceEnabled()
{
    static const bool enabled = [] {
        const char *value = std::getenv("CRYPTOWL_INSECURE_SECRETS");
        return value && std::strcmp(value, "1") == 0;
    }();
    return enabled;
}

std::string escapedText(std::string_view text, std::size_t maxBytes,
                        bool *truncated)
{
    *truncated = text.size() > maxBytes;
    const std::size_t count = std::min(text.size(), maxBytes);
    std::string escaped;
    escaped.reserve(count * 2);

    static constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < count; ++i) {
        const unsigned char value = static_cast<unsigned char>(text[i]);
        switch (value) {
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        default:
            if (value >= 0x20 && value < 0x7f) {
                escaped.push_back(static_cast<char>(value));
            } else {
                escaped += "\\x";
                escaped.push_back(kHex[value >> 4]);
                escaped.push_back(kHex[value & 0x0f]);
            }
            break;
        }
    }
    return escaped;
}

#endif

} // namespace

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
    if (written > 0)
        writeLine(line);
}

#if defined(CRYPTOWL_TRACE_SECRETS) && CRYPTOWL_TRACE_SECRETS

void traceSecret(std::string_view label, std::span<const std::uint8_t> bytes,
                 std::size_t maxBytes)
{
    if (!secretTraceEnabled())
        return;

    const std::size_t count = std::min(bytes.size(), maxBytes);
    std::string line = "[cryptowl:secret] label=";
    line.append(label);
    line += " bytes=" + std::to_string(bytes.size());
    line += " hex=";
    line += toHex(bytes.first(count));
    if (count < bytes.size())
        line += "...";
    line += '\n';
    writeLine(line);
}

void traceSecretText(std::string_view label, std::string_view text,
                     std::size_t maxBytes)
{
    if (!secretTraceEnabled())
        return;

    bool truncated = false;
    const std::string escaped = escapedText(text, maxBytes, &truncated);

    std::string line = "[cryptowl:secret] label=";
    line.append(label);
    line += " bytes=" + std::to_string(text.size());
    line += " text=\"";
    line += escaped;
    if (truncated)
        line += "...";
    line += "\"\n";
    writeLine(line);
}

void traceAeadSecrets(std::string_view operation, std::string_view context,
                      std::span<const std::uint8_t> key,
                      std::span<const std::uint8_t> nonce,
                      std::span<const std::uint8_t> aad,
                      std::span<const std::uint8_t> input,
                      std::span<const std::uint8_t> output,
                      std::span<const std::uint8_t> tag, bool)
{
    if (!secretTraceEnabled())
        return;

    const std::string prefix = std::string(context) + ".";
    const bool encrypt = operation == "encrypt";

    traceSecret(prefix + "key", key);
    traceSecret(prefix + "nonce", nonce);
    traceSecret(prefix + "aad", aad);
    traceSecret(prefix + (encrypt ? "plaintext" : "ciphertext"), input, 2048);
    traceSecret(prefix + (encrypt ? "ciphertext" : "plaintext"), output, 2048);
    traceSecret(prefix + "tag", tag);
}

void traceSqlCipher(std::string_view databasePath,
                    std::span<const std::uint8_t> rawKey)
{
    if (!secretTraceEnabled())
        return;

    traceSecret("sqlcipher.raw_key", rawKey);

    std::string command = "sqlcipher \"";
    command.append(databasePath);
    command += "\"\nPRAGMA key = \"x'";
    command += toHex(rawKey);
    command += "'\";\n.tables\n";
    traceSecretText("sqlcipher.open", command, 8192);
}

#endif

} // namespace cryptowl::crypto
