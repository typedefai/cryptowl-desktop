#include "crypto/Trace.h"

#include "crypto/Bytes.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace cryptowl::crypto {

namespace {

// ---------------------------------------------------------------------------
// Terminal styling
// ---------------------------------------------------------------------------

constexpr std::string_view kDim = "2";
constexpr std::string_view kBold = "1";
constexpr std::string_view kRed = "31";
constexpr std::string_view kGreen = "32";
constexpr std::string_view kYellow = "33";
constexpr std::string_view kBlue = "34";
constexpr std::string_view kMagenta = "35";
constexpr std::string_view kCyan = "36";
constexpr std::string_view kBoldRed = "1;31";
constexpr std::string_view kBoldGreen = "1;32";
constexpr std::string_view kBoldYellow = "1;33";
constexpr std::string_view kBoldMagenta = "1;35";
constexpr std::string_view kBoldCyan = "1;36";
constexpr std::string_view kPlaintext = kBold;
constexpr std::string_view kCiphertext = kGreen;

bool colorEnabled()
{
    // CRYPTOWL_TRACE_COLOR=always|never|auto overrides the automatic choice.
    // The default only colors a real terminal, so redirecting to a file keeps
    // the log free of escape sequences.
    static const bool enabled = [] {
        if (const char *mode = std::getenv("CRYPTOWL_TRACE_COLOR")) {
            if (std::strcmp(mode, "always") == 0)
                return true;
            if (std::strcmp(mode, "never") == 0)
                return false;
        }
        if (const char *noColor = std::getenv("NO_COLOR");
            noColor != nullptr && *noColor != '\0')
            return false;
        if (const char *term = std::getenv("TERM");
            term != nullptr && std::strcmp(term, "dumb") == 0)
            return false;
#if defined(_WIN32)
        const HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
        DWORD mode = 0;
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE
            || !GetConsoleMode(handle, &mode))
            return false;
        if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0
            && !SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            return false;
        return true;
#else
        return ::isatty(STDERR_FILENO) == 1;
#endif
    }();
    return enabled;
}

std::string styled(std::string_view text, std::string_view style)
{
    if (!colorEnabled() || text.empty() || style.empty())
        return std::string(text);

    std::string out;
    out.reserve(text.size() + style.size() + 7);
    out += "\x1b[";
    out.append(style);
    out.push_back('m');
    out.append(text);
    out += "\x1b[0m";
    return out;
}

void writeLine(std::string_view line)
{
#if defined(_WIN32)
    const HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
    const DWORD type =
        (handle == nullptr || handle == INVALID_HANDLE_VALUE)
            ? FILE_TYPE_UNKNOWN
            : GetFileType(handle);
    bool useStderr = type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK;
    if (type == FILE_TYPE_CHAR) {
        DWORD consoleMode = 0;
        useStderr = GetConsoleMode(handle, &consoleMode) != 0;
    }
    if (useStderr) {
        std::fwrite(line.data(), 1, line.size(), stderr);
        std::fputc('\n', stderr);
        std::fflush(stderr);
    } else {
        std::string terminated(line);
        terminated.push_back('\n');
        OutputDebugStringA(terminated.c_str());
    }
#else
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fputc('\n', stderr);
    std::fflush(stderr);
#endif
}

std::string prefix()
{
    return styled("[cryptowl:crypto]", kDim) + " ";
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

constexpr std::size_t kFieldWidth = 10; // "ciphertext"
constexpr std::size_t kSizeWidth = 8;   // "   2048 B"
constexpr std::size_t kLabelWidth = 20;
constexpr std::size_t kHexGroupBytes = 4;
constexpr std::size_t kHexGroupsPerLine = 4;

std::string paddedRight(std::string_view text, std::size_t width)
{
    std::string out(text);
    if (out.size() < width)
        out.append(width - out.size(), ' ');
    return out;
}

std::string paddedLeft(std::string_view text, std::size_t width)
{
    std::string out;
    if (text.size() < width)
        out.append(width - text.size(), ' ');
    out.append(text);
    return out;
}

std::string formatSize(std::size_t size)
{
    return std::to_string(size) + " B";
}

std::string_view textOf(std::span<const std::uint8_t> bytes)
{
    if (bytes.empty())
        return {};
    return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

// Hex in 4-byte groups, 16 bytes per line. This keeps every line readable on
// an 80-column terminal while still fitting a nonce or tag on one line.
std::vector<std::string> hexLines(std::span<const std::uint8_t> bytes,
                                  std::size_t maxBytes, bool *truncated)
{
    const std::size_t count = std::min(bytes.size(), maxBytes);
    *truncated = count < bytes.size();

    std::vector<std::string> lines;
    std::string current;
    for (std::size_t offset = 0; offset < count; offset += kHexGroupBytes) {
        if (!current.empty())
            current.push_back(' ');
        const std::size_t group = std::min(kHexGroupBytes, count - offset);
        current += toHex(bytes.subspan(offset, group));
        if ((offset / kHexGroupBytes + 1) % kHexGroupsPerLine == 0
            || offset + group == count) {
            lines.push_back(std::move(current));
            current.clear();
        }
    }
    return lines;
}

bool isPrintable(std::span<const std::uint8_t> bytes)
{
    if (bytes.empty())
        return false;
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) {
        return byte >= 0x20 && byte < 0x7f;
    });
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

std::string_view labelStyle(std::string_view label)
{
    if (label.starts_with("kdf."))
        return kBoldCyan;
    if (label == "item.dek" || label.starts_with("key."))
        return kBoldMagenta;
    if (label.starts_with("item.payload"))
        return kPlaintext;
    if (label.starts_with("item."))
        return kBoldYellow;
    if (label.starts_with("sqlcipher"))
        return kBoldRed;
    if (label.starts_with("vault."))
        return kBoldGreen;
    return kBold;
}

std::string_view labelHexStyle(std::string_view label)
{
    if (label.find("salt") != std::string_view::npos
        || label.find("nonce") != std::string_view::npos)
        return kYellow;
    if (label.find("payload") != std::string_view::npos
        || label.find("plaintext") != std::string_view::npos)
        return kBold;
    if (label.find("ciphertext") != std::string_view::npos)
        return kGreen;
    if (label.find("tag") != std::string_view::npos)
        return kCyan;
    if (label.starts_with("sqlcipher"))
        return kRed;
    return kMagenta;
}

std::string blockHead(std::string_view name, std::size_t size)
{
    return prefix() + styled("|", kDim) + "  "
        + styled(paddedRight(name, kFieldWidth), kDim) + "  "
        + styled(paddedLeft(formatSize(size), kSizeWidth), kDim) + "  ";
}

void writeBlockField(std::string_view name, std::span<const std::uint8_t> bytes,
                     std::size_t maxBytes, std::string_view style)
{
    const std::string head = blockHead(name, bytes.size());
    bool truncated = false;
    std::vector<std::string> lines = hexLines(bytes, maxBytes, &truncated);
    if (lines.empty()) {
        writeLine(head + styled(truncated ? "<truncated>" : "<empty>", kDim));
        return;
    }
    if (truncated)
        lines.back() += " ...";

    writeLine(head + styled(lines.front(), style));
    const std::string indent(kFieldWidth + kSizeWidth + 6, ' ');
    for (std::size_t i = 1; i < lines.size(); ++i)
        writeLine(prefix() + styled("|", kDim) + indent
                  + styled(lines[i], style));
}

void writeAadField(std::span<const std::uint8_t> aad)
{
    if (!isPrintable(aad)) {
        writeBlockField("aad", aad, 4096, kBlue);
        return;
    }

    const std::string head = blockHead("aad", aad.size());
    bool truncated = false;
    std::string quoted = "\"";
    quoted += escapedText(textOf(aad), 128, &truncated);
    if (truncated)
        quoted += "...";
    quoted += '"';

    std::string line = head + styled(quoted, kBoldCyan);
    writeLine(line);
}

// ---------------------------------------------------------------------------
// Secret lines
// ---------------------------------------------------------------------------

std::string secretHead(std::string_view label, std::size_t bytes)
{
    std::string head = prefix() + styled("secret=1", kDim) + " ";
    head += styled("label=", kDim);
    head += styled(paddedRight(label, kLabelWidth), labelStyle(label));
    head += " " + styled("bytes=", kDim) + styled(std::to_string(bytes), kDim);
    head += " " + styled("hex=", kDim);
    return head;
}

} // namespace

void traceSecret(std::string_view label, std::span<const std::uint8_t> bytes,
                 std::size_t maxBytes)
{
    const std::string head = secretHead(label, bytes.size());
    bool truncated = false;
    std::vector<std::string> lines = hexLines(bytes, maxBytes, &truncated);
    if (lines.empty()) {
        writeLine(head + styled(truncated ? "<truncated>" : "<empty>", kDim));
        return;
    }
    if (truncated)
        lines.back() += " ...";

    writeLine(head + styled(lines.front(), labelHexStyle(label)));
    for (std::size_t i = 1; i < lines.size(); ++i)
        writeLine(prefix() + "  " + styled(lines[i], labelHexStyle(label)));
}

void traceSecretText(std::string_view label, std::string_view text,
                     std::size_t maxBytes)
{
    bool truncated = false;
    std::string quoted = "\"";
    quoted += escapedText(text, maxBytes, &truncated);
    if (truncated)
        quoted += "...";
    quoted += '"';

    std::string line = prefix() + styled("secret=1", kDim) + " ";
    line += styled("label=", kDim);
    line += styled(paddedRight(label, kLabelWidth), labelStyle(label));
    line += " " + styled("bytes=", kDim)
        + styled(std::to_string(text.size()), kDim);
    line += " " + styled("text=", kDim) + styled(quoted, kPlaintext);
    writeLine(line);
}

void traceAeadSecrets(std::string_view operation, std::string_view context,
                      std::span<const std::uint8_t> key,
                      std::span<const std::uint8_t> nonce,
                      std::span<const std::uint8_t> aad,
                      std::span<const std::uint8_t> input,
                      std::span<const std::uint8_t> output,
                      std::span<const std::uint8_t> tag, bool success)
{
    if (context.empty())
        context = std::string_view("aes-gcm");
    const bool encrypt = operation == "encrypt";

    std::string header = prefix() + styled("+-", kDim) + " "
        + styled("AES-256-GCM", kDim) + " "
        + styled(operation, encrypt ? kBoldGreen : kBoldCyan) + "  "
        + styled(context, kBold);
    writeLine(header);

    writeBlockField("key", key, 4096, kMagenta);
    writeBlockField("nonce", nonce, 4096, kYellow);
    writeAadField(aad);
    writeBlockField(encrypt ? "plaintext" : "ciphertext", input, 2048,
                    encrypt ? kPlaintext : kCiphertext);
    writeBlockField(encrypt ? "ciphertext" : "plaintext", output, 2048,
                    encrypt ? kCiphertext : kPlaintext);
    writeBlockField("tag", tag, 4096, kCyan);

    std::string footer = prefix() + styled("+-", kDim) + " "
        + styled(success ? "ok" : "failed", success ? kBoldGreen : kBoldRed);
    writeLine(footer);
}

void traceSqlCipher(std::string_view databasePath,
                    std::span<const std::uint8_t> rawKey)
{
    std::string header = prefix() + styled("+-", kDim) + " "
        + styled("sqlcipher", kBoldCyan) + "  "
        + styled(databasePath, kBold);
    writeLine(header);

    writeBlockField("raw_key", rawKey, 4096, kMagenta);
    writeLine(prefix() + styled("|", kDim) + "  "
              + styled("reopen with:", kDim));

    // Write the command without the trace prefix so it can be copied into a
    // terminal as-is.
    std::string command = "sqlcipher \"";
    command.append(databasePath);
    command += "\"\nPRAGMA key = \"x'";
    command += toHex(rawKey);
    command += "'\";\n.tables";

    std::size_t start = 0;
    while (true) {
        const std::size_t end = command.find('\n', start);
        const std::string_view line =
            end == std::string::npos
                ? std::string_view(command).substr(start)
                : std::string_view(command).substr(start, end - start);
        writeLine(line);
        if (end == std::string::npos)
            break;
        start = end + 1;
    }

    writeLine(prefix() + styled("+-", kDim));
}

} // namespace cryptowl::crypto
