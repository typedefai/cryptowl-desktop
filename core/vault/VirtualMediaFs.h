#pragma once

#include "crypto/FileEnvelope.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace cryptowl::vault {

class VaultSession;

enum class VfsEntryKind
{
    Directory,
    File,
};

struct VfsEntry
{
    VfsEntryKind kind = VfsEntryKind::Directory;
    std::string path;
    std::string name;
    std::string itemId;
    std::string fileId;
    std::uint64_t size = 0;
    std::int64_t modifiedAt = 0;
};

// Read-only virtual tree for the media files exposed by a native mount.
// Paths are POSIX-style and start with '/'. The tree is rebuilt with refresh().
class VirtualMediaFs
{
public:
    explicit VirtualMediaFs(VaultSession &session);

    void refresh(std::string *error = nullptr);

    bool stat(const std::string &path, VfsEntry *entry,
              std::string *error = nullptr) const;
    bool list(const std::string &path, std::vector<VfsEntry> *entries,
              std::string *error = nullptr) const;
    std::unique_ptr<crypto::FileReader> open(const std::string &path,
                                             std::string *error = nullptr) const;

    std::size_t entryCount() const;

private:
    VaultSession &m_session;
    mutable std::mutex m_mutex;
    std::vector<VfsEntry> m_entries;
};

} // namespace cryptowl::vault
