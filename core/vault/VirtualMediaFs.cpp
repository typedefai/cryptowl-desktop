#include "vault/VirtualMediaFs.h"

#include "vault/FileRepository.h"
#include "vault/ItemRepository.h"
#include "vault/VaultSession.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <set>
#include <utility>

namespace cryptowl::vault {

namespace {

void setError(std::string *error, std::string message)
{
    if (error)
        *error = std::move(message);
}

std::string normalizePath(const std::string &input)
{
    if (input.empty())
        return "/";
    std::string path;
    path.reserve(input.size() + 1);
    if (input.front() != '/')
        path.push_back('/');
    for (char ch : input) {
        if (ch == '/' && !path.empty() && path.back() == '/')
            continue;
        path.push_back(ch);
    }
    while (path.size() > 1 && path.back() == '/')
        path.pop_back();
    return path;
}

std::string parentPath(const std::string &path)
{
    if (path == "/")
        return {};
    const std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0)
        return "/";
    return path.substr(0, slash);
}

std::string sanitizeName(std::string name)
{
    if (name.empty())
        name = "media";
    for (char &ch : name) {
        if (ch == '/' || ch == '\\' || ch == '\0'
            || static_cast<unsigned char>(ch) < 0x20) {
            ch = '_';
        }
    }
    if (name == "." || name == "..")
        name = "media";
    return name;
}

std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return value;
}

bool endsWithInsensitive(const std::string &value, const std::string &suffix)
{
    if (suffix.size() > value.size())
        return false;
    return lower(value.substr(value.size() - suffix.size())) == lower(suffix);
}

std::string extensionForMime(const std::string &mime)
{
    if (mime == "image/jpeg")
        return ".jpg";
    if (mime == "image/png")
        return ".png";
    if (mime == "image/gif")
        return ".gif";
    if (mime == "image/webp")
        return ".webp";
    if (mime == "image/bmp")
        return ".bmp";
    if (mime == "image/tiff")
        return ".tiff";
    if (mime == "video/mp4")
        return ".mp4";
    if (mime == "video/quicktime")
        return ".mov";
    if (mime == "video/webm")
        return ".webm";
    if (mime == "video/x-matroska")
        return ".mkv";
    if (mime == "video/x-msvideo")
        return ".avi";
    return {};
}

} // namespace

VirtualMediaFs::VirtualMediaFs(VaultSession &session)
    : m_session(session)
{
}

void VirtualMediaFs::refresh(std::string *error)
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    m_entries.clear();
    m_entries.push_back({VfsEntryKind::Directory, "/", "", {}, {}, 0, 0});
    m_entries.push_back(
        {VfsEntryKind::Directory, "/Photos", "Photos", {}, {}, 0, 0});
    m_entries.push_back(
        {VfsEntryKind::Directory, "/Videos", "Videos", {}, {}, 0, 0});

    std::vector<ItemSummary> items;
    std::string listError;
    if (!m_session.items().list(std::string(), &items, &listError)) {
        setError(error, listError);
        return;
    }

    std::set<std::string> usedPhotos;
    std::set<std::string> usedVideos;
    for (const ItemSummary &item : items) {
        if (item.classification != "C")
            continue;
        const bool photo = item.type == "photo";
        const bool video = item.type == "video";
        if (!photo && !video)
            continue;

        std::vector<FileRecord> files;
        std::string fileError;
        if (!m_session.files().listForItem(item.id, &files, &fileError)) {
            if (error && error->empty())
                *error = fileError;
            continue;
        }

        for (const FileRecord &file : files) {
            std::string name = sanitizeName(item.title);
            std::filesystem::path original(file.name);
            std::string extension = original.extension().string();
            if (extension.empty())
                extension = extensionForMime(file.mimeType);
            if (!extension.empty() && !endsWithInsensitive(name, extension))
                name += extension;

            std::set<std::string> &used = photo ? usedPhotos : usedVideos;
            std::string candidate = name;
            int suffix = 2;
            while (used.count(candidate) > 0) {
                const std::string base =
                    extension.empty() ? name
                                      : name.substr(0, name.size() - extension.size());
                candidate = base + " (" + std::to_string(suffix++) + ")"
                    + extension;
            }
            used.insert(candidate);

            VfsEntry entry;
            entry.kind = VfsEntryKind::File;
            entry.path = (photo ? "/Photos/" : "/Videos/") + candidate;
            entry.name = candidate;
            entry.itemId = item.id;
            entry.fileId = file.id;
            entry.size = file.sizeBytes;
            entry.modifiedAt = file.updatedAt;
            m_entries.push_back(std::move(entry));
        }
    }
}

bool VirtualMediaFs::stat(const std::string &rawPath, VfsEntry *entry,
                          std::string *error) const
{
    if (!entry) {
        setError(error, "VFS entry destination is null");
        return false;
    }
    const std::string path = normalizePath(rawPath);
    const std::lock_guard<std::mutex> lock(m_mutex);
    for (const VfsEntry &candidate : m_entries) {
        if (candidate.path == path) {
            *entry = candidate;
            return true;
        }
    }
    setError(error, "VFS path was not found");
    return false;
}

bool VirtualMediaFs::list(const std::string &rawPath,
                          std::vector<VfsEntry> *entries,
                          std::string *error) const
{
    if (!entries) {
        setError(error, "VFS list destination is null");
        return false;
    }
    entries->clear();
    const std::string path = normalizePath(rawPath);
    const std::lock_guard<std::mutex> lock(m_mutex);

    bool found = false;
    for (const VfsEntry &candidate : m_entries) {
        if (candidate.path == path) {
            found = candidate.kind == VfsEntryKind::Directory;
            break;
        }
    }
    if (!found) {
        setError(error, "VFS directory was not found");
        return false;
    }

    for (const VfsEntry &candidate : m_entries) {
        if (parentPath(candidate.path) == path)
            entries->push_back(candidate);
    }
    std::sort(entries->begin(), entries->end(),
              [](const VfsEntry &left, const VfsEntry &right) {
                  if (left.kind != right.kind)
                      return left.kind == VfsEntryKind::Directory;
                  return lower(left.name) < lower(right.name);
              });
    return true;
}

std::unique_ptr<crypto::FileReader> VirtualMediaFs::open(
    const std::string &rawPath, std::string *error) const
{
    VfsEntry entry;
    if (!stat(rawPath, &entry, error))
        return nullptr;
    if (entry.kind != VfsEntryKind::File) {
        setError(error, "VFS path is not a file");
        return nullptr;
    }
    return m_session.files().openRead(entry.fileId, error);
}

std::size_t VirtualMediaFs::entryCount() const
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

} // namespace cryptowl::vault
