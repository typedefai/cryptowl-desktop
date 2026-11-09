#include "vfs/FuseMount.h"

#include "vault/VirtualMediaFs.h"

#include <QByteArray>
#include <QString>

#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(CRYPTOWL_HAS_FUSE)

#define FUSE_USE_VERSION 35
#include <fuse3/fuse.h>

#include <fcntl.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/statvfs.h>
#endif
#include <unistd.h>

#endif

namespace {

#if defined(CRYPTOWL_HAS_FUSE)

struct MountContext
{
    cryptowl::vault::VirtualMediaFs *fs = nullptr;
};

struct FileHandle
{
    std::unique_ptr<cryptowl::crypto::FileReader> reader;
};

MountContext *context()
{
    return static_cast<MountContext *>(fuse_get_context()->private_data);
}

#ifdef __APPLE__
int fuseGetattr(const char *path, struct fuse_darwin_attr *attributes,
                struct fuse_file_info *)
#else
int fuseGetattr(const char *path, struct stat *attributes,
                struct fuse_file_info *)
#endif
{
    if (!attributes)
        return -EINVAL;
    cryptowl::vault::VfsEntry entry;
    std::string error;
    if (!context()->fs->stat(path, &entry, &error))
        return -ENOENT;

    std::memset(attributes, 0, sizeof(*attributes));
#ifdef __APPLE__
    if (entry.kind == cryptowl::vault::VfsEntryKind::Directory) {
        attributes->mode = S_IFDIR | 0555;
        attributes->nlink = 2;
    } else {
        attributes->mode = S_IFREG | 0444;
        attributes->nlink = 1;
        attributes->size = static_cast<off_t>(entry.size);
    }
    attributes->uid = getuid();
    attributes->gid = getgid();
    attributes->mtimespec.tv_sec = static_cast<time_t>(entry.modifiedAt / 1000);
#else
    if (entry.kind == cryptowl::vault::VfsEntryKind::Directory) {
        attributes->st_mode = S_IFDIR | 0555;
        attributes->st_nlink = 2;
    } else {
        attributes->st_mode = S_IFREG | 0444;
        attributes->st_nlink = 1;
        attributes->st_size = static_cast<off_t>(entry.size);
    }
    attributes->st_uid = getuid();
    attributes->st_gid = getgid();
    attributes->st_mtime = static_cast<time_t>(entry.modifiedAt / 1000);
#endif
    return 0;
}

#ifdef __APPLE__
int fuseReaddir(const char *path, void *buffer, fuse_darwin_fill_dir_t filler,
                off_t, struct fuse_file_info *, enum fuse_readdir_flags)
#else
int fuseReaddir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t,
                struct fuse_file_info *, enum fuse_readdir_flags)
#endif
{
    std::vector<cryptowl::vault::VfsEntry> entries;
    std::string error;
    if (!context()->fs->list(path, &entries, &error))
        return -ENOENT;

    filler(buffer, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    filler(buffer, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    for (const auto &entry : entries) {
        filler(buffer, entry.name.c_str(), nullptr, 0,
               static_cast<fuse_fill_dir_flags>(0));
    }
    return 0;
}

int fuseOpen(const char *path, struct fuse_file_info *info)
{
    if (!info)
        return -EINVAL;
    if ((info->flags & O_ACCMODE) != O_RDONLY)
        return -EROFS;

    std::string error;
    auto reader = context()->fs->open(path, &error);
    if (!reader)
        return -ENOENT;

    auto *handle = new (std::nothrow) FileHandle{std::move(reader)};
    if (!handle)
        return -ENOMEM;
    info->fh = reinterpret_cast<uint64_t>(handle);
    return 0;
}

int fuseRead(const char *, char *buffer, size_t size, off_t offset,
             struct fuse_file_info *info)
{
    if (!info || !buffer)
        return -EINVAL;
    auto *handle = reinterpret_cast<FileHandle *>(info->fh);
    if (!handle || !handle->reader)
        return -EBADF;

    std::string error;
    const std::size_t read = handle->reader->read(
        static_cast<std::uint64_t>(offset),
        std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(buffer), size),
        &error);
    if (read == 0 && !error.empty())
        return -EIO;
    if (read > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return -EOVERFLOW;
    return static_cast<int>(read);
}

int fuseRelease(const char *, struct fuse_file_info *info)
{
    if (info) {
        delete reinterpret_cast<FileHandle *>(info->fh);
        info->fh = 0;
    }
    return 0;
}

#ifdef __APPLE__
int fuseStatfs(const char *, struct statfs *stats)
#else
int fuseStatfs(const char *, struct statvfs *stats)
#endif
{
    if (!stats)
        return -EINVAL;
    std::memset(stats, 0, sizeof(*stats));
    stats->f_bsize = 4096;
#ifndef __APPLE__
    stats->f_frsize = 4096;
#endif
    return 0;
}

struct fuse_operations operations()
{
    struct fuse_operations ops {};
    ops.getattr = fuseGetattr;
    ops.readdir = fuseReaddir;
    ops.open = fuseOpen;
    ops.read = fuseRead;
    ops.release = fuseRelease;
    ops.statfs = fuseStatfs;
    return ops;
}

#else

struct MountContext
{
};

#endif

} // namespace

struct FuseMount::Impl
{
#if defined(CRYPTOWL_HAS_FUSE)
    struct fuse *handle = nullptr;
    std::thread loop;
    std::unique_ptr<MountContext> context;
    QString mountPoint;
    bool mounted = false;
#else
    bool mounted = false;
#endif
};

FuseMount::FuseMount()
    : m_impl(std::make_unique<Impl>())
{
}

FuseMount::~FuseMount()
{
    unmount();
}

bool FuseMount::isAvailable()
{
#if defined(CRYPTOWL_HAS_FUSE)
    return true;
#else
    return false;
#endif
}

bool FuseMount::mount(const QString &mountPoint,
                      cryptowl::vault::VirtualMediaFs *fs, QString *error)
{
#if defined(CRYPTOWL_HAS_FUSE)
    if (m_impl->mounted) {
        if (error)
            *error = QStringLiteral("A media drive is already mounted.");
        return false;
    }
    if (!fs) {
        if (error)
            *error = QStringLiteral("No media file system was provided.");
        return false;
    }

    m_impl->context = std::make_unique<MountContext>();
    m_impl->context->fs = fs;

    struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    fuse_opt_add_arg(&args, "cryptowl");
    fuse_opt_add_arg(&args, "-o");
#ifdef __APPLE__
    fuse_opt_add_arg(&args, "ro,volname=CryptOwl,noappledouble,noapplexattr");
#else
    fuse_opt_add_arg(&args, "ro,fsname=cryptowl");
#endif
    const QByteArray mountPath = mountPoint.toUtf8();

    struct fuse_operations ops = operations();
    struct fuse *handle = fuse_new(&args, &ops, sizeof(ops),
                                   m_impl->context.get());
    fuse_opt_free_args(&args);
    if (!handle) {
        m_impl->context.reset();
        if (error)
            *error = QStringLiteral("Could not create the FUSE file system.");
        return false;
    }

    if (fuse_mount(handle, mountPath.constData()) != 0) {
        const QString message = QString::fromLocal8Bit(std::strerror(errno));
        fuse_destroy(handle);
        m_impl->context.reset();
        if (error)
            *error = QStringLiteral("Could not mount the media drive: %1")
                         .arg(message);
        return false;
    }

    m_impl->handle = handle;
    m_impl->mountPoint = mountPoint;
    m_impl->mounted = true;
    m_impl->loop = std::thread([handle] { fuse_loop(handle); });
    return true;
#else
    (void)mountPoint;
    (void)fs;
    if (error)
        *error = QStringLiteral("Native FUSE support was not built.");
    return false;
#endif
}

void FuseMount::unmount()
{
#if defined(CRYPTOWL_HAS_FUSE)
    if (!m_impl)
        return;
    if (m_impl->handle) {
        fuse_exit(m_impl->handle);
        if (m_impl->loop.joinable())
            m_impl->loop.join();
        fuse_unmount(m_impl->handle);
        fuse_destroy(m_impl->handle);
        m_impl->handle = nullptr;
    }
    m_impl->context.reset();
    m_impl->mountPoint.clear();
    m_impl->mounted = false;
#endif
}

bool FuseMount::isMounted() const
{
    return m_impl && m_impl->mounted;
}

QString FuseMount::mountPoint() const
{
#if defined(CRYPTOWL_HAS_FUSE)
    return m_impl ? m_impl->mountPoint : QString();
#else
    return {};
#endif
}
