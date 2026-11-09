#include "EncryptedMediaDevice.h"

#include <algorithm>
#include <span>
#include <string>
#include <utility>

EncryptedMediaDevice::EncryptedMediaDevice(
    std::unique_ptr<cryptowl::crypto::FileReader> reader, QObject *parent)
    : QIODevice(parent)
    , m_reader(std::move(reader))
{
    open(QIODevice::ReadOnly | QIODevice::Unbuffered);
}

bool EncryptedMediaDevice::isSequential() const
{
    return false;
}

qint64 EncryptedMediaDevice::size() const
{
    return m_reader ? static_cast<qint64>(m_reader->size()) : 0;
}

qint64 EncryptedMediaDevice::pos() const
{
    return m_position;
}

bool EncryptedMediaDevice::seek(qint64 position)
{
    if (!m_reader || position < 0 || position > size())
        return false;
    m_position = position;
    return QIODevice::seek(position);
}

bool EncryptedMediaDevice::atEnd() const
{
    return !m_reader || m_position >= size();
}

qint64 EncryptedMediaDevice::bytesAvailable() const
{
    return std::max<qint64>(0, size() - m_position)
        + QIODevice::bytesAvailable();
}

qint64 EncryptedMediaDevice::readData(char *data, qint64 maxSize)
{
    if (!m_reader || maxSize <= 0)
        return 0;
    std::string error;
    const std::size_t read = m_reader->read(
        static_cast<std::uint64_t>(m_position),
        std::span<std::uint8_t>(reinterpret_cast<std::uint8_t *>(data),
                                static_cast<std::size_t>(maxSize)),
        &error);
    if (read == 0 && !error.empty()) {
        setErrorString(QString::fromStdString(error));
        return -1;
    }
    m_position += static_cast<qint64>(read);
    return static_cast<qint64>(read);
}

qint64 EncryptedMediaDevice::writeData(const char *, qint64)
{
    return -1;
}
