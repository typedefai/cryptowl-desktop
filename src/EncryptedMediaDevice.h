#pragma once

#include "crypto/FileEnvelope.h"

#include <QIODevice>

#include <cstdint>
#include <memory>

class EncryptedMediaDevice : public QIODevice
{
    Q_OBJECT

public:
    explicit EncryptedMediaDevice(
        std::unique_ptr<cryptowl::crypto::FileReader> reader,
        QObject *parent = nullptr);

    bool isSequential() const override;
    qint64 size() const override;
    qint64 pos() const override;
    bool seek(qint64 position) override;
    bool atEnd() const override;
    qint64 bytesAvailable() const override;

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    std::unique_ptr<cryptowl::crypto::FileReader> m_reader;
    qint64 m_position = 0;
};
