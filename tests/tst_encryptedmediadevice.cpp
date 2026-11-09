#include "EncryptedMediaDevice.h"

#include "crypto/FileEnvelope.h"

#include <QByteArray>
#include <QtTest>

#include <memory>
#include <vector>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::MemoryFileReader;

class TestEncryptedMediaDevice : public QObject
{
    Q_OBJECT

private slots:
    void readsAndSeeks();
};

void TestEncryptedMediaDevice::readsAndSeeks()
{
    Bytes data(1000);
    for (std::size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<std::uint8_t>(i & 0xff);

    auto reader = std::make_unique<MemoryFileReader>(Bytes(data));
    EncryptedMediaDevice device(std::move(reader), nullptr);
    QVERIFY(device.isOpen());
    QCOMPARE(device.size(), qint64(data.size()));
    QVERIFY(!device.isSequential());

    QByteArray first = device.read(17);
    QCOMPARE(first.size(), 17);
    QCOMPARE(static_cast<std::uint8_t>(first[0]), std::uint8_t(0));
    QCOMPARE(static_cast<std::uint8_t>(first[16]), std::uint8_t(16));

    QVERIFY(device.seek(500));
    QCOMPARE(device.pos(), qint64(500));
    QByteArray middle = device.read(32);
    QCOMPARE(middle.size(), 32);
    QCOMPARE(static_cast<std::uint8_t>(middle[0]), std::uint8_t(500 & 0xff));

    QVERIFY(device.seek(device.size()));
    QVERIFY(device.atEnd());
    QCOMPARE(device.read(10).size(), 0);
}

QTEST_APPLESS_MAIN(TestEncryptedMediaDevice)
#include "tst_encryptedmediadevice.moc"
