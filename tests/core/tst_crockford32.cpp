#include "crypto/Bytes.h"
#include "crypto/Crockford32.h"
#include "crypto/Random.h"

#include <QtTest>

using namespace cryptowl::crypto;

namespace {

const QString kGoldenEncoded = QStringLiteral(
    "48H24-8H248-H248H-248H2-48H24-8H248-H248H-248H2-48H24-8H248-H0");

}

class TestCrockford32 : public QObject
{
    Q_OBJECT

private slots:
    void roundTripAcrossSizes();
    void goldenArgon2Salt();
    void groupsOfFiveWithHyphens();
    void decodeIgnoresCaseHyphensAndAliases();
    void invalidCharacterRejected();
};

void TestCrockford32::roundTripAcrossSizes()
{
    for (const int size : {1, 4, 12, 16, 32, 33}) {
        const Bytes data = randomBytes(static_cast<std::size_t>(size));
        const Bytes decoded = crockford32Decode(crockford32Encode(data));
        QCOMPARE(decoded.size(), data.size());
        QVERIFY(decoded == data);
    }
}

void TestCrockford32::goldenArgon2Salt()
{
    const Bytes salt(32, 0x22);
    QCOMPARE(QString::fromStdString(crockford32Encode(salt)), kGoldenEncoded);
    QVERIFY(crockford32Decode(kGoldenEncoded.toStdString()) == salt);
}

void TestCrockford32::groupsOfFiveWithHyphens()
{
    const QString encoded = QString::fromStdString(crockford32Encode(Bytes(32, 0x22)));
    const QStringList parts = encoded.split('-');
    QVERIFY(parts.size() >= 2);
    for (int i = 0; i + 1 < parts.size(); ++i)
        QCOMPARE(parts[i].size(), 5);
    QVERIFY(parts.last().size() >= 1 && parts.last().size() <= 5);
}

void TestCrockford32::decodeIgnoresCaseHyphensAndAliases()
{
    const Bytes salt(32, 0x22);
    QVERIFY(crockford32Decode(kGoldenEncoded.toLower().toStdString()) == salt);
    QVERIFY(crockford32Decode(kGoldenEncoded.toStdString().replace(0, 0, "")) == salt);

    std::string withoutHyphens = kGoldenEncoded.toStdString();
    withoutHyphens.erase(std::remove(withoutHyphens.begin(), withoutHyphens.end(), '-'),
                         withoutHyphens.end());
    QVERIFY(crockford32Decode(withoutHyphens) == salt);

    QVERIFY(crockford32Decode("il1") == crockford32Decode("111"));
    QVERIFY(crockford32Decode("o0") == crockford32Decode("00"));
}

void TestCrockford32::invalidCharacterRejected()
{
    QVERIFY_THROWS_EXCEPTION(std::invalid_argument, crockford32Decode("!"));
}

QTEST_APPLESS_MAIN(TestCrockford32)
#include "tst_crockford32.moc"
