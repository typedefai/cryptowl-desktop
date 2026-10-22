#include "crypto/AesGcm.h"
#include "crypto/Argon2.h"
#include "crypto/Bytes.h"
#include "crypto/Errors.h"
#include "crypto/Hash.h"
#include "crypto/Random.h"

#include <QtTest>

#include <span>

using namespace cryptowl::crypto;

namespace {

QString hex(std::span<const std::uint8_t> bytes)
{
    return QString::fromStdString(toHex(bytes));
}

const Bytes kDeviceSecret(32, 0x11);
constexpr std::string_view kMasterPassword = "correct horse battery staple";
const Bytes kArgon2Salt(32, 0x22);
const Bytes kHkdfSalt(32, 0x33);
const Bytes kVaultKey(32, 0x44);
const Bytes kNonce(12, 0x55);

const QString kVectorP = QStringLiteral(
    "89a89e43cc75104a75d4dbcc60e7e6ed0d308e718c0f7b1bf05efaccd70c030b");
const QString kVectorTmk = QStringLiteral(
    "9049f8f4d35de3aef703a68d656e7b777f9e1742d89455414a8fd118c3043588");
const QString kVectorSmk = QStringLiteral(
    "551afd2b0857e902118857a01a680b14e43ff2172950a71a5ec8ec147fcbc809"
    "0471ff96c2b5486960b6596cfe6cfb7b412b93034a7950badda783f298b2e06f");
const QString kRfc5869Case1Okm = QStringLiteral(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865");
const QString kGcmWrappedVaultKey = QStringLiteral(
    "95a6a822d26244284a3b0f4b0f525d433dcd13ab523fe7da64b8dfb95849f045");
const QString kGcmWrapTag = QStringLiteral("f4e47f45e19f97f44e5feb86379dad10");
const QString kFek = QStringLiteral(
    "467b0ef6d6792bec4b6fd16a08ed26b4a769cb69dfc91dd8d386ee5640f3f724");
const QString kHfk = QStringLiteral(
    "e18b8c8bd06eb2070ef02238f931908fc241da4fbb14f984c8027ac078538b7f");

}

class TestCryptoVectors : public QObject
{
    Q_OBJECT

private slots:
    void hmacSha256_matchesP();
    void argon2id_matchesTmk();
    void hkdfSmk_matchesVector();
    void hkdf_rfc5869Case1();
    void hkdfFek_emptySalt();
    void hkdfHfk_emptySalt();
    void aesGcm_wrapVaultKeyVector();
    void aesGcm_roundTrip();
    void aesGcm_wrongAadRejected();
    void aesGcm_invalidSizesRejected();
};

void TestCryptoVectors::hmacSha256_matchesP()
{
    QCOMPARE(hex(hmacSha256(kDeviceSecret, bytesOf(kMasterPassword))), kVectorP);
}

void TestCryptoVectors::argon2id_matchesTmk()
{
    const Bytes p = hmacSha256(kDeviceSecret, bytesOf(kMasterPassword));
    QCOMPARE(hex(argon2id(p, kArgon2Salt)), kVectorTmk);
}

void TestCryptoVectors::hkdfSmk_matchesVector()
{
    const Bytes tmk = fromHex(kVectorTmk.toStdString());
    const Bytes smk = hkdfSha256(tmk, kHkdfSalt, bytesOf("personal"), 64);
    QCOMPARE(hex(smk), kVectorSmk);
}

void TestCryptoVectors::hkdf_rfc5869Case1()
{
    const Bytes okm = hkdfSha256(fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                                 fromHex("000102030405060708090a0b0c"),
                                 fromHex("f0f1f2f3f4f5f6f7f8f9"), 42);
    QCOMPARE(hex(okm), kRfc5869Case1Okm);
}

void TestCryptoVectors::hkdfFek_emptySalt()
{
    const Bytes fek =
        hkdfSha256(kVaultKey, std::span<const std::uint8_t>(), bytesOf("file"), 32);
    QCOMPARE(hex(fek), kFek);
}

void TestCryptoVectors::hkdfHfk_emptySalt()
{
    const Bytes hfk =
        hkdfSha256(kVaultKey, std::span<const std::uint8_t>(), bytesOf("fingerprint"), 32);
    QCOMPARE(hex(hfk), kHfk);
}

void TestCryptoVectors::aesGcm_wrapVaultKeyVector()
{
    const Bytes smk = fromHex(kVectorSmk.toStdString());
    const std::span<const std::uint8_t> smkEnc{smk.data(), 32};

    const GcmCiphertext wrapped =
        aesGcmEncrypt(smkEnc, kNonce, bytesOf("vault_key:smk"), kVaultKey);
    QCOMPARE(hex(wrapped.ciphertext), kGcmWrappedVaultKey);
    QCOMPARE(hex(wrapped.tag), kGcmWrapTag);

    const Bytes unwrapped = aesGcmDecrypt(smkEnc, kNonce, bytesOf("vault_key:smk"),
                                          wrapped.ciphertext, wrapped.tag);
    QCOMPARE(hex(unwrapped), hex(kVaultKey));
}

void TestCryptoVectors::aesGcm_roundTrip()
{
    const Bytes key = randomBytes(32);
    const Bytes nonce = randomBytes(12);
    const std::span<const std::uint8_t> plaintext = bytesOf("secret data");

    const GcmCiphertext out = aesGcmEncrypt(key, nonce, bytesOf("aad"), plaintext);
    QCOMPARE(hex(aesGcmDecrypt(key, nonce, bytesOf("aad"), out.ciphertext, out.tag)),
             hex(plaintext));
}

void TestCryptoVectors::aesGcm_wrongAadRejected()
{
    const Bytes key = randomBytes(32);
    const GcmCiphertext out = aesGcmEncrypt(key, kNonce, bytesOf("vault_key:smk"), kVaultKey);
    QVERIFY_THROWS_EXCEPTION(AuthenticationError,
                             aesGcmDecrypt(key, kNonce, bytesOf("wrong-aad"), out.ciphertext,
                                           out.tag));
}

void TestCryptoVectors::aesGcm_invalidSizesRejected()
{
    QVERIFY_THROWS_EXCEPTION(std::invalid_argument,
                             aesGcmEncrypt(Bytes(16, 0), kNonce, bytesOf("aad"), kVaultKey));
    QVERIFY_THROWS_EXCEPTION(std::invalid_argument,
                             aesGcmEncrypt(kVaultKey, Bytes(8, 0), bytesOf("aad"), kVaultKey));
    QVERIFY_THROWS_EXCEPTION(std::invalid_argument,
                             aesGcmDecrypt(kVaultKey, kNonce, bytesOf("aad"), Bytes(4, 0),
                                           Bytes(8, 0)));
}

QTEST_APPLESS_MAIN(TestCryptoVectors)
#include "tst_crypto_vectors.moc"
