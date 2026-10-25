#include "VaultInfoDialog.h"

#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QtTest>

namespace {

bool writeTextFile(const QString &path, const QByteArray &contents)
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(contents) == contents.size();
}

QString makeVault(QTemporaryDir &dir)
{
    const QString vault = dir.filePath(QStringLiteral("MyVault"));
    if (!QDir().mkpath(vault))
        return QString();

    QJsonObject kdf;
    kdf[QStringLiteral("algorithm")] = QStringLiteral("argon2id");
    kdf[QStringLiteral("m_kib")] = 19456;
    kdf[QStringLiteral("t")] = 2;
    kdf[QStringLiteral("p")] = 1;

    QJsonObject salts;
    salts[QStringLiteral("argon2")] = QStringLiteral("A") + QString(51, QLatin1Char('A'));
    salts[QStringLiteral("hkdf")] = QStringLiteral("B") + QString(51, QLatin1Char('B'));

    QJsonObject wrapped;
    wrapped[QStringLiteral("id")] = QStringLiteral("vault_key:smk");
    wrapped[QStringLiteral("role")] = QStringLiteral("vault_key");
    wrapped[QStringLiteral("wrapper")] = QStringLiteral("smk");
    wrapped[QStringLiteral("algorithm")] = QStringLiteral("AES-256-GCM");
    wrapped[QStringLiteral("ciphertext")] = QStringLiteral("SECRET_CIPHERTEXT");
    wrapped[QStringLiteral("nonce")] = QStringLiteral("SECRET_NONCE");
    wrapped[QStringLiteral("auth_tag")] = QStringLiteral("SECRET_TAG");

    QJsonObject mac;
    mac[QStringLiteral("algorithm")] = QStringLiteral("HMAC-SHA256");
    mac[QStringLiteral("value")] = QStringLiteral("SECRET_MAC");

    QJsonObject meta;
    meta[QStringLiteral("version")] = 3;
    meta[QStringLiteral("vault_id")] = QStringLiteral("unit-test-vault");
    meta[QStringLiteral("created_at")] = 1700000000000.0;
    meta[QStringLiteral("updated_at")] = 1700000001000.0;
    meta[QStringLiteral("kdf")] = kdf;
    meta[QStringLiteral("salts")] = salts;
    meta[QStringLiteral("wrapped_keys")] = QJsonArray{wrapped};
    meta[QStringLiteral("mac")] = mac;

    const QString metaPath = QDir(vault).filePath(QStringLiteral("vault.meta"));
    if (!writeTextFile(metaPath, QJsonDocument(meta).toJson(QJsonDocument::Compact)))
        return QString();
    if (!writeTextFile(QDir(vault).filePath(QStringLiteral("config.json")),
                       QByteArrayLiteral("{}")))
        return QString();
    if (!writeTextFile(QDir(vault).filePath(QStringLiteral("config.sig")),
                       QByteArrayLiteral("signature")))
        return QString();
    if (!writeTextFile(QDir(vault).filePath(QStringLiteral("vault.db")),
                       QByteArrayLiteral("encrypted database")))
        return QString();
    if (!writeTextFile(QDir(vault).filePath(QStringLiteral("device_secret")),
                       QByteArrayLiteral("legacy secret")))
        return QString();

    return vault;
}

} // namespace

class TestVaultInfoDialog : public QObject
{
    Q_OBJECT

private slots:
    void showsVaultInformation();
    void reportsLockedState();
    void reportsMissingMetadata();
};

void TestVaultInfoDialog::showsVaultInformation()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = makeVault(dir);
    QVERIFY(!vault.isEmpty());

    VaultInfoDialog dialog(vault, true);
    auto *text = dialog.findChild<QTextBrowser *>(QStringLiteral("vaultInfoText"));
    QVERIFY(text);

    const QString plain = text->toPlainText();
    QVERIFY(plain.contains(QStringLiteral("MyVault")));
    QVERIFY(plain.contains(QDir::toNativeSeparators(vault)));
    QVERIFY(plain.contains(QStringLiteral("Unlocked")));
    QVERIFY(plain.contains(QStringLiteral("SQLCipher")));
    QVERIFY(plain.contains(QStringLiteral("AES-256-GCM")));
    QVERIFY(plain.contains(QStringLiteral("8192 bytes")));
    QVERIFY(plain.contains(QStringLiteral("argon2id")));
    QVERIFY(plain.contains(QStringLiteral("19456")));
    QVERIFY(plain.contains(QStringLiteral("HMAC-SHA256")));
    QVERIFY(plain.contains(QStringLiteral("vault_key:smk")));
    QVERIFY(plain.contains(QStringLiteral("KEK")));
    QVERIFY(plain.contains(QStringLiteral("Item DEKs")));
    QVERIFY(plain.contains(QStringLiteral("SMK[32:64]")));
    QVERIFY(plain.contains(QStringLiteral("in memory for this session")));
    QVERIFY(plain.contains(QStringLiteral("legacy device_secret file")));
    QVERIFY(plain.contains(QStringLiteral("vault.db")));
    QVERIFY(plain.contains(QStringLiteral("unit-test-vault")));

    // Wrapped key bytes and the metadata MAC value must never be shown.
    QVERIFY(!plain.contains(QStringLiteral("SECRET_CIPHERTEXT")));
    QVERIFY(!plain.contains(QStringLiteral("SECRET_NONCE")));
    QVERIFY(!plain.contains(QStringLiteral("SECRET_TAG")));
    QVERIFY(!plain.contains(QStringLiteral("SECRET_MAC")));
}

void TestVaultInfoDialog::reportsLockedState()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = makeVault(dir);
    QVERIFY(!vault.isEmpty());

    VaultInfoDialog dialog(vault, false);
    auto *text = dialog.findChild<QTextBrowser *>(QStringLiteral("vaultInfoText"));
    QVERIFY(text);

    const QString plain = text->toPlainText();
    QVERIFY(plain.contains(QStringLiteral("Locked")));
    QVERIFY(plain.contains(QStringLiteral("not in memory")));
    QVERIFY(plain.contains(QStringLiteral("not verified")));
}

void TestVaultInfoDialog::reportsMissingMetadata()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = dir.filePath(QStringLiteral("EmptyVault"));
    QVERIFY(QDir().mkpath(vault));

    VaultInfoDialog dialog(vault, false);
    auto *text = dialog.findChild<QTextBrowser *>(QStringLiteral("vaultInfoText"));
    QVERIFY(text);
    QVERIFY(text->toPlainText().contains(QStringLiteral("could not read vault.meta")));
}

QTEST_MAIN(TestVaultInfoDialog)
#include "tst_vaultinfodialog.moc"
