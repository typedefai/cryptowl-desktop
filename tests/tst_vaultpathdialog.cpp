#include "VaultPathDialog.h"

#include <QDir>
#include <QFile>
#include <QLabel>
#include <QTemporaryDir>
#include <QtTest>

namespace {

bool writeFile(const QString &path, const QByteArray &data)
{
    QFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(data) == data.size();
}

} // namespace

class TestVaultPathDialog : public QObject
{
    Q_OBJECT

private slots:
    void openAcceptsVaultFolder();
    void openRejectsOrdinaryFolder();
    void createAcceptsEmptyFolder();
    void createRejectsNonEmptyFolder();
    void expandsHomePath();
};

void TestVaultPathDialog::openAcceptsVaultFolder()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("vault"));
    QVERIFY(QDir().mkpath(vault));
    QVERIFY(writeFile(QDir(vault).filePath(QStringLiteral("vault.meta")), "{}"));

    VaultPathDialog dialog(VaultPathDialog::Mode::Open);
    dialog.setPath(vault);
    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryAccept", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
    QCOMPARE(dialog.path(), QDir::cleanPath(vault));
}

void TestVaultPathDialog::openRejectsOrdinaryFolder()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());

    VaultPathDialog dialog(VaultPathDialog::Mode::Open);
    dialog.setPath(dir.path());
    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryAccept", Qt::DirectConnection));

    QVERIFY(dialog.result() != int(QDialog::Accepted));
    auto *error = dialog.findChild<QLabel *>(QStringLiteral("vaultPathError"));
    QVERIFY(error);
    QVERIFY(!error->text().isEmpty());
}

void TestVaultPathDialog::createAcceptsEmptyFolder()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("new-vault"));
    QVERIFY(QDir().mkpath(vault));

    VaultPathDialog dialog(VaultPathDialog::Mode::Create);
    dialog.setPath(vault);
    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryAccept", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
}

void TestVaultPathDialog::createRejectsNonEmptyFolder()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    QVERIFY(writeFile(QDir(dir.path()).filePath(QStringLiteral("file.txt")), "x"));

    VaultPathDialog dialog(VaultPathDialog::Mode::Create);
    dialog.setPath(dir.path());
    QVERIFY(QMetaObject::invokeMethod(&dialog, "tryAccept", Qt::DirectConnection));

    QVERIFY(dialog.result() != int(QDialog::Accepted));
    auto *error = dialog.findChild<QLabel *>(QStringLiteral("vaultPathError"));
    QVERIFY(error);
    QVERIFY(error->text().contains(QStringLiteral("not empty")));
}

void TestVaultPathDialog::expandsHomePath()
{
    VaultPathDialog dialog(VaultPathDialog::Mode::Open);
    dialog.setPath(QStringLiteral("~"));
    QCOMPARE(dialog.path(), QDir::cleanPath(QDir::homePath()));
}

QTEST_MAIN(TestVaultPathDialog)
#include "tst_vaultpathdialog.moc"
