#include "VaultView.h"

#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"

#include <QListWidget>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QTreeWidget>
#include <QtTest>

#include <memory>
#include <string>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::ItemRepository;
using cryptowl::vault::NewItem;
using cryptowl::vault::VaultDatabase;
using cryptowl::vault::VaultSession;

namespace {

const Bytes kVaultKey(32, 0x44);
const Bytes kSmk(64, 0x33);

std::shared_ptr<VaultSession> openSession(const QString &databasePath,
                                          std::string *error)
{
    auto session = VaultSession::open(
        databasePath.toStdString(), ProtectedValue(Bytes(kVaultKey)),
        ProtectedValue(Bytes(kSmk)), error);
    return std::shared_ptr<VaultSession>(std::move(session));
}

NewItem passwordItem(const std::string &title, const std::string &username,
                     const std::string &secret)
{
    NewItem item;
    item.type = "password";
    item.classification = "S";
    item.title = title;
    item.meta = "{\"username\":\"" + username
        + "\",\"url\":\"https://example.com\"}";
    item.payload = "{\"username\":\"" + username
        + "\",\"url\":\"https://example.com\",\"secret\":\"" + secret
        + "\",\"notes\":\"test notes\"}";
    return item;
}

} // namespace

class TestVaultView : public QObject
{
    Q_OBJECT

private slots:
    void showsStoredPasswords();
    void filtersPasswords();
    void switchesToIconView();
};

void TestVaultView::showsStoredPasswords()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, &error);
    QVERIFY2(session != nullptr, error.c_str());

    std::string id;
    QVERIFY2(session->items().create(
                 passwordItem("GitHub", "riguz", "mock-secret"), &id, &error),
             error.c_str());
    QVERIFY2(session->items().create(
                 passwordItem("Mail", "user", "mail-secret"), &id, &error),
             error.c_str());

    VaultView view(QStringLiteral("/tmp/mock-vault"), session);
    auto *structure = view.findChild<QTreeWidget *>(QStringLiteral("vaultStructure"));
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    auto *info = view.findChild<QTextBrowser *>(QStringLiteral("vaultInfo"));
    QVERIFY(structure);
    QVERIFY(details);
    QVERIFY(info);

    QCOMPARE(structure->topLevelItemCount(), 1);
    QCOMPARE(structure->topLevelItem(0)->childCount(), 1);
    QVERIFY(structure->topLevelItem(0)->child(0)->text(0).contains(
        QStringLiteral("Passwords (2)")));
    QCOMPARE(details->topLevelItemCount(), 2);

    QTreeWidgetItem *github = nullptr;
    for (int i = 0; i < details->topLevelItemCount(); ++i) {
        if (details->topLevelItem(i)->text(0) == QStringLiteral("GitHub"))
            github = details->topLevelItem(i);
    }
    QVERIFY(github);
    details->setCurrentItem(github);
    QVERIFY(info->toPlainText().contains(QStringLiteral("GitHub")));
    QVERIFY(info->toPlainText().contains(QStringLiteral("riguz")));
    QVERIFY(!info->toPlainText().contains(QStringLiteral("mock-secret")));
}

void TestVaultView::filtersPasswords()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, &error);
    QVERIFY2(session != nullptr, error.c_str());

    std::string id;
    QVERIFY2(session->items().create(
                 passwordItem("GitHub", "riguz", "secret"), &id, &error),
             error.c_str());
    QVERIFY2(session->items().create(
                 passwordItem("Mail", "user", "secret"), &id, &error),
             error.c_str());

    VaultView view(QStringLiteral("/tmp/mock-vault"), session);
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    QVERIFY(details);

    view.setFilter(QStringLiteral("GitHub"));
    QCOMPARE(details->topLevelItemCount(), 1);
    QCOMPARE(details->topLevelItem(0)->text(0), QStringLiteral("GitHub"));

    view.setFilter(QString());
    QCOMPARE(details->topLevelItemCount(), 2);
}

void TestVaultView::switchesToIconView()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, &error);
    QVERIFY2(session != nullptr, error.c_str());

    std::string id;
    QVERIFY2(session->items().create(
                 passwordItem("GitHub", "riguz", "secret"), &id, &error),
             error.c_str());

    VaultView view(QStringLiteral("/tmp/mock-vault"), session);
    auto *stack = view.findChild<QStackedWidget *>(QStringLiteral("vaultContentStack"));
    auto *icons = view.findChild<QListWidget *>(QStringLiteral("vaultIcons"));
    QVERIFY(stack);
    QVERIFY(icons);

    view.showIcons();
    QCOMPARE(stack->currentWidget(), icons);
    QCOMPARE(icons->count(), 1);
}

QTEST_MAIN(TestVaultView)
#include "tst_vaultview.moc"
