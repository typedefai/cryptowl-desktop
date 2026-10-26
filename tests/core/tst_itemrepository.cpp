#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"

#include <sqlite3.h>

#include <QTemporaryDir>
#include <QtTest>

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::ItemRecord;
using cryptowl::vault::ItemRepository;
using cryptowl::vault::ItemSummary;
using cryptowl::vault::ItemUpdate;
using cryptowl::vault::NewItem;
using cryptowl::vault::VaultDatabase;
using cryptowl::vault::VaultSession;

namespace {

const Bytes kVaultKey(32, 0x44);
const Bytes kSmk(64, 0x33);

std::unique_ptr<VaultSession> openSession(const QString &databasePath,
                                          const Bytes &smk = kSmk,
                                          std::string *error = nullptr)
{
    return VaultSession::open(databasePath.toStdString(),
                              ProtectedValue(Bytes(kVaultKey)),
                              ProtectedValue(Bytes(smk)), error);
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

NewItem noteItem(const std::string &title, const std::string &body,
                 const std::string &classification)
{
    NewItem item;
    item.type = "plain";
    item.classification = classification;
    item.title = title;
    item.meta = "{}";
    item.payload = body;
    return item;
}

int scalarInt(sqlite3 *database, const char *sql)
{
    int value = -1;
    char *message = nullptr;
    const int rc = sqlite3_exec(
        database, sql,
        [](void *context, int, char **values, char **) {
            if (values && values[0])
                *static_cast<int *>(context) = std::atoi(values[0]);
            return 0;
        },
        &value, &message);
    if (rc != SQLITE_OK) {
        sqlite3_free(message);
        return -1;
    }
    return value;
}

} // namespace

class TestItemRepository : public QObject
{
    Q_OBJECT

private slots:
    void crudRoundTrip();
    void noteTierRoundTrip();
    void preservesItemsAcrossSessions();
    void rejectsWrongSmk();
};

void TestItemRepository::crudRoundTrip()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, kSmk, &error);
    QVERIFY2(session != nullptr, error.c_str());
    ItemRepository &repository = session->items();

    std::string id;
    QVERIFY2(repository.create(passwordItem("GitHub", "riguz", "old-secret"),
                               &id, &error),
             error.c_str());
    QCOMPARE(id.size(), std::size_t(36));
    QCOMPARE(scalarInt(session->handle(),
                       "SELECT count(*) FROM t_item_version;"),
             1);

    std::vector<ItemSummary> items;
    QVERIFY2(repository.list("password", &items, &error), error.c_str());
    QCOMPARE(items.size(), std::size_t(1));
    QCOMPARE(QString::fromStdString(items.front().title), QStringLiteral("GitHub"));
    QVERIFY(items.front().meta.find("riguz") != std::string::npos);

    ItemRecord record;
    QVERIFY2(repository.get(id, &record, &error), error.c_str());
    QCOMPARE(QString::fromStdString(record.title), QStringLiteral("GitHub"));
    QVERIFY(record.payload.find("old-secret") != std::string::npos);
    QVERIFY(record.payload.find("test notes") != std::string::npos);

    ItemUpdate update;
    update.title = "GitHub Work";
    update.meta =
        "{\"username\":\"riguz\",\"url\":\"https://github.com\"}";
    update.payload =
        "{\"username\":\"riguz\",\"url\":\"https://github.com\","
        "\"secret\":\"new-secret\",\"notes\":\"updated\"}";
    QVERIFY2(repository.update(id, update, &error), error.c_str());
    QCOMPARE(scalarInt(session->handle(),
                       "SELECT count(*) FROM t_item_version;"),
             2);

    QVERIFY2(repository.get(id, &record, &error), error.c_str());
    QCOMPARE(QString::fromStdString(record.title), QStringLiteral("GitHub Work"));
    QVERIFY(record.payload.find("new-secret") != std::string::npos);

    // Saving the same content again must not append another version.
    QVERIFY2(repository.update(id, update, &error), error.c_str());
    QCOMPARE(scalarInt(session->handle(),
                       "SELECT count(*) FROM t_item_version;"),
             2);

    QVERIFY2(repository.softDelete(id, &error), error.c_str());
    items.clear();
    QVERIFY2(repository.list("password", &items, &error), error.c_str());
    QVERIFY(items.empty());
    QVERIFY(!repository.get(id, &record, &error));
}

void TestItemRepository::noteTierRoundTrip()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string error;
    auto session = openSession(databasePath, kSmk, &error);
    QVERIFY2(session != nullptr, error.c_str());
    ItemRepository &repository = session->items();

    std::string id;
    QVERIFY2(repository.create(noteItem("Project notes", "confidential body", "C"),
                               &id, &error),
             error.c_str());

    ItemRecord record;
    QVERIFY2(repository.get(id, &record, &error), error.c_str());
    QCOMPARE(QString::fromStdString(record.classification), QStringLiteral("C"));
    QCOMPARE(QString::fromStdString(record.payload),
             QStringLiteral("confidential body"));
    QCOMPARE(scalarInt(session->handle(),
                       "SELECT count(*) FROM t_item_version;"),
             1);

    ItemUpdate makeSecret;
    makeSecret.title = "Project notes";
    makeSecret.classification = "S";
    makeSecret.meta = "{}";
    makeSecret.payload = "secret body";
    QVERIFY2(repository.update(id, makeSecret, &error), error.c_str());
    QVERIFY2(repository.get(id, &record, &error), error.c_str());
    QCOMPARE(QString::fromStdString(record.classification), QStringLiteral("S"));
    QCOMPARE(QString::fromStdString(record.payload), QStringLiteral("secret body"));
    QCOMPARE(scalarInt(session->handle(),
                       "SELECT count(*) FROM t_item_version;"),
             2);

    ItemUpdate makeConfidential;
    makeConfidential.title = "Project notes";
    makeConfidential.classification = "C";
    makeConfidential.meta = "{}";
    makeConfidential.payload = "updated confidential body";
    QVERIFY2(repository.update(id, makeConfidential, &error), error.c_str());
    QVERIFY2(repository.get(id, &record, &error), error.c_str());
    QCOMPARE(QString::fromStdString(record.classification), QStringLiteral("C"));
    QCOMPARE(QString::fromStdString(record.payload),
             QStringLiteral("updated confidential body"));
    QCOMPARE(scalarInt(session->handle(),
                       "SELECT count(*) FROM t_item_version;"),
             3);

    std::string emptyId;
    QVERIFY2(repository.create(noteItem("Empty note", "", "S"), &emptyId, &error),
             error.c_str());
    ItemRecord emptyRecord;
    QVERIFY2(repository.get(emptyId, &emptyRecord, &error), error.c_str());
    QCOMPARE(QString::fromStdString(emptyRecord.classification), QStringLiteral("S"));
    QVERIFY(emptyRecord.payload.empty());
}

void TestItemRepository::preservesItemsAcrossSessions()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    std::string id;
    {
        std::string error;
        auto session = openSession(databasePath, kSmk, &error);
        QVERIFY2(session != nullptr, error.c_str());
        QVERIFY2(session->items().create(passwordItem("Mail", "user", "secret"),
                                         &id, &error),
                 error.c_str());
        QCOMPARE(scalarInt(session->handle(),
                           "SELECT count(*) FROM t_wrapped_key "
                           "WHERE id = 'kek:smk';"),
                 1);
    }

    std::string error;
    auto reopened = openSession(databasePath, kSmk, &error);
    QVERIFY2(reopened != nullptr, error.c_str());
    ItemRecord record;
    QVERIFY2(reopened->items().get(id, &record, &error), error.c_str());
    QCOMPARE(QString::fromStdString(record.title), QStringLiteral("Mail"));
    QVERIFY(record.payload.find("secret") != std::string::npos);
}

void TestItemRepository::rejectsWrongSmk()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString databasePath = dir.filePath(QStringLiteral("vault.db"));
    QVERIFY(VaultDatabase::create(databasePath.toStdString(), kVaultKey));

    {
        std::string error;
        auto session = openSession(databasePath, kSmk, &error);
        QVERIFY2(session != nullptr, error.c_str());
    }

    std::string error;
    auto session = openSession(databasePath, Bytes(64, 0x34), &error);
    QVERIFY(session == nullptr);
    QVERIFY(!error.empty());
}

QTEST_APPLESS_MAIN(TestItemRepository)
#include "tst_itemrepository.moc"
