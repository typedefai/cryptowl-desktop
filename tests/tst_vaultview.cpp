#include "VaultView.h"

#include "TopSecretService.h"
#include "VaultCreator.h"
#include "VaultUnlocker.h"
#include "EncryptedContentWidget.h"
#include "crypto/Bytes.h"
#include "crypto/ProtectedValue.h"
#include "vault/ItemRepository.h"
#include "vault/VaultDatabase.h"
#include "vault/VaultSession.h"

#include <QApplication>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QtTest>

#include <memory>
#include <string>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::ItemRecord;
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

} // namespace

class TestVaultView : public QObject
{
    Q_OBJECT

private slots:
    void showsStoredPasswords();
    void showsNotesAndFiltersByType();
    void editorsLoadSecretsLazily();
    void topSecretRevealAndEditor();
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
    QCOMPARE(structure->topLevelItem(0)->childCount(), 2);
    QVERIFY(structure->topLevelItem(0)->child(0)->text(0).contains(
        QStringLiteral("Passwords (2)")));
    QVERIFY(structure->topLevelItem(0)->child(1)->text(0).contains(
        QStringLiteral("Notes (0)")));
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

void TestVaultView::showsNotesAndFiltersByType()
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
                 noteItem("Project", "first note body", "C"), &id, &error),
             error.c_str());
    QVERIFY2(session->items().create(
                 noteItem("Private", "secret note body", "S"), &id, &error),
             error.c_str());

    VaultView view(QStringLiteral("/tmp/mock-vault"), session);
    auto *structure = view.findChild<QTreeWidget *>(QStringLiteral("vaultStructure"));
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    auto *info = view.findChild<QTextBrowser *>(QStringLiteral("vaultInfo"));
    QVERIFY(structure);
    QVERIFY(details);
    QVERIFY(info);

    QVERIFY(structure->topLevelItem(0)->child(0)->text(0).contains(
        QStringLiteral("Passwords (1)")));
    QVERIFY(structure->topLevelItem(0)->child(1)->text(0).contains(
        QStringLiteral("Notes (2)")));
    QCOMPARE(details->topLevelItemCount(), 3);

    structure->setCurrentItem(structure->topLevelItem(0)->child(1));
    QCOMPARE(details->topLevelItemCount(), 2);

    QTreeWidgetItem *project = nullptr;
    for (int i = 0; i < details->topLevelItemCount(); ++i) {
        if (details->topLevelItem(i)->text(0) == QStringLiteral("Project"))
            project = details->topLevelItem(i);
    }
    QVERIFY(project);
    details->setCurrentItem(project);
    QVERIFY(!info->toPlainText().contains(QStringLiteral("first note body")));
    QVERIFY(info->toPlainText().contains(QStringLiteral("Confidential")));

    QTreeWidgetItem *privateNote = nullptr;
    for (int i = 0; i < details->topLevelItemCount(); ++i) {
        if (details->topLevelItem(i)->text(0) == QStringLiteral("Private"))
            privateNote = details->topLevelItem(i);
    }
    QVERIFY(privateNote);

    details->setCurrentItem(privateNote);
    QVERIFY(!info->toPlainText().contains(QStringLiteral("secret note body")));
    QVERIFY(info->toPlainText().contains(QStringLiteral("Secret")));

    details->setCurrentItem(project);
    QVERIFY(!info->toPlainText().contains(QStringLiteral("first note body")));
    details->setCurrentItem(privateNote);
    QVERIFY(!info->toPlainText().contains(QStringLiteral("secret note body")));
}

void TestVaultView::editorsLoadSecretsLazily()
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
                 noteItem("Private", "secret note body", "S"), &id, &error),
             error.c_str());
    QVERIFY2(session->items().create(
                 noteItem("Public", "public note body", "C"), &id, &error),
             error.c_str());

    VaultView view(QStringLiteral("/tmp/mock-vault"), session);
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    QVERIFY(details);

    const auto select = [details](const QString &title) {
        for (int i = 0; i < details->topLevelItemCount(); ++i) {
            if (details->topLevelItem(i)->text(0) == title) {
                details->setCurrentItem(details->topLevelItem(i));
                return;
            }
        }
    };

    select(QStringLiteral("Private"));
    bool noteDialogSeen = false;
    QString noteFailure;
    QTimer::singleShot(0, [&] {
        auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!dialog) {
            for (QWidget *widget : QApplication::topLevelWidgets()) {
                auto *candidate = qobject_cast<QDialog *>(widget);
                if (candidate && candidate->isVisible()) {
                    dialog = candidate;
                    break;
                }
            }
        }
        if (!dialog) {
            noteFailure = QStringLiteral("note dialog not found");
            return;
        }
        auto *body = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("noteBodyWidget"));
        if (!body) {
            noteFailure = QStringLiteral("note editor widgets missing");
            dialog->reject();
            return;
        }
        auto *eye = body->findChild<QToolButton *>(QStringLiteral("secretEye"));
        if (!eye) {
            noteFailure = QStringLiteral("note eye button missing");
            dialog->reject();
            return;
        }
        noteDialogSeen = true;
        if (body->isLoaded())
            noteFailure = QStringLiteral("note body was loaded before reveal");
        if (!body->content().isEmpty())
            noteFailure = QStringLiteral("note body was not hidden");
        if (eye->isHidden())
            noteFailure = QStringLiteral("note eye button was hidden");

        eye->click();
        if (!body->isLoaded())
            noteFailure = QStringLiteral("note body was not revealed");
        if (body->content() != QStringLiteral("secret note body"))
            noteFailure = QStringLiteral("note body content was wrong");
        dialog->reject();
    });
    view.editSelectedEntry();
    QVERIFY2(noteFailure.isEmpty(), qPrintable(noteFailure));
    QVERIFY(noteDialogSeen);

    select(QStringLiteral("GitHub"));
    bool passwordDialogSeen = false;
    QString passwordFailure;
    QTimer::singleShot(0, [&] {
        auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!dialog) {
            for (QWidget *widget : QApplication::topLevelWidgets()) {
                auto *candidate = qobject_cast<QDialog *>(widget);
                if (candidate && candidate->isVisible()) {
                    dialog = candidate;
                    break;
                }
            }
        }
        if (!dialog) {
            passwordFailure = QStringLiteral("password dialog not found");
            return;
        }
        auto *password = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *notes = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordNotesWidget"));
        if (!password || !notes) {
            passwordFailure = QStringLiteral("password editor widgets missing");
            dialog->reject();
            return;
        }
        auto *passwordEye =
            password->findChild<QToolButton *>(QStringLiteral("secretEye"));
        auto *notesEye =
            notes->findChild<QToolButton *>(QStringLiteral("secretEye"));
        if (!passwordEye || !notesEye) {
            passwordFailure = QStringLiteral("password eye buttons missing");
            dialog->reject();
            return;
        }
        passwordDialogSeen = true;
        if (password->isLoaded())
            passwordFailure = QStringLiteral("password was loaded before reveal");
        if (!password->content().isEmpty())
            passwordFailure = QStringLiteral("password was not hidden");
        if (notes->isLoaded())
            passwordFailure = QStringLiteral("password notes were loaded before reveal");
        if (!notes->content().isEmpty())
            passwordFailure = QStringLiteral("password notes were not hidden");

        passwordEye->click();
        if (password->content() != QStringLiteral("mock-secret"))
            passwordFailure = QStringLiteral("password was not revealed");
        if (!notes->content().isEmpty())
            passwordFailure = QStringLiteral("notes were revealed with the password");
        notesEye->click();
        if (notes->content() != QStringLiteral("test notes"))
            passwordFailure = QStringLiteral("password notes were not revealed");
        dialog->reject();
    });
    view.editSelectedEntry();
    QVERIFY2(passwordFailure.isEmpty(), qPrintable(passwordFailure));
    QVERIFY(passwordDialogSeen);

    select(QStringLiteral("Public"));
    bool publicDialogSeen = false;
    QString publicFailure;
    QTimer::singleShot(0, [&] {
        auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!dialog) {
            for (QWidget *widget : QApplication::topLevelWidgets()) {
                auto *candidate = qobject_cast<QDialog *>(widget);
                if (candidate && candidate->isVisible()) {
                    dialog = candidate;
                    break;
                }
            }
        }
        if (!dialog) {
            publicFailure = QStringLiteral("public note dialog not found");
            return;
        }
        auto *body = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("noteBodyWidget"));
        auto *save = dialog->findChild<QPushButton *>(QStringLiteral("noteSave"));
        if (!body || !save) {
            publicFailure = QStringLiteral("public note editor widgets missing");
            dialog->reject();
            return;
        }
        auto *eye = body->findChild<QToolButton *>(QStringLiteral("secretEye"));
        publicDialogSeen = true;
        if (!body->isLoaded()
            || body->content() != QStringLiteral("public note body")) {
            publicFailure = QStringLiteral("C note content was not loaded directly");
        }
        if (eye && !eye->isHidden())
            publicFailure = QStringLiteral("C note showed an eye button");
        if (!save->isEnabled())
            publicFailure = QStringLiteral("C note save was disabled");
        dialog->reject();
    });
    view.editSelectedEntry();
    QVERIFY2(publicFailure.isEmpty(), qPrintable(publicFailure));
    QVERIFY(publicDialogSeen);
}

void TestVaultView::topSecretRevealAndEditor()
{
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString vault = QDir(dir.path()).filePath(QStringLiteral("personal"));
    QVERIFY(QDir().mkpath(vault));

    Bytes deviceSecret;
    const auto created = VaultCreator::create(
        vault, QStringLiteral("master-password"),
        [&deviceSecret](const QString &, std::span<const std::uint8_t>,
                        std::span<const std::uint8_t> secret, QString *) {
            deviceSecret.assign(secret.begin(), secret.end());
            return true;
        });
    QVERIFY2(created.ok, qPrintable(created.error));

    QFile secretFile(QDir(vault).filePath(QStringLiteral("device_secret")));
    QVERIFY(secretFile.open(QIODevice::WriteOnly));
    QCOMPARE(secretFile.write(reinterpret_cast<const char *>(deviceSecret.data()),
                              static_cast<qint64>(deviceSecret.size())),
             static_cast<qint64>(deviceSecret.size()));
    secretFile.close();

    auto unlocked =
        VaultUnlocker::unlock(vault, QStringLiteral("master-password"), false);
    QVERIFY2(unlocked.ok, qPrintable(unlocked.error));

    const QString databasePath = QDir(vault).filePath(QStringLiteral("vault.db"));
    std::string databaseError;
    VaultDatabase database;
    QVERIFY2(database.open(databasePath.toStdString(), unlocked.vaultKey.span(),
                           &databaseError),
             databaseError.c_str());

    TopSecretService service(vault, database.handle());
    QString topSecretError;
    QVERIFY2(service.setup(unlocked.smk.span(),
                           cryptowl::crypto::bytesOf("secondary-password"),
                           &topSecretError),
             qPrintable(topSecretError));
    ProtectedValue topSecretKek;
    QVERIFY2(service.unlock(cryptowl::crypto::bytesOf("secondary-password"),
                            &topSecretKek, &topSecretError),
             qPrintable(topSecretError));

    auto sessionUnlock =
        VaultUnlocker::unlock(vault, QStringLiteral("master-password"), false);
    QVERIFY2(sessionUnlock.ok, qPrintable(sessionUnlock.error));
    auto session = VaultSession::open(
        databasePath.toStdString(), std::move(sessionUnlock.vaultKey),
        std::move(sessionUnlock.smk), &databaseError);
    QVERIFY2(session != nullptr, databaseError.c_str());
    auto sharedSession = std::shared_ptr<VaultSession>(std::move(session));

    std::string itemError;
    std::string noteId;
    QVERIFY2(sharedSession->items().create(
                 noteItem("Top Note", "top secret body", "T"),
                 topSecretKek.span(), &noteId, &itemError),
             itemError.c_str());
    NewItem topPassword;
    topPassword.type = "password";
    topPassword.classification = "T";
    topPassword.title = "Top Login";
    topPassword.meta = "{}";
    topPassword.payload =
        "{\"username\":\"top\",\"url\":\"\",\"secret\":\"top-secret\","
        "\"notes\":\"top notes\"}";
    std::string passwordId;
    QVERIFY2(sharedSession->items().create(topPassword, topSecretKek.span(),
                                           &passwordId, &itemError),
             itemError.c_str());

    VaultView view(vault, sharedSession);
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    QVERIFY(details);

    const auto select = [details](const QString &title) {
        for (int i = 0; i < details->topLevelItemCount(); ++i) {
            if (details->topLevelItem(i)->text(0) == title) {
                details->setCurrentItem(details->topLevelItem(i));
                return;
            }
        }
    };

    QString failure;
    const auto scheduleUnlock = [&failure] {
        QTimer::singleShot(0, [&failure] {
            auto *dialog =
                qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!dialog) {
                failure = QStringLiteral("Top Secret unlock dialog not found");
                return;
            }
            auto *password =
                dialog->findChild<QLineEdit *>(QStringLiteral("topSecretPassword"));
            auto *button =
                dialog->findChild<QPushButton *>(QStringLiteral("topSecretUnlock"));
            if (!password || !button) {
                failure = QStringLiteral("Top Secret unlock widgets missing");
                dialog->reject();
                return;
            }
            password->setText(QStringLiteral("secondary-password"));
            button->click();
            if (dialog->isVisible()) {
                if (failure.isEmpty())
                    failure = QStringLiteral("Top Secret unlock failed");
                dialog->reject();
            }
        });
    };

    select(QStringLiteral("Top Note"));
    failure.clear();
    QTimer::singleShot(0, [&] {
        auto *editor = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!editor) {
            failure = QStringLiteral("note editor not found");
            return;
        }
        auto *body = editor->findChild<EncryptedContentWidget *>(
            QStringLiteral("noteBodyWidget"));
        auto *save = editor->findChild<QPushButton *>(QStringLiteral("noteSave"));
        if (!body || !save) {
            failure = QStringLiteral("note editor widgets missing");
            editor->reject();
            return;
        }
        auto *eye = body->findChild<QToolButton *>(QStringLiteral("secretEye"));
        if (!eye) {
            failure = QStringLiteral("Top Secret note eye missing");
            editor->reject();
            return;
        }
        if (body->isLoaded())
            failure = QStringLiteral("Top Secret note was loaded before reveal");
        if (!body->content().isEmpty())
            failure = QStringLiteral("Top Secret note was not hidden");
        if (save->isEnabled())
            failure = QStringLiteral("Top Secret note save was enabled");

        scheduleUnlock();
        eye->click();
        if (body->content() != QStringLiteral("top secret body"))
            failure = QStringLiteral("Top Secret note reveal failed");

        body->setContent(QStringLiteral("edited top secret body"));
        scheduleUnlock();
        save->click();
        if (editor->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("Top Secret note save did not complete");
            editor->reject();
        }
    });
    view.editSelectedEntry();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));

    ItemRecord record;
    QVERIFY2(sharedSession->items().get(noteId, topSecretKek.span(), &record,
                                        &itemError),
             itemError.c_str());
    QCOMPARE(QString::fromStdString(record.payload),
             QStringLiteral("edited top secret body"));

    select(QStringLiteral("Top Login"));
    failure.clear();
    QTimer::singleShot(0, [&] {
        auto *editor = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!editor) {
            failure = QStringLiteral("password editor not found");
            return;
        }
        auto *password = editor->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *notes = editor->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordNotesWidget"));
        auto *save =
            editor->findChild<QPushButton *>(QStringLiteral("passwordSave"));
        if (!password || !notes || !save) {
            failure = QStringLiteral("password editor widgets missing");
            editor->reject();
            return;
        }
        auto *passwordEye =
            password->findChild<QToolButton *>(QStringLiteral("secretEye"));
        auto *notesEye =
            notes->findChild<QToolButton *>(QStringLiteral("secretEye"));
        if (!passwordEye || !notesEye) {
            failure = QStringLiteral("Top Secret password eyes missing");
            editor->reject();
            return;
        }
        if (password->isLoaded() || notes->isLoaded())
            failure = QStringLiteral("Top Secret password loaded before reveal");
        if (!password->content().isEmpty() || !notes->content().isEmpty())
            failure = QStringLiteral("Top Secret password masks missing");
        if (save->isEnabled())
            failure = QStringLiteral("Top Secret password save was enabled");

        scheduleUnlock();
        passwordEye->click();
        if (password->content() != QStringLiteral("top-secret"))
            failure = QStringLiteral("Top Secret password reveal failed");
        if (notes->isLoaded())
            failure = QStringLiteral("Top Secret notes loaded with password");

        scheduleUnlock();
        notesEye->click();
        if (notes->content() != QStringLiteral("top notes"))
            failure = QStringLiteral("Top Secret password notes reveal failed");

        notes->setContent(QStringLiteral("edited top notes"));
        scheduleUnlock();
        save->click();
        if (editor->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("Top Secret password save did not complete");
            editor->reject();
        }
    });
    view.editSelectedEntry();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));

    QVERIFY2(sharedSession->items().get(passwordId, topSecretKek.span(), &record,
                                        &itemError),
             itemError.c_str());
    QVERIFY(record.payload.find("edited top notes") != std::string::npos);
    QVERIFY(record.payload.find("top-secret") != std::string::npos);
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
