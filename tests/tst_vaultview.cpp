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
#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QLineEdit>
#include <QListWidget>
#include <QPointer>
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
#include <vector>

using cryptowl::crypto::Bytes;
using cryptowl::crypto::ProtectedValue;
using cryptowl::vault::ItemRecord;
using cryptowl::vault::ItemRepository;
using cryptowl::vault::ItemSummary;
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
        ProtectedValue(Bytes(kSmk)), error, true);
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
    void secretAccessRequiresPasswordEachTime();
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
        auto *editButton =
            dialog->findChild<QPushButton *>(QStringLiteral("passwordViewEdit"));
        if (!password || !notes || !editButton) {
            passwordFailure = QStringLiteral("password view widgets missing");
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
    view.viewSelectedEntry();
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
        std::move(sessionUnlock.smk), &databaseError, true);
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
        auto *viewer = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!viewer) {
            failure = QStringLiteral("password view not found");
            return;
        }
        auto *password = viewer->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *notes = viewer->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordNotesWidget"));
        if (!password || !notes) {
            failure = QStringLiteral("password view widgets missing");
            viewer->reject();
            return;
        }
        auto *passwordEye =
            password->findChild<QToolButton *>(QStringLiteral("secretEye"));
        auto *notesEye =
            notes->findChild<QToolButton *>(QStringLiteral("secretEye"));
        if (!passwordEye || !notesEye) {
            failure = QStringLiteral("Top Secret password view eyes missing");
            viewer->reject();
            return;
        }
        if (password->isLoaded() || notes->isLoaded())
            failure = QStringLiteral("Top Secret password loaded before reveal");
        if (!password->content().isEmpty() || !notes->content().isEmpty())
            failure = QStringLiteral("Top Secret password masks missing");

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
        viewer->reject();
    });
    view.viewSelectedEntry();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));

    failure.clear();
    bool editorSaved = false;
    QTimer editTimer;
    editTimer.setInterval(0);
    connect(&editTimer, &QTimer::timeout, &editTimer, [&] {
        auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!dialog)
            return;
        if (auto *password =
                dialog->findChild<QLineEdit *>(QStringLiteral("topSecretPassword"))) {
            auto *button =
                dialog->findChild<QPushButton *>(QStringLiteral("topSecretUnlock"));
            if (!button) {
                failure = QStringLiteral("Top Secret unlock widgets missing");
                dialog->reject();
                return;
            }
            password->setText(QStringLiteral("secondary-password"));
            button->click();
            return;
        }

        auto *save = dialog->findChild<QPushButton *>(QStringLiteral("passwordSave"));
        auto *password = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *notes = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordNotesWidget"));
        auto *confirm =
            dialog->findChild<QLineEdit *>(QStringLiteral("passwordConfirm"));
        if (!save || editorSaved)
            return;
        if (!password || !notes || !confirm) {
            failure = QStringLiteral("password editor widgets missing");
            dialog->reject();
            return;
        }
        if (!password->isLoaded() || !notes->isLoaded())
            failure = QStringLiteral("password editor did not preload secrets");
        if (confirm->text() != QStringLiteral("top-secret"))
            failure = QStringLiteral("password confirmation was not prefilled");
        if (!save->isEnabled())
            failure = QStringLiteral("password editor save was disabled");

        editorSaved = true;
        notes->setContent(QStringLiteral("edited top notes"));
        scheduleUnlock();
        save->click();
        if (dialog->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("Top Secret password save did not complete");
            dialog->reject();
        }
    });
    editTimer.start();
    view.editSelectedEntry();
    editTimer.stop();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));

    QVERIFY2(sharedSession->items().get(passwordId, topSecretKek.span(), &record,
                                        &itemError),
             itemError.c_str());
    QVERIFY(record.payload.find("edited top notes") != std::string::npos);
    QVERIFY(record.payload.find("top-secret") != std::string::npos);
}

void TestVaultView::secretAccessRequiresPasswordEachTime()
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

    const QString databasePath = QDir(vault).filePath(QStringLiteral("vault.db"));
    std::string databaseError;
    std::string noteId;
    std::string passwordId;
    {
        auto unlocked =
            VaultUnlocker::unlock(vault, QStringLiteral("master-password"), false);
        QVERIFY2(unlocked.ok, qPrintable(unlocked.error));
        auto setup = VaultSession::open(
            databasePath.toStdString(), std::move(unlocked.vaultKey),
            std::move(unlocked.smk), &databaseError, true);
        QVERIFY2(setup != nullptr, databaseError.c_str());
        QVERIFY2(setup->items().create(
                     noteItem("Private", "secret note body", "S"), &noteId,
                     &databaseError),
                 databaseError.c_str());
        QVERIFY2(setup->items().create(
                     passwordItem("Secret Login", "user", "mock-secret"),
                     &passwordId, &databaseError),
                 databaseError.c_str());
    }

    auto unlocked =
        VaultUnlocker::unlock(vault, QStringLiteral("master-password"), false);
    QVERIFY2(unlocked.ok, qPrintable(unlocked.error));
    auto session = VaultSession::open(
        databasePath.toStdString(), std::move(unlocked.vaultKey),
        std::move(unlocked.smk), &databaseError, false);
    QVERIFY2(session != nullptr, databaseError.c_str());
    QVERIFY(!session->hasKek());
    auto sharedSession = std::shared_ptr<VaultSession>(std::move(session));

    VaultView view(vault, sharedSession);
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    QVERIFY(details);

    const auto select = [details](const QString &title) {
        for (int i = 0; i < details->topLevelItemCount(); ++i) {
            if (details->topLevelItem(i)->text(0) == title) {
                details->setCurrentItem(details->topLevelItem(i));
                return true;
            }
        }
        return false;
    };
    QVERIFY(select(QStringLiteral("Private")));

    QString failure;
    int prompts = 0;
    const auto scheduleSecretAccess = [&failure, &prompts] {
        QTimer::singleShot(0, [&failure, &prompts] {
            auto *dialog =
                qobject_cast<QDialog *>(QApplication::activeModalWidget());
            if (!dialog) {
                failure = QStringLiteral("Secret access dialog not found");
                return;
            }
            auto *password =
                dialog->findChild<QLineEdit *>(QStringLiteral("secretAccessPassword"));
            auto *button =
                dialog->findChild<QPushButton *>(QStringLiteral("secretAccessUnlock"));
            if (!password || !button) {
                failure = QStringLiteral("Secret access widgets missing");
                dialog->reject();
                return;
            }
            ++prompts;
            password->setText(QStringLiteral("master-password"));
            button->click();
            if (dialog->isVisible()) {
                if (failure.isEmpty())
                    failure = QStringLiteral("Secret access unlock failed");
                dialog->reject();
            }
        });
    };

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
            failure = QStringLiteral("Secret note eye missing");
            editor->reject();
            return;
        }
        if (body->isLoaded() || !body->content().isEmpty())
            failure = QStringLiteral("Secret note was loaded before reveal");
        if (save->isEnabled())
            failure = QStringLiteral("Secret note save was enabled");

        scheduleSecretAccess();
        eye->click();
        if (body->content() != QStringLiteral("secret note body"))
            failure = QStringLiteral("Secret note reveal failed");
        if (prompts != 1)
            failure = QStringLiteral("Secret note reveal did not prompt");

        eye->click();
        if (!body->content().isEmpty())
            failure = QStringLiteral("Secret note hide did not clear content");
        scheduleSecretAccess();
        eye->click();
        if (body->content() != QStringLiteral("secret note body"))
            failure = QStringLiteral("Secret note second reveal failed");
        if (prompts != 2)
            failure = QStringLiteral("Secret note second reveal was not prompted");

        body->setContent(QStringLiteral("edited secret note"));
        scheduleSecretAccess();
        save->click();
        if (editor->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("Secret note save did not complete");
            editor->reject();
        }
    });
    view.editSelectedEntry();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));
    QCOMPARE(prompts, 3);
    QVERIFY(!sharedSession->hasKek());

    QVERIFY(select(QStringLiteral("Secret Login")));
    failure.clear();
    QTimer::singleShot(0, [&] {
        auto *viewer = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!viewer) {
            failure = QStringLiteral("password view not found");
            return;
        }
        auto *password = viewer->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *notes = viewer->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordNotesWidget"));
        if (!password || !notes) {
            failure = QStringLiteral("password view widgets missing");
            viewer->reject();
            return;
        }
        auto *passwordEye =
            password->findChild<QToolButton *>(QStringLiteral("secretEye"));
        auto *notesEye =
            notes->findChild<QToolButton *>(QStringLiteral("secretEye"));
        if (!passwordEye || !notesEye) {
            failure = QStringLiteral("Secret password view eyes missing");
            viewer->reject();
            return;
        }
        if (password->isLoaded() || notes->isLoaded())
            failure = QStringLiteral("Secret password loaded before reveal");
        if (!password->content().isEmpty() || !notes->content().isEmpty())
            failure = QStringLiteral("Secret password masks missing");

        scheduleSecretAccess();
        passwordEye->click();
        if (password->content() != QStringLiteral("mock-secret"))
            failure = QStringLiteral("Secret password reveal failed");
        if (notes->isLoaded())
            failure = QStringLiteral("Secret password notes loaded with password");

        scheduleSecretAccess();
        notesEye->click();
        if (notes->content() != QStringLiteral("test notes"))
            failure = QStringLiteral("Secret password notes reveal failed");
        viewer->reject();
    });
    view.viewSelectedEntry();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));
    QCOMPARE(prompts, 5);
    QVERIFY(!sharedSession->hasKek());

    failure.clear();
    bool editorSaved = false;
    QPointer<QDialog> lastPrompt;
    QTimer editTimer;
    editTimer.setInterval(0);
    connect(&editTimer, &QTimer::timeout, &editTimer, [&] {
        auto *dialog = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!dialog)
            return;
        auto *prompt =
            dialog->findChild<QLineEdit *>(QStringLiteral("secretAccessPassword"));
        if (prompt) {
            if (dialog == lastPrompt)
                return;
            lastPrompt = dialog;
            auto *button =
                dialog->findChild<QPushButton *>(QStringLiteral("secretAccessUnlock"));
            if (!button) {
                failure = QStringLiteral("Secret access widgets missing");
                dialog->reject();
                return;
            }
            ++prompts;
            prompt->setText(QStringLiteral("master-password"));
            button->click();
            return;
        }

        auto *save = dialog->findChild<QPushButton *>(QStringLiteral("passwordSave"));
        if (!save || editorSaved)
            return;
        auto *password = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *notes = dialog->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordNotesWidget"));
        auto *confirm =
            dialog->findChild<QLineEdit *>(QStringLiteral("passwordConfirm"));
        if (!password || !notes || !confirm) {
            failure = QStringLiteral("password editor widgets missing");
            dialog->reject();
            return;
        }
        if (!password->isLoaded() || !notes->isLoaded())
            failure = QStringLiteral("password editor did not preload secrets");
        if (confirm->text() != QStringLiteral("mock-secret"))
            failure = QStringLiteral("password confirmation was not prefilled");
        if (!save->isEnabled())
            failure = QStringLiteral("password editor save was disabled");

        editorSaved = true;
        notes->setContent(QStringLiteral("edited secret notes"));
        scheduleSecretAccess();
        save->click();
        if (dialog->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("Secret password save did not complete");
            dialog->reject();
        }
    });
    editTimer.start();
    view.editSelectedEntry();
    editTimer.stop();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));
    QCOMPARE(prompts, 7);
    QVERIFY(!sharedSession->hasKek());

    failure.clear();
    QTimer::singleShot(0, [&] {
        auto *editor = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!editor) {
            failure = QStringLiteral("new note editor not found");
            return;
        }
        auto *title = editor->findChild<QLineEdit *>(QStringLiteral("noteTitle"));
        auto *body = editor->findChild<EncryptedContentWidget *>(
            QStringLiteral("noteBodyWidget"));
        auto *classification = editor->findChild<QComboBox *>(
            QStringLiteral("noteClassification"));
        auto *save = editor->findChild<QPushButton *>(QStringLiteral("noteSave"));
        if (!title || !body || !classification || !save) {
            failure = QStringLiteral("new note editor widgets missing");
            editor->reject();
            return;
        }
        title->setText(QStringLiteral("New Secret"));
        body->setContent(QStringLiteral("new secret body"));
        classification->setCurrentIndex(
            classification->findData(QStringLiteral("S")));
        scheduleSecretAccess();
        save->click();
        if (editor->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("new Secret note save did not complete");
            editor->reject();
        }
    });
    view.addNote();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));
    QCOMPARE(prompts, 8);
    QVERIFY(!sharedSession->hasKek());

    failure.clear();
    QTimer::singleShot(0, [&] {
        auto *editor = qobject_cast<QDialog *>(QApplication::activeModalWidget());
        if (!editor) {
            failure = QStringLiteral("new password editor not found");
            return;
        }
        auto *title =
            editor->findChild<QLineEdit *>(QStringLiteral("passwordTitle"));
        auto *username =
            editor->findChild<QLineEdit *>(QStringLiteral("passwordUsername"));
        auto *password = editor->findChild<EncryptedContentWidget *>(
            QStringLiteral("passwordSecretWidget"));
        auto *confirm =
            editor->findChild<QLineEdit *>(QStringLiteral("passwordConfirm"));
        auto *save =
            editor->findChild<QPushButton *>(QStringLiteral("passwordSave"));
        if (!title || !username || !password || !confirm || !save) {
            failure = QStringLiteral("new password editor widgets missing");
            editor->reject();
            return;
        }
        title->setText(QStringLiteral("New Secret Login"));
        username->setText(QStringLiteral("new-user"));
        password->setContent(QStringLiteral("new-secret"));
        confirm->setText(QStringLiteral("new-secret"));
        scheduleSecretAccess();
        save->click();
        if (editor->isVisible()) {
            if (failure.isEmpty())
                failure = QStringLiteral("new Secret password save did not complete");
            editor->reject();
        }
    });
    view.addEntry();
    QVERIFY2(failure.isEmpty(), qPrintable(failure));
    QCOMPARE(prompts, 9);
    QVERIFY(!sharedSession->hasKek());

    auto readUnlock =
        VaultUnlocker::unlock(vault, QStringLiteral("master-password"), false);
    QVERIFY2(readUnlock.ok, qPrintable(readUnlock.error));
    auto reader = VaultSession::open(
        databasePath.toStdString(), std::move(readUnlock.vaultKey),
        std::move(readUnlock.smk), &databaseError, true);
    QVERIFY2(reader != nullptr, databaseError.c_str());
    ItemRecord record;
    QVERIFY2(reader->items().get(noteId, &record, &databaseError),
             databaseError.c_str());
    QCOMPARE(QString::fromStdString(record.payload),
             QStringLiteral("edited secret note"));
    QVERIFY2(reader->items().get(passwordId, &record, &databaseError),
             databaseError.c_str());
    QVERIFY(record.payload.find("mock-secret") != std::string::npos);
    QVERIFY(record.payload.find("edited secret notes") != std::string::npos);

    std::vector<ItemSummary> notes;
    QVERIFY2(reader->items().list("plain", &notes, &databaseError),
             databaseError.c_str());
    bool foundNewNote = false;
    for (const ItemSummary &summary : notes) {
        if (summary.title != "New Secret")
            continue;
        foundNewNote = true;
        QVERIFY2(reader->items().get(summary.id, &record, &databaseError),
                 databaseError.c_str());
        QCOMPARE(QString::fromStdString(record.payload),
                 QStringLiteral("new secret body"));
        QCOMPARE(QString::fromStdString(record.classification),
                 QStringLiteral("S"));
    }
    QVERIFY(foundNewNote);

    std::vector<ItemSummary> passwords;
    QVERIFY2(reader->items().list("password", &passwords, &databaseError),
             databaseError.c_str());
    bool foundNewPassword = false;
    for (const ItemSummary &summary : passwords) {
        if (summary.title != "New Secret Login")
            continue;
        foundNewPassword = true;
        QVERIFY2(reader->items().get(summary.id, &record, &databaseError),
                 databaseError.c_str());
        QVERIFY(record.payload.find("new-secret") != std::string::npos);
    }
    QVERIFY(foundNewPassword);
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
