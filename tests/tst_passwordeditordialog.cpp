#include "PasswordEditorDialog.h"

#include "EncryptedContentWidget.h"

#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QToolButton>
#include <QtTest>

class TestPasswordEditorDialog : public QObject
{
    Q_OBJECT

private slots:
    void roundTripsData();
    void togglesPasswordVisibility();
    void lazyLoadsSecretOnShow();
    void requiresTitle();
};

void TestPasswordEditorDialog::roundTripsData()
{
    PasswordEditorDialog::Data initial;
    initial.title = QStringLiteral("GitHub");
    initial.username = QStringLiteral("riguz");
    initial.url = QStringLiteral("https://github.com");
    initial.password = QStringLiteral("secret");
    initial.notes = QStringLiteral("notes");

    PasswordEditorDialog dialog(initial);
    auto *title = dialog.findChild<QLineEdit *>(QStringLiteral("passwordTitle"));
    auto *username = dialog.findChild<QLineEdit *>(QStringLiteral("passwordUsername"));
    auto *url = dialog.findChild<QLineEdit *>(QStringLiteral("passwordUrl"));
    auto *password = dialog.findChild<EncryptedContentWidget *>(
        QStringLiteral("passwordSecretWidget"));
    auto *notes = dialog.findChild<EncryptedContentWidget *>(
        QStringLiteral("passwordNotesWidget"));
    QVERIFY(title);
    QVERIFY(username);
    QVERIFY(url);
    QVERIFY(password);
    QVERIFY(notes);

    QCOMPARE(title->text(), initial.title);
    QCOMPARE(username->text(), initial.username);
    QCOMPARE(url->text(), initial.url);
    QCOMPARE(password->content(), initial.password);
    QCOMPARE(notes->content(), initial.notes);

    title->setText(QStringLiteral("GitHub Work"));
    username->setText(QStringLiteral("work-user"));
    url->setText(QStringLiteral("https://work.example.com"));
    password->setContent(QStringLiteral("new-secret"), true);
    notes->setContent(QStringLiteral("updated notes"));

    const PasswordEditorDialog::Data result = dialog.data();
    QCOMPARE(result.title, QStringLiteral("GitHub Work"));
    QCOMPARE(result.username, QStringLiteral("work-user"));
    QCOMPARE(result.url, QStringLiteral("https://work.example.com"));
    QCOMPARE(result.password, QStringLiteral("new-secret"));
    QCOMPARE(result.notes, QStringLiteral("updated notes"));
}

void TestPasswordEditorDialog::togglesPasswordVisibility()
{
    PasswordEditorDialog dialog;
    auto *widget = dialog.findChild<EncryptedContentWidget *>(
        QStringLiteral("passwordSecretWidget"));
    QVERIFY(widget);
    auto *lineEdit =
        widget->findChild<QLineEdit *>(QStringLiteral("secretLineEdit"));
    auto *eye = widget->findChild<QToolButton *>(QStringLiteral("secretEye"));
    QVERIFY(lineEdit);
    QVERIFY(eye);
    QCOMPARE(lineEdit->echoMode(), QLineEdit::Password);
    QVERIFY(!widget->isVisible());

    eye->click();
    QCOMPARE(lineEdit->echoMode(), QLineEdit::Normal);
    QVERIFY(widget->isVisible());

    eye->click();
    QCOMPARE(lineEdit->echoMode(), QLineEdit::Password);
    QVERIFY(!widget->isVisible());
    QVERIFY(widget->isLoaded());
}

void TestPasswordEditorDialog::lazyLoadsSecretOnShow()
{
    PasswordEditorDialog::Data initial;
    initial.title = QStringLiteral("GitHub");
    initial.username = QStringLiteral("riguz");
    initial.url = QStringLiteral("https://github.com");

    int loads = 0;
    PasswordEditorDialog dialog(
        initial, [&loads](QString *password, QString *notes, QString *error) {
            ++loads;
            Q_UNUSED(error);
            *password = QStringLiteral("loaded-secret");
            *notes = QStringLiteral("loaded notes");
            return true;
        });

    auto *password = dialog.findChild<EncryptedContentWidget *>(
        QStringLiteral("passwordSecretWidget"));
    auto *notes = dialog.findChild<EncryptedContentWidget *>(
        QStringLiteral("passwordNotesWidget"));
    auto *save = dialog.findChild<QPushButton *>(QStringLiteral("passwordSave"));
    QVERIFY(password);
    QVERIFY(notes);
    QVERIFY(save);
    auto *passwordEye =
        password->findChild<QToolButton *>(QStringLiteral("secretEye"));
    auto *notesEye =
        notes->findChild<QToolButton *>(QStringLiteral("secretEye"));
    QVERIFY(passwordEye);
    QVERIFY(notesEye);

    QCOMPARE(loads, 0);
    QVERIFY(!password->isLoaded());
    QVERIFY(password->content().isEmpty());
    QVERIFY(!notes->isLoaded());
    QVERIFY(notes->content().isEmpty());
    QVERIFY(!save->isEnabled());

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));

    passwordEye->click();
    QCOMPARE(loads, 1);
    QVERIFY(password->isLoaded());
    QCOMPARE(password->content(), QStringLiteral("loaded-secret"));
    QVERIFY(notes->content().isEmpty());
    QVERIFY(!save->isEnabled());

    notesEye->click();
    QCOMPARE(loads, 2);
    QVERIFY(notes->isLoaded());
    QCOMPARE(notes->content(), QStringLiteral("loaded notes"));
    QVERIFY(save->isEnabled());

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));

    passwordEye->click();
    QVERIFY(!password->isLoaded());
    QVERIFY(password->content().isEmpty());
    QVERIFY(!save->isEnabled());

    passwordEye->click();
    QCOMPARE(loads, 3);
    QVERIFY(password->isLoaded());
    QCOMPARE(password->content(), QStringLiteral("loaded-secret"));
}

void TestPasswordEditorDialog::requiresTitle()
{
    PasswordEditorDialog dialog;
    auto *error = dialog.findChild<QLabel *>(QStringLiteral("passwordError"));
    auto *title = dialog.findChild<QLineEdit *>(QStringLiteral("passwordTitle"));
    QVERIFY(error);
    QVERIFY(title);

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));
    QVERIFY(!error->text().isEmpty());

    title->setText(QStringLiteral("Mail"));
    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
}

QTEST_MAIN(TestPasswordEditorDialog)
#include "tst_passwordeditordialog.moc"
