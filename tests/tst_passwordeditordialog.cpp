#include "PasswordEditorDialog.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPushButton>
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
    auto *password = dialog.findChild<QLineEdit *>(QStringLiteral("passwordSecret"));
    auto *notes = dialog.findChild<QPlainTextEdit *>(QStringLiteral("passwordNotes"));
    QVERIFY(title);
    QVERIFY(username);
    QVERIFY(url);
    QVERIFY(password);
    QVERIFY(notes);

    QCOMPARE(title->text(), initial.title);
    QCOMPARE(username->text(), initial.username);
    QCOMPARE(url->text(), initial.url);
    QCOMPARE(password->text(), initial.password);
    QCOMPARE(notes->toPlainText(), initial.notes);

    title->setText(QStringLiteral("GitHub Work"));
    username->setText(QStringLiteral("work-user"));
    url->setText(QStringLiteral("https://work.example.com"));
    password->setText(QStringLiteral("new-secret"));
    notes->setPlainText(QStringLiteral("updated notes"));

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
    auto *password = dialog.findChild<QLineEdit *>(QStringLiteral("passwordSecret"));
    auto *show = dialog.findChild<QCheckBox *>(QStringLiteral("passwordShow"));
    QVERIFY(password);
    QVERIFY(show);
    QCOMPARE(password->echoMode(), QLineEdit::Password);

    show->setChecked(true);
    QCOMPARE(password->echoMode(), QLineEdit::Normal);
    show->setChecked(false);
    QCOMPARE(password->echoMode(), QLineEdit::Password);
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

    auto *password =
        dialog.findChild<QLineEdit *>(QStringLiteral("passwordSecret"));
    auto *notes =
        dialog.findChild<QPlainTextEdit *>(QStringLiteral("passwordNotes"));
    auto *show = dialog.findChild<QCheckBox *>(QStringLiteral("passwordShow"));
    auto *save = dialog.findChild<QPushButton *>(QStringLiteral("passwordSave"));
    auto *hint = dialog.findChild<QLabel *>(QStringLiteral("passwordLockHint"));
    QVERIFY(password);
    QVERIFY(notes);
    QVERIFY(show);
    QVERIFY(save);
    QVERIFY(hint);

    QCOMPARE(loads, 0);
    QVERIFY(!password->text().isEmpty());
    QVERIFY(password->text() != QStringLiteral("loaded-secret"));
    QVERIFY(!password->isEnabled());
    QVERIFY(!notes->toPlainText().isEmpty());
    QVERIFY(notes->toPlainText() != QStringLiteral("loaded notes"));
    QVERIFY(!notes->isEnabled());
    QVERIFY(!show->isChecked());
    QVERIFY(!hint->isHidden());
    QVERIFY(!save->isEnabled());

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));

    show->setChecked(true);
    QCOMPARE(loads, 1);
    QCOMPARE(password->text(), QStringLiteral("loaded-secret"));
    QCOMPARE(notes->toPlainText(), QStringLiteral("loaded notes"));
    QVERIFY(password->isEnabled());
    QVERIFY(notes->isEnabled());
    QVERIFY(hint->isHidden());
    QVERIFY(save->isEnabled());
    QCOMPARE(password->echoMode(), QLineEdit::Normal);

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));

    show->setChecked(false);
    QCOMPARE(password->echoMode(), QLineEdit::Password);
    QCOMPARE(loads, 1);
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
