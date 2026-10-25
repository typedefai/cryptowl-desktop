#include "PasswordEditorDialog.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QtTest>

class TestPasswordEditorDialog : public QObject
{
    Q_OBJECT

private slots:
    void roundTripsData();
    void togglesPasswordVisibility();
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
