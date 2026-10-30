#include "NoteEditorDialog.h"

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QtTest>

class TestNoteEditorDialog : public QObject
{
    Q_OBJECT

private slots:
    void defaultsToConfidential();
    void roundTripsData();
    void lazyLoadsContentOnReveal();
    void requiresTitle();
};

void TestNoteEditorDialog::defaultsToConfidential()
{
    NoteEditorDialog dialog;
    auto *classification =
        dialog.findChild<QComboBox *>(QStringLiteral("noteClassification"));
    QVERIFY(classification);
    QCOMPARE(classification->currentData().toString(), QStringLiteral("C"));
}

void TestNoteEditorDialog::roundTripsData()
{
    NoteEditorDialog::Data initial;
    initial.title = QStringLiteral("Project notes");
    initial.body = QStringLiteral("first line\nsecond line");
    initial.classification = QStringLiteral("S");

    NoteEditorDialog dialog(initial);
    auto *title = dialog.findChild<QLineEdit *>(QStringLiteral("noteTitle"));
    auto *body = dialog.findChild<QPlainTextEdit *>(QStringLiteral("noteBody"));
    auto *classification =
        dialog.findChild<QComboBox *>(QStringLiteral("noteClassification"));
    QVERIFY(title);
    QVERIFY(body);
    QVERIFY(classification);

    QCOMPARE(title->text(), initial.title);
    QCOMPARE(body->toPlainText(), initial.body);
    QCOMPARE(classification->currentData().toString(), QStringLiteral("S"));

    title->setText(QStringLiteral("Updated notes"));
    body->setPlainText(QStringLiteral("updated body"));
    classification->setCurrentIndex(
        classification->findData(QStringLiteral("C")));

    const NoteEditorDialog::Data result = dialog.data();
    QCOMPARE(result.title, QStringLiteral("Updated notes"));
    QCOMPARE(result.body, QStringLiteral("updated body"));
    QCOMPARE(result.classification, QStringLiteral("C"));
}

void TestNoteEditorDialog::lazyLoadsContentOnReveal()
{
    NoteEditorDialog::Data initial;
    initial.title = QStringLiteral("Secret note");
    initial.classification = QStringLiteral("S");

    int loads = 0;
    NoteEditorDialog dialog(
        initial, [&loads](QString *body, QString *error) {
            ++loads;
            Q_UNUSED(error);
            *body = QStringLiteral("loaded secret body");
            return true;
        });

    auto *body = dialog.findChild<QPlainTextEdit *>(QStringLiteral("noteBody"));
    auto *reveal = dialog.findChild<QPushButton *>(QStringLiteral("noteReveal"));
    auto *save = dialog.findChild<QPushButton *>(QStringLiteral("noteSave"));
    auto *hint = dialog.findChild<QLabel *>(QStringLiteral("noteLockHint"));
    QVERIFY(body);
    QVERIFY(reveal);
    QVERIFY(save);
    QVERIFY(hint);

    QCOMPARE(loads, 0);
    QVERIFY(!body->toPlainText().isEmpty());
    QVERIFY(body->toPlainText() != QStringLiteral("loaded secret body"));
    QVERIFY(body->isReadOnly());
    QVERIFY(!hint->isHidden());
    QVERIFY(!reveal->isHidden());
    QVERIFY(!save->isEnabled());

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));

    reveal->click();
    QCOMPARE(loads, 1);
    QCOMPARE(body->toPlainText(), QStringLiteral("loaded secret body"));
    QVERIFY(!body->isReadOnly());
    QVERIFY(hint->isHidden());
    QVERIFY(reveal->isHidden());
    QVERIFY(save->isEnabled());

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
    QCOMPARE(dialog.data().body, QStringLiteral("loaded secret body"));
}

void TestNoteEditorDialog::requiresTitle()
{
    NoteEditorDialog dialog;
    auto *error = dialog.findChild<QLabel *>(QStringLiteral("noteError"));
    auto *title = dialog.findChild<QLineEdit *>(QStringLiteral("noteTitle"));
    QVERIFY(error);
    QVERIFY(title);

    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QVERIFY(dialog.result() != int(QDialog::Accepted));
    QVERIFY(!error->text().isEmpty());

    title->setText(QStringLiteral("Meeting notes"));
    QVERIFY(QMetaObject::invokeMethod(&dialog, "save", Qt::DirectConnection));
    QCOMPARE(dialog.result(), int(QDialog::Accepted));
}

QTEST_MAIN(TestNoteEditorDialog)
#include "tst_noteeditordialog.moc"
