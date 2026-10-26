#include "NoteEditorDialog.h"

#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QtTest>

class TestNoteEditorDialog : public QObject
{
    Q_OBJECT

private slots:
    void defaultsToConfidential();
    void roundTripsData();
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
