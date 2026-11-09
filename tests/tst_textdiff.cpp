#include "TextDiff.h"

#include <QtTest>

#include <algorithm>

class TestTextDiff : public QObject
{
    Q_OBJECT

private slots:
    void reportsInsertDeleteAndEqualLines();
    void rejectsHugeInputs();
};

void TestTextDiff::reportsInsertDeleteAndEqualLines()
{
    const QStringList before = {QStringLiteral("one"), QStringLiteral("two"),
                                QStringLiteral("three")};
    const QStringList after = {QStringLiteral("one"), QStringLiteral("three"),
                               QStringLiteral("four")};
    std::vector<DiffLine> lines;
    QVERIFY(diffLines(before, after, &lines));

    int equal = 0;
    int removed = 0;
    int added = 0;
    for (const DiffLine &line : lines) {
        if (line.kind == DiffLineKind::Equal)
            ++equal;
        else if (line.kind == DiffLineKind::Removed)
            ++removed;
        else
            ++added;
    }
    QCOMPARE(equal, 2);
    QCOMPARE(removed, 1);
    QCOMPARE(added, 1);
    QVERIFY(lines.end()
            != std::find_if(lines.begin(), lines.end(), [](const DiffLine &line) {
                   return line.kind == DiffLineKind::Added
                       && line.text == QStringLiteral("four");
               }));
}

void TestTextDiff::rejectsHugeInputs()
{
    QStringList before;
    QStringList after;
    for (int i = 0; i < 3000; ++i) {
        before.append(QString::number(i));
        after.append(QString::number(i + 1));
    }
    std::vector<DiffLine> lines;
    QVERIFY(!diffLines(before, after, &lines));
}

QTEST_APPLESS_MAIN(TestTextDiff)
#include "tst_textdiff.moc"
