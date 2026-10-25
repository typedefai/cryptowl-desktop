#include "VaultView.h"

#include <QListWidget>
#include <QStackedWidget>
#include <QTextBrowser>
#include <QTreeWidget>
#include <QtTest>

class TestVaultView : public QObject
{
    Q_OBJECT

private slots:
    void showsMockGroupsAndEntries();
    void filtersEntries();
    void switchesToIconView();
};

void TestVaultView::showsMockGroupsAndEntries()
{
    VaultView view(QStringLiteral("/tmp/mock-vault"));

    auto *structure = view.findChild<QTreeWidget *>(QStringLiteral("vaultStructure"));
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    auto *info = view.findChild<QTextBrowser *>(QStringLiteral("vaultInfo"));
    QVERIFY(structure);
    QVERIFY(details);
    QVERIFY(info);

    QCOMPARE(structure->topLevelItemCount(), 1);
    QCOMPARE(structure->topLevelItem(0)->childCount(), 7);
    QCOMPARE(details->topLevelItemCount(), 15);

    structure->setCurrentItem(structure->topLevelItem(0)->child(1)); // Internet
    QCOMPARE(details->topLevelItemCount(), 3);

    details->setCurrentItem(details->topLevelItem(0));
    QVERIFY(info->toPlainText().contains(QStringLiteral("GitHub")));
    QVERIFY(info->toPlainText().contains(QStringLiteral("Group")));
}

void TestVaultView::filtersEntries()
{
    VaultView view(QStringLiteral("/tmp/mock-vault"));
    auto *details = view.findChild<QTreeWidget *>(QStringLiteral("vaultDetails"));
    QVERIFY(details);

    view.setFilter(QStringLiteral("GitHub"));
    QCOMPARE(details->topLevelItemCount(), 1);
    QCOMPARE(details->topLevelItem(0)->text(0), QStringLiteral("GitHub"));

    view.setFilter(QString());
    QCOMPARE(details->topLevelItemCount(), 15);
}

void TestVaultView::switchesToIconView()
{
    VaultView view(QStringLiteral("/tmp/mock-vault"));
    auto *stack = view.findChild<QStackedWidget *>(QStringLiteral("vaultContentStack"));
    auto *icons = view.findChild<QListWidget *>(QStringLiteral("vaultIcons"));
    QVERIFY(stack);
    QVERIFY(icons);

    view.showIcons();
    QCOMPARE(stack->currentWidget(), icons);
    QCOMPARE(icons->count(), 15);
}

QTEST_MAIN(TestVaultView)
#include "tst_vaultview.moc"
