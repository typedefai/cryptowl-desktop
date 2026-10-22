#include "RecentVaultsStore.h"

#include <QSettings>
#include <QTemporaryDir>
#include <QtTest>

class TestRecentVaults : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void init();

    void addsMostRecentFirst();
    void deduplicatesAndMovesToFront();
    void capsAtMaxEntries();
    void removesEntry();
    void persistsAcrossInstances();

private:
    QTemporaryDir m_settingsDir;
};

void TestRecentVaults::initTestCase()
{
    QCoreApplication::setOrganizationName(QStringLiteral("typedefai"));
    QCoreApplication::setApplicationName(QStringLiteral("CryptOwl Desktop Test"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, m_settingsDir.path());
}

void TestRecentVaults::init()
{
    QSettings().clear();
}

void TestRecentVaults::addsMostRecentFirst()
{
    RecentVaultsStore store;
    store.add(m_settingsDir.filePath(QStringLiteral("vault-a")));
    store.add(m_settingsDir.filePath(QStringLiteral("vault-b")));

    QCOMPARE(store.paths(),
             QStringList({m_settingsDir.filePath(QStringLiteral("vault-b")),
                          m_settingsDir.filePath(QStringLiteral("vault-a"))}));
}

void TestRecentVaults::deduplicatesAndMovesToFront()
{
    RecentVaultsStore store;
    const QString pathA = m_settingsDir.filePath(QStringLiteral("vault-a"));
    const QString pathB = m_settingsDir.filePath(QStringLiteral("vault-b"));
    store.add(pathA);
    store.add(pathB);
    store.add(pathA);

    QCOMPARE(store.paths(), QStringList({pathA, pathB}));
}

void TestRecentVaults::capsAtMaxEntries()
{
    RecentVaultsStore store;
    for (int i = 0; i < RecentVaultsStore::kMaxEntries + 2; ++i)
        store.add(m_settingsDir.filePath(QStringLiteral("vault-%1").arg(i)));

    const QStringList paths = store.paths();
    QCOMPARE(paths.size(), RecentVaultsStore::kMaxEntries);
    QCOMPARE(paths.constFirst(), m_settingsDir.filePath(QStringLiteral("vault-11")));
    QVERIFY(!paths.contains(m_settingsDir.filePath(QStringLiteral("vault-0"))));
}

void TestRecentVaults::removesEntry()
{
    RecentVaultsStore store;
    const QString pathA = m_settingsDir.filePath(QStringLiteral("vault-a"));
    const QString pathB = m_settingsDir.filePath(QStringLiteral("vault-b"));
    store.add(pathA);
    store.add(pathB);
    store.remove(pathA);

    QCOMPARE(store.paths(), QStringList({pathB}));

    store.remove(m_settingsDir.filePath(QStringLiteral("vault-missing")));
    QCOMPARE(store.paths(), QStringList({pathB}));
}

void TestRecentVaults::persistsAcrossInstances()
{
    const QString path = m_settingsDir.filePath(QStringLiteral("vault-a"));
    {
        RecentVaultsStore store;
        store.add(path);
    }

    RecentVaultsStore reopened;
    QCOMPARE(reopened.paths(), QStringList({path}));
}

QTEST_GUILESS_MAIN(TestRecentVaults)
#include "tst_recentvaults.moc"
