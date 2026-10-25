#include "VaultInfoDialog.h"

#include "vault/VaultDatabase.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLocale>
#include <QPushButton>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace {

QString escapedOrDash(const QString &text)
{
    return text.isEmpty() ? QStringLiteral("—") : text.toHtmlEscaped();
}

QString stringOrDash(const QJsonValue &value)
{
    return escapedOrDash(value.toString());
}

QString numberOrDash(const QJsonValue &value)
{
    return value.isDouble() ? QString::number(value.toInt()) : QStringLiteral("—");
}

QString timestampOrDash(const QJsonValue &value)
{
    const double milliseconds = value.toDouble(0);
    if (milliseconds <= 0)
        return QStringLiteral("—");
    return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(milliseconds))
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

QString saltDescription(const QJsonValue &value)
{
    const QString encoded = value.toString();
    if (encoded.isEmpty())
        return QStringLiteral("—");
    return QCoreApplication::translate("VaultInfoDialog", "%1 Base32 characters")
        .arg(encoded.size());
}

QString fileSize(const QString &path)
{
    const QFileInfo info(path);
    if (!info.exists())
        return QCoreApplication::translate("VaultInfoDialog", "not present");
    return QLocale().formattedDataSize(info.size());
}

} // namespace

VaultInfoDialog::VaultInfoDialog(const QString &vaultPath, bool unlocked, QWidget *parent)
    : QDialog(parent)
    , m_vaultPath(vaultPath)
    , m_unlocked(unlocked)
{
    setWindowTitle(tr("Vault information"));
    setMinimumSize(580, 500);
    setSizeGripEnabled(true);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);

    auto *browser = new QTextBrowser(this);
    browser->setObjectName(QStringLiteral("vaultInfoText"));
    browser->setOpenExternalLinks(false);
    browser->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    browser->setHtml(buildHtml());
    layout->addWidget(browser, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    layout->addWidget(buttons);
}

QString VaultInfoDialog::buildHtml() const
{
    const QFileInfo directoryInfo(m_vaultPath);
    const QString name = directoryInfo.fileName();
    const QString location = QDir::toNativeSeparators(m_vaultPath);

    QFile metaFile(QDir(m_vaultPath).filePath(QStringLiteral("vault.meta")));
    if (!metaFile.open(QIODevice::ReadOnly)) {
        return tr("<h2>%1</h2><p><b>Location:</b> <code>%2</code></p>"
                  "<p><b>Error:</b> could not read vault.meta.</p>")
            .arg(escapedOrDash(name), escapedOrDash(location));
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(metaFile.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return tr("<h2>%1</h2><p><b>Location:</b> <code>%2</code></p>"
                  "<p><b>Error:</b> vault.meta is not valid JSON.</p>")
            .arg(escapedOrDash(name), escapedOrDash(location));
    }

    const QJsonObject meta = document.object();
    const QJsonObject kdf = meta.value(QStringLiteral("kdf")).toObject();
    const QJsonObject salts = meta.value(QStringLiteral("salts")).toObject();
    const QJsonObject mac = meta.value(QStringLiteral("mac")).toObject();
    const QJsonArray wrappedKeys = meta.value(QStringLiteral("wrapped_keys")).toArray();

    const QString cipherVersion = QString::fromStdString(
        cryptowl::vault::VaultDatabase::cipherVersion());
    const QString metaPath = QDir(m_vaultPath).filePath(QStringLiteral("vault.meta"));
    const QString configPath = QDir(m_vaultPath).filePath(QStringLiteral("config.json"));
    const QString signaturePath = QDir(m_vaultPath).filePath(QStringLiteral("config.sig"));
    const QString databasePath = QDir(m_vaultPath).filePath(QStringLiteral("vault.db"));
    const QString legacySecretPath =
        QDir(m_vaultPath).filePath(QStringLiteral("device_secret"));
    const bool legacySecret = QFileInfo::exists(legacySecretPath);

    QString html;
    html += QStringLiteral("<h2>%1</h2>").arg(escapedOrDash(name));
    html += tr("<p><b>Status:</b> %1<br><b>Location:</b> <code>%2</code></p>")
                .arg(m_unlocked ? tr("Unlocked") : tr("Locked"), escapedOrDash(location));

    html += tr("<h3>Encryption</h3><table cellspacing=\"4\">");
    const auto addRow = [&html](const QString &label, const QString &value) {
        html += QStringLiteral("<tr><td><b>%1</b></td><td>%2</td></tr>")
                    .arg(label, value);
    };

    addRow(tr("Vault format"), numberOrDash(meta.value(QStringLiteral("version"))));
    const QString sqlCipher = cipherVersion.isEmpty()
        ? QStringLiteral("—")
        : tr("%1 (OpenSSL provider)").arg(escapedOrDash(cipherVersion));
    addRow(tr("SQLCipher"), sqlCipher);
    addRow(tr("Database encryption"), QStringLiteral("AES-256-GCM"));
    addRow(tr("Page size"), tr("8192 bytes (SQLCipher 5 default)"));

    const QString kdfMemory = numberOrDash(kdf.value(QStringLiteral("m_kib")));
    const QString kdfIterations = numberOrDash(kdf.value(QStringLiteral("t")));
    const QString kdfParallelism = numberOrDash(kdf.value(QStringLiteral("p")));
    addRow(tr("Password KDF"),
           tr("%1, m=%2 KiB, t=%3, p=%4")
               .arg(stringOrDash(kdf.value(QStringLiteral("algorithm"))), kdfMemory,
                    kdfIterations, kdfParallelism));
    addRow(tr("Key wrapping"), QStringLiteral("AES-256-GCM"));
    addRow(tr("Metadata MAC"),
           tr("%1 (%2)")
               .arg(stringOrDash(mac.value(QStringLiteral("algorithm"))),
                    m_unlocked ? tr("verified on unlock") : tr("not verified")));
    addRow(tr("Config signature"),
           tr("HMAC-SHA256; %1").arg(QFileInfo::exists(signaturePath) ? tr("present")
                                                                      : tr("missing")));
    html += QStringLiteral("</table>");

    html += tr("<h3>Keys</h3><table cellspacing=\"4\">");
    addRow(tr("VaultKey"),
           tr("32-byte SQLCipher raw key; %1")
               .arg(m_unlocked ? tr("in memory for this session")
                               : tr("not in memory; vault is locked")));
    addRow(tr("Device secret"),
           legacySecret ? tr("32 bytes; legacy device_secret file (migrates on next unlock)")
                        : tr("32 bytes; OS secure storage (QtKeychain)"));
    addRow(tr("KEK"),
           tr("32 bytes; SMK-wrapped dev binding; %1")
               .arg(m_unlocked ? tr("in memory for this session")
                               : tr("not in memory")));
    addRow(tr("TMK"), tr("32 bytes; Argon2id output; never stored"));
    addRow(tr("SMK"), tr("64 bytes; HKDF-SHA256 output; never stored"));
    addRow(tr("Metadata MAC key"), tr("SMK[32:64]; derived on demand"));
    addRow(tr("Item DEKs"), tr("one per S-tier item; wrapped by KEK"));
    html += QStringLiteral("</table>");

    html += tr("<p><b>Wrapped VaultKey copies:</b></p><ul>");
    if (wrappedKeys.isEmpty()) {
        html += tr("<li>No wrapped keys found.</li>");
    } else {
        for (const QJsonValue &value : wrappedKeys) {
            const QJsonObject wrapped = value.toObject();
            html += tr("<li><code>%1</code> — role <b>%2</b>, wrapper <b>%3</b>, "
                       "%4</li>")
                        .arg(stringOrDash(wrapped.value(QStringLiteral("id"))),
                             stringOrDash(wrapped.value(QStringLiteral("role"))),
                             stringOrDash(wrapped.value(QStringLiteral("wrapper"))),
                             stringOrDash(wrapped.value(QStringLiteral("algorithm"))));
        }
    }
    html += QStringLiteral("</ul>");
    html += tr("<p><i>Actual key material and wrapped ciphertext are never displayed.</i></p>");

    html += tr("<h3>Vault metadata</h3><table cellspacing=\"4\">");
    addRow(tr("Vault ID"), stringOrDash(meta.value(QStringLiteral("vault_id"))));
    addRow(tr("Created"), timestampOrDash(meta.value(QStringLiteral("created_at"))));
    addRow(tr("Updated"), timestampOrDash(meta.value(QStringLiteral("updated_at"))));
    addRow(tr("Argon2 salt"), saltDescription(salts.value(QStringLiteral("argon2"))));
    addRow(tr("HKDF salt"), saltDescription(salts.value(QStringLiteral("hkdf"))));
    addRow(tr("Secondary salt"), saltDescription(salts.value(QStringLiteral("secondary"))));
    addRow(tr("vault.meta"), fileSize(metaPath));
    addRow(tr("vault.db"), fileSize(databasePath));
    addRow(tr("config.json"), fileSize(configPath));
    html += QStringLiteral("</table>");

    return html;
}
