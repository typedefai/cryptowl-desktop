#include "MainWindow.h"

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QStringList>
#include <QStyle>
#include <QStyleFactory>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("typedefai"));
    QCoreApplication::setApplicationName(QStringLiteral("CryptOwl Desktop"));
    QCoreApplication::setApplicationVersion(QStringLiteral(CRYPTOWL_VERSION));

    // Prefer the native Vista/Aero style where Qt provides it (Windows), then
    // the classic Win32 style, then Fusion.
    for (const QString &styleName :
         {QStringLiteral("WindowsVista"), QStringLiteral("Windows"),
          QStringLiteral("Fusion")}) {
        if (QStyle *style = QStyleFactory::create(styleName)) {
            QApplication::setStyle(style);
            break;
        }
    }

    // Selawik is Microsoft's OFL-licensed, Segoe UI-compatible UI font.
    QFontDatabase::addApplicationFont(QStringLiteral(":/fonts/selawkb.ttf"));
    const int regularFont = QFontDatabase::addApplicationFont(QStringLiteral(":/fonts/selawk.ttf"));
    if (regularFont >= 0) {
        const QStringList families = QFontDatabase::applicationFontFamilies(regularFont);
        if (!families.isEmpty()) {
            QFont font(families.constFirst());
            font.setPointSize(9);
            QApplication::setFont(font);
        }
    }

    MainWindow window;
    window.show();

    return app.exec();
}
