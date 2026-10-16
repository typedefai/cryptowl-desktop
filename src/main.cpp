#include "MainWindow.h"

#include <QApplication>
#include <QStyleFactory>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("typedefai"));
    QCoreApplication::setApplicationName(QStringLiteral("CryptOwl Desktop"));
    QCoreApplication::setApplicationVersion(QStringLiteral(CRYPTOWL_VERSION));

    if (QStyle *fusion = QStyleFactory::create(QStringLiteral("Fusion")))
        QApplication::setStyle(fusion);

    MainWindow window;
    window.show();

    return app.exec();
}
