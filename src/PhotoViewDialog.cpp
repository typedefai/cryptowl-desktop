#include "PhotoViewDialog.h"

#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>

PhotoViewDialog::PhotoViewDialog(const QString &title, const QImage &image,
                                 QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("View photo"));
    setModal(true);
    resize(900, 700);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    auto *heading = new QLabel(this);
    heading->setTextFormat(Qt::RichText);
    heading->setText(QStringLiteral("<b>%1</b>").arg(title.toHtmlEscaped()));
    layout->addWidget(heading);

    auto *imageLabel = new QLabel(this);
    imageLabel->setObjectName(QStringLiteral("photoViewImage"));
    imageLabel->setAlignment(Qt::AlignCenter);
    imageLabel->setPixmap(QPixmap::fromImage(image).scaled(
        860, 600, Qt::KeepAspectRatio, Qt::SmoothTransformation));

    auto *scroll = new QScrollArea(this);
    scroll->setWidget(imageLabel);
    scroll->setWidgetResizable(true);
    scroll->setAlignment(Qt::AlignCenter);
    layout->addWidget(scroll, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    layout->addWidget(buttons);
}
