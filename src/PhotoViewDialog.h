#pragma once

#include <QDialog>
#include <QImage>
#include <QString>

class PhotoViewDialog : public QDialog
{
    Q_OBJECT

public:
    PhotoViewDialog(const QString &title, const QImage &image,
                    QWidget *parent = nullptr);
};
