#pragma once

#include <QDialog>
#include <QString>

class DiffDialog : public QDialog
{
    Q_OBJECT

public:
    DiffDialog(const QString &beforeLabel, const QString &afterLabel,
               const QString &beforeTier, const QString &afterTier,
               const QString &beforeTitle, const QString &afterTitle,
               const QString &beforePayload, const QString &afterPayload,
               bool jsonPayload, QWidget *parent = nullptr);
};
