#pragma once

#include <QDialog>
#include <QString>

#include <functional>

class EncryptedContentWidget;

class PasswordViewDialog : public QDialog
{
    Q_OBJECT

public:
    struct Data
    {
        QString title;
        QString username;
        QString url;
        QString classification;
        QString password;
        QString notes;
    };

    using SecretLoader =
        std::function<bool(QString *password, QString *notes, QString *error)>;

    PasswordViewDialog(const Data &data, SecretLoader loader,
                       QWidget *parent = nullptr);

private:
    EncryptedContentWidget *m_passwordWidget = nullptr;
    EncryptedContentWidget *m_notesWidget = nullptr;
};
