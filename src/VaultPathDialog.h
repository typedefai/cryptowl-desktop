#pragma once

#include <QDialog>

class QLabel;
class QLineEdit;
class QPushButton;

class VaultPathDialog : public QDialog
{
    Q_OBJECT

public:
    enum class Mode
    {
        Open,
        Create,
    };

    explicit VaultPathDialog(Mode mode, QWidget *parent = nullptr);

    QString path() const;
    void setPath(const QString &path);

private slots:
    void browse();
    void tryAccept();

private:
    void setError(const QString &message);

    Mode m_mode;
    QLineEdit *m_pathEdit = nullptr;
    QPushButton *m_browseButton = nullptr;
    QLabel *m_errorLabel = nullptr;
    QPushButton *m_acceptButton = nullptr;
};
