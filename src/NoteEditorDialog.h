#pragma once

#include <QDialog>
#include <QString>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

class NoteEditorDialog : public QDialog
{
    Q_OBJECT

public:
    struct Data
    {
        QString title;
        QString body;
        QString classification = QStringLiteral("C");
    };

    explicit NoteEditorDialog(QWidget *parent = nullptr);
    NoteEditorDialog(const Data &data, QWidget *parent = nullptr);

    Data data() const;

    void reject() override;

private slots:
    void save();

private:
    void buildUi(bool editing);
    void setError(const QString &message);

    QLineEdit *m_titleEdit = nullptr;
    QPlainTextEdit *m_bodyEdit = nullptr;
    QComboBox *m_classificationCombo = nullptr;
    QLabel *m_errorLabel = nullptr;
};
