#pragma once

#include <QWidget>

#include <functional>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QToolButton;
class QIcon;

class EncryptedContentWidget : public QWidget
{
    Q_OBJECT

public:
    enum class Mode
    {
        SingleLine,
        MultiLine,
    };

    using Loader = std::function<bool(QString *content, QString *error)>;

    explicit EncryptedContentWidget(Mode mode, QWidget *parent = nullptr);

    // Lazy mode: the field starts masked; showing it calls the loader.
    // Hiding wipes the current value, so showing again re-loads/decrypts it.
    void setLoader(Loader loader);

    // Direct mode: the value is already available (new draft or C-tier data).
    // Single-line fields can start masked; the eye then only toggles echo.
    void setContent(const QString &content, bool maskSingleLine = false);

    void setReadOnly(bool readOnly);
    void setPlaceholderText(const QString &text);

    QString content() const;
    bool isLoaded() const;
    bool isVisible() const;

    void reveal();
    void hideContent();

signals:
    void revealed();
    void hidden();
    void errorOccurred(const QString &message);
    void copied();

private:
    void updateControls();
    void showMaskedState();
    void setFieldValue(const QString &value);
    QIcon eyeIcon(bool open) const;

    Mode m_mode;
    Loader m_loader;
    bool m_loaded = false;
    bool m_visible = false;
    bool m_readOnly = false;
    bool m_draftMasked = false;

    QLineEdit *m_lineEdit = nullptr;
    QPlainTextEdit *m_textEdit = nullptr;
    QToolButton *m_eyeButton = nullptr;
    QToolButton *m_copyButton = nullptr;
    QLabel *m_statusLabel = nullptr;
};
