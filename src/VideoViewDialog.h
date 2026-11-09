#pragma once

#include "crypto/FileEnvelope.h"

#include <QDialog>
#include <QString>

#include <memory>

class EncryptedMediaDevice;
class QAudioOutput;
class QLabel;
class QMediaPlayer;
class QPushButton;
class QSlider;
class QVideoWidget;

class VideoViewDialog : public QDialog
{
    Q_OBJECT

public:
    VideoViewDialog(
        const QString &title, const QString &sourceName,
        std::unique_ptr<cryptowl::crypto::FileReader> reader,
        QWidget *parent = nullptr);

    ~VideoViewDialog() override;

private slots:
    void togglePlayback();
    void updatePosition(qint64 position);
    void updateDuration(qint64 duration);
    void updateState();
    void showError(const QString &message);

private:
    EncryptedMediaDevice *m_device = nullptr;
    QMediaPlayer *m_player = nullptr;
    QAudioOutput *m_audio = nullptr;
    QVideoWidget *m_video = nullptr;
    QSlider *m_slider = nullptr;
    QPushButton *m_playButton = nullptr;
    QLabel *m_timeLabel = nullptr;
    QLabel *m_errorLabel = nullptr;
};
