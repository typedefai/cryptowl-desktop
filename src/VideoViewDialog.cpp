#include "VideoViewDialog.h"

#include "EncryptedMediaDevice.h"

#include <QAudioOutput>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QMediaPlayer>
#include <QPushButton>
#include <QSlider>
#include <QUrl>
#include <QVBoxLayout>
#include <QVideoWidget>

#include <utility>

VideoViewDialog::VideoViewDialog(
    const QString &title, const QString &sourceName,
    std::unique_ptr<cryptowl::crypto::FileReader> reader,
    QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("View video"));
    setModal(true);
    resize(900, 700);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    auto *heading = new QLabel(this);
    heading->setTextFormat(Qt::RichText);
    heading->setText(QStringLiteral("<b>%1</b>").arg(title.toHtmlEscaped()));
    layout->addWidget(heading);

    m_video = new QVideoWidget(this);
    m_video->setObjectName(QStringLiteral("videoViewSurface"));
    layout->addWidget(m_video, 1);

    m_device = new EncryptedMediaDevice(std::move(reader), this);

    auto *controls = new QHBoxLayout;
    m_playButton = new QPushButton(tr("Play"), this);
    m_playButton->setObjectName(QStringLiteral("videoPlayPause"));
    connect(m_playButton, &QPushButton::clicked, this,
            &VideoViewDialog::togglePlayback);
    controls->addWidget(m_playButton);

    m_slider = new QSlider(Qt::Horizontal, this);
    m_slider->setObjectName(QStringLiteral("videoPosition"));
    m_slider->setRange(0, 0);
    connect(m_slider, &QSlider::sliderMoved, this, [this](int position) {
        if (m_player)
            m_player->setPosition(position);
    });
    controls->addWidget(m_slider, 1);

    m_timeLabel = new QLabel(QStringLiteral("0:00 / 0:00"), this);
    m_timeLabel->setObjectName(QStringLiteral("videoTime"));
    controls->addWidget(m_timeLabel);
    layout->addLayout(controls);

    m_errorLabel = new QLabel(this);
    m_errorLabel->setObjectName(QStringLiteral("videoError"));
    m_errorLabel->setWordWrap(true);
    m_errorLabel->hide();
    layout->addWidget(m_errorLabel);

    m_player = new QMediaPlayer(this);
    m_audio = new QAudioOutput(this);
    m_player->setAudioOutput(m_audio);
    m_player->setVideoOutput(m_video);
    connect(m_player, &QMediaPlayer::positionChanged, this,
            &VideoViewDialog::updatePosition);
    connect(m_player, &QMediaPlayer::durationChanged, this,
            &VideoViewDialog::updateDuration);
    connect(m_player, &QMediaPlayer::playbackStateChanged, this,
            &VideoViewDialog::updateState);
    connect(m_player, &QMediaPlayer::errorOccurred, this,
            [this](QMediaPlayer::Error, const QString &message) {
                showError(message.isEmpty() ? tr("Video playback failed.")
                                            : message);
            });
    const QString suffix = QFileInfo(sourceName).suffix();
    const QUrl sourceUrl(
        QStringLiteral("cryptowl:///video%1")
            .arg(suffix.isEmpty() ? QString() : QStringLiteral(".") + suffix));
    m_player->setSourceDevice(m_device, sourceUrl);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Close"));
    layout->addWidget(buttons);
}

VideoViewDialog::~VideoViewDialog()
{
    if (m_player) {
        m_player->stop();
        m_player->setSourceDevice(nullptr);
    }
}

void VideoViewDialog::togglePlayback()
{
    if (!m_player)
        return;
    if (m_player->playbackState() == QMediaPlayer::PlayingState)
        m_player->pause();
    else
        m_player->play();
}

void VideoViewDialog::updatePosition(qint64 position)
{
    if (!m_slider->isSliderDown())
        m_slider->setValue(static_cast<int>(position));
    const qint64 duration = m_player ? m_player->duration() : 0;
    const qint64 seconds = position / 1000;
    const qint64 totalSeconds = duration / 1000;
    m_timeLabel->setText(
        tr("%1:%2 / %3:%4")
            .arg(seconds / 60, 2, 10, QLatin1Char('0'))
            .arg(seconds % 60, 2, 10, QLatin1Char('0'))
            .arg(totalSeconds / 60, 2, 10, QLatin1Char('0'))
            .arg(totalSeconds % 60, 2, 10, QLatin1Char('0')));
}

void VideoViewDialog::updateDuration(qint64 duration)
{
    m_slider->setRange(0, static_cast<int>(duration));
}

void VideoViewDialog::updateState()
{
    if (!m_player)
        return;
    m_playButton->setText(m_player->playbackState() == QMediaPlayer::PlayingState
                              ? tr("Pause")
                              : tr("Play"));
}

void VideoViewDialog::showError(const QString &message)
{
    m_errorLabel->setText(message);
    m_errorLabel->setVisible(!message.isEmpty());
}
