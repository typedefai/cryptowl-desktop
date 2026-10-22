#include "WelcomePage.h"

#include "RecentVaultsStore.h"
#include "VaultDirectory.h"

#include <QAbstractItemView>
#include <QAction>
#include <QColor>
#include <QDir>
#include <QFileInfo>
#include <QFont>
#include <QFrame>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QLabel>
#include <QLinearGradient>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QPen>
#include <QPoint>
#include <QPixmap>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSize>
#include <QSplitter>
#include <QStackedWidget>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

QString displayName(const QString &path)
{
    const QString name = QFileInfo(path).fileName();
    return name.isEmpty() ? QDir::toNativeSeparators(path) : name;
}

void applyDimTextColor(QWidget *widget)
{
    QPalette palette = widget->palette();
    palette.setColor(QPalette::WindowText, palette.color(QPalette::PlaceholderText));
    widget->setPalette(palette);
}

QImage renderVaultIcon(int size)
{
    QImage image(size, size, QImage::Format_ARGB32_Premultiplied);
    image.fill(Qt::transparent);

    QPainter painter(&image);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.scale(size / 64.0, size / 64.0);

    QPainterPath back;
    back.moveTo(5, 17);
    back.lineTo(25, 17);
    back.lineTo(30, 11);
    back.lineTo(53, 11);
    back.quadTo(59, 11, 59, 17);
    back.lineTo(59, 52);
    back.quadTo(59, 58, 53, 58);
    back.lineTo(11, 58);
    back.quadTo(5, 58, 5, 52);
    back.closeSubpath();

    QLinearGradient backGradient(0, 11, 0, 58);
    backGradient.setColorAt(0.0, QColor(QStringLiteral("#F6C65B")));
    backGradient.setColorAt(1.0, QColor(QStringLiteral("#C88722")));
    painter.setBrush(backGradient);
    painter.setPen(QPen(QColor(QStringLiteral("#8C5A12")), 1.2));
    painter.drawPath(back);

    QPainterPath paper;
    paper.moveTo(13, 22);
    paper.lineTo(51, 22);
    paper.lineTo(51, 48);
    paper.lineTo(13, 48);
    paper.closeSubpath();
    painter.setBrush(QColor(QStringLiteral("#FFFDF5")));
    painter.setPen(QPen(QColor(QStringLiteral("#C9BFA6")), 0.8));
    painter.drawPath(paper);

    QPainterPath front;
    front.moveTo(5, 25);
    front.quadTo(5, 20, 10, 20);
    front.lineTo(54, 20);
    front.quadTo(59, 20, 59, 25);
    front.lineTo(59, 52);
    front.quadTo(59, 58, 53, 58);
    front.lineTo(11, 58);
    front.quadTo(5, 58, 5, 52);
    front.closeSubpath();

    QLinearGradient frontGradient(0, 20, 0, 58);
    frontGradient.setColorAt(0.0, QColor(QStringLiteral("#FFE49A")));
    frontGradient.setColorAt(0.45, QColor(QStringLiteral("#FFD05C")));
    frontGradient.setColorAt(1.0, QColor(QStringLiteral("#EFA92A")));
    painter.setBrush(frontGradient);
    painter.setPen(QPen(QColor(QStringLiteral("#A66A12")), 1.2));
    painter.drawPath(front);

    QPainterPath shine;
    shine.moveTo(8, 24);
    shine.quadTo(8, 23, 12, 23);
    shine.lineTo(52, 23);
    shine.quadTo(56, 23, 56, 26);
    shine.lineTo(56, 30);
    shine.quadTo(32, 36, 8, 30);
    shine.closeSubpath();
    painter.setBrush(QColor(255, 255, 255, 105));
    painter.setPen(Qt::NoPen);
    painter.drawPath(shine);

    return image;
}

const QIcon &vaultIcon()
{
    static const QIcon icon = [] {
        QIcon result;
        for (int size : {16, 24, 32, 48, 64})
            result.addPixmap(QPixmap::fromImage(renderVaultIcon(size)));
        return result;
    }();
    return icon;
}

} // namespace

WelcomePage::WelcomePage(RecentVaultsStore *recentVaults, QWidget *parent)
    : QWidget(parent)
    , m_recentVaults(recentVaults)
{
    auto *splitter = new QSplitter(Qt::Horizontal, this);
    splitter->setChildrenCollapsible(false);
    splitter->addWidget(createVaultListPane());

    auto *detailPane = new QWidget(this);
    detailPane->setMinimumWidth(300);
    auto *detailLayout = new QVBoxLayout(detailPane);
    detailLayout->setContentsMargins(0, 0, 0, 0);

    m_detailStack = new QStackedWidget(detailPane);
    m_emptyDetailPane = createEmptyDetailPane();
    m_vaultDetailPane = createVaultDetailPane();
    m_detailStack->addWidget(m_emptyDetailPane);
    m_detailStack->addWidget(m_vaultDetailPane);
    detailLayout->addWidget(m_detailStack);

    splitter->addWidget(detailPane);
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({210, 440});

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(6, 6, 6, 6);
    layout->addWidget(splitter);

    refreshRecentVaults();
}

QWidget *WelcomePage::createVaultListPane()
{
    auto *pane = new QFrame(this);
    pane->setFrameShape(QFrame::StyledPanel);
    pane->setMinimumWidth(190);

    auto *layout = new QVBoxLayout(pane);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(4);

    auto *header = new QLabel(tr("Vaults"), pane);
    QFont headerFont = header->font();
    headerFont.setBold(true);
    header->setFont(headerFont);
    layout->addWidget(header);

    m_emptyListLabel = new QLabel(tr("No vaults yet"), pane);
    m_emptyListLabel->setAlignment(Qt::AlignCenter);
    applyDimTextColor(m_emptyListLabel);
    layout->addWidget(m_emptyListLabel, 1);

    m_vaultList = new QListWidget(pane);
    m_vaultList->setObjectName(QStringLiteral("vaultList"));
    m_vaultList->setFrameShape(QFrame::NoFrame);
    m_vaultList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_vaultList->setIconSize(QSize(32, 32));
    m_vaultList->setSpacing(2);
    m_vaultList->setUniformItemSizes(true);
    m_vaultList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_vaultList, &QListWidget::itemSelectionChanged, this,
            &WelcomePage::updateVaultDetail);
    connect(m_vaultList, &QListWidget::itemDoubleClicked, this,
            [this](QListWidgetItem *item) {
                if (item)
                    emit openVaultPathRequested(item->data(Qt::UserRole).toString());
            });
    connect(m_vaultList, &QListWidget::customContextMenuRequested, this,
            [this](const QPoint &pos) {
                QListWidgetItem *item = m_vaultList->itemAt(pos);
                if (!item)
                    return;

                QMenu menu(this);
                QAction *removeAction = menu.addAction(tr("Remove from list"));
                if (menu.exec(m_vaultList->viewport()->mapToGlobal(pos)) == removeAction) {
                    m_recentVaults->remove(item->data(Qt::UserRole).toString());
                    refreshRecentVaults();
                }
            });
    layout->addWidget(m_vaultList, 1);

    m_addVaultButton = new QToolButton(pane);
    m_addVaultButton->setObjectName(QStringLiteral("addVaultButton"));
    m_addVaultButton->setText(QStringLiteral("+"));
    m_addVaultButton->setToolTip(tr("Add vault"));
    m_addVaultButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    m_addVaultButton->setMinimumSize(28, 28);
    m_addVaultButton->setPopupMode(QToolButton::InstantPopup);

    auto *addMenu = new QMenu(m_addVaultButton);
    QAction *newAction = addMenu->addAction(tr("Create new vault…"));
    connect(newAction, &QAction::triggered, this, &WelcomePage::createVaultRequested);
    QAction *openAction = addMenu->addAction(tr("Open vault…"));
    connect(openAction, &QAction::triggered, this, &WelcomePage::openVaultRequested);
    m_addVaultButton->setMenu(addMenu);

    auto *buttonRow = new QHBoxLayout;
    buttonRow->setContentsMargins(0, 0, 0, 0);
    buttonRow->addWidget(m_addVaultButton);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    return pane;
}

QWidget *WelcomePage::createEmptyDetailPane()
{
    m_emptyDetailPane = new QWidget(this);
    m_emptyDetailPane->setMinimumWidth(300);

    auto *layout = new QVBoxLayout(m_emptyDetailPane);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(8);
    layout->addStretch();

    auto *icon = new QLabel(m_emptyDetailPane);
    icon->setPixmap(vaultIcon().pixmap(64, 64));
    icon->setAlignment(Qt::AlignCenter);
    layout->addWidget(icon, 0, Qt::AlignHCenter);

    auto *title = new QLabel(tr("CryptOwl Desktop"), m_emptyDetailPane);
    title->setObjectName(QStringLiteral("welcomeTitle"));
    QFont titleFont = title->font();
    titleFont.setPointSizeF(titleFont.pointSizeF() * 1.4);
    titleFont.setBold(true);
    title->setFont(titleFont);

    auto *subtitle = new QLabel(tr("Local-first encrypted vault"), m_emptyDetailPane);
    applyDimTextColor(subtitle);

    auto *hint = new QLabel(
        tr("Select a vault from the list, or create/open one."), m_emptyDetailPane);
    hint->setWordWrap(true);

    auto *createButton = new QPushButton(tr("Create new vault…"), m_emptyDetailPane);
    createButton->setObjectName(QStringLiteral("welcomeCreateVault"));
    connect(createButton, &QPushButton::clicked, this, &WelcomePage::createVaultRequested);

    auto *openButton = new QPushButton(tr("Open vault…"), m_emptyDetailPane);
    openButton->setObjectName(QStringLiteral("welcomeOpenVault"));
    connect(openButton, &QPushButton::clicked, this, &WelcomePage::openVaultRequested);

    auto *buttons = new QHBoxLayout;
    buttons->setContentsMargins(0, 0, 0, 0);
    buttons->setSpacing(8);
    buttons->addWidget(createButton);
    buttons->addWidget(openButton);
    buttons->addStretch();

    layout->addWidget(title);
    layout->addWidget(subtitle);
    layout->addSpacing(12);
    layout->addWidget(hint);
    layout->addSpacing(12);
    layout->addLayout(buttons);
    layout->addStretch();

    return m_emptyDetailPane;
}

QWidget *WelcomePage::createVaultDetailPane()
{
    m_vaultDetailPane = new QWidget(this);
    m_vaultDetailPane->setMinimumWidth(300);

    auto *layout = new QVBoxLayout(m_vaultDetailPane);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(8);

    auto *header = new QHBoxLayout;
    header->setContentsMargins(0, 0, 0, 0);
    header->setSpacing(10);

    auto *icon = new QLabel(m_vaultDetailPane);
    icon->setPixmap(vaultIcon().pixmap(32, 32));
    icon->setFixedSize(32, 32);

    m_vaultName = new QLabel(m_vaultDetailPane);
    m_vaultName->setObjectName(QStringLiteral("vaultName"));
    QFont nameFont = m_vaultName->font();
    nameFont.setPointSizeF(nameFont.pointSizeF() * 1.4);
    nameFont.setBold(true);
    m_vaultName->setFont(nameFont);

    m_vaultStatus = new QLabel(m_vaultDetailPane);
    m_vaultStatus->setObjectName(QStringLiteral("vaultStatus"));
    m_vaultStatus->setFrameShape(QFrame::Panel);
    m_vaultStatus->setFrameShadow(QFrame::Sunken);
    m_vaultStatus->setAlignment(Qt::AlignCenter);
    m_vaultStatus->setMargin(3);

    header->addWidget(icon, 0, Qt::AlignTop);
    header->addWidget(m_vaultName, 1, Qt::AlignTop);
    header->addWidget(m_vaultStatus, 0, Qt::AlignTop);
    layout->addLayout(header);

    m_vaultPath = new QLabel(m_vaultDetailPane);
    m_vaultPath->setObjectName(QStringLiteral("vaultPath"));
    m_vaultPath->setWordWrap(true);
    m_vaultPath->setTextInteractionFlags(Qt::TextSelectableByMouse);
    applyDimTextColor(m_vaultPath);
    layout->addWidget(m_vaultPath);

    auto *actions = new QVBoxLayout;
    actions->setContentsMargins(0, 0, 0, 0);
    actions->setSpacing(6);
    actions->addStretch();

    m_unlockButton = new QPushButton(tr("Unlock…"), m_vaultDetailPane);
    m_unlockButton->setObjectName(QStringLiteral("vaultUnlock"));
    m_unlockButton->setMinimumSize(180, 32);
    m_unlockButton->setToolTip(tr("Unlock this vault"));
    connect(m_unlockButton, &QPushButton::clicked, this, [this] {
        const QString path = currentVaultPath();
        if (!path.isEmpty())
            emit unlockVaultRequested(path);
    });

    m_lockButton = new QPushButton(tr("Lock"), m_vaultDetailPane);
    m_lockButton->setObjectName(QStringLiteral("vaultLock"));
    m_lockButton->setMinimumSize(180, 32);
    m_lockButton->setToolTip(tr("The vault is already locked"));
    connect(m_lockButton, &QPushButton::clicked, this, [this] {
        const QString path = currentVaultPath();
        if (!path.isEmpty())
            emit lockVaultRequested(path);
    });

    actions->addWidget(m_unlockButton, 0, Qt::AlignHCenter);
    actions->addWidget(m_lockButton, 0, Qt::AlignHCenter);
    actions->addStretch();
    layout->addLayout(actions, 1);

    m_removeButton = new QPushButton(tr("Remove from list"), m_vaultDetailPane);
    m_removeButton->setObjectName(QStringLiteral("vaultRemove"));
    connect(m_removeButton, &QPushButton::clicked, this, &WelcomePage::removeSelectedVault);

    auto *footer = new QHBoxLayout;
    footer->setContentsMargins(0, 0, 0, 0);
    footer->addWidget(m_removeButton);
    footer->addStretch();
    layout->addLayout(footer);

    return m_vaultDetailPane;
}

void WelcomePage::refreshRecentVaults()
{
    const QString previousPath = currentVaultPath();
    const QStringList paths = m_recentVaults->paths();

    {
        QSignalBlocker blocker(m_vaultList);
        m_vaultList->clear();

        for (const QString &path : paths) {
            if (!isVaultDirectory(path))
                continue;

            auto *item = new QListWidgetItem(displayName(path), m_vaultList);
            item->setData(Qt::UserRole, path);
            item->setToolTip(QDir::toNativeSeparators(path));
            item->setIcon(vaultIcon());
            item->setSizeHint(QSize(0, 56));
        }

        const bool hasVaults = m_vaultList->count() > 0;
        m_vaultList->setVisible(hasVaults);
        m_emptyListLabel->setVisible(!hasVaults);

        if (hasVaults) {
            int row = 0;
            for (int i = 0; i < m_vaultList->count(); ++i) {
                if (m_vaultList->item(i)->data(Qt::UserRole).toString() == previousPath) {
                    row = i;
                    break;
                }
            }
            m_vaultList->setCurrentRow(row);
        }
    }

    updateVaultDetail();
}

void WelcomePage::selectMostRecentVault()
{
    if (m_vaultList->count() > 0)
        m_vaultList->setCurrentRow(0);
}

QString WelcomePage::currentVaultPath() const
{
    const QListWidgetItem *item = m_vaultList->currentItem();
    return item ? item->data(Qt::UserRole).toString() : QString();
}

void WelcomePage::updateVaultDetail()
{
    const QString path = currentVaultPath();
    if (path.isEmpty()) {
        m_detailStack->setCurrentWidget(m_emptyDetailPane);
        return;
    }

    m_vaultName->setText(displayName(path));
    m_vaultPath->setText(QDir::toNativeSeparators(path));
    m_vaultPath->setToolTip(QDir::toNativeSeparators(path));
    m_vaultStatus->setText(tr("Locked"));
    m_unlockButton->setEnabled(true);
    m_lockButton->setEnabled(false);
    m_detailStack->setCurrentWidget(m_vaultDetailPane);
}

void WelcomePage::removeSelectedVault()
{
    const QString path = currentVaultPath();
    if (path.isEmpty())
        return;

    m_recentVaults->remove(path);
    refreshRecentVaults();
}
