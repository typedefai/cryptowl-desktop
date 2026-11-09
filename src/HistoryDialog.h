#pragma once

#include "vault/ItemRepository.h"

#include <QDialog>
#include <QString>

#include <functional>
#include <vector>

class QPushButton;
class QTreeWidget;

class HistoryDialog : public QDialog
{
    Q_OBJECT

public:
    using VersionLoader = std::function<bool(int seq, QString *payload,
                                            QString *error)>;
    using CurrentLoader = std::function<bool(QString *payload, QString *error)>;
    using RestoreAction = std::function<bool(int seq, QString *error)>;

    HistoryDialog(const QString &itemTitle, const QString &currentTier,
                  std::vector<cryptowl::vault::ItemVersionSummary> versions,
                  VersionLoader versionLoader, CurrentLoader currentLoader,
                  RestoreAction restoreAction, bool jsonPayload,
                  QWidget *parent = nullptr);

private slots:
    void compareSelected();
    void restoreSelected();
    void updateButtons();

private:
    const cryptowl::vault::ItemVersionSummary *selectedVersion() const;

    QString m_itemTitle;
    QString m_currentTier;
    std::vector<cryptowl::vault::ItemVersionSummary> m_versions;
    VersionLoader m_versionLoader;
    CurrentLoader m_currentLoader;
    RestoreAction m_restoreAction;
    bool m_jsonPayload = false;
    QTreeWidget *m_tree = nullptr;
    QPushButton *m_diffButton = nullptr;
    QPushButton *m_restoreButton = nullptr;
};
