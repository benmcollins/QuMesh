// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

// Loads `SessionWindow` from the QuMesh QML module against the same
// singleton table `main.cpp` registers, and configures it the way
// `MachineDetailsWindow`'s session Loader does: properties are set only
// after the window has been created.

#pragma once

#include "appinfo.h"
#include "backupcontroller.h"
#include "batchcontroller.h"
#include "certmodel.h"
#include "computermodel.h"
#include "configstore.h"
#include "filename_formatter.h"
#include "machinedetailscontroller.h"
#include "migrationcontroller.h"
#include "qml_registration.h"
#include "updater.h"
#include "wsman/local_amt_probe.h"

#include <QDir>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QVariantMap>
#include <QtTest>

#include <memory>

namespace qumesh::testing {

/// One per test process: `registerQumeshQmlTypes` registers singleton
/// instances, which can only happen once.
class SessionWindowHarness
{
public:
    SessionWindowHarness()
    {
        m_migration.setStore(&m_store);
        m_computers.setStore(&m_store);
        m_certs.setStorePath(QDir(m_certDir.path())
                                 .filePath(QStringLiteral("certificates.json")));
        m_batch.setComputerModel(&m_computers);
        m_backup.setModel(&m_computers);
        qumesh::app::registerQumeshQmlTypes({
            .updater             = &m_updater,
            .computerModel       = &m_computers,
            .localAmtProbe       = &m_probe,
            .migrationController = &m_migration,
            .certModel           = &m_certs,
            .filenameFormatter   = &m_filenames,
            .appInfo             = &m_appInfo,
            .batchController     = &m_batch,
            .backupController    = &m_backup,
        });
    }

    /// Settings `openWindow()` hands the window, in the order it does.
    struct Target
    {
        QString host = QStringLiteral("127.0.0.1");
        quint16 wsmanPort = 0;     ///< Direct WSMAN port; 0 = AMT default.
        QVariantMap sshConfig;
        /// Apply the SSH config before the host instead of after it.
        bool sshBeforeHost = false;
    };

    /// Create a window and configure it as the session Loader does.
    /// Returns null (after a warning) if the component fails to load.
    std::unique_ptr<QObject> openWindow(const Target &t)
    {
        QQmlComponent comp(&m_engine);
        comp.loadFromModule("QuMesh", "SessionWindow");
        std::unique_ptr<QObject> w(comp.create());
        if (!w) {
            qWarning().noquote() << comp.errorString();
            return {};
        }
        if (auto *c = controller(w.get()); c != nullptr && t.wsmanPort != 0)
            c->setPortForTest(t.wsmanPort);
        if (t.sshBeforeHost)
            w->setProperty("machineSshConfig", t.sshConfig);
        w->setProperty("targetHost", t.host);
        w->setProperty("user", QStringLiteral("admin"));
        w->setProperty("password", QStringLiteral("p"));
        w->setProperty("tls", false);
        if (!t.sshBeforeHost)
            w->setProperty("machineSshConfig", t.sshConfig);
        w->setProperty("label", QStringLiteral("test machine"));
        return w;
    }

    /// The window's shared consent and Power ▾ controller.
    static qumesh::app::MachineDetailsController *controller(QObject *window)
    {
        return window->findChild<qumesh::app::MachineDetailsController *>(
            QStringLiteral("powerController"));
    }

    /// What a panel's Connect button does.
    static void requestConnect(QObject *window, int tab)
    {
        QMetaObject::invokeMethod(window, "requestConnect", Q_ARG(QVariant, tab));
    }

private:
    // Its own directory, never the user's: a store left on the default
    // path would load their real machine list (and decrypt it).
    QTemporaryDir m_configDir;
    QTemporaryDir m_certDir;
    qumesh::config::ConfigStore m_store{m_configDir.path()};
    qumesh::app::MigrationController m_migration;
    qumesh::model::ComputerModel m_computers;
    qumesh::app::CertModel m_certs;
    qumesh::app::Updater m_updater;
    qumesh::wsman::LocalAmtProbe m_probe;
    qumesh::app::FilenameFormatter m_filenames;
    qumesh::app::AppInfo m_appInfo;
    qumesh::app::BatchController m_batch;
    qumesh::app::BackupController m_backup;
    QQmlEngine m_engine;
};

/// `QGuiApplication` setup shared by the SessionWindow tests. Must run
/// before the application object is constructed.
inline void prepareHeadlessQml()
{
    // Before anything resolves a QStandardPaths location.
    QStandardPaths::setTestModeEnabled(true);
    // Keep the macOS Keychain out of it: an unsigned test binary gets a
    // Keychain access prompt, and every rebuild asks again.
    qputenv("QUMESH_NO_KEYSTORE", "1");
    qputenv("QT_QPA_PLATFORM", "offscreen");
    qputenv("QT_QUICK_BACKEND", "software");
}

inline void setApplicationIdentity()
{
    // `Settings` in the QML needs these, as in main.cpp.
    QCoreApplication::setOrganizationName(QStringLiteral("Insynergy"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("insynergy.com"));
    QCoreApplication::setApplicationName(QStringLiteral("QuMesh"));
}

} // namespace qumesh::testing
