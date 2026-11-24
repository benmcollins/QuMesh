// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "appinfo.h"
#include "backupcontroller.h"
#include "batchcontroller.h"
#include "certmodel.h"
#include "computermodel.h"
#include "configstore.h"
#include "filename_formatter.h"
#include "migrationcontroller.h"
#include "qml_registration.h"
#include "updater.h"
#include "wsman/local_amt_probe.h"

#include <QDir>
#include <QGuiApplication>
#include <QMutex>
#include <QMutexLocker>
#include <QObject>
#include <QQmlApplicationEngine>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QStandardPaths>
#include <QString>
#include <QStringList>
#include <QTemporaryDir>
#include <QtTest>

#include <atomic>

namespace {

// Captured-warning sink driven by qInstallMessageHandler. Static so the
// raw C callback can reach it. The test thread is the only writer (no
// concurrent QML loading), so a plain QStringList behind a mutex is
// fine.
struct WarningSink
{
    QMutex mutex;
    QStringList messages;
};

WarningSink &warningSink()
{
    static WarningSink s;
    return s;
}

void captureMessage(QtMsgType type, const QMessageLogContext &ctx,
                    const QString &msg)
{
    // Only treat the three escalating levels as failures. Qt's debug /
    // info logs are routinely emitted by the engine on offscreen
    // (font fallback, layout chatter) and aren't bug signals.
    if (type != QtWarningMsg && type != QtCriticalMsg && type != QtFatalMsg)
        return;

    // Allow-list: regexes that match known-OK warnings the offscreen
    // QPA / Qt's own QML modules emit even on a clean run. Add entries
    // only when CI surfaces them, and document why each one is benign.
    static const QList<QRegularExpression> kAllowList{
        // Qt 6 emits a one-shot informational warning the first time
        // QFontDatabase resolves an alias to a missing family ("Sans
        // Serif"). The offscreen platform ships no system fonts, so
        // this fires regardless of what our QML asks for. Not a bug
        // signal from #251's perspective — drop it.
        QRegularExpression(QStringLiteral(
            "Populating font family aliases took.*\"Sans Serif\"")),
        // Linux/Windows CI runners install Qt from apt or
        // install-qt-action and don't always ship the SVG image
        // plugin (libqsvg). QImageReader rejects our baked branding
        // SVGs with "Unsupported image format" — environmental, not
        // a QML wiring bug. Smoke-test scope is engine load + type
        // resolution, not image-codec coverage.
        QRegularExpression(QStringLiteral(
            "Error decoding: qrc:/icons/.*\\.svg: Unsupported image format")),
        // Windows + offscreen QPA looks for fonts at
        // `<prefix>/lib/fonts/` at QGuiApplication construction. When
        // we run from the build tree (not an installed Qt), the dir
        // doesn't exist and QFontDatabase logs a one-shot warning.
        // Doesn't affect anything the smoke test cares about. See #262.
        QRegularExpression(QStringLiteral(
            "QFontDatabase: Cannot find font directory")),
    };

    for (const auto &re : kAllowList) {
        if (re.match(msg).hasMatch())
            return;
    }

    QString where;
    if (ctx.file)
        where = QStringLiteral("%1:%2 ").arg(ctx.file).arg(ctx.line);
    auto &sink = warningSink();
    QMutexLocker lock(&sink.mutex);
    sink.messages.append(where + msg);
}

} // namespace

class TestQmlEngineLoads : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void mainQmlLoadsWithoutWarnings();
};

void TestQmlEngineLoads::initTestCase()
{
    // Make AppDataLocation point at a sandboxed sub-tree so the
    // CertModel's `<configDir>/certificates.json` lookup in main() (and
    // any QStandardPaths the QML touches at construction time) can't
    // see or write the real user's QuMesh data.
    QStandardPaths::setTestModeEnabled(true);
}

void TestQmlEngineLoads::mainQmlLoadsWithoutWarnings()
{
    // Install the capture handler before constructing the engine so we
    // catch parse / type-resolution / property-assignment messages from
    // `engine.loadFromModule` itself.
    QtMessageHandler previous = qInstallMessageHandler(&captureMessage);
    auto restore = qScopeGuard([previous]{
        qInstallMessageHandler(previous);
    });

    // Mirror `main.cpp`'s singleton wiring exactly. If main grows new
    // singletons, the `QmlSingletonContext` struct gets a new field and
    // this list updates in lock-step — no copy-paste table to drift.
    qumesh::config::ConfigStore configStore;

    qumesh::app::MigrationController migrationController;
    migrationController.setStore(&configStore);
    // Don't call checkAndMaybeMigrate(): it would scan the legacy
    // localStorage on disk, which is exactly the kind of side effect
    // setTestModeEnabled is here to neutralise.

    qumesh::model::ComputerModel computerModel;
    computerModel.setStore(&configStore);

    qumesh::app::CertModel certModel;
    QTemporaryDir certDir;
    QVERIFY(certDir.isValid());
    certModel.setStorePath(QDir(certDir.path())
                           .filePath(QStringLiteral("certificates.json")));

    qumesh::app::Updater updater; // stub linked into this test target
    qumesh::wsman::LocalAmtProbe localAmtProbe; // not started — would open sockets
    qumesh::app::FilenameFormatter filenameFormatter;
    qumesh::app::AppInfo appInfo;
    qumesh::app::BatchController batchController;
    batchController.setComputerModel(&computerModel);

    qumesh::app::BackupController backupController;
    backupController.setModel(&computerModel);

    qumesh::app::registerQumeshQmlTypes({
        .updater              = &updater,
        .computerModel        = &computerModel,
        .localAmtProbe        = &localAmtProbe,
        .migrationController  = &migrationController,
        .certModel            = &certModel,
        .filenameFormatter    = &filenameFormatter,
        .appInfo              = &appInfo,
        .batchController      = &batchController,
        .backupController     = &backupController,
    });

    std::atomic<bool> creationFailed{false};
    QQmlApplicationEngine engine;
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
                     this, [&creationFailed](const QUrl &url) {
        creationFailed.store(true);
        qWarning() << "objectCreationFailed:" << url;
    });

    engine.loadFromModule("QuMesh", "Main");
    QCoreApplication::processEvents();

    auto dumpSink = [&]() -> QString {
        auto &sink = warningSink();
        QMutexLocker lock(&sink.mutex);
        if (sink.messages.isEmpty())
            return QStringLiteral("(no QtMsg output captured)");
        return QStringLiteral("Captured QtMsg output:\n  ")
            + sink.messages.join(QStringLiteral("\n  "));
    };
    QVERIFY2(!creationFailed.load(), qPrintable(dumpSink()));
    QCOMPARE(engine.rootObjects().size(), 1);

    // `MachineDetailsWindow` is reachable only through a Loader with
    // `active: false` at startup (see `Main.qml`), so the up-front load
    // pass above doesn't construct it. Force the Loader active so the
    // smoke test exercises Icon, Section, the cert/wireless/CIRA edit
    // dialogs, and everything else the per-machine window pulls in —
    // which is where the implicitHeight regression behind #251 lived.
    QObject *root = engine.rootObjects().first();
    QObject *loader = root->findChild<QObject*>(QStringLiteral("detailsLoader"));
    QVERIFY2(loader,
             "Main.qml is expected to expose its per-machine details "
             "Loader as `objectName: \"detailsLoader\"`. If the loader "
             "was renamed or removed, update this test to drive whatever "
             "replaces it — otherwise the smoke can no longer catch "
             "MachineDetailsWindow regressions.");
    // The production Loader uses `asynchronous: true` for UI snap, but
    // that turns instantiation into an incremental main-thread job. Flip
    // it sync for the test so a single processEvents drives the load to
    // completion, instead of polling on Loader.status with a timeout.
    loader->setProperty("asynchronous", false);
    loader->setProperty("active", true);
    QCoreApplication::processEvents();
    // QML Loader status: Null=0, Ready=1, Loading=2, Error=3.
    const int loaderStatus = loader->property("status").toInt();
    QVERIFY2(loaderStatus == 1,
             qPrintable(QStringLiteral(
                 "detailsLoader.status expected Ready (1), got %1. %2")
                 .arg(loaderStatus)
                 .arg(dumpSink())));
    QVERIFY2(!creationFailed.load(), qPrintable(dumpSink()));

    // Same trick for the Setup.bin editor window: it's only constructed
    // when the title-bar button is clicked, so the up-front pass doesn't
    // exercise its delegate Components or controller bindings. Force it.
    QObject *setupBinLoader =
        root->findChild<QObject*>(QStringLiteral("setupBinLoader"));
    QVERIFY2(setupBinLoader,
             "Main.qml is expected to expose its Setup.bin editor Loader "
             "as `objectName: \"setupBinLoader\"`. If the loader was "
             "renamed or removed, update this test to drive whatever "
             "replaces it — otherwise the smoke can no longer catch "
             "SetupBinWindow regressions.");
    setupBinLoader->setProperty("asynchronous", false);
    setupBinLoader->setProperty("active", true);
    QCoreApplication::processEvents();
    const int setupBinStatus = setupBinLoader->property("status").toInt();
    QVERIFY2(setupBinStatus == 1,
             qPrintable(QStringLiteral(
                 "setupBinLoader.status expected Ready (1), got %1. %2")
                 .arg(setupBinStatus)
                 .arg(dumpSink())));
    QVERIFY2(!creationFailed.load(), qPrintable(dumpSink()));

    auto &sink = warningSink();
    QStringList captured;
    {
        QMutexLocker lock(&sink.mutex);
        captured = sink.messages;
    }
    if (!captured.isEmpty()) {
        QFAIL(qPrintable(QStringLiteral(
            "Loading Main.qml produced %1 warning(s):\n  %2")
            .arg(captured.size())
            .arg(captured.join(QStringLiteral("\n  ")))));
    }
}

int main(int argc, char *argv[])
{
    // Run headless on every platform regardless of whether the CI lane
    // sets QT_QPA_PLATFORM itself. Must happen before QGuiApplication.
    qputenv("QT_QPA_PLATFORM", "offscreen");
    // No Keychain prompt for an unsigned test binary on macOS.
    qputenv("QUMESH_NO_KEYSTORE", "1");
    // 2D software renderer keeps Qt Quick off any GPU / hardware
    // surface — sometimes needed under offscreen, and never harmful
    // for a load-only smoke test.
    qputenv("QT_QUICK_BACKEND", "software");
    QGuiApplication app(argc, argv);
    // Mirror main.cpp's QCoreApplication setup. Without these the QML
    // `Settings { category: "theme" }` in Main.qml fails to initialise
    // its underlying QSettings ("Failed to initialize QSettings
    // instance. Status code is: 1" + "organizationName /
    // organizationDomain not set") and the smoke captures that as a
    // failure.
    QCoreApplication::setOrganizationName(QStringLiteral("Insynergy"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("insynergy.com"));
    QCoreApplication::setApplicationName(QStringLiteral("QuMesh"));
    TestQmlEngineLoads tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_qml_engine_loads.moc"
