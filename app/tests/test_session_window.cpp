// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

// SessionWindow's consent wiring, driven through the real QML against
// a scripted AMT endpoint. The window is configured after creation,
// exactly as `MachineDetailsWindow`'s session Loader does it, which is
// what hid #459: `Component.onCompleted` saw none of the properties.

#include "fake_amt.h"
#include "session_window_harness.h"

#include <QGuiApplication>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QWindow>
#include <QtTest>

using qumesh::app::MachineDetailsController;
using qumesh::testing::FakeAmt;
using qumesh::testing::SessionWindowHarness;
using qumesh::testing::settle;
using qumesh::testing::waitFor;

namespace {

/// An SSH "server" that accepts and hangs up at once, so the tunnel
/// fails straight away. A closed port won't do: Windows retries a
/// refused localhost connect for several seconds.
class HangUpServer : public QTcpServer
{
public:
    HangUpServer()
    {
        connect(this, &QTcpServer::newConnection, this, [this] {
            while (QTcpSocket *s = nextPendingConnection()) {
                s->close();
                s->deleteLater();
            }
        });
    }
    bool start() { return listen(QHostAddress::LocalHost); }
};

QObject *optInPrompt(QObject *window)
{
    return window->findChild<QObject *>(QStringLiteral("optInPrompt"));
}

bool promptOpen(QObject *window)
{
    QObject *p = optInPrompt(window);
    return p != nullptr && p->property("opened").toBool();
}

/// Start a consent round for the KVM tab and wait for the code dialog.
bool openConsentDialog(QObject *window, const FakeAmt &amt)
{
    SessionWindowHarness::requestConnect(window, 1);
    return waitFor(5000, [&] {
        return amt.countOf(QStringLiteral("StartOptIn")) == 1 && promptOpen(window);
    });
}

QVariantMap sshTo(quint16 port)
{
    return {
        { QStringLiteral("enabled"), true },
        { QStringLiteral("host"), QStringLiteral("127.0.0.1") },
        { QStringLiteral("port"), port },
        { QStringLiteral("user"), QStringLiteral("tunnel") },
        { QStringLiteral("authMode"), 0 },
        { QStringLiteral("password"), QStringLiteral("x") },
    };
}

} // namespace

class TestSessionWindow : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();
    // #459
    void consentIsReadDirectlyWithoutSsh();
    void sshConfigSetAfterCreationKeepsConsentOffTheDirectPath();
    void failedTunnelStillResolvesConnect();
    // #460
    void connectAfterSessionEndedAsksAgain();
    void failedRereadDropsConnect();
    void unreadableFirmwareConnectsEveryTime();
    // #461
    void escapeCancelsConsentRound();
    void noFirmwareTimeoutKeepsDialogOpen();
    void grantedCodeClosesDialogWithoutCancel();

private:
    std::unique_ptr<SessionWindowHarness> m_harness;
};

void TestSessionWindow::initTestCase()
{
    m_harness = std::make_unique<SessionWindowHarness>();
}

void TestSessionWindow::cleanupTestCase()
{
    m_harness.reset();
}

// Baseline: with no tunnel configured the consent read goes straight
// to AMT, and a machine that needs no consent is let through.
void TestSessionWindow::consentIsReadDirectlyWithoutSsh()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 0;

    auto w = m_harness->openWindow({ .wsmanPort = amt.port() });
    QVERIFY(w);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY(waitFor(5000, [&] { return released.count() == 1; }));
    QCOMPARE(released.first().at(0).toInt(), 1);
    QVERIFY2(amt.countOf(QStringLiteral("GetOptInService")) >= 1,
             qPrintable(amt.calls.join(QStringLiteral(", "))));
}

// #459: the Loader sets `machineSshConfig` after creation. The consent
// controller must still pick it up, so nothing reaches AMT except
// through the tunnel. Before the fix the read went straight to AMT.
void TestSessionWindow::sshConfigSetAfterCreationKeepsConsentOffTheDirectPath()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 0;
    HangUpServer ssh;
    QVERIFY(ssh.start());

    auto w = m_harness->openWindow({ .wsmanPort = amt.port(),
                                     .sshConfig = sshTo(ssh.serverPort()) });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY(waitFor(5000, [&] { return !c->sshTunnelStatus().isEmpty(); }));
    QVERIFY(waitFor(8000, [&] { return released.count() == 1; }));
    settle(300);
    QVERIFY2(amt.calls.isEmpty(),
             qPrintable(QStringLiteral("WSMAN bypassed the tunnel: %1")
                            .arg(amt.calls.join(QStringLiteral(", ")))));
}

// #459: a consent read deferred until the tunnel is up must not be
// dropped when the tunnel fails, or Connect silently does nothing.
void TestSessionWindow::failedTunnelStillResolvesConnect()
{
    HangUpServer ssh;
    QVERIFY(ssh.start());
    auto w = m_harness->openWindow({ .sshConfig = sshTo(ssh.serverPort()) });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    SessionWindowHarness::requestConnect(w.get(), 0);
    QVERIFY2(waitFor(8000, [&] { return c->optInStatusKnown(); }),
             qPrintable(QStringLiteral("consent status never resolved; tunnel: %1")
                            .arg(c->sshTunnelStatus())));
    QVERIFY(c->sshTunnelStatus().startsWith(QStringLiteral("SSH failed")));
    QVERIFY(waitFor(2000, [&] { return released.count() == 1; }));
}

// #460: AMT drops consent when the session it was granted for ends.
// The window still holds Received(3) from the last round, so a second
// Connect must ask the firmware, not dial on the cached state.
void TestSessionWindow::connectAfterSessionEndedAsksAgain()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 1; // KVM only

    auto w = m_harness->openWindow({ .wsmanPort = amt.port() });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    QSignalSpy started(c, &MachineDetailsController::optInStarted);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY(waitFor(5000, [&] { return started.count() == 1; }));
    c->sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&] { return released.count() == 1; }));
    QCOMPARE(c->optInState(), 3);

    amt.optInState = 0; // the session ended; the firmware dropped consent
    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY2(waitFor(5000, [&] { return started.count() == 2; }),
             qPrintable(amt.calls.join(QStringLiteral(", "))));
    QCOMPARE(released.count(), 1);
    QCOMPARE(amt.countOf(QStringLiteral("StartOptIn")), 2);
}

// #460: if the re-read fails, the cached state is no basis for a
// connect. The window drops the Connect instead of dialling.
void TestSessionWindow::failedRereadDropsConnect()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 0;

    auto w = m_harness->openWindow({ .wsmanPort = amt.port() });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));
    QSignalSpy readFailed(c, &MachineDetailsController::optInStatusReadFailed);

    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY(waitFor(5000, [&] { return released.count() == 1; }));

    amt.stopListening();
    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY(waitFor(5000, [&] { return readFailed.count() == 1; }));
    settle(200);
    QCOMPARE(released.count(), 1);
    QCOMPARE(w->property("pendingConnectTab").toInt(), -1);
}

// #460 review: on firmware without IPS_OptInService every read fails.
// The first one falls back to "consent not required"; the later ones
// must keep doing so, not count as a failed re-read of a known status.
void TestSessionWindow::unreadableFirmwareConnectsEveryTime()
{
    // Accepts and hangs up without replying, like an absent class.
    QTcpServer dead;
    QVERIFY(dead.listen(QHostAddress::LocalHost));
    QObject::connect(&dead, &QTcpServer::newConnection, &dead, [&dead] {
        while (QTcpSocket *s = dead.nextPendingConnection()) {
            s->close();
            s->deleteLater();
        }
    });

    auto w = m_harness->openWindow({ .wsmanPort = dead.serverPort() });
    QVERIFY(w);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));
    for (int i = 1; i <= 3; ++i) {
        SessionWindowHarness::requestConnect(w.get(), 0);
        QVERIFY2(waitFor(15000, [&] { return released.count() == i; }),
                 qPrintable(QStringLiteral("Connect %1 was not released").arg(i)));
    }
}

// #461: Escape dismisses the dialog. That is the operator giving up,
// so the round must be cancelled and the waiting Connect dropped, not
// left running with the code still on the target's screen.
void TestSessionWindow::escapeCancelsConsentRound()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 1;
    auto w = m_harness->openWindow({ .wsmanPort = amt.port() });
    QVERIFY(w);
    auto *win = qobject_cast<QWindow *>(w.get());
    QVERIFY(win);
    win->show();
    win->requestActivate();
    QVERIFY(QTest::qWaitForWindowExposed(win));
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);

    QVERIFY2(openConsentDialog(w.get(), amt), qPrintable(amt.calls.join(QStringLiteral(", "))));
    QTest::keyClick(win, Qt::Key_Escape);
    QVERIFY(waitFor(2000, [&] { return !promptOpen(w.get()); }));
    QVERIFY2(waitFor(5000, [&] { return amt.countOf(QStringLiteral("CancelOptIn")) == 1; }),
             qPrintable(amt.calls.join(QStringLiteral(", "))));
    QCOMPARE(w->property("pendingConnectTab").toInt(), -1);
    QVERIFY(!c->optInRoundActive());
    settle(300);
    QCOMPARE(amt.countOf(QStringLiteral("CancelOptIn")), 1);
}

// #461: firmware that sets no OptInPolicyTimeout reports 0. The dialog
// has nothing to count down and must not cancel itself after a second.
void TestSessionWindow::noFirmwareTimeoutKeepsDialogOpen()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 1;
    amt.optInPolicyTimeout = 0;
    auto w = m_harness->openWindow({ .wsmanPort = amt.port() });
    QVERIFY(w);

    QVERIFY2(openConsentDialog(w.get(), amt), qPrintable(amt.calls.join(QStringLiteral(", "))));
    settle(2500);
    QVERIFY(promptOpen(w.get()));
    QCOMPARE(amt.countOf(QStringLiteral("CancelOptIn")), 0);
    QCOMPARE(w->property("pendingConnectTab").toInt(), 1);
}

// #461: the window closes the dialog itself once the code is accepted.
// That close must not read as the operator cancelling, which would
// revoke the consent just granted.
void TestSessionWindow::grantedCodeClosesDialogWithoutCancel()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 1;
    auto w = m_harness->openWindow({ .wsmanPort = amt.port() });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    QVERIFY2(openConsentDialog(w.get(), amt), qPrintable(amt.calls.join(QStringLiteral(", "))));
    c->sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&] { return released.count() == 1; }));
    QVERIFY(waitFor(2000, [&] { return !promptOpen(w.get()); }));
    settle(300);
    QCOMPARE(amt.countOf(QStringLiteral("CancelOptIn")), 0);
    QCOMPARE(amt.optInState, 3);
}

int main(int argc, char *argv[])
{
    qumesh::testing::prepareHeadlessQml();
    QGuiApplication app(argc, argv);
    qumesh::testing::setApplicationIdentity();
    TestSessionWindow tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_session_window.moc"
