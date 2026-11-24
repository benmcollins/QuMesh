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
#include <QtTest>

using qumesh::app::MachineDetailsController;
using qumesh::testing::FakeAmt;
using qumesh::testing::SessionWindowHarness;
using qumesh::testing::settle;
using qumesh::testing::waitFor;

namespace {

/// A local port with nothing listening on it.
quint16 deadPort()
{
    QTcpServer s;
    if (!s.listen(QHostAddress::LocalHost)) return 0;
    const quint16 port = s.serverPort();
    s.close();
    return port;
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

    auto w = m_harness->openWindow({ .wsmanPort = amt.port(),
                                     .sshConfig = sshTo(deadPort()) });
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
    auto w = m_harness->openWindow({ .sshConfig = sshTo(deadPort()) });
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

int main(int argc, char *argv[])
{
    qumesh::testing::prepareHeadlessQml();
    QGuiApplication app(argc, argv);
    qumesh::testing::setApplicationIdentity();
    TestSessionWindow tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_session_window.moc"
