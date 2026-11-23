// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "kvm/kvm_codec.h"
#include "kvm/kvm_session.h"
#include "redir/redir_client.h"
#include "redir/redir_codec.h"

#include <QElapsedTimer>
#include <QHostAddress>
#include <QScopeGuard>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtTest>

using namespace qumesh::kvm;
using qumesh::redir::RedirectionClient;

namespace {

template <typename Pred>
bool waitFor(int ms, Pred p)
{
    QElapsedTimer t;
    t.start();
    while (!p()) {
        if (t.elapsed() > ms) return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
    }
    return true;
}

QByteArray be16(quint16 v)
{
    QByteArray b(2, '\0');
    b[0] = static_cast<char>((v >> 8) & 0xFF);
    b[1] = static_cast<char>(v & 0xFF);
    return b;
}

QByteArray be32(quint32 v)
{
    QByteArray b(4, '\0');
    b[0] = static_cast<char>((v >> 24) & 0xFF);
    b[1] = static_cast<char>((v >> 16) & 0xFF);
    b[2] = static_cast<char>((v >> 8) & 0xFF);
    b[3] = static_cast<char>(v & 0xFF);
    return b;
}

QByteArray le16(quint16 v)
{
    QByteArray b(2, '\0');
    b[0] = static_cast<char>(v & 0xFF);
    b[1] = static_cast<char>((v >> 8) & 0xFF);
    return b;
}

QByteArray frame14(quint8 status, quint8 authType, const QByteArray &body)
{
    QByteArray b;
    b.append(char(0x14));
    b.append(char(status));
    b.append(char(0x00));
    b.append(char(0x00));
    b.append(char(authType));
    const quint32 n = static_cast<quint32>(body.size());
    b.append(char(n & 0xFF));
    b.append(char((n >> 8) & 0xFF));
    b.append(char((n >> 16) & 0xFF));
    b.append(char((n >> 24) & 0xFF));
    b.append(body);
    return b;
}

/// Mock that walks the redirection auth, then plays a scripted KVM
/// session: ProtocolVersion → security types → security result →
/// ServerInit → one FramebufferUpdate with a single RAW rect.
class MockServer : public QObject
{
    Q_OBJECT
public:
    MockServer() : m_server(new QTcpServer(this))
    {
        connect(m_server, &QTcpServer::newConnection, this, [this]() {
            m_socket = m_server->nextPendingConnection();
            connect(m_socket, &QTcpSocket::readyRead, this, [this]() {
                handleData();
            });
        });
    }
    bool listen() { return m_server->listen(QHostAddress::LocalHost); }
    quint16 port() const { return m_server->serverPort(); }

    /// Override the 12-byte ProtocolVersion banner the mock pushes
    /// after auth completes. Lets the CSME 21 regression test (#176)
    /// emulate a server announcing RFB 4.0 / 5.0 — the client must
    /// still reply with 3.8.
    void setBanner(const QByteArray &banner) { m_banner = banner; }

    QByteArray received; // bytes received after auth completes
    QPointer<QTcpSocket> m_socket;
    QByteArray m_banner = QByteArrayLiteral("RFB 003.008\n");

private:
    void handleData()
    {
        if (!m_socket) return;
        m_inbox.append(m_socket->readAll());

        for (;;) {
            if (m_inbox.isEmpty()) return;
            const quint8 tag = static_cast<unsigned char>(m_inbox.at(0));

            if (m_kvmActive) {
                received.append(m_inbox);
                m_inbox.clear();
                return;
            }

            if (tag == 0x10) {
                if (m_inbox.size() < 8) return;
                m_inbox.remove(0, 8);
                QByteArray reply(13, '\0');
                reply[0] = 0x11;
                m_socket->write(reply);
            } else if (tag == 0x13) {
                if (m_inbox.size() < 9) return;
                const int len = static_cast<unsigned char>(m_inbox.at(5))
                              | static_cast<unsigned char>(m_inbox.at(6)) << 8
                              | static_cast<unsigned char>(m_inbox.at(7)) << 16
                              | static_cast<unsigned char>(m_inbox.at(8)) << 24;
                if (m_inbox.size() < 9 + len) return;
                const quint8 authType = static_cast<unsigned char>(m_inbox.at(4));
                m_inbox.remove(0, 9 + len);

                if (authType == 0) {
                    QByteArray caps; caps.append(char(4));
                    m_socket->write(frame14(0, 0, caps));
                } else if (m_authStage == 0) {
                    QByteArray body;
                    const QByteArray realm = "Digest:Intel(R) AMT";
                    const QByteArray nonce = "nnn";
                    const QByteArray qop = "auth";
                    body.append(char(realm.size())); body.append(realm);
                    body.append(char(nonce.size())); body.append(nonce);
                    body.append(char(qop.size())); body.append(qop);
                    m_socket->write(frame14(1, 4, body));
                    m_authStage = 1;
                } else {
                    m_socket->write(frame14(0, 4, {}));
                    // Auth complete — now expect the client's 8-byte
                    // 0x40 KVM-start frame, then reply with 0x41 + the
                    // RFB banner. Without that round-trip the firmware
                    // never pushes RFB bytes.
                    m_awaitingKvmStart = true;
                }
            } else if (m_awaitingKvmStart && tag == 0x40) {
                if (m_inbox.size() < 8) return;
                m_inbox.remove(0, 8);
                m_awaitingKvmStart = false;
                m_kvmActive = true;
                QByteArray reply(8, '\0');
                reply[0] = 0x41;
                m_socket->write(reply);
                m_socket->write(m_banner);
            } else {
                received.append(m_inbox);
                m_inbox.clear();
                return;
            }
        }
    }

    QByteArray m_inbox;
    int m_authStage = 0;
    bool m_awaitingKvmStart = false;
    bool m_kvmActive = false;
    QTcpServer *m_server;
};

QByteArray makeServerInit(quint16 w, quint16 h, const QByteArray &name)
{
    QByteArray b;
    b.append(be16(w));
    b.append(be16(h));
    b.append(QByteArray(16, '\0'));   // pixel format
    b.append(be32(static_cast<quint32>(name.size())));
    b.append(name);
    return b;
}

QByteArray makeRawRectUpdate(quint16 x, quint16 y, quint16 w, quint16 h,
                              quint16 color)
{
    QByteArray b;
    b.append(char(MsgFramebufferUpdate));
    b.append(char(0x00));
    b.append(be16(1));            // one rect
    b.append(be16(x));
    b.append(be16(y));
    b.append(be16(w));
    b.append(be16(h));
    b.append(be32(static_cast<quint32>(EncRaw)));
    for (int i = 0; i < w * h; ++i) b.append(le16(color));
    return b;
}

QByteArray makeDesktopSizeUpdate(quint16 w, quint16 h)
{
    QByteArray b;
    b.append(char(MsgFramebufferUpdate));
    b.append(char(0x00));
    b.append(be16(1));
    b.append(be16(0));
    b.append(be16(0));
    b.append(be16(w));
    b.append(be16(h));
    b.append(be32(static_cast<quint32>(EncDesktopSize)));
    return b;
}

} // namespace

class TestKvmSession : public QObject
{
    Q_OBJECT
private slots:
    void handshakeThroughFrameLoopWithRawTile();
    void clientPinsRfb38EvenWhenServerOffers40();
    void kvmExtCmdEnabledByDefault();
    void kvmExtCmdDisabledViaKillSwitch();
    // #433 — AMT's KVM display-buffer ceiling drives the pixel format.
    void fourKDesktopNegotiatesEightBitColour();
    void ordinaryDesktopKeepsSixteenBitColour();
    void oversizedDesktopFailsWithActionableError();
    void sameSizeDesktopSizeDoesNotResendPixelFormat();
    void changedDesktopSizeRenegotiatesPixelFormat();
    void desktopResizeReselectsPixelFormat_data();
    void desktopResizeReselectsPixelFormat();
};

void TestKvmSession::handshakeThroughFrameLoopWithRawTile()
{
    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    QSignalSpy resizedSpy(&session, &KvmSession::desktopResized);
    QSignalSpy tileSpy(&session, &KvmSession::tileUpdated);

    QObject::connect(&client, &RedirectionClient::authenticated,
                     &session, &KvmSession::start);
    client.connectTo(QStringLiteral("127.0.0.1"), server.port());

    QVERIFY(waitFor(5000, [&]() {
        return client.state() == RedirectionClient::State::Authenticated;
    }));

    // The session should now be at Version, waiting for the banner. The
    // mock pushed it on auth completion — wait until the session has
    // written "RFB 003.008\n" back.
    QVERIFY(waitFor(2000, [&]() { return server.received.startsWith("RFB 003.008\n"); }));
    server.received.clear();

    // Send security types: count=1 + None(1).
    QByteArray sec(2, '\0');
    sec[0] = 0x01;
    sec[1] = 0x01;
    server.m_socket->write(sec);

    // Wait for the security choice (1 byte = 0x01).
    QVERIFY(waitFor(2000, [&]() {
        return server.received.size() >= 1
            && static_cast<unsigned char>(server.received.at(0)) == 0x01;
    }));
    server.received.clear();

    // Security result = 0 (success).
    server.m_socket->write(be32(0));

    // Wait for ClientInit (1 byte = 0x01).
    QVERIFY(waitFor(2000, [&]() {
        return server.received.size() >= 1
            && static_cast<unsigned char>(server.received.at(0)) == 0x01;
    }));
    server.received.clear();

    // ServerInit: 320x240 desktop named "AMT".
    server.m_socket->write(makeServerInit(320, 240, "AMT"));

    QVERIFY(waitFor(2000, [&]() { return resizedSpy.count() == 1; }));
    QCOMPARE(resizedSpy.first().at(0).toInt(), 320);
    QCOMPARE(resizedSpy.first().at(1).toInt(), 240);

    // Wait for SetPixelFormat (20 bytes) + SetEncodings (14+ bytes) to
    // arrive. SetPixelFormat goes first to pin the format before any
    // framebuffer traffic. A 320x240 desktop is far inside AMT's
    // display-buffer ceiling, so the automatic choice is RGB565.
    QVERIFY(waitFor(2000, [&]() { return server.received.size() >= 34; }));
    QCOMPARE(static_cast<unsigned char>(server.received.at(0)), quint8(MsgSetPixelFormat));
    QCOMPARE(server.received.mid(0, 20), buildSetPixelFormat(PixelFormat::Rgb565));
    QCOMPARE(static_cast<unsigned char>(server.received.at(20)), quint8(MsgSetEncodings));

    // Send a single 4x4 red rect.
    server.m_socket->write(makeRawRectUpdate(0, 0, 4, 4, 0xF800));

    QVERIFY(waitFor(2000, [&]() { return tileSpy.count() == 1; }));
    const auto args = tileSpy.first();
    QCOMPARE(args.at(0).toInt(), 0);
    QCOMPARE(args.at(1).toInt(), 0);
    const QImage img = args.at(2).value<QImage>();
    QCOMPARE(img.width(), 4);
    QCOMPARE(img.height(), 4);
    QCOMPARE(img.pixel(2, 2), QRgb(0xFFF80000));
}

void TestKvmSession::clientPinsRfb38EvenWhenServerOffers40()
{
    // CSME 21 regression guard (issue #176). Pre-CSME-21 AMT firmware
    // tends to advertise the highest RFB version it speaks; CSME 21
    // strips 4.0 from that menu. To guard against any future change
    // that adapts the client to whatever the server announces, drive
    // the mock with "RFB 004.000\n" and assert the client still
    // writes back "RFB 003.008\n". The session-level test is the
    // load-bearing one — buildVersionResponse() is stateless and
    // takes no input, so it can't directly exercise this.
    MockServer server;
    server.setBanner(QByteArrayLiteral("RFB 004.000\n"));
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    QObject::connect(&client, &RedirectionClient::authenticated,
                     &session, &KvmSession::start);
    client.connectTo(QStringLiteral("127.0.0.1"), server.port());

    QVERIFY(waitFor(5000, [&]() {
        return client.state() == RedirectionClient::State::Authenticated;
    }));
    QVERIFY(waitFor(2000, [&]() {
        return server.received.startsWith("RFB 003.008\n");
    }));
}

namespace {

/// Drive the redir → KVM handshake through ServerInit and return the
/// bytes the client sent immediately afterwards (SetPixelFormat +
/// SetEncodings + KvmExtCmd + FramebufferUpdateRequest = 67 bytes).
/// Exposed for the compression-toggle tests below so they can inspect
/// the KvmExtCmd payload without duplicating the handshake walk.
QByteArray driveHandshakeAndCaptureSetup(MockServer &server,
                                          RedirectionClient &client,
                                          KvmSession &session,
                                          quint16 w = 320, quint16 h = 240,
                                          int expectBytes = 67)
{
    QObject::connect(&client, &RedirectionClient::authenticated,
                     &session, &KvmSession::start);
    client.connectTo(QStringLiteral("127.0.0.1"), server.port());

    if (!waitFor(5000, [&]() {
            return client.state() == RedirectionClient::State::Authenticated;
        })) return {};

    if (!waitFor(2000, [&]() { return server.received.startsWith("RFB 003.008\n"); }))
        return {};
    server.received.clear();

    QByteArray sec(2, '\0');
    sec[0] = 0x01;
    sec[1] = 0x01;
    server.m_socket->write(sec);

    if (!waitFor(2000, [&]() { return server.received.size() >= 1; })) return {};
    server.received.clear();

    server.m_socket->write(be32(0));

    if (!waitFor(2000, [&]() { return server.received.size() >= 1; })) return {};
    server.received.clear();

    server.m_socket->write(makeServerInit(w, h, "AMT"));

    // SetPixelFormat 20 + SetEncodings 16 + KvmExtCmd 21 + FBUR 10 = 67.
    if (!waitFor(2000, [&]() { return server.received.size() >= expectBytes; }))
        return server.received;
    return server.received;
}

} // namespace

void TestKvmSession::kvmExtCmdEnabledByDefault()
{
    // QUMESH_KVM_COMPRESSION unset — the session must enable
    // compression: KvmExtCmd(4, 1) on the wire.
    qunsetenv("QUMESH_KVM_COMPRESSION");

    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    const QByteArray sent = driveHandshakeAndCaptureSetup(server, client, session);
    QVERIFY(!sent.isEmpty());

    QVERIFY2(sent.contains(buildKvmExtCmd(4, 1)),
              "KvmExtCmd(4, 1) not found on wire");
    QVERIFY2(!sent.contains(buildKvmExtCmd(4, 0)),
              "KvmExtCmd(4, 0) unexpectedly present");
}

void TestKvmSession::kvmExtCmdDisabledViaKillSwitch()
{
    // QUMESH_KVM_COMPRESSION=0 is the documented kill switch — must
    // suppress compression and emit (4, 0) instead. Restore on exit
    // so other tests in the suite see a clean environment.
    qputenv("QUMESH_KVM_COMPRESSION", "0");
    auto cleanup = qScopeGuard([]() { qunsetenv("QUMESH_KVM_COMPRESSION"); });

    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    const QByteArray sent = driveHandshakeAndCaptureSetup(server, client, session);
    QVERIFY(!sent.isEmpty());

    QVERIFY2(sent.contains(buildKvmExtCmd(4, 0)),
              "KvmExtCmd(4, 0) not found on wire");
    QVERIFY2(!sent.contains(buildKvmExtCmd(4, 1)),
              "KvmExtCmd(4, 1) unexpectedly present");
}


// --- #433 ------------------------------------------------------------
//
// AMT allocates its KVM display buffer as bytes-per-pixel x w x h and
// hangs up — with no protocol-level error — when that exceeds
// 9,216,000. A 4K desktop is 1.8x over at 16-bit, which is why the
// reporter's session died the moment consent let the RFB handshake
// reach SetPixelFormat.

void TestKvmSession::fourKDesktopNegotiatesEightBitColour()
{
    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    QSignalSpy formatSpy(&session, &KvmSession::pixelFormatChanged);

    const QByteArray sent =
        driveHandshakeAndCaptureSetup(server, client, session, 3840, 2160);
    QVERIFY(!sent.isEmpty());

    QVERIFY2(sent.startsWith(buildSetPixelFormat(PixelFormat::Rgb332)),
              "4K desktop must negotiate 8-bit RGB332");
    QVERIFY2(!sent.contains(buildSetPixelFormat(PixelFormat::Rgb565)),
              "16-bit SetPixelFormat must not be sent for a 4K desktop");
    QCOMPARE(session.pixelFormat(), PixelFormat::Rgb332);
    QCOMPARE(formatSpy.count(), 1);
    QCOMPARE(session.state(), KvmSession::State::FrameLoop);
}

void TestKvmSession::ordinaryDesktopKeepsSixteenBitColour()
{
    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    const QByteArray sent =
        driveHandshakeAndCaptureSetup(server, client, session, 1920, 1080);
    QVERIFY(!sent.isEmpty());

    QVERIFY2(sent.startsWith(buildSetPixelFormat(PixelFormat::Rgb565)),
              "1080p must keep 16-bit RGB565");
    QCOMPARE(session.pixelFormat(), PixelFormat::Rgb565);
}

void TestKvmSession::oversizedDesktopFailsWithActionableError()
{
    // Forcing 16-bit on a 4K desktop is exactly the #433 configuration.
    // We must refuse it up front with a message naming the limit rather
    // than writing SetPixelFormat and letting AMT drop the socket — the
    // firmware's silence is what made this look like a network fault.
    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    session.setPreferredPixelFormat(PixelFormat::Rgb565);
    QSignalSpy closedSpy(&session, &KvmSession::closed);

    const QByteArray sent =
        driveHandshakeAndCaptureSetup(server, client, session, 3840, 2160,
                                       /*expectBytes=*/1);
    QVERIFY(waitFor(2000, [&]() { return closedSpy.count() == 1; }));
    QCOMPARE(session.state(), KvmSession::State::Failed);

    const QString reason = session.lastError();
    QVERIFY2(reason.contains(QStringLiteral("3840")), qPrintable(reason));
    QVERIFY2(reason.contains(QStringLiteral("display")), qPrintable(reason));
    QVERIFY2(!sent.contains(buildSetPixelFormat(PixelFormat::Rgb565)),
              "must not ask AMT for a buffer it cannot allocate");
}

// Some AMT firmwares (seen on a Lenovo ThinkCentre M70q) answer every
// SetPixelFormat with a DesktopSize rect carrying the unchanged size.
// Replying with another SetPixelFormat loops forever and the viewer
// stays blank while input keeps working.

void TestKvmSession::sameSizeDesktopSizeDoesNotResendPixelFormat()
{
    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    QVERIFY(!driveHandshakeAndCaptureSetup(server, client, session).isEmpty());
    QCOMPARE(session.state(), KvmSession::State::FrameLoop);
    server.received.clear();

    server.m_socket->write(makeDesktopSizeUpdate(320, 240));

    QVERIFY(waitFor(2000, [&]() { return server.received.size() >= 10; }));
    QTest::qWait(100);
    QCOMPARE(server.received,
             buildFramebufferUpdateRequest(false, 0, 0, 320, 240));
}

void TestKvmSession::changedDesktopSizeRenegotiatesPixelFormat()
{
    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    QSignalSpy resizedSpy(&session, &KvmSession::desktopResized);
    QVERIFY(!driveHandshakeAndCaptureSetup(server, client, session).isEmpty());
    server.received.clear();

    server.m_socket->write(makeDesktopSizeUpdate(640, 480));

    QVERIFY(waitFor(2000, [&]() { return server.received.size() >= 30; }));
    QCOMPARE(server.received,
             buildSetPixelFormat(PixelFormat::Rgb565)
                 + buildFramebufferUpdateRequest(false, 0, 0, 640, 480));
    QCOMPARE(resizedSpy.last().at(0).toInt(), 640);
    QCOMPARE(resizedSpy.last().at(1).toInt(), 480);
}

// A resize must pick the format again for the new size, not re-send the
// current one: 3840x2160 at 16-bit needs 16,588,800 bytes against AMT's
// 9,216,000-byte limit, and the firmware hangs up (#433). The width-only
// and height-only rows guard the size comparison in each dimension.

void TestKvmSession::desktopResizeReselectsPixelFormat_data()
{
    QTest::addColumn<int>("fromW");
    QTest::addColumn<int>("fromH");

    QTest::newRow("both dimensions") << 320 << 240;
    QTest::newRow("height only") << 3840 << 1080;
    QTest::newRow("width only") << 1920 << 2160;
}

void TestKvmSession::desktopResizeReselectsPixelFormat()
{
    QFETCH(int, fromW);
    QFETCH(int, fromH);

    MockServer server;
    QVERIFY(server.listen());

    RedirectionClient client;
    client.setProtocol(qumesh::redir::Protocol::Kvm);
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));

    KvmSession session(&client);
    QVERIFY(!driveHandshakeAndCaptureSetup(server, client, session, fromW, fromH)
                 .isEmpty());
    QCOMPARE(session.pixelFormat(), PixelFormat::Rgb565);
    server.received.clear();

    server.m_socket->write(makeDesktopSizeUpdate(3840, 2160));

    const QByteArray expected = buildSetPixelFormat(PixelFormat::Rgb332)
        + buildFramebufferUpdateRequest(false, 0, 0, 3840, 2160);
    QVERIFY(waitFor(2000, [&]() { return server.received.size() >= expected.size(); }));
    QCOMPARE(server.received, expected);
    QCOMPARE(session.pixelFormat(), PixelFormat::Rgb332);
}

QTEST_MAIN(TestKvmSession)
#include "test_kvm_session.moc"
