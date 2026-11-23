// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "kvmcontroller.h"
#include "kvmframebuffer.h"

#include <QDataStream>
#include <QGuiApplication>
#include <QHostAddress>
#include <QImage>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QtTest>

using qumesh::app::KvmController;
using qumesh::app::KvmFramebuffer;
using qumesh::kvm::buildSetPixelFormat;
using qumesh::kvm::PixelFormat;

namespace {

// SetPixelFormat 20 + SetEncodings 16 + KvmExtCmd 21 + FBUR 10.
constexpr int kKvmSetupBytes = 67;

QByteArray redirFrame(quint8 status, quint8 authType, const QByteArray &body)
{
    QByteArray b;
    b.append(char(0x14));
    b.append(char(status));
    b.append(2, '\0');
    b.append(char(authType));
    const quint32 n = static_cast<quint32>(body.size());
    for (int shift = 0; shift < 32; shift += 8) b.append(char((n >> shift) & 0xFF));
    b.append(body);
    return b;
}

QByteArray serverInit1080p()
{
    QByteArray b;
    QDataStream out(&b, QIODevice::WriteOnly);
    out << quint16(1920) << quint16(1080);
    out.writeRawData(QByteArray(16, '\0').constData(), 16);
    out << quint32(3);
    out.writeRawData("AMT", 3);
    return b;
}

/// Walks one redirection login and RFB handshake per connection, then
/// records everything the client writes in `wire`.
class MockAmtKvmServer : public QObject
{
    Q_OBJECT
public:
    MockAmtKvmServer()
    {
        connect(&m_server, &QTcpServer::newConnection, this, [this]() {
            QTcpSocket *socket = m_server.nextPendingConnection();
            m_socket = socket;
            m_inbox.clear();
            m_stage = Stage::Redirection;
            m_challenged = false;
            wire.clear();
            connect(socket, &QTcpSocket::readyRead, this, [this, socket]() {
                if (socket != m_socket) return;
                m_inbox.append(socket->readAll());
                while (step()) {}
            });
        });
    }

    bool listen() { return m_server.listen(QHostAddress::LocalHost); }
    [[nodiscard]] quint16 port() const { return m_server.serverPort(); }

    QByteArray wire;

private:
    enum class Stage { Redirection, Version, SecurityChoice, ClientInit, FrameLoop };

    bool take(int n)
    {
        if (m_inbox.size() < n) return false;
        m_inbox.remove(0, n);
        return true;
    }

    bool stepRedirection()
    {
        if (m_inbox.isEmpty()) return false;
        const quint8 tag = static_cast<quint8>(m_inbox.at(0));
        if (tag == 0x10) {
            if (!take(8)) return false;
            QByteArray reply(13, '\0');
            reply[0] = 0x11;
            m_socket->write(reply);
            return true;
        }
        if (tag == 0x13) {
            if (m_inbox.size() < 9) return false;
            const int len = static_cast<quint8>(m_inbox.at(5))
                          | static_cast<quint8>(m_inbox.at(6)) << 8
                          | static_cast<quint8>(m_inbox.at(7)) << 16
                          | static_cast<quint8>(m_inbox.at(8)) << 24;
            if (m_inbox.size() < 9 + len) return false;
            const quint8 authType = static_cast<quint8>(m_inbox.at(4));
            m_inbox.remove(0, 9 + len);
            if (authType == 0) {
                m_socket->write(redirFrame(0, 0, QByteArray(1, char(4))));
            } else if (!m_challenged) {
                QByteArray body;
                for (const QByteArray &field : { QByteArray("Digest:Intel(R) AMT"),
                                                 QByteArray("nnn"), QByteArray("auth") }) {
                    body.append(char(field.size()));
                    body.append(field);
                }
                m_socket->write(redirFrame(1, 4, body));
                m_challenged = true;
            } else {
                m_socket->write(redirFrame(0, 4, {}));
            }
            return true;
        }
        if (tag == 0x40) {
            if (!take(8)) return false;
            QByteArray reply(8, '\0');
            reply[0] = 0x41;
            m_socket->write(reply);
            m_socket->write("RFB 003.008\n");
            m_stage = Stage::Version;
            return true;
        }
        return false;
    }

    bool step()
    {
        switch (m_stage) {
        case Stage::Redirection:
            return stepRedirection();
        case Stage::Version:
            if (!take(12)) return false;
            m_socket->write(QByteArray::fromHex("0101"));
            m_stage = Stage::SecurityChoice;
            return true;
        case Stage::SecurityChoice:
            if (!take(1)) return false;
            m_socket->write(QByteArray(4, '\0'));
            m_stage = Stage::ClientInit;
            return true;
        case Stage::ClientInit:
            if (!take(1)) return false;
            m_socket->write(serverInit1080p());
            m_stage = Stage::FrameLoop;
            return true;
        case Stage::FrameLoop:
            wire.append(m_inbox);
            m_inbox.clear();
            return false;
        }
        return false;
    }

    QTcpServer m_server;
    QTcpSocket *m_socket = nullptr;
    QByteArray m_inbox;
    Stage m_stage = Stage::Redirection;
    bool m_challenged = false;
};

void configure(KvmController &c, const MockAmtKvmServer &server)
{
    c.setHost(QStringLiteral("127.0.0.1"));
    c.setUser(QStringLiteral("admin"));
    c.setPassword(QStringLiteral("p"));
    c.setPortForTest(server.port());
}

bool waitForSetup(const KvmController &c, const MockAmtKvmServer &server)
{
    return QTest::qWaitFor([&]() {
        return c.state() == KvmController::State::Connected
            && server.wire.size() >= kKvmSetupBytes;
    }, 5000);
}

} // namespace

class TestKvmController : public QObject
{
    Q_OBJECT

private slots:
    void saveScreenshot_emptyFramebuffer_returnsFalse();
    void saveScreenshot_emptyPath_returnsFalse();
    void saveScreenshot_writesPngMatchingFramebuffer();
    // #452 — a colour change during a session applies on reconnect.
    void colorDepthChange_whileConnected_appliesOnReconnect();
    void colorDepthPending_clearsWhenSessionEnds();
};

void TestKvmController::saveScreenshot_emptyFramebuffer_returnsFalse()
{
    KvmController c;
    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath("empty.png");
    QVERIFY(!c.saveScreenshot(path));
    QVERIFY(!QFileInfo::exists(path));
}

void TestKvmController::saveScreenshot_emptyPath_returnsFalse()
{
    KvmController c;
    c.framebuffer()->resize(16, 16);
    QVERIFY(!c.saveScreenshot(QString()));
}

void TestKvmController::saveScreenshot_writesPngMatchingFramebuffer()
{
    KvmController c;
    KvmFramebuffer *fb = c.framebuffer();
    fb->resize(32, 16);

    // Paint a recognisable solid-red tile so we can verify roundtrip.
    QImage tile(32, 16, QImage::Format_ARGB32);
    tile.fill(QColor(220, 32, 64));
    fb->applyTile(0, 0, tile);

    QTemporaryDir dir;
    QVERIFY(dir.isValid());
    const QString path = dir.filePath("shot.png");
    QVERIFY(c.saveScreenshot(path));
    QVERIFY(QFileInfo(path).size() > 0);

    QImage loaded(path);
    QVERIFY(!loaded.isNull());
    QCOMPARE(loaded.width(), 32);
    QCOMPARE(loaded.height(), 16);
    // QImage::pixel returns ARGB; the saved PNG round-trip should
    // preserve the exact RGB we painted in.
    QCOMPARE(QColor(loaded.pixel(0, 0)).red(),   220);
    QCOMPARE(QColor(loaded.pixel(0, 0)).green(),  32);
    QCOMPARE(QColor(loaded.pixel(0, 0)).blue(),   64);
    QCOMPARE(QColor(loaded.pixel(31, 15)).red(), 220);
}

void TestKvmController::colorDepthChange_whileConnected_appliesOnReconnect()
{
    MockAmtKvmServer server;
    QVERIFY(server.listen());

    KvmController c;
    configure(c, server);
    c.open();
    QVERIFY(waitForSetup(c, server));
    QVERIFY(server.wire.startsWith(buildSetPixelFormat(PixelFormat::Rgb565)));
    QVERIFY(!c.colorDepthPending());

    server.wire.clear();
    QSignalSpy depthSpy(&c, &KvmController::colorDepthChanged);
    c.setColorDepthMode(2);
    QCOMPARE(depthSpy.size(), 1);
    QVERIFY(c.colorDepthPending());
    QVERIFY(!c.eightBitColor());
    QTest::qWait(100);
    QVERIFY2(server.wire.isEmpty(), "a mid-session colour change must not reach the wire");

    c.setColorDepthMode(0);
    QVERIFY(!c.colorDepthPending());
    c.setColorDepthMode(2);
    QVERIFY(c.colorDepthPending());

    c.open();
    QVERIFY(!c.colorDepthPending());
    QVERIFY(waitForSetup(c, server));
    QVERIFY(server.wire.startsWith(buildSetPixelFormat(PixelFormat::Rgb332)));
    QTRY_VERIFY(c.eightBitColor());
    QVERIFY(!c.colorDepthPending());
}

void TestKvmController::colorDepthPending_clearsWhenSessionEnds()
{
    MockAmtKvmServer server;
    QVERIFY(server.listen());

    KvmController c;
    configure(c, server);
    c.open();
    QVERIFY(waitForSetup(c, server));
    c.setColorDepthMode(1);
    QVERIFY(c.colorDepthPending());

    // QML binds through this NOTIFY, so leaving Connected has to emit it.
    QSignalSpy depthSpy(&c, &KvmController::colorDepthChanged);
    c.close();
    QCOMPARE(c.state(), KvmController::State::Disconnected);
    QVERIFY(!c.colorDepthPending());
    QCOMPARE(depthSpy.size(), 1);
}

QTEST_MAIN(TestKvmController)
#include "test_kvmcontroller.moc"
