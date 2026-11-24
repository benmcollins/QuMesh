// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

// End-to-end check that SessionWindow's consent round really runs
// through the machine's SSH tunnel (#459). An in-process libssh server
// accepts the tunnel, records where each `direct-tcpip` channel asks to
// go, and forwards WSMAN channels to FakeAmt.
//
// POSIX-only, for the same reason as `ssh/tests/test_ssh_tunnel_shutdown`:
// vcpkg's libssh server path hangs the client's auth step on Windows.

#include "fake_amt.h"
#include "session_window_harness.h"

#include <QGuiApplication>
#include <QMutex>
#include <QMutexLocker>
#include <QSignalSpy>
#include <QtTest>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <vector>

using qumesh::app::MachineDetailsController;
using qumesh::testing::FakeAmt;
using qumesh::testing::SessionWindowHarness;
using qumesh::testing::waitFor;

namespace {

constexpr int kAmtWsmanPort = 16992;
const QString kAmtHost = QStringLiteral("amt.example.invalid");

QByteArray generateHostKeyPem()
{
    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    Q_ASSERT(pkey != nullptr);
    BIO *kb = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(kb, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char *kp = nullptr;
    const long kn = BIO_get_mem_data(kb, &kp);
    QByteArray pem(kp, static_cast<int>(kn));
    BIO_free(kb);
    EVP_PKEY_free(pkey);
    return pem;
}

/// SSH server that accepts any password, records the destination of
/// every `direct-tcpip` channel, and forwards channels for the AMT
/// WSMAN port to a local TCP port. Other channels are refused. Each
/// client session gets its own thread: the window's controller and its
/// three panels all open sessions, and the panels' sessions stay parked
/// at the host-key prompt nobody answers.
class ForwardingSshServer
{
public:
    explicit ForwardingSshServer(quint16 forwardTo)
        : m_forwardTo(forwardTo), m_bind(ssh_bind_new())
    {
        m_hostKeyPem = generateHostKeyPem();
        const char *addr = "127.0.0.1";
        const int port = 0;
        const int verbosity = SSH_LOG_NOLOG;
        ssh_bind_options_set(m_bind, SSH_BIND_OPTIONS_BINDADDR, addr);
        ssh_bind_options_set(m_bind, SSH_BIND_OPTIONS_BINDPORT, &port);
        ssh_bind_options_set(m_bind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
        ssh_bind_options_set(m_bind, SSH_BIND_OPTIONS_IMPORT_KEY_STR,
                             m_hostKeyPem.constData());
    }

    ~ForwardingSshServer()
    {
        m_stop.store(true);
        {
            // Unblock sessions still waiting on a client that never
            // finished its handshake.
            QMutexLocker lock(&m_mutex);
            for (int fd : m_sessionFds) ::shutdown(fd, SHUT_RDWR);
        }
        if (m_acceptThread.joinable()) m_acceptThread.join();
        for (std::thread &t : m_sessionThreads)
            if (t.joinable()) t.join();
        ssh_bind_free(m_bind);
    }

    bool listen()
    {
        if (ssh_bind_listen(m_bind) != SSH_OK) return false;
        sockaddr_in sa{};
        socklen_t len = sizeof(sa);
        if (::getsockname(ssh_bind_get_fd(m_bind),
                          reinterpret_cast<sockaddr *>(&sa), &len) != 0)
            return false;
        m_port = ntohs(sa.sin_port);
        m_acceptThread = std::thread([this] { acceptLoop(); });
        return true;
    }
    [[nodiscard]] quint16 port() const { return m_port; }

    /// "host:port" of every channel a client asked for, in order.
    [[nodiscard]] QStringList destinations() const
    {
        QMutexLocker lock(&m_mutex);
        return m_destinations;
    }
    [[nodiscard]] QStringList wsmanDestinations() const
    {
        QStringList out;
        const QString suffix = QStringLiteral(":%1").arg(kAmtWsmanPort);
        for (const QString &d : destinations())
            if (d.endsWith(suffix)) out << d;
        return out;
    }

private:
    void acceptLoop()
    {
        const int listenFd = ssh_bind_get_fd(m_bind);
        while (!m_stop.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd, &rfds);
            timeval tv{0, 50 * 1000};
            const int sr = ::select(listenFd + 1, &rfds, nullptr, nullptr, &tv);
            if (sr < 0) break;
            if (sr == 0) continue;
            ssh_session sess = ssh_new();
            if (sess == nullptr) continue;
            if (ssh_bind_accept(m_bind, sess) != SSH_OK) {
                ssh_free(sess);
                continue;
            }
            {
                QMutexLocker lock(&m_mutex);
                m_sessionFds.push_back(ssh_get_fd(sess));
            }
            m_sessionThreads.emplace_back([this, sess] {
                handleSession(sess);
                {
                    QMutexLocker lock(&m_mutex);
                    m_sessionFds.erase(std::remove(m_sessionFds.begin(),
                                                   m_sessionFds.end(),
                                                   ssh_get_fd(sess)),
                                       m_sessionFds.end());
                }
                ssh_disconnect(sess);
                ssh_free(sess);
            });
        }
    }

    void handleSession(ssh_session sess)
    {
        if (ssh_handle_key_exchange(sess) != SSH_OK) return;
        ssh_set_auth_methods(sess, SSH_AUTH_METHOD_PASSWORD);
        while (!m_stop.load()) {
            ssh_message msg = ssh_message_get(sess);
            if (msg == nullptr) return;
            const int type = ssh_message_type(msg);
            if (type == SSH_REQUEST_AUTH) {
                ssh_message_auth_reply_success(msg, /*partial=*/0);
                ssh_message_free(msg);
                continue;
            }
            if (type == SSH_REQUEST_CHANNEL_OPEN
                && ssh_message_subtype(msg) == SSH_CHANNEL_DIRECT_TCPIP) {
                const QString host = QString::fromUtf8(
                    ssh_message_channel_request_open_destination(msg));
                const int port = ssh_message_channel_request_open_destination_port(msg);
                {
                    QMutexLocker lock(&m_mutex);
                    m_destinations << QStringLiteral("%1:%2").arg(host).arg(port);
                }
                if (port == kAmtWsmanPort) {
                    ssh_channel chan = ssh_message_channel_request_open_reply_accept(msg);
                    ssh_message_free(msg);
                    if (chan == nullptr) return;
                    forward(chan);
                    continue;
                }
            }
            ssh_message_reply_default(msg);
            ssh_message_free(msg);
        }
    }

    /// Pump one channel to and from the forwarding target until the
    /// target closes its side (FakeAmt answers `Connection: close`).
    void forward(ssh_channel chan)
    {
        const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(m_forwardTo);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (sock < 0 || ::connect(sock, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0) {
            if (sock >= 0) ::close(sock);
            ssh_channel_close(chan);
            ssh_channel_free(chan);
            return;
        }
        ::fcntl(sock, F_SETFL, ::fcntl(sock, F_GETFL) | O_NONBLOCK);

        char buf[8192];
        bool clientEof = false;
        while (!m_stop.load()) {
            bool idle = true;
            const int n = ssh_channel_read_nonblocking(chan, buf, sizeof(buf), 0);
            if (n == SSH_ERROR) break;
            if (n > 0) {
                idle = false;
                for (int sent = 0; sent < n;) {
                    const ssize_t w = ::send(sock, buf + sent, size_t(n - sent), 0);
                    if (w > 0) sent += int(w);
                    else if (errno == EAGAIN || errno == EWOULDBLOCK) ::usleep(1000);
                    else break;
                }
            }
            if (!clientEof && ssh_channel_is_eof(chan)) {
                clientEof = true;
                ::shutdown(sock, SHUT_WR);
            }
            const ssize_t r = ::recv(sock, buf, sizeof(buf), 0);
            if (r > 0) {
                idle = false;
                ssh_channel_write(chan, buf, uint32_t(r));
            } else if (r == 0) {
                ssh_channel_send_eof(chan);
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }
            if (idle) ::usleep(2000);
        }
        ::close(sock);
        ssh_channel_close(chan);
        ssh_channel_free(chan);
    }

    quint16 m_forwardTo;
    ssh_bind m_bind;
    QByteArray m_hostKeyPem;
    quint16 m_port = 0;
    std::atomic<bool> m_stop{false};
    std::thread m_acceptThread;
    std::vector<std::thread> m_sessionThreads; ///< Touched by the accept thread only until join.
    mutable QMutex m_mutex;
    std::vector<int> m_sessionFds;
    QStringList m_destinations;
};

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

/// Answer the controller's SSH host-key prompt, as the operator would.
void trustHostKeyWhenAsked(MachineDetailsController *c)
{
    QObject::connect(c, &MachineDetailsController::sshHostKeyPromptRequired, c,
                     [c](const QString &, const QString &) {
                         c->trustPendingSshHostKey(false);
                     });
}

QString describe(const FakeAmt &amt, const ForwardingSshServer &ssh,
                 const MachineDetailsController *c)
{
    return QStringLiteral("AMT calls: [%1]; channels: [%2]; tunnel: %3")
        .arg(amt.calls.join(QStringLiteral(", ")),
             ssh.destinations().join(QStringLiteral(", ")),
             c->sshTunnelStatus());
}

} // namespace

class TestSessionWindowSsh : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void cleanupTestCase();
    void consentRoundRunsThroughTunnel();
    void sshConfigBeforeHostStillTunnelsToHost();
    void cancelledHostKeyPromptStillResolvesConnect();

private:
    std::unique_ptr<SessionWindowHarness> m_harness;
};

void TestSessionWindowSsh::initTestCase()
{
    m_harness = std::make_unique<SessionWindowHarness>();
}

void TestSessionWindowSsh::cleanupTestCase()
{
    m_harness.reset();
}

// The whole round: status read, StartOptIn, the operator's code, and
// the panel being let through, all over the tunnel to the window's host.
void TestSessionWindowSsh::consentRoundRunsThroughTunnel()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 1; // KVM only
    ForwardingSshServer ssh(amt.port());
    QVERIFY(ssh.listen());

    auto w = m_harness->openWindow({ .host = kAmtHost, .sshConfig = sshTo(ssh.port()) });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    trustHostKeyWhenAsked(c);
    QSignalSpy started(c, &MachineDetailsController::optInStarted);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    SessionWindowHarness::requestConnect(w.get(), 1);
    QVERIFY2(waitFor(15000, [&] { return started.count() == 1; }),
             qPrintable(describe(amt, ssh, c)));
    QVERIFY(started.first().at(0).toBool());

    c->sendOptInCode(123456);
    QVERIFY2(waitFor(10000, [&] { return released.count() == 1; }),
             qPrintable(describe(amt, ssh, c)));
    QCOMPARE(released.first().at(0).toInt(), 1);

    QCOMPARE(amt.countOf(QStringLiteral("StartOptIn")), 1);
    QCOMPARE(amt.countOf(QStringLiteral("SendOptInCode")), 1);
    const QStringList wsman = ssh.wsmanDestinations();
    QVERIFY2(wsman.size() >= amt.calls.size(), qPrintable(describe(amt, ssh, c)));
    for (const QString &d : wsman)
        QCOMPARE(d, QStringLiteral("%1:%2").arg(kAmtHost).arg(kAmtWsmanPort));
}

// The tunnel's target must follow the window's host even when the SSH
// config arrives first: before the fix it was fixed at whatever the host
// was when the config was applied, here still empty.
void TestSessionWindowSsh::sshConfigBeforeHostStillTunnelsToHost()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 0;
    ForwardingSshServer ssh(amt.port());
    QVERIFY(ssh.listen());

    auto w = m_harness->openWindow({ .host = kAmtHost,
                                     .sshConfig = sshTo(ssh.port()),
                                     .sshBeforeHost = true });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    trustHostKeyWhenAsked(c);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    SessionWindowHarness::requestConnect(w.get(), 0);
    QVERIFY2(waitFor(15000, [&] { return released.count() == 1; }),
             qPrintable(describe(amt, ssh, c)));
    QVERIFY2(amt.countOf(QStringLiteral("GetOptInService")) >= 1,
             qPrintable(describe(amt, ssh, c)));
    const QStringList wsman = ssh.wsmanDestinations();
    QVERIFY(!wsman.isEmpty());
    for (const QString &d : wsman)
        QCOMPARE(d, QStringLiteral("%1:%2").arg(kAmtHost).arg(kAmtWsmanPort));
}

// Cancelling the host-key prompt turns SSH off for this window
// (SshHostKeyTrustDialog's onCancelled). A Connect already waiting on
// the tunnel must then go ahead the way any later one would, not wait
// for a tunnel that no longer exists.
void TestSessionWindowSsh::cancelledHostKeyPromptStillResolvesConnect()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    amt.optInRequired = 0;
    ForwardingSshServer ssh(amt.port());
    QVERIFY(ssh.listen());

    auto w = m_harness->openWindow({ .wsmanPort = amt.port(),
                                     .sshConfig = sshTo(ssh.port()) });
    QVERIFY(w);
    MachineDetailsController *c = SessionWindowHarness::controller(w.get());
    QVERIFY(c);
    QSignalSpy released(w.get(), SIGNAL(connectReleased(int)));

    // Connect while the tunnel is still coming up, so the read waits.
    SessionWindowHarness::requestConnect(w.get(), 0);
    QVERIFY2(waitFor(15000, [&] { return c->awaitingSshHostKeyTrust(); }),
             qPrintable(describe(amt, ssh, c)));
    QVERIFY(amt.calls.isEmpty());

    c->setSshConfig({}); // what the dialog's Cancel does
    QVERIFY2(waitFor(5000, [&] { return released.count() == 1; }),
             qPrintable(describe(amt, ssh, c)));
    QVERIFY(amt.countOf(QStringLiteral("GetOptInService")) >= 1);

    // And a later Connect isn't parked either.
    SessionWindowHarness::requestConnect(w.get(), 0);
    QVERIFY2(waitFor(5000, [&] { return released.count() == 2; }),
             qPrintable(describe(amt, ssh, c)));
}

int main(int argc, char *argv[])
{
    qumesh::testing::prepareHeadlessQml();
    QGuiApplication app(argc, argv);
    qumesh::testing::setApplicationIdentity();
    TestSessionWindowSsh tc;
    return QTest::qExec(&tc, argc, argv);
}

#include "test_session_window_ssh.moc"
