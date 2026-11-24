// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

// Scripted WS-Management endpoint shared by the consent tests. Speaks
// just enough of IPS_OptInService and IPS_KVMRedirectionSettingData to
// drive a user-consent round, and can hold individual replies so a
// test can force a particular reply order.

#pragma once

#include <QByteArray>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QHash>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QStringList>
#include <QTcpServer>
#include <QTcpSocket>

#include <algorithm>
#include <functional>
#include <utility>

namespace qumesh::testing {

/// Minimal WS-Management endpoint. Answers `IPS_OptInService` GETs from
/// a caller-controlled `optInState` and records every invoked method so
/// the tests can assert on the call sequence.
class FakeAmt : public QObject
{
    Q_OBJECT
public:
    int optInState = 0;        ///< 0 NotStarted .. 4 InSession
    /// Raw `OptInRequired`: 0 = none, 1 = KVM only, 4294967295 = all.
    quint32 optInRequired = 1;
    quint32 sendCodeReturnValue = 0;
    quint32 startOptInReturnValue = 0;
    quint32 cancelReturnValue = 0;
    int startOptInState = 2;   ///< Where an accepted StartOptIn lands.
    QStringList calls;         ///< method names, in order

    ~FakeAmt() override
    {
        // m_buffers dies before m_server, whose child sockets emit
        // disconnected as they are destroyed.
        const auto sockets = m_server.findChildren<QTcpSocket *>();
        for (QTcpSocket *sock : sockets) sock->disconnect(this);
    }

    bool listen()
    {
        connect(&m_server, &QTcpServer::newConnection, this, &FakeAmt::onConnection);
        return m_server.listen(QHostAddress::LocalHost);
    }
    [[nodiscard]] quint16 port() const { return m_server.serverPort(); }

    [[nodiscard]] int countOf(const QString &method) const
    {
        return static_cast<int>(std::count(calls.cbegin(), calls.cend(), method));
    }

    /// Withhold the reply to the next `IPS_OptInService` read, reporting
    /// `staleState` when it is released: a read the firmware answered
    /// before a consent operation changed its state.
    void holdNextStatusRead(int staleState)
    {
        m_holdNextStatusRead = true;
        m_staleState = staleState;
    }
    /// Apply the next call to `method` but withhold its reply.
    void holdNextReplyTo(const QByteArray &method) { m_holdMethod = method; }
    [[nodiscard]] int heldReplies() const { return static_cast<int>(m_held.size()); }
    [[nodiscard]] bool holdingReply() const { return !m_held.isEmpty(); }
    /// Release a held reply, the oldest by default.
    void releaseHeldReply(int index = 0)
    {
        if (index >= m_held.size()) return;
        const Held held = m_held.takeAt(index);
        if (held.socket.isNull()) return;
        held.socket->write(held.reply);
        held.socket->flush();
        held.socket->disconnectFromHost();
    }

private slots:
    void onConnection()
    {
        while (QTcpSocket *sock = m_server.nextPendingConnection()) {
            connect(sock, &QTcpSocket::readyRead, this, [this, sock]() {
                m_buffers[sock].append(sock->readAll());
                serve(sock);
            });
            connect(sock, &QTcpSocket::disconnected, this, [this, sock]() {
                m_buffers.remove(sock);
                sock->deleteLater();
            });
        }
    }

private:
    /// Wait for a complete request (headers + Content-Length body),
    /// then answer it.
    void serve(QTcpSocket *sock)
    {
        QByteArray &buf = m_buffers[sock];
        const int headerEnd = buf.indexOf("\r\n\r\n");
        if (headerEnd < 0) return;

        int contentLength = 0;
        const QByteArray headers = buf.left(headerEnd);
        for (const QByteArray &line : headers.split('\n')) {
            const QByteArray l = line.trimmed().toLower();
            if (l.startsWith("content-length:"))
                contentLength = l.mid(15).trimmed().toInt();
        }
        const int bodyStart = headerEnd + 4;
        if (buf.size() < bodyStart + contentLength) return;

        const QByteArray body = buf.mid(bodyStart, contentLength);
        buf.remove(0, bodyStart + contentLength);

        if (m_holdNextStatusRead && isStatusRead(body)) {
            m_holdNextStatusRead = false;
            const int liveState = std::exchange(optInState, m_staleState);
            m_held.append({ sock, respond(body) });
            optInState = liveState;
            return;
        }
        if (!m_holdMethod.isEmpty() && body.contains(m_holdMethod)) {
            m_holdMethod.clear();
            m_held.append({ sock, respond(body) });
            return;
        }

        sock->write(respond(body));
        sock->flush();
        // The client sends `Connection: close`; honour it so each
        // request gets its own connection exactly as against real AMT.
        sock->disconnectFromHost();
    }

    static bool isStatusRead(const QByteArray &body)
    {
        return !body.contains("StartOptIn") && !body.contains("SendOptInCode")
            && !body.contains("CancelOptIn")
            && !body.contains("IPS_KVMRedirectionSettingData");
    }

    QByteArray respond(const QByteArray &body)
    {
        QByteArray payload;
        if (body.contains("StartOptIn")) {
            calls << QStringLiteral("StartOptIn");
            // Real firmware puts a code on the target's screen here.
            if (startOptInReturnValue == 0) optInState = startOptInState;
            payload = invokeReply("StartOptIn", startOptInReturnValue);
        } else if (body.contains("SendOptInCode")) {
            calls << QStringLiteral("SendOptInCode");
            if (sendCodeReturnValue == 0) optInState = 3; // RECEIVED
            payload = invokeReply("SendOptInCode", sendCodeReturnValue);
        } else if (body.contains("CancelOptIn")) {
            calls << QStringLiteral("CancelOptIn");
            if (cancelReturnValue == 0) optInState = 0;
            payload = invokeReply("CancelOptIn", cancelReturnValue);
        } else if (body.contains("IPS_KVMRedirectionSettingData")) {
            calls << QStringLiteral("GetKvmSettings");
            payload = kvmSettingsReply();
        } else {
            calls << QStringLiteral("GetOptInService");
            payload = optInServiceReply();
        }

        QByteArray out = "HTTP/1.1 200 OK\r\n";
        out += "Content-Type: application/soap+xml;charset=UTF-8\r\n";
        out += "Content-Length: " + QByteArray::number(payload.size()) + "\r\n";
        out += "Connection: close\r\n\r\n";
        out += payload;
        return out;
    }

    static QByteArray envelope(const QByteArray &inner)
    {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
               "<a:Envelope xmlns:a=\"http://www.w3.org/2003/05/soap-envelope\" "
               "xmlns:g=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_OptInService\" "
               "xmlns:k=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_KVMRedirectionSettingData\">"
               "<a:Header/><a:Body>" + inner + "</a:Body></a:Envelope>";
    }

    static QByteArray invokeReply(const QByteArray &method, quint32 rv)
    {
        return envelope("<g:" + method + "_OUTPUT><g:ReturnValue>"
                        + QByteArray::number(rv)
                        + "</g:ReturnValue></g:" + method + "_OUTPUT>");
    }

    QByteArray optInServiceReply() const
    {
        return envelope("<g:IPS_OptInService>"
                        "<g:OptInRequired>" + QByteArray::number(optInRequired) + "</g:OptInRequired>"
                        "<g:OptInState>" + QByteArray::number(optInState) + "</g:OptInState>"
                        "<g:CanModifyOptInPolicy>1</g:CanModifyOptInPolicy>"
                        "</g:IPS_OptInService>");
    }

    static QByteArray kvmSettingsReply()
    {
        return envelope("<k:IPS_KVMRedirectionSettingData>"
                        "<k:OptInPolicy>true</k:OptInPolicy>"
                        "<k:OptInPolicyTimeout>60</k:OptInPolicyTimeout>"
                        "<k:Is5900PortEnabled>false</k:Is5900PortEnabled>"
                        "<k:SessionTimeout>0</k:SessionTimeout>"
                        "</k:IPS_KVMRedirectionSettingData>");
    }

    QTcpServer m_server;
    QHash<QTcpSocket *, QByteArray> m_buffers;
    QByteArray m_holdMethod;
    bool m_holdNextStatusRead = false;
    int m_staleState = 0;
    struct Held {
        QPointer<QTcpSocket> socket;
        QByteArray reply;
    };
    QList<Held> m_held;
};

/// Pump the event loop for `ms` with no success condition — used to
/// give queued status reads and timer ticks a chance to fire so a test
/// can assert that something did *not* happen.
inline void settle(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
}

inline bool waitFor(int ms, const std::function<bool()> &pred)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms) {
        if (pred()) return true;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    return pred();
}

} // namespace qumesh::testing
