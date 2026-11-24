// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "wsman/wsman_client.h"

#include <QCryptographicHash>
#include <QMetaObject>
#include <QPointer>
#include <QQueue>
#include <QRandomGenerator>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTimer>
#include <QUrl>

#include <memory>

#ifdef Q_OS_WIN
#  include <winsock2.h>
#else
#  include <unistd.h>
#endif

namespace qumesh::wsman {

namespace {

/// `connectToHost` and a socket factory can fail synchronously, inside
/// `sendEnvelope`, before the caller has connected to `finished()`.
/// Queue the signal so the failure still reaches that caller.
void emitFinishedQueued(WsmanReply *reply)
{
    QMetaObject::invokeMethod(reply, &WsmanReply::finished, Qt::QueuedConnection);
}

} // namespace

namespace {

/// Upper bound on a single WSMAN HTTP reply body. AMT's largest
/// legitimate enumerations (audit log, event log, cert dump) are
/// well under 4 MB even with thousands of rows — 32 MB is two orders
/// of magnitude over and exists purely as an OOM guard against a
/// hostile or buggy responder (Content-Length: 9_999_999_999 or a
/// runaway chunked stream). See #271.
constexpr qint64 kWsmanMaxBodyBytes = 32LL * 1024LL * 1024LL;

/// Match the formatting used elsewhere: uppercase hex, colon-separated.
QString fingerprintFor(const QSslCertificate &cert)
{
    const QByteArray hash = QCryptographicHash::hash(cert.toDer(),
                                                      QCryptographicHash::Sha256);
    QString out;
    out.reserve(hash.size() * 3);
    for (int i = 0; i < hash.size(); ++i) {
        if (i > 0) out += QLatin1Char(':');
        out += QString::asprintf("%02X", static_cast<quint8>(hash.at(i)));
    }
    return out;
}

QByteArray md5Hex(const QByteArray &in)
{
    return QCryptographicHash::hash(in, QCryptographicHash::Md5).toHex();
}

/// Parse the directives out of a `WWW-Authenticate: Digest ...` value.
/// Handles `key=value` and `key="value"` forms, ignores anything outside
/// of the leading "Digest" scheme.
QHash<QByteArray, QByteArray> parseDigestChallenge(const QByteArray &headerValue)
{
    QHash<QByteArray, QByteArray> out;
    // Strict prefix check: require an exact case-insensitive `Digest`
    // token followed by whitespace, so a `DigestX realm=...` header
    // doesn't get parsed as a Digest challenge (which would otherwise
    // produce a garbage `x realm` key and bogus state).
    if (headerValue.size() <= 6
        || headerValue.left(6).toLower() != "digest") return out;
    const char sep = headerValue.at(6);
    if (sep != ' ' && sep != '\t') return out;
    int i = 7;
    while (i < headerValue.size()) {
        while (i < headerValue.size() && (headerValue[i] == ' ' || headerValue[i] == ','))
            ++i;
        int keyStart = i;
        while (i < headerValue.size() && headerValue[i] != '=') ++i;
        if (i == headerValue.size()) break;
        const QByteArray key = headerValue.mid(keyStart, i - keyStart).trimmed().toLower();
        ++i; // skip '='
        QByteArray value;
        if (i < headerValue.size() && headerValue[i] == '"') {
            ++i;
            int valStart = i;
            while (i < headerValue.size() && headerValue[i] != '"') ++i;
            value = headerValue.mid(valStart, i - valStart);
            if (i < headerValue.size()) ++i; // skip closing quote
        } else {
            int valStart = i;
            while (i < headerValue.size() && headerValue[i] != ',') ++i;
            value = headerValue.mid(valStart, i - valStart).trimmed();
        }
        if (!key.isEmpty()) out.insert(key, value);
    }
    return out;
}

QByteArray randomCnonce()
{
    auto *rng = QRandomGenerator::system();
    quint64 buf[2] = { rng->generate64(), rng->generate64() };
    return QByteArray::fromRawData(reinterpret_cast<const char *>(buf), sizeof(buf)).toHex();
}

} // namespace

// ---- WsmanReply --------------------------------------------------------------

struct WsmanReply::Private
{
    QPointer<WsmanClient> client;
    QSslSocket *socket = nullptr;
    QTimer *timeoutTimer = nullptr;
    QString errorString;
    int httpStatus = 0;
    QByteArray body;

    QByteArray method = "POST";
    QByteArray requestPath;
    QByteArray hostHeader;
    QByteArray envelope;
    QByteArray soapAction;

    QByteArray responseBuffer;
    QHash<QByteArray, QByteArray> responseHeaders;

    /// Digest 401 retries already spent on THIS reply. A persistent
    /// 401 — a wrong password is the realistic trigger — would
    /// otherwise loop connect → 401 → connect forever, one fresh TCP
    /// connection per bounce. See #435.
    int digestRetries = 0;

    enum State {
        Idle,
        Connecting,
        TlsHandshaking,
        WritingRequest,
        ReadingHeaders,
        ReadingBodyContentLength,
        ReadingBodyChunked,
        Done,
        Failed,
    };
    State state = Idle;

    qint64 expectedBody = -1;
    bool ownsSocket = true;
    bool finished = false;

    // Chunked transfer state.
    qint64 currentChunkRemaining = 0;
    bool readingChunkSize = true;
};

WsmanReply::WsmanReply(QObject *parent)
    : QObject(parent), d(std::make_unique<Private>()) {}

WsmanReply::~WsmanReply()
{
    if (d->socket != nullptr && d->ownsSocket) {
        d->socket->abort();
        d->socket->deleteLater();
    }
}

QByteArray WsmanReply::readAll() const { return d->body; }
bool WsmanReply::hasError() const { return !d->errorString.isEmpty(); }
QString WsmanReply::errorString() const { return d->errorString; }
int WsmanReply::httpStatus() const { return d->httpStatus; }

void WsmanReply::abort()
{
    if (d->finished) return;
    if (d->socket != nullptr) d->socket->abort();
    d->errorString = QStringLiteral("Aborted");
    d->state = Private::Failed;
    d->finished = true;
    emit finished();
}

// ---- WsmanClient -------------------------------------------------------------

struct WsmanClient::Private
{
    QUrl endpoint;
    QString user;
    QString pass;
    QStringList trustedFingerprints;
    PeerCertSummary pendingPeerCert;
    bool awaitingTrust = false;
    int timeoutMs = 30000;
    SocketFactory socketFactory;

    // Cached Digest challenge state. Refreshed on every successful 401
    // dance; subsequent requests reuse it and increment `nc`.
    bool haveDigestChallenge = false;
    QByteArray digestRealm;
    QByteArray digestNonce;
    QByteArray digestQop;
    QByteArray digestAlgorithm;
    QByteArray digestOpaque;
    quint64 nc = 0;

    // Single-flight queue used when `serializeRequests == true`.
    bool serializeRequests = false;
    QPointer<WsmanReply> currentRequest;
    QQueue<QPointer<WsmanReply>> pendingQueue;
};

WsmanClient::WsmanClient(QObject *parent)
    : QObject(parent), d(std::make_unique<Private>()) {}

WsmanClient::~WsmanClient() = default;

void WsmanClient::setEndpoint(QUrl endpoint) { d->endpoint = std::move(endpoint); }
void WsmanClient::setCredentials(QString user, QString pass)
{
    d->user = std::move(user);
    d->pass = std::move(pass);
    d->haveDigestChallenge = false; // Old nonce won't match new creds.
}
void WsmanClient::setTrustedFingerprints(QStringList fingerprints)
{
    d->trustedFingerprints = std::move(fingerprints);
}
void WsmanClient::setTransferTimeoutMs(int ms) { d->timeoutMs = ms; }
void WsmanClient::setSocketFactory(SocketFactory factory)
{
    d->socketFactory = std::move(factory);
}
void WsmanClient::setSerializeRequests(bool serialize)
{
    d->serializeRequests = serialize;
}
QUrl WsmanClient::endpoint() const { return d->endpoint; }
PeerCertSummary WsmanClient::pendingPeerCert() const { return d->pendingPeerCert; }
bool WsmanClient::awaitingTrust() const { return d->awaitingTrust; }

void WsmanClient::trustPendingPeerCert()
{
    if (!d->awaitingTrust || d->pendingPeerCert.fingerprintSha256.isEmpty()) return;
    if (!d->trustedFingerprints.contains(d->pendingPeerCert.fingerprintSha256))
        d->trustedFingerprints.append(d->pendingPeerCert.fingerprintSha256);
    d->pendingPeerCert = {};
    d->awaitingTrust = false;
}

namespace {

/// Compute the `response` value of an RFC 7616 / 2617 Digest auth
/// challenge with `qop=auth, algorithm=MD5`. AMT firmware accepts this
/// and rejects unspecified algorithms.
QByteArray computeDigestResponse(const QByteArray &user, const QByteArray &realm,
                                  const QByteArray &pass, const QByteArray &nonce,
                                  const QByteArray &cnonce, const QByteArray &nc,
                                  const QByteArray &qop, const QByteArray &method,
                                  const QByteArray &uri)
{
    const QByteArray ha1 = md5Hex(user + ":" + realm + ":" + pass);
    const QByteArray ha2 = md5Hex(method + ":" + uri);
    return md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
}

/// Per RFC 7616 §3.4.6: quoted-string fields in the Authorization
/// header must backslash-escape embedded backslash and double-quote.
/// AMT usernames usually don't contain either, but the same code
/// path runs for SSH-tunnelled requests where `user` is operator-
/// supplied via the Computer config — a username with `\` or `"`
/// produces a malformed header that AMT rejects with no useful
/// diagnostic. Escape backslash first so the inserted `\` isn't
/// re-escaped by the quote pass. See #277.
QByteArray quotedStringEscape(const QByteArray &v)
{
    QByteArray out;
    out.reserve(v.size());
    for (char ch : v) {
        if (ch == '\\' || ch == '"') out.append('\\');
        out.append(ch);
    }
    return out;
}

/// Build the `Authorization: Digest …` header for one request.
QByteArray buildDigestHeader(const WsmanClient::Private &c, const QByteArray &method,
                              const QByteArray &uri, const QByteArray &user,
                              const QByteArray &pass, quint64 nc)
{
    const QByteArray ncBytes = QByteArray::number(nc, 16).rightJustified(8, '0');
    const QByteArray cnonce = randomCnonce();
    const QByteArray qop = c.digestQop.isEmpty() ? QByteArrayLiteral("auth") : c.digestQop;
    // Note: computeDigestResponse hashes the *raw* (unescaped) realm /
    // user / nonce per the digest algorithm; escaping is purely a
    // header-serialisation concern.
    const QByteArray response = computeDigestResponse(user, c.digestRealm, pass,
                                                      c.digestNonce, cnonce,
                                                      ncBytes, qop, method, uri);

    QByteArray out = "Digest ";
    out += "username=\"" + quotedStringEscape(user) + "\", ";
    out += "realm=\"" + quotedStringEscape(c.digestRealm) + "\", ";
    out += "nonce=\"" + quotedStringEscape(c.digestNonce) + "\", ";
    out += "uri=\"" + quotedStringEscape(uri) + "\", ";
    out += "response=\"" + response + "\", ";
    if (!c.digestAlgorithm.isEmpty())
        out += "algorithm=" + c.digestAlgorithm + ", ";
    else
        out += "algorithm=MD5, ";
    out += "qop=" + qop + ", ";
    out += "nc=" + ncBytes + ", ";
    out += "cnonce=\"" + cnonce + "\"";
    if (!c.digestOpaque.isEmpty())
        out += ", opaque=\"" + quotedStringEscape(c.digestOpaque) + "\"";
    return out;
}

void writeRequestBytes(QSslSocket *sock, const QByteArray &method,
                       const QByteArray &path, const QByteArray &hostHeader,
                       const QByteArray &soapAction, const QByteArray &body,
                       const QByteArray &authHeader)
{
    QByteArray req;
    req += method + " " + path + " HTTP/1.1\r\n";
    req += "Host: " + hostHeader + "\r\n";
    req += "Content-Type: application/soap+xml;charset=UTF-8\r\n";
    if (!soapAction.isEmpty())
        req += "SOAPAction: \"" + soapAction + "\"\r\n";
    req += "User-Agent: QuMesh/0.1\r\n";
    req += "Accept: */*\r\n";
    req += "Connection: close\r\n";
    if (!authHeader.isEmpty())
        req += "Authorization: " + authHeader + "\r\n";
    req += "Content-Length: " + QByteArray::number(body.size()) + "\r\n\r\n";
    req += body;
    sock->write(req);
}

} // namespace

namespace {

void readMore(WsmanReply *reply, WsmanClient *client,
              WsmanClient::Private &cd, WsmanReply::Private &rd);

/// Common socket setup shared by direct and factory-supplied sockets.
/// Attaches the TLS, error, and read-side handlers; the readyRead
/// handler is wired here too so callers don't need to duplicate it.
void wireSocketHandlers(WsmanReply *reply, WsmanClient *client,
                        WsmanClient::Private &cd, WsmanReply::Private &rd,
                        QSslSocket *sock, bool prompts)
{
    rd.socket = sock;
    const bool tls = cd.endpoint.scheme().compare(
        QStringLiteral("https"), Qt::CaseInsensitive) == 0;

    if (tls) {
        QObject::connect(sock, &QSslSocket::sslErrors,
                         reply, [sock, &cd, client, prompts](const QList<QSslError> &errors) {
            const QList<QSslCertificate> chain = sock->peerCertificateChain();
            if (chain.isEmpty()) return;
            const QSslCertificate &leaf = chain.first();
            const QString fp = fingerprintFor(leaf);
            if (cd.trustedFingerprints.contains(fp)) {
                emit client->peerCertVerifiedByPin(fp);
                sock->ignoreSslErrors(errors);
                return;
            }
            if (!prompts) return; // retry path doesn't re-prompt
            PeerCertSummary s;
            const auto subjects = leaf.subjectInfo(QSslCertificate::CommonName);
            const auto issuers  = leaf.issuerInfo(QSslCertificate::CommonName);
            if (!subjects.isEmpty()) s.subject = subjects.first();
            if (!issuers.isEmpty())  s.issuer  = issuers.first();
            s.fingerprintSha256 = fp;
            s.notBefore = leaf.effectiveDate().toString(Qt::ISODate);
            s.notAfter  = leaf.expiryDate().toString(Qt::ISODate);
            s.der = leaf.toDer();
            cd.pendingPeerCert = s;
            cd.awaitingTrust = true;
            emit client->trustPromptRequired(s);
            // Leave the errors unignored — handshake will fail, the
            // reply surfaces an error, the controller surfaces the
            // dialog and re-issues the request once trusted.
        });
    }

    // Capture the reply by QPointer and re-derive `rd` on each call.
    // The socket is parented to `reply`, so the connections are auto-
    // disconnected when `reply` is destroyed — but using QPointer here
    // is a belt-and-braces guard against any signal that might already
    // be sitting in the event queue when the reply goes away.
    QPointer<WsmanReply> wr(reply);
    QObject::connect(sock, &QSslSocket::errorOccurred, reply,
                     [wr](QAbstractSocket::SocketError) {
        if (wr.isNull()) return;
        auto &rd = *wr->d;
        if (rd.finished) return;
        rd.errorString = rd.socket->errorString();
        rd.state = WsmanReply::Private::Failed;
        rd.finished = true;
        emitFinishedQueued(wr.data());
    });

    QObject::connect(sock, &QSslSocket::readyRead, reply,
                     [wr, client, &cd]() {
        if (wr.isNull()) return;
        readMore(wr.data(), client, cd, *wr->d);
    });
}

/// Close an orphaned tunnel fd when the consuming reply died before
/// the async socket factory delivered its result.
void closeOrphanFd(qintptr fd)
{
    if (fd < 0) return;
#ifdef Q_OS_WIN
    ::closesocket(static_cast<SOCKET>(fd));
#else
    ::close(static_cast<int>(fd));
#endif
}

/// Arm the per-reply transfer timeout, once. Idempotent: the guard
/// means whichever of `startTransport` / `retryWithDigest` runs first
/// creates the timer and later calls are no-ops, so the timeout bounds
/// the whole reply — retries included — rather than being restarted by
/// each attempt.
///
/// This must be called from BOTH entry points. `sendEnvelope`'s
/// `startNow` skips `startTransport` entirely when a Digest challenge
/// is already cached, so before #435 every request after the client's
/// first 401 ran with no timeout armed at all: on a stall the reply
/// never emitted `finished()`, the caller's callback never ran, and a
/// controller's `decInflight()` was never reached — a permanent "busy"
/// in the UI.
void armTimeout(WsmanReply *reply, WsmanClient::Private &cd,
                WsmanReply::Private &rd)
{
    // Armed before the socket is opened so it covers the async
    // socket-open window too — a stalled tunnel open would otherwise
    // sit forever.
    if (rd.timeoutTimer != nullptr || cd.timeoutMs <= 0) return;
    rd.timeoutTimer = new QTimer(reply);
    rd.timeoutTimer->setSingleShot(true);
    rd.timeoutTimer->setInterval(cd.timeoutMs);
    QObject::connect(rd.timeoutTimer, &QTimer::timeout, reply, [reply, &rd]() {
        if (rd.finished) return;
        rd.errorString = QStringLiteral("Request timed out");
        rd.state = WsmanReply::Private::Failed;
        if (rd.socket != nullptr) rd.socket->abort();
        rd.finished = true;
        emit reply->finished();
    });
    rd.timeoutTimer->start();
}

/// Open or adopt the socket the reply will use. Sets `Connecting` or
/// `TlsHandshaking` and connects all the socket signals. With an async
/// socket factory the function returns immediately; the remainder of
/// the setup runs from inside the factory's completion callback.
void startTransport(WsmanReply *reply, WsmanClient *client,
                    WsmanClient::Private &cd, WsmanReply::Private &rd)
{
    armTimeout(reply, cd, rd);

    const bool tls = cd.endpoint.scheme().compare(
        QStringLiteral("https"), Qt::CaseInsensitive) == 0;

    auto finishViaFactorySocket = [client, &cd, &rd](WsmanReply *r, QSslSocket *sock) {
        const bool tlsLocal = cd.endpoint.scheme().compare(
            QStringLiteral("https"), Qt::CaseInsensitive) == 0;
        wireSocketHandlers(r, client, cd, rd, sock, /*prompts=*/true);
        if (tlsLocal) {
            QObject::connect(sock, &QSslSocket::encrypted, r, [r]() {
                // Queue through invokeMethod so any pending sslErrors
                // handler runs first.
                QMetaObject::invokeMethod(r, [r]() {
                    auto &rd2 = *r->d;
                    if (rd2.finished) return;
                    rd2.state = WsmanReply::Private::WritingRequest;
                    writeRequestBytes(rd2.socket, rd2.method, rd2.requestPath,
                                       rd2.hostHeader, rd2.soapAction, rd2.envelope,
                                       QByteArray());
                    rd2.state = WsmanReply::Private::ReadingHeaders;
                }, Qt::QueuedConnection);
            });
            rd.state = WsmanReply::Private::TlsHandshaking;
            sock->setPeerVerifyName(cd.endpoint.host());
            sock->startClientEncryption();
        } else {
            rd.state = WsmanReply::Private::WritingRequest;
            writeRequestBytes(sock, rd.method, rd.requestPath, rd.hostHeader,
                              rd.soapAction, rd.envelope, QByteArray());
            rd.state = WsmanReply::Private::ReadingHeaders;
        }
    };

    if (cd.socketFactory) {
        rd.state = WsmanReply::Private::Connecting;
        QPointer<WsmanReply> wr(reply);
        cd.socketFactory(
            [wr, &rd, finishViaFactorySocket](qintptr fd, QString error) {
                if (wr.isNull()) {
                    closeOrphanFd(fd);
                    return;
                }
                if (rd.finished) {
                    closeOrphanFd(fd);
                    return;
                }
                if (fd < 0) {
                    rd.errorString = error.isEmpty()
                        ? QStringLiteral("SSH tunnel socket could not be opened")
                        : error;
                    rd.state = WsmanReply::Private::Failed;
                    rd.finished = true;
                    if (rd.timeoutTimer != nullptr) rd.timeoutTimer->stop();
                    emitFinishedQueued(wr.data());
                    return;
                }
                auto *sock = new QSslSocket(wr.data());
                if (!sock->setSocketDescriptor(fd, QAbstractSocket::ConnectedState)) {
                    rd.errorString = QStringLiteral("setSocketDescriptor failed: %1")
                                         .arg(sock->errorString());
                    rd.state = WsmanReply::Private::Failed;
                    rd.finished = true;
                    sock->deleteLater();
                    if (rd.timeoutTimer != nullptr) rd.timeoutTimer->stop();
                    emitFinishedQueued(wr.data());
                    return;
                }
                finishViaFactorySocket(wr.data(), sock);
            });
        return;
    }

    // Direct TCP connect.
    auto *sock = new QSslSocket(reply);
    wireSocketHandlers(reply, client, cd, rd, sock, /*prompts=*/true);
    QObject::connect(sock, &QSslSocket::connected, reply, [reply, sock, tls, &cd]() {
        auto &rd = *reply->d;
        if (rd.finished) return;
        if (tls) {
            rd.state = WsmanReply::Private::TlsHandshaking;
            sock->setPeerVerifyName(cd.endpoint.host());
            sock->startClientEncryption();
        } else {
            rd.state = WsmanReply::Private::WritingRequest;
            writeRequestBytes(sock, rd.method, rd.requestPath, rd.hostHeader,
                              rd.soapAction, rd.envelope, QByteArray());
            rd.state = WsmanReply::Private::ReadingHeaders;
        }
    });
    if (tls) {
        QObject::connect(sock, &QSslSocket::encrypted, reply, [reply]() {
            auto &rd = *reply->d;
            if (rd.finished) return;
            rd.state = WsmanReply::Private::WritingRequest;
            writeRequestBytes(rd.socket, rd.method, rd.requestPath,
                              rd.hostHeader, rd.soapAction, rd.envelope,
                              QByteArray());
            rd.state = WsmanReply::Private::ReadingHeaders;
        });
    }
    rd.state = WsmanReply::Private::Connecting;
    const QString host = cd.endpoint.host();
    const quint16 port = static_cast<quint16>(cd.endpoint.port(tls ? 16993 : 16992));
    sock->connectToHost(host, port);
}

void readMore(WsmanReply *reply, WsmanClient *client,
               WsmanClient::Private &cd, WsmanReply::Private &rd);

void finishReply(WsmanReply *reply, WsmanReply::Private &rd, const QString &err)
{
    if (rd.finished) return;
    if (!err.isEmpty()) {
        rd.errorString = err;
        rd.state = WsmanReply::Private::Failed;
    } else {
        rd.state = WsmanReply::Private::Done;
    }
    rd.finished = true;
    if (rd.timeoutTimer != nullptr) rd.timeoutTimer->stop();
    emit reply->finished();
}

/// Retry the same request with a freshly-computed `Authorization`
/// header. Opens a *new* socket because we already closed the previous
/// one (Connection: close after 401).
void retryWithDigest(WsmanReply *reply, WsmanClient *client,
                     WsmanClient::Private &cd, WsmanReply::Private &rd)
{
    armTimeout(reply, cd, rd);
    if (rd.socket != nullptr) {
        rd.socket->disconnectFromHost();
        rd.socket->deleteLater();
        rd.socket = nullptr;
    }
    rd.responseBuffer.clear();
    rd.responseHeaders.clear();
    rd.body.clear();
    rd.httpStatus = 0;
    rd.expectedBody = -1;
    rd.currentChunkRemaining = 0;
    rd.readingChunkSize = true;

    const bool tls = cd.endpoint.scheme().compare(
        QStringLiteral("https"), Qt::CaseInsensitive) == 0;

    const QByteArray auth = buildDigestHeader(cd, rd.method, rd.requestPath,
                                              cd.user.toUtf8(), cd.pass.toUtf8(),
                                              ++cd.nc);

    // Capture the reply by QPointer in every inner connect lambda
    // below, and re-derive `rd` on each entry. If the reply is
    // destroyed mid-retry (e.g. UI cancels in flight), the QPointer
    // goes null and the lambda bails before touching freed memory.
    // `cd` (the client's `Private`) is safe to capture by reference:
    // the client parents the reply, so the client outlives any
    // lambda whose `wr` is non-null.
    QPointer<WsmanReply> wrTop(reply);

    auto doWrite = [wrTop, auth]() {
        if (wrTop.isNull()) return;
        auto &rd = *wrTop->d;
        if (rd.finished) return;
        writeRequestBytes(rd.socket, rd.method, rd.requestPath, rd.hostHeader,
                          rd.soapAction, rd.envelope, auth);
        rd.state = WsmanReply::Private::ReadingHeaders;
    };

    auto wireFactorySocket = [client, &cd, doWrite, tls](WsmanReply *r, QSslSocket *sock) {
        auto &rd = *r->d;
        wireSocketHandlers(r, client, cd, rd, sock, /*prompts=*/false);
        if (tls) {
            QObject::connect(sock, &QSslSocket::encrypted, r, doWrite);
            rd.state = WsmanReply::Private::TlsHandshaking;
            sock->setPeerVerifyName(cd.endpoint.host());
            sock->startClientEncryption();
        } else {
            doWrite();
        }
    };

    if (cd.socketFactory) {
        rd.state = WsmanReply::Private::Connecting;
        QPointer<WsmanReply> wr(reply);
        cd.socketFactory([wr, wireFactorySocket](qintptr fd, QString error) {
            if (wr.isNull()) { closeOrphanFd(fd); return; }
            auto &rd = *wr->d;
            if (rd.finished) { closeOrphanFd(fd); return; }
            if (fd < 0) {
                finishReply(wr.data(), rd,
                            error.isEmpty()
                                ? QStringLiteral("SSH tunnel socket could not be opened")
                                : error);
                return;
            }
            auto *sock = new QSslSocket(wr.data());
            if (!sock->setSocketDescriptor(fd, QAbstractSocket::ConnectedState)) {
                finishReply(wr.data(), rd, QStringLiteral("setSocketDescriptor failed"));
                sock->deleteLater();
                return;
            }
            wireFactorySocket(wr.data(), sock);
        });
        return;
    }

    // Direct TCP connect.
    auto *sock = new QSslSocket(reply);
    wireSocketHandlers(reply, client, cd, rd, sock, /*prompts=*/false);
    QObject::connect(sock, &QSslSocket::connected, reply, [sock, tls, &cd, doWrite, wrTop]() {
        if (wrTop.isNull()) return;
        auto &rd = *wrTop->d;
        if (rd.finished) return;
        if (tls) {
            rd.state = WsmanReply::Private::TlsHandshaking;
            sock->setPeerVerifyName(cd.endpoint.host());
            sock->startClientEncryption();
        } else {
            doWrite();
        }
    });
    if (tls) QObject::connect(sock, &QSslSocket::encrypted, reply, doWrite);
    rd.state = WsmanReply::Private::Connecting;
    const QString host = cd.endpoint.host();
    const quint16 port = static_cast<quint16>(cd.endpoint.port(tls ? 16993 : 16992));
    sock->connectToHost(host, port);
}

/// Single read pass: consume the socket buffer, advance the state
/// machine, and decide whether we need to read more or finish.
void readMore(WsmanReply *reply, WsmanClient *client,
               WsmanClient::Private &cd, WsmanReply::Private &rd)
{
    if (rd.finished || rd.socket == nullptr) return;
    const QByteArray chunk = rd.socket->readAll();
    if (chunk.isEmpty() && rd.socket->state() != QAbstractSocket::ConnectedState
        && rd.state == WsmanReply::Private::ReadingHeaders) {
        finishReply(reply, rd, QStringLiteral("Connection closed before headers"));
        return;
    }
    rd.responseBuffer.append(chunk);

    if (rd.state == WsmanReply::Private::ReadingHeaders) {
        const int headerEnd = rd.responseBuffer.indexOf("\r\n\r\n");
        if (headerEnd < 0) return; // need more bytes
        const QByteArray rawHeaders = rd.responseBuffer.left(headerEnd);
        rd.responseBuffer.remove(0, headerEnd + 4);

        QList<QByteArray> lines = rawHeaders.split('\n');
        if (lines.isEmpty()) {
            finishReply(reply, rd, QStringLiteral("Empty response"));
            return;
        }
        // Status line: HTTP/1.1 200 OK
        QByteArray statusLine = lines.takeFirst();
        if (statusLine.endsWith('\r')) statusLine.chop(1);
        const QList<QByteArray> statusParts = statusLine.split(' ');
        if (statusParts.size() < 2) {
            finishReply(reply, rd, QStringLiteral("Malformed status line"));
            return;
        }
        rd.httpStatus = statusParts.at(1).toInt();

        rd.responseHeaders.clear();
        for (const QByteArray &lineRaw : lines) {
            QByteArray line = lineRaw;
            if (line.endsWith('\r')) line.chop(1);
            const int colon = line.indexOf(':');
            if (colon < 0) continue;
            const QByteArray name = line.left(colon).trimmed().toLower();
            const QByteArray value = line.mid(colon + 1).trimmed();
            rd.responseHeaders.insert(name, value);
        }

        // 401 → parse challenge and retry on a new socket.
        if (rd.httpStatus == 401) {
            const QByteArray wwwAuth = rd.responseHeaders.value("www-authenticate");
            if (wwwAuth.isEmpty()) {
                finishReply(reply, rd, QStringLiteral("401 without WWW-Authenticate"));
                return;
            }
            const auto params = parseDigestChallenge(wwwAuth);
            const QByteArray previousNonce = cd.digestNonce;
            cd.digestRealm = params.value("realm");
            cd.digestNonce = params.value("nonce");
            // AMT sometimes advertises `qop="auth,auth-int"`. We have
            // to pick a single value and send THAT back in the
            // Authorization header (and use it in the response hash)
            // — sending the whole comma-joined string makes the
            // server's hash diverge from ours and the auth fails.
            const QByteArray rawQop = params.value("qop");
            cd.digestQop = QByteArrayLiteral("auth");
            if (!rawQop.isEmpty()) {
                bool foundAuth = false;
                for (const QByteArray &p : rawQop.split(',')) {
                    if (p.trimmed() == "auth") { foundAuth = true; break; }
                }
                if (!foundAuth) cd.digestQop = rawQop.split(',').first().trimmed();
            }
            cd.digestAlgorithm = params.value("algorithm");
            cd.digestOpaque = params.value("opaque");
            cd.haveDigestChallenge = !cd.digestRealm.isEmpty() && !cd.digestNonce.isEmpty();
            // Rewind the counter only when the nonce is genuinely
            // replaced. `nc` must be unique and strictly increasing for
            // the lifetime of a given nonce, so resetting on *every*
            // 401 meant two replies racing against the same rotated
            // nonce could both send nc=00000001 — a duplicate, which is
            // exactly what a server's replay check rejects. Requests
            // are unserialized on the direct transport
            // (`setSerializeRequests(false)`), so that race is
            // reachable rather than theoretical.
            if (cd.digestNonce != previousNonce) cd.nc = 0;
            if (!cd.haveDigestChallenge) {
                finishReply(reply, rd, QStringLiteral("Unsupported auth challenge"));
                return;
            }

            // Cap the retries. One is the normal case: an unauthed
            // request draws a challenge and the retry carries the
            // response. A second is legitimate only when the server
            // says the nonce went stale — that invalidates the first
            // attempt through no fault of the credentials. Anything
            // beyond that is a password the device will never accept,
            // and retrying just opens another TCP connection (every
            // attempt is a fresh socket: we send `Connection: close`).
            // The reference caps at 3 with a 500 ms backoff and is
            // single-flight by construction; we don't need the backoff
            // because we stop rather than sleep. See #435.
            const bool stale = params.value("stale").toLower() == "true";
            const int allowed = stale ? 2 : 1;
            if (rd.digestRetries >= allowed) {
                finishReply(reply, rd,
                            QStringLiteral("Authentication failed — Intel AMT "
                                           "rejected the credentials"));
                return;
            }
            ++rd.digestRetries;
            retryWithDigest(reply, client, cd, rd);
            return;
        }

        // Decide body-read mode.
        const QByteArray te = rd.responseHeaders.value("transfer-encoding");
        const QByteArray cl = rd.responseHeaders.value("content-length");
        if (te.toLower().contains("chunked")) {
            rd.state = WsmanReply::Private::ReadingBodyChunked;
            rd.readingChunkSize = true;
            rd.currentChunkRemaining = 0;
        } else if (!cl.isEmpty()) {
            rd.state = WsmanReply::Private::ReadingBodyContentLength;
            rd.expectedBody = cl.toLongLong();
            if (rd.expectedBody < 0) {
                finishReply(reply, rd, QStringLiteral("Bad Content-Length"));
                return;
            }
            if (rd.expectedBody > kWsmanMaxBodyBytes) {
                finishReply(reply, rd,
                    QStringLiteral("Content-Length %1 exceeds %2-byte cap")
                        .arg(rd.expectedBody).arg(kWsmanMaxBodyBytes));
                return;
            }
        } else {
            // No Content-Length, no chunked → read until close.
            rd.state = WsmanReply::Private::ReadingBodyContentLength;
            rd.expectedBody = -2; // sentinel: read-to-close
        }
    }

    if (rd.state == WsmanReply::Private::ReadingBodyContentLength) {
        if (rd.expectedBody == -2) {
            // Read-to-close path: cap the running body so a peer that
            // streams forever (no Content-Length, no chunked) can't
            // exhaust process memory. See #271.
            if (rd.body.size() + rd.responseBuffer.size() > kWsmanMaxBodyBytes) {
                finishReply(reply, rd,
                    QStringLiteral("Reply body exceeds %1-byte cap")
                        .arg(kWsmanMaxBodyBytes));
                return;
            }
            rd.body.append(rd.responseBuffer);
            rd.responseBuffer.clear();
            if (rd.socket->state() != QAbstractSocket::ConnectedState) {
                finishReply(reply, rd, QString());
            }
            return;
        }
        const qint64 need = rd.expectedBody - rd.body.size();
        if (need <= 0) {
            finishReply(reply, rd, QString());
            return;
        }
        const qint64 take = qMin<qint64>(need, rd.responseBuffer.size());
        rd.body.append(rd.responseBuffer.left(take));
        rd.responseBuffer.remove(0, take);
        if (rd.body.size() >= rd.expectedBody) {
            finishReply(reply, rd, QString());
        }
        return;
    }

    if (rd.state == WsmanReply::Private::ReadingBodyChunked) {
        for (;;) {
            if (rd.readingChunkSize) {
                const int eol = rd.responseBuffer.indexOf("\r\n");
                if (eol < 0) return;
                QByteArray sizeLine = rd.responseBuffer.left(eol);
                rd.responseBuffer.remove(0, eol + 2);
                const int semi = sizeLine.indexOf(';');
                if (semi >= 0) sizeLine = sizeLine.left(semi);
                bool ok = false;
                rd.currentChunkRemaining = sizeLine.toLongLong(&ok, 16);
                if (!ok || rd.currentChunkRemaining < 0) {
                    finishReply(reply, rd, QStringLiteral("Bad chunk size"));
                    return;
                }
                if (rd.currentChunkRemaining == 0) {
                    // Trailer headers and final CRLF — read until done
                    // or close. AMT never emits trailers, so simplify
                    // by finishing here.
                    finishReply(reply, rd, QString());
                    return;
                }
                rd.readingChunkSize = false;
            }
            if (rd.responseBuffer.isEmpty()) return;
            const qint64 take = qMin<qint64>(rd.currentChunkRemaining,
                                             rd.responseBuffer.size());
            // Cap the running body across all chunks — a malicious
            // peer can send arbitrarily many small chunks and OOM us
            // otherwise. See #271.
            if (rd.body.size() + take > kWsmanMaxBodyBytes) {
                finishReply(reply, rd,
                    QStringLiteral("Reply body exceeds %1-byte cap")
                        .arg(kWsmanMaxBodyBytes));
                return;
            }
            rd.body.append(rd.responseBuffer.left(take));
            rd.responseBuffer.remove(0, take);
            rd.currentChunkRemaining -= take;
            if (rd.currentChunkRemaining == 0) {
                // Each chunk is followed by CRLF.
                if (rd.responseBuffer.size() < 2) return;
                rd.responseBuffer.remove(0, 2);
                rd.readingChunkSize = true;
            } else {
                return; // need more bytes
            }
        }
    }
}

} // namespace

WsmanReply *WsmanClient::sendEnvelope(const QByteArray &envelope, const char *soapAction)
{
    auto *reply = new WsmanReply(this);
    auto &rd = *reply->d;
    rd.client = this;
    rd.envelope = envelope;
    if (soapAction != nullptr) rd.soapAction = QByteArray(soapAction);
    rd.requestPath = d->endpoint.path(QUrl::FullyEncoded).toUtf8();
    if (rd.requestPath.isEmpty()) rd.requestPath = "/";
    rd.hostHeader = (d->endpoint.host() + QStringLiteral(":")
                     + QString::number(d->endpoint.port(
                         d->endpoint.scheme().compare(QStringLiteral("https"),
                             Qt::CaseInsensitive) == 0 ? 16993 : 16992))).toUtf8();

    auto *client = this;
    auto &cd = *d;

    auto startNow = [reply, client, &cd, &rd]() {
        // If we already have a valid Digest challenge cached, send the
        // first attempt pre-authed and skip the 401 round-trip.
        // startTransport / retryWithDigest both attach the readyRead
        // handler internally now — needed because with an async socket
        // factory `rd.socket` isn't populated when these return.
        if (cd.haveDigestChallenge && !cd.user.isEmpty()) {
            retryWithDigest(reply, client, cd, rd);
            return;
        }
        startTransport(reply, client, cd, rd);
    };

    if (!cd.serializeRequests) {
        startNow();
        return reply;
    }

    // Serialized mode: enqueue. The single-flight drainer picks the
    // next reply off the queue when the in-flight one finishes.
    cd.pendingQueue.enqueue(reply);
    QObject::connect(reply, &WsmanReply::finished, client, [client]() {
        auto &cd2 = *client->d;
        cd2.currentRequest = nullptr;
        while (!cd2.pendingQueue.isEmpty()) {
            QPointer<WsmanReply> next = cd2.pendingQueue.dequeue();
            if (next == nullptr) continue; // reply got destroyed while queued
            cd2.currentRequest = next;
            // The pending reply's `rd` already has envelope / path /
            // host set from `sendEnvelope`; we just need to fire its
            // transport via the same logic the un-serialized path uses.
            auto &nrd = *next->d;
            auto *c = client;
            if (cd2.haveDigestChallenge && !cd2.user.isEmpty()) {
                retryWithDigest(next, c, cd2, nrd);
            } else {
                startTransport(next, c, cd2, nrd);
            }
            return;
        }
    });

    if (cd.currentRequest == nullptr) {
        cd.currentRequest = cd.pendingQueue.dequeue();
        startNow();
    }
    return reply;
}

} // namespace qumesh::wsman
