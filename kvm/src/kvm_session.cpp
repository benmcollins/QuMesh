// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "kvm/kvm_session.h"

#include "redir/redir_client.h"
#include "redir/redir_codec.h"

#include <QByteArray>
#include <QLoggingCategory>
#include <QMetaObject>

Q_LOGGING_CATEGORY(lcKvmSession, "qumesh.kvm.session", QtInfoMsg)

namespace qumesh::kvm {

namespace {

/// Compression is on by default; `QUMESH_KVM_COMPRESSION` is a kill
/// switch. Returns `false` only when the env var is explicitly set to
/// `0` / `false` / `off` (case-insensitive). Anything else — including
/// unset — leaves compression enabled. The variable will retire once
/// the default has been stable across a release or two.
bool readCompressionEnabled()
{
    if (!qEnvironmentVariableIsSet("QUMESH_KVM_COMPRESSION")) return true;
    const QByteArray raw = qgetenv("QUMESH_KVM_COMPRESSION").trimmed().toLower();
    return !(raw == "0" || raw == "false" || raw == "off");
}

const char *stateName(KvmSession::State s)
{
    switch (s) {
    case KvmSession::State::Idle:       return "Idle";
    case KvmSession::State::Version:    return "Version";
    case KvmSession::State::Security:   return "Security";
    case KvmSession::State::AuthResult: return "AuthResult";
    case KvmSession::State::ServerInit: return "ServerInit";
    case KvmSession::State::FrameLoop:  return "FrameLoop";
    case KvmSession::State::Failed:     return "Failed";
    }
    return "?";
}

} // namespace

using qumesh::redir::RedirectionClient;

KvmSession::KvmSession(RedirectionClient *client, QObject *parent)
    : QObject(parent), m_client(client)
{
    Q_ASSERT(client != nullptr);
    connect(m_client, &RedirectionClient::rawBytes, this, &KvmSession::onRawBytes);
    connect(m_client, &RedirectionClient::failed, this,
            [this](const QString &reason) { fail(reason); });
}

KvmSession::~KvmSession() = default;

void KvmSession::start()
{
    if (m_client->state() != RedirectionClient::State::Authenticated) {
        fail(QStringLiteral("client not authenticated"));
        return;
    }
    // The RLE inflate stream's sliding window must be empty at the
    // start of every session.
    m_inflate.reset();
    // Re-derive the format from the next ServerInit; a previous session
    // may have dropped to 8-bit for a desktop that has since changed.
    m_format = PixelFormat::Rgb565;
    m_compressionEnabled = readCompressionEnabled();
    qCInfo(lcKvmSession) << "KVM compression"
                          << (m_compressionEnabled
                                  ? "enabled (default)"
                                  : "disabled via QUMESH_KVM_COMPRESSION=0");
    setState(State::Version);
}

void KvmSession::onRawBytes(const QByteArray &chunk)
{
    m_inbox.append(chunk);
    drainInbox();
}

void KvmSession::drainInbox()
{
    // Bound the work done per call. A FramebufferUpdate can contain
    // dozens of rects; running them all synchronously starves input
    // handling and the QML repaint cycle.
    constexpr int kMaxStepsPerCall = 16;
    for (int i = 0; i < kMaxStepsPerCall; ++i) {
        if (m_state == State::Version
            || m_state == State::Security
            || m_state == State::AuthResult
            || m_state == State::ServerInit) {
            if (!stepHandshake()) return;
        } else if (m_state == State::FrameLoop) {
            if (!stepFrameLoop()) return;
        } else {
            return;
        }
    }
    // More work to do — reschedule via the event loop so the UI gets
    // a chance to repaint and outbound input events get flushed.
    if (!m_inbox.isEmpty()) {
        QMetaObject::invokeMethod(this, &KvmSession::drainInbox,
                                   Qt::QueuedConnection);
    }
}

bool KvmSession::stepHandshake()
{
    switch (m_state) {
    case State::Version: {
        if (m_inbox.size() < 12) return false;
        m_inbox.remove(0, 12);
        writeFrame(buildVersionResponse());
        setState(State::Security);
        return true;
    }
    case State::Security: {
        const int n = tryParseSecurityTypes(m_inbox);
        if (n == 0) return false;
        m_inbox.remove(0, n);
        writeFrame(buildSecurityChoice());
        setState(State::AuthResult);
        return true;
    }
    case State::AuthResult: {
        int consumed = 0;
        // tryParseSecurityResult returns false ONLY when there aren't
        // enough bytes OR when the status word is non-zero. Distinguish
        // those by inspecting `consumed`.
        const bool ok = tryParseSecurityResult(m_inbox, &consumed);
        if (consumed == 0) return false;
        if (!ok) {
            fail(QStringLiteral("KVM auth result failed"));
            return false;
        }
        m_inbox.remove(0, consumed);
        writeFrame(buildClientInit());
        setState(State::ServerInit);
        return true;
    }
    case State::ServerInit: {
        ServerInit info;
        int consumed = 0;
        if (!tryParseServerInit(m_inbox, &info, &consumed)) return false;
        m_inbox.remove(0, consumed);
        m_width = info.width;
        m_height = info.height;
        emit desktopResized(m_width, m_height);
        // Pin the wire format before anything else. The decoder follows
        // whatever we pin here; without the pin, firmwares whose
        // ServerInit advertised a different default (e.g. 32-bit BGRA)
        // keep sending pixels in that format and the framebuffer renders
        // black or scrambled (#115).
        if (!negotiatePixelFormat(m_width, m_height)) return false;
        writeFrame(buildSetEncodings());
        // KvmExtCmd 4 toggles zlib on RLE blocks. We enable it by
        // default — the compressed path has been validated against
        // real firmware and the bandwidth win on slow links is
        // significant. `QUMESH_KVM_COMPRESSION=0` is a kill switch
        // for any future hardware that misbehaves with compression
        // on; the variable is intended to retire after a release or
        // two. Older AMT versions silently ignore the frame either
        // way — it looks like a ClientCutText.
        writeFrame(buildKvmExtCmd(4, m_compressionEnabled ? 1 : 0));
        writeFrame(buildFramebufferUpdateRequest(false, 0, 0, m_width, m_height));
        setState(State::FrameLoop);
        return true;
    }
    default:
        return false;
    }
}

bool KvmSession::stepFrameLoop()
{
    if (m_pendingRects > 0) {
        RectHeader rect;
        int rectConsumed = 0;
        if (!tryParseRectHeader(m_inbox, &rect, &rectConsumed)) return false;
        QByteArrayView payload(m_inbox.data() + rectConsumed,
                                m_inbox.size() - rectConsumed);

        DecodedRect dr;
        int payloadConsumed = 0;
        const DecodeStatus s = tryDecodeRect(payload, rect, &dr,
                                              &payloadConsumed, &m_inflate,
                                              m_format);
        if (s == DecodeStatus::NeedMore) return false;
        if (s == DecodeStatus::UnsupportedEncoding) {
            fail(QStringLiteral("unsupported KVM encoding %1").arg(rect.encoding));
            return false;
        }
        if (s == DecodeStatus::UnsupportedSubencoding) {
            fail(QStringLiteral("unsupported KVM RLE subencoding"));
            return false;
        }
        if (s == DecodeStatus::Malformed) {
            fail(QStringLiteral("malformed KVM rect (encoding %1)").arg(rect.encoding));
            return false;
        }

        if (dr.isDesktopSize) {
            const bool sizeChanged = (rect.w != m_width || rect.h != m_height);
            m_width = rect.w;
            m_height = rect.h;
            emit desktopResized(m_width, m_height);
            // A resize changes the display-buffer arithmetic, so the
            // format that fitted the old desktop may not fit this one.
            // Re-negotiate before asking for pixels, then force a full
            // repaint — an incremental request against a
            // freshly-resized framebuffer leaves the screen stale.
            // Only when the size really changed: some firmwares answer
            // every SetPixelFormat with a DesktopSize of the same
            // dimensions, and re-negotiating on those loops forever
            // without a single pixel rect arriving.
            if (sizeChanged && !negotiatePixelFormat(m_width, m_height)) return false;
            m_inbox.remove(0, rectConsumed + payloadConsumed);
            --m_pendingRects;
            if (m_pendingRects == 0)
                writeFrame(buildFramebufferUpdateRequest(false, 0, 0, m_width, m_height));
            return true;
        } else if (!dr.image.isNull()) {
            emit tileUpdated(rect.x, rect.y, dr.image);
        }

        m_inbox.remove(0, rectConsumed + payloadConsumed);
        --m_pendingRects;

        if (m_pendingRects == 0) requestIncremental();
        return true;
    }

    if (m_inbox.isEmpty()) return false;
    const unsigned char tag = static_cast<unsigned char>(m_inbox.at(0));

    if (tag == MsgFramebufferUpdate) {
        FrameUpdateHeader hdr;
        int consumed = 0;
        if (!tryParseFrameUpdate(m_inbox, &hdr, &consumed)) return false;
        m_inbox.remove(0, consumed);
        m_pendingRects = hdr.numRects;
        return true;
    }
    if (tag == MsgBell) {
        m_inbox.remove(0, 1);
        emit bell();
        return true;
    }
    if (tag == MsgServerCutText) {
        // 1 tag + 3 padding + u32 length + bytes; we just consume it.
        // Cap len at 1 MB — far over any realistic clipboard payload —
        // so a wire-supplied 4 GB length can't sign-overflow the
        // `static_cast<int>` and cause an OOB read at the `remove()`
        // call below. See #271.
        constexpr quint32 kServerCutTextMax = 1u * 1024u * 1024u;
        if (m_inbox.size() < 8) return false;
        const quint32 len = (static_cast<quint32>(static_cast<unsigned char>(m_inbox.at(4))) << 24)
                          | (static_cast<quint32>(static_cast<unsigned char>(m_inbox.at(5))) << 16)
                          | (static_cast<quint32>(static_cast<unsigned char>(m_inbox.at(6))) << 8)
                          | static_cast<quint32>(static_cast<unsigned char>(m_inbox.at(7)));
        if (len > kServerCutTextMax) {
            fail(QStringLiteral("ServerCutText length too large: %1").arg(len));
            return false;
        }
        if (m_inbox.size() < qsizetype(8) + qsizetype(len)) return false;
        m_inbox.remove(0, qsizetype(8) + qsizetype(len));
        return true;
    }

    fail(QStringLiteral("unknown KVM server message 0x%1")
             .arg(tag, 2, 16, QLatin1Char('0')));
    return false;
}

bool KvmSession::negotiatePixelFormat(int w, int h)
{
    if (w <= 0 || h <= 0) return true; // nothing to size yet

    const PixelFormat wanted = m_preferredFormat.value_or(chooseFormatFor(w, h));
    const qint64 needed = displayBufferBytes(wanted, w, h);

    if (needed > kMaxDisplayBufferBytes) {
        // No supported format fits. Fail loudly here rather than
        // writing SetPixelFormat and letting AMT hang up on us — the
        // firmware gives no error, it just closes the socket, which is
        // what made #433 look like a network fault.
        const bool forced = m_preferredFormat.has_value();
        fail(QStringLiteral(
                 "The %1×%2 desktop needs %3 MB of Intel AMT KVM display "
                 "buffer, over the firmware's %4 MB limit%5. Lower the "
                 "target's resolution%6.")
                 .arg(w).arg(h)
                 .arg(needed / 1048576.0, 0, 'f', 1)
                 .arg(kMaxDisplayBufferBytes / 1048576.0, 0, 'f', 1)
                 .arg(forced ? QStringLiteral(" at the colour depth you selected")
                             : QString())
                 .arg(forced ? QStringLiteral(" or switch colour depth back to Auto")
                             : QString()));
        return false;
    }

    const bool changed = (wanted != m_format);
    m_format = wanted;
    qCInfo(lcKvmSession) << "KVM pixel format"
                          << (wanted == PixelFormat::Rgb565 ? "RGB565 (16-bit)"
                                                             : "RGB332 (8-bit)")
                          << "for" << w << "x" << h
                          << "— display buffer" << needed << "of"
                          << kMaxDisplayBufferBytes << "bytes";
    writeFrame(buildSetPixelFormat(m_format));
    if (changed) emit pixelFormatChanged(m_format);
    return true;
}

void KvmSession::requestIncremental()
{
    writeFrame(buildFramebufferUpdateRequest(true, 0, 0, m_width, m_height));
}

void KvmSession::sendKey(quint32 keysym, bool down)
{
    if (m_state != State::FrameLoop) return;
    writeFrame(buildKeyEvent(keysym, down));
}

void KvmSession::sendPointer(quint8 buttonMask, quint16 x, quint16 y)
{
    if (m_state != State::FrameLoop) return;
    writeFrame(buildPointerEvent(buttonMask, x, y));
}

void KvmSession::sendCtrlAltDel()
{
    constexpr quint32 kCtrl = 0xFFE3;
    constexpr quint32 kAlt  = 0xFFE9;
    constexpr quint32 kDel  = 0xFFFF;
    sendKey(kCtrl, true);
    sendKey(kAlt,  true);
    sendKey(kDel,  true);
    sendKey(kDel,  false);
    sendKey(kAlt,  false);
    sendKey(kCtrl, false);
}

void KvmSession::requestFullRefresh()
{
    if (m_state != State::FrameLoop) return;
    writeFrame(buildFramebufferUpdateRequest(false, 0, 0, m_width, m_height));
}

void KvmSession::setState(State s)
{
    if (s == m_state) return;
    // Version -> Security -> AuthResult -> ServerInit -> FrameLoop is
    // where a KVM session dies *after* redirection already succeeded;
    // the two qCInfo lines below only fire once ServerInit is reached.
    qCDebug(lcKvmSession) << "state" << stateName(m_state) << "->" << stateName(s);
    m_state = s;
    emit stateChanged(s);
}

void KvmSession::fail(QString reason)
{
    m_lastError = std::move(reason);
    qCWarning(lcKvmSession) << "session failed in state" << stateName(m_state)
                             << ":" << m_lastError;
    setState(State::Failed);
    emit closed(m_lastError);
}

void KvmSession::writeFrame(const QByteArray &frame)
{
    if (m_client->writeRaw(frame) <= 0) {
        fail(QStringLiteral("KVM write failed: %1").arg(m_client->lastError()));
    }
}

} // namespace qumesh::kvm
