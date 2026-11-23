// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#pragma once

#include <QByteArray>
#include <QImage>
#include <QObject>
#include <QString>

#include <optional>

#include "kvm/kvm_codec.h"

namespace qumesh::redir {
class RedirectionClient;
}

namespace qumesh::kvm {

/// Drives the AMT KVM (HW remote desktop) protocol on top of an
/// authenticated `RedirectionClient`.
///
/// State machine after `start()`:
///   Version   — waiting for "RFB 003.xxx".
///   Security  — waiting for security types list.
///   AuthResult — waiting for the 4-byte security result.
///   ServerInit — waiting for the desktop dimensions + name.
///   FrameLoop  — running, framebuffer updates flow as tile signals.
class KvmSession : public QObject
{
    Q_OBJECT
public:
    enum class State {
        Idle,
        Version,
        Security,
        AuthResult,
        ServerInit,
        FrameLoop,
        Failed,
    };
    Q_ENUM(State)

    explicit KvmSession(qumesh::redir::RedirectionClient *client,
                         QObject *parent = nullptr);
    ~KvmSession() override;

    [[nodiscard]] State state() const { return m_state; }
    [[nodiscard]] QString lastError() const { return m_lastError; }
    [[nodiscard]] quint16 desktopWidth() const { return m_width; }
    [[nodiscard]] quint16 desktopHeight() const { return m_height; }

    /// The pixel format currently negotiated with the firmware. Only
    /// meaningful from `ServerInit` onwards.
    [[nodiscard]] PixelFormat pixelFormat() const { return m_format; }

    /// Override the automatic pixel-format choice. `std::nullopt` (the
    /// default) means "pick per `chooseFormatFor()`", which keeps 16-bit
    /// colour whenever the desktop fits inside AMT's display buffer and
    /// drops to 8-bit when it doesn't. Forcing `Rgb565` on an
    /// oversized desktop reproduces #433 and is rejected at ServerInit
    /// with a clear error rather than a silent hang-up.
    void setPreferredPixelFormat(std::optional<PixelFormat> f) { m_preferredFormat = f; }

    /// Begin the handshake. Only legal once the underlying client is
    /// `Authenticated`.
    void start();

    /// Send a key press / release using an X11 keysym.
    void sendKey(quint32 keysym, bool down);

    /// Send a pointer event in framebuffer coordinates. `buttonMask`
    /// is a bitmask of currently-held buttons.
    void sendPointer(quint8 buttonMask, quint16 x, quint16 y);

    /// Convenience: emit Ctrl+Alt+Del as a single keystroke burst.
    void sendCtrlAltDel();

    /// Convenience: request the entire desktop be refreshed
    /// (non-incremental). Call after a settings change.
    void requestFullRefresh();

signals:
    void stateChanged(State state);
    void desktopResized(int width, int height);
    /// Emitted whenever the negotiated wire format changes, including
    /// the initial choice at ServerInit. The UI surfaces this so an
    /// automatic drop to 8-bit is visible rather than mysterious.
    void pixelFormatChanged(PixelFormat format);
    void tileUpdated(int x, int y, const QImage &tile);
    void bell();
    void closed(const QString &reason);

private:
    /// Choose + apply the wire pixel format for a `w × h` desktop,
    /// writing SetPixelFormat. Returns false (after calling `fail()`)
    /// when the desktop is too large for AMT's display buffer at any
    /// supported format.
    bool negotiatePixelFormat(int w, int h);
    /// Returns false (after calling `fail()`) when a `w × h` desktop
    /// does not fit AMT's display buffer at the format it would use.
    bool checkDisplayBuffer(int w, int h);
    void onRawBytes(const QByteArray &chunk);
    void drainInbox();
    bool stepHandshake();
    bool stepFrameLoop();
    /// End of an update whose last rect is a DesktopSize, or that
    /// changed the size earlier: re-negotiate if the size changed, then
    /// request a full repaint. Returns false after `fail()`.
    bool finishResizedUpdate();
    void requestIncremental();
    void setState(State s);
    void fail(QString reason);
    void writeFrame(const QByteArray &frame);

    qumesh::redir::RedirectionClient *m_client;
    QByteArray m_inbox;
    State m_state = State::Idle;
    QString m_lastError;

    quint16 m_width = 0;
    quint16 m_height = 0;
    PixelFormat m_format = PixelFormat::Rgb565;
    std::optional<PixelFormat> m_preferredFormat;
    int m_pendingRects = 0;
    bool m_resizedInUpdate = false;   ///< A DesktopSize in this update changed the size.
    InflateStream m_inflate;     ///< Persists across all RLE blocks.

    /// Cached at `start()`. Compression is on by default;
    /// `QUMESH_KVM_COMPRESSION=0` is the kill switch. When `true` the
    /// handshake emits `KvmExtCmd(4, 1)` and AMT may send
    /// zlib-compressed RLE blocks (decoded via `m_inflate`).
    bool m_compressionEnabled = true;
};

} // namespace qumesh::kvm
