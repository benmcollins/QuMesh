// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#pragma once

#include <QImage>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantMap>
#include <QtQmlIntegration>

#include "kvm/kvm_codec.h"
#include "kvmframebuffer.h"
#include "redir/redir_client.h"

#include <optional>

namespace qumesh::kvm {
class KvmSession;
}

namespace qumesh::ssh { class SshSession; }

namespace qumesh::app {

class MjpegMovRecorder;
class SshTunnelHost;

/// QML-creatable controller for one KVM session. Owns the redirection
/// client, the KVM session driver, and the framebuffer the QML viewer
/// renders.
class KvmController : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QString host READ host WRITE setHost NOTIFY hostChanged)
    Q_PROPERTY(QString user READ user WRITE setUser NOTIFY userChanged)
    Q_PROPERTY(QString password READ password WRITE setPassword NOTIFY passwordChanged)
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)
    Q_PROPERTY(int desktopWidth READ desktopWidth NOTIFY desktopResized)
    Q_PROPERTY(int desktopHeight READ desktopHeight NOTIFY desktopResized)
    Q_PROPERTY(KvmFramebuffer *framebuffer READ framebuffer CONSTANT)
    Q_PROPERTY(bool tls READ tls WRITE setTls NOTIFY tlsChanged)
    Q_PROPERTY(QStringList trustedFingerprints READ trustedFingerprints
                   WRITE setTrustedFingerprints NOTIFY trustedFingerprintsChanged)
    Q_PROPERTY(QString pendingCertSubject READ pendingCertSubject NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertIssuer READ pendingCertIssuer NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertFingerprint READ pendingCertFingerprint NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertNotBefore READ pendingCertNotBefore NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertNotAfter READ pendingCertNotAfter NOTIFY pendingCertChanged)
    Q_PROPERTY(bool awaitingTrust READ awaitingTrust NOTIFY awaitingTrustChanged)
    Q_PROPERTY(bool recording READ isRecording NOTIFY recordingChanged)
    /// Operator's colour-depth preference: 0 = Auto, 1 = force 16-bit
    /// RGB565, 2 = force 8-bit RGB332. Auto keeps 16-bit whenever the
    /// desktop fits inside AMT's KVM display buffer and drops to 8-bit
    /// when it doesn't — a 4K target needs 8-bit (#433).
    Q_PROPERTY(int colorDepthMode READ colorDepthMode WRITE setColorDepthMode
                   NOTIFY colorDepthChanged)
    /// True when the live session negotiated 8-bit colour. The panel
    /// shows this so an automatic drop is visible rather than looking
    /// like a rendering bug.
    Q_PROPERTY(bool eightBitColor READ eightBitColor NOTIFY colorDepthChanged)
    /// True while connected with a `colorDepthMode` this session did not
    /// open with. The mode applies on the next connection: switching
    /// live would race the rects already in flight at the old depth.
    Q_PROPERTY(bool colorDepthPending READ colorDepthPending NOTIFY colorDepthChanged)

    // SSH host-key prompt — see `SshHostKeyTrustDialog.qml`. Bound
    // when the per-machine SSH tunnel encounters an unpinned key.
    Q_PROPERTY(bool awaitingSshHostKeyTrust READ awaitingSshHostKeyTrust
                   NOTIFY sshHostKeyPromptChanged)
    Q_PROPERTY(QString pendingSshHostKeyFingerprint READ pendingSshHostKeyFingerprint
                   NOTIFY sshHostKeyPromptChanged)
    Q_PROPERTY(QString pendingSshHostKeyType READ pendingSshHostKeyType
                   NOTIFY sshHostKeyPromptChanged)

public:
    enum class State {
        Disconnected,
        Connecting,
        Authenticating,
        AwaitingTrust,
        Negotiating,
        Connected,
        Failed,
    };
    Q_ENUM(State)

    explicit KvmController(QObject *parent = nullptr);
    ~KvmController() override;

    [[nodiscard]] QString host() const { return m_host; }
    [[nodiscard]] QString user() const { return m_user; }
    [[nodiscard]] QString password() const { return m_password; }
    [[nodiscard]] State state() const { return m_state; }
    [[nodiscard]] QString lastError() const { return m_lastError; }
    [[nodiscard]] int desktopWidth() const { return m_width; }
    [[nodiscard]] int desktopHeight() const { return m_height; }
    [[nodiscard]] KvmFramebuffer *framebuffer() const { return m_framebuffer; }
    [[nodiscard]] bool tls() const { return m_tls; }
    [[nodiscard]] QStringList trustedFingerprints() const { return m_trustedFingerprints; }
    [[nodiscard]] bool awaitingTrust() const { return m_state == State::AwaitingTrust; }
    [[nodiscard]] QString pendingCertSubject() const { return m_pendingCert.subject; }
    [[nodiscard]] QString pendingCertIssuer() const { return m_pendingCert.issuer; }
    [[nodiscard]] QString pendingCertFingerprint() const { return m_pendingCert.fingerprintSha256; }
    [[nodiscard]] QString pendingCertNotBefore() const { return m_pendingCert.notBefore; }
    [[nodiscard]] QString pendingCertNotAfter() const { return m_pendingCert.notAfter; }
    [[nodiscard]] bool isRecording() const;
    [[nodiscard]] bool awaitingSshHostKeyTrust() const { return m_awaitingSshHostKeyTrust; }
    [[nodiscard]] QString pendingSshHostKeyFingerprint() const { return m_pendingSshHostKey; }
    [[nodiscard]] QString pendingSshHostKeyType() const { return m_pendingSshHostKeyType; }

    void setHost(const QString &v);
    /// Override the redirection port. Tests only — production derives
    /// 16994 / 16995 from `tls`. Not exposed to QML.
    void setPortForTest(quint16 v) { m_portOverride = v; }
    void setUser(const QString &v);
    void setPassword(const QString &v);
    void setTls(bool v);
    void setTrustedFingerprints(QStringList v);
    void setSshSession(qumesh::ssh::SshSession *session) { m_sshSession = session; }

    /// QML-friendly: take the per-machine SSH config (as produced by
    /// `ComputerModel::sshConfigFor`). When enabled, the controller
    /// owns an `SshTunnelHost` that opens the session lazily; `open()`
    /// then waits for the session to reach `Connected` before
    /// dialing the AMT host.
    Q_INVOKABLE void setSshConfig(const QVariantMap &cfg);

    Q_INVOKABLE void open();
    Q_INVOKABLE void close();
    Q_INVOKABLE void trustPendingCert(bool persist);
    /// Resolves a pending SSH host-key prompt (see `SshTunnelHost`).
    /// On accept, resumes the paused SSH session; with `persist` also
    /// emits `trustedSshHostKeyAdded` so the QML layer can pin the
    /// fingerprint on the per-machine config.
    Q_INVOKABLE void trustPendingSshHostKey(bool persist);
    Q_INVOKABLE void sendCtrlAltDel();
    /// Send a single key tap (down → up) by X11 keysym.
    Q_INVOKABLE void sendKeyTap(quint32 keysym);
    /// Press/release one key. `down=true` for press.
    Q_INVOKABLE void sendKey(quint32 keysym, bool down);
    /// Mouse pointer event in framebuffer coordinates.
    Q_INVOKABLE void sendPointer(int buttonMask, int x, int y);
    /// Save the current framebuffer to a PNG file at `path`. Returns
    /// true on success. False if the framebuffer is empty, the path is
    /// empty, or QImage::save fails. `path` is a local filesystem path
    /// (the QML caller converts `FileDialog.selectedFile` first).
    Q_INVOKABLE bool saveScreenshot(const QString &path) const;
    /// Start recording the framebuffer as MJPEG-in-MOV to `path` at
    /// `fps`. The recorder samples the framebuffer on a timer; tiles
    /// arrive at variable rates from the host, so fixed-rate sampling
    /// keeps the MOV's playback timeline honest. Returns true if the
    /// file was opened and the header was written.
    Q_INVOKABLE bool startRecording(const QString &path, int fps = 5);
    /// Stop the in-progress recording and finalise the MOV. Safe to
    /// call when not recording.
    Q_INVOKABLE void stopRecording();

    [[nodiscard]] int colorDepthMode() const { return m_colorDepthMode; }
    void setColorDepthMode(int v);
    [[nodiscard]] bool eightBitColor() const { return m_eightBitColor; }
    [[nodiscard]] bool colorDepthPending() const
    {
        return m_state == State::Connected && m_colorDepthMode != m_sessionColorDepthMode;
    }

signals:
    void hostChanged();
    void userChanged();
    void passwordChanged();
    void stateChanged();
    void lastErrorChanged();
    void desktopResized();
    void tlsChanged();
    void trustedFingerprintsChanged();
    void pendingCertChanged();
    void awaitingTrustChanged();
    void trustedFingerprintAdded(const QString &fingerprint);
    /// Emitted when the per-machine SSH tunnel encounters an unpinned
    /// host key. QML surfaces `SshHostKeyTrustDialog`.
    void sshHostKeyPromptRequired(const QString &fingerprint,
                                   const QString &keyType);
    /// NOTIFY for the `awaitingSshHostKeyTrust` / pending properties.
    void sshHostKeyPromptChanged();
    /// Emitted after `trustPendingSshHostKey(true)` so the QML layer
    /// can persist the fingerprint into ComputerModel.
    void trustedSshHostKeyAdded(const QString &fingerprint);
    /// Forwarded from the underlying client whenever a TLS
    /// reconnect quietly matched a pinned fingerprint. The QML side
    /// uses it to flash a small "verified" badge.
    void peerCertVerifiedByPin(const QString &fingerprint);
    void recordingChanged();
    void colorDepthChanged();

private:
    void setState(State s);
    void setLastError(const QString &e);
    void teardown();

    QString m_host;
    quint16 m_portOverride = 0;
    QString m_user;
    QString m_password;
    State m_state = State::Disconnected;
    QString m_lastError;
    /// Translate `m_colorDepthMode` into what KvmSession expects.
    [[nodiscard]] std::optional<qumesh::kvm::PixelFormat> preferredPixelFormat() const;

    int m_colorDepthMode = 0;   ///< 0 Auto, 1 force 16-bit, 2 force 8-bit.
    int m_sessionColorDepthMode = 0;   ///< The mode the current session opened with.
    bool m_eightBitColor = false;
    int m_width = 0;
    int m_height = 0;
    bool m_tls = false;
    QStringList m_trustedFingerprints;
    qumesh::redir::PeerCertSummary m_pendingCert;

    KvmFramebuffer *m_framebuffer;
    QPointer<qumesh::redir::RedirectionClient> m_client;
    QPointer<qumesh::kvm::KvmSession> m_session;
    qumesh::ssh::SshSession *m_sshSession = nullptr;
    SshTunnelHost *m_sshHost = nullptr;
    bool m_openDeferred = false;
    MjpegMovRecorder *m_recorder = nullptr;
    QTimer m_recordTimer;
    bool m_framebufferDirty = false;

    QString m_pendingSshHostKey;
    QString m_pendingSshHostKeyType;
    bool m_awaitingSshHostKeyTrust = false;
};

} // namespace qumesh::app
