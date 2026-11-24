// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "machinedetailscontroller.h"

#include <QDateTime>
#include <QLoggingCategory>
#include <QFile>
#include <QTimer>
#include <QUrl>

#include "certs/cert_parser.h"
#include "wsman/cert_request_builder.h"
#include "wsman/operations.h"
#include "wsman/wsman_client.h"

#include "ssh/ssh_session.h"
#include "ssh/ssh_tunnel.h"
#include "ssh_tunnel_opener.h"

// Named for the feature rather than the file: this translation unit is
// >4000 lines covering dozens of unrelated WSMAN concerns, and a
// per-file category would become a dumping ground. QtInfoMsg for the
// same reason as redir/src/redir_client.cpp.
Q_LOGGING_CATEGORY(lcOptIn, "qumesh.app.optin", QtInfoMsg)

namespace qumesh::app {

namespace {

const char *optInStateName(int s)
{
    switch (s) {
    case 0: return "NotStarted";
    case 1: return "Requested";
    case 2: return "Displayed";
    case 3: return "Received";
    case 4: return "InSession";
    }
    return "?";
}

} // namespace

MachineDetailsController::MachineDetailsController(QObject *parent)
    : QObject(parent), m_client(new qumesh::wsman::WsmanClient(this))
{
    connect(m_client, &qumesh::wsman::WsmanClient::trustPromptRequired,
            this, &MachineDetailsController::onTrustPromptRequired);
    connect(m_client, &qumesh::wsman::WsmanClient::peerCertVerifiedByPin,
            this, &MachineDetailsController::peerCertVerifiedByPin);
}

MachineDetailsController::~MachineDetailsController() = default;

bool MachineDetailsController::sshTunnelActive() const
{
    return m_sshEnabled
        && m_sshSession != nullptr
        && m_sshSession->state() == qumesh::ssh::SshSession::Connected;
}

void MachineDetailsController::setSshConfig(const QVariantMap &cfg)
{
    const bool enabled = cfg.value(QStringLiteral("enabled")).toBool();
    if (!enabled) {
        m_sshEnabled = false;
        if (m_sshSession != nullptr) {
            m_sshSession->close();
            m_sshSession->deleteLater();
            m_sshSession = nullptr;
        }
        if (m_awaitingSshHostKeyTrust) {
            m_pendingSshHostKey.clear();
            m_pendingSshHostKeyType.clear();
            m_awaitingSshHostKeyTrust = false;
            emit sshHostKeyPromptChanged();
        }
        m_client->setSocketFactory({});
        m_client->setSerializeRequests(false);
        m_sshTunnelStatus.clear();
        emit sshTunnelStateChanged();
        return;
    }

    m_sshEnabled = true;
    m_sshConnecting = true;
    // AMT typically only accepts ~2 concurrent HTTPS WSMAN sessions;
    // over an SSH tunnel the extras silently stall instead of failing
    // fast, so let the WsmanClient single-flight requests while the
    // tunnel is active.
    m_client->setSerializeRequests(true);
    if (m_sshSession == nullptr) {
        m_sshSession = new qumesh::ssh::SshSession(this);
        connect(m_sshSession, &qumesh::ssh::SshSession::stateChanged, this,
                [this](qumesh::ssh::SshSession::State s) {
                    switch (s) {
                    case qumesh::ssh::SshSession::Connecting:
                        m_sshTunnelStatus = QStringLiteral("Connecting…"); break;
                    case qumesh::ssh::SshSession::Authenticating:
                        m_sshTunnelStatus = QStringLiteral("Authenticating…"); break;
                    case qumesh::ssh::SshSession::NeedsHostKeyTrust:
                        m_sshTunnelStatus = QStringLiteral("Awaiting host-key trust"); break;
                    case qumesh::ssh::SshSession::Connected:
                        m_sshTunnelStatus = QStringLiteral("via SSH");
                        m_sshConnecting = false;
                        runPendingRefreshes();
                        break;
                    case qumesh::ssh::SshSession::Failed:
                        m_sshTunnelStatus = QStringLiteral("SSH failed: %1")
                                                .arg(m_sshSession->lastError());
                        m_sshConnecting = false;
                        m_pendingRefreshes = 0;
                        break;
                    case qumesh::ssh::SshSession::Disconnected:
                        m_sshTunnelStatus.clear();
                        m_sshConnecting = false;
                        m_pendingRefreshes = 0;
                        break;
                    }
                    emit sshTunnelStateChanged();
                });
        connect(m_sshSession, &qumesh::ssh::SshSession::hostKeyPromptRequired, this,
                [this](const QString &fp, const QString &keyType) {
                    // SshSession is now paused in `NeedsHostKeyTrust`.
                    // Hold the pending state and surface the prompt to
                    // QML — `SshHostKeyTrustDialog` calls
                    // `trustPendingSshHostKey(persist)` on accept, or
                    // `close()` to abandon. Pre-#270 this auto-pinned
                    // every unknown key (TOFU-every-time), which
                    // silently accepted post-first-connect key
                    // rotation — effectively no MITM defence.
                    m_pendingSshHostKey = fp;
                    m_pendingSshHostKeyType = keyType;
                    m_awaitingSshHostKeyTrust = true;
                    emit sshHostKeyPromptChanged();
                    emit sshHostKeyPromptRequired(fp, keyType);
                });
    }

    qumesh::ssh::SshSession::Params p;
    p.host = cfg.value(QStringLiteral("host")).toString();
    p.port = static_cast<quint16>(cfg.value(QStringLiteral("port"), 22).toInt());
    p.user = cfg.value(QStringLiteral("user")).toString();
    p.authMode = cfg.value(QStringLiteral("authMode")).toInt()
                     == int(qumesh::ssh::SshSession::AuthKey)
                     ? qumesh::ssh::SshSession::AuthKey
                     : qumesh::ssh::SshSession::AuthPassword;
    p.password = cfg.value(QStringLiteral("password")).toString();
    p.privateKeyPath = cfg.value(QStringLiteral("keyPath")).toString();
    p.privateKeyPassphrase = cfg.value(QStringLiteral("keyPassphrase")).toString();
    const QVariantList fps = cfg.value(QStringLiteral("trustedHostKeyFingerprints"))
                                  .toList();
    for (const QVariant &v : fps) p.trustedHostKeyFingerprints.append(v.toString());

    // Each WSMAN request opens a fresh SshTunnel; the channel is short-
    // lived (the WsmanClient closes the socket once the response body
    // is consumed). Channel-create cost over an already-authenticated
    // SSH session is ~1 ms, well below user-perceptible.
    m_client->setSocketFactory(makeSshSocketFactory(
        m_sshSession, m_host,
        static_cast<quint16>(m_tls ? 16993 : 16992)));

    m_sshSession->open(p);
    emit sshTunnelStateChanged();
}

void MachineDetailsController::trustPendingSshHostKey(bool persist)
{
    if (!m_awaitingSshHostKeyTrust) return;
    const QString fp = m_pendingSshHostKey;
    m_pendingSshHostKey.clear();
    m_pendingSshHostKeyType.clear();
    m_awaitingSshHostKeyTrust = false;
    emit sshHostKeyPromptChanged();
    if (m_sshSession != nullptr) m_sshSession->trustPendingHostKey();
    if (persist) emit trustedSshHostKeyAdded(fp);
}

bool MachineDetailsController::deferIfSshConnecting(PendingRefresh kind)
{
    if (!m_sshConnecting) return false;
    m_pendingRefreshes |= kind;
    return true;
}

void MachineDetailsController::runPendingRefreshes()
{
    const int p = m_pendingRefreshes;
    m_pendingRefreshes = 0;
    if (p & PendingOverview)     refreshOverview();
    if (p & PendingPower)        refreshPower();
    if (p & PendingNetwork)      refreshNetwork();
    if (p & PendingTime)         refreshTime();
    if (p & PendingEventLog)     refreshEventLog();
    if (p & PendingUserAccounts) refreshUserAccounts();
    if (p & PendingHardware)     refreshHardware();
    if (p & PendingAuditLog)     refreshAuditLog();
    if (p & PendingActiveSessions) refreshActiveSessions();
    if (p & PendingDeviceCerts)  refreshDeviceCerts();
    if (p & PendingRemoteAccess) refreshRemoteAccess();
    if (p & PendingWireless)     refreshWireless();
    if (p & PendingAgentPresence) refreshAgentPresence();
    if (p & PendingEventSubscriptions) refreshEventSubscriptions();
    if (p & PendingWakeAlarms)   refreshWakeAlarms();
    if (p & PendingSystemDefense) refreshSystemDefense();
}

void MachineDetailsController::setHost(const QString &v)
{
    if (v == m_host) return;
    m_host = v;
    emit hostChanged();
    rebuildEndpoint();
}

void MachineDetailsController::setUser(const QString &v)
{
    if (v == m_user) return;
    m_user = v;
    emit userChanged();
    m_client->setCredentials(m_user, m_password);
}

void MachineDetailsController::setPassword(const QString &v)
{
    if (v == m_password) return;
    m_password = v;
    emit passwordChanged();
    m_client->setCredentials(m_user, m_password);
}

void MachineDetailsController::setTls(bool v)
{
    if (v == m_tls) return;
    m_tls = v;
    emit tlsChanged();
    rebuildEndpoint();
}

void MachineDetailsController::setTrustedFingerprints(QStringList v)
{
    if (v == m_trustedFingerprints) return;
    m_trustedFingerprints = std::move(v);
    m_client->setTrustedFingerprints(m_trustedFingerprints);
    emit trustedFingerprintsChanged();
}

QString MachineDetailsController::powerSourceLabel() const
{
    switch (m_powerSource) {
    case 0:  return QStringLiteral("Plugged-in");
    case 1:  return QStringLiteral("On battery");
    default: return QStringLiteral("(unknown)");
    }
}

QString MachineDetailsController::provisioningModeLabel() const
{
    // Mirrors `legacy/source/Commander.htm` line ~45371. Mode 4 = CCM,
    // anything else (typically 1/2/3) at state 2 = ACM.
    if (m_provisioningState != 2) return QStringLiteral("Pre-provisioning");
    return m_provisioningMode == 4
        ? QStringLiteral("Activated in CCM")
        : QStringLiteral("Activated in ACM");
}

QString MachineDetailsController::powerStateLabel() const
{
    switch (m_powerState) {
    case 0:  return QStringLiteral("Unknown");
    case 2:  return QStringLiteral("On");
    case 3:  return QStringLiteral("Standby (light)");
    case 4:  return QStringLiteral("Standby (deep)");
    case 6:  return QStringLiteral("Off (soft)");
    case 7:  return QStringLiteral("Hibernate");
    case 8:  return QStringLiteral("Off (hard)");
    case 9:  return QStringLiteral("Power cycle");
    case 13: return QStringLiteral("Standby");
    case 14: return QStringLiteral("Standby");
    default: return QStringLiteral("Power state %1").arg(m_powerState);
    }
}

void MachineDetailsController::rebuildEndpoint()
{
    if (m_host.isEmpty()) return;
    QUrl url;
    url.setScheme(m_tls ? QStringLiteral("https") : QStringLiteral("http"));
    url.setHost(m_host);
    // AMT WSMAN: 16992 plain / 16993 TLS — fixed by the protocol.
    // Tests point this at a local fake endpoint; production always
    // derives from `m_tls`.
    url.setPort(m_portOverride != 0 ? m_portOverride : (m_tls ? 16993 : 16992));
    url.setPath(QStringLiteral("/wsman"));
    m_client->setEndpoint(url);
    m_client->setCredentials(m_user, m_password);
    m_client->setTrustedFingerprints(m_trustedFingerprints);
}

void MachineDetailsController::onTrustPromptRequired(
        const qumesh::wsman::PeerCertSummary &s)
{
    m_pendingCert = s;
    if (!m_awaitingTrust) {
        m_awaitingTrust = true;
        emit awaitingTrustChanged();
    }
    emit pendingCertChanged();
    // Suppress the SSL-handshake error message from the failed reply
    // — the trust dialog is more informative than "SSL handshake
    // failed: hostname mismatch".
    if (!m_lastError.isEmpty()) {
        m_lastError.clear();
        emit lastErrorChanged();
    }
}

void MachineDetailsController::close()
{
    if (m_awaitingTrust) {
        m_pendingCert = {};
        m_awaitingTrust = false;
        emit awaitingTrustChanged();
        emit pendingCertChanged();
    }
    m_pendingTrustResume = nullptr;
    emit closeRequested();
}

void MachineDetailsController::trustPendingCert(bool persist)
{
    if (!m_awaitingTrust) return;
    const QString fp = m_pendingCert.fingerprintSha256;
    m_client->trustPendingPeerCert();
    if (!m_trustedFingerprints.contains(fp)) {
        m_trustedFingerprints.append(fp);
        emit trustedFingerprintsChanged();
    }
    m_pendingCert = {};
    m_awaitingTrust = false;
    emit awaitingTrustChanged();
    emit pendingCertChanged();
    if (persist && !fp.isEmpty()) emit trustedFingerprintAdded(fp);

    // Resume whatever fetch was in flight when the prompt fired.
    // Move-take so a re-entry through the resumed refresh (which
    // re-sets m_pendingTrustResume to itself) doesn't loop.
    if (auto fn = std::move(m_pendingTrustResume)) {
        fn();
    } else {
        // No fetch was in flight — restart the overview, which is the
        // section we open on first connect.
        refreshOverview();
    }
}

void MachineDetailsController::incInflight()
{
    const bool was = busy();
    ++m_inflight;
    if (busy() != was) emit busyChanged();
}

void MachineDetailsController::decInflight()
{
    const bool was = busy();
    if (m_inflight > 0) --m_inflight;
    if (busy() != was) emit busyChanged();
}

void MachineDetailsController::setLastError(const QString &e)
{
    // While we're prompting for trust the failed reply's "SSL handshake
    // failed" text is noisier than the dialog itself; drop it.
    QString filtered = e;
    if (m_awaitingTrust && filtered.contains(QStringLiteral("SSL")))
        filtered.clear();
    if (filtered == m_lastError) return;
    m_lastError = filtered;
    emit lastErrorChanged();
}

void MachineDetailsController::refreshOverview()
{
    if (deferIfSshConnecting(PendingOverview)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    setLastError({});
    m_pendingTrustResume = [this]{ refreshOverview(); };

    // identify — no credentials required.
    incInflight();
    qumesh::wsman::identify(m_client, [this](qumesh::wsman::IdentifyResult r) {
        if (r.ok) {
            m_amtProtocolVersion = r.protocolVersion;
            m_amtVendor          = r.productVendor;
            m_amtVersion         = r.productVersion;
            emit identifyChanged();
        } else if (!r.error.isEmpty()) {
            setLastError(QStringLiteral("Identify: %1").arg(r.error));
        }
        decInflight();
    });

    incInflight();
    qumesh::wsman::getPowerState(m_client, [this](qumesh::wsman::PowerStateResult r) {
        if (r.ok) {
            if (m_powerState != r.powerState) {
                m_powerState = r.powerState;
                emit powerStateChanged();
            }
        } else if (!r.error.isEmpty()) {
            setLastError(QStringLiteral("Power: %1").arg(r.error));
        }
        decInflight();
    });

    incInflight();
    qumesh::wsman::getGeneralSettings(m_client,
        [this](qumesh::wsman::GeneralSettingsResult r) {
            if (r.ok) {
                m_hostName     = r.hostName;
                m_domainName   = r.domainName;
                m_digestRealm  = r.digestRealm;
                m_networkInterfaceEnabled = r.networkInterfaceEnabled;
                m_rmcpPingResponseEnabled = r.rmcpPingResponseEnabled;
                m_powerSource  = r.powerSource;
                emit generalSettingsChanged();
            } else if (!r.error.isEmpty()) {
                setLastError(QStringLiteral("GeneralSettings: %1").arg(r.error));
            }
            decInflight();
        });

    incInflight();
    qumesh::wsman::getMeVersion(m_client,
        [this](qumesh::wsman::MeVersionResult r) {
            if (r.ok) {
                m_meVersionString = r.versionString;

                // Build the fingerprint snapshot (#174). The Sku field
                // is a numeric bitmask string when present; decode the
                // single bit that distinguishes "Full AMT" from "ISM"
                // so the UI can render a friendly label without needing
                // to know the encoding.
                QVariantMap fp;
                fp.insert(QStringLiteral("amtVersion"),      r.versionString);
                fp.insert(QStringLiteral("buildNumber"),     r.buildNumber);
                fp.insert(QStringLiteral("recoveryVersion"), r.recoveryVersion);
                fp.insert(QStringLiteral("sku"),             r.sku);
                fp.insert(QStringLiteral("vendorId"),        r.vendorId);
                fp.insert(QStringLiteral("flash"),           r.flash);

                // SKU bitmask: bit 14 = ISM ("Intel Standard Manageability"),
                // bit 15 = AMT (full vPro). When both are clear we have
                // pre-provisioning / unprovisioned firmware. Older
                // firmware reports the field as a plain string we can't
                // decode — fall through to "(SKU code: X)" then.
                bool numeric = false;
                const quint64 skuMask = r.sku.toULongLong(&numeric);
                QString skuLabel;
                if (numeric) {
                    constexpr quint64 kAmtBit = 1ULL << 15;
                    constexpr quint64 kIsmBit = 1ULL << 14;
                    if (skuMask & kAmtBit)      skuLabel = tr("Full AMT (vPro)");
                    else if (skuMask & kIsmBit) skuLabel = tr("Intel Standard Manageability (ISM)");
                    else                        skuLabel = tr("Pre-provisioning / unknown SKU");
                } else if (!r.sku.isEmpty()) {
                    skuLabel = tr("SKU code: %1").arg(r.sku);
                }
                fp.insert(QStringLiteral("skuLabel"), skuLabel);

                m_amtFingerprint = fp;
                emit meVersionChanged();
            }
            // Soft failure: older firmware may not enumerate
            // CIM_SoftwareIdentity. Leave the previous value in place.
            decInflight();
        });

    incInflight();
    qumesh::wsman::getSetupAndConfiguration(m_client,
        [this](qumesh::wsman::SetupAndConfigResult r) {
            if (r.ok) {
                m_provisioningState = r.provisioningState;
                m_provisioningMode  = r.provisioningMode;
                emit setupConfigChanged();
            }
            // Soft failure: pre-AMT-5 firmware doesn't expose the
            // service. Leave provisioning labels at "Pre-provisioning".
            decInflight();
        });

    incInflight();
    qumesh::wsman::getRedirectionStatus(m_client,
        [this](qumesh::wsman::RedirectionStatusResult r) {
            if (r.ok) {
                m_redirectionListenerEnabled = r.redirectionListenerEnabled;
                m_solEnabled    = r.solEnabled;
                m_iderEnabled   = r.iderEnabled;
                m_kvmEnabled    = r.kvmEnabled;
                m_kvmAvailable  = r.kvmAvailable;
                emit redirectionStatusChanged();
            } else if (!r.error.isEmpty()) {
                setLastError(QStringLiteral("Redirection: %1").arg(r.error));
            }
            decInflight();
        });

    incInflight();
    qumesh::wsman::getComputerSystem(m_client,
        [this](qumesh::wsman::ComputerSystemResult r) {
            if (r.ok) {
                m_systemName        = r.name;
                m_systemElementName = r.elementName;
                m_systemUuid        = r.systemUuid;
                emit computerSystemChanged();
            } else if (!r.error.isEmpty()) {
                setLastError(QStringLiteral("ComputerSystem: %1").arg(r.error));
            }
            decInflight();
        });

    incInflight();
    qumesh::wsman::getBootCapabilities(m_client,
        [this](qumesh::wsman::BootCapabilitiesResult r) {
            if (r.ok) {
                m_capBiosSetup          = r.biosSetup;
                m_capBiosPause          = r.biosPause;
                m_capSecureErase        = r.secureErase;
                m_capPlatformErase      = r.platformErase;
                m_capPlatformEraseMask  = r.platformEraseMask;
                m_capForceUefiHttpsBoot = r.forceUefiHttpsBoot;
                m_capForceWinReBoot      = r.forceWinReBoot;
                m_capForceUefiLocalPbaBoot = r.forceUefiLocalPbaBoot;

                // Keyed snapshot for the read-only Boot Capabilities
                // pane (#172). The QML iterates the map directly so the
                // ordering is preserved by QVariantMap's sort. Labels
                // are derived in QML — keep keys as the raw AMT names.
                QVariantMap bc;
                bc.insert(QStringLiteral("IDER"),                   r.ider);
                bc.insert(QStringLiteral("SOL"),                    r.sol);
                bc.insert(QStringLiteral("BIOSReflash"),            r.biosReflash);
                bc.insert(QStringLiteral("BIOSSetup"),              r.biosSetup);
                bc.insert(QStringLiteral("BIOSPause"),              r.biosPause);
                bc.insert(QStringLiteral("ForcePXEBoot"),           r.forcePxeBoot);
                bc.insert(QStringLiteral("ForceHDDBoot"),           r.forceHddBoot);
                bc.insert(QStringLiteral("ForceCDorDVDBoot"),       r.forceCdOrDvdBoot);
                bc.insert(QStringLiteral("VerbosityScreenBlank"),   r.verbosityScreenBlank);
                bc.insert(QStringLiteral("PowerButtonLock"),        r.powerButtonLock);
                bc.insert(QStringLiteral("ResetButtonLock"),        r.resetButtonLock);
                bc.insert(QStringLiteral("KeyboardLock"),           r.keyboardLock);
                bc.insert(QStringLiteral("SleepButtonLock"),        r.sleepButtonLock);
                bc.insert(QStringLiteral("UserPasswordBypass"),     r.userPasswordBypass);
                bc.insert(QStringLiteral("ForcedProgressEvents"),   r.forcedProgressEvents);
                bc.insert(QStringLiteral("VerbosityVerbose"),       r.verbosityVerbose);
                bc.insert(QStringLiteral("VerbosityQuiet"),         r.verbosityQuiet);
                bc.insert(QStringLiteral("ConfigurationDataReset"), r.configurationDataReset);
                bc.insert(QStringLiteral("BIOSSecureBoot"),         r.biosSecureBoot);
                bc.insert(QStringLiteral("SecureErase"),            r.secureErase);
                bc.insert(QStringLiteral("ForceWinREBoot"),         r.forceWinReBoot);
                bc.insert(QStringLiteral("ForceUEFILocalPBABoot"),  r.forceUefiLocalPbaBoot);
                bc.insert(QStringLiteral("ForceUEFIHTTPSBoot"),     r.forceUefiHttpsBoot);
                bc.insert(QStringLiteral("AMTSecureBootControl"),   r.amtSecureBootControl);
                bc.insert(QStringLiteral("PlatformErase"),          r.platformErase);
                bc.insert(QStringLiteral("PlatformEraseMask"),      static_cast<int>(r.platformEraseMask));
                m_bootCapabilities = bc;

                emit bootCapabilitiesChanged();
            } else if (!r.error.isEmpty()) {
                // Capabilities are advisory — log but don't blame the
                // user. Older firmware may not expose this resource.
                setLastError(QStringLiteral("BootCapabilities: %1").arg(r.error));
            }
            decInflight();
        });

    refreshOptInStatus();
}

void MachineDetailsController::refreshOptInStatus()
{
    if (deferIfSshConnecting(PendingOverview)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) return;
    // Each call is two chained WSMAN GETs on their own connections and
    // AMT accepts very few concurrent sessions. Under the 500 ms poll a
    // slow ME would otherwise stack up generations of in-flight
    // requests until the device stopped answering anything (#433).
    if (m_optInStatusInFlight) return;
    m_optInStatusInFlight = true;
    m_pendingTrustResume = [this]{ refreshOptInStatus(); };
    incInflight();
    const quint64 stateGeneration = m_optInStateGeneration;
    // Only a read sent while polling is known to postdate this round's
    // accepted StartOptIn.
    const quint64 pollRound = m_optInPolling ? m_optInRoundSerial : 0;
    qumesh::wsman::getOptInStatus(m_client,
        [this, stateGeneration, pollRound](qumesh::wsman::OptInServiceResult r) {
            m_optInStatusInFlight = false;
            if (r.ok) {
                const bool wasKnown = m_optInStatusKnown;
                m_optInStatusKnown = true;
                const int prevState = m_optInState;
                // A consent operation was answered while this read was
                // on the wire, or a StartOptIn or CancelOptIn is still
                // unanswered, so its OptInState may predate that change.
                // Writing it back could undo a granted PIN or restore a
                // cancelled consent. An unanswered SendOptInCode does not
                // count: a read sent after it is the fallback that
                // reports the grant if its reply is lost.
                const bool staleState = (stateGeneration != m_optInStateGeneration)
                                        || m_optInRoundOpsInFlight > 0;
                // Even a stale read proves this round reached Displayed.
                if (pollRound != 0 && pollRound == m_optInRoundSerial
                    && r.optInState == 2) {
                    m_optInRoundSawDisplayed = true;
                }
                m_optInRequired         = r.optInRequired;
                m_optInRequiredRaw      = r.optInRequiredRaw;
                if (!staleState) m_optInState = r.optInState;
                m_canModifyOptInPolicy  = r.canModifyOptInPolicy;
                m_kvmOptInPolicy        = r.kvmOptInPolicy;
                m_optInPolicyTimeoutSec = r.optInPolicyTimeoutSec;
                m_kvmIs5900PortEnabled  = r.is5900PortEnabled;
                m_kvmSessionTimeoutMinutes = r.sessionTimeoutMinutes;
                m_kvmGreyscaleRequested = r.greyscalePixelFormatRequested;
                // Guarded on change: startOptInPolling runs this every
                // 500 ms, so an unconditional line would be a firehose.
                // One line per real transition is the whole diagnostic.
                if (m_optInState != prevState || !wasKnown) {
                    qCDebug(lcOptIn) << "OptInState" << optInStateName(prevState)
                                      << "->" << optInStateName(m_optInState)
                                      // The raw tri-state, not the flattened bool: "which
                                      // protocols does this machine gate" is the
                                      // question a consent report actually needs
                                      // answering (#437).
                                      << "- requiredRaw" << m_optInRequiredRaw
                                      << "canModifyPolicy" << m_canModifyOptInPolicy
                                      << "kvmPolicy" << m_kvmOptInPolicy
                                      << "timeout" << m_optInPolicyTimeoutSec << "s";
                }
                emit optInStatusChanged();
                // Drive the polling state machine. See #171: while
                // we're between StartOptIn and SendOptInCode, watch
                // for state transitions caused by the target-side
                // operator (Granted → unblock, NotStarted → cancelled
                // at target).
                if (m_optInPolling && !staleState) {
                    if (m_optInState == 3 || m_optInState == 4) {
                        // RECEIVED or IN_SESSION — consent is satisfied.
                        // Either the code we sent landed, or the operator
                        // approved at the target on firmware that allows
                        // it. Both end the round.
                        endOptInRound();
                        emit optInGranted();
                    } else if ((m_optInRoundSawDisplayed
                                && m_optInState <= 1 /* NotStarted/Requested */)
                               || (m_optInRoundCancelRaced && m_optInState == 0)) {
                        // Target-side operator either cancelled or the
                        // firmware timed out and dropped state back, or
                        // an older CancelOptIn landed after this round's
                        // StartOptIn. Otherwise this round must really
                        // have reached Displayed: Requested on the way up
                        // is not an expiry.
                        endOptInRound();
                        emit optInExpiredOrDenied();
                    }
                }
                // Polling reads again. Otherwise this read was the only
                // answer coming, so replace it.
                if (staleState && !m_optInPolling) requestOptInReread();
            }
            else if (!m_optInStatusKnown) {
                qCWarning(lcOptIn) << "IPS_OptInService unreadable (" << r.error
                                    << ") — treating consent as not required";
                // Soft failure on the FIRST read: older AMT firmware
                // (<= 5) doesn't expose IPS_OptInService at all, and a
                // transport hiccup looks identical from here.
                //
                // Resolve to "consent not required" and mark the status
                // known, so callers gated on `optInStatusKnown` proceed
                // instead of waiting for an answer that will never come.
                // The reference does the same — a non-200 on the
                // IPS_OptInService read calls `connectDesktop(true)`,
                // i.e. connect anyway (Commander.htm:50753). If the
                // firmware really does want consent it enforces that
                // itself; the cost of guessing wrong is the pre-#433
                // behaviour, whereas guessing the other way hangs the
                // Connect button with no error at all.
                m_optInStatusKnown = true;
                m_optInRequired = false;
                emit optInStatusChanged();
                emit optInStatusUnavailable(r.error);
            }
            // A later failure leaves the previously-read values alone —
            // a blip must not downgrade a machine we know needs consent.
            decInflight();
            flushOptInReread();
        });
}

void MachineDetailsController::setKvmOptInPolicyEnabled(bool enabled)
{
    setLastError({});
    incInflight();
    qumesh::wsman::setKvmOptInPolicy(m_client, enabled,
        [this, enabled](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (r.ok) {
                m_kvmOptInPolicy = enabled;
                emit optInStatusChanged();
                // Re-read the runtime fields too — disabling the
                // policy flips `OptInRequired` back to false.
                refreshOptInStatus();
            } else {
                emit optInPolicyChangeFailed(r.error);
            }
        });
}

void MachineDetailsController::setKvmSettings(const QVariantMap &fields)
{
    // Keys only. `fields["rfbPassword"]` is the RFB/VNC password being
    // written to the firmware; "which knobs did the app try to change"
    // is all a diagnosis needs.
    qCInfo(lcOptIn) << "KVM settings patch, fields:" << fields.keys();
    setLastError({});
    qumesh::wsman::KvmSettingsPatch patch;
    if (fields.contains(QStringLiteral("optInPolicy"))) {
        patch.setOptInPolicy = true;
        patch.optInPolicy = fields.value(QStringLiteral("optInPolicy")).toBool();
    }
    if (fields.contains(QStringLiteral("is5900PortEnabled"))) {
        patch.setIs5900PortEnabled = true;
        patch.is5900PortEnabled = fields.value(QStringLiteral("is5900PortEnabled")).toBool();
    }
    if (fields.contains(QStringLiteral("sessionTimeoutMinutes"))) {
        patch.setSessionTimeoutMinutes = true;
        patch.sessionTimeoutMinutes = fields.value(QStringLiteral("sessionTimeoutMinutes")).toInt();
    }
    if (fields.contains(QStringLiteral("rfbPassword"))) {
        patch.setRfbPassword = true;
        patch.rfbPassword = fields.value(QStringLiteral("rfbPassword")).toString();
    }
    if (fields.contains(QStringLiteral("greyscaleRequested"))) {
        patch.setGreyscaleRequested = true;
        patch.greyscaleRequested = fields.value(QStringLiteral("greyscaleRequested")).toBool();
    }
    incInflight();
    qumesh::wsman::setKvmSettings(m_client, patch,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("KVM settings: %1").arg(r.error));
            // Re-read so the read-only QML bindings reflect the
            // firmware's reality (which may have clamped values).
            refreshOptInStatus();
        });
}

void MachineDetailsController::setKvmServiceEnabled(bool enabled)
{
    setLastError({});
    incInflight();
    qumesh::wsman::setKvmRedirectionEnabled(m_client, enabled,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("KVM enable/disable: %1").arg(r.error));
            // The redirection-status fields will pick the change up
            // on the next overview refresh.
            refreshOverview();
        });
}

void MachineDetailsController::startOptIn()
{
    // One consent round at a time. Without this latch,
    // startOptIn -> refreshOptInStatus -> optInStatusChanged ->
    // startOptIn is a closed cycle: every round puts a fresh code on
    // the target's screen and opens more WSMAN connections, and the ME
    // stops answering long before the operator can type anything (#433).
    if (m_optInRoundActive) {
        // Both early-outs are #433's own fix, and are now the likeliest
        // cause of "the consent dialog never appeared". A path that
        // returns without doing anything and leaves no trace is exactly
        // what generates a maintainer round-trip.
        qCDebug(lcOptIn) << "StartOptIn skipped: a consent round is already outstanding";
        return;
    }
    if (m_optInFailures >= kMaxOptInFailures) {
        qCWarning(lcOptIn) << "StartOptIn refused: gave up after" << m_optInFailures
                            << "consecutive failures";
        return;
    }
    qCInfo(lcOptIn) << "StartOptIn invoked";
    setOptInRoundActive(true);
    const quint64 round = ++m_optInRoundSerial;
    m_optInRoundSawDisplayed = false;
    m_optInRoundCancelRaced = false;
    ++m_optInRoundOpsInFlight;
    incInflight();
    qumesh::wsman::startOptIn(m_client,
        [this, round](qumesh::wsman::InvokeResult r) {
            decInflight();
            endOptInRoundOp();
            // A round that has ended must stay silent: optInStarted opens
            // the consent dialog, and a late failure would release the
            // latch of the round that replaced it.
            if (round != m_optInRoundSerial) {
                qCDebug(lcOptIn) << "ignoring StartOptIn reply for a round that has ended";
                return;
            }
            if (r.ok) {
                qCInfo(lcOptIn) << "StartOptIn accepted — a code is on the "
                                    "target's screen; polling for the result";
                m_optInFailures = 0;
                emit optInStarted(true, QString());
                startOptInPolling();
                // Deliberately no refreshOptInStatus() here: the poll
                // timer already re-reads state, and an extra read on
                // this path is what closed the retry loop.
                return;
            }
            qCWarning(lcOptIn) << "StartOptIn failed:" << r.error;
            setOptInRoundActive(false);
            ++m_optInFailures;
            emit optInStarted(false, r.error);
            if (m_optInFailures >= kMaxOptInFailures) {
                emit optInGaveUp(r.error.isEmpty()
                                     ? tr("Intel AMT refused to start user consent.")
                                     : r.error);
            }
        });
}

void MachineDetailsController::sendOptInCode(int code)
{
    // `code` is the one-time consent PIN displayed on the target's
    // screen — a live authorisation secret for the duration of the
    // round. It must never reach a log line users paste publicly.
    qCInfo(lcOptIn) << "SendOptInCode invoked (code redacted)";
    const quint64 round = m_optInRoundSerial;
    incInflight();
    qumesh::wsman::sendOptInCode(m_client, static_cast<quint32>(code),
        [this, round](qumesh::wsman::InvokeResult r) {
            decInflight();
            ++m_optInStateGeneration;
            // The round ended while this reply was on the wire. It must
            // stay silent: optInCodeResult releases the waiting session,
            // and a rejection reopens the dialog. An accepted code may
            // still have moved the firmware, so ask it.
            if (round != m_optInRoundSerial) {
                qCInfo(lcOptIn) << "ignoring consent code reply for a round that has ended";
                if (r.ok) requestOptInReread();
                return;
            }
            if (!r.ok) {
                // Wrong code: the firmware keeps the round open, so
                // stay latched and let the operator retype. Re-opening
                // the modal here would wipe the error and restart the
                // countdown from the full timeout.
                qCWarning(lcOptIn) << "consent code rejected:" << r.error;
                emit optInCodeResult(false, r.error);
                emit optInCodeRejected(r.error);
                return;
            }
            // Accepted. AMT is now at RECEIVED(3) and stays there until
            // a redirection session actually starts — it does NOT reach
            // IN_SESSION(4) on its own, so nothing further is pending.
            qCInfo(lcOptIn) << "consent code accepted — OptInState now Received(3)";
            endOptInRound();
            m_optInFailures = 0;
            m_optInState = 3;
            emit optInStatusChanged();
            emit optInCodeResult(true, QString());
        });
}

void MachineDetailsController::cancelOptIn()
{
    qCInfo(lcOptIn) << "CancelOptIn invoked";
    endOptInRound();
    const quint64 round = m_optInRoundSerial;
    ++m_optInRoundOpsInFlight;
    incInflight();
    qumesh::wsman::cancelOptIn(m_client,
        [this, round](qumesh::wsman::InvokeResult r) {
            decInflight();
            endOptInRoundOp();
            if (!r.ok) {
                // The firmware may still be in the round, or may have
                // accepted a code just before this. Ask it.
                qCWarning(lcOptIn) << "CancelOptIn failed:" << r.error;
                requestOptInReread();
                return;
            }
            // A newer round began while this reply was on the wire
            // (SessionWindow sends cancel and start back to back).
            // Writing NotStarted could erase consent it has gained, but
            // the cancel may also have landed after it, so ask.
            if (round != m_optInRoundSerial) {
                m_optInRoundCancelRaced = true;
                requestOptInReread();
                return;
            }
            // Reflect the firmware's post-cancel state locally without
            // re-entering the status read on this path.
            m_optInState = 0;
            emit optInStatusChanged();
        });
}

void MachineDetailsController::endOptInRoundOp()
{
    --m_optInRoundOpsInFlight;
    ++m_optInStateGeneration;
    flushOptInReread();
}

void MachineDetailsController::endOptInRound()
{
    stopOptInPolling();
    setOptInRoundActive(false);
    ++m_optInRoundSerial;
}

void MachineDetailsController::requestOptInReread()
{
    // Capped per Connect: SessionWindow answers a status change by
    // cancelling a displayed round, so a firmware that keeps refusing
    // the cancel would otherwise loop against the ME (#433).
    if (m_optInRereadPending || m_optInRereads >= kMaxOptInFailures) return;
    m_optInRereadPending = true;
    flushOptInReread();
}

void MachineDetailsController::flushOptInReread()
{
    if (!m_optInRereadPending || m_optInRoundOpsInFlight > 0 || m_optInStatusInFlight) return;
    m_optInRereadPending = false;
    ++m_optInRereads;
    refreshOptInStatus();
}

bool MachineDetailsController::consentRequiredFor(int protocol) const
{
    switch (m_optInRequiredRaw) {
    case 0:
        return false;
    case 1:
        // KVM only. SOL and IDE-R proceed without a prompt.
        return protocol == Kvm;
    default:
        // 0xFFFFFFFF, and anything else non-zero we don't recognise —
        // err toward asking, since a spurious prompt is recoverable and
        // an unprompted session just gets refused by the firmware.
        return true;
    }
}

bool MachineDetailsController::consentSatisfiedFor(int protocol) const
{
    if (!consentRequiredFor(protocol)) return true;
    return m_optInState == 3 || m_optInState == 4;
}

void MachineDetailsController::setOptInRoundActive(bool v)
{
    if (m_optInRoundActive == v) return;
    m_optInRoundActive = v;
    emit optInRoundActiveChanged();
}

void MachineDetailsController::resetOptInAttempts()
{
    m_optInFailures = 0;
    m_optInRereads = 0;
}

void MachineDetailsController::startOptInPolling()
{
    if (m_optInPollTimer == nullptr) {
        m_optInPollTimer = new QTimer(this);
        m_optInPollTimer->setInterval(500);
        // refreshOptInStatus drives the state-transition detection in
        // the getOptInStatus callback above.
        connect(m_optInPollTimer, &QTimer::timeout,
                this, &MachineDetailsController::refreshOptInStatus);
    }
    m_optInPolling = true;
    m_optInPollTimer->start();
}

void MachineDetailsController::stopOptInPolling()
{
    m_optInPolling = false;
    if (m_optInPollTimer != nullptr) m_optInPollTimer->stop();
}


void MachineDetailsController::refreshNetwork()
{
    if (deferIfSshConnecting(PendingNetwork)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshNetwork(); };
    incInflight();
    qumesh::wsman::getEthernetSettings(m_client,
        [this](qumesh::wsman::EthernetSettingsResult r) {
            if (r.ok) {
                m_macAddress     = r.macAddress;
                m_dhcpEnabled    = r.dhcpEnabled;
                m_ipAddress      = r.ipAddress;
                m_subnetMask     = r.subnetMask;
                m_defaultGateway = r.defaultGateway;
                m_primaryDns     = r.primaryDns;
                m_secondaryDns   = r.secondaryDns;

                QVariantList ifaces;
                ifaces.reserve(r.interfaces.size());
                for (const auto &i : r.interfaces) {
                    QVariantMap m;
                    m.insert(QStringLiteral("instanceId"),     i.instanceId);
                    m.insert(QStringLiteral("macAddress"),     i.macAddress);
                    m.insert(QStringLiteral("dhcpEnabled"),    i.dhcpEnabled);
                    m.insert(QStringLiteral("ipSyncEnabled"),  i.ipSyncEnabled);
                    m.insert(QStringLiteral("ipAddress"),      i.ipAddress);
                    m.insert(QStringLiteral("subnetMask"),     i.subnetMask);
                    m.insert(QStringLiteral("defaultGateway"), i.defaultGateway);
                    m.insert(QStringLiteral("primaryDns"),     i.primaryDns);
                    m.insert(QStringLiteral("secondaryDns"),   i.secondaryDns);

                    QVariantList lp;
                    QStringList lpLabels;
                    for (int c : i.linkPolicy) {
                        lp.append(c);
                        lpLabels.append(qumesh::wsman::linkPolicyLabel(c));
                    }
                    m.insert(QStringLiteral("linkPolicy"),      lp);
                    m.insert(QStringLiteral("linkPolicyLabel"), lpLabels.join(", "));

                    QVariantMap v6;
                    v6.insert(QStringLiteral("present"), i.ipv6.present);
                    QVariantList addrs;
                    for (const QString &a : i.ipv6.addresses) addrs.append(a);
                    v6.insert(QStringLiteral("addresses"),     addrs);
                    v6.insert(QStringLiteral("addressesLabel"), i.ipv6.addresses.join(", "));
                    v6.insert(QStringLiteral("defaultRouter"), i.ipv6.defaultRouter);
                    v6.insert(QStringLiteral("primaryDns"),    i.ipv6.primaryDns);
                    v6.insert(QStringLiteral("secondaryDns"),  i.ipv6.secondaryDns);
                    m.insert(QStringLiteral("ipv6"), v6);

                    ifaces.append(m);
                }
                m_networkInterfaces = std::move(ifaces);

                emit ethernetChanged();
            } else if (!r.error.isEmpty()) {
                setLastError(QStringLiteral("Ethernet: %1").arg(r.error));
            }
            decInflight();
        });

}

void MachineDetailsController::refreshTime()
{
    if (deferIfSshConnecting(PendingTime)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshTime(); };
    incInflight();
    qumesh::wsman::getTimeSettings(m_client,
        [this](qumesh::wsman::TimeSettingsResult r) {
            if (r.ok) {
                m_amtEpoch = r.secondsSinceEpoch;
                emit timeChanged();
            } else if (!r.error.isEmpty()) {
                setLastError(QStringLiteral("Time: %1").arg(r.error));
            }
            decInflight();

        });
}

void MachineDetailsController::syncDeviceTime()
{
    if (deferIfSshConnecting(PendingTime)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot sync."));
        return;
    }
    incInflight();
    // The 3-point exchange: read Ta0 from the device, record the host
    // clock at receive (Tm1) and send (Tm2 — same instant in this
    // simple flow), then push them back. The firmware uses the gap to
    // compute drift and corrects. After success, re-read to update the
    // skew display.
    qumesh::wsman::getTimeSettings(m_client,
        [this](qumesh::wsman::TimeSettingsResult r) {
            if (!r.ok) {
                if (!r.error.isEmpty())
                    setLastError(QStringLiteral("Time sync (read): %1").arg(r.error));
                decInflight();
                return;
            }
            const qint64 ta0 = r.secondsSinceEpoch;
            const qint64 tmHost = QDateTime::currentSecsSinceEpoch();
            qumesh::wsman::setHighAccuracyTimeSync(m_client, ta0, tmHost, tmHost,
                [this](qumesh::wsman::InvokeResult inv) {
                    if (!inv.ok && !inv.error.isEmpty()) {
                        setLastError(QStringLiteral("Time sync (set): %1").arg(inv.error));
                        decInflight();
                        return;
                    }
                    // Re-read after sync so the QML skew row falls to ~0.
                    qumesh::wsman::getTimeSettings(m_client,
                        [this](qumesh::wsman::TimeSettingsResult rr) {
                            if (rr.ok) {
                                m_amtEpoch = rr.secondsSinceEpoch;
                                emit timeChanged();
                            }
                            decInflight();
                        });
                });
        });
}

void MachineDetailsController::refreshEventLog()
{
    if (deferIfSshConnecting(PendingEventLog)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshEventLog(); };
    incInflight();
    qumesh::wsman::enumerateEventLog(m_client,
        [this](qumesh::wsman::EventLogResult r) {
            decInflight();
            if (!r.ok) {
                if (!r.error.isEmpty())
                    setLastError(QStringLiteral("Event log: %1").arg(r.error));
                return;
            }
            QVariantList list;
            list.reserve(r.entries.size());
            for (const auto &e : r.entries) {
                QVariantMap m;
                m.insert(QStringLiteral("recordId"),    e.recordId);
                m.insert(QStringLiteral("timestamp"),   e.timestamp);
                m.insert(QStringLiteral("severity"),    e.severity);
                m.insert(QStringLiteral("message"),     e.message);
                m.insert(QStringLiteral("entityLabel"), e.entityLabel);
                list.append(m);
            }
            m_eventLog = std::move(list);

            emit eventLogChanged();
        });
}

void MachineDetailsController::refreshHardware()
{
    if (deferIfSshConnecting(PendingHardware)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshHardware(); };
    incInflight();
    qumesh::wsman::getHardwareInventory(m_client,
        [this](qumesh::wsman::HardwareInventoryResult r) {
            decInflight();
            if (!r.ok) {
                if (!r.error.isEmpty())
                    setLastError(QStringLiteral("Hardware: %1").arg(r.error));
                return;
            }
            QVariantMap inv;
            inv.insert(QStringLiteral("platformModel"),        r.platformModel);
            inv.insert(QStringLiteral("platformManufacturer"), r.platformManufacturer);
            inv.insert(QStringLiteral("platformVersion"),      r.platformVersion);
            inv.insert(QStringLiteral("platformSerialNumber"), r.platformSerialNumber);
            inv.insert(QStringLiteral("platformSystemId"),     r.platformSystemId);

            inv.insert(QStringLiteral("baseboardManufacturer"), r.baseboardManufacturer);
            inv.insert(QStringLiteral("baseboardModel"),        r.baseboardModel);
            inv.insert(QStringLiteral("baseboardVersion"),      r.baseboardVersion);
            inv.insert(QStringLiteral("baseboardSerialNumber"), r.baseboardSerialNumber);
            inv.insert(QStringLiteral("baseboardAssetTag"),     r.baseboardAssetTag);
            inv.insert(QStringLiteral("baseboardReplaceable"),  r.baseboardReplaceable);
            inv.insert(QStringLiteral("baseboardCanBeFRUedKnown"),
                                                      r.baseboardCanBeFRUedKnown);

            inv.insert(QStringLiteral("biosVendor"),      r.biosVendor);
            inv.insert(QStringLiteral("biosVersion"),     r.biosVersion);
            inv.insert(QStringLiteral("biosReleaseDate"), r.biosReleaseDate);

            QVariantList cpus;
            for (const auto &c : r.processors) {
                QVariantMap m;
                m.insert(QStringLiteral("manufacturer"), c.manufacturer);
                m.insert(QStringLiteral("version"),      c.version);
                m.insert(QStringLiteral("family"),       c.family);
                m.insert(QStringLiteral("familyLabel"),  c.familyLabel);
                m.insert(QStringLiteral("maxClockSpeedMhz"), c.maxClockSpeedMhz);
                m.insert(QStringLiteral("cpuStatus"),      c.cpuStatus);
                m.insert(QStringLiteral("cpuStatusLabel"), c.cpuStatusLabel);
                cpus.append(m);
            }
            inv.insert(QStringLiteral("processors"), cpus);

            QVariantList dimms;
            for (const auto &d : r.memoryModules) {
                QVariantMap m;
                m.insert(QStringLiteral("bankLabel"),     d.bankLabel);
                m.insert(QStringLiteral("manufacturer"),  d.manufacturer);
                m.insert(QStringLiteral("serialNumber"),  d.serialNumber);
                m.insert(QStringLiteral("capacityBytes"), qlonglong(d.capacityBytes));
                m.insert(QStringLiteral("formFactor"),    d.formFactor);
                m.insert(QStringLiteral("formFactorLabel"), d.formFactorLabel);
                m.insert(QStringLiteral("memoryType"),    d.memoryType);
                m.insert(QStringLiteral("memoryTypeLabel"), d.memoryTypeLabel);
                m.insert(QStringLiteral("assetTag"),      d.assetTag);
                m.insert(QStringLiteral("partNumber"),    d.partNumber);
                dimms.append(m);
            }
            inv.insert(QStringLiteral("memoryModules"), dimms);

            QVariantList storage;
            for (const auto &s : r.storageDevices) {
                QVariantMap m;
                m.insert(QStringLiteral("model"),          s.model);
                m.insert(QStringLiteral("serialNumber"),   s.serialNumber);
                m.insert(QStringLiteral("maxMediaSizeKb"), qlonglong(s.maxMediaSizeKb));
                storage.append(m);
            }
            inv.insert(QStringLiteral("storageDevices"), storage);

            QVariantMap batt;
            batt.insert(QStringLiteral("present"),           r.battery.present);
            batt.insert(QStringLiteral("deviceId"),          r.battery.deviceId);
            batt.insert(QStringLiteral("manufacturer"),      r.battery.manufacturer);
            batt.insert(QStringLiteral("manufactureDate"),   r.battery.manufactureDate);
            batt.insert(QStringLiteral("serialNumber"),      r.battery.serialNumber);
            batt.insert(QStringLiteral("chemistry"),         r.battery.chemistry);
            batt.insert(QStringLiteral("chemistryLabel"),    r.battery.chemistryLabel);
            batt.insert(QStringLiteral("designCapacityMwh"), qlonglong(r.battery.designCapacityMwh));
            batt.insert(QStringLiteral("designVoltageMv"),   qlonglong(r.battery.designVoltageMv));
            batt.insert(QStringLiteral("otherIdentifyingInfo"), r.battery.otherIdentifyingInfo);
            inv.insert(QStringLiteral("battery"), batt);

            m_hardwareInventory = std::move(inv);
            emit hardwareChanged();
        });
}

void MachineDetailsController::refreshWireless()
{
    if (deferIfSshConnecting(PendingWireless)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshWireless(); };
    incInflight();
    qumesh::wsman::getWireless(m_client,
        [this](qumesh::wsman::WirelessResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Wireless: %1").arg(r.error));

            QVariantMap port;
            port.insert(QStringLiteral("present"), r.port.present);
            port.insert(QStringLiteral("portState"), r.port.portState);
            port.insert(QStringLiteral("portStateLabel"),
                        qumesh::wsman::wifiPortStateLabel(r.port.portState));
            port.insert(QStringLiteral("radioState"), r.port.radioState);
            port.insert(QStringLiteral("radioStateLabel"),
                        qumesh::wsman::wifiRadioStateLabel(r.port.radioState));
            port.insert(QStringLiteral("currentSsid"), r.port.currentSsid);
            port.insert(QStringLiteral("localProfileSyncEnabled"),
                        r.port.localProfileSyncEnabled);
            port.insert(QStringLiteral("uefiProfileShareEnabled"),
                        r.port.uefiProfileShareEnabled);

            QVariantList profiles;
            for (const auto &p : r.profiles) {
                QVariantMap m;
                m.insert(QStringLiteral("elementName"), p.elementName);
                m.insert(QStringLiteral("ssid"),        p.ssid);
                m.insert(QStringLiteral("priority"),    p.priority);
                m.insert(QStringLiteral("authMethod"),  p.authenticationMethod);
                m.insert(QStringLiteral("authMethodLabel"),
                         qumesh::wsman::wifiAuthMethodLabel(p.authenticationMethod));
                m.insert(QStringLiteral("encryption"),  p.encryptionMethod);
                m.insert(QStringLiteral("encryptionLabel"),
                         qumesh::wsman::wifiEncryptionLabel(p.encryptionMethod));
                m.insert(QStringLiteral("eap8021xProtocol"), p.eap8021xProtocol);
                m.insert(QStringLiteral("eap8021xProtocolLabel"),
                         p.eap8021xProtocol >= 0
                             ? qumesh::wsman::eap8021xProtocolLabel(p.eap8021xProtocol)
                             : QString());
                profiles.append(m);
            }

            QVariantMap wired;
            wired.insert(QStringLiteral("present"), r.wired.present);
            wired.insert(QStringLiteral("enabled"), r.wired.enabled);
            wired.insert(QStringLiteral("authenticationProtocol"),
                         r.wired.authenticationProtocol);
            wired.insert(QStringLiteral("authProtocolLabel"),
                         r.wired.authenticationProtocol >= 0
                             ? qumesh::wsman::eap8021xProtocolLabel(
                                   r.wired.authenticationProtocol)
                             : QString());

            QVariantMap wl;
            wl.insert(QStringLiteral("ok"),       r.ok);
            wl.insert(QStringLiteral("port"),     port);
            wl.insert(QStringLiteral("profiles"), profiles);
            wl.insert(QStringLiteral("wired"),    wired);
            m_wireless = std::move(wl);
            emit wirelessChanged();
        });
}

namespace {

qumesh::wsman::WiFiPskProfile pskProfileFromMap(const QVariantMap &fields)
{
    qumesh::wsman::WiFiPskProfile p;
    p.elementName = fields.value(QStringLiteral("elementName")).toString();
    p.ssid        = fields.value(QStringLiteral("ssid")).toString();
    p.authenticationMethod =
        fields.value(QStringLiteral("authenticationMethod"), 6).toInt();
    p.encryptionMethod =
        fields.value(QStringLiteral("encryptionMethod"), 4).toInt();
    p.priority = fields.value(QStringLiteral("priority"), 1).toInt();
    p.psk      = fields.value(QStringLiteral("psk")).toString();

    // Phase C (#223) — optional enterprise / EAP fields. The PSK side
    // leaves them at defaults so the wire shape is unchanged.
    p.enterpriseEnabled =
        fields.value(QStringLiteral("enterpriseEnabled"), false).toBool();
    p.authenticationProtocol =
        fields.value(QStringLiteral("authenticationProtocol"), 0).toInt();
    p.eapUsername =
        fields.value(QStringLiteral("eapUsername")).toString();
    p.eapPassword =
        fields.value(QStringLiteral("eapPassword")).toString();
    p.eapServerCertificateName =
        fields.value(QStringLiteral("eapServerCertificateName")).toString();
    p.eapServerCertificateNameComparison =
        fields.value(QStringLiteral("eapServerCertificateNameComparison"), 1).toInt();
    p.clientCertificateInstanceId =
        fields.value(QStringLiteral("clientCertificateInstanceId")).toString();
    p.caCertificateInstanceId =
        fields.value(QStringLiteral("caCertificateInstanceId")).toString();
    return p;
}

} // namespace

void MachineDetailsController::addWiFiPskProfile(const QVariantMap &fields)
{
    setLastError({});
    const auto profile = pskProfileFromMap(fields);
    if (profile.elementName.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Add WiFi: profile name is empty."));
        return;
    }
    if (profile.ssid.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Add WiFi: SSID is empty."));
        return;
    }
    if (!profile.enterpriseEnabled) {
        if (profile.psk.length() < 8) {
            // WPA2/WPA3 PSK is at least 8 chars. Fail fast rather than
            // letting AMT round-trip a vague fault.
            setLastError(QStringLiteral(
                "Add WiFi: PSK must be at least 8 characters."));
            return;
        }
    } else {
        // EAP-TLS (proto 0) requires a client cert; PEAP / TTLS /
        // EAP-FAST (proto 1..5) require username + password. Both
        // benefit from a CA cert for RADIUS-server validation, but
        // the firmware will still accept the profile without one.
        if (profile.authenticationProtocol == 0
            && profile.clientCertificateInstanceId.isEmpty()) {
            setLastError(QStringLiteral(
                "Add WiFi: EAP-TLS requires a client certificate."));
            return;
        }
        if (profile.authenticationProtocol != 0
            && (profile.eapUsername.isEmpty() || profile.eapPassword.isEmpty())) {
            setLastError(QStringLiteral(
                "Add WiFi: PEAP/TTLS/EAP-FAST requires username + password."));
            return;
        }
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add WiFi: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addWiFiSettingsPsk(m_client, profile,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add WiFi: failed.")
                    : QStringLiteral("Add WiFi: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::updateWiFiPskProfile(const QVariantMap &fields)
{
    setLastError({});
    const auto profile = pskProfileFromMap(fields);
    if (profile.elementName.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Update WiFi: profile name is empty."));
        return;
    }
    if (!profile.enterpriseEnabled
        && profile.psk.length() > 0 && profile.psk.length() < 8) {
        setLastError(QStringLiteral(
            "Update WiFi: PSK must be at least 8 characters."));
        return;
    }
    if (profile.enterpriseEnabled) {
        if (profile.authenticationProtocol == 0
            && profile.clientCertificateInstanceId.isEmpty()) {
            setLastError(QStringLiteral(
                "Update WiFi: EAP-TLS requires a client certificate."));
            return;
        }
        if (profile.authenticationProtocol != 0
            && (profile.eapUsername.isEmpty() || profile.eapPassword.isEmpty())) {
            setLastError(QStringLiteral(
                "Update WiFi: PEAP/TTLS/EAP-FAST requires username + password."));
            return;
        }
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Update WiFi: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::updateWiFiSettingsPsk(m_client, profile,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Update WiFi: failed.")
                    : QStringLiteral("Update WiFi: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::deleteWiFiProfile(const QString &elementName)
{
    setLastError({});
    if (elementName.isEmpty()) {
        setLastError(QStringLiteral("Delete WiFi: missing profile name."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete WiFi: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteWiFiProfile(m_client, elementName,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete WiFi: failed.")
                    : QStringLiteral("Delete WiFi: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::deleteAllITWiFiProfiles()
{
    setLastError({});
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Bulk delete: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteAllITWiFiProfiles(m_client,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete IT profiles: failed.")
                    : QStringLiteral("Delete IT profiles: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::deleteAllUserWiFiProfiles()
{
    setLastError({});
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Bulk delete: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteAllUserWiFiProfiles(m_client,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete user profiles: failed.")
                    : QStringLiteral("Delete user profiles: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::setWifiPortEnabled(bool enabled)
{
    setLastError({});
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("WiFi port: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::setWiFiPortState(m_client, enabled,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("WiFi port: failed.")
                    : QStringLiteral("WiFi port: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::setWifiSyncSettings(
    int localProfileSynchronization, int uefiWiFiProfileShare)
{
    setLastError({});
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("WiFi sync: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::setWiFiSyncSettings(m_client,
        localProfileSynchronization, uefiWiFiProfileShare,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("WiFi sync: failed.")
                    : QStringLiteral("WiFi sync: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::setWiredEnterpriseProfile(
    bool enabled, int authenticationProtocol)
{
    setLastError({});
    if (authenticationProtocol < 0 || authenticationProtocol > 5) {
        setLastError(QStringLiteral(
            "Wired 802.1x: authentication protocol %1 is not in 0..5.")
            .arg(authenticationProtocol));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Wired 802.1x: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::setWired8021xProfile(m_client, enabled, authenticationProtocol,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Wired 802.1x: failed.")
                    : QStringLiteral("Wired 802.1x: %1").arg(r.error));
                return;
            }
            refreshWireless();
        });
}

void MachineDetailsController::refreshAgentPresence()
{
    if (deferIfSshConnecting(PendingAgentPresence)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshAgentPresence(); };
    incInflight();
    qumesh::wsman::getAgentPresence(m_client,
        [this](qumesh::wsman::AgentPresenceResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Agent presence: %1").arg(r.error));

            QVariantList watchdogs;
            watchdogs.reserve(r.watchdogs.size());
            for (const auto &w : r.watchdogs) {
                QVariantMap m;
                m.insert(QStringLiteral("deviceIdGuid"),       w.deviceIdGuid);
                m.insert(QStringLiteral("description"),        w.description);
                m.insert(QStringLiteral("monitoredEntity"),    w.monitoredEntityCode);
                m.insert(QStringLiteral("monitoredEntityLabel"), w.monitoredEntityLabel);
                m.insert(QStringLiteral("currentState"),       w.currentStateCode);
                m.insert(QStringLiteral("currentStateLabel"),  w.currentStateLabel);
                m.insert(QStringLiteral("enabledState"),       w.enabledStateCode);
                m.insert(QStringLiteral("enabledStateLabel"),  w.enabledStateLabel);
                m.insert(QStringLiteral("startupIntervalSec"), w.startupIntervalSec);
                m.insert(QStringLiteral("timeoutIntervalSec"), w.timeoutIntervalSec);
                watchdogs.append(m);
            }
            QVariantList actions;
            actions.reserve(r.actions.size());
            for (const auto &a : r.actions) {
                QVariantMap m;
                m.insert(QStringLiteral("watchdogDeviceIdGuid"), a.watchdogDeviceIdGuid);
                m.insert(QStringLiteral("oldState"),             a.oldState);
                m.insert(QStringLiteral("oldStateLabel"),        a.oldStateLabel);
                m.insert(QStringLiteral("newState"),             a.newState);
                m.insert(QStringLiteral("newStateLabel"),        a.newStateLabel);
                m.insert(QStringLiteral("eventOnTransition"),    a.eventOnTransition);
                m.insert(QStringLiteral("actionSac"),            a.actionSac);
                m.insert(QStringLiteral("actionSacLabel"),       a.actionSacLabel);
                m.insert(QStringLiteral("actionEac"),            a.actionEac);
                actions.append(m);
            }
            QVariantMap ap;
            ap.insert(QStringLiteral("ok"),              r.ok);
            ap.insert(QStringLiteral("maxTotalAgents"),  r.maxTotalAgents);
            ap.insert(QStringLiteral("maxTotalActions"), r.maxTotalActions);
            ap.insert(QStringLiteral("watchdogs"),       watchdogs);
            ap.insert(QStringLiteral("actions"),         actions);
            m_agentPresence = std::move(ap);
            emit agentPresenceChanged();
        });
}

namespace {

/// Pull the controller-shaped QVariantMap into a wsman watchdog struct.
/// Centralised so add / replace stay consistent on field names.
qumesh::wsman::AgentPresenceWatchdog watchdogFromFields(const QVariantMap &f)
{
    qumesh::wsman::AgentPresenceWatchdog w;
    w.deviceIdGuid       = f.value(QStringLiteral("deviceIdGuid")).toString().trimmed();
    w.description        = f.value(QStringLiteral("description")).toString().trimmed();
    bool ok = false;
    const int me = f.value(QStringLiteral("monitoredEntityCode")).toInt(&ok);
    w.monitoredEntityCode = ok ? me : -1;
    w.startupIntervalSec = f.value(QStringLiteral("startupIntervalSec")).toInt();
    w.timeoutIntervalSec = f.value(QStringLiteral("timeoutIntervalSec")).toInt();
    return w;
}

} // namespace

void MachineDetailsController::addAgentPresenceWatchdog(const QVariantMap &fields)
{
    setLastError({});
    const auto w = watchdogFromFields(fields);
    if (w.deviceIdGuid.isEmpty()) {
        setLastError(QStringLiteral("Add watchdog: DeviceID is required."));
        return;
    }
    if (w.timeoutIntervalSec <= 0) {
        setLastError(QStringLiteral("Add watchdog: timeout must be > 0 seconds."));
        return;
    }
    // Block at the firmware ceiling so we don't fire a request the
    // device is just going to reject. The cap comes from
    // AMT_AgentPresenceCapabilities (read by refreshAgentPresence).
    const int cap = m_agentPresence.value(QStringLiteral("maxTotalAgents")).toInt();
    const int current = m_agentPresence.value(QStringLiteral("watchdogs")).toList().size();
    if (cap > 0 && current >= cap) {
        setLastError(QStringLiteral("Add watchdog: at the firmware ceiling (%1).").arg(cap));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add watchdog: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::registerWatchdogAgent(m_client, w,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add watchdog: failed.")
                    : QStringLiteral("Add watchdog: %1").arg(r.error));
                return;
            }
            refreshAgentPresence();
        });
}

void MachineDetailsController::deleteAgentPresenceWatchdog(const QString &deviceIdGuid)
{
    setLastError({});
    if (deviceIdGuid.isEmpty()) {
        setLastError(QStringLiteral("Delete watchdog: missing DeviceID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete watchdog: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteAgentPresenceWatchdog(m_client, deviceIdGuid,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete watchdog: failed.")
                    : QStringLiteral("Delete watchdog: %1").arg(r.error));
                return;
            }
            refreshAgentPresence();
        });
}

void MachineDetailsController::replaceAgentPresenceWatchdog(const QString &oldDeviceIdGuid,
                                                              const QVariantMap &fields)
{
    setLastError({});
    if (oldDeviceIdGuid.isEmpty()) {
        // No prior row — fall through to plain add.
        addAgentPresenceWatchdog(fields);
        return;
    }
    const auto w = watchdogFromFields(fields);
    if (w.deviceIdGuid.isEmpty() || w.timeoutIntervalSec <= 0) {
        setLastError(QStringLiteral("Save watchdog: DeviceID and timeout (> 0) are required."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Save watchdog: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteAgentPresenceWatchdog(m_client, oldDeviceIdGuid,
        [this, w](qumesh::wsman::InvokeResult delRes) {
            if (!delRes.ok) {
                decInflight();
                setLastError(delRes.error.isEmpty()
                    ? QStringLiteral("Save watchdog: failed to delete previous row.")
                    : QStringLiteral("Save watchdog: %1").arg(delRes.error));
                return;
            }
            qumesh::wsman::registerWatchdogAgent(m_client, w,
                [this](qumesh::wsman::InvokeResult addRes) {
                    decInflight();
                    if (!addRes.ok) {
                        setLastError(addRes.error.isEmpty()
                            ? QStringLiteral("Save watchdog: previous row was removed but the new one could not be added.")
                            : QStringLiteral("Save watchdog: previous row removed; RegisterAgent: %1").arg(addRes.error));
                        refreshAgentPresence();
                        return;
                    }
                    refreshAgentPresence();
                });
        });
}

void MachineDetailsController::addWatchdogAction(const QVariantMap &fields)
{
    setLastError({});
    const QString deviceId = fields.value(QStringLiteral("watchdogDeviceIdGuid"))
                                   .toString().trimmed();
    if (deviceId.isEmpty()) {
        setLastError(QStringLiteral("Add action: missing watchdog DeviceID."));
        return;
    }
    bool conv = false;
    const int oldState = fields.value(QStringLiteral("oldState")).toInt(&conv);
    if (!conv) {
        setLastError(QStringLiteral("Add action: OldState is required."));
        return;
    }
    conv = false;
    const int newState = fields.value(QStringLiteral("newState")).toInt(&conv);
    if (!conv) {
        setLastError(QStringLiteral("Add action: NewState is required."));
        return;
    }
    conv = false;
    const int actionSac = fields.value(QStringLiteral("actionSac")).toInt(&conv);
    if (!conv) {
        setLastError(QStringLiteral("Add action: action type is required."));
        return;
    }
    int actionEac = -1;
    if (fields.contains(QStringLiteral("actionEac"))) {
        bool eacConv = false;
        const int e = fields.value(QStringLiteral("actionEac")).toInt(&eacConv);
        if (eacConv && e >= 0) actionEac = e;
    }
    const bool eventOnTransition =
        fields.value(QStringLiteral("eventOnTransition")).toBool();

    // Cap-check against the firmware ceiling from
    // AMT_AgentPresenceCapabilities, mirroring the watchdog add path.
    const int cap = m_agentPresence.value(QStringLiteral("maxTotalActions")).toInt();
    const int current = m_agentPresence.value(QStringLiteral("actions")).toList().size();
    if (cap > 0 && current >= cap) {
        setLastError(QStringLiteral("Add action: at the firmware ceiling (%1).").arg(cap));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add action: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addAgentPresenceWatchdogAction(m_client, deviceId,
        oldState, newState, eventOnTransition, actionSac, actionEac,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add action: failed.")
                    : QStringLiteral("Add action: %1").arg(r.error));
                return;
            }
            refreshAgentPresence();
        });
}

void MachineDetailsController::deleteWatchdogAction(const QString &watchdogDeviceIdGuid,
                                                     int oldState, int newState)
{
    setLastError({});
    if (watchdogDeviceIdGuid.isEmpty()) {
        setLastError(QStringLiteral("Delete action: missing watchdog DeviceID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete action: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteAgentPresenceWatchdogAction(m_client,
        watchdogDeviceIdGuid, oldState, newState,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete action: failed.")
                    : QStringLiteral("Delete action: %1").arg(r.error));
                return;
            }
            refreshAgentPresence();
        });
}

void MachineDetailsController::refreshEventSubscriptions()
{
    if (deferIfSshConnecting(PendingEventSubscriptions)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshEventSubscriptions(); };
    incInflight();
    qumesh::wsman::getEventSubscriptions(m_client,
        [this](qumesh::wsman::EventSubscriptionsResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Event subscriptions: %1").arg(r.error));

            QVariantList filters;
            filters.reserve(r.filters.size());
            for (const auto &f : r.filters) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"),     f.instanceId);
                m.insert(QStringLiteral("collectionName"), f.collectionName);
                filters.append(m);
            }
            QVariantList listeners;
            listeners.reserve(r.listeners.size());
            for (const auto &l : r.listeners) {
                QVariantMap m;
                m.insert(QStringLiteral("name"),              l.name);
                m.insert(QStringLiteral("destination"),       l.destination);
                m.insert(QStringLiteral("deliveryMode"),      l.deliveryMode);
                m.insert(QStringLiteral("deliveryModeLabel"), l.deliveryModeLabel);
                listeners.append(m);
            }
            QVariantList subscriptions;
            subscriptions.reserve(r.subscriptions.size());
            for (const auto &s : r.subscriptions) {
                QVariantMap m;
                m.insert(QStringLiteral("filterInstanceId"), s.filterInstanceId);
                m.insert(QStringLiteral("listenerName"),     s.listenerName);
                // Pre-resolve the destination URL + delivery label so
                // the QML can render rows in a single binding without
                // a nested lookup.
                QString dest, deliveryLabel;
                for (const auto &l : r.listeners) {
                    if (l.name == s.listenerName) {
                        dest = l.destination;
                        deliveryLabel = l.deliveryModeLabel;
                        break;
                    }
                }
                m.insert(QStringLiteral("destination"),       dest);
                m.insert(QStringLiteral("deliveryModeLabel"), deliveryLabel);
                subscriptions.append(m);
            }
            QVariantMap es;
            es.insert(QStringLiteral("ok"),            r.ok);
            es.insert(QStringLiteral("filters"),       filters);
            es.insert(QStringLiteral("listeners"),     listeners);
            es.insert(QStringLiteral("subscriptions"), subscriptions);
            m_eventSubscriptions = std::move(es);
            emit eventSubscriptionsChanged();
        });
}

namespace {

/// Render an ISO-8601 duration `PnDTnHnM` (the shape AMT uses for
/// alarm recurrences) into a friendly "every N days N hours N minutes"
/// string. Pieces that are zero are dropped. Returns empty when the
/// input doesn't parse.
QString humanizeIsoDuration(const QString &iso)
{
    if (iso.isEmpty() || !iso.startsWith(QLatin1Char('P'))) return {};
    int days = 0, hours = 0, mins = 0;
    bool conv = false;
    int i = 1; // skip 'P'
    bool inTime = false;
    while (i < iso.size()) {
        if (iso.at(i) == QLatin1Char('T')) { inTime = true; ++i; continue; }
        int j = i;
        while (j < iso.size() && iso.at(j).isDigit()) ++j;
        if (j == i || j >= iso.size()) break;
        const int n = iso.mid(i, j - i).toInt(&conv);
        if (!conv) return {};
        const char16_t unit = iso.at(j).unicode();
        if (!inTime && unit == u'D') days = n;
        else if (inTime && unit == u'H') hours = n;
        else if (inTime && unit == u'M') mins = n;
        i = j + 1;
    }
    QStringList parts;
    if (days  > 0) parts << QObject::tr("%1 day%2").arg(days).arg(days == 1 ? "" : "s");
    if (hours > 0) parts << QObject::tr("%1 hour%2").arg(hours).arg(hours == 1 ? "" : "s");
    if (mins  > 0) parts << QObject::tr("%1 minute%2").arg(mins).arg(mins == 1 ? "" : "s");
    if (parts.isEmpty()) return {};
    return parts.join(QStringLiteral(", "));
}

} // namespace

void MachineDetailsController::subscribeToEventFilter(const QString &filterInstanceId,
                                                       const QString &deliveryMode,
                                                       const QString &notifyUrl,
                                                       const QString &user,
                                                       const QString &pass)
{
    setLastError({});
    if (filterInstanceId.isEmpty()) {
        setLastError(QStringLiteral("Subscribe: filter is required."));
        return;
    }
    if (notifyUrl.isEmpty()
        || !(notifyUrl.startsWith(QStringLiteral("http://"))
              || notifyUrl.startsWith(QStringLiteral("https://")))) {
        setLastError(QStringLiteral("Subscribe: notify URL must be http:// or https://."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Subscribe: host is empty."));
        return;
    }
    const auto mode = deliveryMode.compare(QStringLiteral("Push"), Qt::CaseInsensitive) == 0
        ? qumesh::wsman::EventDeliveryMode::Push
        : qumesh::wsman::EventDeliveryMode::PushWithAck;
    incInflight();
    qumesh::wsman::subscribeToEventFilter(m_client, filterInstanceId, mode,
        notifyUrl, user, pass,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Subscribe: failed.")
                    : QStringLiteral("Subscribe: %1").arg(r.error));
                return;
            }
            refreshEventSubscriptions();
        });
}

void MachineDetailsController::unsubscribeFromEventFilter(const QString &filterInstanceId,
                                                            const QString &listenerName)
{
    setLastError({});
    if (filterInstanceId.isEmpty() || listenerName.isEmpty()) {
        setLastError(QStringLiteral("Unsubscribe: filter and listener are required."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Unsubscribe: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::unsubscribeFromEventFilter(m_client, filterInstanceId, listenerName,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Unsubscribe: failed.")
                    : QStringLiteral("Unsubscribe: %1").arg(r.error));
                return;
            }
            refreshEventSubscriptions();
        });
}

void MachineDetailsController::refreshWakeAlarms()
{
    if (deferIfSshConnecting(PendingWakeAlarms)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshWakeAlarms(); };
    incInflight();
    qumesh::wsman::getWakeAlarms(m_client,
        [this](qumesh::wsman::WakeAlarmsResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Wake alarms: %1").arg(r.error));

            QVariantList list;
            list.reserve(r.alarms.size());
            for (const auto &a : r.alarms) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"),         a.instanceId);
                m.insert(QStringLiteral("elementName"),        a.elementName);
                m.insert(QStringLiteral("startTimeIso"),       a.startTimeIso);
                const QDateTime dt = QDateTime::fromString(a.startTimeIso,
                                                            Qt::ISODate);
                m.insert(QStringLiteral("startTimeLocal"),
                         dt.isValid()
                             ? dt.toLocalTime().toString(QStringLiteral(
                                   "yyyy-MM-dd HH:mm"))
                             : a.startTimeIso);
                m.insert(QStringLiteral("intervalIso"),        a.intervalIso);
                m.insert(QStringLiteral("intervalLabel"),
                         humanizeIsoDuration(a.intervalIso));
                m.insert(QStringLiteral("deleteOnCompletion"), a.deleteOnCompletion);
                list.append(m);
            }
            m_wakeAlarms = std::move(list);
            emit wakeAlarmsChanged();
        });
}

void MachineDetailsController::addWakeAlarm(const QVariantMap &fields)
{
    setLastError({});
    qumesh::wsman::WakeAlarm a;
    a.elementName        = fields.value(QStringLiteral("elementName")).toString().trimmed();
    a.startTimeIso       = fields.value(QStringLiteral("startTimeIso")).toString().trimmed();
    a.intervalIso        = fields.value(QStringLiteral("intervalIso")).toString().trimmed();
    a.deleteOnCompletion = fields.value(QStringLiteral("deleteOnCompletion")).toBool();

    if (a.elementName.isEmpty()) {
        setLastError(QStringLiteral("Add alarm: name is required."));
        return;
    }
    if (a.startTimeIso.isEmpty()) {
        setLastError(QStringLiteral("Add alarm: start time is required."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add alarm: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addWakeAlarm(m_client, a,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add alarm: failed.")
                    : QStringLiteral("Add alarm: %1").arg(r.error));
                return;
            }
            refreshWakeAlarms();
        });
}

void MachineDetailsController::deleteWakeAlarm(const QString &instanceId)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("Delete alarm: missing instance ID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete alarm: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteWakeAlarm(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete alarm: failed.")
                    : QStringLiteral("Delete alarm: %1").arg(r.error));
                return;
            }
            refreshWakeAlarms();
        });
}

void MachineDetailsController::replaceWakeAlarm(const QString &oldInstanceId,
                                                 const QVariantMap &fields)
{
    setLastError({});
    if (oldInstanceId.isEmpty()) {
        // No prior row — fall through to plain add.
        addWakeAlarm(fields);
        return;
    }
    qumesh::wsman::WakeAlarm a;
    a.elementName        = fields.value(QStringLiteral("elementName")).toString().trimmed();
    a.startTimeIso       = fields.value(QStringLiteral("startTimeIso")).toString().trimmed();
    a.intervalIso        = fields.value(QStringLiteral("intervalIso")).toString().trimmed();
    a.deleteOnCompletion = fields.value(QStringLiteral("deleteOnCompletion")).toBool();
    if (a.elementName.isEmpty() || a.startTimeIso.isEmpty()) {
        setLastError(QStringLiteral("Save alarm: name and start time are required."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Save alarm: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteWakeAlarm(m_client, oldInstanceId,
        [this, a](qumesh::wsman::InvokeResult delRes) {
            if (!delRes.ok) {
                decInflight();
                setLastError(delRes.error.isEmpty()
                    ? QStringLiteral("Save alarm: failed to delete previous row.")
                    : QStringLiteral("Save alarm: %1").arg(delRes.error));
                return;
            }
            qumesh::wsman::addWakeAlarm(m_client, a,
                [this](qumesh::wsman::InvokeResult addRes) {
                    decInflight();
                    if (!addRes.ok) {
                        // The old row is gone at this point; surface
                        // the failure so the operator knows to re-add
                        // by hand if AMT rejected the new shape.
                        setLastError(addRes.error.isEmpty()
                            ? QStringLiteral("Save alarm: previous row was removed but the new one could not be added.")
                            : QStringLiteral("Save alarm: previous row removed; AddAlarm: %1").arg(addRes.error));
                        refreshWakeAlarms();
                        return;
                    }
                    refreshWakeAlarms();
                });
        });
}

void MachineDetailsController::wsmanBrowse(const QString &classOrUri,
                                           const QString &kind,
                                           const QVariantMap &selectors)
{
    rebuildEndpoint();
    if (m_host.isEmpty() || classOrUri.isEmpty()) return;

    QHash<QString, QString> sels;
    for (auto it = selectors.begin(); it != selectors.end(); ++it)
        sels.insert(it.key(), it.value().toString());
    const auto k = kind.compare(QStringLiteral("enumerate"), Qt::CaseInsensitive) == 0
                       ? qumesh::wsman::BrowseKind::Enumerate
                       : qumesh::wsman::BrowseKind::Get;

    incInflight();
    qumesh::wsman::executeBrowse(m_client, classOrUri, k, sels,
        [this, k](qumesh::wsman::WsmanBrowseResult r) {
            decInflight();
            QVariantMap m;
            m.insert(QStringLiteral("ok"),         r.ok);
            m.insert(QStringLiteral("error"),      r.error);
            m.insert(QStringLiteral("kind"),
                     k == qumesh::wsman::BrowseKind::Enumerate
                         ? QStringLiteral("enumerate")
                         : QStringLiteral("get"));
            m.insert(QStringLiteral("itemCount"),  r.itemCount);
            m.insert(QStringLiteral("xml"),
                     QString::fromUtf8(r.xml));
            m_wsmanBrowseResult = std::move(m);
            emit wsmanBrowseResultChanged();
        });
}

void MachineDetailsController::refreshSystemDefense()
{
    if (deferIfSshConnecting(PendingSystemDefense)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshSystemDefense(); };
    incInflight();
    qumesh::wsman::getSystemDefense(m_client,
        [this](qumesh::wsman::SystemDefenseResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("System Defense: %1").arg(r.error));

            const auto mkPolicy = [](const qumesh::wsman::SystemDefensePolicy &p) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"), p.instanceId);
                m.insert(QStringLiteral("policyName"), p.policyName);
                m.insert(QStringLiteral("priority"),   p.priority);
                m.insert(QStringLiteral("defaultPolicy"), p.defaultPolicy);
                m.insert(QStringLiteral("txEnabled"),  p.txEnabled);
                m.insert(QStringLiteral("rxEnabled"),  p.rxEnabled);
                return m;
            };
            const auto mkHdr = [](const qumesh::wsman::Hdr8021Filter &f) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"),      f.instanceId);
                m.insert(QStringLiteral("name"),            f.name);
                m.insert(QStringLiteral("filterDirection"), f.filterDirection);
                m.insert(QStringLiteral("vlanTag"),         f.vlanTag);
                m.insert(QStringLiteral("etherType"),       f.etherType);
                m.insert(QStringLiteral("priority"),        f.priority);
                return m;
            };
            const auto mkIp = [](const qumesh::wsman::IpHeadersFilter &f) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"),      f.instanceId);
                m.insert(QStringLiteral("name"),            f.name);
                m.insert(QStringLiteral("filterDirection"), f.filterDirection);
                m.insert(QStringLiteral("srcAddress"),      f.srcAddress);
                m.insert(QStringLiteral("dstAddress"),      f.dstAddress);
                m.insert(QStringLiteral("protocol"),        f.protocol);
                m.insert(QStringLiteral("srcPort"),         f.srcPort);
                m.insert(QStringLiteral("dstPort"),         f.dstPort);
                return m;
            };

            QVariantList policies, hdrFilters, ipFilters;
            for (const auto &p : r.policies)   policies.append(mkPolicy(p));
            for (const auto &f : r.hdrFilters) hdrFilters.append(mkHdr(f));
            for (const auto &f : r.ipFilters)  ipFilters.append(mkIp(f));

            // Stats are surfaced as a map keyed by filter InstanceID
            // so QML can do a single O(1) lookup per row instead of
            // walking the list on every binding evaluation.
            QVariantMap statsByInstance;
            for (const auto &s : r.stats) {
                QVariantMap m;
                m.insert(QStringLiteral("packetsPassed"),
                          QVariant::fromValue(s.packetsPassed));
                m.insert(QStringLiteral("packetsDropped"),
                          QVariant::fromValue(s.packetsDropped));
                statsByInstance.insert(s.filterInstanceId, m);
            }

            // Per-policy port bindings — flatten the join rows into a
            // map keyed by the policy InstanceID so the QML row binding
            // can render the bound port without scanning a list.
            QVariantMap portBindingsByPolicy;
            for (const auto &b : r.portBindings) {
                QVariantMap m;
                m.insert(QStringLiteral("portDeviceId"), b.portDeviceId);
                portBindingsByPolicy.insert(b.policyInstanceId, m);
            }

            QVariantMap sd;
            sd.insert(QStringLiteral("ok"),         r.ok);
            sd.insert(QStringLiteral("supported"),  r.supported);
            sd.insert(QStringLiteral("policies"),   policies);
            sd.insert(QStringLiteral("hdrFilters"), hdrFilters);
            sd.insert(QStringLiteral("ipFilters"),  ipFilters);
            sd.insert(QStringLiteral("stats"),      statsByInstance);
            sd.insert(QStringLiteral("portBindings"), portBindingsByPolicy);
            m_systemDefense = std::move(sd);
            emit systemDefenseChanged();
        });
}

void MachineDetailsController::refreshSystemDefenseStats()
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("System Defense stats: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::getActiveFilterStatistics(m_client,
        [this](QList<qumesh::wsman::ActiveFilterStatRow> rows, QString err) {
            decInflight();
            if (!err.isEmpty()) {
                // Quiet failure — stats are best-effort. Surface a
                // banner only if the operator explicitly triggered the
                // poll (not on the background tree refresh).
                setLastError(QStringLiteral("System Defense stats: %1").arg(err));
                return;
            }
            QVariantMap statsByInstance;
            for (const auto &s : rows) {
                QVariantMap m;
                m.insert(QStringLiteral("packetsPassed"),
                          QVariant::fromValue(s.packetsPassed));
                m.insert(QStringLiteral("packetsDropped"),
                          QVariant::fromValue(s.packetsDropped));
                statsByInstance.insert(s.filterInstanceId, m);
            }
            m_systemDefense.insert(QStringLiteral("stats"), statsByInstance);
            emit systemDefenseChanged();
        });
}

void MachineDetailsController::deleteSystemDefensePolicy(const QString &instanceId)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("Delete policy: missing instance ID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete policy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteSystemDefensePolicy(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete policy: failed.")
                    : QStringLiteral("Delete policy: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::deleteSystemDefenseHdrFilter(const QString &instanceId)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("Delete L2 filter: missing instance ID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete L2 filter: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteHdr8021Filter(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete L2 filter: failed.")
                    : QStringLiteral("Delete L2 filter: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::deleteSystemDefenseIpFilter(const QString &instanceId)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("Delete L3/L4 filter: missing instance ID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete L3/L4 filter: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteIpHeadersFilter(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete L3/L4 filter: failed.")
                    : QStringLiteral("Delete L3/L4 filter: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::bindSystemDefensePolicy(int portIndex,
                                                          const QString &policyInstanceId)
{
    setLastError({});
    if (portIndex < 0) {
        setLastError(QStringLiteral("Bind policy: port index must be >= 0."));
        return;
    }
    if (policyInstanceId.isEmpty()) {
        setLastError(QStringLiteral("Bind policy: missing policy InstanceID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Bind policy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::bindSystemDefensePolicyToPort(m_client, portIndex, policyInstanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Bind policy: failed.")
                    : QStringLiteral("Bind policy: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::unbindSystemDefensePolicy(int portIndex,
                                                            const QString &policyInstanceId)
{
    setLastError({});
    if (portIndex < 0 || policyInstanceId.isEmpty()) {
        setLastError(QStringLiteral("Unbind policy: port index and policy are required."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Unbind policy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::unbindSystemDefensePolicyFromPort(m_client, portIndex, policyInstanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Unbind policy: failed.")
                    : QStringLiteral("Unbind policy: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::addSystemDefensePolicyAction(const QVariantMap &fields)
{
    setLastError({});
    qumesh::wsman::SystemDefensePolicy p;
    p.policyName = fields.value(QStringLiteral("policyName")).toString().trimmed();
    p.priority   = fields.value(QStringLiteral("priority"), 0).toInt();
    p.txDefaultCount      = fields.value(QStringLiteral("txDefaultCount")).toBool();
    p.txDefaultDrop       = fields.value(QStringLiteral("txDefaultDrop")).toBool();
    p.txDefaultMatchEvent = fields.value(QStringLiteral("txDefaultMatchEvent")).toBool();
    p.rxDefaultCount      = fields.value(QStringLiteral("rxDefaultCount")).toBool();
    p.rxDefaultDrop       = fields.value(QStringLiteral("rxDefaultDrop")).toBool();
    p.rxDefaultMatchEvent = fields.value(QStringLiteral("rxDefaultMatchEvent")).toBool();

    // Dialog hands picked filters as InstanceID strings; pull the
    // trailing integer handle out of each. IDs without a trailing
    // digit get silently dropped (defence in depth — the picker
    // shouldn't surface those rows in the first place).
    for (const QVariant &v :
         fields.value(QStringLiteral("filterInstanceIds")).toList()) {
        const int h = qumesh::wsman::extractFilterHandleFromInstanceId(
            v.toString());
        if (h >= 0) p.filterCreationHandles.append(h);
    }

    if (p.policyName.isEmpty()) {
        setLastError(QStringLiteral("Add policy: name is required."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add policy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addSystemDefensePolicy(m_client, p,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add policy: failed.")
                    : QStringLiteral("Add policy: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::addSystemDefenseIpFilter(const QVariantMap &fields)
{
    setLastError({});
    qumesh::wsman::IpHeadersFilter f;
    f.name               = fields.value(QStringLiteral("name")).toString().trimmed();
    bool ok = false;
    f.ipVersion          = fields.value(QStringLiteral("ipVersion")).toInt(&ok);
    if (!ok) f.ipVersion = -1;
    ok = false;
    f.filterProfile      = fields.value(QStringLiteral("filterProfile")).toInt(&ok);
    if (!ok) f.filterProfile = -1;
    f.filterProfileData  = fields.value(QStringLiteral("filterProfileData")).toInt();
    ok = false;
    f.filterDirection    = fields.value(QStringLiteral("filterDirection")).toInt(&ok);
    if (!ok) f.filterDirection = -1;
    f.actionEventOnMatch = fields.value(QStringLiteral("actionEventOnMatch")).toBool();
    f.srcAddress         = fields.value(QStringLiteral("srcAddress")).toString().trimmed();
    f.dstAddress         = fields.value(QStringLiteral("dstAddress")).toString().trimmed();
    // Optional numeric matchers default to -1 = "not set" = field
    // omitted on the wire (AMT rejects empty scalars on Create).
    ok = false;
    f.protocol           = fields.value(QStringLiteral("protocol"), -1).toInt(&ok);
    if (!ok) f.protocol = -1;
    ok = false;
    f.srcPort            = fields.value(QStringLiteral("srcPort"), -1).toInt(&ok);
    if (!ok) f.srcPort = -1;
    ok = false;
    f.srcPortEnd         = fields.value(QStringLiteral("srcPortEnd"), -1).toInt(&ok);
    if (!ok) f.srcPortEnd = -1;
    ok = false;
    f.dstPort            = fields.value(QStringLiteral("dstPort"), -1).toInt(&ok);
    if (!ok) f.dstPort = -1;
    ok = false;
    f.dstPortEnd         = fields.value(QStringLiteral("dstPortEnd"), -1).toInt(&ok);
    if (!ok) f.dstPortEnd = -1;

    if (f.name.isEmpty()) {
        setLastError(QStringLiteral("Add L3/L4 filter: name is required."));
        return;
    }
    if (f.ipVersion != 4 && f.ipVersion != 6) {
        setLastError(QStringLiteral("Add L3/L4 filter: IP version must be 4 or 6."));
        return;
    }
    if (f.filterProfile < 0 || f.filterProfile > 4) {
        setLastError(QStringLiteral("Add L3/L4 filter: action must be one of Allow / Drop / Rate Limit."));
        return;
    }
    if (f.filterDirection != 0 && f.filterDirection != 1) {
        setLastError(QStringLiteral("Add L3/L4 filter: direction must be Tx or Rx."));
        return;
    }
    if (f.filterProfile == 2 && f.filterProfileData <= 0) {
        setLastError(QStringLiteral("Add L3/L4 filter: rate limit must be > 0 packets/second."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add L3/L4 filter: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addIpHeadersFilter(m_client, f,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add L3/L4 filter: failed.")
                    : QStringLiteral("Add L3/L4 filter: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

void MachineDetailsController::addSystemDefenseHdrFilter(const QVariantMap &fields)
{
    setLastError({});
    qumesh::wsman::Hdr8021Filter f;
    f.name               = fields.value(QStringLiteral("name")).toString().trimmed();
    bool ok = false;
    f.etherType          = fields.value(QStringLiteral("etherType")).toInt(&ok);
    if (!ok) f.etherType = -1;
    ok = false;
    f.filterProfile      = fields.value(QStringLiteral("filterProfile")).toInt(&ok);
    if (!ok) f.filterProfile = -1;
    f.filterProfileData  = fields.value(QStringLiteral("filterProfileData")).toInt();
    ok = false;
    f.filterDirection    = fields.value(QStringLiteral("filterDirection")).toInt(&ok);
    if (!ok) f.filterDirection = -1;
    f.actionEventOnMatch = fields.value(QStringLiteral("actionEventOnMatch")).toBool();

    if (f.name.isEmpty()) {
        setLastError(QStringLiteral("Add L2 filter: name is required."));
        return;
    }
    if (f.etherType < 0) {
        setLastError(QStringLiteral("Add L2 filter: ethertype is required."));
        return;
    }
    if (f.filterProfile < 0 || f.filterProfile > 4) {
        setLastError(QStringLiteral("Add L2 filter: action must be one of Allow / Drop / Rate Limit."));
        return;
    }
    if (f.filterDirection != 0 && f.filterDirection != 1) {
        setLastError(QStringLiteral("Add L2 filter: direction must be Tx or Rx."));
        return;
    }
    if (f.filterProfile == 2 && f.filterProfileData <= 0) {
        setLastError(QStringLiteral("Add L2 filter: rate limit must be > 0 packets/second."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add L2 filter: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addHdr8021Filter(m_client, f,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add L2 filter: failed.")
                    : QStringLiteral("Add L2 filter: %1").arg(r.error));
                return;
            }
            refreshSystemDefense();
        });
}

QString MachineDetailsController::readTextFromPath(const QString &pathOrUrl) const
{
    // Accept either a plain path or a file:// URL — QML's FileDialog
    // hands back the latter. Anything else (http://, etc.) is rejected:
    // this entry point is for local PEM files only.
    QString path = pathOrUrl;
    if (path.startsWith(QStringLiteral("file://"))) {
        const QUrl u(path);
        if (u.isLocalFile()) path = u.toLocalFile();
        else return {};
    }
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};
    return QString::fromUtf8(f.readAll());
}

bool MachineDetailsController::writeTextToPath(const QString &pathOrUrl,
                                                 const QString &text) const
{
    QString path = pathOrUrl;
    if (path.startsWith(QStringLiteral("file://"))) {
        const QUrl u(path);
        if (u.isLocalFile()) path = u.toLocalFile();
        else return false;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    const QByteArray bytes = text.toUtf8();
    return f.write(bytes) == bytes.size();
}

void MachineDetailsController::addCertificateFromPem(const QString &pem,
                                                     bool asTrustedRoot)
{
    setLastError({});
    if (pem.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Add certificate: PEM is empty."));
        return;
    }
    QString parseErr;
    const auto entry = qumesh::certs::CertParser::fromPem(pem.toUtf8(), &parseErr);
    if (entry.certDer.isEmpty()) {
        setLastError(QStringLiteral("Add certificate: %1").arg(
            parseErr.isEmpty() ? QStringLiteral("no certificate block found")
                               : parseErr));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add certificate: host is empty."));
        return;
    }
    const QString b64 = QString::fromLatin1(entry.certDer.toBase64());
    auto cb = [this](qumesh::wsman::InvokeResult r) {
        decInflight();
        if (!r.ok) {
            setLastError(r.error.isEmpty()
                ? QStringLiteral("Add certificate: failed.")
                : QStringLiteral("Add certificate: %1").arg(r.error));
            return;
        }
        refreshDeviceCerts();
    };
    incInflight();
    if (asTrustedRoot)
        qumesh::wsman::addTrustedRootCertificate(m_client, b64, std::move(cb));
    else
        qumesh::wsman::addCertificate(m_client, b64, std::move(cb));
}

void MachineDetailsController::deleteDeviceCertificate(const QString &instanceId)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("Delete certificate: missing instance ID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete certificate: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteDeviceCertificate(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete certificate: failed.")
                    : QStringLiteral("Delete certificate: %1").arg(r.error));
                return;
            }
            refreshDeviceCerts();
        });
}

void MachineDetailsController::deleteDeviceKeyPair(const QString &instanceId)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("Delete key pair: missing instance ID."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Delete key pair: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteDeviceKeyPair(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Delete key pair: failed.")
                    : QStringLiteral("Delete key pair: %1").arg(r.error));
                return;
            }
            refreshDeviceCerts();
        });
}

void MachineDetailsController::setTlsSettingsForInstance(
    const QString &instanceId, bool enabled, bool mutualAuth,
    bool acceptNonSecureConnections, const QVariantList &trustedCn)
{
    setLastError({});
    if (instanceId.isEmpty()) {
        setLastError(QStringLiteral("TLS settings: missing instance ID."));
        return;
    }
    if (mutualAuth && trustedCn.isEmpty()) {
        // The QML side should already block this, but a second
        // defense at the controller boundary avoids bricking the
        // endpoint if a future caller forgets the check.
        setLastError(QStringLiteral(
            "TLS settings: mutual-auth requires at least one trusted CN."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("TLS settings: host is empty."));
        return;
    }
    QStringList cns;
    cns.reserve(trustedCn.size());
    for (const QVariant &v : trustedCn) {
        const QString s = v.toString().trimmed();
        if (!s.isEmpty()) cns.append(s);
    }
    incInflight();
    qumesh::wsman::setTlsSettings(m_client, instanceId, enabled, mutualAuth,
        acceptNonSecureConnections, cns,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("TLS settings: failed.")
                    : QStringLiteral("TLS settings: %1").arg(r.error));
                return;
            }
            refreshDeviceCerts();
        });
}

void MachineDetailsController::generateKeyPairAndCsr(int keyLength,
                                                     int keyAlgorithm,
                                                     const QString &subjectDn,
                                                     int signingAlgorithm)
{
    setLastError({});
    if (subjectDn.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Issue cert: Subject DN is empty."));
        emit csrFailed(lastError());
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Issue cert: host is empty."));
        emit csrFailed(lastError());
        return;
    }
    incInflight();
    qumesh::wsman::generateKeyPair(m_client, keyAlgorithm, keyLength,
        [this, subjectDn, signingAlgorithm]
        (qumesh::wsman::GenerateKeyPairResult kp) {
            if (!kp.ok) {
                decInflight();
                setLastError(kp.error.isEmpty()
                    ? QStringLiteral("Issue cert: GenerateKeyPair failed")
                    : QStringLiteral("Issue cert: GenerateKeyPair: %1").arg(kp.error));
                emit csrFailed(lastError());
                return;
            }
            // Step 2: pull the freshly generated public key so we can
            // build the null-signed PKCS#10 template.
            const QString keyId = kp.keyPairInstanceId;
            qumesh::wsman::getPublicPrivateKeyPair(m_client, keyId,
                [this, keyId, subjectDn, signingAlgorithm]
                (qumesh::wsman::PublicPrivateKeyPairGetResult kg) {
                    if (!kg.ok || kg.derKey.isEmpty()) {
                        decInflight();
                        setLastError(kg.error.isEmpty()
                            ? QStringLiteral("Issue cert: missing public key on new pair")
                            : QStringLiteral("Issue cert: read public key: %1").arg(kg.error));
                        emit csrFailed(lastError());
                        return;
                    }
                    QString buildErr;
                    const QByteArray nullCsr = qumesh::wsman::buildNullSignedPkcs10Csr(
                        kg.derKey, subjectDn, signingAlgorithm, &buildErr);
                    if (nullCsr.isEmpty()) {
                        decInflight();
                        setLastError(QStringLiteral(
                            "Issue cert: build null-signed CSR: %1").arg(buildErr));
                        emit csrFailed(lastError());
                        return;
                    }
                    // Step 3: AMT signs the template with its private key.
                    qumesh::wsman::generatePkcs10Request(m_client, keyId,
                        signingAlgorithm, nullCsr,
                        [this](qumesh::wsman::GeneratePkcs10RequestResult pr) {
                            decInflight();
                            if (!pr.ok || pr.signedRequestDer.isEmpty()) {
                                setLastError(pr.error.isEmpty()
                                    ? QStringLiteral("Issue cert: GeneratePKCS10RequestEx failed")
                                    : QStringLiteral("Issue cert: %1").arg(pr.error));
                                emit csrFailed(lastError());
                                return;
                            }
                            // Wrap the firmware-signed DER as PEM so the
                            // operator can paste it into their CA's web
                            // form without an extra hex/base64 step.
                            const QByteArray b64 = pr.signedRequestDer.toBase64(
                                QByteArray::Base64Encoding);
                            QByteArray pem("-----BEGIN CERTIFICATE REQUEST-----\n");
                            for (int i = 0; i < b64.size(); i += 64) {
                                pem.append(b64.mid(i, 64));
                                pem.append('\n');
                            }
                            pem.append("-----END CERTIFICATE REQUEST-----\n");
                            emit csrReady(QString::fromLatin1(pem));
                        });
                });
        });
}

void MachineDetailsController::installSignedCertAndBindTls(
    const QString &signedCertPem, const QString &tlsEndpointCollectionId)
{
    setLastError({});
    if (signedCertPem.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Install cert: PEM is empty."));
        emit certInstallFailed(lastError());
        return;
    }
    if (tlsEndpointCollectionId.trimmed().isEmpty()) {
        setLastError(QStringLiteral("Install cert: pick a TLS endpoint to bind."));
        emit certInstallFailed(lastError());
        return;
    }
    QString parseErr;
    const auto entry = qumesh::certs::CertParser::fromPem(
        signedCertPem.toUtf8(), &parseErr);
    if (entry.certDer.isEmpty()) {
        setLastError(parseErr.isEmpty()
            ? QStringLiteral("Install cert: no certificate block found")
            : QStringLiteral("Install cert: %1").arg(parseErr));
        emit certInstallFailed(lastError());
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Install cert: host is empty."));
        emit certInstallFailed(lastError());
        return;
    }
    const QByteArray b64 = entry.certDer.toBase64();
    const QString fingerprint = entry.fingerprintSha256;

    incInflight();
    qumesh::wsman::addCertificate(m_client, QString::fromLatin1(b64),
        [this, fingerprint, tlsEndpointCollectionId]
        (qumesh::wsman::InvokeResult r) {
            if (!r.ok) {
                decInflight();
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Install cert: AddCertificate failed")
                    : QStringLiteral("Install cert: %1").arg(r.error));
                emit certInstallFailed(lastError());
                return;
            }
            // Re-enumerate device certs to find the freshly added row
            // (AMT picks the InstanceID; we match by SHA-256 fingerprint
            // after running each stored DER back through CertParser
            // for the same canonical "AA:BB:…" format).
            qumesh::wsman::getDeviceCertStore(m_client,
                [this, fingerprint, tlsEndpointCollectionId]
                (qumesh::wsman::DeviceCertResult store) {
                    if (!store.ok) {
                        decInflight();
                        setLastError(QStringLiteral(
                            "Install cert: re-enumerate device store failed: %1")
                            .arg(store.error));
                        emit certInstallFailed(lastError());
                        return;
                    }
                    QString newInstanceId;
                    for (const auto &c : store.certificates) {
                        const QByteArray der = QByteArray::fromBase64(
                            c.x509Base64.toLatin1());
                        if (der.isEmpty()) continue;
                        QString parseErr;
                        const auto storedEntry =
                            qumesh::certs::CertParser::fromDer(der, &parseErr);
                        if (storedEntry.fingerprintSha256 == fingerprint) {
                            newInstanceId = c.instanceId;
                            break;
                        }
                    }
                    if (newInstanceId.isEmpty()) {
                        decInflight();
                        setLastError(QStringLiteral(
                            "Install cert: couldn't locate the new cert in the device store"));
                        emit certInstallFailed(lastError());
                        return;
                    }
                    const bool replace = !store.activeCertInstanceIds.isEmpty();
                    qumesh::wsman::bindCertToTlsEndpoint(m_client,
                        newInstanceId, tlsEndpointCollectionId, replace,
                        [this, newInstanceId]
                        (qumesh::wsman::InvokeResult bindRes) {
                            decInflight();
                            if (!bindRes.ok) {
                                setLastError(bindRes.error.isEmpty()
                                    ? QStringLiteral("Install cert: bind to TLS endpoint failed")
                                    : QStringLiteral("Install cert: bind: %1").arg(bindRes.error));
                                emit certInstallFailed(lastError());
                                return;
                            }
                            refreshDeviceCerts();
                            emit certInstalled(newInstanceId);
                        });
                });
        });
}

void MachineDetailsController::refreshRemoteAccess()
{
    if (deferIfSshConnecting(PendingRemoteAccess)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshRemoteAccess(); };
    incInflight();
    qumesh::wsman::getRemoteAccess(m_client,
        [this](qumesh::wsman::RemoteAccessResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Remote access: %1").arg(r.error));

            QVariantMap envDet;
            envDet.insert(QStringLiteral("enabled"),
                          !r.envDetection.domains.isEmpty());
            envDet.insert(QStringLiteral("domains"),
                          QVariant(r.envDetection.domains));
            envDet.insert(QStringLiteral("domainsLabel"),
                          r.envDetection.domains.join(", "));

            QVariantMap user;
            user.insert(QStringLiteral("enabledState"),
                        r.userInitiated.enabledState);
            user.insert(QStringLiteral("label"),
                        qumesh::wsman::userInitiatedCiraLabel(
                            r.userInitiated.enabledState));

            QVariantList policies;
            for (const auto &p : r.policies) {
                QVariantMap m;
                m.insert(QStringLiteral("name"),           p.name);
                m.insert(QStringLiteral("trigger"),        p.trigger);
                m.insert(QStringLiteral("tunnelLifeTime"), p.tunnelLifeTime);
                m.insert(QStringLiteral("mpsNames"),       p.mpsNames);
                m.insert(QStringLiteral("mpsNamesLabel"),  p.mpsNames.join(", "));
                // Surface the structured periodic fields so the edit
                // dialog can recover them without string-parsing the
                // user-facing scheduleLabel.
                m.insert(QStringLiteral("periodicInterval"),   p.periodicInterval);
                m.insert(QStringLiteral("periodicSeconds"),    p.periodicSeconds);
                m.insert(QStringLiteral("periodicTimeOfDay"),  p.periodicTimeOfDay);
                m.insert(QStringLiteral("periodicHour"),       p.periodicHour);
                m.insert(QStringLiteral("periodicMinute"),     p.periodicMinute);
                if (p.periodicInterval) {
                    m.insert(QStringLiteral("scheduleLabel"),
                             QStringLiteral("Every %1 s").arg(p.periodicSeconds));
                } else if (p.periodicTimeOfDay) {
                    m.insert(QStringLiteral("scheduleLabel"),
                             QStringLiteral("%1:%2 daily")
                                 .arg(p.periodicHour, 2, 10, QLatin1Char('0'))
                                 .arg(p.periodicMinute, 2, 10, QLatin1Char('0')));
                } else {
                    m.insert(QStringLiteral("scheduleLabel"), QString());
                }
                policies.append(m);
            }

            QVariantList servers;
            for (const auto &s : r.servers) {
                QVariantMap m;
                m.insert(QStringLiteral("name"),       s.name);
                m.insert(QStringLiteral("accessInfo"), s.accessInfo);
                m.insert(QStringLiteral("port"),       s.port);
                m.insert(QStringLiteral("cn"),         s.cn);
                m.insert(QStringLiteral("mpsType"),    s.mpsType);
                m.insert(QStringLiteral("cila"),       s.mpsType == 1);
                servers.append(m);
            }

            QVariantList proxies;
            for (const auto &p : r.httpProxies) {
                QVariantMap m;
                // The `name` key is the load-bearing selector for the
                // Delete invoke; it was missing from the original
                // Phase-A→Phase-B handoff (HTTP proxies, #214), so the
                // sidebar's Delete button silently fired the empty-name
                // path. Surface it so QML can read modelData.name.
                m.insert(QStringLiteral("name"),       p.name);
                m.insert(QStringLiteral("accessInfo"), p.accessInfo);
                m.insert(QStringLiteral("port"),       p.port);
                m.insert(QStringLiteral("networkDnsSuffix"), p.networkDnsSuffix);
                proxies.append(m);
            }

            QVariantMap ra;
            ra.insert(QStringLiteral("ok"),            r.ok);
            ra.insert(QStringLiteral("envDetection"),  envDet);
            ra.insert(QStringLiteral("userInitiated"), user);
            ra.insert(QStringLiteral("policies"),      policies);
            ra.insert(QStringLiteral("servers"),       servers);
            ra.insert(QStringLiteral("httpProxies"),   proxies);
            ra.insert(QStringLiteral("httpProxySupported"), r.httpProxySupported);
            m_remoteAccess = std::move(ra);
            emit remoteAccessChanged();
        });
}

void MachineDetailsController::addHttpProxy(const QString &accessInfo, int port,
                                            const QString &networkDnsSuffix)
{
    setLastError({});
    const QString info = accessInfo.trimmed();
    if (info.isEmpty()) {
        setLastError(QStringLiteral("HTTP proxy: address is empty."));
        return;
    }
    if (port < 1 || port > 65535) {
        setLastError(QStringLiteral(
            "HTTP proxy: port %1 is out of range (1–65535).").arg(port));
        return;
    }
    // AMT firmware refuses more than 15 IPS_HTTPProxyAccessPoint
    // instances. Refusing here rather than letting AMT fault keeps
    // the failure path next to the user input.
    const QVariantList existing =
        m_remoteAccess.value(QStringLiteral("httpProxies")).toList();
    if (existing.size() >= 15) {
        setLastError(QStringLiteral(
            "HTTP proxy: AMT already has the maximum of 15 entries."));
        return;
    }
    const int infoFormat = qumesh::wsman::classifyAccessInfo(info);

    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("HTTP proxy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addHttpProxy(m_client, info, infoFormat, port, networkDnsSuffix,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("HTTP proxy: AddProxyAccessPoint failed.")
                    : QStringLiteral("HTTP proxy: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::deleteHttpProxy(const QString &name)
{
    setLastError({});
    if (name.isEmpty()) {
        setLastError(QStringLiteral("HTTP proxy: missing identity."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("HTTP proxy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::deleteHttpProxy(m_client, name,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("HTTP proxy: delete failed.")
                    : QStringLiteral("HTTP proxy: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::setEnvironmentDetection(const QStringList &domains)
{
    setLastError({});
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Env detection: host is empty."));
        return;
    }
    QStringList trimmed;
    trimmed.reserve(domains.size());
    for (const QString &d : domains) {
        const QString t = d.trimmed();
        if (!t.isEmpty()) trimmed.append(t);
    }
    incInflight();
    qumesh::wsman::setEnvironmentDetection(m_client, trimmed,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Env detection: failed.")
                    : QStringLiteral("Env detection: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::setUserInitiatedConnectionState(int enabledState)
{
    setLastError({});
    if (enabledState < 32768 || enabledState > 32771) {
        setLastError(QStringLiteral(
            "User-initiated CIRA: state %1 is outside 32768..32771.")
            .arg(enabledState));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("User-initiated CIRA: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::setUserInitiatedConnectionState(m_client, enabledState,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("User-initiated CIRA: failed.")
                    : QStringLiteral("User-initiated CIRA: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::addMpServer(const QVariantMap &fields)
{
    setLastError({});
    qumesh::wsman::MpServerInput in;
    in.accessInfo = fields.value(QStringLiteral("accessInfo")).toString().trimmed();
    in.port       = fields.value(QStringLiteral("port"), 4433).toInt();
    in.commonName = fields.value(QStringLiteral("commonName")).toString();
    in.mpsType    = fields.value(QStringLiteral("mpsType"), 0).toInt();
    in.authMethod = fields.value(QStringLiteral("authMethod"), 1).toInt();
    in.username   = fields.value(QStringLiteral("username")).toString();
    in.password   = fields.value(QStringLiteral("password")).toString();
    in.infoFormat = qumesh::wsman::classifyAccessInfo(in.accessInfo);

    if (in.accessInfo.isEmpty()) {
        setLastError(QStringLiteral("Add MPS: AccessInfo is empty."));
        return;
    }
    if (in.port < 1 || in.port > 65535) {
        setLastError(QStringLiteral(
            "Add MPS: port %1 is out of range (1–65535).").arg(in.port));
        return;
    }
    if (in.authMethod != 1
        && (in.username.isEmpty() || in.password.isEmpty())) {
        setLastError(QStringLiteral(
            "Add MPS: auth method requires both username and password."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add MPS: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::addMpServer(m_client, in,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add MPS: failed.")
                    : QStringLiteral("Add MPS: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::updateMpServer(const QString &name,
                                              const QVariantMap &fields)
{
    setLastError({});
    if (name.isEmpty()) {
        setLastError(QStringLiteral("Edit MPS: missing identity."));
        return;
    }
    const QString accessInfo =
        fields.value(QStringLiteral("accessInfo")).toString().trimmed();
    const int port = fields.value(QStringLiteral("port"), 4433).toInt();
    const QString commonName =
        fields.value(QStringLiteral("commonName")).toString();
    if (accessInfo.isEmpty()) {
        setLastError(QStringLiteral("Edit MPS: AccessInfo is empty."));
        return;
    }
    if (port < 1 || port > 65535) {
        setLastError(QStringLiteral(
            "Edit MPS: port %1 is out of range.").arg(port));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Edit MPS: host is empty."));
        return;
    }
    const int infoFormat = qumesh::wsman::classifyAccessInfo(accessInfo);
    incInflight();
    qumesh::wsman::updateMpServer(m_client, name, accessInfo, infoFormat, port,
                                   commonName,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Edit MPS: failed.")
                    : QStringLiteral("Edit MPS: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::removeMpServer(const QString &name)
{
    setLastError({});
    if (name.isEmpty()) {
        setLastError(QStringLiteral("Remove MPS: missing identity."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Remove MPS: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::removeMpServer(m_client, name,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Remove MPS: failed.")
                    : QStringLiteral("Remove MPS: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::addCiraPolicyRule(const QVariantMap &fields)
{
    setLastError({});
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("CIRA policy: host is empty."));
        return;
    }

    qumesh::wsman::CiraPolicyInput in;
    in.trigger        = fields.value(QStringLiteral("trigger"), 0).toInt();
    in.tunnelLifeTime = fields.value(QStringLiteral("tunnelLifeTime"), 0).toInt();
    if (in.trigger < 0 || in.trigger > 2) {
        setLastError(QStringLiteral("CIRA policy: trigger %1 out of range (0..2).")
            .arg(in.trigger));
        return;
    }
    if (in.tunnelLifeTime < 0) {
        setLastError(QStringLiteral("CIRA policy: tunnel lifetime must be >= 0."));
        return;
    }
    if (in.trigger == 2) {
        const QString mode = fields.value(QStringLiteral("periodicMode")).toString();
        if (mode == QStringLiteral("interval")) {
            in.periodicInterval = true;
            in.periodicSeconds  = fields.value(QStringLiteral("periodicSeconds"), 0).toInt();
            if (in.periodicSeconds <= 0) {
                setLastError(QStringLiteral("CIRA policy: periodic interval must be > 0."));
                return;
            }
        } else if (mode == QStringLiteral("timeOfDay")) {
            in.periodicTimeOfDay = true;
            in.periodicHour   = fields.value(QStringLiteral("periodicHour"), 0).toInt();
            in.periodicMinute = fields.value(QStringLiteral("periodicMinute"), 0).toInt();
            if (in.periodicHour < 0 || in.periodicHour > 23
                || in.periodicMinute < 0 || in.periodicMinute > 59) {
                setLastError(QStringLiteral("CIRA policy: hour 0–23, minute 0–59."));
                return;
            }
        } else {
            setLastError(QStringLiteral(
                "CIRA policy: periodic mode must be 'interval' or 'timeOfDay'."));
            return;
        }
    }

    const auto toList = [&](const QString &key) {
        QStringList out;
        const QVariant v = fields.value(key);
        if (v.canConvert<QStringList>()) {
            out = v.toStringList();
        } else {
            for (const QVariant &item : v.toList())
                out.append(item.toString());
        }
        return out;
    };
    in.ciraMpsNames = toList(QStringLiteral("ciraMpsNames"));
    in.cilaMpsNames = toList(QStringLiteral("cilaMpsNames"));
    if (in.ciraMpsNames.isEmpty() && in.cilaMpsNames.isEmpty()) {
        setLastError(QStringLiteral(
            "CIRA policy: at least one MPS server must be bound."));
        return;
    }

    incInflight();
    qumesh::wsman::addRemoteAccessPolicyRule(m_client, in,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("CIRA policy: AddRemoteAccessPolicyRule failed.")
                    : QStringLiteral("CIRA policy: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::removeCiraPolicyRule(const QString &policyName)
{
    setLastError({});
    if (policyName.isEmpty()) {
        setLastError(QStringLiteral("Remove CIRA policy: missing identity."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Remove CIRA policy: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::removeRemoteAccessPolicyRule(m_client, policyName,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Remove CIRA policy: failed.")
                    : QStringLiteral("Remove CIRA policy: %1").arg(r.error));
                return;
            }
            refreshRemoteAccess();
        });
}

void MachineDetailsController::refreshDeviceCerts()
{
    if (deferIfSshConnecting(PendingDeviceCerts)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshDeviceCerts(); };
    incInflight();
    qumesh::wsman::getDeviceCertStore(m_client,
        [this](qumesh::wsman::DeviceCertResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Device certs: %1").arg(r.error));

            QVariantList certs;
            QHash<QString, bool> hasKey;
            for (const auto &k : r.keyPairs)
                hasKey.insert(k.instanceId, true);
            const QSet<QString> activeIds(r.activeCertInstanceIds.begin(),
                                          r.activeCertInstanceIds.end());

            QSet<QString> keysClaimedByCerts;
            for (const auto &c : r.certificates) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"),    c.instanceId);
                m.insert(QStringLiteral("subjectCn"),     c.subjectCn);
                m.insert(QStringLiteral("issuerCn"),      c.issuerCn);
                m.insert(QStringLiteral("subjectRaw"),    c.subjectRaw);
                m.insert(QStringLiteral("issuerRaw"),     c.issuerRaw);
                m.insert(QStringLiteral("trustedRoot"),   c.trustedRoot);
                m.insert(QStringLiteral("derSizeBytes"),  c.derSizeBytes);
                // A cert "has a private key" when a key pair shares
                // an InstanceID-suffix with the cert. AMT's pairing
                // convention is "Intel(r) AMT Certificate: <n>" vs
                // "Intel(r) AMT Key: <n>" — match by the trailing
                // suffix.
                bool hasPrivateKey = false;
                QString matchedKey;
                const int colon = c.instanceId.lastIndexOf(QLatin1Char(':'));
                const QString suffix = colon < 0 ? QString()
                                                 : c.instanceId.mid(colon + 1).trimmed();
                if (!suffix.isEmpty()) {
                    for (const auto &k : r.keyPairs) {
                        if (k.instanceId.endsWith(suffix)) {
                            hasPrivateKey = true;
                            matchedKey = k.instanceId;
                            break;
                        }
                    }
                }
                if (!matchedKey.isEmpty())
                    keysClaimedByCerts.insert(matchedKey);
                m.insert(QStringLiteral("hasPrivateKey"), hasPrivateKey);
                m.insert(QStringLiteral("active"),
                         activeIds.contains(c.instanceId));
                certs.append(m);
            }

            QVariantList orphans;
            for (const auto &k : r.keyPairs) {
                if (keysClaimedByCerts.contains(k.instanceId)) continue;
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"),   k.instanceId);
                m.insert(QStringLiteral("derSizeBytes"), k.derSizeBytes);
                orphans.append(m);
            }

            QVariantList tls;
            for (const auto &t : r.tlsSettings) {
                QVariantMap m;
                m.insert(QStringLiteral("instanceId"), t.instanceId);
                m.insert(QStringLiteral("isLocal"),
                         t.instanceId.contains(QStringLiteral("LMS")));
                m.insert(QStringLiteral("enabled"),      t.enabled);
                m.insert(QStringLiteral("mutualAuthentication"),
                         t.mutualAuthentication);
                m.insert(QStringLiteral("acceptNonSecureConnections"),
                         t.acceptNonSecureConnections);
                m.insert(QStringLiteral("trustedCn"),    t.trustedCn);
                m.insert(QStringLiteral("trustedCnLabel"), t.trustedCn.join(", "));
                QString label;
                if (!t.enabled) {
                    label = QStringLiteral("Disabled");
                } else {
                    label = t.mutualAuthentication
                        ? QStringLiteral("Mutual-auth TLS")
                        : QStringLiteral("Server-auth TLS");
                    if (t.acceptNonSecureConnections)
                        label += QStringLiteral(" + non-TLS");
                }
                m.insert(QStringLiteral("label"), label);
                tls.append(m);
            }

            QVariantMap store;
            store.insert(QStringLiteral("certificates"), certs);
            store.insert(QStringLiteral("orphanKeys"),   orphans);
            store.insert(QStringLiteral("tlsSettings"),  tls);
            store.insert(QStringLiteral("ok"),           r.ok);
            m_deviceCertStore = std::move(store);
            emit deviceCertStoreChanged();
        });
}

void MachineDetailsController::refreshActiveSessions()
{
    if (deferIfSshConnecting(PendingActiveSessions)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshActiveSessions(); };
    incInflight();
    qumesh::wsman::getActiveSessions(m_client,
        [this](qumesh::wsman::ActiveSessionsResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Active sessions: %1").arg(r.error));

            const auto pack = [](const QList<qumesh::wsman::ActiveRedirectionSession> &list) {
                QVariantList out;
                out.reserve(list.size());
                for (const auto &s : list) {
                    QVariantMap m;
                    m.insert(QStringLiteral("sourceAddress"),    s.sourceAddress);
                    m.insert(QStringLiteral("sourcePort"),       s.sourcePort);
                    m.insert(QStringLiteral("sessionInstanceId"), s.sessionInstanceId);
                    out.append(m);
                }
                return out;
            };

            QVariantMap as;
            as.insert(QStringLiteral("ok"),   r.ok);
            as.insert(QStringLiteral("sol"),  pack(r.sol));
            as.insert(QStringLiteral("kvm"),  pack(r.kvm));
            as.insert(QStringLiteral("ider"), pack(r.ider));
            m_activeSessions = std::move(as);
            emit activeSessionsChanged();
        });
}

void MachineDetailsController::refreshAuditLog()
{
    if (deferIfSshConnecting(PendingAuditLog)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshAuditLog(); };
    // Kick the state read and the records walk in parallel; QML only
    // re-renders once both have completed by binding to the single
    // `auditLogChanged` signal that each emits.
    incInflight();
    qumesh::wsman::getAuditLogState(m_client,
        [this](qumesh::wsman::AuditLogState s) {
            decInflight();
            QVariantMap st;
            st.insert(QStringLiteral("ok"), s.ok);
            st.insert(QStringLiteral("auditState"),             s.auditState);
            st.insert(QStringLiteral("overwritePolicy"),        s.overwritePolicy);
            st.insert(QStringLiteral("currentNumberOfRecords"), s.currentNumberOfRecords);
            st.insert(QStringLiteral("percentageFree"),         s.percentageFree);
            st.insert(QStringLiteral("maxAllowedAuditors"),     s.maxAllowedAuditors);
            st.insert(QStringLiteral("enabledState"),           s.enabledState);
            // Decoded bits — bit 0 enabled, bit 1 locked, bit 2 almost
            // full, bit 3 full, bit 4 no signing key.
            st.insert(QStringLiteral("enabled"),     (s.auditState & 0x01) != 0);
            st.insert(QStringLiteral("locked"),      (s.auditState & 0x02) != 0);
            st.insert(QStringLiteral("almostFull"),  (s.auditState & 0x04) != 0);
            st.insert(QStringLiteral("full"),        (s.auditState & 0x08) != 0);
            st.insert(QStringLiteral("noSigningKey"), (s.auditState & 0x10) != 0);
            m_auditLogState = std::move(st);
            emit auditLogChanged();
        });

    incInflight();
    qumesh::wsman::enumerateAuditLog(m_client,
        [this](qumesh::wsman::AuditLogResult r) {
            decInflight();
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Audit log: %1").arg(r.error));
            QVariantList list;
            list.reserve(r.entries.size());
            for (const auto &e : r.entries) {
                QVariantMap m;
                m.insert(QStringLiteral("auditAppId"),    e.auditAppId);
                m.insert(QStringLiteral("eventId"),       e.eventId);
                m.insert(QStringLiteral("auditAppLabel"), e.auditAppLabel);
                m.insert(QStringLiteral("eventLabel"),    e.eventLabel);
                m.insert(QStringLiteral("initiatorType"), e.initiatorType);
                m.insert(QStringLiteral("initiator"),     e.initiator);
                m.insert(QStringLiteral("unixSeconds"),   qlonglong(e.unixSeconds));
                m.insert(QStringLiteral("netAddress"),    e.netAddress);
                list.append(m);
            }
            m_auditLogEntries = std::move(list);
            emit auditLogChanged();
        });
}

void MachineDetailsController::refreshUserAccounts()
{
    if (deferIfSshConnecting(PendingUserAccounts)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshUserAccounts(); };
    incInflight();
    qumesh::wsman::enumerateUserAccounts(m_client,
        [this](qumesh::wsman::UserAccountsResult r) {
            decInflight();
            if (!r.ok) {
                if (!r.error.isEmpty())
                    setLastError(QStringLiteral("User accounts: %1").arg(r.error));
                return;
            }
            QVariantList list;
            list.reserve(r.accounts.size());
            for (const auto &u : r.accounts) {
                QVariantMap m;
                m.insert(QStringLiteral("handle"),           u.handle);
                m.insert(QStringLiteral("name"),             u.name);
                m.insert(QStringLiteral("digestUsername"),   u.digestUsername);
                m.insert(QStringLiteral("kerberosUserSidB64"), u.kerberosUserSidB64);
                m.insert(QStringLiteral("isKerberos"),
                         !u.kerberosUserSidB64.isEmpty());
                m.insert(QStringLiteral("accessPermission"),     u.accessPermission);
                m.insert(QStringLiteral("accessPermissionLabel"),
                         qumesh::wsman::accessPermissionLabel(u.accessPermission));
                // Human-readable realm list: filter out the unnamed
                // reserved slots, label realm 3 specially as
                // "Administrator" since it's the all-access bit.
                QVariantList realmList;
                QStringList realmLabels;
                bool isAdmin = (u.accessPermission == 999);
                for (int rr : u.realms) {
                    realmList.append(rr);
                    if (rr == 3) {
                        isAdmin = true;
                        realmLabels.append(QStringLiteral("Administrator"));
                    } else {
                        const QString rn = qumesh::wsman::realmName(rr);
                        if (!rn.isEmpty()) realmLabels.append(rn);
                    }
                }
                m.insert(QStringLiteral("realms"),       realmList);
                m.insert(QStringLiteral("realmCount"),   realmList.size());
                m.insert(QStringLiteral("realmsLabel"),  realmLabels.join(", "));
                m.insert(QStringLiteral("isAdmin"),      isAdmin);
                m.insert(QStringLiteral("enabled"),      u.enabled);
                m.insert(QStringLiteral("hidden"),       u.hidden);
                list.append(m);
            }

            m_userAccounts = std::move(list);
            emit userAccountsChanged();
        });
}

void MachineDetailsController::addUserAccount(const QVariantMap &fields)
{
    setLastError({});
    const QString username = fields.value(QStringLiteral("digestUsername"))
                                  .toString().trimmed();
    const QString plaintext = fields.value(QStringLiteral("password")).toString();
    if (username.isEmpty()) {
        setLastError(QStringLiteral("Add user: username is empty."));
        return;
    }
    if (plaintext.isEmpty()) {
        setLastError(QStringLiteral("Add user: password is empty."));
        return;
    }
    if (m_digestRealm.isEmpty()) {
        setLastError(QStringLiteral(
            "Add user: digest realm unknown — refresh General Settings first."));
        return;
    }
    const int access = fields.value(QStringLiteral("accessPermission"), 2).toInt();
    const QVariantList rin = fields.value(QStringLiteral("realms")).toList();
    QList<int> realms;
    realms.reserve(rin.size());
    for (const QVariant &v : rin)
        realms.append(v.toInt());

    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Add user: host is empty."));
        return;
    }
    const QString digestPw = qumesh::wsman::computeDigestPassword(
        username, m_digestRealm, plaintext);
    incInflight();
    qumesh::wsman::addUserAclEntryEx(m_client, username, digestPw, access, realms,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Add user: failed.")
                    : QStringLiteral("Add user: %1").arg(r.error));
                return;
            }
            refreshUserAccounts();
        });
}

void MachineDetailsController::updateUserAccount(int handle,
                                                 const QVariantMap &patch)
{
    setLastError({});
    if (handle < 0) {
        setLastError(QStringLiteral(
            "Update user: admin entry must be rotated via setAdminPassword."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Update user: host is empty."));
        return;
    }

    qumesh::wsman::UserAclEntryPatch p;
    if (patch.contains(QStringLiteral("digestUsername"))) {
        p.setDigestUsername = true;
        p.digestUsername =
            patch.value(QStringLiteral("digestUsername")).toString();
    }
    if (patch.contains(QStringLiteral("password"))) {
        if (m_digestRealm.isEmpty()) {
            setLastError(QStringLiteral(
                "Update user: digest realm unknown — refresh first."));
            return;
        }
        // Username for digest derivation: prefer the patched username if
        // present (rename + repassword in one go), otherwise look up
        // the existing one from the cached account list.
        QString u = p.setDigestUsername ? p.digestUsername : QString();
        if (u.isEmpty()) {
            for (const QVariant &v : std::as_const(m_userAccounts)) {
                const auto m = v.toMap();
                if (m.value(QStringLiteral("handle")).toInt() == handle) {
                    u = m.value(QStringLiteral("digestUsername")).toString();
                    break;
                }
            }
        }
        if (u.isEmpty()) {
            setLastError(QStringLiteral(
                "Update user: cannot resolve current username for digest."));
            return;
        }
        p.setDigestPassword = true;
        p.digestPassword = qumesh::wsman::computeDigestPassword(
            u, m_digestRealm,
            patch.value(QStringLiteral("password")).toString());
    }
    if (patch.contains(QStringLiteral("accessPermission"))) {
        p.setAccessPermission = true;
        p.accessPermission =
            patch.value(QStringLiteral("accessPermission")).toInt();
    }
    if (patch.contains(QStringLiteral("realms"))) {
        p.setRealms = true;
        const QVariantList rin = patch.value(QStringLiteral("realms")).toList();
        p.realms.reserve(rin.size());
        for (const QVariant &v : rin)
            p.realms.append(v.toInt());
    }

    incInflight();
    qumesh::wsman::updateUserAclEntryEx(m_client, handle, p,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Update user: failed.")
                    : QStringLiteral("Update user: %1").arg(r.error));
                return;
            }
            refreshUserAccounts();
        });
}

void MachineDetailsController::removeUserAccount(int handle)
{
    setLastError({});
    if (handle < 0) {
        setLastError(QStringLiteral("Remove user: cannot delete the admin entry."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Remove user: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::removeUserAclEntry(m_client, handle,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Remove user: failed.")
                    : QStringLiteral("Remove user: %1").arg(r.error));
                return;
            }
            refreshUserAccounts();
        });
}

void MachineDetailsController::setAccountEnabled(int handle, bool enabled)
{
    setLastError({});
    if (handle < 0) {
        setLastError(QStringLiteral(
            "Set enabled: cannot disable the admin entry."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Set enabled: host is empty."));
        return;
    }
    incInflight();
    qumesh::wsman::setAclEnabledState(m_client, handle, enabled,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Set enabled: failed.")
                    : QStringLiteral("Set enabled: %1").arg(r.error));
                return;
            }
            refreshUserAccounts();
        });
}

void MachineDetailsController::setAdminPassword(const QString &username,
                                                const QString &newPassword)
{
    setLastError({});
    const QString u = username.trimmed();
    if (u.isEmpty()) {
        setLastError(QStringLiteral("Admin: username is empty."));
        return;
    }
    if (newPassword.isEmpty()) {
        setLastError(QStringLiteral("Admin: password is empty."));
        return;
    }
    if (m_digestRealm.isEmpty()) {
        setLastError(QStringLiteral(
            "Admin: digest realm unknown — refresh General Settings first."));
        return;
    }
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Admin: host is empty."));
        return;
    }
    const QString digestPw =
        qumesh::wsman::computeDigestPassword(u, m_digestRealm, newPassword);
    incInflight();
    qumesh::wsman::setAdminAclEntryEx(m_client, u, digestPw,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(r.error.isEmpty()
                    ? QStringLiteral("Admin: failed.")
                    : QStringLiteral("Admin: %1").arg(r.error));
                return;
            }
            refreshUserAccounts();
        });
}

void MachineDetailsController::refreshPower()
{
    if (deferIfSshConnecting(PendingPower)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        setLastError(QStringLiteral("Host is empty — cannot refresh."));
        return;
    }
    m_pendingTrustResume = [this]{ refreshPower(); };
    incInflight();
    qumesh::wsman::getPowerState(m_client, [this](qumesh::wsman::PowerStateResult r) {
        if (r.ok) {
            if (m_powerState != r.powerState) {
                m_powerState = r.powerState;
                emit powerStateChanged();
            }
        } else if (!r.error.isEmpty()) {
            setLastError(QStringLiteral("Power: %1").arg(r.error));
        }
        decInflight();
    });

    // Power schemes share the Power section, so let them ride along on
    // the same refresh. Soft-failure on older firmware that doesn't
    // surface AMT_SystemPowerScheme — leaves the list empty.
    refreshPowerSchemes();
}

void MachineDetailsController::refreshPowerSchemes()
{
    if (deferIfSshConnecting(PendingPower)) return;
    rebuildEndpoint();
    if (m_host.isEmpty()) return;
    m_pendingTrustResume = [this]{ refreshPowerSchemes(); };
    incInflight();
    qumesh::wsman::getPowerSchemes(m_client,
        [this](qumesh::wsman::PowerSchemesResult r) {
            if (r.ok) {
                QVariantList list;
                list.reserve(r.schemes.size());
                for (const auto &p : r.schemes) {
                    QVariantMap m;
                    m.insert(QStringLiteral("instanceId"),  p.instanceId);
                    m.insert(QStringLiteral("schemeGuid"),  p.schemeGuid);
                    m.insert(QStringLiteral("description"), p.description);
                    list.append(m);
                }
                m_powerSchemes = std::move(list);
                m_currentPowerSchemeId = r.currentInstanceId;
                emit powerSchemesChanged();
            } else if (!r.error.isEmpty()) {
                // Soft failure — older firmware may not expose the
                // class. Leave the previous list in place.
            }
            decInflight();
        });
}

void MachineDetailsController::setPowerScheme(const QString &instanceId)
{
    if (deferIfSshConnecting(PendingPower)) return;
    rebuildEndpoint();
    if (m_host.isEmpty() || instanceId.isEmpty()) return;
    incInflight();
    qumesh::wsman::setPowerScheme(m_client, instanceId,
        [this](qumesh::wsman::InvokeResult r) {
            if (!r.ok && !r.error.isEmpty())
                setLastError(QStringLiteral("Set power scheme: %1").arg(r.error));
            decInflight();
            // Re-read so the radio dot follows the firmware's reality
            // (in case the Set succeeded but firmware moved the dot
            // elsewhere, or failed and stayed put).
            refreshPowerSchemes();
        });
}

void MachineDetailsController::bootToBios(bool reset)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(reset ? 10 : 2);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = reset ? 10 : 2;
    p.biosSetup = true;
    qumesh::wsman::performBootAction(m_client, p,
        [this, reset](qumesh::wsman::InvokeResult r) {
            decInflight();
            const int code = reset ? 10 : 2;
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to BIOS: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::bootToPxe(bool reset)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(reset ? 10 : 2);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = reset ? 10 : 2;
    p.amtBootSource = QStringLiteral("Force PXE Boot");
    qumesh::wsman::performBootAction(m_client, p,
        [this, reset](qumesh::wsman::InvokeResult r) {
            decInflight();
            const int code = reset ? 10 : 2;
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to PXE: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::bootToIderCdrom(bool reset)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(reset ? 10 : 2);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = reset ? 10 : 2;
    p.amtBootSource = QStringLiteral("Force CD/DVD Boot");
    p.useIder = true;
    p.iderBootDevice = 1; // CD-ROM
    qumesh::wsman::performBootAction(m_client, p,
        [this, reset](qumesh::wsman::InvokeResult r) {
            decInflight();
            const int code = reset ? 10 : 2;
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to IDE-R CDROM: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::bootToIderFloppy(bool reset)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(reset ? 10 : 2);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = reset ? 10 : 2;
    p.amtBootSource = QStringLiteral("Force CD/DVD Boot");
    p.useIder = true;
    p.iderBootDevice = 0; // Floppy
    qumesh::wsman::performBootAction(m_client, p,
        [this, reset](qumesh::wsman::InvokeResult r) {
            decInflight();
            const int code = reset ? 10 : 2;
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to IDE-R Floppy: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

int MachineDetailsController::amtVersionMajor() const
{
    // amtVersion looks like "11.8.50" / "16.1.25.0" / "5.2.0". Parse
    // the leading integer; return -1 when we haven't fetched it yet.
    if (m_amtVersion.isEmpty()) return -1;
    const int dot = m_amtVersion.indexOf(QLatin1Char('.'));
    const QString head = dot < 0 ? m_amtVersion : m_amtVersion.left(dot);
    bool ok = false;
    const int n = head.toInt(&ok);
    return ok ? n : -1;
}

void MachineDetailsController::osWakeFromSleep()
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(2);
    incInflight();
    qumesh::wsman::requestOsPowerStateChange(m_client, 2,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("OS wake: %1").arg(r.error));
                emit powerChangeCompleted(2, false, r.error);
                return;
            }
            emit powerChangeCompleted(2, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::osPutToSleep()
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(3);
    incInflight();
    qumesh::wsman::requestOsPowerStateChange(m_client, 3,
        [this](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("OS sleep: %1").arg(r.error));
                emit powerChangeCompleted(3, false, r.error);
                return;
            }
            emit powerChangeCompleted(3, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::bootToSecureErase(bool reset, const QString &password)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    const int code = reset ? 10 : 2;
    emit powerChangeRequested(code);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = code;
    p.biosSetup = true;
    p.secureErase = true;
    p.rsePassword = password;
    qumesh::wsman::performBootAction(m_client, p,
        [this, code](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to Secure Erase: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::bootToPlatformErase(bool reset, int flagsIn,
                                                    const QString &psid,
                                                    const QString &ssdPassword)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    if (flagsIn == 0) {
        setLastError(QStringLiteral("Platform Erase: no sub-actions selected"));
        return;
    }
    setLastError({});
    const int code = reset ? 10 : 2;
    emit powerChangeRequested(code);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = code;
    p.platformErase = true;
    int tlvCount = 0;
    const QByteArray tlv = qumesh::wsman::buildPlatformEraseTlv(
        static_cast<quint32>(flagsIn), psid, ssdPassword, &tlvCount);
    p.platformEraseTlvBase64 = QString::fromLatin1(tlv.toBase64());
    p.platformEraseTlvCount = tlvCount;
    qumesh::wsman::performBootAction(m_client, p,
        [this, code](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to Platform Erase: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::bootToHttpsBootUrl(bool reset, const QString &url)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    if (!url.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)) {
        setLastError(QStringLiteral("HTTPS Boot: URL must start with https://"));
        return;
    }
    setLastError({});
    const int code = reset ? 10 : 2;
    emit powerChangeRequested(code);
    incInflight();
    qumesh::wsman::BootActionParams p;
    p.targetPowerState = code;
    p.amtBootSource = QStringLiteral("Force OCR UEFI HTTPS Boot");
    p.httpsBootUrl = true;
    p.httpsBootUrlStr = url;
    qumesh::wsman::performBootAction(m_client, p,
        [this, code](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to HTTPS URL: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

void MachineDetailsController::changePowerState(int code)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(code, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    emit powerChangeRequested(code);
    incInflight();
    qumesh::wsman::requestPowerStateChange(m_client, code,
        [this, code](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("Power change %1: %2")
                                  .arg(code).arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            // Give the firmware ~1 s to settle before re-reading the
            // current state. Keeping it synchronous (no QTimer) — the
            // user can hit Refresh if they want sooner.
            refreshPower();
        });
}

namespace {

// Strip the "Intel(r) AMT: " prefix from a boot-source InstanceID so
// it slots into `BootActionParams::amtBootSource`, which the chain's
// `buildChangeBootOrderEnvelope` re-prepends.
QString trimAmtPrefix(const QString &instanceId)
{
    constexpr QLatin1String kPrefix("Intel(r) AMT: ");
    if (instanceId.startsWith(kPrefix))
        return instanceId.mid(kPrefix.size());
    return instanceId;
}

} // namespace

void MachineDetailsController::bootToWinRE(bool reset)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    setLastError({});
    const int code = reset ? 10 : 2;
    emit powerChangeRequested(code);
    incInflight();

    // Phase 1: enumerate CIM_BootSourceSetting and locate the row
    // whose BIOSBootString contains "WinRe" — that's the firmware-
    // registered Windows Recovery boot option. Matches Intel MPS's
    // `getWinReBootSource` heuristic. If the BIOS hasn't registered
    // one, we surface an error rather than silently picking a wrong
    // row.
    qumesh::wsman::enumerateBootSourceSettings(m_client,
        [this, code](qumesh::wsman::BootSourceSettingsResult res) {
            if (!res.ok) {
                decInflight();
                setLastError(QStringLiteral(
                    "Boot to WinRE: enumerate boot sources: %1").arg(res.error));
                emit powerChangeCompleted(code, false, lastError());
                return;
            }
            const qumesh::wsman::BootSourceSetting *winre = nullptr;
            for (const auto &s : res.sources) {
                if (s.biosBootString.contains(
                        QStringLiteral("WinRe"), Qt::CaseInsensitive)
                    && s.instanceId.startsWith(QStringLiteral(
                        "Intel(r) AMT: Force OCR UEFI Boot Option"))) {
                    winre = &s;
                    break;
                }
            }
            if (winre == nullptr) {
                decInflight();
                setLastError(QStringLiteral(
                    "Boot to WinRE: BIOS hasn't registered a Windows Recovery boot option."));
                emit powerChangeCompleted(code, false, lastError());
                return;
            }

            int tlvCount = 0;
            const QByteArray tlv = qumesh::wsman::buildOcrPbaBootTlv(
                winre->bootString, &tlvCount);

            qumesh::wsman::BootActionParams p;
            p.targetPowerState = code;
            p.amtBootSource = trimAmtPrefix(winre->instanceId);
            p.oneClickRecovery = true;
            p.ocrTlvBase64 = QString::fromLatin1(tlv.toBase64());
            p.ocrTlvCount = tlvCount;

            qumesh::wsman::performBootAction(m_client, p,
                [this, code](qumesh::wsman::InvokeResult r) {
                    decInflight();
                    if (!r.ok) {
                        setLastError(QStringLiteral("Boot to WinRE: %1").arg(r.error));
                        emit powerChangeCompleted(code, false, r.error);
                        return;
                    }
                    emit powerChangeCompleted(code, true, QString());
                    refreshPower();
                });
        });
}

void MachineDetailsController::bootToLocalPBA(bool reset, int pbaIndex)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    if (pbaIndex < 1 || pbaIndex > 10) {
        setLastError(QStringLiteral("Boot to PBA: pbaIndex must be 1..10."));
        emit powerChangeCompleted(0, false, lastError());
        return;
    }
    setLastError({});
    const int code = reset ? 10 : 2;
    emit powerChangeRequested(code);
    incInflight();

    qumesh::wsman::enumerateBootSourceSettings(m_client,
        [this, code, pbaIndex](qumesh::wsman::BootSourceSettingsResult res) {
            if (!res.ok) {
                decInflight();
                setLastError(QStringLiteral(
                    "Boot to PBA: enumerate boot sources: %1").arg(res.error));
                emit powerChangeCompleted(code, false, lastError());
                return;
            }
            // Collect every Force OCR UEFI Boot Option row in
            // InstanceID order. The Nth match is the operator's
            // "PBA #N" pick — same indexing convention Intel's MPS
            // uses via bootPath strings.
            QList<const qumesh::wsman::BootSourceSetting *> pbas;
            for (const auto &s : res.sources) {
                if (s.instanceId.startsWith(QStringLiteral(
                        "Intel(r) AMT: Force OCR UEFI Boot Option"))) {
                    pbas.append(&s);
                }
            }
            std::sort(pbas.begin(), pbas.end(),
                      [](const qumesh::wsman::BootSourceSetting *a,
                         const qumesh::wsman::BootSourceSetting *b) {
                          return a->instanceId < b->instanceId;
                      });
            if (pbaIndex > pbas.size()) {
                decInflight();
                setLastError(QStringLiteral(
                    "Boot to PBA: only %1 PBA boot options registered.")
                    .arg(pbas.size()));
                emit powerChangeCompleted(code, false, lastError());
                return;
            }
            const auto *pba = pbas.at(pbaIndex - 1);

            int tlvCount = 0;
            const QByteArray tlv = qumesh::wsman::buildOcrPbaBootTlv(
                pba->bootString, &tlvCount);

            qumesh::wsman::BootActionParams p;
            p.targetPowerState = code;
            p.amtBootSource = trimAmtPrefix(pba->instanceId);
            p.oneClickRecovery = true;
            p.ocrTlvBase64 = QString::fromLatin1(tlv.toBase64());
            p.ocrTlvCount = tlvCount;

            qumesh::wsman::performBootAction(m_client, p,
                [this, code](qumesh::wsman::InvokeResult r) {
                    decInflight();
                    if (!r.ok) {
                        setLastError(QStringLiteral("Boot to PBA: %1").arg(r.error));
                        emit powerChangeCompleted(code, false, r.error);
                        return;
                    }
                    emit powerChangeCompleted(code, true, QString());
                    refreshPower();
                });
        });
}

void MachineDetailsController::bootToOcrHttpsUrl(bool reset,
                                                 const QString &url,
                                                 const QString &hashAlg,
                                                 const QString &hashHex,
                                                 const QString &pinnedServerCertHashAlg,
                                                 const QString &pinnedServerCertHashHex,
                                                 const QString &username,
                                                 const QString &password)
{
    rebuildEndpoint();
    if (m_host.isEmpty()) {
        emit powerChangeCompleted(0, false, QStringLiteral("Host is empty"));
        return;
    }
    if (!url.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)) {
        setLastError(QStringLiteral("Boot to OCR HTTPS: URL must start with https://"));
        emit powerChangeCompleted(0, false, lastError());
        return;
    }
    setLastError({});
    const int code = reset ? 10 : 2;
    emit powerChangeRequested(code);
    incInflight();

    // Decode the hex digests. `QByteArray::fromHex` is tolerant of
    // whitespace + colon separators so operators can paste any
    // standard digest format. Empty input → empty output, which the
    // TLV builder treats as "skip this entry".
    const QByteArray imageHash = QByteArray::fromHex(hashHex.toLatin1());
    const QByteArray pinnedCertHash =
        QByteArray::fromHex(pinnedServerCertHashHex.toLatin1());

    int tlvCount = 0;
    const QByteArray tlv = qumesh::wsman::buildOcrHttpsBootPinnedTlv(
        url, hashAlg, imageHash,
        pinnedServerCertHashAlg, pinnedCertHash,
        username, password, &tlvCount);

    qumesh::wsman::BootActionParams p;
    p.targetPowerState = code;
    // Same boot source InstanceID as the existing UEFI HTTPS Boot —
    // the OCR-vs-plain HTTPS Boot distinction is encoded in the TLV
    // payload (image-hash pinning, server-cert pinning), not the
    // boot source name.
    p.amtBootSource = QStringLiteral("Force OCR UEFI HTTPS Boot");
    p.oneClickRecovery = true;
    p.ocrTlvBase64 = QString::fromLatin1(tlv.toBase64());
    p.ocrTlvCount = tlvCount;

    qumesh::wsman::performBootAction(m_client, p,
        [this, code](qumesh::wsman::InvokeResult r) {
            decInflight();
            if (!r.ok) {
                setLastError(QStringLiteral("Boot to OCR HTTPS: %1").arg(r.error));
                emit powerChangeCompleted(code, false, r.error);
                return;
            }
            emit powerChangeCompleted(code, true, QString());
            refreshPower();
        });
}

} // namespace qumesh::app
