// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#pragma once

#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVariantList>
#include <QtQmlIntegration>

#include "wsman/wsman_client.h" // for PeerCertSummary

#include <QVariantMap>

#include <functional>

class QTimer;

namespace qumesh::ssh { class SshSession; }

namespace qumesh::app {

/// QML-creatable controller for one Machine Details window. Owns a
/// WSMAN client, exposes per-category fetch methods, and surfaces the
/// results as Q_PROPERTYs the QML side binds to. No background polling
/// — every fetch is user-triggered (or kicked off when a page becomes
/// visible).
class MachineDetailsController : public QObject
{
    Q_OBJECT
    QML_ELEMENT

    // Connection inputs (set by the QML window from the saved machine).
    Q_PROPERTY(QString host READ host WRITE setHost NOTIFY hostChanged)
    Q_PROPERTY(QString user READ user WRITE setUser NOTIFY userChanged)
    Q_PROPERTY(QString password READ password WRITE setPassword NOTIFY passwordChanged)
    Q_PROPERTY(bool tls READ tls WRITE setTls NOTIFY tlsChanged)
    Q_PROPERTY(QStringList trustedFingerprints READ trustedFingerprints
                   WRITE setTrustedFingerprints NOTIFY trustedFingerprintsChanged)

    // SSH tunnel — `true` when the saved machine config asks us to route
    // every byte through an SSH session. The actual SSH parameters are
    // pushed via `setSshConfig`; this bool is the cheap "is tunneling
    // active?" indicator the QML side binds to for the title-bar badge.
    Q_PROPERTY(bool sshTunnelActive READ sshTunnelActive NOTIFY sshTunnelStateChanged)
    Q_PROPERTY(QString sshTunnelStatus READ sshTunnelStatus NOTIFY sshTunnelStateChanged)

    // Trust-on-first-use surface for CertTrustDialog. Mirrors the shape
    // SolController / KvmController already expose so the same dialog
    // can render us.
    Q_PROPERTY(bool awaitingTrust READ awaitingTrust NOTIFY awaitingTrustChanged)
    Q_PROPERTY(QString pendingCertSubject READ pendingCertSubject NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertIssuer READ pendingCertIssuer NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertFingerprint READ pendingCertFingerprint NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertNotBefore READ pendingCertNotBefore NOTIFY pendingCertChanged)
    Q_PROPERTY(QString pendingCertNotAfter READ pendingCertNotAfter NOTIFY pendingCertChanged)

    // Trust-on-first-use surface for the SSH host-key prompt. Mirrors
    // the pendingCert* shape so SshHostKeyTrustDialog can render us via
    // the same controller-as-QtObject convention.
    Q_PROPERTY(bool awaitingSshHostKeyTrust READ awaitingSshHostKeyTrust
                   NOTIFY sshHostKeyPromptChanged)
    Q_PROPERTY(QString pendingSshHostKeyFingerprint READ pendingSshHostKeyFingerprint
                   NOTIFY sshHostKeyPromptChanged)
    Q_PROPERTY(QString pendingSshHostKeyType READ pendingSshHostKeyType
                   NOTIFY sshHostKeyPromptChanged)

    // Overview / power.
    Q_PROPERTY(int powerState READ powerState NOTIFY powerStateChanged)
    Q_PROPERTY(QString powerStateLabel READ powerStateLabel NOTIFY powerStateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY lastErrorChanged)

    // Identify.
    Q_PROPERTY(QString amtProtocolVersion READ amtProtocolVersion NOTIFY identifyChanged)
    Q_PROPERTY(QString amtVendor READ amtVendor NOTIFY identifyChanged)
    Q_PROPERTY(QString amtVersion READ amtVersion NOTIFY identifyChanged)
    /// Parsed `amtVersion.major` (the first integer of the dotted
    /// version) — used by the QML side to gate menu entries on
    /// firmware that needs a minimum AMT level (e.g. OS Wake-on-Sleep
    /// requires AMT 10+).
    Q_PROPERTY(int amtVersionMajor READ amtVersionMajor NOTIFY identifyChanged)

    // General settings.
    Q_PROPERTY(QString hostName READ hostName NOTIFY generalSettingsChanged)
    Q_PROPERTY(QString domainName READ domainName NOTIFY generalSettingsChanged)
    Q_PROPERTY(QString digestRealm READ digestRealm NOTIFY generalSettingsChanged)
    Q_PROPERTY(bool networkInterfaceEnabled READ networkInterfaceEnabled NOTIFY generalSettingsChanged)
    Q_PROPERTY(bool rmcpPingResponseEnabled READ rmcpPingResponseEnabled NOTIFY generalSettingsChanged)
    /// -1 = unknown, 0 = plugged in / AC, 1 = on battery.
    Q_PROPERTY(int powerSource READ powerSource NOTIFY generalSettingsChanged)
    /// Localized label matching `powerSource` (so QML doesn't need its
    /// own switch).
    Q_PROPERTY(QString powerSourceLabel READ powerSourceLabel NOTIFY generalSettingsChanged)

    // Intel ME firmware version (CIM_SoftwareIdentity[InstanceID='AMT']).
    Q_PROPERTY(QString meVersionString READ meVersionString NOTIFY meVersionChanged)
    /// Full AMT firmware fingerprint — SKU, build, recovery image,
    /// vendor ID, flash version, plus a friendly SKU label. Keys mirror
    /// the named fields on `MeVersionResult` so the QML binds straight
    /// to `controller.amtFingerprint.sku` / `.skuLabel` / etc. Empty
    /// until the first successful overview refresh. See issue #174.
    Q_PROPERTY(QVariantMap amtFingerprint READ amtFingerprint NOTIFY meVersionChanged)

    // Provisioning state (AMT_SetupAndConfigurationService).
    Q_PROPERTY(int provisioningState READ provisioningState NOTIFY setupConfigChanged)
    Q_PROPERTY(int provisioningMode  READ provisioningMode  NOTIFY setupConfigChanged)
    Q_PROPERTY(QString provisioningModeLabel READ provisioningModeLabel
                   NOTIFY setupConfigChanged)

    // Active features — derived from AMT_RedirectionService + CIM_KVMRedirectionSAP.
    Q_PROPERTY(bool redirectionListenerEnabled READ redirectionListenerEnabled
                   NOTIFY redirectionStatusChanged)
    Q_PROPERTY(bool solEnabled  READ solEnabled  NOTIFY redirectionStatusChanged)
    Q_PROPERTY(bool iderEnabled READ iderEnabled NOTIFY redirectionStatusChanged)
    Q_PROPERTY(bool kvmEnabled  READ kvmEnabled  NOTIFY redirectionStatusChanged)
    Q_PROPERTY(bool kvmAvailable READ kvmAvailable NOTIFY redirectionStatusChanged)

    // Computer system.
    Q_PROPERTY(QString systemName READ systemName NOTIFY computerSystemChanged)
    Q_PROPERTY(QString systemElementName READ systemElementName NOTIFY computerSystemChanged)
    Q_PROPERTY(QString systemUuid READ systemUuid NOTIFY computerSystemChanged)

    // Ethernet settings — single-interface scalars (interface 0) kept
    // for backward compat; the QML side now also reads
    // `networkInterfaces` for the multi-NIC + IPv6 view.
    Q_PROPERTY(QString macAddress READ macAddress NOTIFY ethernetChanged)
    Q_PROPERTY(bool dhcpEnabled READ dhcpEnabled NOTIFY ethernetChanged)
    Q_PROPERTY(QString ipAddress READ ipAddress NOTIFY ethernetChanged)
    Q_PROPERTY(QString subnetMask READ subnetMask NOTIFY ethernetChanged)
    Q_PROPERTY(QString defaultGateway READ defaultGateway NOTIFY ethernetChanged)
    Q_PROPERTY(QString primaryDns READ primaryDns NOTIFY ethernetChanged)
    Q_PROPERTY(QString secondaryDns READ secondaryDns NOTIFY ethernetChanged)
    Q_PROPERTY(QVariantList networkInterfaces READ networkInterfaces
                   NOTIFY ethernetChanged)

    // Time.
    Q_PROPERTY(qint64 amtEpoch READ amtEpoch NOTIFY timeChanged)

    // Power schemes (#162) — read-only list + the currently-active
    // InstanceID. Empty until first refresh; `currentPowerSchemeId`
    // may stay empty if the firmware doesn't surface the
    // CIM_ElementSettingData association.
    Q_PROPERTY(QVariantList powerSchemes READ powerSchemes
                   NOTIFY powerSchemesChanged)
    Q_PROPERTY(QString currentPowerSchemeId READ currentPowerSchemeId
                   NOTIFY powerSchemesChanged)

    // Event log — list of QVariantMaps for the QML ListView.
    Q_PROPERTY(QVariantList eventLog READ eventLog NOTIFY eventLogChanged)

    // User accounts — list of QVariantMaps.
    Q_PROPERTY(QVariantList userAccounts READ userAccounts NOTIFY userAccountsChanged)

    // Hardware inventory — a QVariantMap so QML can index into nested
    // lists (processors/memoryModules/storageDevices/battery) without
    // a separate Q_PROPERTY per section.
    Q_PROPERTY(QVariantMap hardwareInventory READ hardwareInventory NOTIFY hardwareChanged)

    // Audit log — read-only.
    Q_PROPERTY(QVariantMap  auditLogState   READ auditLogState   NOTIFY auditLogChanged)
    Q_PROPERTY(QVariantList auditLogEntries READ auditLogEntries NOTIFY auditLogChanged)

    // Active redirection sessions (SOL / KVM / IDE-R) — read-only.
    Q_PROPERTY(QVariantMap activeSessions READ activeSessions NOTIFY activeSessionsChanged)

    // Device certificate store — read-only.
    Q_PROPERTY(QVariantMap  deviceCertStore READ deviceCertStore NOTIFY deviceCertStoreChanged)

    // CIRA / Remote-access — read-only.
    Q_PROPERTY(QVariantMap  remoteAccess READ remoteAccess NOTIFY remoteAccessChanged)

    // Wireless — read-only.
    Q_PROPERTY(QVariantMap  wireless READ wireless NOTIFY wirelessChanged)

    // Agent presence watchdogs (#164 Phase A) — read-only snapshot of
    // AMT_AgentPresenceCapabilities + the AMT_AgentPresenceWatchdog list.
    Q_PROPERTY(QVariantMap  agentPresence READ agentPresence NOTIFY agentPresenceChanged)

    // Event subscriptions (#163 Phase A) — filters / listeners / subs.
    Q_PROPERTY(QVariantMap  eventSubscriptions READ eventSubscriptions
                   NOTIFY eventSubscriptionsChanged)

    // Wake alarms (#161 Phase A) — read-only list of IPS_AlarmClockOccurrence
    // rows, with friendly local-time + interval labels resolved in the
    // controller so the QML can render in a single binding.
    Q_PROPERTY(QVariantList wakeAlarms READ wakeAlarms NOTIFY wakeAlarmsChanged)

    // WSMAN browser (#167) — dev tool. Set by the most recent
    // `wsmanBrowse()` call.
    Q_PROPERTY(QVariantMap wsmanBrowseResult READ wsmanBrowseResult
                   NOTIFY wsmanBrowseResultChanged)

    // System Defense (#165 Phase A) — ACM-only read-only snapshot.
    // `supported=false` when the firmware doesn't expose the classes
    // (ISM SKUs). QML further hides the pane when provisioningMode == 4
    // (CCM) since System Defense is administered in ACM.
    Q_PROPERTY(QVariantMap systemDefense READ systemDefense
                   NOTIFY systemDefenseChanged)

    // Boot capabilities — which power-to-X menu entries we show.
    Q_PROPERTY(bool capBiosSetup READ capBiosSetup NOTIFY bootCapabilitiesChanged)
    Q_PROPERTY(bool capBiosPause READ capBiosPause NOTIFY bootCapabilitiesChanged)
    Q_PROPERTY(bool capSecureErase READ capSecureErase NOTIFY bootCapabilitiesChanged)
    Q_PROPERTY(bool capPlatformErase READ capPlatformErase NOTIFY bootCapabilitiesChanged)
    /// Raw `AMT_BootCapabilities.PlatformErase` bitmask the QML uses to
    /// build the per-sub-action checkbox list.
    Q_PROPERTY(int capPlatformEraseMask READ capPlatformEraseMask NOTIFY bootCapabilitiesChanged)
    Q_PROPERTY(bool capForceUefiHttpsBoot READ capForceUefiHttpsBoot NOTIFY bootCapabilitiesChanged)
    /// One-Click Recovery (#170) capability bits, surfaced as scalar
    /// `Q_PROPERTY` for QML's enable/visible gates. Mirrors the
    /// `AMT_BootCapabilities` fields `ForceWinREBoot` and
    /// `ForceUEFILocalPBABoot`.
    Q_PROPERTY(bool capForceWinReBoot READ capForceWinReBoot NOTIFY bootCapabilitiesChanged)
    Q_PROPERTY(bool capForceUefiLocalPbaBoot READ capForceUefiLocalPbaBoot NOTIFY bootCapabilitiesChanged)

    /// Comprehensive `AMT_BootCapabilities` snapshot keyed by capability
    /// name for the read-only Boot Capabilities pane (#172). Each value
    /// is a `bool`. Empty until the first successful Hardware refresh.
    Q_PROPERTY(QVariantMap bootCapabilities READ bootCapabilities NOTIFY bootCapabilitiesChanged)

    // User-consent (OptIn) policy + runtime state. Populated after
    // `refreshOverview` (and refreshed on demand via `refreshOptInStatus`).
    Q_PROPERTY(bool optInRequired READ optInRequired NOTIFY optInStatusChanged)
    Q_PROPERTY(int optInState READ optInState NOTIFY optInStatusChanged)
    Q_PROPERTY(bool canModifyOptInPolicy READ canModifyOptInPolicy NOTIFY optInStatusChanged)
    Q_PROPERTY(bool kvmOptInPolicy READ kvmOptInPolicy NOTIFY optInStatusChanged)
    /// `IPS_KVMRedirectionSettingData.OptInPolicyTimeout` — seconds the
    /// firmware will wait for the operator to enter the consent code.
    /// Drives the countdown on the PIN-entry modal. 0 when the firmware
    /// didn't expose the field. See #171.
    Q_PROPERTY(int optInPolicyTimeoutSec READ optInPolicyTimeoutSec
                   NOTIFY optInStatusChanged)
    /// True when redirection may proceed: either consent isn't required
    /// at all, or the firmware has already accepted a code.
    ///
    /// AMT reports RECEIVED(3) once `SendOptInCode` succeeds and only
    /// moves to IN_SESSION(4) once a redirection session is actually
    /// running, so both count as satisfied. Testing `state != 4` alone
    /// re-requests consent the instant it is granted — see #433 and the
    /// reference implementation's `OptInState != 3 && != 4` gate.
    Q_PROPERTY(bool optInSatisfied READ optInSatisfied NOTIFY optInStatusChanged)
    /// False until `getOptInStatus` has succeeded once. Callers must
    /// not infer "consent isn't required" from the default-constructed
    /// state — that would dial redirection before we know the policy.
    Q_PROPERTY(bool optInStatusKnown READ optInStatusKnown NOTIFY optInStatusChanged)
    /// True between `startOptIn()` and the resolution of that round
    /// (code accepted, cancelled, expired, or the failure cap hit).
    /// Guards against re-entering the consent dance.
    Q_PROPERTY(bool optInRoundActive READ optInRoundActive
                   NOTIFY optInRoundActiveChanged)

    // KVM settings (#175) — sit on the same IPS_KVMRedirectionSettingData
    // class as the OptIn fields above, so they ride the same refresh.
    Q_PROPERTY(bool kvmIs5900PortEnabled READ kvmIs5900PortEnabled
                   NOTIFY optInStatusChanged)
    Q_PROPERTY(int  kvmSessionTimeoutMinutes READ kvmSessionTimeoutMinutes
                   NOTIFY optInStatusChanged)
    Q_PROPERTY(bool kvmGreyscaleRequested READ kvmGreyscaleRequested
                   NOTIFY optInStatusChanged)

public:
    /// The three redirection protocols, numbered to match the session
    /// window's tab order so QML can pass a tab index straight through.
    enum RedirProtocol {
        Sol  = 0,
        Kvm  = 1,
        Ider = 2,
    };
    Q_ENUM(RedirProtocol)

    explicit MachineDetailsController(QObject *parent = nullptr);
    ~MachineDetailsController() override;

    [[nodiscard]] QString host() const { return m_host; }
    [[nodiscard]] QString user() const { return m_user; }
    [[nodiscard]] QString password() const { return m_password; }
    [[nodiscard]] bool    tls()  const { return m_tls; }
    [[nodiscard]] QStringList trustedFingerprints() const { return m_trustedFingerprints; }
    void setHost(const QString &v);
    void setUser(const QString &v);
    void setPassword(const QString &v);
    void setTls(bool v);
    void setTrustedFingerprints(QStringList v);
    /// Point the WSMAN endpoint at an arbitrary port. Tests only —
    /// production derives 16992/16993 from `tls`.
    void setPortForTest(quint16 v) { m_portOverride = v; rebuildEndpoint(); }

    [[nodiscard]] bool sshTunnelActive() const;
    [[nodiscard]] QString sshTunnelStatus() const { return m_sshTunnelStatus; }

    /// Apply the per-machine SSH config (as produced by
    /// `ComputerModel::sshConfigFor`). When `cfg["enabled"]` is true the
    /// controller routes every WSMAN request through the SSH tunnel by
    /// installing a socket factory on the underlying `WsmanClient`.
    /// Passing an empty / disabled map tears any existing tunnel down.
    Q_INVOKABLE void setSshConfig(const QVariantMap &cfg);

    [[nodiscard]] bool awaitingTrust() const { return m_awaitingTrust; }
    [[nodiscard]] QString pendingCertSubject() const { return m_pendingCert.subject; }
    [[nodiscard]] QString pendingCertIssuer() const { return m_pendingCert.issuer; }
    [[nodiscard]] QString pendingCertFingerprint() const { return m_pendingCert.fingerprintSha256; }
    [[nodiscard]] QString pendingCertNotBefore() const { return m_pendingCert.notBefore; }
    [[nodiscard]] QString pendingCertNotAfter() const { return m_pendingCert.notAfter; }

    [[nodiscard]] bool awaitingSshHostKeyTrust() const { return m_awaitingSshHostKeyTrust; }
    [[nodiscard]] QString pendingSshHostKeyFingerprint() const { return m_pendingSshHostKey; }
    [[nodiscard]] QString pendingSshHostKeyType() const { return m_pendingSshHostKeyType; }

    [[nodiscard]] int powerState() const { return m_powerState; }
    [[nodiscard]] QString powerStateLabel() const;
    [[nodiscard]] bool busy() const { return m_inflight > 0; }
    [[nodiscard]] QString lastError() const { return m_lastError; }

    [[nodiscard]] QString amtProtocolVersion() const { return m_amtProtocolVersion; }
    [[nodiscard]] QString amtVendor() const { return m_amtVendor; }
    [[nodiscard]] QString amtVersion() const { return m_amtVersion; }
    [[nodiscard]] int amtVersionMajor() const;

    [[nodiscard]] QString hostName() const { return m_hostName; }
    [[nodiscard]] QString domainName() const { return m_domainName; }
    [[nodiscard]] QString digestRealm() const { return m_digestRealm; }
    [[nodiscard]] bool networkInterfaceEnabled() const { return m_networkInterfaceEnabled; }
    [[nodiscard]] bool rmcpPingResponseEnabled() const { return m_rmcpPingResponseEnabled; }
    [[nodiscard]] int     powerSource() const { return m_powerSource; }
    [[nodiscard]] QString powerSourceLabel() const;

    [[nodiscard]] QString meVersionString() const { return m_meVersionString; }
    [[nodiscard]] QVariantMap amtFingerprint() const { return m_amtFingerprint; }

    [[nodiscard]] int provisioningState() const { return m_provisioningState; }
    [[nodiscard]] int provisioningMode()  const { return m_provisioningMode; }
    [[nodiscard]] QString provisioningModeLabel() const;

    [[nodiscard]] bool redirectionListenerEnabled() const { return m_redirectionListenerEnabled; }
    [[nodiscard]] bool solEnabled()   const { return m_solEnabled; }
    [[nodiscard]] bool iderEnabled()  const { return m_iderEnabled; }
    [[nodiscard]] bool kvmEnabled()   const { return m_kvmEnabled; }
    [[nodiscard]] bool kvmAvailable() const { return m_kvmAvailable; }

    [[nodiscard]] QString systemName() const { return m_systemName; }
    [[nodiscard]] QString systemElementName() const { return m_systemElementName; }
    [[nodiscard]] QString systemUuid() const { return m_systemUuid; }

    [[nodiscard]] QString macAddress() const { return m_macAddress; }
    [[nodiscard]] bool dhcpEnabled() const { return m_dhcpEnabled; }
    [[nodiscard]] QString ipAddress() const { return m_ipAddress; }
    [[nodiscard]] QString subnetMask() const { return m_subnetMask; }
    [[nodiscard]] QString defaultGateway() const { return m_defaultGateway; }
    [[nodiscard]] QString primaryDns() const { return m_primaryDns; }
    [[nodiscard]] QString secondaryDns() const { return m_secondaryDns; }
    [[nodiscard]] QVariantList networkInterfaces() const { return m_networkInterfaces; }

    [[nodiscard]] qint64 amtEpoch() const { return m_amtEpoch; }

    [[nodiscard]] QVariantList powerSchemes() const { return m_powerSchemes; }
    [[nodiscard]] QString currentPowerSchemeId() const { return m_currentPowerSchemeId; }

    [[nodiscard]] bool capBiosSetup() const { return m_capBiosSetup; }
    [[nodiscard]] bool capBiosPause() const { return m_capBiosPause; }
    [[nodiscard]] bool capSecureErase() const { return m_capSecureErase; }
    [[nodiscard]] bool capPlatformErase() const { return m_capPlatformErase; }
    [[nodiscard]] int  capPlatformEraseMask() const {
        return static_cast<int>(m_capPlatformEraseMask);
    }
    [[nodiscard]] bool capForceUefiHttpsBoot() const { return m_capForceUefiHttpsBoot; }
    [[nodiscard]] bool capForceWinReBoot() const { return m_capForceWinReBoot; }
    [[nodiscard]] bool capForceUefiLocalPbaBoot() const { return m_capForceUefiLocalPbaBoot; }
    [[nodiscard]] QVariantMap bootCapabilities() const { return m_bootCapabilities; }

    [[nodiscard]] bool optInRequired() const { return m_optInRequired; }
    [[nodiscard]] int  optInState() const { return m_optInState; }
    [[nodiscard]] bool canModifyOptInPolicy() const { return m_canModifyOptInPolicy; }
    [[nodiscard]] bool kvmOptInPolicy() const { return m_kvmOptInPolicy; }
    [[nodiscard]] int  optInPolicyTimeoutSec() const { return m_optInPolicyTimeoutSec; }
    [[nodiscard]] bool optInSatisfied() const
    {
        return !m_optInRequired || m_optInState == 3 || m_optInState == 4;
    }
    [[nodiscard]] bool optInRoundActive() const { return m_optInRoundActive; }
    [[nodiscard]] bool optInStatusKnown() const { return m_optInStatusKnown; }
    [[nodiscard]] bool kvmIs5900PortEnabled() const { return m_kvmIs5900PortEnabled; }
    [[nodiscard]] int  kvmSessionTimeoutMinutes() const { return m_kvmSessionTimeoutMinutes; }
    [[nodiscard]] bool kvmGreyscaleRequested() const { return m_kvmGreyscaleRequested; }

    [[nodiscard]] QVariantList eventLog() const { return m_eventLog; }
    [[nodiscard]] QVariantList userAccounts() const { return m_userAccounts; }
    [[nodiscard]] QVariantMap  hardwareInventory() const { return m_hardwareInventory; }
    [[nodiscard]] QVariantMap  auditLogState() const     { return m_auditLogState; }
    [[nodiscard]] QVariantList auditLogEntries() const   { return m_auditLogEntries; }
    [[nodiscard]] QVariantMap  activeSessions() const    { return m_activeSessions; }
    [[nodiscard]] QVariantMap  deviceCertStore() const   { return m_deviceCertStore; }
    [[nodiscard]] QVariantMap  remoteAccess() const      { return m_remoteAccess; }
    [[nodiscard]] QVariantMap  wireless() const          { return m_wireless; }
    [[nodiscard]] QVariantMap  agentPresence() const     { return m_agentPresence; }
    [[nodiscard]] QVariantMap  eventSubscriptions() const { return m_eventSubscriptions; }
    [[nodiscard]] QVariantList wakeAlarms() const        { return m_wakeAlarms; }
    [[nodiscard]] QVariantMap  wsmanBrowseResult() const { return m_wsmanBrowseResult; }
    [[nodiscard]] QVariantMap  systemDefense() const     { return m_systemDefense; }

    /// Fetch the overview bundle (identify + general settings + system +
    /// power state). Each completes independently; the QML side just
    /// reacts to whichever property changes.
    Q_INVOKABLE void refreshOverview();

    /// Refresh individual categories.
    Q_INVOKABLE void refreshNetwork();
    Q_INVOKABLE void refreshTime();
    /// Push the host's current time at the AMT clock via the 3-point
    /// SetHighAccuracyTimeSynch handshake. Fires `lastError` / emits
    /// `timeChanged` after the post-sync re-read completes. See #173.
    Q_INVOKABLE void syncDeviceTime();
    Q_INVOKABLE void refreshPower();
    Q_INVOKABLE void refreshEventLog();
    Q_INVOKABLE void refreshUserAccounts();

    /// Invoke `AMT_AuthorizationService.AddUserAclEntryEx`. `fields`
    /// keys: `digestUsername` (string), `password` (cleartext string —
    /// hashed against the device's digest realm before transmission),
    /// `accessPermission` (int, 0/1/2), `realms` (QVariantList of int
    /// bit-indices). Errors land on `lastError`; on success the user
    /// list re-fetches. See #156.
    Q_INVOKABLE void addUserAccount(const QVariantMap &fields);

    /// Partial update for an existing user. `patch` keys are any of
    /// `digestUsername`, `password`, `accessPermission`, `realms`.
    /// Only present fields are sent. See #156.
    Q_INVOKABLE void updateUserAccount(int handle, const QVariantMap &patch);

    /// Invoke `RemoveUserAclEntry`. The QML side guards against
    /// deleting the operator's own row before calling. See #156.
    Q_INVOKABLE void removeUserAccount(int handle);

    /// Invoke `SetAclEnabledState`. The QML side guards against
    /// disabling the operator's own row before calling. See #156.
    Q_INVOKABLE void setAccountEnabled(int handle, bool enabled);

    /// Invoke `SetAdminAclEntryEx` — rotates the AMT admin entry's
    /// username and/or password. AMT preserves the admin's realm
    /// allocation across the rotation. See #156.
    Q_INVOKABLE void setAdminPassword(const QString &username,
                                      const QString &newPassword);

    Q_INVOKABLE void refreshHardware();
    Q_INVOKABLE void refreshAuditLog();

    /// Enumerate IPS_SolSessionUsingPort + IPS_KvmSessionUsingPort +
    /// IPS_IderSessionUsingPort. Useful for "who's currently holding
    /// SOL / KVM / IDE-R?" diagnostics — AMT only allows one session
    /// per channel. See #160.
    Q_INVOKABLE void refreshActiveSessions();
    Q_INVOKABLE void refreshDeviceCerts();

    /// Install a certificate parsed from PEM-encoded `pem` into the
    /// AMT device cert store. When `asTrustedRoot` is true the cert
    /// is registered via `AddTrustedRootCertificate` (trust anchor);
    /// otherwise via `AddCertificate` (intermediate / chain). Errors
    /// land on `lastError`. See #157.
    Q_INVOKABLE void addCertificateFromPem(const QString &pem,
                                            bool asTrustedRoot);

    /// Read a UTF-8 text file (typically a PEM-encoded certificate)
    /// off disk and return its contents as a QString. Accepts either
    /// a local path or a `file://` URL — the QML side often has the
    /// latter from a `FileDialog`. Empty on read failure (the QML
    /// caller treats empty as "leave the existing PEM alone").
    ///
    /// Replaces the synchronous `XMLHttpRequest("GET", url, false)`
    /// pattern in `AddCertificateDialog.qml` — that one hitched the
    /// UI on multi-MB PKCS#7 chains. See #298.
    Q_INVOKABLE QString readTextFromPath(const QString &pathOrUrl) const;
    /// Counterpart for the CSR save flow: write `text` to a local
    /// path or `file://` URL. Returns true on success. Replaces the
    /// synchronous `XMLHttpRequest("PUT", file://…)` IssueCertificate-
    /// Dialog used to spool the CSR. See #298.
    Q_INVOKABLE bool writeTextToPath(const QString &pathOrUrl,
                                      const QString &text) const;

    /// WS-Transfer Delete on `AMT_PublicKeyCertificate` with the given
    /// `instanceId`. The QML guards against deleting an ACTIVE cert.
    /// See #157.
    Q_INVOKABLE void deleteDeviceCertificate(const QString &instanceId);

    /// WS-Transfer Delete on `AMT_PublicPrivateKeyPair`. Used to clean
    /// up orphaned key pairs left when their matching cert was
    /// imported elsewhere or rotated. See #157.
    Q_INVOKABLE void deleteDeviceKeyPair(const QString &instanceId);

    /// Put a new TLS mode + trusted-CN set on the
    /// `AMT_TLSSettingData` row identified by `instanceId`. `trustedCn`
    /// is only meaningful when `mutualAuth` is true. See #157.
    Q_INVOKABLE void setTlsSettingsForInstance(const QString &instanceId,
                                                bool enabled,
                                                bool mutualAuth,
                                                bool acceptNonSecureConnections,
                                                const QVariantList &trustedCn);

    /// Phase C of the device-cert work (#222): issue a fresh
    /// certificate from scratch. Kicks off the multi-step flow —
    /// GenerateKeyPair → Get on the returned EPR for DERKey → build
    /// null-signed PKCS#10 template → GeneratePKCS10RequestEx. Emits
    /// `csrReady(pem)` on success or `csrFailed(err)` on any step's
    /// failure. `keyAlgorithm` 0 = RSA (only value AMT accepts);
    /// `signingAlgorithm` 0 = SHA1-RSA (removed from CSME 18.0+),
    /// 1 = SHA256-RSA.
    Q_INVOKABLE void generateKeyPairAndCsr(int keyLength,
                                            int keyAlgorithm,
                                            const QString &subjectDn,
                                            int signingAlgorithm);

    /// Phase C step 2 (#222): install the signed cert into the device
    /// store and bind it to the chosen TLS endpoint collection.
    /// Internally: AddCertificate → re-enumerate (to find the new
    /// InstanceID by fingerprint) → bindCertToTlsEndpoint → refresh.
    /// Emits `certInstalled(newInstanceId)` or `certInstallFailed(err)`.
    Q_INVOKABLE void installSignedCertAndBindTls(
        const QString &signedCertPem,
        const QString &tlsEndpointCollectionId);

    Q_INVOKABLE void refreshRemoteAccess();

    /// Invoke `IPS_HTTPProxyService.AddProxyAccessPoint` and re-read
    /// the CIRA pane on success. `accessInfo` must be non-empty and
    /// `port` 1–65535; the in-memory list must hold fewer than 15
    /// entries (AMT firmware cap). Failures land in `lastError`.
    /// See #177.
    Q_INVOKABLE void addHttpProxy(const QString &accessInfo, int port,
                                  const QString &networkDnsSuffix);

    /// Delete the `IPS_HTTPProxyAccessPoint` with the given `Name`
    /// and re-read the CIRA pane on success. See #177.
    Q_INVOKABLE void deleteHttpProxy(const QString &name);

    /// Put `AMT_EnvironmentDetectionSettingData` with a new domain
    /// list. The list controls AMT's "am I on the corporate network"
    /// heuristic; empty means "always treat as off-network". See #158.
    Q_INVOKABLE void setEnvironmentDetection(const QStringList &domains);

    /// Invoke `AMT_UserInitiatedConnectionService.RequestStateChange`.
    /// `enabledState` follows the same codes the read side exposes:
    /// 32768 Disabled / 32769 BIOS / 32770 OS / 32771 BIOS+OS.
    /// See #158.
    Q_INVOKABLE void setUserInitiatedConnectionState(int enabledState);

    /// Invoke `AMT_RemoteAccessService.AddMpServer`. `fields` keys:
    ///   accessInfo (string), port (int), commonName (string),
    ///   mpsType (int, 0=CIRA / 1=CILA),
    ///   authMethod (int, 1=none / 2=digest),
    ///   username (string, when authMethod != 1),
    ///   password (string, when authMethod != 1).
    /// `infoFormat` is derived from `accessInfo` automatically. See #158.
    Q_INVOKABLE void addMpServer(const QVariantMap &fields);

    /// Put on `AMT_ManagementPresenceRemoteSAP` to edit an existing
    /// server's accessInfo / port / CN. Auth credentials are
    /// untouched by this call. `fields` keys: accessInfo (string),
    /// port (int), commonName (string). See #158.
    Q_INVOKABLE void updateMpServer(const QString &name,
                                     const QVariantMap &fields);

    /// WS-Transfer Delete on `AMT_ManagementPresenceRemoteSAP`.
    /// AMT cascades the linked MPSUsernamePassword row. See #158.
    Q_INVOKABLE void removeMpServer(const QString &name);

    /// Invoke `AMT_RemoteAccessService.AddRemoteAccessPolicyRule`.
    /// The firmware is idempotent on `trigger`, so this is also the
    /// edit path. `fields` keys:
    ///   trigger (int, 0=User Initiated / 1=Alert / 2=Periodic),
    ///   tunnelLifeTime (int, seconds),
    ///   periodicMode (string, "interval" or "timeOfDay") — only
    ///                meaningful when trigger == 2,
    ///   periodicSeconds (int) — required when mode == "interval",
    ///   periodicHour (int) / periodicMinute (int) — required when
    ///                 mode == "timeOfDay",
    ///   ciraMpsNames (QStringList) — `MpsServer.name` for mpsType=0,
    ///   cilaMpsNames (QStringList) — `MpsServer.name` for mpsType=1.
    /// See #224.
    Q_INVOKABLE void addCiraPolicyRule(const QVariantMap &fields);

    /// WS-Transfer Delete on `AMT_RemoteAccessPolicyRule` keyed by
    /// `PolicyRuleName`. AMT cascades the linked AppliesToMPS rows.
    /// See #224.
    Q_INVOKABLE void removeCiraPolicyRule(const QString &policyName);

    Q_INVOKABLE void refreshWireless();

    /// Add a PSK WiFi profile (WPA2-PSK or WPA3-PSK). `fields` keys:
    ///   elementName (string), ssid (string),
    ///   authenticationMethod (int — 6 WPA2-PSK, 7 WPA3-PSK),
    ///   encryptionMethod (int — 3 TKIP, 4 CCMP),
    ///   priority (int), psk (cleartext passphrase).
    /// EAP-TLS / PEAP profiles need cert binding and ship in a later
    /// Phase C. See #159.
    Q_INVOKABLE void addWiFiPskProfile(const QVariantMap &fields);

    /// Update an existing PSK profile, keyed by `elementName`. Same
    /// patch shape as `addWiFiPskProfile`. See #159.
    Q_INVOKABLE void updateWiFiPskProfile(const QVariantMap &fields);

    /// Delete a single WiFi profile by `elementName`. See #159.
    Q_INVOKABLE void deleteWiFiProfile(const QString &elementName);

    /// Bulk-delete all IT-channel WiFi profiles. Heavy hammer.
    Q_INVOKABLE void deleteAllITWiFiProfiles();

    /// Bulk-delete all OS-side (user) WiFi profiles.
    Q_INVOKABLE void deleteAllUserWiFiProfiles();

    /// Toggle the WiFi port at the AMT firmware level.
    Q_INVOKABLE void setWifiPortEnabled(bool enabled);

    /// Update both sync toggles in one call. -1 leaves a field
    /// untouched (the controller re-reads the current value).
    Q_INVOKABLE void setWifiSyncSettings(int localProfileSynchronization,
                                          int uefiWiFiProfileShare);

    /// Wired enterprise (`AMT_8021XProfile`) edit. `authenticationProtocol`
    /// follows the CIM enum used elsewhere.
    Q_INVOKABLE void setWiredEnterpriseProfile(bool enabled,
                                                int authenticationProtocol);
    /// Enumerate AMT_AgentPresenceWatchdog + read
    /// AMT_AgentPresenceCapabilities for the Watchdogs pane. See #164.
    Q_INVOKABLE void refreshAgentPresence();
    /// Invoke `AMT_AgentPresenceService.RegisterAgent` with an
    /// embedded `AMT_AgentPresenceWatchdog`. `fields` carries
    /// `deviceIdGuid` (string), `description` (string),
    /// `monitoredEntityCode` (int), `startupIntervalSec` (int),
    /// `timeoutIntervalSec` (int). The controller blocks the call
    /// if adding would exceed `AMT_AgentPresenceCapabilities.MaxTotalAgents`.
    /// On success refreshes the section. See #348.
    Q_INVOKABLE void addAgentPresenceWatchdog(const QVariantMap &fields);
    /// WS-Transfer Delete on `AMT_AgentPresenceWatchdog` keyed by
    /// `deviceIdGuid`. The firmware cascades the watchdog's
    /// `AMT_AgentPresenceWatchdogAction` rows. On success refreshes
    /// the section. See #348.
    Q_INVOKABLE void deleteAgentPresenceWatchdog(const QString &deviceIdGuid);
    /// Edit-as-replace: delete the watchdog keyed by `oldDeviceIdGuid`,
    /// and on success fire RegisterAgent with `fields`. AMT has no
    /// in-place modify for the watchdog class. See #348.
    Q_INVOKABLE void replaceAgentPresenceWatchdog(const QString &oldDeviceIdGuid,
                                                    const QVariantMap &fields);
    /// Invoke `AMT_AgentPresenceService.AddAction` to attach a new
    /// per-watchdog action. `fields`: `watchdogDeviceIdGuid` (string),
    /// `oldState` / `newState` (int — watchdog state codes 1/2/4/8/16),
    /// `eventOnTransition` (bool), `actionSac` (int — 1/2/16/17/18 per
    /// Intel SDC) and an optional `actionEac` (int — pass -1 to omit).
    /// Blocks at `AMT_AgentPresenceCapabilities.MaxTotalActions`. On
    /// success refreshes the section. See #350.
    Q_INVOKABLE void addWatchdogAction(const QVariantMap &fields);
    /// WS-Transfer Delete on `AMT_AgentPresenceWatchdogAction` keyed
    /// by `(Watchdog, OldState, NewState)`. On success refreshes the
    /// section. See #350.
    Q_INVOKABLE void deleteWatchdogAction(const QString &watchdogDeviceIdGuid,
                                           int oldState, int newState);
    /// Enumerate CIM_FilterCollection + CIM_ListenerDestination +
    /// CIM_FilterCollectionSubscription. See #163.
    Q_INVOKABLE void refreshEventSubscriptions();
    /// Invoke WS-Eventing Subscribe against the AMT firmware to
    /// route notifications from `filterInstanceId` to `notifyUrl`.
    /// `deliveryMode` is the dialog's enum string — `"Push"` or
    /// `"PushWithAck"`. `user` / `pass` are optional HTTP basic
    /// auth credentials forwarded to the listener. On success
    /// refreshes the section. See #345.
    Q_INVOKABLE void subscribeToEventFilter(const QString &filterInstanceId,
                                             const QString &deliveryMode,
                                             const QString &notifyUrl,
                                             const QString &user,
                                             const QString &pass);
    /// Invoke WS-Eventing Unsubscribe. `filterInstanceId` +
    /// `listenerName` together identify the
    /// `CIM_FilterCollectionSubscription` row to drop. AMT cleans
    /// up the auto-created listener if no other subscription
    /// references it. On success refreshes the section. See #345.
    Q_INVOKABLE void unsubscribeFromEventFilter(const QString &filterInstanceId,
                                                  const QString &listenerName);
    /// Enumerate IPS_AlarmClockOccurrence for the Wake alarms pane.
    /// See #161 phase A.
    Q_INVOKABLE void refreshWakeAlarms();
    /// Invoke `AMT_AlarmClockService.AddAlarm` with an embedded
    /// `IPS_AlarmClockOccurrence`. `fields` carries `elementName`
    /// (string), `startTimeIso` (ISO-8601 datetime), `intervalIso`
    /// (ISO-8601 duration or empty), and `deleteOnCompletion` (bool).
    /// On success refreshes the section. See #347.
    Q_INVOKABLE void addWakeAlarm(const QVariantMap &fields);
    /// WS-Transfer Delete on `IPS_AlarmClockOccurrence` keyed by
    /// `instanceId`. On success refreshes the section. See #347.
    Q_INVOKABLE void deleteWakeAlarm(const QString &instanceId);
    /// Edit-as-replace: delete the row keyed by `oldInstanceId`, and
    /// on success fire `AddAlarm` with `fields`. AMT has no in-place
    /// modify for `IPS_AlarmClockOccurrence`, so the controller chains
    /// the two operations and surfaces only one error banner if either
    /// step fails. See #347.
    Q_INVOKABLE void replaceWakeAlarm(const QString &oldInstanceId,
                                       const QVariantMap &fields);
    /// Fire one WSMAN Get or Enumerate against `classOrUri`. `kind` is
    /// the string `"get"` or `"enumerate"`. `selectors` is a key→value
    /// map applied to Get only. Result lands in `wsmanBrowseResult`.
    Q_INVOKABLE void wsmanBrowse(const QString &classOrUri,
                                 const QString &kind,
                                 const QVariantMap &selectors);
    /// Enumerate the System Defense classes for the ACM-only pane.
    /// See #165 phase A.
    Q_INVOKABLE void refreshSystemDefense();
    /// Repoll `AMT_ActiveFilterStatistics` only — used when the
    /// operator clicks "Refresh stats" so per-filter counters update
    /// without bouncing the whole policy/filter tree. See #346.
    Q_INVOKABLE void refreshSystemDefenseStats();
    /// WS-Transfer Delete on `AMT_SystemDefensePolicy`. AMT cascades
    /// the policy's port bindings. On success refreshes the section.
    /// See #346.
    Q_INVOKABLE void deleteSystemDefensePolicy(const QString &instanceId);
    /// WS-Transfer Delete on `AMT_Hdr8021Filter`. See #346.
    Q_INVOKABLE void deleteSystemDefenseHdrFilter(const QString &instanceId);
    /// WS-Transfer Create of a new `AMT_Hdr8021Filter`. `fields`
    /// carries `name` (string), `etherType` (int — `HdrProtocolID8021`
    /// on the wire), `filterProfile` (int, 0..4), `filterProfileData`
    /// (int, only used at `filterProfile == 2` rate-limit),
    /// `filterDirection` (int, 0=Tx / 1=Rx), `actionEventOnMatch`
    /// (bool). On success refreshes the section. See #353.
    Q_INVOKABLE void addSystemDefenseHdrFilter(const QVariantMap &fields);
    /// WS-Transfer Create of a new `AMT_IPHeadersFilter`. `fields`
    /// carries `name`, `ipVersion` (4|6), `filterProfile` (0..4),
    /// `filterProfileData`, `filterDirection` (0|1),
    /// `actionEventOnMatch`, and the optional matchers `protocol`,
    /// `srcAddress` / `dstAddress` (dotted-quad for v4, colon-hex
    /// for v6), `srcPort` / `srcPortEnd`, `dstPort` / `dstPortEnd`.
    /// Each optional matcher is omitted from the wire when unset.
    /// On success refreshes the section. See #358.
    Q_INVOKABLE void addSystemDefenseIpFilter(const QVariantMap &fields);
    /// WS-Transfer Create of a new `AMT_SystemDefensePolicy`. `fields`
    /// carries `policyName` (string), `priority` (int, default 0),
    /// the six default-action booleans
    /// `txDefaultCount` / `txDefaultDrop` / `txDefaultMatchEvent` /
    /// `rxDefaultCount` / `rxDefaultDrop` / `rxDefaultMatchEvent`,
    /// and `filterInstanceIds` — a QStringList of L2/L3 filter
    /// InstanceIDs (the controller extracts the trailing handle).
    /// On success refreshes the section. See #357.
    Q_INVOKABLE void addSystemDefensePolicyAction(const QVariantMap &fields);
    /// WS-Transfer Create of an `AMT_NetworkPortSystemDefensePolicy`
    /// row binding `policyInstanceId` to the Ethernet port indexed
    /// by `portIndex`. AMT supports at most one policy per port; the
    /// caller is expected to unbind any prior policy first. On
    /// success refreshes the section. See #359.
    Q_INVOKABLE void bindSystemDefensePolicy(int portIndex,
                                                const QString &policyInstanceId);
    /// WS-Transfer Delete on the join row identified by
    /// (portIndex, policyInstanceId). On success refreshes the
    /// section. See #359.
    Q_INVOKABLE void unbindSystemDefensePolicy(int portIndex,
                                                  const QString &policyInstanceId);
    /// WS-Transfer Delete on `AMT_IPHeadersFilter`. See #346.
    Q_INVOKABLE void deleteSystemDefenseIpFilter(const QString &instanceId);
    /// Enumerate `AMT_SystemPowerScheme` and resolve the active one.
    /// Auto-called as part of `refreshPower` so the dialog is ready
    /// when the operator clicks the Power Policy button. See #162.
    Q_INVOKABLE void refreshPowerSchemes();
    /// Push `instanceId` as the active power scheme via
    /// `AMT_SystemPowerScheme.SetPowerScheme`, then re-read so the
    /// currentPowerSchemeId binding follows.
    Q_INVOKABLE void setPowerScheme(const QString &instanceId);
    /// Read `IPS_OptInService` + `IPS_KVMRedirectionSettingData` and
    /// update the four exposed properties. Also called by
    /// `refreshOverview`.
    Q_INVOKABLE void refreshOptInStatus();
    /// Flip the persisted KVM consent policy. Fires
    /// `optInPolicyChangeFailed` if AMT rejects the Put (most often
    /// because the current login lacks the realm).
    Q_INVOKABLE void setKvmOptInPolicyEnabled(bool enabled);
    /// Apply a partial update to IPS_KVMRedirectionSettingData. `fields`
    /// is a key→value map; recognised keys: `is5900PortEnabled` (bool),
    /// `optInPolicy` (bool), `sessionTimeoutMinutes` (int), `rfbPassword`
    /// (string; empty clears it), `greyscaleRequested` (bool). Any key
    /// not present in the map is left untouched on the firmware side.
    /// See #175.
    Q_INVOKABLE void setKvmSettings(const QVariantMap &fields);
    /// Enable / disable KVM at the device level via
    /// `CIM_KVMRedirectionSAP.RequestStateChange`. Disabling stops new
    /// sessions until re-enabled. See #175.
    Q_INVOKABLE void setKvmServiceEnabled(bool enabled);
    /// Start the AMT-side consent prompt — the firmware shows a
    /// 6-digit code on the target's local screen.
    Q_INVOKABLE void startOptIn();
    /// Submit the operator-entered consent code.
    Q_INVOKABLE void sendOptInCode(int code);
    /// Abort a pending opt-in.
    Q_INVOKABLE void cancelOptIn();
    /// Clear the consecutive-failure counter so a fresh user-initiated
    /// attempt is allowed after `optInGaveUp`.
    Q_INVOKABLE void resetOptInAttempts();
    /// Does `protocol` need user consent on this machine?
    ///
    /// AMT's `OptInRequired` is a tri-state, not a bool: `1` gates KVM
    /// alone, `0xFFFFFFFF` gates everything. Asking the coarse
    /// `optInRequired` instead puts a consent PIN on the target's
    /// screen for Serial Console sessions that don't need one (#437).
    /// The reference applies the same asymmetry — any non-zero for the
    /// desktop path (Commander.htm:48442), only `0xFFFFFFFF` elsewhere
    /// (Commander.htm:50760).
    Q_INVOKABLE bool consentRequiredFor(int protocol) const;
    /// True when `protocol` may proceed: either it needs no consent, or
    /// the firmware has already accepted a code. See `optInSatisfied`
    /// for why states 3 and 4 both count.
    Q_INVOKABLE bool consentSatisfiedFor(int protocol) const;
    /// Stop the consent poll timer. Called when the session window
    /// closes so an abandoned round doesn't keep polling the ME.
    Q_INVOKABLE void stopOptInPollingNow() { stopOptInPolling(); }

    /// CIM power-state codes:
    ///   2  = Power On
    ///   5  = Master Bus Reset
    ///   8  = Power Off (Hard)
    ///   10 = Master Bus Reset Graceful
    ///   12 = Power Off (Soft Graceful)
    Q_INVOKABLE void powerOn()           { changePowerState(2); }
    Q_INVOKABLE void powerOffHard()      { changePowerState(8); }
    Q_INVOKABLE void powerReset()        { changePowerState(5); }
    Q_INVOKABLE void powerResetGraceful(){ changePowerState(10); }
    Q_INVOKABLE void powerOffSoft()      { changePowerState(12); }

    /// Boot-source-override actions. Each chains
    /// ChangeBootOrder(clear) → Put AMT_BootSettingData →
    /// SetBootConfigRole(1) → (optionally) ChangeBootOrder(source) →
    /// RequestPowerStateChange. `reset` selects between power-on
    /// (false → CIM state 2) and graceful-reset (true → CIM state 10).
    Q_INVOKABLE void bootToBios(bool reset);
    Q_INVOKABLE void bootToPxe(bool reset);
    Q_INVOKABLE void bootToIderCdrom(bool reset);
    Q_INVOKABLE void bootToIderFloppy(bool reset);

    /// `IPS_PowerManagementService.RequestOSPowerSavingStateChange`
    /// — wake the running OS from sleep / put it back to sleep. AMT
    /// 10+ only; the QML side hides the menu entries below that.
    Q_INVOKABLE void osWakeFromSleep();
    Q_INVOKABLE void osPutToSleep();

    /// Boot to Secure Erase. `password` is the AMT RSE (Remote Secure
    /// Erase) password — required by firmware versions that enforce
    /// it. Pass empty when not configured. Gated in the UI on
    /// `capSecureErase`.
    Q_INVOKABLE void bootToSecureErase(bool reset, const QString &password);

    /// Boot to Platform Erase. `flags` is a subset of
    /// `capPlatformEraseMask` — the bits the user ticked in the
    /// modal. `psid` only applies when bit 1 (Pyrite Revert) is set;
    /// `ssdPassword` only when bit 2 (Secure Erase All SSDs) is set.
    Q_INVOKABLE void bootToPlatformErase(bool reset, int flags,
                                          const QString &psid,
                                          const QString &ssdPassword);

    /// Boot to an arbitrary HTTPS-hosted ISO. AMT does the download
    /// itself, so `url` must be a reachable HTTPS endpoint. Gated in
    /// the UI on `capForceUefiHttpsBoot` + the connection being TLS
    /// (otherwise the firmware refuses).
    Q_INVOKABLE void bootToHttpsBootUrl(bool reset, const QString &url);

    /// One-Click Recovery (#170). Boot the device into the BIOS-
    /// registered Windows Recovery Environment. Enumerates
    /// `CIM_BootSourceSetting`, picks the row whose `BIOSBootString`
    /// contains "WinRe", and triggers the OCR boot via the standard
    /// chain. Surfaces a `lastError` when BIOS hasn't registered a
    /// WinRE row.
    Q_INVOKABLE void bootToWinRE(bool reset);

    /// One-Click Recovery (#170). Boot to the `pbaIndex`-th BIOS-
    /// registered Pre-Boot Authentication image (1..10). The boot
    /// options are enumerated in InstanceID order, so #1 is the
    /// first row AMT exposes.
    Q_INVOKABLE void bootToLocalPBA(bool reset, int pbaIndex);

    /// One-Click Recovery (#170). Fetch a signed PBA image over
    /// HTTPS at `url`. `hashAlg` ∈ {"sha256","sha384","sha512"} and
    /// `hashHex` pin the boot image; pass empty values to skip. The
    /// optional `pinnedServerCertHash*` pair (same alg names, hex
    /// digest) pins the recovery server's cert. `username` /
    /// `password` carry HTTPS basic auth. Hex strings are decoded
    /// by the controller; we take strings rather than `QByteArray`
    /// because QML can't easily produce raw byte buffers.
    Q_INVOKABLE void bootToOcrHttpsUrl(bool reset,
                                        const QString &url,
                                        const QString &hashAlg,
                                        const QString &hashHex,
                                        const QString &pinnedServerCertHashAlg,
                                        const QString &pinnedServerCertHashHex,
                                        const QString &username,
                                        const QString &password);

    /// Called by the QML trust prompt. On accept, the pending cert's
    /// fingerprint is promoted into the trusted list, the trust state
    /// clears, and the operation that triggered the prompt is retried.
    /// When `persist` is true we also emit `trustedFingerprintAdded`
    /// so the QML layer can write the fingerprint back to ComputerModel.
    Q_INVOKABLE void trustPendingCert(bool persist);

    /// Called by the SSH host-key trust prompt. On accept, the
    /// pending SSH key fingerprint is promoted into the trusted list
    /// and the in-flight SSH session resumes its auth step.
    Q_INVOKABLE void trustPendingSshHostKey(bool persist);

    /// Called by CertTrustDialog when the user declines the prompt.
    /// Clears pending trust state and asks the QML window to close.
    Q_INVOKABLE void close();

    /// Clear the `lastError` property — wired to the ResultBanner's
    /// Dismiss button (#283) so the operator can clear stale errors
    /// without switching sections.
    Q_INVOKABLE void clearLastError() { setLastError({}); }

signals:
    void hostChanged();
    void userChanged();
    void passwordChanged();
    void tlsChanged();
    void trustedFingerprintsChanged();
    void busyChanged();
    void lastErrorChanged();
    void powerStateChanged();
    void identifyChanged();
    void generalSettingsChanged();
    void computerSystemChanged();
    void ethernetChanged();
    void timeChanged();
    void powerSchemesChanged();
    void meVersionChanged();
    void setupConfigChanged();
    void redirectionStatusChanged();
    void awaitingTrustChanged();
    void pendingCertChanged();
    void bootCapabilitiesChanged();
    void eventLogChanged();
    void userAccountsChanged();
    void hardwareChanged();
    void auditLogChanged();
    void activeSessionsChanged();
    void deviceCertStoreChanged();
    /// Phase C (#222) — `generateKeyPairAndCsr` reached the firmware-
    /// signed CSR. `pemCsr` is a PEM-wrapped CertificationRequest the
    /// operator can hand off to a CA.
    void csrReady(const QString &pemCsr);
    /// Phase C (#222) — any step of `generateKeyPairAndCsr` failed.
    void csrFailed(const QString &error);
    /// Phase C (#222) — `installSignedCertAndBindTls` finished: the
    /// signed cert is in the device store and bound to the chosen
    /// TLS endpoint collection.
    void certInstalled(const QString &newCertInstanceId);
    void certInstallFailed(const QString &error);
    void remoteAccessChanged();
    void wirelessChanged();
    void agentPresenceChanged();
    void eventSubscriptionsChanged();
    void wakeAlarmsChanged();
    void wsmanBrowseResultChanged();
    void systemDefenseChanged();
    void optInStatusChanged();
    void optInRoundActiveChanged();
    /// The very first `IPS_OptInService` read failed, so the consent
    /// policy is unknowable — most often AMT <= 5, which has no such
    /// class. Consent is treated as not required and redirection is
    /// allowed to proceed; the UI may note it.
    void optInStatusUnavailable(const QString &error);
    /// Result of a `setKvmOptInPolicyEnabled` Put. `ok=false` carries
    /// the firmware-reported reason (most commonly the AMT login lacks
    /// the realm to modify the policy).
    void optInPolicyChangeFailed(const QString &error);
    /// Result of `startOptIn` — when ok, AMT is now showing a code on
    /// the target's local screen and the operator should be prompted
    /// for it.
    void optInStarted(bool ok, const QString &error);
    /// Result of `sendOptInCode` — when ok, the redir framebuffer /
    /// serial / IDE-R should unblock on the active session.
    void optInCodeResult(bool ok, const QString &error);
    /// Polling saw `OptInState` transition to `InSession` (4) —
    /// consent has been granted (either by entering the code, or by
    /// the operator at the target hitting "Allow" on the local
    /// screen for firmwares that support that). The PIN-entry modal
    /// should close and the redirection session can proceed.
    void optInGranted();
    /// A wrong code was rejected but the round is still live — the
    /// modal should stay open, show `error`, and keep its countdown
    /// running rather than restarting it.
    void optInCodeRejected(const QString &error);
    /// `StartOptIn` failed `kMaxOptInFailures` times in a row. The
    /// consent dance is abandoned; the caller should surface `error`
    /// and stop expecting a prompt.
    void optInGaveUp(const QString &error);
    /// Polling saw `OptInState` drop back to NotStarted/Requested
    /// after we'd seen it Displayed — the target-side operator
    /// either cancelled or the firmware timed the request out. The
    /// modal should close with an "expired or denied" message. See #171.
    void optInExpiredOrDenied();
    void powerChangeRequested(int state);
    void powerChangeCompleted(int state, bool ok, const QString &error);
    /// Emitted after `trustPendingCert(true)` — the QML layer persists
    /// the fingerprint into ComputerModel.
    void trustedFingerprintAdded(const QString &fingerprint);
    /// Forwarded from the underlying client whenever a TLS
    /// reconnect quietly matched a pinned fingerprint. The QML side
    /// uses it to flash a small "verified" badge.
    void peerCertVerifiedByPin(const QString &fingerprint);
    /// Emitted from `close()`; the QML window listens and dismisses
    /// itself.
    void closeRequested();
    /// SSH-tunnel state change. The QML title bar listens and lights
    /// the "via SSH" badge / error state.
    void sshTunnelStateChanged();
    /// Emitted when the operator must confirm an SSH host key on first
    /// connect (or after a key rotation). The QML side surfaces a
    /// confirm-and-pin dialog and either calls `trustPendingSshHostKey`
    /// or `close()`.
    void sshHostKeyPromptRequired(const QString &fingerprint,
                                   const QString &keyType);
    /// NOTIFY for the SSH `awaitingSshHostKeyTrust` / pending fields.
    /// Fires whenever the prompt opens or closes.
    void sshHostKeyPromptChanged();
    /// Emitted after `trustPendingSshHostKey()` — the QML layer
    /// persists the fingerprint into ComputerModel.
    void trustedSshHostKeyAdded(const QString &fingerprint);

private:
    void rebuildEndpoint();
    /// Point the WSMAN socket factory at the current host and port
    /// through the SSH session. Re-run whenever either changes, so the
    /// tunnel target doesn't depend on the order a window sets them.
    void applySshSocketFactory();
    void changePowerState(int code);
    void incInflight();
    void decInflight();
    void setLastError(const QString &e);
    void onTrustPromptRequired(const qumesh::wsman::PeerCertSummary &s);

    /// Refresh methods that get called while the SSH tunnel is still
    /// negotiating are buffered here as bits and replayed once the
    /// `SshSession` reaches `Connected`. Without this the first wave
    /// of refresh calls (overview, power, etc.) hits the WSMAN socket
    /// factory before the session is up and every one fails with
    /// "SSH tunnel socket could not be opened".
    enum PendingRefresh : int {
        PendingOverview     = 1 << 0,
        PendingNetwork      = 1 << 1,
        PendingTime         = 1 << 2,
        PendingPower        = 1 << 3,
        PendingEventLog     = 1 << 4,
        PendingUserAccounts = 1 << 5,
        PendingHardware     = 1 << 6,
        PendingAuditLog     = 1 << 7,
        PendingDeviceCerts  = 1 << 8,
        PendingRemoteAccess = 1 << 9,
        PendingWireless       = 1 << 10,
        PendingAgentPresence       = 1 << 11,
        PendingEventSubscriptions  = 1 << 12,
        PendingWakeAlarms          = 1 << 13,
        PendingSystemDefense       = 1 << 14,
        PendingActiveSessions      = 1 << 15,
        PendingOptInStatus         = 1 << 16,
    };
    int m_pendingRefreshes = 0;
    /// `true` between `setSshConfig(enabled=true)` and the session
    /// reaching `Connected` (or `Failed`). While true, refreshes are
    /// buffered into `m_pendingRefreshes` instead of being issued.
    bool m_sshConnecting = false;
    [[nodiscard]] bool deferIfSshConnecting(PendingRefresh kind);
    void runPendingRefreshes();
    /// Remember which top-level fetch was in flight when the TLS
    /// trust prompt fired, so we can resume it once the user
    /// accepts. Every refresh* entry point stores a self-referential
    /// lambda here; `trustPendingCert(true)` moves-takes it and
    /// invokes. Pre-#276 this was a 4-value enum that left ~14
    /// refresh methods unwired — accepting Trust on those did
    /// nothing visible. See #276.
    std::function<void()> m_pendingTrustResume;

    qumesh::wsman::WsmanClient *m_client = nullptr;
    QString m_host;
    QString m_user;
    QString m_password;
    bool m_tls = false;
    QStringList m_trustedFingerprints;
    qumesh::wsman::PeerCertSummary m_pendingCert;
    bool m_awaitingTrust = false;

    // SSH tunnel state. The session is lazily created when
    // `setSshConfig(...enabled=true)` is called; per-request
    // SshTunnels are then handed to the WsmanClient via its socket
    // factory. The status string is what the QML title-bar badge
    // displays ("connecting…", "via SSH", error text).
    qumesh::ssh::SshSession *m_sshSession = nullptr;
    bool m_sshEnabled = false;
    QString m_sshTunnelStatus;
    QString m_pendingSshHostKey;
    QString m_pendingSshHostKeyType;
    bool m_awaitingSshHostKeyTrust = false;

    int m_powerState = 0;
    int m_inflight = 0;
    QString m_lastError;

    QString m_amtProtocolVersion;
    QString m_amtVendor;
    QString m_amtVersion;

    QString m_hostName;
    QString m_domainName;
    QString m_digestRealm;
    bool m_networkInterfaceEnabled = false;
    bool m_rmcpPingResponseEnabled = false;
    int m_powerSource = -1;

    QString m_meVersionString;
    QVariantMap m_amtFingerprint;

    int m_provisioningState = -1;
    int m_provisioningMode  = -1;

    bool m_redirectionListenerEnabled = false;
    bool m_solEnabled  = false;
    bool m_iderEnabled = false;
    bool m_kvmEnabled  = false;
    bool m_kvmAvailable = false;

    QString m_systemName;
    QString m_systemElementName;
    QString m_systemUuid;

    QString m_macAddress;
    bool m_dhcpEnabled = false;
    QString m_ipAddress;
    QString m_subnetMask;
    QString m_defaultGateway;
    QString m_primaryDns;
    QString m_secondaryDns;
    QVariantList m_networkInterfaces;

    qint64 m_amtEpoch = 0;

    QVariantList m_powerSchemes;
    QString m_currentPowerSchemeId;

    bool m_capBiosSetup = false;
    bool m_capBiosPause = false;
    bool m_capSecureErase = false;
    bool m_capPlatformErase = false;
    bool m_capForceWinReBoot = false;
    bool m_capForceUefiLocalPbaBoot = false;
    quint32 m_capPlatformEraseMask = 0;
    bool m_capForceUefiHttpsBoot = false;
    QVariantMap m_bootCapabilities;

    QVariantList m_eventLog;
    QVariantList m_userAccounts;
    QVariantMap  m_hardwareInventory;
    QVariantMap  m_auditLogState;
    QVariantList m_auditLogEntries;
    QVariantMap  m_activeSessions;
    QVariantMap  m_deviceCertStore;
    QVariantMap  m_remoteAccess;
    QVariantMap  m_wireless;
    QVariantMap  m_agentPresence;
    QVariantMap  m_eventSubscriptions;
    QVariantList m_wakeAlarms;
    QVariantMap  m_wsmanBrowseResult;
    QVariantMap  m_systemDefense;

    bool m_optInRequired = false;
    quint32 m_optInRequiredRaw = 0;   ///< See `consentRequiredFor`.
    int m_optInState = 0;
    bool m_canModifyOptInPolicy = false;
    bool m_kvmOptInPolicy = false;
    int  m_optInPolicyTimeoutSec = 0;
    bool m_kvmIs5900PortEnabled = false;
    int  m_kvmSessionTimeoutMinutes = 0;
    bool m_kvmGreyscaleRequested = false;
    bool m_optInPolling = false;       ///< See `startOptInPolling`.
    QTimer *m_optInPollTimer = nullptr;
    /// Set while a consent round is outstanding. `startOptIn()` is a
    /// no-op while true, which breaks the
    /// startOptIn → refreshOptInStatus → optInStatusChanged → startOptIn
    /// feedback loop that could otherwise run unbounded against the ME.
    bool m_optInRoundActive = false;
    /// Consecutive `StartOptIn` failures. At `kMaxOptInFailures` we stop
    /// retrying and surface the error instead of hammering the firmware.
    int m_optInFailures = 0;
    static constexpr int kMaxOptInFailures = 3;
    /// Guards `refreshOptInStatus()` against overlapping polls — each
    /// tick is two chained WSMAN GETs and AMT accepts very few
    /// concurrent sessions.
    quint16 m_portOverride = 0;   ///< Tests only; 0 = derive from `tls`.
    bool m_optInStatusInFlight = false;
    /// Bumped when a consent operation is answered. A status read that
    /// spans the reply must not write its OptInState back or drive
    /// polling, since it may predate the operation.
    quint64 m_optInStateGeneration = 0;
    /// StartOptIn and CancelOptIn calls awaiting a reply.
    int m_optInRoundOpsInFlight = 0;
    /// Bumped when a round starts or ends. A reply from an older round
    /// must not write OptInState or signal the UI.
    quint64 m_optInRoundSerial = 0;
    /// A read sent while polling this round has reported Displayed.
    bool m_optInRoundSawDisplayed = false;
    /// An older CancelOptIn was answered during this round, so it may
    /// have landed after this round's StartOptIn.
    bool m_optInRoundCancelRaced = false;
    /// An operation's outcome is ambiguous, so re-read the firmware once
    /// nothing else is on the wire.
    bool m_optInRereadPending = false;
    int m_optInRereads = 0;     ///< Since the last `resetOptInAttempts`.
    void endOptInRoundOp();
    void endOptInRound();
    void requestOptInReread();
    void flushOptInReread();
    /// Set once `getOptInStatus` has returned successfully.
    bool m_optInStatusKnown = false;
    void setOptInRoundActive(bool v);

    void startOptInPolling();
    void stopOptInPolling();
};

} // namespace qumesh::app
