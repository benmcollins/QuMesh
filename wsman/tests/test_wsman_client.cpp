// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

#include "wsman/operations.h"
#include "wsman/wsman_client.h"

#include <QHttpServer>
#include <QHttpServerRequest>
#include <QHttpServerResponse>
#include <QObject>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtTest>

using namespace qumesh::wsman;

class TestWsmanClient : public QObject
{
    Q_OBJECT
private slots:
    void initTestCase();
    void synchronousSocketFailureReachesFinished();
    // #435 — digest 401 retry cap + timeout on every path.
    void digestRetryIsCappedOnPersistent401();
    void staleNonceAllowsOneExtraRetry();
    void cachedChallengePathIsStillTimedOut();
    void identifyRoundTripsAgainstMockServer();
    void getPowerStateRoundTripsAgainstMockServer();
    void httpErrorPropagates();
    void transportErrorSkipsBodyParse();
    void getGeneralSettingsExtractsPowerSource();
    void getSetupAndConfigurationDecodesProvisioning();
    void getBootCapabilitiesDecodesAllFlags();
    void getMeVersionPicksAmtInstanceFromEnumeration();
    void getRedirectionStatusSplitsEnabledStateBitmask();
    void getHardwareInventoryStitchesAllSections();
    void getAuditLogStateDecodesBitmask();
    void enumerateAuditLogParsesBinaryRecords();
    void enumerateUserAccountsMergesAdminAndAclEntries();
    void getEthernetSettingsReturnsMultipleInterfacesWithIPv6();
    void getDeviceCertStoreStitchesCertsKeysAndTls();
    void splitDnHelperHandlesEmptyAndMultiple();
    void getRemoteAccessStitchesEnvPoliciesServersAndProxies();
    void getWirelessJoinsProfilesAnd8021xByElementName();
    void setHighAccuracyTimeSyncEncodesParamsAndDecodesReturn();
    void getPowerSchemesEnumeratesAndDetectsCurrentViaElementSettingData();
    void getAgentPresenceDecodesBase64DeviceIdAndStateEnums();
    void getEventSubscriptionsJoinsFiltersListenersAndSubscriptions();
    void getWakeAlarmsExtractsNestedStartTimeAndInterval();
    void executeBrowsePrefixesClassNamesAndCarriesRawXml();
    void getSystemDefenseEnumeratesCoreFilterClasses();
    void setKvmSettingsRoundTripsPartialPatch();
    void setKvmRedirectionEnabledSendsCorrectRequestedState();
    void buildExtendedDataRoundTripsBothPeriodicBranches();
    void addRemoteAccessPolicyRuleEncodesPeriodicEnvelope();

private:
    QUrl endpointFor(quint16 port) const;
};

namespace {

constexpr char kIdentifyResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsmid=\"http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd\">"
    "<s:Header/><s:Body>"
    "<wsmid:IdentifyResponse>"
    "<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>"
    "<wsmid:ProductVendor>Intel(r) AMT</wsmid:ProductVendor>"
    "<wsmid:ProductVersion>16.0.0</wsmid:ProductVersion>"
    "</wsmid:IdentifyResponse>"
    "</s:Body></s:Envelope>";

constexpr char kPowerStateResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:cim=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_AssociatedPowerManagementService\">"
    "<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</a:Action></s:Header>"
    "<s:Body>"
    "<cim:CIM_AssociatedPowerManagementService>"
    "<cim:PowerState>2</cim:PowerState>"
    "</cim:CIM_AssociatedPowerManagementService>"
    "</s:Body></s:Envelope>";

constexpr char kGeneralSettingsResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings\">"
    "<s:Header/><s:Body>"
    "<g:AMT_GeneralSettings>"
    "<g:HostName>laptop-7</g:HostName>"
    "<g:DomainName>example.com</g:DomainName>"
    "<g:DigestRealm>Digest:0123</g:DigestRealm>"
    "<g:PowerSource>1</g:PowerSource>"
    "</g:AMT_GeneralSettings>"
    "</s:Body></s:Envelope>";

constexpr char kSetupAndConfigCcmResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SetupAndConfigurationService\">"
    "<s:Header/><s:Body>"
    "<c:AMT_SetupAndConfigurationService>"
    "<c:ProvisioningState>2</c:ProvisioningState>"
    "<c:ProvisioningMode>4</c:ProvisioningMode>"
    "</c:AMT_SetupAndConfigurationService>"
    "</s:Body></s:Envelope>";

// Synthetic AMT_BootCapabilities body. Mixes supported and
// unsupported flags so the parser has to honor each field
// independently, and uses a numeric PlatformErase to exercise the
// bitmask path (bits 1, 2, 6, 25 set).
constexpr char kBootCapabilitiesResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_BootCapabilities\">"
    "<s:Header/><s:Body>"
    "<c:AMT_BootCapabilities>"
    "<c:IDER>true</c:IDER>"
    "<c:SOL>true</c:SOL>"
    "<c:BIOSReflash>false</c:BIOSReflash>"
    "<c:BIOSSetup>true</c:BIOSSetup>"
    "<c:BIOSPause>false</c:BIOSPause>"
    "<c:ForcePXEBoot>true</c:ForcePXEBoot>"
    "<c:ForceHDDBoot>true</c:ForceHDDBoot>"
    "<c:ForceCDorDVDBoot>true</c:ForceCDorDVDBoot>"
    "<c:VerbosityScreenBlank>false</c:VerbosityScreenBlank>"
    "<c:PowerButtonLock>false</c:PowerButtonLock>"
    "<c:ResetButtonLock>false</c:ResetButtonLock>"
    "<c:KeyboardLock>false</c:KeyboardLock>"
    "<c:SleepButtonLock>false</c:SleepButtonLock>"
    "<c:UserPasswordBypass>false</c:UserPasswordBypass>"
    "<c:ForcedProgressEvents>true</c:ForcedProgressEvents>"
    "<c:VerbosityVerbose>true</c:VerbosityVerbose>"
    "<c:VerbosityQuiet>false</c:VerbosityQuiet>"
    "<c:ConfigurationDataReset>true</c:ConfigurationDataReset>"
    "<c:BIOSSecureBoot>true</c:BIOSSecureBoot>"
    "<c:SecureErase>true</c:SecureErase>"
    "<c:ForceWinREBoot>true</c:ForceWinREBoot>"
    "<c:ForceUEFILocalPBABoot>false</c:ForceUEFILocalPBABoot>"
    "<c:ForceUEFIHTTPSBoot>true</c:ForceUEFIHTTPSBoot>"
    "<c:AMTSecureBootControl>true</c:AMTSecureBootControl>"
    "<c:PlatformErase>33554502</c:PlatformErase>"  // bits 1,2,6,25
    "</c:AMT_BootCapabilities>"
    "</s:Body></s:Envelope>";

constexpr char kEnumerateResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
    "<s:Header/><s:Body>"
    "<wsen:EnumerateResponse>"
    "<wsen:EnumerationContext>ctx-1</wsen:EnumerationContext>"
    "</wsen:EnumerateResponse>"
    "</s:Body></s:Envelope>";

constexpr char kSoftwareIdentityPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_SoftwareIdentity\">"
    "<s:Header/><s:Body>"
    "<wsen:PullResponse>"
    "<wsen:Items>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>BIOS</c:InstanceID>"
    "<c:VersionString>1.2.3</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>AMT</c:InstanceID>"
    "<c:VersionString>16.1.25</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>Sku</c:InstanceID>"
    "<c:VersionString>X</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>Build Number</c:InstanceID>"
    "<c:VersionString>2122</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>AMT FW Recovery Version</c:InstanceID>"
    "<c:VersionString>16.0.5</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>VendorID</c:InstanceID>"
    "<c:VersionString>8086</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "<c:CIM_SoftwareIdentity>"
    "<c:InstanceID>Flash</c:InstanceID>"
    "<c:VersionString>16.0.0.1</c:VersionString>"
    "</c:CIM_SoftwareIdentity>"
    "</wsen:Items>"
    "<wsen:EndOfSequence/>"
    "</wsen:PullResponse>"
    "</s:Body></s:Envelope>";

constexpr char kRedirectionServiceResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:r=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RedirectionService\">"
    "<s:Header/><s:Body>"
    "<r:AMT_RedirectionService>"
    "<r:ListenerEnabled>true</r:ListenerEnabled>"
    // EnabledState 32771 = base 32768 + 1 (IDE-R) + 2 (SOL) — same shape
    // the legacy app writes on toggle (`legacy/source/Commander.htm`
    // line ~50098).
    "<r:EnabledState>32771</r:EnabledState>"
    "</r:AMT_RedirectionService>"
    "</s:Body></s:Envelope>";

// --- Hardware-inventory fixtures ----------------------------------

constexpr char kChassisPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_Chassis\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_Chassis>"
    "<c:Model>ProBook 450 G7</c:Model>"
    "<c:Manufacturer>HP</c:Manufacturer>"
    "<c:Version>KBC Version 12.34</c:Version>"
    "<c:SerialNumber>5CD012ABCD</c:SerialNumber>"
    "</c:CIM_Chassis>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kSysPackagingPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_SystemPackaging\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_SystemPackaging>"
    // Bytes (no dashes) on the wire; first three dwords are
    // little-endian. The expected guidToStr output for this is
    // `33221100-5544-7766-8899-aabbccddeeff`.
    "<c:PlatformGUID>00112233445566778899AABBCCDDEEFF</c:PlatformGUID>"
    "</c:CIM_SystemPackaging>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kBiosPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_BIOSElement\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_BIOSElement>"
    "<c:Manufacturer>HP</c:Manufacturer>"
    "<c:SoftwareElementID>S70 Ver. 01.07.00</c:SoftwareElementID>"
    "<c:ReleaseDate><c:Datetime>20200115000000.000000+000</c:Datetime></c:ReleaseDate>"
    "</c:CIM_BIOSElement>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kProcessorPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_Processor\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_Processor>"
    "<c:Family>198</c:Family>"
    "<c:MaxClockSpeed>3600</c:MaxClockSpeed>"
    "<c:CPUStatus>1</c:CPUStatus>"
    "</c:CIM_Processor>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kChipPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_Chip\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_Chip>"
    "<c:Manufacturer>Intel</c:Manufacturer>"
    "<c:Version>Intel(R) Core(TM) i7-1065G7</c:Version>"
    "</c:CIM_Chip>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kPhysMemoryPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PhysicalMemory\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_PhysicalMemory>"
    "<c:BankLabel>ChannelA-DIMM0</c:BankLabel>"
    "<c:Manufacturer>Samsung</c:Manufacturer>"
    "<c:SerialNumber>0xCAFEF00D</c:SerialNumber>"
    // 16 GiB
    "<c:Capacity>17179869184</c:Capacity>"
    "<c:FormFactor>13</c:FormFactor>"
    "<c:MemoryType>26</c:MemoryType>"
    "<c:Tag>9876</c:Tag>"
    "<c:PartNumber>M471A2K43DB1-CWE</c:PartNumber>"
    "</c:CIM_PhysicalMemory>"
    "<c:CIM_PhysicalMemory>"
    "<c:BankLabel>ChannelB-DIMM0</c:BankLabel>"
    "<c:Manufacturer>Samsung</c:Manufacturer>"
    "<c:SerialNumber>0xCAFEBABE</c:SerialNumber>"
    "<c:Capacity>17179869184</c:Capacity>"
    "<c:FormFactor>13</c:FormFactor>"
    "<c:MemoryType>26</c:MemoryType>"
    "<c:Tag>9877</c:Tag>"
    "<c:PartNumber>M471A2K43DB1-CWE</c:PartNumber>"
    "</c:CIM_PhysicalMemory>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kMediaPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_MediaAccessDevice\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_MediaAccessDevice>"
    "<c:MaxMediaSize>512110190</c:MaxMediaSize>"
    "</c:CIM_MediaAccessDevice>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kPhysPackagePullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_PhysicalPackage\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_PhysicalPackage>" // 0 — chassis
    "<c:PackageType>3</c:PackageType>"
    "<c:Manufacturer>HP</c:Manufacturer>"
    "</c:CIM_PhysicalPackage>"
    "<c:CIM_PhysicalPackage>" // 1 — storage (matches Media[0] per legacy +1 shift)
    "<c:PackageType>13</c:PackageType>"
    "<c:Model>Samsung SSD 970 EVO Plus 500GB</c:Model>"
    "<c:SerialNumber>S5GXNS0NA00001</c:SerialNumber>"
    "</c:CIM_PhysicalPackage>"
    "<c:CIM_PhysicalPackage>" // 2 — battery (PackageType=11)
    "<c:PackageType>11</c:PackageType>"
    "<c:Manufacturer>HP</c:Manufacturer>"
    "<c:SerialNumber>BAT-001</c:SerialNumber>"
    "<c:ManufactureDate><c:Datetime>20200110000000.000000+000</c:Datetime></c:ManufactureDate>"
    "</c:CIM_PhysicalPackage>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kBatteryPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_Battery\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_Battery>"
    "<c:DeviceID>Battery 0</c:DeviceID>"
    "<c:Chemistry>5</c:Chemistry>"
    "<c:DesignCapacity>45000</c:DesignCapacity>"
    "<c:DesignVoltage>11400</c:DesignVoltage>"
    "</c:CIM_Battery>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kAuditLogStateResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuditLog\">"
    "<s:Header/><s:Body>"
    "<a:AMT_AuditLog>"
    // 0x05 = bit 0 (enabled) + bit 2 (almost full)
    "<a:AuditState>5</a:AuditState>"
    "<a:OverwritePolicy>1</a:OverwritePolicy>"
    "<a:CurrentNumberOfRecords>42</a:CurrentNumberOfRecords>"
    "<a:PercentageFree>15</a:PercentageFree>"
    "<a:MaxAllowedAuditors>4</a:MaxAllowedAuditors>"
    "<a:EnabledState>2</a:EnabledState>"
    "</a:AMT_AuditLog>"
    "</s:Body></s:Envelope>";

constexpr char kCardPullResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
    " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_Card\">"
    "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
    "<c:CIM_Card>"
    "<c:Manufacturer>HP</c:Manufacturer>"
    "<c:Model>867D</c:Model>"
    "<c:Version>KBC Version 12.34</c:Version>"
    "<c:SerialNumber>PJTQ001SDS3SU</c:SerialNumber>"
    "<c:Tag>AssetXYZ</c:Tag>"
    "<c:CanBeFRUed>true</c:CanBeFRUed>"
    "</c:CIM_Card>"
    "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

constexpr char kKvmSapEnabledResponse[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:k=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_KVMRedirectionSAP\">"
    "<s:Header/><s:Body>"
    "<k:CIM_KVMRedirectionSAP>"
    "<k:EnabledState>6</k:EnabledState>"
    "</k:CIM_KVMRedirectionSAP>"
    "</s:Body></s:Envelope>";

} // namespace

void TestWsmanClient::initTestCase()
{
    // QHttpServer requires the event loop; QTEST_GUILESS_MAIN provides one.
}

QUrl TestWsmanClient::endpointFor(quint16 port) const
{
    QUrl u;
    u.setScheme(QStringLiteral("http"));
    u.setHost(QStringLiteral("127.0.0.1"));
    u.setPort(port);
    u.setPath(QStringLiteral("/wsman"));
    return u;
}

void TestWsmanClient::identifyRoundTripsAgainstMockServer()
{
    QHttpServer server;
    QByteArray receivedBody;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     receivedBody = req.body();
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(kIdentifyResponse));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release(); // QHttpServer takes ownership

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    IdentifyResult result;
    QEventLoop loop;
    identify(&client, [&](IdentifyResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.productVendor, QStringLiteral("Intel(r) AMT"));
    QCOMPARE(result.productVersion, QStringLiteral("16.0.0"));
    QVERIFY(receivedBody.contains("Identify"));
}

void TestWsmanClient::getPowerStateRoundTripsAgainstMockServer()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &) {
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(kPowerStateResponse));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    PowerStateResult result;
    QEventLoop loop;
    getPowerState(&client, [&](PowerStateResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.powerState, 2);
}

void TestWsmanClient::httpErrorPropagates()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [](const QHttpServerRequest &) {
                     return QHttpServerResponse(QHttpServerResponder::StatusCode::InternalServerError);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    IdentifyResult result;
    QEventLoop loop;
    identify(&client, [&](IdentifyResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY(!result.ok);
    QVERIFY(!result.error.isEmpty());
}

// Regression for #375: when the peer closes the TCP connection before
// sending any HTTP response, `WsmanReply::hasError()` is set and the
// operation handler must NOT attempt to parse the (empty) body — it
// must emit the transport error and bail. The contract being tested
// is "result.error is non-empty AND the SOAP-derived fields stayed
// at their default-zero values, proving no parse-of-vacuous-body ran".
void TestWsmanClient::transportErrorSkipsBodyParse()
{
    // Plain QTcpServer that accepts and immediately disconnects — no
    // HTTP framing at all, so the client's header reader observes
    // "Connection closed before headers" and calls finishReply with
    // that error string.
    QTcpServer tcp;
    QObject::connect(&tcp, &QTcpServer::newConnection, &tcp, [&]() {
        while (auto *sock = tcp.nextPendingConnection()) {
            sock->disconnectFromHost();
            sock->deleteLater();
        }
    });
    QVERIFY(tcp.listen(QHostAddress::LocalHost));
    const quint16 port = tcp.serverPort();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));
    // Keep the test fast — if anything regresses we want a quick fail,
    // not the 30s default.
    client.setTransferTimeoutMs(2000);

    IdentifyResult result;
    QEventLoop loop;
    identify(&client, [&](IdentifyResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY(!result.ok);
    QVERIFY2(!result.error.isEmpty(),
             "transport error should propagate as a non-empty result.error");
    // Body parse would have populated these from a parseResponse() of an
    // empty body — they'd all be empty strings, which is the same as
    // the default. Tighten the assertion by verifying the *error* is
    // a transport-shaped one (not a SOAP fault message). The exact
    // string is set in wsman_client.cpp's finishReply().
    QVERIFY2(result.protocolVersion.isEmpty(),
             "no SOAP body should have been parsed on transport error");
    QVERIFY2(result.productVendor.isEmpty(),
             "no SOAP body should have been parsed on transport error");
    QVERIFY2(result.productVersion.isEmpty(),
             "no SOAP body should have been parsed on transport error");
}

void TestWsmanClient::getGeneralSettingsExtractsPowerSource()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &) {
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(kGeneralSettingsResponse));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    GeneralSettingsResult result;
    QEventLoop loop;
    getGeneralSettings(&client, [&](GeneralSettingsResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.hostName, QStringLiteral("laptop-7"));
    QCOMPARE(result.powerSource, 1);
}

void TestWsmanClient::getSetupAndConfigurationDecodesProvisioning()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &) {
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(kSetupAndConfigCcmResponse));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    SetupAndConfigResult result;
    QEventLoop loop;
    getSetupAndConfiguration(&client, [&](SetupAndConfigResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.provisioningState, 2);
    QCOMPARE(result.provisioningMode, 4);
}

void TestWsmanClient::getBootCapabilitiesDecodesAllFlags()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &) {
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(kBootCapabilitiesResponse));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    BootCapabilitiesResult result;
    QEventLoop loop;
    getBootCapabilities(&client, [&](BootCapabilitiesResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));

    // Spot-check every flag — the parser has 24 independent code paths
    // and a typo in any of them would silently grey out a Boot Caps
    // chip on every machine. Locking each one keeps that honest.
    QVERIFY(result.ider);
    QVERIFY(result.sol);
    QVERIFY(!result.biosReflash);
    QVERIFY(result.biosSetup);
    QVERIFY(!result.biosPause);
    QVERIFY(result.forcePxeBoot);
    QVERIFY(result.forceHddBoot);
    QVERIFY(result.forceCdOrDvdBoot);
    QVERIFY(!result.verbosityScreenBlank);
    QVERIFY(!result.powerButtonLock);
    QVERIFY(!result.resetButtonLock);
    QVERIFY(!result.keyboardLock);
    QVERIFY(!result.sleepButtonLock);
    QVERIFY(!result.userPasswordBypass);
    QVERIFY(result.forcedProgressEvents);
    QVERIFY(result.verbosityVerbose);
    QVERIFY(!result.verbosityQuiet);
    QVERIFY(result.configurationDataReset);
    QVERIFY(result.biosSecureBoot);
    QVERIFY(result.secureErase);
    QVERIFY(result.forceWinReBoot);
    QVERIFY(!result.forceUefiLocalPbaBoot);
    QVERIFY(result.forceUefiHttpsBoot);
    QVERIFY(result.amtSecureBootControl);

    // PlatformErase came in as a numeric bitmask — bits 1, 2, 6, 25.
    QVERIFY(result.platformErase);
    QCOMPARE(result.platformEraseMask, quint32{33554502});
    QVERIFY((result.platformEraseMask & (1u << 1)) != 0);
    QVERIFY((result.platformEraseMask & (1u << 2)) != 0);
    QVERIFY((result.platformEraseMask & (1u << 6)) != 0);
    QVERIFY((result.platformEraseMask & (1u << 25)) != 0);
    QVERIFY((result.platformEraseMask & (1u << 31)) == 0);
}

void TestWsmanClient::getMeVersionPicksAmtInstanceFromEnumeration()
{
    // The CIM_SoftwareIdentity enumeration POSTs twice — Enumerate then
    // Pull. The mock switches on the action header (cheaper than parsing
    // the body for `<wsen:Enumerate>` vs `<wsen:Pull>`).
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const QByteArray response = body.contains("<wsen:Pull")
                         || body.contains(":Pull>")
                             ? QByteArray(kSoftwareIdentityPullResponse)
                             : QByteArray(kEnumerateResponse);
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    MeVersionResult result;
    QEventLoop loop;
    getMeVersion(&client, [&](MeVersionResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.versionString, QStringLiteral("16.1.25"));

    // Fingerprint rows (#174) — the parser walks every row and routes
    // the well-known InstanceIDs into named fields using case-insensitive
    // substring matching so different firmware spellings all land in the
    // same UI binding.
    QCOMPARE(result.buildNumber,     QStringLiteral("2122"));
    QCOMPARE(result.recoveryVersion, QStringLiteral("16.0.5"));
    QCOMPARE(result.sku,             QStringLiteral("X"));
    QCOMPARE(result.vendorId,        QStringLiteral("8086"));
    QCOMPARE(result.flash,           QStringLiteral("16.0.0.1"));

    // The generic identities list preserves every row in pull order
    // (including non-AMT rows like BIOS) so the UI can surface vendor
    // / future InstanceIDs without parser changes.
    QCOMPARE(result.identities.size(), 7);
    QCOMPARE(result.identities.at(0).first,  QStringLiteral("BIOS"));
    QCOMPARE(result.identities.at(0).second, QStringLiteral("1.2.3"));
    QCOMPARE(result.identities.at(1).first,  QStringLiteral("AMT"));
}

void TestWsmanClient::getRedirectionStatusSplitsEnabledStateBitmask()
{
    // Two Gets — AMT_RedirectionService and CIM_KVMRedirectionSAP. The
    // request body carries the resource URI; route on it.
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const QByteArray response =
                         body.contains("CIM_KVMRedirectionSAP")
                             ? QByteArray(kKvmSapEnabledResponse)
                             : QByteArray(kRedirectionServiceResponse);
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    RedirectionStatusResult result;
    QEventLoop loop;
    getRedirectionStatus(&client, [&](RedirectionStatusResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QVERIFY(result.redirectionListenerEnabled);
    QVERIFY(result.solEnabled);
    QVERIFY(result.iderEnabled);
    QVERIFY(result.kvmAvailable);
    QVERIFY(result.kvmEnabled);
}

void TestWsmanClient::getHardwareInventoryStitchesAllSections()
{
    // Ten classes, one route. Switch on resource URI in the request
    // body. The first POST per class is Enumerate, the second is Pull.
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     // Pull responses are returned only when the body
                     // contains a Pull. Enumerate goes first.
                     const bool isPull = body.contains(":Pull>")
                                      || body.contains("<wsen:Pull");
                     QByteArray response;
                     auto matches = [&](const char *uri) { return body.contains(uri); };
                     if (!isPull) {
                         response = QByteArray(kEnumerateResponse);
                     } else if (matches("CIM_Chassis")) {
                         response = QByteArray(kChassisPullResponse);
                     } else if (matches("CIM_SystemPackaging")) {
                         response = QByteArray(kSysPackagingPullResponse);
                     } else if (matches("CIM_BIOSElement")) {
                         response = QByteArray(kBiosPullResponse);
                     } else if (matches("CIM_Processor")) {
                         response = QByteArray(kProcessorPullResponse);
                     } else if (matches("CIM_Chip")) {
                         response = QByteArray(kChipPullResponse);
                     } else if (matches("CIM_PhysicalMemory")) {
                         response = QByteArray(kPhysMemoryPullResponse);
                     } else if (matches("CIM_MediaAccessDevice")) {
                         response = QByteArray(kMediaPullResponse);
                     } else if (matches("CIM_PhysicalPackage")) {
                         response = QByteArray(kPhysPackagePullResponse);
                     } else if (matches("CIM_Battery")) {
                         response = QByteArray(kBatteryPullResponse);
                     } else if (matches("CIM_Card")) {
                         response = QByteArray(kCardPullResponse);
                     } else {
                         response = QByteArray(kEnumerateResponse);
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    HardwareInventoryResult result;
    QEventLoop loop;
    getHardwareInventory(&client, [&](HardwareInventoryResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(10000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));

    // Platform / GUID byte-swap.
    QCOMPARE(result.platformModel, QStringLiteral("ProBook 450 G7"));
    QCOMPARE(result.platformManufacturer, QStringLiteral("HP"));
    QCOMPARE(result.platformSystemId,
             QStringLiteral("33221100-5544-7766-8899-aabbccddeeff"));

    // Baseboard
    QCOMPARE(result.baseboardManufacturer, QStringLiteral("HP"));
    QCOMPARE(result.baseboardModel, QStringLiteral("867D"));
    QVERIFY(result.baseboardCanBeFRUedKnown);
    QVERIFY(result.baseboardReplaceable);

    // BIOS — Datetime is nested under ReleaseDate; the parser picks it up.
    QCOMPARE(result.biosVendor, QStringLiteral("HP"));
    QCOMPARE(result.biosVersion, QStringLiteral("S70 Ver. 01.07.00"));
    QVERIFY(!result.biosReleaseDate.isEmpty());

    // Processors zipped with chips.
    QCOMPARE(result.processors.size(), 1);
    QCOMPARE(result.processors.first().family, 198);
    QCOMPARE(result.processors.first().familyLabel,
             QStringLiteral("Intel® Core™ i7 Processor"));
    QCOMPARE(result.processors.first().manufacturer, QStringLiteral("Intel"));
    QCOMPARE(result.processors.first().maxClockSpeedMhz, 3600);
    QCOMPARE(result.processors.first().cpuStatusLabel, QStringLiteral("Enabled"));

    // Two DIMMs — DDR4 (26), SODIMM (13), 16 GiB each.
    QCOMPARE(result.memoryModules.size(), 2);
    QCOMPARE(result.memoryModules.first().memoryTypeLabel, QStringLiteral("DDR4"));
    QCOMPARE(result.memoryModules.first().formFactorLabel, QStringLiteral("SODIMM"));
    QCOMPARE(result.memoryModules.first().capacityBytes, 17179869184LL);

    // One storage device — package index +1 zip.
    QCOMPARE(result.storageDevices.size(), 1);
    QCOMPARE(result.storageDevices.first().model,
             QStringLiteral("Samsung SSD 970 EVO Plus 500GB"));
    QCOMPARE(result.storageDevices.first().serialNumber,
             QStringLiteral("S5GXNS0NA00001"));

    // Battery — present, matched physical package by PackageType=11.
    QVERIFY(result.battery.present);
    QCOMPARE(result.battery.deviceId, QStringLiteral("Battery 0"));
    QCOMPARE(result.battery.chemistryLabel, QStringLiteral("Lithium-ion"));
    QCOMPARE(result.battery.designCapacityMwh, 45000LL);
    QCOMPARE(result.battery.designVoltageMv,   11400LL);
    QCOMPARE(result.battery.serialNumber,      QStringLiteral("BAT-001"));
}

void TestWsmanClient::getAuditLogStateDecodesBitmask()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &) {
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(kAuditLogStateResponse));
                 });
    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    AuditLogState s;
    QEventLoop loop;
    getAuditLogState(&client, [&](AuditLogState r) { s = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(s.ok, qPrintable(s.error));
    QCOMPARE(s.auditState, 5);
    QCOMPARE(s.currentNumberOfRecords, 42);
    QCOMPARE(s.percentageFree, 15);
}

void TestWsmanClient::enumerateAuditLogParsesBinaryRecords()
{
    // Hand-build two records into one chunk and verify the parser
    // walks the binary fields correctly. Record one is a Local-
    // initiator event with an event ID that lives in the audit string
    // table; record two is an HTTP-digest event with a user name.
    auto makeBE16 = [](quint16 v) {
        QByteArray r; r.resize(2);
        r[0] = char(v >> 8); r[1] = char(v & 0xFF);
        return r;
    };
    auto makeBE32 = [](quint32 v) {
        QByteArray r; r.resize(4);
        r[0] = char(v >> 24); r[1] = char((v >> 16) & 0xFF);
        r[2] = char((v >>  8) & 0xFF); r[3] = char(v & 0xFF);
        return r;
    };

    const quint16 auditApp = 20;   // Security Audit Log
    const quint16 eventOk  = 3;    // 2003 → "Security Audit Log Enabled"
    const quint32 t        = 1700000000u;

    QByteArray rec1;
    rec1 += makeBE16(auditApp);
    rec1 += makeBE16(eventOk);
    rec1.append(char(2));          // InitiatorType: Local
    rec1 += makeBE32(t);
    rec1.append(char(0));          // MCLocationType
    rec1.append(char(9));          // netlen
    rec1.append("192.0.2.1", 9);
    rec1.append(char(0));          // exlen

    QByteArray rec2;
    rec2 += makeBE16(17);          // RCO
    rec2 += makeBE16(0);           // → 1700 "Performed Power Up"
    rec2.append(char(0));          // HTTP digest
    rec2.append(char(5));          // userlen
    rec2.append("admin", 5);
    rec2 += makeBE32(t);
    rec2.append(char(0));          // MCLocationType
    rec2.append(char(0));          // netlen
    rec2.append(char(0));          // exlen

    const QString b64a = QString::fromLatin1(rec1.toBase64());
    const QString b64b = QString::fromLatin1(rec2.toBase64());

    const QString response = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuditLog\">"
        "<s:Header/><s:Body>"
        "<g:ReadRecords_OUTPUT>"
        "<g:TotalRecordCount>2</g:TotalRecordCount>"
        "<g:RecordsReturned>2</g:RecordsReturned>"
        "<g:EventRecords>%1</g:EventRecords>"
        "<g:EventRecords>%2</g:EventRecords>"
        "<g:ReturnValue>0</g:ReturnValue>"
        "</g:ReadRecords_OUTPUT>"
        "</s:Body></s:Envelope>").arg(b64a, b64b);
    const QByteArray responseBytes = response.toUtf8();

    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &) {
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                responseBytes);
                 });
    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    AuditLogResult res;
    QEventLoop loop;
    enumerateAuditLog(&client, [&](AuditLogResult r) { res = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(res.ok, qPrintable(res.error));
    QCOMPARE(res.entries.size(), 2);

    QCOMPARE(res.entries[0].auditAppId, 20);
    QCOMPARE(res.entries[0].eventId,    3);
    QCOMPARE(res.entries[0].auditAppLabel, QStringLiteral("Security Audit Log"));
    QCOMPARE(res.entries[0].eventLabel,    QStringLiteral("Security Audit Log Enabled"));
    QCOMPARE(res.entries[0].initiator,     QStringLiteral("Local"));
    QCOMPARE(res.entries[0].unixSeconds,   1700000000LL);
    QCOMPARE(res.entries[0].netAddress,    QStringLiteral("192.0.2.1"));

    QCOMPARE(res.entries[1].auditAppId, 17);
    QCOMPARE(res.entries[1].eventLabel, QStringLiteral("Performed Power Up"));
    QCOMPARE(res.entries[1].initiator,  QStringLiteral("admin"));
}

void TestWsmanClient::enumerateUserAccountsMergesAdminAndAclEntries()
{
    // Three invokes hit the mock: GetAdminAclEntry, EnumerateUserAclEntries,
    // and per-handle GetUserAclEntryEx + GetAclEnabledState. The mock
    // routes on the method name embedded in the body.
    static const char *adminResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService\">"
        "<s:Header/><s:Body>"
        "<a:GetAdminAclEntry_OUTPUT>"
        "<a:Username>admin</a:Username>"
        "<a:ReturnValue>0</a:ReturnValue>"
        "</a:GetAdminAclEntry_OUTPUT>"
        "</s:Body></s:Envelope>";

    static const char *enumResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService\">"
        "<s:Header/><s:Body>"
        "<a:EnumerateUserAclEntries_OUTPUT>"
        "<a:Handles>1</a:Handles>"
        "<a:Handles>2</a:Handles>"
        "<a:ReturnValue>0</a:ReturnValue>"
        "</a:EnumerateUserAclEntries_OUTPUT>"
        "</s:Body></s:Envelope>";

    static const char *userEntryDigest =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService\">"
        "<s:Header/><s:Body>"
        "<a:GetUserAclEntryEx_OUTPUT>"
        "<a:DigestUsername>operator</a:DigestUsername>"
        "<a:AccessPermission>2</a:AccessPermission>"
        "<a:Realms>2</a:Realms>"   // Redirection
        "<a:Realms>5</a:Realms>"   // Remote Control
        "<a:Realms>13</a:Realms>"  // General Information
        "<a:ReturnValue>0</a:ReturnValue>"
        "</a:GetUserAclEntryEx_OUTPUT>"
        "</s:Body></s:Envelope>";

    static const char *enabledTrue =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService\">"
        "<s:Header/><s:Body>"
        "<a:GetAclEnabledState_OUTPUT>"
        "<a:Enabled>true</a:Enabled>"
        "<a:ReturnValue>0</a:ReturnValue>"
        "</a:GetAclEnabledState_OUTPUT>"
        "</s:Body></s:Envelope>";

    // Distinguish the two handles by tracking which Handle value appears
    // in the request body. Handle=1 returns a digest user (enabled);
    // Handle=2 returns a Kerberos user (disabled) for variety.
    static const char *userEntryKerberos =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService\">"
        "<s:Header/><s:Body>"
        "<a:GetUserAclEntryEx_OUTPUT>"
        "<a:KerberosUserSid>AQUAAAAAAAUVAAAAAAAAAAAAAAA=</a:KerberosUserSid>"
        "<a:AccessPermission>1</a:AccessPermission>"
        "<a:Realms>3</a:Realms>"   // bit 3 = administrator
        "<a:ReturnValue>0</a:ReturnValue>"
        "</a:GetUserAclEntryEx_OUTPUT>"
        "</s:Body></s:Envelope>";

    static const char *enabledFalse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:a=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AuthorizationService\">"
        "<s:Header/><s:Body>"
        "<a:GetAclEnabledState_OUTPUT>"
        "<a:Enabled>false</a:Enabled>"
        "<a:ReturnValue>0</a:ReturnValue>"
        "</a:GetAclEnabledState_OUTPUT>"
        "</s:Body></s:Envelope>";

    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     QByteArray response;
                     if (body.contains("GetAdminAclEntry")) {
                         response = adminResponse;
                     } else if (body.contains("EnumerateUserAclEntries")) {
                         response = enumResponse;
                     } else if (body.contains("GetUserAclEntryEx")) {
                         response = body.contains("<g:Handle>2</g:Handle>")
                              || body.contains("Handle>2</")
                                       ? QByteArray(userEntryKerberos)
                                       : QByteArray(userEntryDigest);
                     } else if (body.contains("GetAclEnabledState")) {
                         response = body.contains("<g:Handle>2</g:Handle>")
                              || body.contains("Handle>2</")
                                       ? QByteArray(enabledFalse)
                                       : QByteArray(enabledTrue);
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    UserAccountsResult res;
    QEventLoop loop;
    enumerateUserAccounts(&client, [&](UserAccountsResult r) {
        res = r;
        loop.quit();
    });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(res.ok, qPrintable(res.error));

    // Three rows expected: admin (handle=-1), handle=1, handle=2.
    QCOMPARE(res.accounts.size(), 3);
    QCOMPARE(res.accounts[0].handle, -1);
    QCOMPARE(res.accounts[0].digestUsername, QStringLiteral("admin"));
    QCOMPARE(res.accounts[0].accessPermission, 999);

    // Handle=1 should have the digest user with three realms.
    const auto &u1 = res.accounts[1];
    QCOMPARE(u1.handle, 1);
    QCOMPARE(u1.digestUsername, QStringLiteral("operator"));
    QCOMPARE(u1.accessPermission, 2);
    QCOMPARE(u1.realms.size(), 3);
    QVERIFY(u1.realms.contains(2));
    QVERIFY(u1.realms.contains(5));
    QVERIFY(u1.enabled);

    // Handle=2 should be Kerberos, realm 3 (administrator bit), disabled.
    const auto &u2 = res.accounts[2];
    QCOMPARE(u2.handle, 2);
    QVERIFY(u2.digestUsername.isEmpty());
    QVERIFY(!u2.kerberosUserSidB64.isEmpty());
    QCOMPARE(u2.accessPermission, 1);
    QVERIFY(u2.realms.contains(3));
    QVERIFY(!u2.enabled);

    // Label helpers.
    QCOMPARE(accessPermissionLabel(0),   QStringLiteral("Local only"));
    QCOMPARE(accessPermissionLabel(2),   QStringLiteral("All (Local & Network)"));
    QCOMPARE(accessPermissionLabel(999), QStringLiteral("Administrator"));
    QCOMPARE(realmName(2),  QStringLiteral("Redirection"));
    QCOMPARE(realmName(20), QStringLiteral("Audit Log"));
    QCOMPARE(realmName(3),  QString()); // sentinel
}

void TestWsmanClient::getEthernetSettingsReturnsMultipleInterfacesWithIPv6()
{
    // Two AMT_EthernetPortSettings instances + matching IPS_IPv6PortSettings
    // for interface 0 only (mirrors AMT 11 where IPv6 is wired-only by
    // default). Mock routes by resource URI.
    static const char *ethPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:e=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_EthernetPortSettings\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<e:AMT_EthernetPortSettings>"
        "<e:InstanceID>Intel(r) AMT Ethernet Port Settings 0</e:InstanceID>"
        "<e:MACAddress>aa:bb:cc:dd:ee:ff</e:MACAddress>"
        "<e:DHCPEnabled>true</e:DHCPEnabled>"
        "<e:IpSyncEnabled>true</e:IpSyncEnabled>"
        "<e:IPAddress>192.168.1.5</e:IPAddress>"
        "<e:SubnetMask>255.255.255.0</e:SubnetMask>"
        "<e:DefaultGateway>192.168.1.1</e:DefaultGateway>"
        "<e:PrimaryDNS>8.8.8.8</e:PrimaryDNS>"
        "<e:LinkPolicy>1</e:LinkPolicy>"
        "<e:LinkPolicy>14</e:LinkPolicy>"
        "<e:LinkPolicy>16</e:LinkPolicy>"
        "</e:AMT_EthernetPortSettings>"
        "<e:AMT_EthernetPortSettings>"
        "<e:InstanceID>Intel(r) AMT Ethernet Port Settings 1</e:InstanceID>"
        "<e:MACAddress>11:22:33:44:55:66</e:MACAddress>"
        "<e:DHCPEnabled>false</e:DHCPEnabled>"
        "<e:IpSyncEnabled>false</e:IpSyncEnabled>"
        "<e:IPAddress>10.0.0.5</e:IPAddress>"
        "<e:SubnetMask>255.0.0.0</e:SubnetMask>"
        "<e:LinkPolicy>1</e:LinkPolicy>"
        "</e:AMT_EthernetPortSettings>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *ipv6Pull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:v=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_IPv6PortSettings\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<v:IPS_IPv6PortSettings>"
        "<v:InstanceID>Intel(r) AMT IPv6 Port Settings 0</v:InstanceID>"
        "<v:CurrentAddressInfo>2001:db8::1,64,static,enabled</v:CurrentAddressInfo>"
        "<v:CurrentAddressInfo>fe80::1,64,linklocal,enabled</v:CurrentAddressInfo>"
        "<v:CurrentDefaultRouter>2001:db8::ff</v:CurrentDefaultRouter>"
        "<v:CurrentPrimaryDNS>2001:4860:4860::8888</v:CurrentPrimaryDNS>"
        "</v:IPS_IPv6PortSettings>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPull = body.contains(":Pull>")
                                      || body.contains("<wsen:Pull");
                     QByteArray response;
                     if (!isPull) {
                         response = QByteArray(kEnumerateResponse);
                     } else if (body.contains("IPS_IPv6PortSettings")) {
                         response = ipv6Pull;
                     } else {
                         response = ethPull;
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });
    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    EthernetSettingsResult result;
    QEventLoop loop;
    getEthernetSettings(&client, [&](EthernetSettingsResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));

    QCOMPARE(result.interfaces.size(), 2);

    // Interface 0: wired DHCP, IPv6 attached.
    const auto &if0 = result.interfaces[0];
    QCOMPARE(if0.macAddress, QStringLiteral("aa:bb:cc:dd:ee:ff"));
    QVERIFY(if0.dhcpEnabled);
    QVERIFY(if0.ipSyncEnabled);
    QCOMPARE(if0.ipAddress, QStringLiteral("192.168.1.5"));
    QCOMPARE(if0.linkPolicy.size(), 3);
    QVERIFY(if0.linkPolicy.contains(1));
    QVERIFY(if0.linkPolicy.contains(14));
    QVERIFY(if0.linkPolicy.contains(16));
    QVERIFY(if0.ipv6.present);
    QCOMPARE(if0.ipv6.addresses.size(), 2);
    QCOMPARE(if0.ipv6.addresses.first(), QStringLiteral("2001:db8::1"));
    QCOMPARE(if0.ipv6.defaultRouter, QStringLiteral("2001:db8::ff"));
    QCOMPARE(if0.ipv6.primaryDns, QStringLiteral("2001:4860:4860::8888"));

    // Interface 1: static IP, no IPv6.
    const auto &if1 = result.interfaces[1];
    QVERIFY(!if1.dhcpEnabled);
    QCOMPARE(if1.ipAddress, QStringLiteral("10.0.0.5"));
    QVERIFY(!if1.ipv6.present);

    // Backward-compat single-interface scalars match if[0].
    QCOMPARE(result.macAddress, QStringLiteral("aa:bb:cc:dd:ee:ff"));
    QCOMPARE(result.ipAddress, QStringLiteral("192.168.1.5"));

    // Label helper spot-check.
    QCOMPARE(linkPolicyLabel(1),   QStringLiteral("S0/AC"));
    QCOMPARE(linkPolicyLabel(224), QStringLiteral("Sx/DC"));
}

void TestWsmanClient::splitDnHelperHandlesEmptyAndMultiple()
{
    QCOMPARE(splitDn(QString()).size(), 0);
    auto m = splitDn(QStringLiteral("CN=Intel(R) AMT, O=Intel Corporation, C=US"));
    QCOMPARE(m.value(QStringLiteral("CN")), QStringLiteral("Intel(R) AMT"));
    QCOMPARE(m.value(QStringLiteral("O")),  QStringLiteral("Intel Corporation"));
    QCOMPARE(m.value(QStringLiteral("C")),  QStringLiteral("US"));
}

void TestWsmanClient::getDeviceCertStoreStitchesCertsKeysAndTls()
{
    // Fixture covers: trusted-root cert (with the legacy `TrustedRootCertficate`
    // typo); a non-root cert paired with a key by suffix; an orphan
    // key pair; both TLS endpoints; an `AMT_TLSCredentialContext`
    // pointing at the non-root cert as active.
    static const char *certPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<p:AMT_PublicKeyCertificate>"
        "<p:InstanceID>Intel(r) AMT Certificate: Handle: 0</p:InstanceID>"
        "<p:Subject>CN=Server Cert, O=Acme, C=US</p:Subject>"
        "<p:Issuer>CN=Acme Root CA, O=Acme</p:Issuer>"
        "<p:TrustedRootCertficate>false</p:TrustedRootCertficate>"
        "<p:X509Certificate>SGVsbG8gV29ybGQ=</p:X509Certificate>"  // 11 bytes
        "</p:AMT_PublicKeyCertificate>"
        "<p:AMT_PublicKeyCertificate>"
        "<p:InstanceID>Intel(r) AMT Certificate: Handle: 1</p:InstanceID>"
        "<p:Subject>CN=Acme Root CA, O=Acme</p:Subject>"
        "<p:Issuer>CN=Acme Root CA, O=Acme</p:Issuer>"
        "<p:TrustedRootCertficate>true</p:TrustedRootCertficate>"
        "<p:X509Certificate>SGVsbG8=</p:X509Certificate>"          // 5 bytes
        "</p:AMT_PublicKeyCertificate>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *keyPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicPrivateKeyPair\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        // Matching key for cert handle 0 (suffix " 0").
        "<p:AMT_PublicPrivateKeyPair>"
        "<p:InstanceID>Intel(r) AMT Key: Handle: 0</p:InstanceID>"
        "<p:DERKey>QUFBQQ==</p:DERKey>"
        "</p:AMT_PublicPrivateKeyPair>"
        // Orphan key with no matching cert.
        "<p:AMT_PublicPrivateKeyPair>"
        "<p:InstanceID>Intel(r) AMT Key: Handle: 99</p:InstanceID>"
        "<p:DERKey>QkJCQg==</p:DERKey>"
        "</p:AMT_PublicPrivateKeyPair>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *tlsPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:t=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSSettingData\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<t:AMT_TLSSettingData>"
        "<t:InstanceID>Intel(r) AMT LMS TLS Settings</t:InstanceID>"
        "<t:Enabled>true</t:Enabled>"
        "<t:MutualAuthentication>false</t:MutualAuthentication>"
        "<t:AcceptNonSecureConnections>true</t:AcceptNonSecureConnections>"
        "</t:AMT_TLSSettingData>"
        "<t:AMT_TLSSettingData>"
        "<t:InstanceID>Intel(r) AMT 802.3 TLS Settings</t:InstanceID>"
        "<t:Enabled>true</t:Enabled>"
        "<t:MutualAuthentication>true</t:MutualAuthentication>"
        "<t:AcceptNonSecureConnections>false</t:AcceptNonSecureConnections>"
        "<t:TrustedCN>amt-admin.example.com</t:TrustedCN>"
        "<t:TrustedCN>backup-admin.example.com</t:TrustedCN>"
        "</t:AMT_TLSSettingData>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *ctxPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
        " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/09/transfer\""
        " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TLSCredentialContext\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<c:AMT_TLSCredentialContext>"
        "<c:ElementInContext>"
          "<a:Address>/wsman</a:Address>"
          "<a:ReferenceParameters>"
            "<w:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_PublicKeyCertificate</w:ResourceURI>"
            "<w:SelectorSet>"
              "<w:Selector Name=\"InstanceID\">Intel(r) AMT Certificate: Handle: 0</w:Selector>"
            "</w:SelectorSet>"
          "</a:ReferenceParameters>"
        "</c:ElementInContext>"
        "</c:AMT_TLSCredentialContext>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPull = body.contains(":Pull>")
                                      || body.contains("<wsen:Pull");
                     QByteArray response;
                     if (!isPull) {
                         response = QByteArray(kEnumerateResponse);
                     } else if (body.contains("AMT_PublicKeyCertificate")) {
                         response = certPull;
                     } else if (body.contains("AMT_PublicPrivateKeyPair")) {
                         response = keyPull;
                     } else if (body.contains("AMT_TLSCredentialContext")) {
                         response = ctxPull;
                     } else if (body.contains("AMT_TLSSettingData")) {
                         response = tlsPull;
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });
    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    DeviceCertResult res;
    QEventLoop loop;
    getDeviceCertStore(&client, [&](DeviceCertResult r) {
        res = r;
        loop.quit();
    });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(res.ok, qPrintable(res.error));
    QCOMPARE(res.certificates.size(), 2);

    QCOMPARE(res.certificates[0].subjectCn, QStringLiteral("Server Cert"));
    QCOMPARE(res.certificates[0].issuerCn,  QStringLiteral("Acme Root CA"));
    QVERIFY(!res.certificates[0].trustedRoot);
    QCOMPARE(res.certificates[0].derSizeBytes, 11);

    QCOMPARE(res.certificates[1].subjectCn, QStringLiteral("Acme Root CA"));
    QVERIFY(res.certificates[1].trustedRoot);  // typo-spelled field accepted

    QCOMPARE(res.keyPairs.size(), 2);
    QCOMPARE(res.tlsSettings.size(), 2);

    bool foundMutual = false, foundLocal = false;
    for (const auto &t : res.tlsSettings) {
        if (t.mutualAuthentication) {
            foundMutual = true;
            QCOMPARE(t.trustedCn.size(), 2);
            QCOMPARE(t.trustedCn.first(), QStringLiteral("amt-admin.example.com"));
        }
        if (t.instanceId.contains(QStringLiteral("LMS"))) foundLocal = true;
    }
    QVERIFY(foundMutual);
    QVERIFY(foundLocal);

    // TLS credential context points at handle 0.
    QCOMPARE(res.activeCertInstanceIds.size(), 1);
    QCOMPARE(res.activeCertInstanceIds.first(),
             QStringLiteral("Intel(r) AMT Certificate: Handle: 0"));
}

void TestWsmanClient::getRemoteAccessStitchesEnvPoliciesServersAndProxies()
{
    // Build a `Periodic` policy ExtendedData blob: type=0 (interval) +
    // seconds=3600 — 8 bytes BE — and base64 it.
    auto be32 = [](quint32 v) {
        QByteArray r; r.resize(4);
        r[0] = char(v >> 24); r[1] = char((v >> 16) & 0xFF);
        r[2] = char((v >>  8) & 0xFF); r[3] = char(v & 0xFF);
        return r;
    };
    QByteArray periodicExt;
    periodicExt += be32(0);          // type 0 = interval
    periodicExt += be32(3600);       // every 3600 s
    const QString periodicExtB64 = QString::fromLatin1(periodicExt.toBase64());

    static const char *envDetectResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:e=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_EnvironmentDetectionSettingData\">"
        "<s:Header/><s:Body>"
        "<e:AMT_EnvironmentDetectionSettingData>"
        "<e:DetectionStrings>corp.example.com</e:DetectionStrings>"
        "<e:DetectionStrings>internal.example.com</e:DetectionStrings>"
        "</e:AMT_EnvironmentDetectionSettingData>"
        "</s:Body></s:Envelope>";

    static const char *userInitResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:u=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_UserInitiatedConnectionService\">"
        "<s:Header/><s:Body>"
        "<u:AMT_UserInitiatedConnectionService>"
        "<u:EnabledState>32771</u:EnabledState>"
        "</u:AMT_UserInitiatedConnectionService>"
        "</s:Body></s:Envelope>";

    const QString policyRuleResponseTmpl = QStringLiteral(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RemoteAccessPolicyRule\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<p:AMT_RemoteAccessPolicyRule>"
        "<p:PolicyRuleName>User Initiated</p:PolicyRuleName>"
        "<p:Trigger>0</p:Trigger>"
        "<p:TunnelLifeTime>0</p:TunnelLifeTime>"
        "</p:AMT_RemoteAccessPolicyRule>"
        "<p:AMT_RemoteAccessPolicyRule>"
        "<p:PolicyRuleName>Periodic</p:PolicyRuleName>"
        "<p:Trigger>2</p:Trigger>"
        "<p:TunnelLifeTime>1800</p:TunnelLifeTime>"
        "<p:ExtendedData>%1</p:ExtendedData>"
        "</p:AMT_RemoteAccessPolicyRule>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>"
    ).arg(periodicExtB64);
    const QByteArray policyRuleResponse = policyRuleResponseTmpl.toUtf8();

    static const char *appliesResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
        " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/09/transfer\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RemoteAccessPolicyAppliesToMPS\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<p:AMT_RemoteAccessPolicyAppliesToMPS>"
        "<p:PolicySet>"
          "<a:Address>/wsman</a:Address>"
          "<a:ReferenceParameters>"
            "<w:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RemoteAccessPolicyRule</w:ResourceURI>"
            "<w:SelectorSet><w:Selector Name=\"PolicyRuleName\">Periodic</w:Selector></w:SelectorSet>"
          "</a:ReferenceParameters>"
        "</p:PolicySet>"
        "<p:ManagedElement>"
          "<a:Address>/wsman</a:Address>"
          "<a:ReferenceParameters>"
            "<w:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_ManagementPresenceRemoteSAP</w:ResourceURI>"
            "<w:SelectorSet><w:Selector Name=\"Name\">MPS-1</w:Selector></w:SelectorSet>"
          "</a:ReferenceParameters>"
        "</p:ManagedElement>"
        "</p:AMT_RemoteAccessPolicyAppliesToMPS>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *mpsResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:m=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_ManagementPresenceRemoteSAP\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<m:AMT_ManagementPresenceRemoteSAP>"
        "<m:Name>MPS-1</m:Name>"
        "<m:AccessInfo>mps.example.com</m:AccessInfo>"
        "<m:Port>4433</m:Port>"
        "<m:CN>mps.example.com</m:CN>"
        "<m:MpsType>0</m:MpsType>"
        "</m:AMT_ManagementPresenceRemoteSAP>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *proxyServiceResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_HTTPProxyService\">"
        "<s:Header/><s:Body>"
        "<p:IPS_HTTPProxyService>"
        "<p:EnabledState>2</p:EnabledState>"
        "</p:IPS_HTTPProxyService>"
        "</s:Body></s:Envelope>";

    static const char *proxyAccessPointResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_HTTPProxyAccessPoint\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<p:IPS_HTTPProxyAccessPoint>"
        "<p:AccessInfo>proxy.corp.example.com</p:AccessInfo>"
        "<p:Port>3128</p:Port>"
        "<p:NetworkDnsSuffix>example.com</p:NetworkDnsSuffix>"
        "</p:IPS_HTTPProxyAccessPoint>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPull = body.contains(":Pull>")
                                      || body.contains("<wsen:Pull");
                     QByteArray response;
                     if (!isPull && body.contains("AMT_EnvironmentDetectionSettingData")) {
                         response = envDetectResponse;
                     } else if (!isPull && body.contains("AMT_UserInitiatedConnectionService")) {
                         response = userInitResponse;
                     } else if (!isPull && body.contains("IPS_HTTPProxyService")) {
                         response = proxyServiceResponse;
                     } else if (!isPull) {
                         response = QByteArray(kEnumerateResponse);
                     } else if (body.contains("AMT_RemoteAccessPolicyRule")) {
                         response = policyRuleResponse;
                     } else if (body.contains("AMT_RemoteAccessPolicyAppliesToMPS")) {
                         response = appliesResponse;
                     } else if (body.contains("AMT_ManagementPresenceRemoteSAP")) {
                         response = mpsResponse;
                     } else if (body.contains("IPS_HTTPProxyAccessPoint")) {
                         response = proxyAccessPointResponse;
                     } else {
                         // empty pull for MpsUsernamePassword etc.
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
                             "<s:Header/><s:Body><wsen:PullResponse>"
                             "<wsen:Items/><wsen:EndOfSequence/>"
                             "</wsen:PullResponse></s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    RemoteAccessResult res;
    QEventLoop loop;
    getRemoteAccess(&client, [&](RemoteAccessResult r) {
        res = r;
        loop.quit();
    });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(res.ok, qPrintable(res.error));
    QCOMPARE(res.envDetection.domains.size(), 2);
    QCOMPARE(res.envDetection.domains.first(),
             QStringLiteral("corp.example.com"));
    QCOMPARE(res.userInitiated.enabledState, 32771);

    // Two policies — User Initiated (no extended data) and Periodic
    // (interval 3600). Order is the legacy emit order.
    QCOMPARE(res.policies.size(), 2);
    QCOMPARE(res.policies[0].name, QStringLiteral("User Initiated"));
    QCOMPARE(res.policies[1].name, QStringLiteral("Periodic"));
    QVERIFY(res.policies[1].periodicInterval);
    QCOMPARE(res.policies[1].periodicSeconds, 3600);
    QCOMPARE(res.policies[1].tunnelLifeTime, 1800);
    QCOMPARE(res.policies[1].mpsNames.size(), 1);
    QCOMPARE(res.policies[1].mpsNames.first(), QStringLiteral("MPS-1"));

    QCOMPARE(res.servers.size(), 1);
    QCOMPARE(res.servers.first().accessInfo,
             QStringLiteral("mps.example.com"));
    QCOMPARE(res.servers.first().port, 4433);

    QVERIFY(res.httpProxySupported);
    QCOMPARE(res.httpProxies.size(), 1);
    QCOMPARE(res.httpProxies.first().accessInfo,
             QStringLiteral("proxy.corp.example.com"));

    QCOMPARE(userInitiatedCiraLabel(32771),
             QStringLiteral("BIOS + OS enabled"));
}

void TestWsmanClient::getWirelessJoinsProfilesAnd8021xByElementName()
{
    static const char *wifiPortResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:p=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_WiFiPort\">"
        "<s:Header/><s:Body>"
        "<p:CIM_WiFiPort>"
        "<p:EnabledState>32769</p:EnabledState>"
        "</p:CIM_WiFiPort>"
        "</s:Body></s:Envelope>";

    static const char *wifiEndpointResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:e=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_WiFiEndpoint\">"
        "<s:Header/><s:Body>"
        "<e:CIM_WiFiEndpoint>"
        "<e:EnabledState>2</e:EnabledState>"
        "<e:LANID>HomeNet</e:LANID>"
        "</e:CIM_WiFiEndpoint>"
        "</s:Body></s:Envelope>";

    static const char *wifiConfigSvcResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_WiFiPortConfigurationService\">"
        "<s:Header/><s:Body>"
        "<c:AMT_WiFiPortConfigurationService>"
        "<c:localProfileSynchronizationEnabled>1</c:localProfileSynchronizationEnabled>"
        "</c:AMT_WiFiPortConfigurationService>"
        "</s:Body></s:Envelope>";

    static const char *wifiSettingsPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:p=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_WiFiEndpointSettings\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        // Should be filtered out (Endpoint User Settings).
        "<p:CIM_WiFiEndpointSettings>"
        "<p:ElementName>EndpointUserSettings</p:ElementName>"
        "<p:SSID></p:SSID>"
        "<p:AuthenticationMethod>1</p:AuthenticationMethod>"
        "<p:EncryptionMethod>5</p:EncryptionMethod>"
        "<p:Priority>0</p:Priority>"
        "</p:CIM_WiFiEndpointSettings>"
        // Priority 2 — should sort after priority 0 below.
        "<p:CIM_WiFiEndpointSettings>"
        "<p:ElementName>GuestNet</p:ElementName>"
        "<p:SSID>GuestNet</p:SSID>"
        "<p:AuthenticationMethod>6</p:AuthenticationMethod>"
        "<p:EncryptionMethod>4</p:EncryptionMethod>"
        "<p:Priority>2</p:Priority>"
        "</p:CIM_WiFiEndpointSettings>"
        // Priority 0 — sorts first; 802.1x linked.
        "<p:CIM_WiFiEndpointSettings>"
        "<p:ElementName>CorpNet</p:ElementName>"
        "<p:SSID>CorpNet</p:SSID>"
        "<p:AuthenticationMethod>7</p:AuthenticationMethod>"
        "<p:EncryptionMethod>4</p:EncryptionMethod>"
        "<p:Priority>0</p:Priority>"
        "</p:CIM_WiFiEndpointSettings>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *ieee8021xPull =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
        " xmlns:p=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_IEEE8021xSettings\">"
        "<s:Header/><s:Body><wsen:PullResponse><wsen:Items>"
        "<p:CIM_IEEE8021xSettings>"
        "<p:ElementName>CorpNet</p:ElementName>"
        "<p:AuthenticationProtocol>0</p:AuthenticationProtocol>"
        "</p:CIM_IEEE8021xSettings>"
        "</wsen:Items><wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>";

    static const char *wiredProfileResponse =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:p=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_8021XProfile\">"
        "<s:Header/><s:Body>"
        "<p:AMT_8021XProfile>"
        "<p:Enabled>true</p:Enabled>"
        "<p:AuthenticationProtocol>2</p:AuthenticationProtocol>"
        "</p:AMT_8021XProfile>"
        "</s:Body></s:Envelope>";

    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPull = body.contains(":Pull>")
                                      || body.contains("<wsen:Pull");
                     QByteArray response;
                     if (!isPull && body.contains("CIM_WiFiPort\"")) {
                         response = wifiPortResponse;
                     } else if (!isPull && body.contains("CIM_WiFiPort/")) {
                         response = wifiPortResponse;
                     } else if (!isPull && body.contains("CIM_WiFiPort<")) {
                         response = wifiPortResponse;
                     } else if (!isPull && body.contains("CIM_WiFiEndpoint\"")
                                       && !body.contains("CIM_WiFiEndpointSettings")) {
                         response = wifiEndpointResponse;
                     } else if (!isPull && body.contains("CIM_WiFiEndpoint<")
                                       && !body.contains("CIM_WiFiEndpointSettings")) {
                         response = wifiEndpointResponse;
                     } else if (!isPull && body.contains("CIM_WiFiEndpoint/")
                                       && !body.contains("CIM_WiFiEndpointSettings")) {
                         response = wifiEndpointResponse;
                     } else if (!isPull && body.contains("AMT_WiFiPortConfigurationService")) {
                         response = wifiConfigSvcResponse;
                     } else if (!isPull && body.contains("AMT_8021XProfile")) {
                         response = wiredProfileResponse;
                     } else if (!isPull) {
                         response = QByteArray(kEnumerateResponse);
                     } else if (body.contains("CIM_WiFiEndpointSettings")) {
                         response = wifiSettingsPull;
                     } else if (body.contains("CIM_IEEE8021xSettings")) {
                         response = ieee8021xPull;
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    WirelessResult res;
    QEventLoop loop;
    getWireless(&client, [&](WirelessResult r) {
        res = r;
        loop.quit();
    });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(res.ok, qPrintable(res.error));
    QVERIFY(res.port.present);
    QCOMPARE(res.port.portState, 32769);
    QCOMPARE(res.port.radioState, 2);
    QCOMPARE(res.port.currentSsid, QStringLiteral("HomeNet"));
    QCOMPARE(res.port.localProfileSyncEnabled, 1);

    // Endpoint User Settings entry filtered out — 2 profiles remain.
    QCOMPARE(res.profiles.size(), 2);
    // Sorted by priority — CorpNet (0) first, GuestNet (2) second.
    QCOMPARE(res.profiles[0].elementName, QStringLiteral("CorpNet"));
    QCOMPARE(res.profiles[0].eap8021xProtocol, 0);   // EAP-TLS
    QCOMPARE(res.profiles[1].elementName, QStringLiteral("GuestNet"));
    QCOMPARE(res.profiles[1].eap8021xProtocol, -1);

    QVERIFY(res.wired.present);
    QVERIFY(res.wired.enabled);
    QCOMPARE(res.wired.authenticationProtocol, 2);   // PEAPv0/EAP-MSCHAPv2

    // Label helpers.
    QCOMPARE(wifiAuthMethodLabel(7), QStringLiteral("WPA2 802.1x"));
    QCOMPARE(wifiEncryptionLabel(4), QStringLiteral("CCMP-AES"));
    QCOMPARE(wifiPortStateLabel(32769),
             QStringLiteral("Enabled in S0, Sx/AC"));
    QCOMPARE(wifiRadioStateLabel(2), QStringLiteral("On, Connected"));
    QCOMPARE(eap8021xProtocolLabel(0), QStringLiteral("EAP-TLS"));
}

void TestWsmanClient::setHighAccuracyTimeSyncEncodesParamsAndDecodesReturn()
{
    // The Set call sends an Invoke envelope with Ta0/Tm1/Tm2 as POSTed
    // body params. Capture the body to verify each param round-trips
    // and assert ReturnValue==0 maps to ok=true.
    QByteArray captured;
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     captured = req.body();
                     constexpr const char *resp =
                         "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                         "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                         " xmlns:t=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_TimeSynchronizationService\">"
                         "<s:Header/><s:Body>"
                         "<t:SetHighAccuracyTimeSynch_OUTPUT>"
                         "<t:ReturnValue>0</t:ReturnValue>"
                         "</t:SetHighAccuracyTimeSynch_OUTPUT>"
                         "</s:Body></s:Envelope>";
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(resp));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    InvokeResult result;
    QEventLoop loop;
    setHighAccuracyTimeSync(&client, 1700000000LL, 1700000001LL, 1700000002LL,
        [&](InvokeResult r) { result = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.returnValue, 0);

    // The three params have to land on the wire — a typo in any of
    // them would silently push a wrong clock to the firmware.
    QVERIFY2(captured.contains("Ta0"), captured.constData());
    QVERIFY2(captured.contains("1700000000"), captured.constData());
    QVERIFY2(captured.contains("Tm1"), captured.constData());
    QVERIFY2(captured.contains("1700000001"), captured.constData());
    QVERIFY2(captured.contains("Tm2"), captured.constData());
    QVERIFY2(captured.contains("1700000002"), captured.constData());

    // AMT's XSD requires the three params in this exact order;
    // shuffling them yields SchemaValidationError.
    const int iTa0 = captured.indexOf("Ta0");
    const int iTm1 = captured.indexOf("Tm1");
    const int iTm2 = captured.indexOf("Tm2");
    QVERIFY2(iTa0 < iTm1 && iTm1 < iTm2,
             qPrintable(QStringLiteral("Ta0/Tm1/Tm2 out of order: %1/%2/%3")
                            .arg(iTa0).arg(iTm1).arg(iTm2)));
}

void TestWsmanClient::getPowerSchemesEnumeratesAndDetectsCurrentViaElementSettingData()
{
    // Two enumerates: AMT_SystemPowerScheme (the list of schemes) and
    // CIM_ElementSettingData (the association that flags one of them
    // IsCurrent). Switch on the resource URI in the SOAP body.
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isElementSettingData =
                         body.contains("CIM_ElementSettingData");
                     const bool isPull = body.contains(":Pull")
                                       || body.contains("<wsen:Pull");

                     QByteArray response;
                     if (!isPull) {
                         // Enumerate → return a context.
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
                             "<s:Header/><s:Body>"
                             "<wsen:EnumerateResponse>"
                             "<wsen:EnumerationContext>ctx</wsen:EnumerationContext>"
                             "</wsen:EnumerateResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isElementSettingData) {
                         // Pull on CIM_ElementSettingData. One row with
                         // IsCurrent=1 pointing at the "Balanced" scheme.
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
                             " xmlns:wsman=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\""
                             " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ElementSettingData\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:CIM_ElementSettingData>"
                             "<c:IsCurrent>1</c:IsCurrent>"
                             "<c:SettingData>"
                             "<wsa:Address>http://example.com/wsman</wsa:Address>"
                             "<wsa:ReferenceParameters>"
                             "<wsman:ResourceURI>http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SystemPowerScheme</wsman:ResourceURI>"
                             "<wsman:SelectorSet>"
                             "<wsman:Selector Name=\"CreationClassName\">AMT_SystemPowerScheme</wsman:Selector>"
                             "<wsman:Selector Name=\"InstanceID\">Intel(r) AMT:Power Scheme 1</wsman:Selector>"
                             "</wsman:SelectorSet>"
                             "</wsa:ReferenceParameters>"
                             "</c:SettingData>"
                             "</c:CIM_ElementSettingData>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     } else {
                         // Pull on AMT_SystemPowerScheme. Two rows.
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SystemPowerScheme\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:AMT_SystemPowerScheme>"
                             "<c:InstanceID>Intel(r) AMT:Power Scheme 0</c:InstanceID>"
                             "<c:SchemeGUID>{aaaaaaaa-bbbb-cccc-dddd-000000000000}</c:SchemeGUID>"
                             "<c:Description>0:Power Saver</c:Description>"
                             "</c:AMT_SystemPowerScheme>"
                             "<c:AMT_SystemPowerScheme>"
                             "<c:InstanceID>Intel(r) AMT:Power Scheme 1</c:InstanceID>"
                             "<c:SchemeGUID>{aaaaaaaa-bbbb-cccc-dddd-111111111111}</c:SchemeGUID>"
                             "<c:Description>1:Balanced</c:Description>"
                             "</c:AMT_SystemPowerScheme>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    PowerSchemesResult result;
    QEventLoop loop;
    getPowerSchemes(&client, [&](PowerSchemesResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.schemes.size(), 2);
    QCOMPARE(result.schemes.at(0).description, QStringLiteral("0:Power Saver"));
    QCOMPARE(result.schemes.at(1).description, QStringLiteral("1:Balanced"));

    // The EPR walk on CIM_ElementSettingData should have pulled the
    // matching InstanceID out of the second Selector and parked it as
    // currentInstanceId. The dialog uses this to preselect the radio.
    QCOMPARE(result.currentInstanceId,
             QStringLiteral("Intel(r) AMT:Power Scheme 1"));
}

void TestWsmanClient::getAgentPresenceDecodesBase64DeviceIdAndStateEnums()
{
    // The watchdog's DeviceID arrives as base64 of 16 raw GUID bytes.
    // For the test we use the GUID 00112233-4455-6677-8899-aabbccddeeff
    // which encodes as "ABEiM0RVZneImaq7zN3u/w==" in base64.
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isCaps = body.contains("AMT_AgentPresenceCapabilities");
                     const bool isWatchdog = body.contains("AMT_AgentPresenceWatchdog");
                     const bool isPull = body.contains(":Pull")
                                       || body.contains("<wsen:Pull");

                     QByteArray response;
                     if (isCaps) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AgentPresenceCapabilities\">"
                             "<s:Header/><s:Body>"
                             "<c:AMT_AgentPresenceCapabilities>"
                             "<c:MaxTotalAgents>4</c:MaxTotalAgents>"
                             "<c:MaxTotalActions>16</c:MaxTotalActions>"
                             "</c:AMT_AgentPresenceCapabilities>"
                             "</s:Body></s:Envelope>";
                     } else if (isWatchdog && !isPull) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
                             "<s:Header/><s:Body>"
                             "<wsen:EnumerateResponse>"
                             "<wsen:EnumerationContext>ctx</wsen:EnumerationContext>"
                             "</wsen:EnumerateResponse>"
                             "</s:Body></s:Envelope>";
                     } else {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_AgentPresenceWatchdog\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:AMT_AgentPresenceWatchdog>"
                             "<c:DeviceID>ABEiM0RVZneImaq7zN3u/w==</c:DeviceID>"
                             "<c:MonitoredEntityDescription>Endpoint AV</c:MonitoredEntityDescription>"
                             "<c:MonitoredEntity>7</c:MonitoredEntity>"
                             "<c:CurrentState>4</c:CurrentState>"
                             "<c:EnabledState>2</c:EnabledState>"
                             "<c:StartupInterval>3600</c:StartupInterval>"
                             "<c:TimeoutInterval>60</c:TimeoutInterval>"
                             "</c:AMT_AgentPresenceWatchdog>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    AgentPresenceResult result;
    QEventLoop loop;
    getAgentPresence(&client, [&](AgentPresenceResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.maxTotalAgents, 4);
    QCOMPARE(result.maxTotalActions, 16);
    QCOMPARE(result.watchdogs.size(), 1);

    const AgentPresenceWatchdog &w = result.watchdogs.first();
    // Standard 8-4-4-4-12 GUID with the byte stream we encoded.
    QCOMPARE(w.deviceIdGuid,
             QStringLiteral("00112233-4455-6677-8899-aabbccddeeff"));
    QCOMPARE(w.description, QStringLiteral("Endpoint AV"));
    QCOMPARE(w.monitoredEntityCode, 7);
    QCOMPARE(w.monitoredEntityLabel, QStringLiteral("Application"));
    QCOMPARE(w.currentStateCode, 4);
    QCOMPARE(w.currentStateLabel, QStringLiteral("Running"));
    QCOMPARE(w.enabledStateCode, 2);
    QCOMPARE(w.enabledStateLabel, QStringLiteral("Enabled"));
    QCOMPARE(w.startupIntervalSec, 3600);
    QCOMPARE(w.timeoutIntervalSec, 60);
}

void TestWsmanClient::getEventSubscriptionsJoinsFiltersListenersAndSubscriptions()
{
    // Three enumerates: filters, listeners, subscriptions. Route by
    // ResourceURI inside the POSTed envelope.
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isFilter = body.contains("CIM_FilterCollectionSubscription") == false
                                          && body.contains("CIM_FilterCollection");
                     const bool isListener = body.contains("CIM_ListenerDestination");
                     const bool isSubscription = body.contains("CIM_FilterCollectionSubscription");
                     const bool isPull = body.contains(":Pull")
                                       || body.contains("<wsen:Pull");

                     QByteArray response;
                     if (!isPull) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
                             "<s:Header/><s:Body>"
                             "<wsen:EnumerateResponse>"
                             "<wsen:EnumerationContext>ctx</wsen:EnumerationContext>"
                             "</wsen:EnumerateResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isSubscription) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
                             " xmlns:wsman=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\""
                             " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_FilterCollectionSubscription\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:CIM_FilterCollectionSubscription>"
                             "<c:Filter>"
                             "<wsa:Address>http://example/wsman</wsa:Address>"
                             "<wsa:ReferenceParameters>"
                             "<wsman:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_FilterCollection</wsman:ResourceURI>"
                             "<wsman:SelectorSet>"
                             "<wsman:Selector Name=\"InstanceID\">Intel(r) AMT:All Events</wsman:Selector>"
                             "</wsman:SelectorSet>"
                             "</wsa:ReferenceParameters>"
                             "</c:Filter>"
                             "<c:Handler>"
                             "<wsa:Address>http://example/wsman</wsa:Address>"
                             "<wsa:ReferenceParameters>"
                             "<wsman:ResourceURI>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ListenerDestinationWSManagement</wsman:ResourceURI>"
                             "<wsman:SelectorSet>"
                             "<wsman:Selector Name=\"CreationClassName\">CIM_ListenerDestinationWSMAN</wsman:Selector>"
                             "<wsman:Selector Name=\"Name\">Subscription 1</wsman:Selector>"
                             "</wsman:SelectorSet>"
                             "</wsa:ReferenceParameters>"
                             "</c:Handler>"
                             "</c:CIM_FilterCollectionSubscription>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isListener) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ListenerDestination\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:CIM_ListenerDestination>"
                             "<c:Name>Subscription 1</c:Name>"
                             "<c:Destination>https://siem.example.com/events</c:Destination>"
                             "<c:DeliveryMode>3</c:DeliveryMode>"
                             "</c:CIM_ListenerDestination>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isFilter) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_FilterCollection\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:CIM_FilterCollection>"
                             "<c:InstanceID>Intel(r) AMT:All Events</c:InstanceID>"
                             "<c:CollectionName>Intel(r) AMT:All Events</c:CollectionName>"
                             "</c:CIM_FilterCollection>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    EventSubscriptionsResult result;
    QEventLoop loop;
    getEventSubscriptions(&client, [&](EventSubscriptionsResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.filters.size(),       1);
    QCOMPARE(result.listeners.size(),     1);
    QCOMPARE(result.subscriptions.size(), 1);

    QCOMPARE(result.filters.first().instanceId,
             QStringLiteral("Intel(r) AMT:All Events"));
    QCOMPARE(result.listeners.first().destination,
             QStringLiteral("https://siem.example.com/events"));
    QCOMPARE(result.listeners.first().deliveryMode, 3);
    QCOMPARE(result.listeners.first().deliveryModeLabel,
             QStringLiteral("Push with ACK"));

    // The subscription's Filter / Handler EPRs land in named fields
    // so the QML can join filter → destination by name without doing
    // any EPR walking itself.
    QCOMPARE(result.subscriptions.first().filterInstanceId,
             QStringLiteral("Intel(r) AMT:All Events"));
    QCOMPARE(result.subscriptions.first().listenerName,
             QStringLiteral("Subscription 1"));
}

void TestWsmanClient::getWakeAlarmsExtractsNestedStartTimeAndInterval()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPull = body.contains(":Pull")
                                       || body.contains("<wsen:Pull");
                     QByteArray response;
                     if (!isPull) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
                             "<s:Header/><s:Body>"
                             "<wsen:EnumerateResponse>"
                             "<wsen:EnumerationContext>ctx</wsen:EnumerationContext>"
                             "</wsen:EnumerateResponse>"
                             "</s:Body></s:Envelope>";
                     } else {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:p=\"http://schemas.dmtf.org/wbem/wscim/1/common\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_AlarmClockOccurrence\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:IPS_AlarmClockOccurrence>"
                             "<c:InstanceID>Intel(r) AMT:Alarm 1</c:InstanceID>"
                             "<c:ElementName>Patch Tuesday Wake</c:ElementName>"
                             "<c:StartTime><p:Datetime>2026-06-09T03:00:00Z</p:Datetime></c:StartTime>"
                             "<c:Interval><p:Interval>P7DT0H0M</p:Interval></c:Interval>"
                             "<c:DeleteOnCompletion>false</c:DeleteOnCompletion>"
                             "</c:IPS_AlarmClockOccurrence>"
                             "<c:IPS_AlarmClockOccurrence>"
                             "<c:InstanceID>Intel(r) AMT:Alarm 2</c:InstanceID>"
                             "<c:ElementName>One-shot Imaging</c:ElementName>"
                             "<c:StartTime><p:Datetime>2026-05-20T22:30:00Z</p:Datetime></c:StartTime>"
                             "<c:DeleteOnCompletion>true</c:DeleteOnCompletion>"
                             "</c:IPS_AlarmClockOccurrence>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    WakeAlarmsResult result;
    QEventLoop loop;
    getWakeAlarms(&client, [&](WakeAlarmsResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.alarms.size(), 2);

    const WakeAlarm &a = result.alarms.first();
    QCOMPARE(a.instanceId,   QStringLiteral("Intel(r) AMT:Alarm 1"));
    QCOMPARE(a.elementName,  QStringLiteral("Patch Tuesday Wake"));
    QCOMPARE(a.startTimeIso, QStringLiteral("2026-06-09T03:00:00Z"));
    QCOMPARE(a.intervalIso,  QStringLiteral("P7DT0H0M"));
    QCOMPARE(a.deleteOnCompletion, false);

    const WakeAlarm &b = result.alarms.at(1);
    QCOMPARE(b.elementName,  QStringLiteral("One-shot Imaging"));
    QCOMPARE(b.startTimeIso, QStringLiteral("2026-05-20T22:30:00Z"));
    QVERIFY(b.intervalIso.isEmpty());
    QCOMPARE(b.deleteOnCompletion, true);
}

void TestWsmanClient::executeBrowsePrefixesClassNamesAndCarriesRawXml()
{
    // The browser's contract: (a) a bare class name gets the right base
    // URI prefix per the AMT_/IPS_/CIM_ convention, and (b) the raw
    // response body lands in the result so the operator can read it.
    QByteArray getRequestUri;
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     // Capture the ResourceURI off the first Get so we
                     // can assert the prefix logic.
                     const int s = body.indexOf("<w:ResourceURI>");
                     if (s >= 0 && getRequestUri.isEmpty()) {
                         const int e = body.indexOf("</w:ResourceURI>", s);
                         if (e > s)
                             getRequestUri = body.mid(s + 15, e - (s + 15));
                     }
                     constexpr const char *resp =
                         "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                         "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                         " xmlns:g=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings\">"
                         "<s:Header/><s:Body>"
                         "<g:AMT_GeneralSettings>"
                         "<g:HostName>test-host</g:HostName>"
                         "</g:AMT_GeneralSettings>"
                         "</s:Body></s:Envelope>";
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(resp));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    WsmanBrowseResult result;
    QEventLoop loop;
    executeBrowse(&client, QStringLiteral("AMT_GeneralSettings"),
                  BrowseKind::Get, {},
                  [&](WsmanBrowseResult r) { result = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.kind, BrowseKind::Get);
    // Prefix expansion: bare `AMT_*` → Intel AMT schema URI.
    QCOMPARE(getRequestUri,
             QByteArrayLiteral(
                 "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_GeneralSettings"));
    // The raw response body lands in `xml` for the operator to read.
    QVERIFY2(result.xml.contains("<g:HostName>test-host</g:HostName>"),
             result.xml.constData());
}

void TestWsmanClient::getSystemDefenseEnumeratesCoreFilterClasses()
{
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPolicy = body.contains("AMT_SystemDefensePolicy");
                     const bool isHdr    = body.contains("AMT_Hdr8021Filter");
                     const bool isIp     = body.contains("AMT_IPHeadersFilter");
                     const bool isPull = body.contains(":Pull")
                                       || body.contains("<wsen:Pull");

                     QByteArray response;
                     if (!isPull) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\">"
                             "<s:Header/><s:Body>"
                             "<wsen:EnumerateResponse>"
                             "<wsen:EnumerationContext>ctx</wsen:EnumerationContext>"
                             "</wsen:EnumerateResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isPolicy) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_SystemDefensePolicy\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:AMT_SystemDefensePolicy>"
                             "<c:InstanceID>Block-All</c:InstanceID>"
                             "<c:PolicyName>Block all inbound</c:PolicyName>"
                             "<c:Priority>10</c:Priority>"
                             "<c:DefaultPolicy>true</c:DefaultPolicy>"
                             "</c:AMT_SystemDefensePolicy>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isHdr) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_Hdr8021Filter\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:AMT_Hdr8021Filter>"
                             "<c:InstanceID>L2-IPv4</c:InstanceID>"
                             "<c:Name>Match-IPv4</c:Name>"
                             "<c:FilterDirection>1</c:FilterDirection>"
                             "<c:HdrProtocolID8021>2048</c:HdrProtocolID8021>"
                             "</c:AMT_Hdr8021Filter>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     } else if (isIp) {
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:wsen=\"http://schemas.xmlsoap.org/ws/2004/09/enumeration\""
                             " xmlns:c=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_IPHeadersFilter\">"
                             "<s:Header/><s:Body>"
                             "<wsen:PullResponse>"
                             "<wsen:Items>"
                             "<c:AMT_IPHeadersFilter>"
                             "<c:InstanceID>L3-DNS</c:InstanceID>"
                             "<c:Name>Allow-DNS</c:Name>"
                             "<c:FilterDirection>2</c:FilterDirection>"
                             "<c:HdrProtocolID8>17</c:HdrProtocolID8>"
                             "<c:HdrDestPortStart>53</c:HdrDestPortStart>"
                             "</c:AMT_IPHeadersFilter>"
                             "</wsen:Items>"
                             "<wsen:EndOfSequence/>"
                             "</wsen:PullResponse>"
                             "</s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    SystemDefenseResult result;
    QEventLoop loop;
    getSystemDefense(&client, [&](SystemDefenseResult r) {
        result = r;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QVERIFY(result.supported);
    QCOMPARE(result.policies.size(),   1);
    QCOMPARE(result.hdrFilters.size(), 1);
    QCOMPARE(result.ipFilters.size(),  1);

    QCOMPARE(result.policies.first().policyName,
             QStringLiteral("Block all inbound"));
    QCOMPARE(result.policies.first().defaultPolicy, true);

    QCOMPARE(result.hdrFilters.first().etherType, 2048);
    QCOMPARE(result.ipFilters.first().dstPort,    53);
    QCOMPARE(result.ipFilters.first().protocol,   17);
}

void TestWsmanClient::setKvmSettingsRoundTripsPartialPatch()
{
    // The Put must echo back the un-patched fields verbatim and apply
    // the patched fields. Capture the Put body and inspect it.
    QByteArray capturedPut;
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     const QByteArray body = req.body();
                     const bool isPut = body.contains("/transfer/Put");
                     QByteArray response;
                     if (!isPut) {
                         // Initial Get — return a representative record.
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                             " xmlns:k=\"http://intel.com/wbem/wscim/1/ips-schema/1/IPS_KVMRedirectionSettingData\">"
                             "<s:Header/><s:Body>"
                             "<k:IPS_KVMRedirectionSettingData>"
                             "<k:InstanceID>Intel(r) KVM Redirection Settings</k:InstanceID>"
                             "<k:EnabledByMEBx>true</k:EnabledByMEBx>"
                             "<k:Is5900PortEnabled>false</k:Is5900PortEnabled>"
                             "<k:OptInPolicy>false</k:OptInPolicy>"
                             "<k:OptInPolicyTimeout>120</k:OptInPolicyTimeout>"
                             "<k:SessionTimeout>0</k:SessionTimeout>"
                             "<k:DefaultScreen>0</k:DefaultScreen>"
                             "<k:GreyscalePixelFormatRequested>false</k:GreyscalePixelFormatRequested>"
                             "</k:IPS_KVMRedirectionSettingData>"
                             "</s:Body></s:Envelope>";
                     } else {
                         capturedPut = body;
                         response =
                             "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                             "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
                             "<s:Header/><s:Body></s:Body></s:Envelope>";
                     }
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                response);
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    KvmSettingsPatch patch;
    patch.setIs5900PortEnabled = true;     patch.is5900PortEnabled = true;
    patch.setSessionTimeoutMinutes = true; patch.sessionTimeoutMinutes = 10;
    patch.setRfbPassword = true;           patch.rfbPassword = QStringLiteral("hunter2!");
    // OptInPolicy + Greyscale stay untouched → should round-trip
    // from the Get response.

    InvokeResult result;
    QEventLoop loop;
    setKvmSettings(&client, patch,
        [&](InvokeResult r) { result = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));

    // Patched fields land on the wire with the new values. The Put
    // envelope namespaces the body elements via the `r:` prefix the
    // builder assigns to the resource URI.
    QVERIFY2(capturedPut.contains("Is5900PortEnabled>true"),
             capturedPut.constData());
    QVERIFY2(capturedPut.contains("SessionTimeout>10"),
             capturedPut.constData());
    QVERIFY2(capturedPut.contains("hunter2!"),
             capturedPut.constData());

    // Untouched fields preserved from the Get response.
    QVERIFY2(capturedPut.contains("OptInPolicy>false"),
             capturedPut.constData());
    QVERIFY2(capturedPut.contains("OptInPolicyTimeout>120"),
             capturedPut.constData());
}

void TestWsmanClient::setKvmRedirectionEnabledSendsCorrectRequestedState()
{
    QByteArray captured;
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     captured = req.body();
                     constexpr const char *resp =
                         "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                         "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                         " xmlns:k=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_KVMRedirectionSAP\">"
                         "<s:Header/><s:Body>"
                         "<k:RequestStateChange_OUTPUT>"
                         "<k:ReturnValue>0</k:ReturnValue>"
                         "</k:RequestStateChange_OUTPUT>"
                         "</s:Body></s:Envelope>";
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(resp));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    // Disable case — RequestedState 3.
    InvokeResult result;
    QEventLoop loop;
    setKvmRedirectionEnabled(&client, false,
        [&](InvokeResult r) { result = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QVERIFY2(captured.contains("RequestedState"), captured.constData());
    QVERIFY2(captured.contains(">3<"), captured.constData());

    captured.clear();
    QEventLoop loop2;
    setKvmRedirectionEnabled(&client, true,
        [&](InvokeResult r) { result = r; loop2.quit(); });
    QTimer::singleShot(5000, &loop2, &QEventLoop::quit);
    loop2.exec();

    QVERIFY(result.ok);
    QVERIFY2(captured.contains(">2<"), captured.constData());
}

void TestWsmanClient::buildExtendedDataRoundTripsBothPeriodicBranches()
{
    // Interval branch: type=0 + 4-byte seconds → 8 bytes total.
    const QString b64Interval = buildExtendedData(true, 300, 0, 0);
    const QByteArray rawInterval = QByteArray::fromBase64(b64Interval.toLatin1());
    QCOMPARE(rawInterval.size(), 8);
    // type 0
    QCOMPARE(quint8(rawInterval[0]), quint8(0));
    QCOMPARE(quint8(rawInterval[1]), quint8(0));
    QCOMPARE(quint8(rawInterval[2]), quint8(0));
    QCOMPARE(quint8(rawInterval[3]), quint8(0));
    // 300 = 0x0000012C
    QCOMPARE(quint8(rawInterval[4]), quint8(0x00));
    QCOMPARE(quint8(rawInterval[5]), quint8(0x00));
    QCOMPARE(quint8(rawInterval[6]), quint8(0x01));
    QCOMPARE(quint8(rawInterval[7]), quint8(0x2C));

    RemoteAccessPolicy decodedInterval;
    decodeExtendedData(b64Interval, decodedInterval);
    QVERIFY(decodedInterval.periodicInterval);
    QCOMPARE(decodedInterval.periodicSeconds, 300);
    QVERIFY(!decodedInterval.periodicTimeOfDay);

    // Time-of-day branch: type=1 + 4-byte hour + 4-byte minute → 12 bytes.
    const QString b64Tod = buildExtendedData(false, 0, 14, 30);
    const QByteArray rawTod = QByteArray::fromBase64(b64Tod.toLatin1());
    QCOMPARE(rawTod.size(), 12);
    // type 1
    QCOMPARE(quint8(rawTod[3]), quint8(1));
    // hour 14
    QCOMPARE(quint8(rawTod[7]), quint8(14));
    // minute 30
    QCOMPARE(quint8(rawTod[11]), quint8(30));

    RemoteAccessPolicy decodedTod;
    decodeExtendedData(b64Tod, decodedTod);
    QVERIFY(!decodedTod.periodicInterval);
    QVERIFY(decodedTod.periodicTimeOfDay);
    QCOMPARE(decodedTod.periodicHour, 14);
    QCOMPARE(decodedTod.periodicMinute, 30);
}

void TestWsmanClient::addRemoteAccessPolicyRuleEncodesPeriodicEnvelope()
{
    // Capture the POST body to verify the hand-rolled envelope carries
    // every load-bearing field: Trigger, TunnelLifeTime, ExtendedData
    // (base64), a <MpServer> EPR for each CIRA name, and an
    // <InternalMpServer> EPR for each CILA name.
    QByteArray captured;
    QHttpServer server;
    server.route(QStringLiteral("/wsman"), QHttpServerRequest::Method::Post,
                 [&](const QHttpServerRequest &req) {
                     captured = req.body();
                     constexpr const char *resp =
                         "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                         "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                         " xmlns:r=\"http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RemoteAccessService\">"
                         "<s:Header/><s:Body>"
                         "<r:AddRemoteAccessPolicyRule_OUTPUT>"
                         "<r:ReturnValue>0</r:ReturnValue>"
                         "</r:AddRemoteAccessPolicyRule_OUTPUT>"
                         "</s:Body></s:Envelope>";
                     return QHttpServerResponse(QByteArrayLiteral("application/soap+xml"),
                                                QByteArray(resp));
                 });

    auto tcp = std::make_unique<QTcpServer>();
    QVERIFY(tcp->listen(QHostAddress::LocalHost));
    const quint16 port = tcp->serverPort();
    QVERIFY(server.bind(tcp.get()));
    tcp.release();

    WsmanClient client;
    client.setEndpoint(endpointFor(port));

    CiraPolicyInput in;
    in.trigger = 2;                 // Periodic
    in.tunnelLifeTime = 1200;
    in.periodicInterval = true;
    in.periodicSeconds = 300;
    in.ciraMpsNames << QStringLiteral("MpsExternal1");
    in.cilaMpsNames << QStringLiteral("MpsInternal1");

    InvokeResult result;
    QEventLoop loop;
    addRemoteAccessPolicyRule(&client, in,
        [&](InvokeResult r) { result = r; loop.quit(); });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(result.returnValue, 0);

    // SOAPAction header has to target AddRemoteAccessPolicyRule —
    // the action URI lives in the body's WS-Addressing <Action>.
    QVERIFY2(captured.contains("AddRemoteAccessPolicyRule"), captured.constData());

    // Trigger=2 must land on the wire.
    QVERIFY2(captured.contains("<r:Trigger>2</r:Trigger>"),
             captured.constData());
    // TunnelLifeTime
    QVERIFY2(captured.contains("<r:TunnelLifeTime>1200</r:TunnelLifeTime>"),
             captured.constData());
    // ExtendedData must be base64 of 8 bytes: 00 00 00 00 00 00 01 2C.
    // QByteArray::toBase64 emits "AAAAAAAAASw=" for that sequence.
    QVERIFY2(captured.contains("<r:ExtendedData>AAAAAAAAASw=</r:ExtendedData>"),
             captured.constData());

    // CIRA bucket → <MpServer> with the SAP resource URI + Name selector.
    QVERIFY2(captured.contains("<r:MpServer>"), captured.constData());
    QVERIFY2(captured.contains("AMT_ManagementPresenceRemoteSAP"),
             captured.constData());
    QVERIFY2(captured.contains(">MpsExternal1<"), captured.constData());
    // CILA bucket → <InternalMpServer>.
    QVERIFY2(captured.contains("<r:InternalMpServer>"),
             captured.constData());
    QVERIFY2(captured.contains(">MpsInternal1<"), captured.constData());

    // XSD requires Trigger → TunnelLifeTime → ExtendedData → MpServer
    // → InternalMpServer in this order; shuffling fails server-side.
    const int iTrigger      = captured.indexOf("<r:Trigger>");
    const int iTunnel       = captured.indexOf("<r:TunnelLifeTime>");
    const int iExt          = captured.indexOf("<r:ExtendedData>");
    const int iMpServer     = captured.indexOf("<r:MpServer>");
    const int iInternalMps  = captured.indexOf("<r:InternalMpServer>");
    QVERIFY2(iTrigger < iTunnel && iTunnel < iExt
              && iExt < iMpServer && iMpServer < iInternalMps,
             qPrintable(QStringLiteral(
                 "Body element order wrong: %1/%2/%3/%4/%5")
                 .arg(iTrigger).arg(iTunnel).arg(iExt)
                 .arg(iMpServer).arg(iInternalMps)));
}

// --- #435: digest 401 retry is bounded, and every path is timed ------

namespace {

/// Raw TCP endpoint that speaks just enough HTTP to exercise the
/// Digest dance. Counts connections so a test can prove the client
/// stopped retrying rather than merely that it eventually gave up.
class DigestFake : public QObject
{
    Q_OBJECT
public:
    /// Number of 401s to issue before switching to `finalBody`. Set
    /// huge to model a device that will never accept the credentials.
    int challengesToIssue = 999;
    /// Mark the Nth challenge (1-based) `stale=true`.
    int staleOnChallenge = -1;
    /// When true, accept the connection and never write a byte —
    /// models a wedged ME. Applied once `challengesToIssue` is spent.
    bool goSilentWhenDone = false;
    QByteArray finalBody;

    int connections = 0;      ///< TCP connections accepted.
    int challengesSent = 0;

    bool listen()
    {
        connect(&m_server, &QTcpServer::newConnection, this, &DigestFake::onConnection);
        return m_server.listen(QHostAddress::LocalHost);
    }
    [[nodiscard]] quint16 port() const { return m_server.serverPort(); }

    ~DigestFake() override
    {
        // Members unwind in reverse declaration order, so `m_buf` is
        // gone by the time `m_server` tears down its child sockets —
        // and their `disconnected` handler reaches straight back into
        // it. Drop the handlers first. Only bites when a socket is
        // still open at teardown, which `goSilentWhenDone` guarantees.
        m_server.close();
        const auto socks = m_buf.keys();
        for (QTcpSocket *sock : socks) sock->disconnect(this);
        m_buf.clear();
    }

private slots:
    void onConnection()
    {
        while (QTcpSocket *sock = m_server.nextPendingConnection()) {
            ++connections;
            connect(sock, &QTcpSocket::readyRead, this, [this, sock]() {
                m_buf[sock].append(sock->readAll());
                serve(sock);
            });
            connect(sock, &QTcpSocket::disconnected, this, [this, sock]() {
                m_buf.remove(sock);
                sock->deleteLater();
            });
        }
    }

private:
    void serve(QTcpSocket *sock)
    {
        QByteArray &buf = m_buf[sock];
        const int headerEnd = buf.indexOf("\r\n\r\n");
        if (headerEnd < 0) return;
        int contentLength = 0;
        for (const QByteArray &line : buf.left(headerEnd).split('\n')) {
            const QByteArray l = line.trimmed().toLower();
            if (l.startsWith("content-length:"))
                contentLength = l.mid(15).trimmed().toInt();
        }
        if (buf.size() < headerEnd + 4 + contentLength) return;
        buf.remove(0, headerEnd + 4 + contentLength);

        if (challengesSent < challengesToIssue) {
            ++challengesSent;
            QByteArray chal = "HTTP/1.1 401 Unauthorized\r\n";
            chal += "WWW-Authenticate: Digest realm=\"Digest:AB\", "
                    "nonce=\"deadbeef\", qop=\"auth\"";
            if (challengesSent == staleOnChallenge) chal += ", stale=true";
            chal += "\r\n";
            chal += "Content-Length: 0\r\n";
            chal += "Connection: close\r\n\r\n";
            sock->write(chal);
            sock->flush();
            sock->disconnectFromHost();
            return;
        }

        if (goSilentWhenDone) return;   // accepted, never answered

        QByteArray out = "HTTP/1.1 200 OK\r\n";
        out += "Content-Type: application/soap+xml\r\n";
        out += "Content-Length: " + QByteArray::number(finalBody.size()) + "\r\n";
        out += "Connection: close\r\n\r\n";
        out += finalBody;
        sock->write(out);
        sock->flush();
        sock->disconnectFromHost();
    }

    QTcpServer m_server;
    QHash<QTcpSocket *, QByteArray> m_buf;
};

} // namespace

void TestWsmanClient::digestRetryIsCappedOnPersistent401()
{
    // A device that will never accept these credentials. Before #435
    // this looped connect -> 401 -> connect indefinitely, one fresh TCP
    // connection per bounce, bounded only by the transfer timeout.
    DigestFake fake;
    fake.challengesToIssue = 999;
    QVERIFY(fake.listen());

    WsmanClient client;
    client.setEndpoint(endpointFor(fake.port()));
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("wrong"));
    client.setTransferTimeoutMs(10000);   // must NOT be what stops us

    IdentifyResult result;
    QEventLoop loop;
    identify(&client, [&](IdentifyResult r) { result = r; loop.quit(); });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(!result.ok, "a permanently-rejected credential must not report success");
    QVERIFY2(!result.error.isEmpty(), "the failure must carry a reason");
    QVERIFY2(!result.error.contains(QStringLiteral("timed out")),
              qPrintable(QStringLiteral("gave up via the timeout rather than the "
                                        "retry cap: %1").arg(result.error)));
    // One unauthed attempt + exactly one retry.
    QCOMPARE(fake.connections, 2);
    QCOMPARE(fake.challengesSent, 2);
}

void TestWsmanClient::staleNonceAllowsOneExtraRetry()
{
    // A stale nonce invalidates an attempt through no fault of the
    // credentials, so it earns one more try — but only one.
    DigestFake fake;
    fake.challengesToIssue = 2;
    fake.staleOnChallenge = 2;
    fake.finalBody = QByteArray(kIdentifyResponse);
    QVERIFY(fake.listen());

    WsmanClient client;
    client.setEndpoint(endpointFor(fake.port()));
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));
    client.setTransferTimeoutMs(10000);

    IdentifyResult result;
    QEventLoop loop;
    identify(&client, [&](IdentifyResult r) { result = r; loop.quit(); });
    QTimer::singleShot(8000, &loop, &QEventLoop::quit);
    loop.exec();

    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(fake.connections, 3);   // unauthed + retry + stale retry
}

void TestWsmanClient::cachedChallengePathIsStillTimedOut()
{
    // The subtle half of #435. `sendEnvelope`'s `startNow` skips
    // `startTransport` once a challenge is cached and calls
    // `retryWithDigest` directly — which used to be the only place the
    // timeout was NOT armed. A device that then went quiet left the
    // reply hanging forever: no `finished()`, so a controller's
    // `decInflight()` never ran and the UI stayed "busy" permanently.
    DigestFake fake;
    fake.challengesToIssue = 1;
    fake.finalBody = QByteArray(kIdentifyResponse);
    QVERIFY(fake.listen());

    WsmanClient client;
    client.setEndpoint(endpointFor(fake.port()));
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));
    client.setTransferTimeoutMs(1500);

    // Request 1 completes the 401 dance, leaving a cached challenge.
    {
        IdentifyResult first;
        QEventLoop loop;
        identify(&client, [&](IdentifyResult r) { first = r; loop.quit(); });
        QTimer::singleShot(8000, &loop, &QEventLoop::quit);
        loop.exec();
        QVERIFY2(first.ok, qPrintable(first.error));
    }

    // Request 2 therefore starts pre-authed. Now the device goes quiet.
    fake.goSilentWhenDone = true;

    bool callbackRan = false;
    IdentifyResult second;
    QEventLoop loop2;
    identify(&client, [&](IdentifyResult r) {
        callbackRan = true;
        second = r;
        loop2.quit();
    });
    // Generous relative to the 1.5s transfer timeout: if the timeout is
    // armed the callback lands quickly; if it isn't, this expires and
    // callbackRan stays false.
    QTimer::singleShot(8000, &loop2, &QEventLoop::quit);
    loop2.exec();

    QVERIFY2(callbackRan,
              "the pre-authed request never completed — no timeout was armed on "
              "the cached-challenge path, so the caller waits forever");
    QVERIFY(!second.ok);
    QVERIFY2(second.error.contains(QStringLiteral("timed out")),
              qPrintable(second.error));
}


// A failure inside sendEnvelope happens before the caller can connect to
// finished(). Losing it left controllers busy with their callback unrun.
void TestWsmanClient::synchronousSocketFailureReachesFinished()
{
    WsmanClient client;
    client.setEndpoint(QUrl(QStringLiteral("http://127.0.0.1:16992/wsman")));
    client.setCredentials(QStringLiteral("admin"), QStringLiteral("p"));
    client.setSocketFactory([](WsmanClient::SocketCallback done) {
        done(-1, QStringLiteral("no route to host"));
    });

    WsmanReply *reply = client.sendEnvelope(QByteArrayLiteral("<x/>"));
    QSignalSpy finishedSpy(reply, &WsmanReply::finished);
    QVERIFY(finishedSpy.wait(2000));
    QVERIFY(reply->hasError());
    QCOMPARE(finishedSpy.size(), 1);
    reply->deleteLater();
}

QTEST_GUILESS_MAIN(TestWsmanClient)
#include "test_wsman_client.moc"
