// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

pragma ComponentBehavior: Bound

import QtCore
import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Dialogs
import QtQuick.Layouts
import QuMesh

/// Embeddable KVM viewer pane. Owns its own `KvmController`; the
/// containing window drives connect/disconnect through `start()` /
/// `stop()`. Used by `SessionWindow.qml` as one of its tabs.
Item {
    id: root

    property string targetHost
    property string machineName
    property string user
    property string password
    property bool tls: false
    property var trustedFingerprints: []
    property var sshConfig: ({})

    // The prefix the save dialogs default the filename to. Prefer the
    // user-given machine name; fall back to the host so a freshly-added
    // unnamed machine still gets a usable suggestion.
    readonly property string saveNamePrefix:
        machineName.length > 0 ? machineName : targetHost

    signal trustedFingerprintPersistRequested(string fingerprint)
    signal trustedSshHostKeyPersistRequested(string fingerprint)
    signal peerCertVerifiedByPin(string fingerprint)
    /// The operator asked to connect. The host decides *when* that may
    /// happen — on a consent-gated machine the redirection socket must
    /// not be opened until AMT has accepted the code (#433).
    signal connectRequested()

    onSshConfigChanged: controller.setSshConfig(root.sshConfig || ({}))

    function start() {
        controller.host = root.targetHost;
        controller.user = root.user;
        controller.password = root.password;
        controller.tls = root.tls;
        controller.trustedFingerprints = root.trustedFingerprints;
        controller.open();
    }
    function stop() { controller.close() }

    function focusViewer() { viewer.forceActiveFocus() }

    // X11 keysyms used by the Send-keys menu.
    readonly property int kXkLAlt: 0xFFE9
    readonly property int kXkLCtrl: 0xFFE3
    readonly property int kXkLMeta: 0xFFE7
    readonly property int kXkLShift: 0xFFE1
    readonly property int kXkEscape: 0xFF1B
    readonly property int kXkTab: 0xFF09
    readonly property int kXkF1Base: 0xFFBE

    function chord(keys) {
        for (let i = 0; i < keys.length; ++i)
            controller.sendKey(keys[i], true);
        for (let i = keys.length - 1; i >= 0; --i)
            controller.sendKey(keys[i], false);
    }

    onVisibleChanged: if (visible) viewer.forceActiveFocus()
    Component.onCompleted: if (visible) viewer.forceActiveFocus()

    KvmController {
        id: controller
        Component.onCompleted: controller.setSshConfig(root.sshConfig || ({}))
        onTrustedFingerprintAdded: function(fp) {
            root.trustedFingerprintPersistRequested(fp);
        }
        onTrustedSshHostKeyAdded: function(fp) {
            root.trustedSshHostKeyPersistRequested(fp);
        }
        onPeerCertVerifiedByPin: function(fp) { root.peerCertVerifiedByPin(fp) }
        onStateChanged: {
            if (state === KvmController.Connected) ActivityHeartbeat.reportSuccess();
            else if (state === KvmController.Failed)
                ActivityHeartbeat.reportFailure(qsTr("KVM: %1").arg(lastError));
        }
    }

    CertTrustDialog {
        controller: controller
    }

    /// SSH host-key prompt for the per-tab tunnel (#270).
    SshHostKeyTrustDialog {
        controller: controller
        onCancelled: controller.setSshConfig({})
    }

    // Open the save dialogs with a sensible default name pre-populated:
    //   "<machine> YYYY-MM-DD at H.MM.SS [AP]M.<ext>"
    // The folder defaults to the user's Documents directory; the dialog
    // remembers wherever the user navigates to afterwards.
    function openScreenshotDialog() {
        screenshotDialog.currentFolder =
            StandardPaths.writableLocation(StandardPaths.DocumentsLocation);
        screenshotDialog.selectedFile = screenshotDialog.currentFolder + "/"
            + FilenameFormatter.defaultName(root.saveNamePrefix, "png");
        screenshotDialog.open();
    }
    function openRecordDialog() {
        recordDialog.currentFolder =
            StandardPaths.writableLocation(StandardPaths.DocumentsLocation);
        recordDialog.selectedFile = recordDialog.currentFolder + "/"
            + FilenameFormatter.defaultName(root.saveNamePrefix, "mov");
        recordDialog.open();
    }

    FileDialog {
        id: screenshotDialog
        fileMode: FileDialog.SaveFile
        defaultSuffix: "png"
        nameFilters: [qsTr("PNG images (*.png)"), qsTr("All files (*)")]
        title: qsTr("Save KVM screenshot")
        onAccepted: {
            const path = Paths.urlToLocalFile(screenshotDialog.selectedFile);
            if (path.length > 0) controller.saveScreenshot(path);
        }
    }

    FileDialog {
        id: recordDialog
        fileMode: FileDialog.SaveFile
        defaultSuffix: "mov"
        nameFilters: [qsTr("QuickTime movie (*.mov)"), qsTr("All files (*)")]
        title: qsTr("Record KVM session to MOV")
        onAccepted: {
            const path = Paths.urlToLocalFile(recordDialog.selectedFile);
            if (path.length > 0) controller.startRecording(path);
        }
    }

    // Wall-clock seconds since the active recording started. Driven by
    // a 1 Hz tick rather than the recorder's frame timer so the chip
    // updates smoothly even when no frames are being captured.
    QtObject {
        id: recState
        property int elapsedSec: 0
    }
    Timer {
        running: controller.recording
        interval: 1000
        repeat: true
        onTriggered: recState.elapsedSec += 1
        onRunningChanged: if (!running) recState.elapsedSec = 0
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 8
        spacing: 8

        RowLayout {
            spacing: 8
            Layout.fillWidth: true

            Rectangle {
                implicitWidth: 10
                implicitHeight: 10
                radius: 5
                color: controller.state === KvmController.Connected ? Colors.on
                     : controller.state === KvmController.Failed ? Colors.error
                     : controller.state === KvmController.Disconnected ? Colors.off
                     : Colors.standby
            }

            Text {
                text: {
                    switch (controller.state) {
                    case KvmController.Disconnected:   return qsTr("Disconnected");
                    case KvmController.Connecting:     return qsTr("Connecting…");
                    case KvmController.Authenticating: return qsTr("Authenticating…");
                    case KvmController.Negotiating:    return qsTr("Negotiating display…");
                    case KvmController.Connected: {
                        const size = controller.eightBitColor
                            ? qsTr("%1×%2 · 8-bit")
                                .arg(controller.desktopWidth)
                                .arg(controller.desktopHeight)
                            : qsTr("%1×%2")
                                .arg(controller.desktopWidth)
                                .arg(controller.desktopHeight);
                        return controller.colorDepthPending
                            ? qsTr("%1 · reconnect to apply colour").arg(size)
                            : size;
                    }
                    case KvmController.Failed:         return qsTr("Failed: %1").arg(controller.lastError);
                    }
                    return "";
                }
                color: controller.state === KvmController.Failed ? Colors.error : Colors.textMuted
                font.family: Type.sans
                font.pixelSize: Type.sizeS
                font.features: ({ "tnum": 1 })
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.minimumWidth: 48
                ToolTip.visible: truncated && statusHover.hovered
                ToolTip.text: text

                HoverHandler { id: statusHover }
            }

            Button {
                text: qsTr("Save screenshot")
                font.family: Type.sans
                font.pixelSize: Type.sizeXs
                enabled: controller.state === KvmController.Connected
                onClicked: root.openScreenshotDialog()
            }

            // Pulsing red dot + elapsed time, shown only during recording.
            Rectangle {
                visible: controller.recording
                implicitWidth: 8
                implicitHeight: 8
                radius: 4
                color: Colors.error
                SequentialAnimation on opacity {
                    running: controller.recording
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 0.25; duration: 600 }
                    NumberAnimation { from: 0.25; to: 1.0; duration: 600 }
                }
            }
            Text {
                visible: controller.recording
                text: {
                    const s = recState.elapsedSec;
                    const m = Math.floor(s / 60);
                    return qsTr("REC %1:%2").arg(m).arg(String(s % 60).padStart(2, "0"));
                }
                color: Colors.error
                font.family: Type.mono
                font.pixelSize: Type.sizeXs
                font.features: ({ "tnum": 1 })
            }

            Button {
                text: controller.recording ? qsTr("Stop recording")
                                            : qsTr("Record video")
                font.family: Type.sans
                font.pixelSize: Type.sizeXs
                enabled: controller.state === KvmController.Connected
                onClicked: {
                    if (controller.recording) controller.stopRecording();
                    else                       root.openRecordDialog();
                }
            }

            Button {
                text: qsTr("Send keys ▾")
                font.family: Type.sans
                font.pixelSize: Type.sizeXs
                enabled: controller.state === KvmController.Connected
                onClicked: sendMenu.popup()

                Menu {
                    id: sendMenu
                    MenuItem {
                        text: qsTr("Ctrl+Alt+Del")
                        onTriggered: controller.sendCtrlAltDel()
                    }
                    MenuSeparator {}
                    MenuItem {
                        text: qsTr("Alt+Tab")
                        onTriggered: root.chord([root.kXkLAlt, root.kXkTab])
                    }
                    MenuItem {
                        text: qsTr("Alt+F4")
                        onTriggered: root.chord([root.kXkLAlt, root.kXkF1Base + 3])
                    }
                    MenuItem {
                        text: qsTr("Esc")
                        onTriggered: controller.sendKeyTap(root.kXkEscape)
                    }
                    MenuSeparator {}
                    MenuItem {
                        text: qsTr("Win key")
                        onTriggered: controller.sendKeyTap(root.kXkLMeta)
                    }
                    MenuItem {
                        text: qsTr("Win+L (lock)")
                        onTriggered: root.chord([root.kXkLMeta, 0x6C])
                    }
                    MenuItem {
                        text: qsTr("Win+R (run)")
                        onTriggered: root.chord([root.kXkLMeta, 0x72])
                    }
                    MenuItem {
                        text: qsTr("Win+E (explorer)")
                        onTriggered: root.chord([root.kXkLMeta, 0x65])
                    }
                    MenuItem {
                        text: qsTr("Win+D (desktop)")
                        onTriggered: root.chord([root.kXkLMeta, 0x64])
                    }
                    MenuSeparator {}
                    Menu {
                        title: qsTr("Function keys")
                        Repeater {
                            model: 12
                            delegate: MenuItem {
                                required property int index
                                text: qsTr("F%1").arg(index + 1)
                                onTriggered: controller.sendKeyTap(root.kXkF1Base + index)
                            }
                        }
                    }
                }
            }

            Button {
                text: qsTr("Colour ▾")
                font.family: Type.sans
                font.pixelSize: Type.sizeS
                ToolTip.visible: hovered
                ToolTip.text: qsTr("Intel AMT's KVM display buffer is limited. "
                                   + "Desktops above roughly 2560×1600 must use "
                                   + "8-bit colour; Auto picks for you. "
                                   + "Changes apply when you reconnect in this window.")
                onClicked: depthMenu.popup()

                Menu {
                    id: depthMenu
                    MenuItem {
                        text: controller.colorDepthMode === 0
                            ? qsTr("● Auto") : qsTr("Auto")
                        onTriggered: controller.colorDepthMode = 0
                    }
                    MenuItem {
                        text: controller.colorDepthMode === 1
                            ? qsTr("● 16-bit colour") : qsTr("16-bit colour")
                        onTriggered: controller.colorDepthMode = 1
                    }
                    MenuItem {
                        text: controller.colorDepthMode === 2
                            ? qsTr("● 8-bit colour") : qsTr("8-bit colour")
                        onTriggered: controller.colorDepthMode = 2
                    }
                }
            }

            Button {
                text: controller.state === KvmController.Disconnected
                      || controller.state === KvmController.Failed
                    ? qsTr("Connect") : qsTr("Disconnect")
                font.family: Type.sans
                font.pixelSize: Type.sizeS
                onClicked: {
                    if (controller.state === KvmController.Disconnected
                        || controller.state === KvmController.Failed) {
                        root.connectRequested();
                    } else {
                        controller.close();
                    }
                }
            }
        }

        KvmViewer {
            id: viewer
            controller: controller
            focus: true
            Layout.fillWidth: true
            Layout.fillHeight: true
        }
    }
}
