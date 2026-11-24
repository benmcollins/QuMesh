// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import QuMesh

/// Modal that asks the operator for the 6-digit consent code AMT is
/// displaying on the target's local screen. Drive it via `openFor()`;
/// resolves into `submitted(code)` or `cancelled`.
///
/// `cancelled` comes from `onRejected` alone, so Cancel, Escape and the
/// countdown each report it exactly once (#461). Callers dismiss the
/// dialog with `close()` once consent resolves, which stays silent: a
/// stray cancel there would revoke a consent the firmware just granted.
Dialog {
    id: root

    /// Optional error string from a previous \`sendOptInCode\` attempt
    /// (wrong code, expired, etc.). Shown in red under the field.
    property string errorText: ""

    /// Seconds the firmware will wait for the operator to enter the
    /// consent code (from `IPS_KVMRedirectionSettingData.OptInPolicyTimeout`).
    /// 0 hides the countdown. Set via `openFor(timeout)`.
    property int timeoutSec: 0
    property int secondsRemaining: 0

    signal submitted(int code)
    signal cancelled

    objectName: "optInPrompt"
    title: qsTr("Enter consent code")
    modal: true
    closePolicy: Popup.CloseOnEscape
    anchors.centerIn: parent
    standardButtons: Dialog.NoButton
    implicitWidth: 480

    onClosed: countdownTimer.stop()
    onRejected: root.cancelled()

    Timer {
        id: countdownTimer
        interval: 1000
        repeat: true
        onTriggered: {
            if (root.secondsRemaining <= 0) {
                stop();
                root.reject();
                return;
            }
            root.secondsRemaining -= 1;
        }
    }

    function openFor(timeout) {
        root.errorText = "";
        codeField.text = "";
        root.timeoutSec = timeout || 0;
        root.secondsRemaining = root.timeoutSec;
        // 0 means the firmware set no limit; there is nothing to count.
        if (root.timeoutSec > 0) countdownTimer.start();
        else countdownTimer.stop();
        root.open();
        codeField.forceActiveFocus();
    }

    /// The firmware rejected the code but the consent round is still
    /// live. Keep the modal and its countdown exactly as they are —
    /// calling `openFor()` again would wipe `errorText` on entry and
    /// hand the operator a full fresh timeout the firmware isn't
    /// honouring.
    function reprompt(error) {
        root.errorText = error;
        codeField.text = "";
        if (!root.opened) root.open();
        codeField.forceActiveFocus();
    }

    contentItem: ColumnLayout {
        spacing: 12

        Text {
            text: qsTr("AMT is displaying a 6-digit consent code on the remote machine's local screen. Read it from the target and enter it here to unlock the session.")
            color: Colors.text
            font.family: Type.sans
            font.pixelSize: Type.sizeS
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        TextField {
            id: codeField
            placeholderText: qsTr("123456")
            inputMethodHints: Qt.ImhDigitsOnly
            validator: IntValidator { bottom: 0; top: 999999 }
            maximumLength: 6
            font.family: Type.mono
            font.pixelSize: Type.sizeL
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
            Layout.preferredHeight: 48
            Keys.onReturnPressed: if (codeField.text.length === 6) submitBtn.clicked()
        }

        Text {
            visible: root.timeoutSec > 0
            text: qsTr("Time remaining: %1s").arg(root.secondsRemaining)
            color: root.secondsRemaining <= 10 ? Colors.error : Colors.textMuted
            font.family: Type.mono
            font.pixelSize: Type.sizeXs
            horizontalAlignment: Text.AlignHCenter
            Layout.fillWidth: true
        }

        Text {
            visible: root.errorText.length > 0
            text: root.errorText
            color: Colors.error
            font.family: Type.sans
            font.pixelSize: Type.sizeXs
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        RowLayout {
            spacing: 8
            Layout.fillWidth: true

            Item { Layout.fillWidth: true }

            FlatButton {
                text: qsTr("Cancel")
                font.family: Type.sans
                font.pixelSize: Type.sizeS
                onClicked: root.reject()
            }

            AccentButton {
                id: submitBtn
                text: qsTr("Submit")
                font.family: Type.sans
                font.pixelSize: Type.sizeS
                enabled: codeField.text.length === 6
                onClicked: {
                    root.submitted(parseInt(codeField.text));
                    // Don't close yet — the controller may report a wrong
                    // code and the caller will call `openFor()` again with
                    // an updated `errorText` to re-prompt.
                }
            }
        }
    }
}
