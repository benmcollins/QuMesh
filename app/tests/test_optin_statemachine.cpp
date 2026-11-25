// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Ben Collins <ben@ironrocketsmc.org>

// Regression tests for the AMT user-consent (OptIn) state machine, #433.
//
// The bug: `SendOptInCode` moves the firmware to RECEIVED(3), and only
// a running redirection session takes it to IN_SESSION(4). Code that
// tested `OptInState != 4` therefore concluded consent was still
// needed the instant it was granted, re-issued `StartOptIn`, revoked
// the consent the operator had just entered, and dropped the KVM
// session they were in the middle of opening. Worse, `StartOptIn` →
// `refreshOptInStatus` → `optInStatusChanged` → `StartOptIn` closed a
// loop with no attempt cap, which hammered the ME until it stopped
// answering anything at all.
//
// These tests drive MachineDetailsController against a scripted HTTP
// endpoint that speaks just enough WS-Management to exercise the
// sequence.

#include "fake_amt.h"
#include "machinedetailscontroller.h"

#include <QtTest>

using qumesh::app::MachineDetailsController;

using qumesh::testing::FakeAmt;
using qumesh::testing::settle;
using qumesh::testing::waitFor;

namespace {

/// Point a controller at the fake endpoint.
void aim(MachineDetailsController &c, const FakeAmt &amt)
{
    c.setHost(QStringLiteral("127.0.0.1"));
    c.setUser(QStringLiteral("admin"));
    c.setPassword(QStringLiteral("p"));
    c.setTls(false);
    c.setPortForTest(amt.port());
}

} // namespace

class TestOptInStateMachine : public QObject
{
    Q_OBJECT
private slots:
    void grantedConsentIsNotReRequested();
    void receivedStateCountsAsSatisfied();
    void startOptInIsNotReentrantWhileRoundIsLive();
    void repeatedStartFailuresGiveUpInsteadOfLooping();
    void rejectedCodeKeepsRoundOpen();
    void unreadableStatusResolvesToNotRequired();
    void laterFailedReadIsReported();
    // A status read that predates a consent operation must not undo it.
    void staleReadDoesNotUndoGrantedConsent();
    void staleReadDoesNotRestoreCancelledConsent();
    void staleReadDoesNotEndNewRound();
    void requestedStateIsNotAnExpiry();
    void failedCancelRereadsFirmware();
    void acceptedCodeSurvivesFailedCancel();
    void readSpanningCancelAndStartDoesNotGrant();
    void lateRejectionAfterGrantStaysSilent();
    void requestedAfterLocalDisplayedIsNotExpiry();
    void displayedFromEarlierRoundDoesNotCarryOver();
    void displayedReadFromEndedRoundDoesNotCount();
    void refusedCancelRereadsAreCapped();
    void readLandingBeforeCancelReplyIsIgnored();
    void readLandingAfterCancelReplyIsIgnored();
    void staleReadDoesNotGrantNewRound();
    void lateAcceptedCodeAfterCancelRereads();
    void refusedCancelNeverExposesNotStarted();
    void lostCodeReplyIsGrantedByPoll();
    void overlappedDisplayedReadStillDetectsExpiry();
    void supersededCancelRereadsFirmware();
    void cancelLandingAfterStartEndsDeadRound_data();
    void cancelLandingAfterStartEndsDeadRound();
    void racedCancelDoesNotCarryIntoNextRound();
    void discardedRereadIsReplaced();
    void rereadWaitsForOutstandingStart();
    void lateCancelReplyDoesNotEraseNewConsent();
    void lateCodeReplyDoesNotGrantCancelledRound();
    void lateStartReplyDoesNotReviveCancelledRound();
    // #437 — OptInRequired is a tri-state, not a bool.
    void kvmOnlyPolicyDoesNotGateSolOrIder();
    void alwaysRequiredPolicyGatesEveryProtocol();
    void noPolicyGatesNothing();
};

// The core #433 regression: once the operator's code is accepted the
// firmware sits at RECEIVED(3). Nothing may ask for consent again —
// doing so revokes it and kills the session being opened.
void TestOptInStateMachine::grantedConsentIsNotReRequested()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("StartOptIn") == 1; }));

    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return codeSpy.count() == 1; }));
    QVERIFY(codeSpy.first().at(0).toBool());

    // Let every queued status read and poll tick settle so a stray
    // StartOptIn would have landed by now.
    settle(2000);

    QCOMPARE(amt.optInState, 3);
    QCOMPARE(c.optInState(), 3);
    QVERIFY2(c.optInSatisfied(),
              "RECEIVED(3) must count as consent granted");
    QCOMPARE(amt.countOf("SendOptInCode"), 1);
    QVERIFY2(amt.countOf("StartOptIn") == 1,
              qPrintable(QStringLiteral("StartOptIn re-issued after a granted "
                                        "consent — call sequence was: %1")
                             .arg(amt.calls.join(QStringLiteral(", ")))));
}

void TestOptInStateMachine::receivedStateCountsAsSatisfied()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    // Consent required, nothing granted yet.
    amt.optInRequired = 1;
    amt.optInState = 0;
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));
    QVERIFY(!c.optInSatisfied());

    // RECEIVED and IN_SESSION are both "go".
    amt.optInState = 3;
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 3; }));
    QVERIFY(c.optInSatisfied());

    amt.optInState = 4;
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 4; }));
    QVERIFY(c.optInSatisfied());

    // A machine with no consent policy is always satisfied.
    amt.optInRequired = 0;
    amt.optInState = 0;
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return !c.optInRequired(); }));
    QVERIFY(c.optInSatisfied());
}

void TestOptInStateMachine::startOptInIsNotReentrantWhileRoundIsLive()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    c.startOptIn();
    // Every extra call while the round is outstanding must be dropped;
    // each one would otherwise put a fresh code on the target's screen.
    for (int i = 0; i < 5; ++i) c.startOptIn();

    QVERIFY(waitFor(5000, [&]() { return amt.countOf("StartOptIn") >= 1; }));
    settle(1500);
    QCOMPARE(amt.countOf("StartOptIn"), 1);
    QVERIFY(c.optInRoundActive());

    // Cancelling releases the latch so a later attempt is allowed.
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("CancelOptIn") == 1; }));
    QVERIFY(!c.optInRoundActive());
}

void TestOptInStateMachine::repeatedStartFailuresGiveUpInsteadOfLooping()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    // Firmware refuses every StartOptIn. Without a cap, each failure
    // fed the next attempt and the ME was hammered until it stopped
    // answering anything — the "can't connect at all any more" half of
    // #433.
    amt.startOptInReturnValue = 1;

    QSignalSpy gaveUpSpy(&c, &MachineDetailsController::optInGaveUp);
    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);

    // Drive far more attempts than the cap allows.
    for (int i = 0; i < 12; ++i) {
        c.startOptIn();
        settle(250);
    }
    settle(1000);

    QVERIFY2(gaveUpSpy.count() >= 1, "expected optInGaveUp after the cap");
    QVERIFY2(amt.countOf("StartOptIn") <= 3,
              qPrintable(QStringLiteral("StartOptIn attempted %1 times; the cap "
                                        "is 3. Sequence: %2")
                             .arg(amt.countOf("StartOptIn"))
                             .arg(amt.calls.join(QStringLiteral(", ")))));
    QVERIFY(!c.optInRoundActive());

    // Every attempt reported failure to the UI rather than silently retrying.
    for (int i = 0; i < startedSpy.count(); ++i)
        QVERIFY(!startedSpy.at(i).at(0).toBool());

    // An explicit reset lets the operator try again.
    c.resetOptInAttempts();
    amt.startOptInReturnValue = 0;
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("StartOptIn") == 4; }));
}

void TestOptInStateMachine::rejectedCodeKeepsRoundOpen()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    amt.sendCodeReturnValue = 1; // wrong code

    QSignalSpy rejectedSpy(&c, &MachineDetailsController::optInCodeRejected);
    QSignalSpy resultSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("StartOptIn") == 1; }));

    c.sendOptInCode(111111);
    QVERIFY(waitFor(5000, [&]() { return resultSpy.count() == 1; }));
    QVERIFY(!resultSpy.first().at(0).toBool());
    QCOMPARE(rejectedSpy.count(), 1);

    // A wrong code must not restart the consent round — the code on the
    // target's screen is still the right one to type.
    settle(1500);
    QCOMPARE(amt.countOf("StartOptIn"), 1);
    QVERIFY(c.optInRoundActive());
    QVERIFY(!c.optInSatisfied());
}


// Firmware without IPS_OptInService (AMT <= 5), or a transport hiccup on
// the first read, must not leave callers waiting forever for a policy
// answer that never arrives. Gating Connect on `optInStatusKnown` made
// that a silent hang with no error and no spinner; the reference
// connects anyway on a failed read (Commander.htm:50753).
void TestOptInStateMachine::unreadableStatusResolvesToNotRequired()
{
    // A server that accepts the connection and closes without replying
    // stands in for "this class does not exist here".
    QTcpServer dead;
    QVERIFY(dead.listen(QHostAddress::LocalHost));
    QObject::connect(&dead, &QTcpServer::newConnection, &dead, [&]() {
        while (QTcpSocket *s = dead.nextPendingConnection()) {
            s->close();
            s->deleteLater();
        }
    });

    MachineDetailsController c;
    c.setHost(QStringLiteral("127.0.0.1"));
    c.setUser(QStringLiteral("admin"));
    c.setPassword(QStringLiteral("p"));
    c.setTls(false);
    c.setPortForTest(dead.serverPort());

    QSignalSpy unavailableSpy(&c, &MachineDetailsController::optInStatusUnavailable);

    QVERIFY(!c.optInStatusKnown());
    c.refreshOptInStatus();

    // The status must resolve one way or another — never stay unknown.
    QVERIFY2(waitFor(15000, [&]() { return c.optInStatusKnown(); }),
              "first IPS_OptInService read failed and optInStatusKnown never "
              "became true — Connect would hang silently forever");
    QCOMPARE(unavailableSpy.count(), 1);
    QVERIFY2(c.optInSatisfied(),
              "an unreadable consent policy must not block redirection");
}

// #460: once the status is known, a failed read keeps the cached values
// but must say so, or a Connect waiting on it never hears back.
void TestOptInStateMachine::laterFailedReadIsReported()
{
    FakeAmt amt;
    QVERIFY(amt.listen());
    MachineDetailsController c;
    aim(c, amt);
    QSignalSpy changed(&c, &MachineDetailsController::optInStatusChanged);
    QSignalSpy failed(&c, &MachineDetailsController::optInStatusReadFailed);
    QSignalSpy unavailable(&c, &MachineDetailsController::optInStatusUnavailable);

    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));
    QVERIFY(c.optInRequired());
    const int changesBefore = changed.count();

    amt.stopListening();
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return failed.count() == 1; }));
    QCOMPARE(unavailable.count(), 0);
    QCOMPARE(changed.count(), changesBefore);
    QVERIFY2(c.optInRequired(), "a failed read must not downgrade the policy");
}

void TestOptInStateMachine::staleReadDoesNotUndoGrantedConsent()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    amt.holdNextStatusRead(2);  // answered while the code was on screen
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return codeSpy.size() == 1; }));
    QVERIFY(codeSpy.first().at(0).toBool());
    QCOMPARE(c.optInState(), 3);

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return statusSpy.size() >= 1; }));

    QCOMPARE(c.optInState(), 3);
    QVERIFY(c.optInSatisfied());
}

void TestOptInStateMachine::staleReadDoesNotRestoreCancelledConsent()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy grantedSpy(&c, &MachineDetailsController::optInGranted);

    amt.holdNextStatusRead(3);  // answered before the operator cancelled
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    QSignalSpy cancelSpy(&c, &MachineDetailsController::optInStatusChanged);
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return cancelSpy.size() == 1; }));
    QCOMPARE(c.optInState(), 0);

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return statusSpy.size() >= 1; }));

    QCOMPARE(c.optInState(), 0);
    QVERIFY2(!c.optInSatisfied(), "a cancelled consent must not read as granted");
    QCOMPARE(grantedSpy.size(), 0);
}

void TestOptInStateMachine::staleReadDoesNotEndNewRound()
{
    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    amt.holdNextStatusRead(0);  // answered before StartOptIn reached AMT
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return statusSpy.size() >= 1; }));

    QCOMPARE(expiredSpy.size(), 0);
    QVERIFY2(c.optInRoundActive(), "a stale read must not end the round just started");
}


void TestOptInStateMachine::requestedStateIsNotAnExpiry()
{
    FakeAmt amt;
    amt.startOptInState = 1;    // Requested: not on the target's screen yet
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 1; }));
    QCOMPARE(expiredSpy.size(), 0);
    QVERIFY(c.optInRoundActive());

    amt.optInState = 2;
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));
    QCOMPARE(expiredSpy.size(), 0);

    amt.optInState = 0;     // the code timed out on the target
    QVERIFY2(waitFor(5000, [&]() { return expiredSpy.size() == 1; }),
             "a drop after Displayed must end the round");
    QVERIFY(!c.optInRoundActive());
}

void TestOptInStateMachine::failedCancelRereadsFirmware()
{
    FakeAmt amt;
    amt.cancelReturnValue = 1;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    amt.holdNextStatusRead(2);
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("CancelOptIn") == 1; }));
    settle(100);

    // The target approved while the refused cancel was on the wire. Only
    // a read started after the cancel can report it.
    amt.optInState = 3;
    amt.releaseHeldReply();
    QVERIFY2(waitFor(5000, [&]() { return c.optInState() == 3; }),
             "a refused cancel must be followed by a fresh read");
}

void TestOptInStateMachine::acceptedCodeSurvivesFailedCancel()
{
    FakeAmt amt;
    amt.cancelReturnValue = 1;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.holdNextReplyTo("SendOptInCode");
    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("CancelOptIn") == 1; }));
    settle(100);

    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 3; }));
    QCOMPARE(amt.optInState, 3);
    QVERIFY(c.optInSatisfied());
    QVERIFY2(codeSpy.isEmpty(), "the operator cancelled, so no session may be released");
}

void TestOptInStateMachine::readSpanningCancelAndStartDoesNotGrant()
{
    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);

    amt.holdNextStatusRead(3);  // answered before the round was torn down
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 1; }));

    // SessionWindow replaces a stale round with these two calls.
    amt.holdNextReplyTo("StartOptIn");
    c.cancelOptIn();
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 2; }));
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("CancelOptIn") == 1; }));

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply();     // the stale read
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("GetKvmSettings") >= 2; }));
    settle(100);
    QVERIFY(statusSpy.size() >= 1);
    QVERIFY2(c.optInState() != 3 && !c.optInSatisfied(),
             "a read from before the cancel must not release a session");

    amt.releaseHeldReply();     // StartOptIn
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(c.optInRoundActive());
    QVERIFY(!c.optInSatisfied());
}

void TestOptInStateMachine::lateRejectionAfterGrantStaysSilent()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);
    QSignalSpy rejectedSpy(&c, &MachineDetailsController::optInCodeRejected);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.sendCodeReturnValue = 1;
    amt.holdNextReplyTo("SendOptInCode");
    c.sendOptInCode(111111);
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    amt.sendCodeReturnValue = 0;
    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return codeSpy.size() == 1; }));
    QVERIFY(codeSpy.first().at(0).toBool());

    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return !c.busy(); }));
    QVERIFY2(rejectedSpy.isEmpty(), "a rejection would reopen the dialog over the session");
    QCOMPARE(codeSpy.size(), 1);
    QCOMPARE(c.optInState(), 3);
}

void TestOptInStateMachine::lateCancelReplyDoesNotEraseNewConsent()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    // SessionWindow tears down a stale round and starts the next at once.
    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 2; }));

    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return codeSpy.size() == 1; }));
    QCOMPARE(c.optInState(), 3);

    amt.releaseHeldReply();
    settle(200);
    QCOMPARE(amt.optInState, 3);
    QCOMPARE(c.optInState(), 3);
    QVERIFY(c.optInSatisfied());
}

void TestOptInStateMachine::lateCodeReplyDoesNotGrantCancelledRound()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    // Learn the policy first: with none known, everything reads as satisfied.
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.holdNextReplyTo("SendOptInCode");
    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    QSignalSpy cancelSpy(&c, &MachineDetailsController::optInStatusChanged);
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return cancelSpy.size() >= 1 && c.optInState() == 0; }));

    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return !c.busy(); }));
    QCOMPARE(amt.optInState, 0);
    QCOMPARE(c.optInState(), 0);
    QVERIFY2(!c.optInSatisfied(), "a cancelled round must not read as granted");
    QVERIFY2(codeSpy.isEmpty(), "optInCodeResult releases the waiting session");
}

void TestOptInStateMachine::lateStartReplyDoesNotReviveCancelledRound()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);

    amt.holdNextReplyTo("StartOptIn");
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    QSignalSpy cancelSpy(&c, &MachineDetailsController::optInStatusChanged);
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return cancelSpy.size() == 1; }));

    amt.releaseHeldReply();
    settle(700);    // longer than the 500 ms poll interval

    QVERIFY2(startedSpy.isEmpty(), "optInStarted opens the consent dialog");
    QVERIFY(!c.optInRoundActive());
    QCOMPARE(c.optInState(), 0);
    QCOMPARE(amt.countOf("GetOptInService"), 0);
}

void TestOptInStateMachine::requestedAfterLocalDisplayedIsNotExpiry()
{
    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    amt.startOptInState = 1;
    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 1; }));
    settle(700);    // longer than the 500 ms poll interval
    QCOMPARE(expiredSpy.size(), 0);
    QVERIFY(c.optInRoundActive());
}

void TestOptInStateMachine::displayedFromEarlierRoundDoesNotCarryOver()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 0; }));

    amt.startOptInState = 1;
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 2; }));
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 1; }));
    settle(700);
    QCOMPARE(expiredSpy.size(), 0);
    QVERIFY(c.optInRoundActive());
}

void TestOptInStateMachine::displayedReadFromEndedRoundDoesNotCount()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    amt.holdNextStatusRead(2);
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.countOf("CancelOptIn") == 1; }));
    settle(100);

    amt.startOptInState = 1;
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 2; }));

    amt.releaseHeldReply();     // Displayed, but from the cancelled round
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 1; }));
    settle(700);
    QCOMPARE(expiredSpy.size(), 0);
    QVERIFY(c.optInRoundActive());
}

void TestOptInStateMachine::refusedCancelRereadsAreCapped()
{
    FakeAmt amt;
    amt.optInState = 2;
    amt.cancelReturnValue = 1;
    amt.startOptInReturnValue = 1;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    // What SessionWindow::driveConsent does on every status change.
    const auto drive = [&]() {
        if (c.optInRoundActive()) return;
        if (c.optInState() == 2) c.cancelOptIn();
        c.startOptIn();
    };
    QObject::connect(&c, &MachineDetailsController::optInStatusChanged, &c, drive);

    c.resetOptInAttempts();
    drive();
    settle(1500);
    const int readsAfterFirst = amt.countOf("GetOptInService");
    QVERIFY2(amt.countOf("CancelOptIn") <= 4,
             qPrintable(QStringLiteral("%1 CancelOptIn calls").arg(amt.countOf("CancelOptIn"))));
    QVERIFY2(readsAfterFirst <= 4, qPrintable(QStringLiteral("%1 reads").arg(readsAfterFirst)));

    // The cap is per Connect.
    c.resetOptInAttempts();
    drive();
    settle(1000);
    const int moreReads = amt.countOf("GetOptInService") - readsAfterFirst;
    QVERIFY2(moreReads >= 1 && moreReads <= 3,
             qPrintable(QStringLiteral("%1 reads after reset").arg(moreReads)));
}

void TestOptInStateMachine::readLandingBeforeCancelReplyIsIgnored()
{
    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 1; }));
    amt.holdNextStatusRead(3);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 2; }));

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply(1);    // the read, while the cancel is unanswered
    QVERIFY(waitFor(5000, [&]() { return statusSpy.size() >= 1; }));
    QCOMPARE(c.optInState(), 2);

    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 0; }));
    QVERIFY(!c.optInSatisfied());
}

void TestOptInStateMachine::readLandingAfterCancelReplyIsIgnored()
{
    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 1; }));
    amt.holdNextStatusRead(3);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 2; }));

    amt.releaseHeldReply();     // the cancel
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 0; }));

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply();     // the read that was sent before it landed
    QVERIFY(waitFor(5000, [&]() { return statusSpy.size() >= 1; }));
    QCOMPARE(c.optInState(), 0);
    QVERIFY(!c.optInSatisfied());
}

void TestOptInStateMachine::staleReadDoesNotGrantNewRound()
{
    FakeAmt amt;
    amt.optInState = 3;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 3; }));

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy grantedSpy(&c, &MachineDetailsController::optInGranted);

    amt.holdNextStatusRead(3);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    QSignalSpy statusSpy(&c, &MachineDetailsController::optInStatusChanged);
    amt.releaseHeldReply();
    QVERIFY(waitFor(5000, [&]() { return statusSpy.size() >= 1; }));
    QCOMPARE(grantedSpy.size(), 0);
    QVERIFY(c.optInRoundActive());
}

void TestOptInStateMachine::lateAcceptedCodeAfterCancelRereads()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.holdNextReplyTo("SendOptInCode");
    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    QSignalSpy cancelSpy(&c, &MachineDetailsController::optInStatusChanged);
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return cancelSpy.size() >= 1 && c.optInState() == 0; }));

    amt.optInState = 3;     // the code landed after the cancel
    amt.releaseHeldReply();
    QVERIFY2(waitFor(5000, [&]() { return c.optInState() == 3; }),
             "an accepted code for an ended round must trigger a fresh read");
    QVERIFY2(codeSpy.isEmpty(), "the operator cancelled, so no session may be released");
}

void TestOptInStateMachine::refusedCancelNeverExposesNotStarted()
{
    FakeAmt amt;
    amt.optInState = 2;
    amt.cancelReturnValue = 1;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    QList<int> seen;
    QObject::connect(&c, &MachineDetailsController::optInStatusChanged, &c,
                     [&]() { seen.append(c.optInState()); });

    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return !seen.isEmpty(); }));
    settle(200);
    QVERIFY2(!seen.contains(0), "a refused cancel must not report NotStarted");
    QCOMPARE(c.optInState(), 2);
}

void TestOptInStateMachine::lostCodeReplyIsGrantedByPoll()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy grantedSpy(&c, &MachineDetailsController::optInGranted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    amt.holdNextReplyTo("SendOptInCode");
    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    QVERIFY2(waitFor(3000, [&]() { return grantedSpy.size() == 1; }),
             "a poll must report the grant while the code reply is missing");
    QCOMPARE(c.optInState(), 3);
    QVERIFY(!c.optInRoundActive());

    amt.releaseHeldReply();
    settle(200);
    QCOMPARE(grantedSpy.size(), 1);
    QVERIFY2(codeSpy.isEmpty(), "the session was already released by the poll");
}

void TestOptInStateMachine::overlappedDisplayedReadStillDetectsExpiry()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    amt.holdNextStatusRead(2);
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));

    amt.sendCodeReturnValue = 1;
    c.sendOptInCode(111111);
    QVERIFY(waitFor(5000, [&]() { return codeSpy.size() == 1; }));

    amt.optInState = 0;     // the code timed out on the target
    amt.releaseHeldReply();
    QVERIFY2(waitFor(5000, [&]() { return expiredSpy.size() == 1; }),
             "a discarded read still proves the round reached Displayed");
    QVERIFY(!c.optInRoundActive());
}

void TestOptInStateMachine::supersededCancelRereadsFirmware()
{
    FakeAmt amt;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy codeSpy(&c, &MachineDetailsController::optInCodeResult);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 2; }));
    c.sendOptInCode(123456);
    QVERIFY(waitFor(5000, [&]() { return codeSpy.size() == 1; }));
    QCOMPARE(c.optInState(), 3);

    amt.optInState = 0;     // the delayed cancel took effect last
    amt.releaseHeldReply();
    QVERIFY2(waitFor(5000, [&]() { return c.optInState() == 0; }),
             "a superseded cancel must be followed by a fresh read");
    QVERIFY(!c.optInSatisfied());
}

void TestOptInStateMachine::cancelLandingAfterStartEndsDeadRound_data()
{
    QTest::addColumn<bool>("pollWhileCancelUnanswered");
    QTest::newRow("cancel reply before first poll") << false;
    QTest::newRow("cancel reply after polls") << true;
}

void TestOptInStateMachine::cancelLandingAfterStartEndsDeadRound()
{
    QFETCH(bool, pollWhileCancelUnanswered);

    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));

    amt.optInState = 0;     // the cancel took effect after the start
    if (pollWhileCancelUnanswered) settle(700);
    amt.releaseHeldReply();

    QVERIFY2(waitFor(5000, [&]() { return expiredSpy.size() == 1; }),
             "a round whose code was cancelled must not keep its dialog open");
    QVERIFY(!c.optInRoundActive());
    QCOMPARE(c.optInState(), 0);
}

void TestOptInStateMachine::racedCancelDoesNotCarryIntoNextRound()
{
    FakeAmt amt;
    amt.optInState = 2;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    QSignalSpy startedSpy(&c, &MachineDetailsController::optInStarted);
    QSignalSpy expiredSpy(&c, &MachineDetailsController::optInExpiredOrDenied);

    amt.holdNextReplyTo("CancelOptIn");
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.holdingReply(); }));
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 1; }));
    amt.releaseHeldReply();     // an older cancel answered during this round
    QVERIFY(waitFor(5000, [&]() { return !c.busy(); }));

    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 0; }));
    QVERIFY(waitFor(5000, [&]() { return !c.busy(); }));

    // The next round has not left NotStarted yet. No cancel raced it.
    amt.startOptInState = 0;
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return startedSpy.size() == 2; }));
    settle(700);    // longer than the 500 ms poll interval
    QCOMPARE(expiredSpy.size(), 0);
    QVERIFY(c.optInRoundActive());
}

void TestOptInStateMachine::discardedRereadIsReplaced()
{
    FakeAmt amt;
    amt.cancelReturnValue = 1;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);

    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));

    amt.sendCodeReturnValue = 1;
    amt.holdNextReplyTo("SendOptInCode");
    c.sendOptInCode(111111);
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 1; }));

    // The reread after the refused cancel gets held too.
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));
    settle(50);
    amt.holdNextStatusRead(2);
    c.cancelOptIn();
    QVERIFY(waitFor(5000, [&]() { return amt.heldReplies() == 2; }));

    amt.optInState = 3;         // approved at the target
    amt.releaseHeldReply();     // the rejected code, making the read stale
    settle(100);
    amt.releaseHeldReply();     // the read
    QVERIFY2(waitFor(5000, [&]() { return c.optInState() == 3; }),
             "a discarded read must be replaced when nothing is polling");
}

void TestOptInStateMachine::rereadWaitsForOutstandingStart()
{
    FakeAmt amt;
    amt.optInState = 2;
    amt.startOptInReturnValue = 1;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 2; }));
    const int readsBefore = amt.countOf("GetOptInService");

    amt.holdNextReplyTo("StartOptIn");
    c.cancelOptIn();
    c.startOptIn();
    QVERIFY(waitFor(5000, [&]() {
        return amt.holdingReply() && amt.countOf("CancelOptIn") == 1;
    }));
    settle(200);
    QCOMPARE(amt.countOf("GetOptInService"), readsBefore);

    amt.releaseHeldReply();     // StartOptIn, refused
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 0; }));
    QCOMPARE(amt.optInState, 0);
}

// --- #437: OptInRequired granularity ---------------------------------
//
// AMT's OptInRequired is a tri-state (0 / 1 = KVM only / 0xFFFFFFFF =
// all). Flattening it to a bool made a KVM-only machine demand a
// consent PIN for Serial Console sessions that need none — a
// regression the #433 consent gating made reachable, since SOL and
// IDE-R now route through the same gate.

void TestOptInStateMachine::kvmOnlyPolicyDoesNotGateSolOrIder()
{
    FakeAmt amt;
    amt.optInRequired = 1;      // KVM only
    amt.optInState = 0;         // nothing granted
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));

    QVERIFY2(c.consentRequiredFor(MachineDetailsController::Kvm),
              "KVM must still be gated under a KVM-only policy");
    QVERIFY2(!c.consentRequiredFor(MachineDetailsController::Sol),
              "Serial Console must NOT be gated under a KVM-only policy");
    QVERIFY2(!c.consentRequiredFor(MachineDetailsController::Ider),
              "IDE-R must NOT be gated under a KVM-only policy");

    // ...and therefore SOL/IDE-R may connect immediately while KVM waits.
    QVERIFY(!c.consentSatisfiedFor(MachineDetailsController::Kvm));
    QVERIFY(c.consentSatisfiedFor(MachineDetailsController::Sol));
    QVERIFY(c.consentSatisfiedFor(MachineDetailsController::Ider));
}

void TestOptInStateMachine::alwaysRequiredPolicyGatesEveryProtocol()
{
    FakeAmt amt;
    amt.optInRequired = 4294967295u;   // 0xFFFFFFFF — always required
    amt.optInState = 0;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));

    for (const int p : {int(MachineDetailsController::Sol),
                        int(MachineDetailsController::Kvm),
                        int(MachineDetailsController::Ider)}) {
        QVERIFY2(c.consentRequiredFor(p),
                  qPrintable(QStringLiteral("protocol %1 must be gated when "
                                            "consent is always required").arg(p)));
        QVERIFY(!c.consentSatisfiedFor(p));
    }

    // A granted code satisfies all three at once.
    amt.optInState = 3;   // RECEIVED
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInState() == 3; }));
    for (const int p : {int(MachineDetailsController::Sol),
                        int(MachineDetailsController::Kvm),
                        int(MachineDetailsController::Ider)}) {
        QVERIFY(c.consentSatisfiedFor(p));
    }
}

void TestOptInStateMachine::noPolicyGatesNothing()
{
    FakeAmt amt;
    amt.optInRequired = 0;
    amt.optInState = 0;
    QVERIFY(amt.listen());

    MachineDetailsController c;
    aim(c, amt);
    c.refreshOptInStatus();
    QVERIFY(waitFor(5000, [&]() { return c.optInStatusKnown(); }));

    for (const int p : {int(MachineDetailsController::Sol),
                        int(MachineDetailsController::Kvm),
                        int(MachineDetailsController::Ider)}) {
        QVERIFY(!c.consentRequiredFor(p));
        QVERIFY(c.consentSatisfiedFor(p));
    }
}

QTEST_MAIN(TestOptInStateMachine)
#include "test_optin_statemachine.moc"
