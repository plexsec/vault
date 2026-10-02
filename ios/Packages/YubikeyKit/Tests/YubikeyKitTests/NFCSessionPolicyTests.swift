import XCTest
@testable import YubikeyKit

/// Pins the CoreNFC session-lifecycle policy.
///
/// These tests exist because the code they protect cannot be exercised off-device:
/// `NFCTagTransport` needs CoreNFC, which has no simulator. The policy itself is
/// ordinary arithmetic and classification, so it lives in `YubikeyKit` and is
/// checked here — including the exact failure that motivated it, CoreNFC error
/// 202 "Session invalidated unexpectedly".
final class NFCSessionPolicyTests: XCTestCase {

    // MARK: Cooldown

    func testNoCooldownBeforeAnySessionHasBeenInvalidated() {
        XCTAssertEqual(NFCSessionPolicy.cooldownRemaining(lastInvalidation: nil), 0)
    }

    func testCooldownIsFullWhenTheSessionWasJustInvalidated() {
        let now = DispatchTime(uptimeNanoseconds: 1_000_000_000)
        XCTAssertEqual(
            NFCSessionPolicy.cooldownRemaining(lastInvalidation: now, now: now),
            NFCSessionPolicy.cooldown,
            accuracy: 1e-9
        )
    }

    func testCooldownCountsDown() {
        // Half the cooldown has elapsed: the other half must still be waited out.
        let start = DispatchTime(uptimeNanoseconds: 1_000_000_000)
        let half = DispatchTime(
            uptimeNanoseconds: start.uptimeNanoseconds + UInt64(NFCSessionPolicy.cooldown / 2 * 1_000_000_000)
        )
        XCTAssertEqual(
            NFCSessionPolicy.cooldownRemaining(lastInvalidation: start, now: half),
            NFCSessionPolicy.cooldown / 2,
            accuracy: 1e-9
        )
    }

    func testCooldownIsOverOnceEnoughTimeHasPassed() {
        let start = DispatchTime(uptimeNanoseconds: 1_000_000_000)
        let later = DispatchTime(
            uptimeNanoseconds: start.uptimeNanoseconds + UInt64(NFCSessionPolicy.cooldown * 1_000_000_000) + 1
        )
        XCTAssertEqual(NFCSessionPolicy.cooldownRemaining(lastInvalidation: start, now: later), 0)
    }

    /// A non-monotonic clock reading must not underflow into a negative wait.
    func testClockGoingBackwardsWaitsTheFullCooldown() {
        let later = DispatchTime(uptimeNanoseconds: 2_000_000_000)
        let earlier = DispatchTime(uptimeNanoseconds: 1_000_000_000)
        XCTAssertEqual(
            NFCSessionPolicy.cooldownRemaining(lastInvalidation: later, now: earlier),
            NFCSessionPolicy.cooldown,
            accuracy: 1e-9
        )
    }

    // MARK: Failure classification

    func testReaderSessionInvalidationCodesAreClassified() {
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: 200), .cancelledByOperator)
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: 201), .timedOut)
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: 202), .sessionEndedUnexpectedly)
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: 203), .systemBusy)
    }

    /// An unrecognised or absent code is left unclassified rather than guessed at.
    func testUnknownAndAbsentCodesFallBackToOther() {
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: nil), .other)
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: 42), .other)
        XCTAssertEqual(NFCSessionPolicy.kind(forCode: 0), .other)
    }

    /// The regression this whole policy exists for: 202 on `begin()` is a race,
    /// not a decision, so it must be retried. Operator cancellation and the
    /// system timeout must not be.
    func testOnlyTheSessionRacesAreRetriedOnBegin() {
        XCTAssertTrue(NFCSessionPolicy.isRetryableOnBegin(.sessionEndedUnexpectedly))
        XCTAssertTrue(NFCSessionPolicy.isRetryableOnBegin(.systemBusy))
        XCTAssertFalse(NFCSessionPolicy.isRetryableOnBegin(.cancelledByOperator))
        XCTAssertFalse(NFCSessionPolicy.isRetryableOnBegin(.timedOut))
        XCTAssertFalse(NFCSessionPolicy.isRetryableOnBegin(.other))
    }

    // MARK: Operator-facing text

    /// The message must name the session, not the key: "the YubiKey could not be
    /// reached" was what misled the operator into thinking the card had refused
    /// the reset.
    func testSessionEndedMessageNamesTheSessionAndSaysNothingWasLost() {
        let message = NFCSessionPolicy.message(for: .sessionEndedUnexpectedly, fallback: "unused")
        XCTAssertTrue(message.contains("NFC session"))
        XCTAssertTrue(message.contains("did not complete"))
    }

    /// Each kind needs its own wording; one shared string made a transport race
    /// indistinguishable from an operator cancellation.
    func testEachFailureKindHasItsOwnWording() {
        let kinds: [NFCSessionPolicy.SessionFailureKind] = [
            .cancelledByOperator, .timedOut, .sessionEndedUnexpectedly, .systemBusy,
        ]
        let messages = kinds.map { NFCSessionPolicy.message(for: $0, fallback: "unused") }
        XCTAssertEqual(Set(messages).count, kinds.count, "failure kinds must not share wording")
    }

    /// Only the unclassified case falls back to the system string.
    func testOtherKindUsesTheSystemDescription() {
        XCTAssertEqual(
            NFCSessionPolicy.message(for: .other, fallback: "Reader session is invalid."),
            "Reader session is invalid."
        )
    }

    func testDescribeUsesTheSuppliedCodeAndOtherwiseFallsBack() {
        let error = NSError(domain: "NFCError", code: 202, userInfo: [
            NSLocalizedDescriptionKey: "Session invalidated unexpectedly",
        ])
        XCTAssertEqual(
            NFCSessionPolicy.describe(error, code: 202),
            NFCSessionPolicy.message(for: .sessionEndedUnexpectedly, fallback: "unused")
        )
        XCTAssertEqual(
            NFCSessionPolicy.describe(error),
            "Session invalidated unexpectedly",
            "without a code the system description is all we have"
        )
    }

    /// The retry budget must allow a race to be absorbed but still end.
    func testBeginAttemptBudgetIsBoundedAndAllowsARetry() {
        XCTAssertGreaterThanOrEqual(NFCSessionPolicy.maximumBeginAttempts, 2)
        XCTAssertLessThanOrEqual(NFCSessionPolicy.maximumBeginAttempts, 5)
    }

    /// The wait for confirmation must be bounded, or a missing delegate callback
    /// would hang the ceremony.
    func testInvalidationWaitIsBounded() {
        XCTAssertGreaterThan(NFCSessionPolicy.invalidationWaitTimeout, 0)
        XCTAssertLessThanOrEqual(NFCSessionPolicy.invalidationWaitTimeout, 10)
    }
}
