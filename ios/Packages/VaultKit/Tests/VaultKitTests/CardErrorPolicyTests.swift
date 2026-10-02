import XCTest
@testable import VaultKit

/// Pins `CardError.isDefinitiveCardRejection`, which decides whether a failed
/// mutating step rewinds the ceremony to the card-inspection screen.
///
/// The distinction is not cosmetic. The ceremony's rule (design.md §5.2 rule 1)
/// is that a mutating step whose outcome is unknown must be re-inspected before
/// anything else happens — but a card that answered "no" wrote nothing, and
/// rewinding there would send the operator back over a mistyped PIN. Getting the
/// classification wrong in the *other* direction is worse: treating an unknown
/// outcome as known could hide a half-written key.
final class CardErrorPolicyTests: XCTestCase {

    private let definitiveRejections: [CardError] = [
        .pinIncorrect(retriesRemaining: 2),
        .pinIncorrect(retriesRemaining: nil),
        .pinBlocked,
        .adminPinBlocked,
        .conditionsNotSatisfied,
        .unsupportedFirmware,
        .keyImportRejected,
        .unsupportedFeature("instruction not supported"),
        .unsupportedKeyType("an RSA key occupies the signature slot"),
    ]

    private let unknownOutcomes: [CardError] = [
        .transportUnavailable("the NFC session ended unexpectedly, so this operation did not complete"),
        .cardNotSelected,
        .malformedResponse("response chaining did not terminate"),
        .unexpectedStatusWord(sw1: 0x6A, sw2: 0x80),
        .signatureFailed,
    ]

    func testDefinitiveRejectionsDoNotForceReinspection() {
        for error in definitiveRejections {
            XCTAssertTrue(
                error.isDefinitiveCardRejection,
                "\(error) is the card refusing an operation, so nothing was written"
            )
        }
    }

    /// The conservative direction: anything whose effect is unclear must count as
    /// unknown, including status words this app does not interpret.
    func testUnknownOutcomesForceReinspection() {
        for error in unknownOutcomes {
            XCTAssertFalse(
                error.isDefinitiveCardRejection,
                "\(error) leaves the card state unclear and must be re-inspected"
            )
        }
    }

    /// Nothing may be classified both ways, and the two sets must cover every
    /// case: a new case added without a decision here would silently default to
    /// "known", which is the dangerous direction.
    func testClassificationCoversEveryCase() {
        let all: [CardError] = definitiveRejections + unknownOutcomes
        for error in all {
            XCTAssertEqual(
                error.isDefinitiveCardRejection,
                definitiveRejections.contains(error),
                "\(error) is classified inconsistently"
            )
        }
    }

    /// The transport failure the operator actually hit — an NFC session that
    /// ended mid-reset — must be the rewinding kind.
    func testSessionLossIsNotADefinitiveRejection() {
        let sessionLost = CardError.transportUnavailable(
            "the NFC session ended unexpectedly, so this operation did not complete; hold the iPhone against the YubiKey and try again"
        )
        XCTAssertFalse(sessionLost.isDefinitiveCardRejection)
    }
}
