import Foundation
import XCTest
@testable import YubikeyKit
import VaultKit
import YubikeyKitMock

/// A reset is `TERMINATE DF` + `ACTIVATE FILE` + re-SELECT, and the ceremony's
/// reset step sends all three inside **one** NFC session. If that session drops
/// between the first two — the failure the operator sees as "the YubiKey could
/// not be reached" — the card is left *terminated*: wiped, deactivated, and
/// answering `6985` to everything but `ACTIVATE FILE`.
///
/// These tests pin the recovery, which is what stops such a card from needing
/// GPG or `ykman` to be usable by this app again.
final class TerminatedAppletTests: XCTestCase {

    private let selectAPDU = "00a4040006d2760001240100"

    func testSelectReactivatesAnAppletLeftTerminatedByAnInterruptedReset() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        transport.simulateInterruptedReset()
        XCTAssertTrue(transport.appletIsTerminated, "precondition: the applet is terminated")

        // A fresh session — the operator's next tap, after the error.
        try await card.open()

        XCTAssertFalse(transport.appletIsTerminated, "SELECT must have reactivated the DF")

        let apdus = transport.receivedAPDUs
        XCTAssertEqual(apdus.filter { $0 == "00440000" }.count, 1, "ACTIVATE FILE must be sent")
        let activateIndex = try XCTUnwrap(apdus.firstIndex(of: "00440000"))
        XCTAssertEqual(
            apdus.filter { $0 == selectAPDU }.count, 2,
            "SELECT is refused while terminated, so it must be repeated after ACTIVATE FILE"
        )
        XCTAssertTrue(
            apdus[..<activateIndex].contains(selectAPDU),
            "the refused SELECT must come before ACTIVATE FILE"
        )
        XCTAssertTrue(
            apdus[(activateIndex + 1)...].contains(selectAPDU),
            "a successful re-SELECT must come after ACTIVATE FILE"
        )
    }

    /// `6285` (`NO INPUT DATA`) is the other status word the OpenPGP spec allows
    /// for a deactivated DF, and the one yubikit also treats as "not activated".
    func testSelectAlsoRecoversFromTheNoInputDataStatusWord() async throws {
        let transport = MockYubikeyTransport()
        transport.terminatedSelectStatusWord = StatusWord(sw1: 0x62, sw2: 0x85)
        let card = OpenPGPCard(transport: transport)
        transport.simulateInterruptedReset()

        try await card.open()

        XCTAssertTrue(transport.receivedAPDUs.contains("00440000"))
        XCTAssertFalse(transport.appletIsTerminated)
    }

    func testHealthyAppletIsNeverSentActivateFile() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)

        try await card.open()

        XCTAssertTrue(transport.receivedAPDUs.contains(selectAPDU))
        XCTAssertFalse(
            transport.receivedAPDUs.contains("00440000"),
            "the recovery path must not fire on an ordinary select"
        )
    }

    /// While terminated, only ACTIVATE FILE and a re-SELECT are accepted — so the
    /// recovery cannot happen by accident and the mock cannot hide the state.
    func testTerminatedAppletRefusesEverythingExceptActivate() async throws {
        let transport = MockYubikeyTransport()
        transport.simulateInterruptedReset()
        let card = OpenPGPCard(transport: transport)

        // SELECT is refused (that is the signal), and so is a data read.
        let selectResponse = try await transport.exchange(
            CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: OpenPGPCard.openPGPAID, expectedLength: 0)
        )
        XCTAssertEqual(selectResponse.status, StatusWord(sw1: 0x69, sw2: 0x85))
        await XCTAssertThrowsErrorAsync {
            try await card.getDataObject(OpenPGPDataObject.applicationRelatedData)
        } verify: { error in
            XCTAssertEqual(error as? CardError, .conditionsNotSatisfied)
        }
    }

    /// The normal path must keep working in one session: TERMINATE, ACTIVATE,
    /// re-SELECT, with the card neither terminated nor holding a key afterwards.
    func testCompletedResetLeavesTheAppletActive() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset(adminPIN: OpenPGPPinDefaults.admin)

        XCTAssertFalse(transport.appletIsTerminated)
        XCTAssertFalse(transport.hasKey(in: .signature))
        XCTAssertFalse(transport.hasKey(in: .authentication))

        // A later session must select cleanly, with no recovery needed.
        let alreadySent = transport.receivedAPDUs.count
        try await card.open()
        let secondSession = Array(transport.receivedAPDUs.dropFirst(alreadySent))
        XCTAssertFalse(
            secondSession.contains("00440000"),
            "a reset that completed must not need the recovery path"
        )
    }
}
