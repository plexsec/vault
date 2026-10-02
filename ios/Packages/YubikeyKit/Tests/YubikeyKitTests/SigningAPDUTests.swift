import Foundation
import VaultKit
import XCTest

@testable import YubikeyKit
@testable import YubikeyKitMock

/// The signing APDUs: `VERIFY PW1` and `PSO:CDS`.
///
/// The card here is the APDU-level fake, so these tests are about the *protocol*
/// the app speaks — which PIN, in which session, in which order, and what each
/// status word turns into. That the signature is a valid ECDSA signature is
/// VaultKit's business (`ECDSASignatureTests`, against published vectors); a fake
/// card that produced real signatures would be testing arithmetic twice and the
/// wiring once.
final class SigningAPDUTests: XCTestCase {
    private let digest = [UInt8](repeating: 0x5a, count: 32)
    private let userPIN: [UInt8] = Array("246810".utf8)

    private func prepareCard() async throws -> (MockYubikeyTransport, OpenPGPCard) {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.select()
        // Provision a key into the signature slot and set the user PIN to one the
        // test knows, the way a provisioning ceremony leaves the card.
        try await card.verify(pin: OpenPGPPinDefaults.admin, reference: .admin, operation: .verifyAdminPIN)
        try await card.setPINs(userPIN: userPIN, adminPIN: OpenPGPPinDefaults.admin)
        try await card.importKey(
            slot: .signature,
            algorithm: .secp256k1,
            privateKey: SensitiveBytes(copying: [UInt8](repeating: 0x11, count: 32)),
            fingerprint: [UInt8](repeating: 0x22, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: OpenPGPPinDefaults.admin
        )
        return (transport, card)
    }

    // MARK: - Happy path

    func testVerifyThenSignOnOneSession() async throws {
        let (transport, card) = try await prepareCard()
        try await card.verifyUserPIN(userPIN)
        let response = try await card.computeDigitalSignature(digest: digest)

        XCTAssertEqual(transport.signatureCounter, 1)
        XCTAssertEqual(transport.lastSignedDigest, digest)
        // The response is a DER signature this app's own parser accepts.
        let signature = try ECDSASignature.decode(cardResponse: response)
        XCTAssertEqual(signature.r.count, 32)
        XCTAssertEqual(signature.s.count, 32)
    }

    /// The whole reason `SignerCard.sign(digest:userPIN:)` is one method: VERIFY
    /// state does not survive a session boundary, so a verify and a sign in
    /// different sessions must fail on the *second* one.
    func testSessionBoundaryLosesPW1Verification() async throws {
        let (transport, card) = try await prepareCard()
        try await card.close()
        // A new tap: the card is selected again, the key is still there, and the
        // PIN is no longer verified.
        try await card.open()
        try await card.select()
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await card.computeDigitalSignature(digest: self.digest)
        }
        XCTAssertEqual(error as? CardError, .userPinNotVerified)
        XCTAssertEqual(transport.signatureCounter, 0, "a refused signature must not count")
    }

    /// And the `SignerCard` entry point keeps both in one session.
    func testTransportSessionCardSignsInASingleSession() async throws {
        let transport = MockYubikeyTransport()
        // Seed the card the same way `prepareCard` does, but through a session card
        // so every call opens its own session, as it does in the app.
        let seeder = OpenPGPCard(transport: transport)
        try await seeder.open()
        try await seeder.select()
        try await seeder.verify(pin: OpenPGPPinDefaults.admin, reference: .admin, operation: .verifyAdminPIN)
        try await seeder.setPINs(userPIN: userPIN, adminPIN: OpenPGPPinDefaults.admin)
        try await seeder.importKey(
            slot: .signature,
            algorithm: .secp256k1,
            privateKey: SensitiveBytes(copying: [UInt8](repeating: 0x11, count: 32)),
            fingerprint: [UInt8](repeating: 0x22, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: OpenPGPPinDefaults.admin
        )
        await seeder.close()

        let sessionCard = TransportSessionCard(makeTransport: { transport })
        let response = try await sessionCard.sign(digest: digest, userPIN: userPIN)
        XCTAssertEqual(transport.signatureRequestCount, 1)
        XCTAssertNoThrow(try ECDSASignature.decode(cardResponse: response))
    }

    // MARK: - Refusals

    func testSigningWithoutAKeyInTheSignatureSlot() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.select()
        try await card.verifyUserPIN(OpenPGPPinDefaults.user)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await card.computeDigitalSignature(digest: self.digest)
        }
        XCTAssertEqual(error as? CardError, .unexpectedStatusWord(sw1: 0x6A, sw2: 0x88))
    }

    func testWrongDigestLengthIsRefusedBeforeTheCardIsAsked() async throws {
        let (transport, card) = try await prepareCard()
        try await card.verifyUserPIN(userPIN)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await card.computeDigitalSignature(digest: [0x01, 0x02])
        }
            guard case .malformedResponse = (error as? CardError) else {
                return XCTFail("got \(String(describing: error))")
            }
        XCTAssertEqual(transport.signatureRequestCount, 0)
    }

    func testWrongPINDecrementsTheRetriesTheCardReports() async throws {
        let (_, card) = try await prepareCard()
        let error = await XCTAssertThrowsErrorAsync {
            try await card.verifyUserPIN([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        }
        XCTAssertEqual(error as? CardError, .pinIncorrect(retriesRemaining: 2))
    }

    /// An unfinished touch. The app must treat it as "unknown", not as a refusal:
    /// the card may have produced a signature, so nothing is retried.
    func testUnfinishedTouchIsReportedAndNotCounted() async throws {
        let (transport, card) = try await prepareCard()
        transport.touchNotCompleted = true
        try await card.verifyUserPIN(userPIN)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await card.computeDigitalSignature(digest: self.digest)
        }
        XCTAssertEqual(error as? CardError, .touchNotCompleted)
        XCTAssertEqual(transport.signatureCounter, 0)
        XCTAssertFalse(
            CardError.touchNotCompleted.isDefinitiveCardRejection,
            "an unfinished touch must not be classified as a refusal: the card may have signed"
        )
    }

    func testBlockedPW1IsReportedAsBlocked() async throws {
        let (transport, card) = try await prepareCard()
        transport.userPinBlockedForSigning = true
        try await card.verifyUserPIN(userPIN)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await card.computeDigitalSignature(digest: self.digest)
        }
        XCTAssertEqual(error as? CardError, .pinBlocked)
        XCTAssertEqual(transport.signatureCounter, 0)
    }

    /// `PSO:CDS` moves the counter exactly once, which is what makes the counter
    /// evidence that a signature happened.
    func testCounterMovesOncePerSignature() async throws {
        let (transport, card) = try await prepareCard()
        try await card.verifyUserPIN(userPIN)
        _ = try await card.computeDigitalSignature(digest: digest)
        _ = try await card.computeDigitalSignature(digest: [UInt8](repeating: 0x0f, count: 32))
        XCTAssertEqual(transport.signatureCounter, 2)
        let counter = try await card.signatureCounter()
        XCTAssertEqual(counter, 2)
    }
}

/// `XCTAssertThrowsError` has no async form, so the session-boundary tests need
/// this. Returns the error so the caller can assert on it.
func XCTAssertThrowsErrorAsync(
    _ expression: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async -> Error? {
    do {
        try await expression()
        XCTFail("expected an error", file: file, line: line)
        return nil
    } catch {
        return error
    }
}
