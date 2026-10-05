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
    }

    // MARK: - One key, one session (amendment 33)

    /// The signing flow reads the key the request named, and **nothing else**.
    ///
    /// `inventory()` answers "what does this card hold?" by reading the public key of
    /// *each* slot, which is what an inventory is for. Signing asks a narrower question,
    /// and the APDUs are where that is visible: one `GENERATE ASYMMETRIC KEY PAIR`
    /// (`00 47 81 00`) carrying the signature slot's control reference (`0xB6`), and none
    /// carrying the authentication slot's (`0xA4`). Reading a second key before knowing
    /// which one the transaction needs is the defect this pins.
    func testTheSigningIdentityReadTouchesOneSlotOnly() async throws {
        let transport = MockYubikeyTransport()
        let card = TransportSessionCard(makeTransport: { transport })
        let adminPIN = OpenPGPPinDefaults.admin
        try await card.reset()
        try await card.setPINs(userPIN: userPIN, adminPIN: adminPIN)
        // Both slots hold a key, as a provisioned card's do — so a read of the other
        // slot would succeed and leave no other trace than the APDU.
        for (slot, algorithm, seed, fingerprint) in [
            (KeySlot.signature, KeyAlgorithm.secp256k1, UInt8(0x11), UInt8(0x22)),
            (KeySlot.authentication, KeyAlgorithm.ed25519, UInt8(0x33), UInt8(0x44)),
        ] {
            try await card.importKey(
                slot: slot,
                algorithm: algorithm,
                privateKey: SensitiveBytes(copying: [UInt8](repeating: seed, count: 32)),
                fingerprint: [UInt8](repeating: fingerprint, count: 20),
                creationTime: Date(timeIntervalSince1970: 1_700_000_000),
                adminPIN: adminPIN
            )
        }
        try await card.writePairingManifest([0x01, 0x02, 0x03], adminPIN: adminPIN)

        // `receivedAPDUs` is read-only on the mock: the slice after the provisioning
        // above is what the signing read itself sent.
        let before = transport.receivedAPDUs.count
        let identity = try await card.readSigningIdentity(slot: .signature)
        let sent = Array(transport.receivedAPDUs.dropFirst(before))
        XCTAssertEqual(identity.publicKey?.count, 33, "the signature slot's key, normalised to compressed")
        XCTAssertEqual(identity.pairingManifest, [0x01, 0x02, 0x03])
        XCTAssertNotNil(identity.serial)

        let keyReads = sent.filter { $0.hasPrefix("00478100") }
        XCTAssertEqual(keyReads.count, 1, "exactly one key read: \(keyReads)")
        XCTAssertTrue(keyReads[0].contains("b600"), "and it is the signature slot's: \(keyReads[0])")
        XCTAssertFalse(
            sent.contains { $0.hasPrefix("00478100") && $0.contains("a400") },
            "the authentication slot's key must not be read: \(sent)"
        )
        // One session, too: a second SELECT would be a second reader session, and on NFC
        // that is a second tap.
        XCTAssertEqual(
            sent.filter { $0.hasPrefix("00a40400") }.count, 1,
            "the whole pre-signing read must be one session: \(sent)"
        )
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

/// The DEBUG-only vector: the simulated card must return a *real* signature for the
/// digest the sample request carries, because the app verifies what it gets back.
/// Pinned here so a mismatch is a two-second test rather than a three-minute UI run.
final class SimulatedCardVectorTests: XCTestCase {
    func testTheSimulatedCardReturnsTheGeneratedSignature() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.select()
        try await card.verify(pin: OpenPGPPinDefaults.admin, reference: .admin, operation: .verifyAdminPIN)
        try await card.setPINs(userPIN: Array("246810".utf8), adminPIN: OpenPGPPinDefaults.admin)
        try await card.importKey(
            slot: .signature,
            algorithm: .secp256k1,
            privateKey: SensitiveBytes(copying: [UInt8](repeating: 0x11, count: 32)),
            fingerprint: [UInt8](repeating: 0x22, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: OpenPGPPinDefaults.admin
        )
        let digest = try Hex.decode("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
        try await card.verifyUserPIN(Array("246810".utf8))
        let response = try await card.computeDigitalSignature(digest: digest)
        XCTAssertEqual(
            response.hexString,
            try SimulatedSigningVectors.signatures[digest.hexString].map { $0 }
                ?? "the generated vector is missing for this digest",
            "the simulated card must return the generated signature, not the placeholder"
        )
    }
}
