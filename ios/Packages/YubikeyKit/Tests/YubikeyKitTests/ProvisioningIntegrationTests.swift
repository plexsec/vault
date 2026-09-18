import Foundation
import XCTest
import VaultKit
import YubikeyKit
import YubikeyKitMock

/// End-to-end integration: the real ceremony, the real OpenPGP APDU layer, the
/// real session-per-operation wrapper, and a scripted card.
///
/// The unit tests either drive `ProvisioningCeremony` against a `SignerCard`
/// double, or drive `OpenPGPCard` against a scripted transport. Neither closes
/// the loop. This file does: nothing here is mocked at the protocol boundary, so
/// a mismatch between what the ceremony asks for and what the APDU layer sends
/// shows up as a failure rather than in a test-only seam.
final class ProvisioningIntegrationTests: XCTestCase {

    private static let adminPIN = "87654321"
    private static let userPIN = "246810"

    private func makeCeremony(
        transport: MockYubikeyTransport,
        entropy: [UInt8] = [UInt8](repeating: 0, count: 32),
        appVersion: String = "integration-test"
    ) -> (ProvisioningCeremony, TransportSessionCard) {
        // Every card operation gets its own transport session, exactly as the app
        // does, so the per-session VERIFY behaviour is exercised for real.
        let card = TransportSessionCard(makeTransport: { transport })
        let ceremony = ProvisioningCeremony(
            card: card,
            entropySource: ScriptedEntropySource(bytes: entropy),
            transportDescription: "Simulated (integration test)",
            appVersion: appVersion,
            clock: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        return (ceremony, card)
    }

    /// The complete §4.2 flow, with no protocol-level mocking.
    func testFullCeremonyAgainstTheAPDULayer() async throws {
        let transport = MockYubikeyTransport()
        let (ceremony, _) = makeCeremony(transport: transport)

        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)

        let inventory = try await ceremony.inspectCard()
        XCTAssertEqual(inventory.openPGPVersion, "3.4")
        XCTAssertFalse(inventory.hasSignatureKey)
        XCTAssertTrue(inventory.isFactoryFresh)

        try await ceremony.resetCard(adminPIN: Array("12345678".utf8))
        try await ceremony.setPINs(
            userPIN: Array(Self.userPIN.utf8),
            adminPIN: Array(Self.adminPIN.utf8)
        )
        try await ceremony.applyPolicy()

        // The policy must have landed on the card, not just in the ceremony.
        XCTAssertEqual(transport.currentUIF, [0x02, 0x20])
        XCTAssertEqual(transport.currentPWStatus.first, 0x00)
        XCTAssertEqual(transport.currentPWStatus.count, 7)

        try ceremony.generateEntropy()
        let words = try ceremony.generateMnemonic()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })

        let summary = try ceremony.deriveKey(for: .ethereum)
        // The 24-word form of all-zero entropy is "abandon x23 + art", and this
        // address was produced independently by tools/derive.
        XCTAssertEqual(words.last, "art")
        XCTAssertEqual(summary.address, "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb")
        XCTAssertEqual(
            summary.publicKeyHex,
            "02dc286c821c7490afbe20a79d13123b9f41f3d7ef21e4a9caacd22f5983b28eca"
        )

        try await ceremony.importKey()
        // The card really holds the key: verify against the mock's own state too.
        XCTAssertTrue(transport.hasKey)
        // The card's fingerprint object (0xC7) is 20 bytes; the BIP32 fingerprint
        // is 4 bytes and is zero-padded when written.
        XCTAssertEqual(transport.currentFingerprint.count, 20)
        XCTAssertTrue(Hex.encode(transport.currentFingerprint).hasPrefix(summary.fingerprintHex))

        let readBack = try await ceremony.verifyReadBack()
        XCTAssertTrue(readBack.matches)
        XCTAssertEqual(readBack.cardPublicKeyHex, summary.publicKeyHex)

        let check = try ceremony.submitIndependentCheck(
            address: summary.address,
            source: "tools/derive (independent)"
        )
        XCTAssertTrue(check.matched)

        let ur = try ceremony.buildPairingUR(style: .keystoneLegacy, policy: .singleKeyOnly)
        XCTAssertEqual(ur.type, "crypto-hdkey")
        let decoded = try HDKey(ur: try UR(urString: ur.string))
        XCTAssertNil(decoded.chainCode)
        XCTAssertEqual(decoded.keyData, summary.publicKeyCompressed)
        XCTAssertEqual(decoded.origin?.sourceFingerprint, UInt32(summary.masterFingerprintHex.prefix(8), radix: 16))

        let baseline = try await ceremony.readCounterBaseline()
        XCTAssertEqual(baseline, 0)

        let report = ceremony.finish()
        XCTAssertTrue(report.readBackVerified)
        XCTAssertEqual(report.counterBaseline, 0)
        XCTAssertEqual(transport.signatureCounter, 0)

        // The whole exchange must have gone through real APDUs.
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00a40400") }, "no SELECT")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00db3fff") }, "no key import")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00478100") }, "no public-key read")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00ca007a") }, "no counter read")
    }

    /// Re-provisioning a YubiKey that already holds a key.
    ///
    /// The ceremony state machine forces the destructive reset before anything
    /// else, so "silently overwrite the old key" is not reachable: the failure
    /// mode being guarded against is a *second* ceremony that skips the reset,
    /// and that is refused as an ordering violation before the card is touched.
    func testReProvisioningRequiresTheDestructiveResetFirst() async throws {
        let transport = MockYubikeyTransport()
        let (first, _) = makeCeremony(transport: transport)
        try first.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await first.inspectCard()
        try await first.resetCard(adminPIN: Array("12345678".utf8))
        try await first.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await first.applyPolicy()
        try first.generateEntropy()
        let words = try first.generateMnemonic()
        let challenge = try first.transcriptionChallenge()
        try first.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        _ = try first.deriveKey(for: .ethereum)
        try await first.importKey()
        XCTAssertTrue(transport.hasKey)
        let firstFingerprint = transport.currentFingerprint

        // Second ceremony on the same key: inventory reports the existing key,
        // and the reset step is due.
        let (second, _) = makeCeremony(
            transport: transport,
            entropy: [UInt8](repeating: 0xFF, count: 32)
        )
        try second.begin(mode: .freshGeneration, postureConfirmed: true)
        let inventory = try await second.inspectCard()
        XCTAssertTrue(inventory.hasSignatureKey)
        XCTAssertFalse(inventory.isFactoryFresh)
        XCTAssertTrue(second.report.warnings.contains { $0.contains("not factory-fresh") })

        // Skipping the reset is refused before the card is touched.
        await XCTAssertThrowsErrorAsync {
            try await second.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .stepOutOfOrder(expected: .reset, actual: .pinProvisioning))
        }
        // And the destructive reset itself needs an explicit acknowledgement,
        // because this card holds a key that may still secure funds.
        await XCTAssertThrowsErrorAsync {
            try await second.resetCard(adminPIN: Array(Self.adminPIN.utf8))
        } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .destructiveResetNotAcknowledged)
        }
        // The factory default no longer works: the first ceremony changed it.
        await XCTAssertThrowsErrorAsync {
            try await second.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        } verify: { error in
            XCTAssertEqual(error as? CardError, .pinIncorrect(retriesRemaining: 2))
        }
        XCTAssertEqual(transport.currentFingerprint, firstFingerprint, "the old key must be untouched")

        // Only after acknowledging the destruction does the slot clear.
        try await second.resetCard(adminPIN: Array(Self.adminPIN.utf8), acknowledgingDestruction: true)
        XCTAssertFalse(transport.hasKey)

        try await second.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await second.applyPolicy()
        try second.generateEntropy()
        let words2 = try second.generateMnemonic()
        let challenge2 = try second.transcriptionChallenge()
        try second.confirmTranscription(entries: challenge2.map { ($0, words2[$0]) })
        let summary2 = try second.deriveKey(for: .ethereum)
        try await second.importKey()
        let readBack = try await second.verifyReadBack()
        XCTAssertTrue(readBack.matches)
        XCTAssertNotEqual(summary2.fingerprintHex, Hex.encode(firstFingerprint).prefix(8).description)
    }

    /// Restoring the same mnemonic onto a different card must reproduce the same
    /// public key through the full stack.
    func testRestoreThroughTheFullStackReproducesTheKey() async throws {
        let originalTransport = MockYubikeyTransport()
        let (original, _) = makeCeremony(transport: originalTransport)
        try original.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await original.inspectCard()
        try await original.resetCard(adminPIN: Array("12345678".utf8))
        try await original.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await original.applyPolicy()
        try original.generateEntropy()
        let words = try original.generateMnemonic()
        let challenge = try original.transcriptionChallenge()
        try original.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        let originalSummary = try original.deriveKey(for: .ethereum)

        let newTransport = MockYubikeyTransport(serial: 0x1111_2222)
        let (restored, _) = makeCeremony(transport: newTransport)
        try restored.begin(mode: .restoreFromMnemonic, postureConfirmed: true)
        _ = try await restored.inspectCard()
        try await restored.resetCard(adminPIN: Array("12345678".utf8))
        try await restored.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await restored.applyPolicy()
        try restored.restoreMnemonic(words: words)
        let challenge2 = try restored.transcriptionChallenge()
        try restored.confirmTranscription(entries: challenge2.map { ($0, words[$0]) })
        let restoredSummary = try restored.deriveKey(for: .ethereum)
        try await restored.importKey()
        let readBack = try await restored.verifyReadBack()

        XCTAssertEqual(restoredSummary.publicKeyHex, originalSummary.publicKeyHex)
        XCTAssertEqual(readBack.cardPublicKeyHex, originalSummary.publicKeyHex)
        XCTAssertTrue(
            Hex.encode(newTransport.currentFingerprint).hasPrefix(originalSummary.fingerprintHex),
            "the restored card must carry the same key fingerprint"
        )
    }

    /// A card whose public key does not match what was imported (counterfeit, or
    /// tampered firmware) must void the ceremony and wipe the ceremony's secrets.
    func testCounterfeitCardVoidsTheCeremony() async throws {
        let transport = MockYubikeyTransport()
        transport.storedPublicKeyOverride = Array(try Hex.decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ))
        let (ceremony, _) = makeCeremony(transport: transport)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8))
        try await ceremony.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await ceremony.applyPolicy()
        try ceremony.generateEntropy()
        let words = try ceremony.generateMnemonic()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        _ = try ceremony.deriveKey(for: .ethereum)
        try await ceremony.importKey()

        await XCTAssertThrowsErrorAsync { try await ceremony.verifyReadBack() } verify: { error in
            guard case .readBackMismatch = (error as? CeremonyError) else {
                return XCTFail("expected readBackMismatch, got \(error)")
            }
        }
        XCTAssertEqual(ceremony.step, .cardInventory)
        XCTAssertNil(ceremony.derivedKey)
    }

    /// An interruption mid-import is detected as an unresolved mutating step.
    func testInterruptedImportRequiresReinspection() async throws {
        let transport = MockYubikeyTransport()
        let (ceremony, _) = makeCeremony(transport: transport)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8))
        try await ceremony.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await ceremony.applyPolicy()
        try ceremony.generateEntropy()
        let words = try ceremony.generateMnemonic()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        _ = try ceremony.deriveKey(for: .ethereum)

        transport.injectedFailure = .transportError("NFC session invalidated")
        await XCTAssertThrowsErrorAsync { try await ceremony.importKey() }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .cardInventory, "the card state is unknown and must be re-read")
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("re-inspect") })
    }
}
