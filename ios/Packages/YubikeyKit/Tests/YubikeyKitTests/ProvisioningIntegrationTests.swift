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
///
/// Both slots are exercised: secp256k1 into the signature slot, Ed25519 into the
/// authentication slot, from one mnemonic.
final class ProvisioningIntegrationTests: XCTestCase {

    private static let adminPIN = "87654321"
    private static let userPIN = "246810"

    /// Identities for the all-zero-entropy mnemonic ("abandon x23 + art"),
    /// produced independently by tools/derive.
    private enum Expected {
        static let evmAddress = "0x1CDE9225FfE472d7426a0e18A3407635F9fA8FDb"
        static let bitcoinAddress = "bc1qrrhfau8tacy745fsdcmvsjtdehkx2xhlge55vyd"
        static let secp256k1PublicKey = "0342d943b8dba93a4ce29b858479c67f1e4f1110eecbe1f83dc01b455eb8b123b3"
        static let ed25519PublicKey = "20c821b6510834ae1c47084c6f61fd97864d5f12d731f95f4b06fe477b1efb45"
    }

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

    /// Steps 1-8 through the real APDU layer. Returns the mnemonic and the
    /// derived keys.
    @discardableResult
    private func walkToDerivation(
        _ ceremony: ProvisioningCeremony,
        mode: CeremonyMode = .freshGeneration,
        restoredWords: [String]? = nil
    ) async throws -> (mnemonic: [String], keys: DerivedKeys) {
        try ceremony.begin(mode: mode, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8))
        try await ceremony.setPINs(
            userPIN: Array(Self.userPIN.utf8),
            adminPIN: Array(Self.adminPIN.utf8)
        )
        try await ceremony.applyPolicy()

        if let restoredWords {
            try ceremony.restoreMnemonic(words: restoredWords)
        } else {
            try ceremony.generateEntropy()
            try ceremony.advance()
        }
        let words = try ceremony.mnemonicForDisplay()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        let keys = try ceremony.deriveKeys()
        try ceremony.advance()
        return (words, keys)
    }

    /// The complete §4.2 flow, with no protocol-level mocking.
    func testFullCeremonyAgainstTheAPDULayer() async throws {
        let transport = MockYubikeyTransport()
        let (ceremony, _) = makeCeremony(transport: transport)

        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)

        let inventory = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        XCTAssertEqual(inventory.openPGPVersion, "3.4")
        XCTAssertFalse(inventory.holdsKey(in: .signature))
        XCTAssertFalse(inventory.holdsKey(in: .authentication))
        XCTAssertTrue(inventory.isFactoryFresh)

        try await ceremony.resetCard(adminPIN: Array("12345678".utf8))
        try await ceremony.setPINs(
            userPIN: Array(Self.userPIN.utf8),
            adminPIN: Array(Self.adminPIN.utf8)
        )
        try await ceremony.applyPolicy()

        // The policy must have landed on both slots, not just in the ceremony.
        XCTAssertEqual(transport.currentUIF(.signature), [0x02, 0x20])
        XCTAssertEqual(transport.currentUIF(.authentication), [0x02, 0x20])
        XCTAssertEqual(transport.currentPWStatus.first, 0x00)
        XCTAssertEqual(transport.currentPWStatus.count, 7)

        try ceremony.generateEntropy()
        try ceremony.advance()

        let words = try ceremony.mnemonicForDisplay()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })

        let keys = try ceremony.deriveKeys()
        try ceremony.advance()
        // The 24-word form of all-zero entropy is "abandon x23 + art", and these
        // identities were produced independently by tools/derive.
        XCTAssertEqual(words.last, "art")
        XCTAssertEqual(keys.secp256k1.evmAddress, Expected.evmAddress)
        XCTAssertEqual(keys.secp256k1.bitcoinAddress, Expected.bitcoinAddress)
        XCTAssertEqual(keys.secp256k1.publicKeyHex, Expected.secp256k1PublicKey)
        XCTAssertEqual(keys.ed25519.identity, Expected.ed25519PublicKey)

        try await ceremony.importKeys()
        // The card really holds both keys: verify against the mock's own state.
        XCTAssertTrue(transport.hasKey(in: .signature))
        XCTAssertTrue(transport.hasKey(in: .authentication))
        // The fingerprint objects (0xC7 / 0xC9) are 20 bytes; the derivation
        // fingerprints are 4 bytes and are zero-padded when written.
        XCTAssertEqual(transport.currentFingerprint(.signature).count, 20)
        XCTAssertTrue(Hex.encode(transport.currentFingerprint(.signature))
            .hasPrefix(keys.secp256k1.fingerprintHex))
        XCTAssertTrue(Hex.encode(transport.currentFingerprint(.authentication))
            .hasPrefix(keys.ed25519.fingerprintHex))

        let readBack = try await ceremony.verifyReadBack()
        try ceremony.advance()
        XCTAssertEqual(readBack[.secp256k1]?.matches, true)
        XCTAssertEqual(readBack[.ed25519]?.matches, true)
        XCTAssertEqual(readBack[.secp256k1]?.cardPublicKeyHex, keys.secp256k1.publicKeyHex)
        XCTAssertEqual(readBack[.ed25519]?.cardPublicKeyHex, keys.ed25519.publicKeyHex)

        let urs = try ceremony.buildPairingURs(style: .keystoneLegacy, policy: .singleKeyOnly)
        try ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()

        let secp256k1UR = try XCTUnwrap(urs[.secp256k1])
        let secp256k1 = try HDKey(ur: try UR(urString: secp256k1UR.string))
        XCTAssertNil(secp256k1.chainCode)
        XCTAssertEqual(secp256k1.keyData, keys.secp256k1.publicKey)
        XCTAssertEqual(secp256k1.useInfo?.type, 0)
        XCTAssertEqual(secp256k1.origin?.sourceFingerprint,
                       UInt32(keys.secp256k1.masterFingerprintHex.prefix(8), radix: 16))

        let ed25519UR = try XCTUnwrap(urs[.ed25519])
        let ed25519 = try HDKey(ur: try UR(urString: ed25519UR.string))
        XCTAssertNil(ed25519.chainCode)
        XCTAssertEqual(ed25519.keyData, keys.ed25519.publicKey)
        XCTAssertTrue(ed25519.isEd25519)
        XCTAssertEqual(ed25519.useInfo?.type, 501)

        let baseline = try await ceremony.readCounterBaseline()
        try ceremony.advance()
        XCTAssertEqual(baseline, 0)

        let report = ceremony.finish()
        XCTAssertTrue(report.readBackVerified)
        XCTAssertEqual(report.counterBaseline, 0)
        XCTAssertEqual(transport.signatureCounter, 0)
        XCTAssertTrue(report.warnings.contains { $0.contains("no hardware signature counter") })

        // The whole exchange must have gone through real APDUs, including per-slot
        // addresses.
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00a40400") }, "no SELECT")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00db3fff") }, "no key import")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("0047810001b600") }, "no signature-slot read")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("0047810001a400") }, "no authentication-slot read")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00ca007a") }, "no counter read")
        // Both UIF objects must have been written.
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00da00d602022000") })
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00da00d802022000") })
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
        try await walkToDerivation(first)
        try await first.importKeys()
        XCTAssertTrue(transport.hasKey(in: .signature))
        XCTAssertTrue(transport.hasKey(in: .authentication))
        let firstFingerprint = transport.currentFingerprint(.signature)

        // Second ceremony on the same key: inventory reports the existing keys,
        // and the reset step is due.
        let (second, _) = makeCeremony(
            transport: transport,
            entropy: [UInt8](repeating: 0xFF, count: 32)
        )
        try second.begin(mode: .freshGeneration, postureConfirmed: true)
        let inventory = try await second.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try second.advance()
        XCTAssertTrue(inventory.holdsKey(in: .signature))
        XCTAssertTrue(inventory.holdsKey(in: .authentication))
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
        XCTAssertEqual(transport.currentFingerprint(.signature), firstFingerprint, "the old key must be untouched")

        // Only after acknowledging the destruction do the slots clear.
        try await second.resetCard(adminPIN: Array(Self.adminPIN.utf8), acknowledgingDestruction: true)
        XCTAssertFalse(transport.hasKey(in: .signature))
        XCTAssertFalse(transport.hasKey(in: .authentication))
    }

    /// Restoring the same mnemonic onto a different card must reproduce both keys
    /// through the full stack.
    func testRestoreThroughTheFullStackReproducesBothKeys() async throws {
        let originalTransport = MockYubikeyTransport()
        let (original, _) = makeCeremony(transport: originalTransport)
        let originalWalk = try await walkToDerivation(original)
        try await original.importKeys()

        let newTransport = MockYubikeyTransport(serial: 0x1111_2222)
        let (restored, _) = makeCeremony(transport: newTransport)
        let restoredWalk = try await walkToDerivation(
            restored,
            mode: .restoreFromMnemonic,
            restoredWords: originalWalk.mnemonic
        )
        try await restored.importKeys()
        let readBack = try await restored.verifyReadBack()

        for algorithm in KeyAlgorithm.allCases {
            XCTAssertEqual(
                restoredWalk.keys[algorithm].publicKeyHex,
                originalWalk.keys[algorithm].publicKeyHex,
                "\(algorithm) key must be reproduced"
            )
            XCTAssertEqual(readBack[algorithm]?.cardPublicKeyHex, originalWalk.keys[algorithm].publicKeyHex)
        }
        XCTAssertTrue(
            Hex.encode(newTransport.currentFingerprint(.signature))
                .hasPrefix(originalWalk.keys.secp256k1.fingerprintHex),
            "the restored card must carry the same key fingerprint"
        )
        XCTAssertTrue(
            Hex.encode(newTransport.currentFingerprint(.authentication))
                .hasPrefix(originalWalk.keys.ed25519.fingerprintHex)
        )
    }

    /// A card whose public key does not match what was imported (counterfeit, or
    /// tampered firmware) must void the ceremony and wipe the ceremony's secrets.
    func testCounterfeitCardVoidsTheCeremony() async throws {
        let transport = MockYubikeyTransport()
        transport.storedPublicKeyOverride[.signature] = Array(try Hex.decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ))
        let (ceremony, _) = makeCeremony(transport: transport)
        try await walkToDerivation(ceremony)
        try await ceremony.importKeys()

        await XCTAssertThrowsErrorAsync { try await ceremony.verifyReadBack() } verify: { error in
            guard case .readBackMismatch = (error as? CeremonyError) else {
                return XCTFail("expected readBackMismatch, got \(error)")
            }
        }
        XCTAssertEqual(ceremony.step, .cardInventory)
        XCTAssertNil(ceremony.derivedKeys)
    }

    /// An interruption mid-import is detected as an unresolved mutating step.
    func testInterruptedImportRequiresReinspection() async throws {
        let transport = MockYubikeyTransport()
        let (ceremony, _) = makeCeremony(transport: transport)
        try await walkToDerivation(ceremony)

        transport.injectedFailure = .transportError("NFC session invalidated")
        await XCTAssertThrowsErrorAsync { try await ceremony.importKeys() }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .cardInventory, "the card state is unknown and must be re-read")
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("re-inspect") })
    }
}
