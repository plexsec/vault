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
        transport.challengeBytes = entropy
        let card = TransportSessionCard(makeTransport: { transport })
        let ceremony = ProvisioningCeremony(
            card: card,
            systemRandom: { count in SensitiveBytes(count: count) },
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
        try await ceremony.resetCard()
        try await ceremony.setPINs(
            userPIN: Array(Self.userPIN.utf8),
            adminPIN: Array(Self.adminPIN.utf8)
        )
        try await ceremony.setPINRetries()

        if let restoredWords {
            try ceremony.restoreMnemonic(words: restoredWords)
        } else {
            try await ceremony.generateEntropy()
            try ceremony.advance()
        }
        let words = try ceremony.mnemonicForDisplay()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        let keys = try ceremony.deriveKeys()
        try ceremony.advance()
        return (words, keys)
    }

    /// The tail of the ceremony as one step: the keys, the policy and the pairing
    /// manifest are written, and then all of it is read back off the card.
    ///
    /// The policy cannot be written any earlier: writing a slot's algorithm attributes
    /// resets that slot and the applet drops its touch policy with it, so an earlier
    /// write is silently discarded (amendment 26). It is one step with the import and
    /// the read-back, so there is no ordering left to get wrong (amendments 32 and 37).
    @discardableResult
    private func finishProvisioning(_ ceremony: ProvisioningCeremony) async throws -> [KeyAlgorithm: ReadBackResult] {
        let readBack = try await ceremony.importAndVerify()
        // The step closes on the operator's Continue; the tests are the operator here.
        try ceremony.advance()
        return readBack
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

        try await ceremony.resetCard()
        try await ceremony.setPINs(
            userPIN: Array(Self.userPIN.utf8),
            adminPIN: Array(Self.adminPIN.utf8)
        )
        try await ceremony.setPINRetries()

        try await ceremony.generateEntropy()
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

        let readBack = try await ceremony.importAndVerify()
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

        XCTAssertEqual(readBack[.secp256k1]?.matches, true)
        XCTAssertEqual(readBack[.ed25519]?.matches, true)
        XCTAssertEqual(readBack[.secp256k1]?.cardPublicKeyHex, keys.secp256k1.publicKeyHex)
        XCTAssertEqual(readBack[.ed25519]?.cardPublicKeyHex, keys.ed25519.publicKeyHex)

        // The policy was written by the import step, **after** the last key, and the
        // read-back above is what confirmed it. Writing a slot's algorithm attributes
        // resets that slot, and the applet drops its touch policy with it, so the order
        // is the fix for a card that reported `9000` for every write and ended up with
        // touch disabled (amendment 26); doing both in one step is what keeps the order
        // out of reach (amendment 32).
        XCTAssertEqual(transport.currentUIF(.signature), [0x02, 0x20])
        XCTAssertEqual(transport.currentUIF(.authentication), [0x02, 0x20])
        XCTAssertEqual(transport.currentPWStatus.first, 0x00)
        XCTAssertEqual(ceremony.report.touchPolicyVerified, true)

        // The manifest goes to the card itself, through the real APDU layer, inside the
        // same step — this is the write that makes a later re-pair possible without a
        // reset.
        let stored = try XCTUnwrap(ceremony.pairingManifest)
        XCTAssertEqual(transport.storedPairingManifest, stored.encoded())
        // Version 2 carries one master fingerprint per entry: a wallet has two
        // masters (BIP32 and SLIP-0010) and they differ, so a re-pair cannot
        // rebuild the Ed25519 code from a single stored value.
        XCTAssertEqual(stored.encoded().count, 198)
        XCTAssertLessThanOrEqual(stored.encoded().count, PrivateUseDataObject.maximumValueLength)
        XCTAssertEqual(stored.entries.count, 2)
        XCTAssertTrue(
            transport.receivedAPDUs.contains { $0.hasPrefix("00da0102") },
            "the manifest must reach the card as PUT DATA 0x0102"
        )

        // The step closes on the operator's Continue.
        try ceremony.advance()

        let urs = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
        try ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()

        let secp256k1UR = try XCTUnwrap(urs[.secp256k1])
        let secp256k1 = try HDKey(ur: try UR(urString: secp256k1UR.string))
        XCTAssertNotNil(secp256k1.chainCode, "MetaMask requires a chain code on crypto-hdkey")
        XCTAssertNotEqual(secp256k1.keyData, keys.secp256k1.publicKey,
                          "secp256k1 is exported at the account level, not the leaf")
        XCTAssertEqual(secp256k1.origin?.components,
                       [.hardened(44), .hardened(0), .hardened(0)])
        XCTAssertEqual(secp256k1.children?.components, [.normal(0), .normal(0)])
        XCTAssertEqual(secp256k1.useInfo?.type, 0)
        XCTAssertEqual(secp256k1.origin?.sourceFingerprint,
                       UInt32(keys.secp256k1.masterFingerprintHex.prefix(8), radix: 16))

        let ed25519UR = try XCTUnwrap(urs[.ed25519])
        let ed25519 = try HDKey(ur: try UR(urString: ed25519UR.string))
        XCTAssertNotNil(ed25519.chainCode)
        XCTAssertEqual(ed25519.keyData, keys.ed25519.publicKey)
        XCTAssertNil(ed25519.children)
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
        // TERMINATE DF and ACTIVATE FILE are case-1 commands (no Le byte); a Le
        // byte was rejected by real hardware.
        XCTAssertTrue(transport.receivedAPDUs.contains("00e60000"), "TERMINATE DF must be case 1 (no Le)")
        XCTAssertTrue(transport.receivedAPDUs.contains("00440000"), "ACTIVATE FILE must be case 1 (no Le)")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00db3fff") }, "no key import")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("0047810002b600") }, "no signature-slot read")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("0047810002a400") }, "no authentication-slot read")
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00ca007a") }, "no counter read")
        // Both UIF objects must have been written.
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00da00d602022000") })
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00da00d802022000") })
    }

    /// A chosen retry limit (not the factory 3) travels through the APDU layer and
    /// is readable afterwards — **per password**, which is what the two inputs are
    /// for: one `F2` carries both choices, and the card keeps them apart.
    ///
    /// The UI walk raises both pickers to different numbers; this is the same thing
    /// without the simulator.
    func testChosenRetryLimitsReachTheCardPerPIN() async throws {
        let transport = MockYubikeyTransport()
        let (ceremony, _) = makeCeremony(transport: transport)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard()
        try await ceremony.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: Array(Self.adminPIN.utf8))
        try await ceremony.setPINRetries(user: 4, admin: 6)

        // One command carries all three counters: PW1 = 4, the resetting code's byte
        // (inert — this app never sets a resetting code, and the card reports 0 for
        // it, so it carries the User PIN's number), PW3 = 6.
        XCTAssertEqual(transport.receivedAPDUs.last { $0.hasPrefix("00f2") }, "00f2000003" + "040406" + "00")
        XCTAssertEqual(transport.currentRetryLimits.user, 4)
        XCTAssertEqual(transport.currentRetryLimits.admin, 6, "the Admin PIN's limit is its own choice")
        XCTAssertEqual(ceremony.report.userPINRetryLimit, 4)
        XCTAssertEqual(ceremony.report.adminPINRetryLimit, 6)
        XCTAssertEqual(ceremony.step, .entropy)
    }

    // MARK: The touch policy and the key import (amendment 26)

    /// Writing a slot's algorithm attributes resets that slot, and the applet
    /// drops its touch policy with it.
    ///
    /// This is the behaviour that made a provisioned card report `00 20` — touch
    /// off — while every write in the ceremony answered `9000`. It is reproduced
    /// here because the mock has to be able to fail the ordering test below; a
    /// mock that kept the policy across an import would have kept the bug
    /// invisible (the APDU layer and the applet both report success).
    func testImportingAKeyDiscardsThatSlotsTouchPolicy() async throws {
        let transport = MockYubikeyTransport()
        let card = TransportSessionCard(makeTransport: { transport })
        let adminPIN = Array(Self.adminPIN.utf8)

        try await card.reset()
        try await card.setPINs(userPIN: Array(Self.userPIN.utf8), adminPIN: adminPIN)
        try await card.applyPolicy(adminPIN: adminPIN)
        XCTAssertEqual(transport.currentUIF(.signature), OpenPGPTouchPolicy.fixedEncoded)
        XCTAssertEqual(transport.currentUIF(.authentication), OpenPGPTouchPolicy.fixedEncoded)

        try await card.importKey(
            slot: .signature,
            algorithm: .secp256k1,
            privateKey: SensitiveBytes(copying: [UInt8](repeating: 0x11, count: 32)),
            fingerprint: [UInt8](repeating: 0x22, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: adminPIN
        )

        XCTAssertEqual(
            transport.currentUIF(.signature),
            OpenPGPTouchPolicy.offEncoded,
            "the import must drop the slot's touch policy, as the applet does"
        )
        // The other slot was not touched.
        XCTAssertEqual(transport.currentUIF(.authentication), OpenPGPTouchPolicy.fixedEncoded)
    }

    /// With the policy written after the last key import, everything the ceremony
    /// still does to the card leaves it alone.
    ///
    /// This is the other half of the ordering guarantee: it is not enough for the
    /// policy write to land, it has to survive the rest of the run.
    func testPolicyAppliedAfterTheImportSurvivesTheRestOfTheCeremony() async throws {
        let transport = MockYubikeyTransport()
        let (ceremony, _) = makeCeremony(transport: transport)
        _ = try await walkToDerivation(ceremony)
        _ = try await finishProvisioning(ceremony)   // import + policy + manifest, then read-back

        XCTAssertEqual(transport.currentUIF(.signature), OpenPGPTouchPolicy.fixedEncoded)
        XCTAssertEqual(transport.currentUIF(.authentication), OpenPGPTouchPolicy.fixedEncoded)

        // Everything the rest of the ceremony still does to the card.
        _ = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
        try ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()
        _ = try await ceremony.readCounterBaseline()

        XCTAssertEqual(
            transport.currentUIF(.signature),
            OpenPGPTouchPolicy.fixedEncoded,
            "nothing after the policy write may disturb the touch policy"
        )
        XCTAssertEqual(transport.currentUIF(.authentication), OpenPGPTouchPolicy.fixedEncoded)
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
        try await finishProvisioning(first)
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
        // because this card holds a key that may still secure funds — and now that
        // the reset takes no Admin PIN (amendment 30), this acknowledgement is the
        // *only* thing standing between a stray tap and that key.
        await XCTAssertThrowsErrorAsync {
            try await second.resetCard()
        } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .destructiveResetNotAcknowledged)
        }
        XCTAssertEqual(transport.currentFingerprint(.signature), firstFingerprint, "the old key must be untouched")

        // Only after acknowledging the destruction do the slots clear. No PIN is
        // involved: the applet's Admin PIN is the one the first ceremony set, and
        // this call does not ask for it — it blocks it instead.
        try await second.resetCard(acknowledgingDestruction: true)
        XCTAssertFalse(transport.hasKey(in: .signature))
        XCTAssertFalse(transport.hasKey(in: .authentication))
    }

    /// Restoring the same mnemonic onto a different card must reproduce both keys
    /// through the full stack.
    func testRestoreThroughTheFullStackReproducesBothKeys() async throws {
        let originalTransport = MockYubikeyTransport()
        let (original, _) = makeCeremony(transport: originalTransport)
        let originalWalk = try await walkToDerivation(original)
        try await finishProvisioning(original)

        let newTransport = MockYubikeyTransport(serial: 0x1111_2222)
        let (restored, _) = makeCeremony(transport: newTransport)
        let restoredWalk = try await walkToDerivation(
            restored,
            mode: .restoreFromMnemonic,
            restoredWords: originalWalk.mnemonic
        )
        let readBack = try await finishProvisioning(restored)

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

        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
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
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .cardInventory, "the card state is unknown and must be re-read")
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("re-inspect") })
    }
}
