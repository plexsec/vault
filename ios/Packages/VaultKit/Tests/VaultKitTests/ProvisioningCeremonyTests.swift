import XCTest
@testable import VaultKit

/// Drives the §4.2 ceremony against the scripted card, asserting both the happy
/// path and that every hard gate actually refuses to be skipped.
///
/// One ceremony now provisions **two** keys from one mnemonic: secp256k1 into the
/// signature slot, Ed25519 into the authentication slot. The per-key steps are
/// therefore checked for both keys, including the failure paths.
final class ProvisioningCeremonyTests: XCTestCase {

    /// All-zero 32-byte entropy produces "abandon x23 + art" (the 24-word form;
    /// "abandon x11 + about" is the 12-word form). The expected identities below
    /// were produced by tools/derive and are cross-checked in
    /// testDifferentialDerivationVectors.
    private enum Expected {
        static let evmAddress = "0x1CDE9225FfE472d7426a0e18A3407635F9fA8FDb"
        static let bitcoinAddress = "bc1qrrhfau8tacy745fsdcmvsjtdehkx2xhlge55vyd"
        static let ed25519PublicKey = "20c821b6510834ae1c47084c6f61fd97864d5f12d731f95f4b06fe477b1efb45"
        static let secp256k1Fingerprint = "c774f787"
        static let ed25519Fingerprint = "2d945750"
    }

    private func makeCeremony(
        card: MockSignerCard = MockSignerCard(),
        entropy: [UInt8] = [UInt8](repeating: 0, count: 32),
        date: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> ProvisioningCeremony {
        card.challengeBytes = entropy
        return ProvisioningCeremony(
            card: card,
            systemRandom: { count in SensitiveBytes(count: count) },
            transportDescription: "USB-C (CCID)",
            appVersion: "0.1.0-test",
            clock: { date }
        )
    }

    struct WalkResult {
        let keys: DerivedKeys
        let mnemonic: [String]
    }

    /// Walks steps 1-8 (preflight through derivation). Returns the derived keys
    /// and the mnemonic, because the mnemonic step is deliberately unreachable
    /// once derivation has happened.
    private func runThroughDerivation(
        _ ceremony: ProvisioningCeremony,
        mode: CeremonyMode = .freshGeneration,
        restoredWords: [String]? = nil
    ) async throws -> WalkResult {
        try ceremony.begin(mode: mode, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        if let restoredWords {
            try ceremony.restoreMnemonic(words: restoredWords)
        } else {
            try await ceremony.generateEntropy()
            // Advancing from the entropy step is what derives the words, so
            // "step == .mnemonic" always implies a populated mnemonic.
            try ceremony.advance()
        }
        let words = try ceremony.mnemonicForDisplay()
        XCTAssertEqual(words.count, 24, "the mnemonic must be populated at the mnemonic step")
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        let keys = try ceremony.deriveKeys()
        try ceremony.advance()
        return WalkResult(keys: keys, mnemonic: words)
    }

    /// Steps 9-13: import, read-back, pairing, counter.
    private func completeCeremony(
        _ ceremony: ProvisioningCeremony,
        style: URTypeStyle = .keystoneLegacy,
        chainCodeAcknowledged: Bool = true
    ) async throws -> CeremonyReport {
        _ = try await ceremony.importAndVerify()
        // One step writes the whole card — both keys, then the policy, because writing
        // a slot's algorithm attributes resets that slot and the applet discards its
        // touch policy with it (amendment 26), then the pairing manifest, so that a
        // card is never told to advertise a key that has not been verified to be in it
        // — and reads all of it back before it will advance (amendment 37). A card that
        // cannot store a manifest is a degraded card rather than an abort: the keys and
        // the mnemonic are unaffected.
        try ceremony.advance()
        _ = try ceremony.buildPairingURs(style: style, chainCodeAcknowledged: chainCodeAcknowledged)
        ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()
        _ = try await ceremony.readCounterBaseline()
        try ceremony.advance()
        return ceremony.finish()
    }

    // MARK: Happy path

    func testFreshGenerationHappyPath() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        let walk = try await runThroughDerivation(ceremony)
        let keys = walk.keys

        // Both algorithms are derived from the one mnemonic, at their fixed paths.
        XCTAssertEqual(keys.secp256k1.path.description, "m/44'/0'/0'/0/0")
        XCTAssertEqual(keys.ed25519.path.description, "m/44'/501'/0'/0'")
        XCTAssertEqual(keys.secp256k1.slot, .signature)
        XCTAssertEqual(keys.ed25519.slot, .authentication)

        // One secp256k1 key, two address encodings.
        XCTAssertEqual(keys.secp256k1.evmAddress, Expected.evmAddress)
        XCTAssertEqual(keys.secp256k1.identity, Expected.evmAddress)
        XCTAssertEqual(keys.secp256k1.bitcoinAddress, Expected.bitcoinAddress)
        XCTAssertEqual(keys.secp256k1.fingerprintHex, Expected.secp256k1Fingerprint)

        // Ed25519 identity is the public key itself; no chain-specific address.
        XCTAssertEqual(keys.ed25519.identity, Expected.ed25519PublicKey)
        XCTAssertNil(keys.ed25519.evmAddress)
        XCTAssertNil(keys.ed25519.bitcoinAddress)
        XCTAssertEqual(keys.ed25519.fingerprintHex, Expected.ed25519Fingerprint)
        XCTAssertEqual(keys.ed25519.publicKey.count, 32)
        XCTAssertEqual(keys.secp256k1.publicKey.count, 33)

        let readBack = try await ceremony.importAndVerify()

        // Both keys are in the card, with the fingerprint each was imported with.
        XCTAssertEqual(card.storedPrivateKey(.signature)?.count, 32)
        XCTAssertEqual(card.storedPrivateKey(.authentication)?.count, 32)
        XCTAssertEqual(card.storedFingerprint(.signature), Array(try Hex.decode(Expected.secp256k1Fingerprint)))
        XCTAssertEqual(card.storedFingerprint(.authentication), Array(try Hex.decode(Expected.ed25519Fingerprint)))

        // Both read-backs come out of the same step, and the step only advanced because
        // the card reported them: the keys and the policy are read back inside it
        // (amendment 37).
        XCTAssertEqual(readBack[.secp256k1]?.matches, true)
        XCTAssertEqual(readBack[.ed25519]?.matches, true)
        XCTAssertEqual(readBack[.secp256k1]?.identityFromCardKey, Expected.evmAddress)
        XCTAssertEqual(readBack[.ed25519]?.identityFromCardKey, Expected.ed25519PublicKey)
        XCTAssertEqual(ceremony.report.touchPolicyVerified, true)
        // The step closes on the operator's Continue rather than by itself: the card's
        // own answer has to be on screen first.
        XCTAssertEqual(ceremony.step, .keyImport)
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .pairingExport)

        // Pairing cannot complete without the codes ...
        XCTAssertThrowsError(try ceremony.advance()) { error in
            XCTAssertEqual(
                error as? CeremonyError,
                .stepIncomplete(step: .pairingExport, detail: "the pairing codes have not been produced yet")
            )
        }

        let urs = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
        XCTAssertEqual(urs.count, 2)
        for (_, ur) in urs {
            XCTAssertEqual(ur.type, "crypto-hdkey")
            XCTAssertNoThrow(try UR(urString: ur.string))
        }

        // ... and, with the codes on screen, not until the operator has compared
        // the addresses their wallet shows with the ones in this ceremony.
        XCTAssertThrowsError(try ceremony.advance()) { error in
            XCTAssertEqual(error as? CeremonyError, .pairingAddressNotConfirmed)
        }
        ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .counterBaseline)

        let baseline = try await ceremony.readCounterBaseline()
        XCTAssertEqual(baseline, 0)
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .teardown)
        let report = ceremony.finish()

        XCTAssertNotNil(report.completedAt)
        XCTAssertTrue(report.readBackVerified)
        XCTAssertEqual(report.counterBaseline, 0)
        XCTAssertEqual(report.keys.count, 2)
        XCTAssertEqual(report.key(.secp256k1)?.identity, Expected.evmAddress)
        XCTAssertEqual(report.key(.ed25519)?.identity, Expected.ed25519PublicKey)
        XCTAssertEqual(report.key(.secp256k1)?.pairingURType, "crypto-hdkey")
        XCTAssertTrue(report.pairingIncludedChainCode)
        XCTAssertTrue(ceremony.isFinished)
        // The Ed25519 slot has no counter, which the report must state.
        XCTAssertTrue(report.warnings.contains { $0.contains("no hardware signature counter") })

        // The card call sequence must match design.md §4.2 exactly, with both
        // slots written in a fixed order.
        XCTAssertEqual(card.calls, [
            .inventory, .reset, .inventory, .setPINs,
            // The retry limit is set right after the PINs it applies to, and read
            // back (design.md §4.2 step 3).
            .setPINRetries(user: 3, admin: 3), .inventory,
            .randomBytes(count: 32),
            .importKey(slot: .signature, algorithm: .secp256k1, fingerprint: Expected.secp256k1Fingerprint),
            .importKey(slot: .authentication, algorithm: .ed25519, fingerprint: Expected.ed25519Fingerprint),
            // The policy is written *after* the last key, in the same step, and read
            // back by the read-back that follows it (amendment 26, amendment 32).
            .applyPolicy(adminPIN: Array("87654321".utf8)),
            .readPublicKey(slot: .signature),
            .readPublicKey(slot: .authentication),
            .inventory,
            // The manifest write and the read-back that proves it landed. The
            // byte count is asserted so a format change that would overflow the
            // applet's 254-byte private-use object fails here, not on a card.
            .writePairingManifest(byteCount: 198),
            .readPairingManifest,
            .signatureCounter,
        ])
        XCTAssertEqual(ceremony.report.pairingManifestStored, true)
        XCTAssertEqual(card.pairingManifestBytes?.count, 198)
    }

    /// The two keys must be independent: the same mnemonic at one path must not
    /// produce the same key material for both algorithms.
    func testBothAlgorithmsDeriveDistinctKeys() async throws {
        let ceremony = makeCeremony()
        let keys = try await runThroughDerivation(ceremony).keys
        XCTAssertNotEqual(keys.secp256k1.publicKey, keys.ed25519.publicKey)
        XCTAssertNotEqual(keys.secp256k1.publicKeyHex, keys.ed25519.publicKeyHex)
    }

    /// design.md §8.2: recovery onto a new card must reproduce both keys.
    func testRestoreReproducesBothKeys() async throws {
        let generated = makeCeremony()
        let generatedWalk = try await runThroughDerivation(generated)
        let words = generatedWalk.mnemonic
        let original = generatedWalk.keys

        let restoreCard = MockSignerCard()
        let restored = makeCeremony(card: restoreCard)
        let walk = try await runThroughDerivation(restored, mode: .restoreFromMnemonic, restoredWords: words)
        let recovered = walk.keys

        for algorithm in KeyAlgorithm.allCases {
            XCTAssertEqual(recovered[algorithm].publicKeyHex, original[algorithm].publicKeyHex)
            XCTAssertEqual(recovered[algorithm].identity, original[algorithm].identity)
            XCTAssertEqual(recovered[algorithm].fingerprintHex, original[algorithm].fingerprintHex)
        }
        XCTAssertEqual(recovered.secp256k1.bitcoinAddress, original.secp256k1.bitcoinAddress)

        let report = try await completeCeremony(restored)
        XCTAssertEqual(report.key(.secp256k1)?.identity, original.secp256k1.identity)
        XCTAssertEqual(report.key(.ed25519)?.identity, original.ed25519.identity)
    }

    func testRestoreRejectsInvalidMnemonic() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .restoreFromMnemonic, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        XCTAssertThrowsError(try ceremony.restoreMnemonic(words: Array(repeating: "abandon", count: 12))) { error in
            XCTAssertEqual(error as? BIP39Error, .invalidChecksum)
        }
    }

    // MARK: A failed import must not trap the operator (amendment 29)

    /// The keys are written one slot at a time, so a failure on the second slot
    /// leaves the first holding a key — and the applet refuses to overwrite it. The
    /// ceremony must say so and send the operator back to the reset, because a bare
    /// "import failed" invites a retry that cannot work.
    func testAFailedImportLeavesTheCardPartlyProvisionedAndSaysSo() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)

        // The signature key lands; the authentication import is refused.
        card.refuseImportForSlot = .authentication

        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            guard case .importLeftTheCardPartlyProvisioned(let slots, let detail)? = error as? CeremonyError else {
                return XCTFail("expected importLeftTheCardPartlyProvisioned, got \(error)")
            }
            XCTAssertEqual(slots, ["Signature slot"], "named the way the operator sees them")
            XCTAssertTrue(detail.contains("rejected"), detail)
        }
        XCTAssertEqual(ceremony.step, .cardInventory, "the operator must be sent back to inspection")
        XCTAssertTrue(card.hasKey(in: .signature), "the card really is half provisioned")
    }

    /// And when nothing was written, the original error is reported unchanged —
    /// no ceremony-level noise for a clean failure.
    func testAnImportThatWroteNothingReportsItsOwnError() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        card.failurePoint = .keyImport
        card.refuseImportForSlot = .signature

        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            XCTAssertEqual(error as? CardError, .keyImportRejected)
        }
    }

    // MARK: PIN retry limits (amendment 27)

    /// The operator chooses 3-10 **per password**; the card reports both counters
    /// back, and both choices are recorded in the report.
    func testTheRetryLimitsAreChosenPerPINAndReadBack() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        XCTAssertEqual(ceremony.step, .pinRetries)

        try await ceremony.setPINRetries(user: 6, admin: 4)
        XCTAssertEqual(card.retryLimitUser, 6)
        XCTAssertEqual(card.retryLimitAdmin, 4, "the two numbers must travel independently")
        XCTAssertTrue(card.calls.contains(.setPINRetries(user: 6, admin: 4)))
        XCTAssertEqual(ceremony.report.userPINRetryLimit, 6)
        XCTAssertEqual(ceremony.report.adminPINRetryLimit, 4)
        XCTAssertEqual(ceremony.step, .entropy)
    }

    /// A number outside the offered range never reaches the card — on either input.
    func testARetryLimitOutsideTheOfferedRangeIsRefused() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))

        for value in [2, 11, 0, 100] {
            await XCTAssertThrowsErrorAsync {
                try await ceremony.setPINRetries(user: value, admin: 4)
            } verify: { error in
                XCTAssertEqual(
                    error as? CeremonyError,
                    .invalidRetryLimit(requested: value, allowed: CardPolicy.retryLimits)
                )
            }
            await XCTAssertThrowsErrorAsync {
                try await ceremony.setPINRetries(user: 4, admin: value)
            } verify: { error in
                XCTAssertEqual(
                    error as? CeremonyError,
                    .invalidRetryLimit(requested: value, allowed: CardPolicy.retryLimits)
                )
            }
        }
        XCTAssertFalse(card.calls.contains { if case .setPINRetries = $0 { return true } else { return false } })
        XCTAssertEqual(ceremony.step, .pinRetries, "the step must not advance on a refusal")
        XCTAssertEqual(card.retryLimitUser, 3, "the card keeps the factory value")
        XCTAssertEqual(card.retryLimitAdmin, 3)
    }

    /// A card that answers `9000` and keeps its old counters must stop the
    /// ceremony: a retry limit that only appears to be set is worse than none.
    func testRetryLimitsTheCardDoesNotApplyFailTheCeremony() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))

        card.retryWritesAreIgnored = true
        await XCTAssertThrowsErrorAsync { try await ceremony.setPINRetries(user: 9, admin: 4) } verify: { error in
            guard case .retryLimitsNotApplied(let detail)? = error as? CeremonyError else {
                return XCTFail("expected retryLimitsNotApplied, got \(error)")
            }
            XCTAssertTrue(detail.contains("3"), detail)
            XCTAssertTrue(detail.contains("9"), detail)
            XCTAssertTrue(detail.contains("4"), "both chosen numbers belong in the message: \(detail)")
        }
        XCTAssertEqual(ceremony.step, .pinRetries)
        XCTAssertNil(ceremony.report.userPINRetryLimit)
        XCTAssertNil(ceremony.report.adminPINRetryLimit)
    }

    /// The read-back step re-reads the counters, so a later step silently resetting
    /// them is caught before any pairing code exists.
    func testTheImportStepRechecksTheRetryLimits() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries(user: 8, admin: 5)
        try await ceremony.generateEntropy()
        try ceremony.advance()
        let words = try ceremony.mnemonicForDisplay()
        try ceremony.confirmTranscription(entries: try ceremony.transcriptionChallenge().map { ($0, words[$0]) })
        _ = try ceremony.deriveKeys()
        try ceremony.advance()

        // Something reset the counters behind the ceremony's back (a reset would
        // wipe the keys too, so this stands in for any such disturbance) — and only
        // the Admin PIN's counter moved, which the User PIN's assertion would miss.
        // It is set before the step runs, because the retry limits are re-read inside
        // the same step that wrote them (amendment 37).
        card.inventoryResult.retryCounters = RetryCounters(user: 8, reset: 0, admin: 3)
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            guard case .policyNotApplied(let detail)? = error as? CeremonyError else {
                return XCTFail("expected policyNotApplied, got \(error)")
            }
            XCTAssertTrue(detail.contains("retry limits"), detail)
            XCTAssertTrue(detail.contains("8/3"), "the message must name what the card reported: \(detail)")
        }
        XCTAssertEqual(ceremony.step, .keyImport, "the ceremony must not move on")
        XCTAssertNil(ceremony.report.touchPolicyVerified)
    }

    // MARK: The touch policy is verified, not assumed (amendment 26)

    /// A card that answers `9000` to the policy writes and stores nothing must stop
    /// the ceremony — at the read-back that follows the write.
    ///
    /// This is the failure that produced a card the app believed was protected —
    /// "no signature without a touch" — and which was in fact writing `00 20`. The
    /// read-back is the gate; without it the ceremony cannot tell the two apart.
    func testAPolicyTheCardDoesNotReportBackFailsTheCeremony() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)

        // Every write is answered `9000`; nothing changes on the card. The policy is
        // written by the import step, so the flag goes up before it runs.
        card.uifWritesAreIgnored = true
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            guard case .policyNotApplied(let detail)? = error as? CeremonyError else {
                return XCTFail("expected policyNotApplied, got \(error)")
            }
            XCTAssertTrue(detail.contains("signature slot"), detail)
            XCTAssertTrue(detail.contains("off"), "the message must say what the card reported")
        }
        // The step must not have advanced, the report must not claim success, and the
        // gate must refuse to let the ceremony walk past it — the keys matched, so only
        // the policy check stands between the card and a wallet.
        XCTAssertEqual(ceremony.step, .keyImport)
        XCTAssertNil(ceremony.report.touchPolicyVerified)
        XCTAssertThrowsError(try ceremony.advance()) { error in
            XCTAssertEqual(
                error as? CeremonyError,
                .stepIncomplete(
                    step: .keyImport,
                    detail: "the touch policy has not been confirmed on the card yet"
                )
            )
        }
    }

    /// The policy is written inside the key-import step, after the last key, and the
    /// read-back that follows is what confirms it.
    ///
    /// There is no policy step to order any more. That is the point: the applet
    /// discards a slot's touch policy when that slot's algorithm attributes are
    /// written (amendment 26), so a step of its own could be moved before the import
    /// — where its work would be thrown away while every write still answered
    /// `9000`. What this test can still check is the order of the calls the applet
    /// actually sees, and that the policy write really happens before the read-back
    /// the UI gates on.
    func testThePolicyIsWrittenAfterTheLastKeyImport() async throws {
        // The mode's declared path: the import step is followed directly by the export,
        // with no read-back or manifest step in between for the writes to be separated
        // from their proof (amendment 37).
        let path = CeremonyMode.freshGeneration.path
        let importIndex = try XCTUnwrap(path.firstIndex(of: .keyImport))
        XCTAssertEqual(
            path[importIndex + 1], .pairingExport,
            "nothing may be advertised before the policy is verified"
        )

        // And the call order on a card, which is what the applet actually sees.
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        _ = try await ceremony.importAndVerify()
        XCTAssertEqual(ceremony.step, .keyImport, "the policy write and its proof belong to the import step")
        try ceremony.advance()
        let importCall = try XCTUnwrap(card.calls.lastIndex { if case .importKey = $0 { return true } else { return false } })
        let policyCall = try XCTUnwrap(card.calls.lastIndex { if case .applyPolicy = $0 { return true } else { return false } })
        XCTAssertGreaterThan(
            policyCall, importCall,
            "writing a slot's algorithm attributes drops its touch policy, so the policy goes last"
        )
        XCTAssertEqual(ceremony.report.touchPolicyVerified, true)
        XCTAssertEqual(card.inventoryResult.touchPolicy[.signature], CardPolicy.touchFixed)
        XCTAssertEqual(card.inventoryResult.touchPolicy[.authentication], CardPolicy.touchFixed)
    }

    // MARK: Hard gates

    func testStepsCannotRunOutOfOrder() async throws {
        let ceremony = makeCeremony()
        await XCTAssertThrowsErrorAsync { try await ceremony.inspectCard() } verify: { error in
            XCTAssertEqual(
                error as? CeremonyError,
                .stepOutOfOrder(expected: .notStarted, actual: .cardInventory)
            )
        }

        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        await XCTAssertThrowsErrorAsync {
            try await ceremony.resetCard(acknowledgingDestruction: true)
        }
        await XCTAssertThrowsErrorAsync { try await ceremony.generateEntropy() }
        // The mnemonic cannot be reached without generating entropy first.
        XCTAssertThrowsError(try ceremony.advance())
    }

    func testMnemonicCannotBeReadAfterTheMnemonicStep() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        // We are now on the keyImport step, so the mnemonic must be unreachable.
        XCTAssertThrowsError(try ceremony.mnemonicForDisplay()) { error in
            XCTAssertEqual(error as? CeremonyError, .stepOutOfOrder(expected: .keyImport, actual: .mnemonic))
        }
    }

    func testDerivationRequiresTranscriptionConfirmation() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        try await ceremony.generateEntropy()
        // Without advancing, the mnemonic step is not even due yet, so derivation
        // is refused by the ordering gate.
        XCTAssertThrowsError(try ceremony.deriveKeys())
        try ceremony.advance()
        let words = try ceremony.mnemonicForDisplay()
        XCTAssertEqual(words.count, 24)
        // The ordering gate fires first (the mnemonic step is still due), which is
        // the stronger guarantee; the `mnemonicNotConfirmed` guard is
        // defence-in-depth behind it.
        XCTAssertThrowsError(try ceremony.deriveKeys()) { error in
            XCTAssertEqual(error as? CeremonyError, .stepOutOfOrder(expected: .mnemonic, actual: .derivation))
        }
    }

    func testTranscriptionMismatchIsRejected() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        try await ceremony.generateEntropy()
        try ceremony.advance()
        XCTAssertThrowsError(try ceremony.confirmTranscription(entries: [(5, "wrong")])) { error in
            XCTAssertEqual(error as? CeremonyError, .transcriptionMismatch(index: 5))
        }
        // Case-insensitive, whitespace-tolerant matching is accepted.
        let words = try ceremony.mnemonicForDisplay()
        XCTAssertNoThrow(try ceremony.confirmTranscription(entries: [(0, " \(words[0].uppercased()) ")]))
    }

    /// A used YubiKey is a legitimate re-provisioning target, so inspection must
    /// warn rather than refuse. The hard gate sits on the destructive reset.
    func testUsedYubiKeyWarnsAndRequiresAcknowledgementBeforeReset() async throws {
        let card = MockSignerCard(inventory: CardInventory(
            openPGPVersion: "3.4",
            serial: "12345678",
            algorithmAttributes: [.signature: [0x13, 0x2B, 0x81, 0x04, 0x00, 0x22]],
            pwStatusBytes: [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F],
            occupiedSlots: [.signature],
            signatureCounter: 7,
            isFactoryFresh: false
        ))
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        let inventory = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        XCTAssertTrue(inventory.holdsKey(in: .signature))
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("not factory-fresh") })

        // Refuses to erase a working signer without an explicit acknowledgement.
        await XCTAssertThrowsErrorAsync {
            try await ceremony.resetCard()
        } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .destructiveResetNotAcknowledged)
        }
        XCTAssertEqual(card.resetCount, 0, "the card must not be touched without acknowledgement")

        // With acknowledgement the reset proceeds.
        try await ceremony.resetCard(acknowledgingDestruction: true)
        XCTAssertEqual(card.resetCount, 1)
        XCTAssertEqual(ceremony.step, .pinProvisioning)
    }

    /// A key in the authentication slot alone must also trip the destructive gate.
    func testOccupiedAuthenticationSlotAlsoRequiresAcknowledgement() async throws {
        let card = MockSignerCard(inventory: CardInventory(
            openPGPVersion: "3.4",
            serial: "12345678",
            occupiedSlots: [.authentication],
            signatureCounter: 0,
            isFactoryFresh: false
        ))
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        await XCTAssertThrowsErrorAsync {
            try await ceremony.resetCard()
        } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .destructiveResetNotAcknowledged)
        }
    }

    func testUnsupportedOpenPGPVersionWarnsAndHardGates() async throws {
        let card = MockSignerCard(inventory: CardInventory(
            openPGPVersion: "3.3",
            serial: "12345678",
            isFactoryFresh: true
        ))
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        let inventory = try await ceremony.inspectCard()
        XCTAssertFalse(inventory.likelySupportsSecp256k1)
        XCTAssertTrue(inventory.isDefinitelyUnsupported)
        // The inventory stays readable, but the warning is definitive ...
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("does not support secp256k1/Ed25519") })
        // ... and the ceremony refuses to advance.
        XCTAssertThrowsError(try ceremony.advance()) { error in
            XCTAssertEqual(error as? CeremonyError, .unsupportedAppletVersion(version: "3.3"))
        }
    }

    // MARK: Mandatory verification failures

    func testSecp256k1ReadBackMismatchVoidsTheProcedureAndWipesSecrets() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        // A counterfeit or tampered card returning a different public key. The step
        // reads the keys back inside itself, so the mismatch surfaces from the write's
        // own proof rather than from a screen the operator could walk past.
        card.storedPublicKeyOverride[.signature] = Array(try Hex.decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ))

        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            guard case .readBackMismatch(let algorithm, _, _) = (error as? CeremonyError) else {
                return XCTFail("expected readBackMismatch, got \(error)")
            }
            XCTAssertEqual(algorithm, .secp256k1)
        }
        XCTAssertEqual(ceremony.step, .cardInventory, "must return to card inspection")
        XCTAssertNil(ceremony.derivedKeys, "derived keys must be wiped")
        XCTAssertFalse(ceremony.report.readBackVerified)
    }

    /// The Ed25519 key gets the same treatment: a mismatch there is just as fatal.
    func testEd25519ReadBackMismatchVoidsTheProcedure() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        card.storedPublicKeyOverride[.authentication] = [UInt8](repeating: 0xAB, count: 32)

        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            guard case .readBackMismatch(let algorithm, _, _) = (error as? CeremonyError) else {
                return XCTFail("expected readBackMismatch, got \(error)")
            }
            XCTAssertEqual(algorithm, .ed25519)
        }
        XCTAssertEqual(ceremony.step, .cardInventory)
        XCTAssertNil(ceremony.derivedKeys)
    }

    func testNonZeroCounterBaselineStopsTheCeremony() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        let keys = try await runThroughDerivation(ceremony).keys
        _ = try await ceremony.importAndVerify()
        try ceremony.advance()
        _ = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
        ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()

        // The card has signed something the desktop does not know about.
        card.counterValue = 3
        await XCTAssertThrowsErrorAsync { try await ceremony.readCounterBaseline() } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .counterNotZero(3))
        }
    }

    // MARK: PIN policy

    func testPINPolicyRules() {
        XCTAssertNil(ProvisioningCeremony.validatePINPolicy(
            userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8)
        ))
        XCTAssertNotNil(ProvisioningCeremony.validatePINPolicy(
            userPIN: Array("12345".utf8), adminPIN: Array("87654321".utf8)
        ))
        XCTAssertNotNil(ProvisioningCeremony.validatePINPolicy(
            userPIN: Array("123456".utf8), adminPIN: Array("8765432".utf8)
        ))
        XCTAssertNotNil(ProvisioningCeremony.validatePINPolicy(
            userPIN: Array("123456".utf8), adminPIN: Array("123456".utf8)
        ))
        XCTAssertNotNil(ProvisioningCeremony.validatePINPolicy(
            userPIN: Array("12345a".utf8), adminPIN: Array("87654321".utf8)
        ))
        XCTAssertTrue(ProvisioningCeremony.PINPolicy.adminLockoutIsFatal)
        XCTAssertEqual(ProvisioningCeremony.PINPolicy.minimumUserLength, 6)
        XCTAssertEqual(ProvisioningCeremony.PINPolicy.minimumAdminLength, 8)
    }

    func testWeakPINsAreRejectedBeforeTouchingTheCard() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        await XCTAssertThrowsErrorAsync {
            try await ceremony.setPINs(userPIN: Array("1234".utf8), adminPIN: Array("87654321".utf8))
        }
        XCTAssertEqual(card.pinChangeCount, 0, "the card must not be touched for an invalid PIN policy")
    }

    // MARK: Pairing export

    /// The pairing export must satisfy Keystone/MetaMask's `CryptoHDKey`:
    /// a chain code is mandatory (its absence is what makes MetaMask throw
    /// "Cannot read properties of undefined (reading 'length')"), and the
    /// secp256k1 key is exported at the BIP44 account level with the children
    /// path pinned to the card's leaf so no unsignable sibling is offered.
    func testPairingExportIsKeystoneCompatibleForBothKeys() async throws {
        let ceremony = makeCeremony()
        let walk = try await runThroughDerivation(ceremony)
        _ = try await ceremony.importAndVerify()
        try ceremony.advance()

        let urs = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
        ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()

        // secp256k1: account-level key, chain code, children pinned to 0/0.
        let secp256k1 = try HDKey(ur: try XCTUnwrap(urs[.secp256k1]))
        XCTAssertNotNil(secp256k1.chainCode, "a crypto-hdkey without a chain code crashes MetaMask")
        XCTAssertEqual(secp256k1.keyData.count, 33)
        XCTAssertNotEqual(secp256k1.keyData, walk.keys.secp256k1.publicKey,
                          "the export is the account key, not the leaf")
        XCTAssertEqual(secp256k1.origin?.components,
                       [.hardened(44), .hardened(0), .hardened(0)],
                       "origin must be the BIP44 account level")
        XCTAssertEqual(secp256k1.children?.components, [.normal(0), .normal(0)],
                       "children must pin the derivation to the leaf, with no wildcard")
        XCTAssertEqual(secp256k1.useInfo?.type, 0)
        XCTAssertFalse(secp256k1.isEd25519)
        // `source-fingerprint` is per key, and this is the assertion that says so:
        // the secp256k1 key names the BIP32 master, the Ed25519 key below names
        // the SLIP-0010 master, and the two differ. Both values were produced by
        // the independent oracle (tools/derive) for this mnemonic, so this is a
        // cross-implementation check and not a reading of the app's own output.
        XCTAssertEqual(secp256k1.origin?.sourceFingerprint, 0x5436_d724)
        // Field 9 is not decorative: MetaMask's `getAccountLabel()` does
        // `name[0].toUpperCase()` on the keyring name, which is only ever
        // restored from this field and is otherwise left `undefined` by
        // `BaseKeyring.deserialize()`.
        XCTAssertEqual(secp256k1.name, PairingPolicy.deviceName)

        // Ed25519: exported at its own path, also with a chain code.
        let ed25519 = try HDKey(ur: try XCTUnwrap(urs[.ed25519]))
        XCTAssertNotNil(ed25519.chainCode)
        XCTAssertEqual(ed25519.keyData, walk.keys.ed25519.publicKey)
        XCTAssertEqual(ed25519.origin?.components, walk.keys.ed25519.path.components)
        XCTAssertNil(ed25519.children, "SLIP-0010 is all-hardened; there is nothing to derive")
        XCTAssertEqual(ed25519.useInfo?.type, 501)
        XCTAssertTrue(ed25519.isEd25519)
        XCTAssertEqual(ed25519.name, PairingPolicy.deviceName)
        // The SLIP-0010 master, from the oracle. If this ever equals the
        // secp256k1 value above, one of the two keys is naming a master it does
        // not belong to, and a wallet that trusts it will derive from nothing.
        XCTAssertEqual(ed25519.origin?.sourceFingerprint, 0xb216_0abd)

        XCTAssertTrue(ceremony.report.pairingIncludedChainCode)
        XCTAssertTrue(ceremony.report.warnings.contains(PairingPolicy.chainCodeWarning))
        XCTAssertTrue(ceremony.pairingExports[.secp256k1]?.isAccountLevel == true)
        XCTAssertEqual(ceremony.report.key(.secp256k1)?.pairingPath, "m/44'/0'/0'")
        XCTAssertTrue(ceremony.report.key(.secp256k1)?.pairingAccountLevel == true)
    }

    func testUnacknowledgedChainCodeExportIsRefused() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        _ = try await ceremony.importAndVerify()
        try ceremony.advance()
        XCTAssertThrowsError(try ceremony.buildPairingURs(style: .v2, chainCodeAcknowledged: false)) { error in
            XCTAssertEqual(error as? CeremonyError, .pairingPolicyNotAcknowledged)
        }
    }

    /// The chain-code warning must be recorded exactly once even when the pairing
    /// codes are regenerated (the operator can press "Regenerate").
    func testChainCodeWarningIsRecordedOnce() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        _ = try await ceremony.importAndVerify()
        try ceremony.advance()

        _ = try ceremony.buildPairingURs(style: .v2, chainCodeAcknowledged: true)
        _ = try ceremony.buildPairingURs(style: .v2, chainCodeAcknowledged: true)
        XCTAssertEqual(
            ceremony.report.warnings.filter { $0 == PairingPolicy.chainCodeWarning }.count,
            1
        )
    }

    // MARK: Secret hygiene

    func testReportNeverContainsSecrets() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        let walk = try await runThroughDerivation(ceremony)
        let mnemonic = walk.mnemonic
        let report = try await completeCeremony(ceremony)
        let secp256k1PrivateKey = card.storedPrivateKey(.signature).map { Hex.encode($0) }
        let ed25519PrivateKey = card.storedPrivateKey(.authentication).map { Hex.encode($0) }

        let text = report.printableLines().joined(separator: "\n")
        let json = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)

        // Whole-token comparison: short words like "art" legitimately appear as
        // substrings of report labels ("started"), so substring matching would
        // produce false positives.
        let mnemonicWords = Set(mnemonic.map { $0.lowercased() })
        for (label, document) in [("printout", text), ("encoded report", json)] {
            let leaked = Self.tokens(document).intersection(mnemonicWords)
            XCTAssertTrue(leaked.isEmpty, "\(label) leaked mnemonic words: \(leaked.sorted())")
        }
        for (label, document) in [("printout", text), ("encoded report", json)] {
            if let secp256k1PrivateKey {
                XCTAssertFalse(document.contains(secp256k1PrivateKey), "\(label) leaked the secp256k1 private key")
            }
            if let ed25519PrivateKey {
                // The Ed25519 secret is the derivation seed; the public key is a
                // different value and legitimately appears.
                XCTAssertNotEqual(ed25519PrivateKey, walk.keys.ed25519.identity)
                XCTAssertFalse(document.contains(ed25519PrivateKey), "\(label) leaked the Ed25519 seed")
            }
        }
        // The mnemonic phrase itself must never appear as a contiguous string.
        XCTAssertFalse(text.contains(mnemonic.joined(separator: " ")))
    }

    private static func tokens(_ text: String) -> Set<String> {
        Set(text.lowercased()
            .split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map(String.init))
    }

    func testWipeClearsMnemonicKeysAndPairing() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        XCTAssertNotNil(ceremony.derivedKeys)
        ceremony.wipe()
        XCTAssertNil(ceremony.derivedKeys)
        XCTAssertTrue(ceremony.pairingURs.isEmpty)
        XCTAssertThrowsError(try ceremony.mnemonicForDisplay())
    }

    func testInterruptionDuringMutatingStepForcesReinspection() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .reset)

        // The NFC session drops mid-reset: the card state is now unknown.
        card.failurePoint = .resetTransport
        await XCTAssertThrowsErrorAsync { try await ceremony.resetCard(acknowledgingDestruction: true) }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .cardInventory, "must re-inspect before retrying a mutating step")
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("re-inspect") })
    }

    /// The complement of the test above, for the step that no longer has a
    /// definitive failure mode at all.
    ///
    /// The reset's first act is to block the PINs, so a card that *answered* has
    /// still changed: the attempts that were burnt are gone. There is no "nothing
    /// was written, stay where you are" case here, which is why the reset does not
    /// use `withMutatingStep` — not even for a failure the applet itself reported.
    func testAResetThatCouldNotBlockThePINsStillForcesReinspection() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .reset)

        // The card answered, and what it said was that the counters would not
        // reach zero — a state it is now in, with the keys untouched.
        card.failurePoint = .reset
        await XCTAssertThrowsErrorAsync {
            try await ceremony.resetCard(acknowledgingDestruction: true)
        } verify: { error in
            XCTAssertEqual(error as? CardError, .pinBlockingIncomplete(user: 2, admin: 0))
        }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .cardInventory, "the card changed, so it has to be re-read")
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("tap reset again") })
    }

    /// A rejected key import is likewise definitive: `PUT DATA 3F FF` answered
    /// `6A80`, so the slot is untouched and the ceremony can carry on from there.
    func testRejectedKeyImportDoesNotRewind() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        XCTAssertEqual(ceremony.step, .keyImport)

        card.failurePoint = .keyImport
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.importAndVerify() } verify: { error in
            XCTAssertEqual(error as? CardError, .keyImportRejected)
        }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .keyImport, "a rejected import must not force a card re-read")
    }

    func testInterruptionDuringReadOnlyStepDoesNotRewind() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        // Not a mutating step, so an interruption leaves the position alone.
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .reset)
    }

    // MARK: Entropy policy

    func testEntropyCommitmentIsFirstFourBytesOfSHA256() async throws {
        let entropy: [UInt8] = Array(0...31)
        let ceremony = makeCeremony(entropy: entropy)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        let commitment = try await ceremony.generateEntropy()
        XCTAssertEqual(commitment, Hex.encode(Array(SHA256.hash(entropy).prefix(4))))
        XCTAssertEqual(ceremony.report.entropyCommitmentHex, commitment)
        XCTAssertEqual(commitment.count, 8)
    }

    /// The entropy must be the XOR of the card RNG and the system RNG: either
    /// source being predictable alone must not make the result predictable.
    func testEntropyIsXOROfCardAndSystemRNG() async throws {
        let card = MockSignerCard()
        card.challengeBytes = [UInt8](repeating: 0xAA, count: 32)
        let ceremony = ProvisioningCeremony(
            card: card,
            systemRandom: { count in SensitiveBytes(copying: [UInt8](repeating: 0xFF, count: count)) },
            transportDescription: "USB-C (CCID)",
            appVersion: "0.1.0-test",
            clock: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()

        let commitment = try await ceremony.generateEntropy()
        // 0xAA XOR 0xFF = 0x55
        XCTAssertEqual(commitment, Hex.encode(Array(SHA256.hash([UInt8](repeating: 0x55, count: 32)).prefix(4))))
    }

    func testDiceRollsAreRecordedButNonAuthoritative() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        try ceremony.recordDiceRolls([1, 6, 3, 4])
        XCTAssertThrowsError(try ceremony.recordDiceRolls([7])) { error in
            XCTAssertEqual(error as? CeremonyError, .diceRollsOutOfRange)
        }
        try await ceremony.generateEntropy()
        try ceremony.advance()
        let words = try ceremony.mnemonicForDisplay()
        // All-zero scripted entropy still yields the all-abandon mnemonic even
        // though dice rolls were recorded: dice do not feed the mnemonic in v1.
        XCTAssertEqual(words.first, "abandon")
        XCTAssertEqual(words.last, "art")
        XCTAssertEqual(ceremony.report.diceRolls, [1, 6, 3, 4])
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("Fewer than 99 dice rolls") })
    }

    func testTranscriptionChallengeIsStableAndInRange() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        // The inventory stays on screen; the operator acknowledges it.
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        try await ceremony.generateEntropy()
        try ceremony.advance()
        let first = try ceremony.transcriptionChallenge()
        let second = try ceremony.transcriptionChallenge()
        XCTAssertEqual(first, second)
        XCTAssertEqual(Set(first).count, first.count, "indices must be distinct")
        XCTAssertEqual(first.count, 3)
        XCTAssertTrue(first.allSatisfy { (0..<24).contains($0) })
    }

    // MARK: Printout

    func testPrintableLinesCoverAppendixB() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        let report = try await completeCeremony(ceremony)
        let text = report.printableLines().joined(separator: "\n")
        for expected in ["entropy commitment:", "path:", "key fingerprint:",
                         "yubikey serial:", "openpgp applet:", "read-back verified: yes",
                         "[secp256k1]", "[ed25519]",
                         "evm address:", "bitcoin address:", "identity:",
                         "signature counter baseline", "no hardware signature counter"] {
            XCTAssertTrue(text.contains(expected), "printout missing: \(expected)")
        }
    }

    // MARK: Pairing manifest (design.md §4.2 step 8b)

    /// The card keeps the pairing material, so the codes can be produced again
    /// without resetting the applet — which is the entire point of the step.
    func testTheCeremonyStoresAManifestThatDescribesTheCardsKeys() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        _ = try await completeCeremony(ceremony)

        let stored = try XCTUnwrap(card.pairingManifestBytes)
        let manifest = try PairingManifest.decode(stored)
        XCTAssertEqual(manifest.entries.count, 2)
        XCTAssertEqual(ceremony.report.pairingManifestStored, true)

        // The card's own keys are what the manifest is checked against, and the
        // ceremony performs that check before it will advertise anything.
        let leaf = try XCTUnwrap(card.storedPrivateKey(.signature))
        let ed25519 = try XCTUnwrap(card.storedPrivateKey(.authentication))
        XCTAssertNoThrow(
            try manifest.verify(
                against: CardKeyReport(
                    cardSerial: [0, 0, 0, 0],
                    publicKeys: [
                        .secp256k1: try Secp256k1.publicKey(fromPrivateKey: leaf),
                        .ed25519: try Ed25519.publicKey(fromSeed: ed25519),
                    ]
                )
            )
        )
    }

    /// A card that cannot store a manifest is not a broken card: the keys and the
    /// mnemonic are unaffected, and all that is lost is re-pairing without the
    /// mnemonic later. The ceremony warns and carries on.
    func testACardWithoutThePrivateUseObjectWarnsAndContinues() async throws {
        let card = MockSignerCard(
            inventory: {
                var inventory = MockSignerCard.factoryFreshCard
                inventory.pairingManifest = .unsupported
                return inventory
            }()
        )
        card.supportsPairingManifest = false
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)

        let report = try await completeCeremony(ceremony)

        XCTAssertEqual(report.pairingManifestStored, false)
        XCTAssertTrue(
            report.warnings.contains { $0.contains("no pairing manifest was stored") },
            "the operator must be told the re-pair will need the mnemonic: \(report.warnings)"
        )
        // The ceremony still completed: the pairing codes themselves are fine.
        XCTAssertEqual(report.keys.count, 2)
        for key in report.keys {
            XCTAssertNotNil(key.pairingURType, "the codes are still produced")
        }
    }

    /// Storage that hands back something other than what was written is never
    /// trusted, and the ceremony says so instead of pretending.
    func testAManifestThatDoesNotReadBackIsNotTrusted() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        // The override is in place before the step runs: the manifest is written, and
        // read straight back, inside it.
        card.pairingManifestReadBackOverride = [UInt8](repeating: 0, count: 194)

        _ = try await ceremony.importAndVerify()
        try ceremony.advance()

        XCTAssertNil(ceremony.pairingManifest)
        XCTAssertEqual(ceremony.pairingManifestOutcome?.isStored, false)
        XCTAssertEqual(ceremony.report.pairingManifestStored, false)
        XCTAssertTrue(
            ceremony.report.warnings.contains { $0.contains("did not read back byte-for-byte") },
            "a write that cannot be read back must be reported: \(ceremony.report.warnings)"
        )
        // The step still advances, because the keys are already verified.
        XCTAssertEqual(ceremony.step, .pairingExport)
    }

    /// A wrong Admin PIN at this point is a warning, not a ceremony failure: every
    /// key is already in the card and verified.
    func testAFailedManifestWriteIsAWarningNotAnAbort() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        card.failurePoint = .pairingManifest

        _ = try await ceremony.importAndVerify()
        try ceremony.advance()

        XCTAssertNil(ceremony.pairingManifest)
        XCTAssertTrue(
            ceremony.report.warnings.contains { $0.contains("pairing manifest could not be stored") },
            "expected a warning, got \(ceremony.report.warnings)"
        )
        XCTAssertEqual(card.hasKey(in: .signature), true, "the keys are unaffected")
        XCTAssertEqual(ceremony.step, .pairingExport, "a degraded manifest does not stop the ceremony")
    }

    /// The writes and their proof are one step, so there is no ordering left for the
    /// view layer — or an interruption — to get wrong: no entry point writes the card
    /// without reading it back, and the export cannot be reached before the card has
    /// been written and verified (amendment 37).
    func testTheWritesAndTheirReadBackAreOneStep() async throws {
        let path = CeremonyMode.freshGeneration.path
        let index = try XCTUnwrap(path.firstIndex(of: .keyImport))
        XCTAssertEqual(path[index + 1], .pairingExport, "the export follows the import directly")
        XCTAssertEqual(path.filter { $0 == .keyImport }.count, 1)

        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)

        // The step does not advance on its own and does not take a bare acknowledgement:
        // `importAndVerify` is the only way forward, and it ends with a card the
        // ceremony has read back.
        XCTAssertEqual(ceremony.step, .keyImport)
        XCTAssertThrowsError(try ceremony.advance()) { error in
            XCTAssertEqual(
                error as? CeremonyError,
                .stepIncomplete(step: .keyImport, detail: "the public keys have not been verified yet")
            )
        }
    }

    /// The manifest carries no secret, but it is written to the card and must not
    /// leak into the operator's printed record beyond the fact that it exists.
    func testTheReportDoesNotCarryTheManifestItself() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        let report = try await completeCeremony(ceremony)
        let text = report.printableLines().joined(separator: "\n")

        let manifest = try PairingManifest.decode(try XCTUnwrap(card.pairingManifestBytes))
        let chainCode = try XCTUnwrap(manifest.entry(for: .secp256k1)?.chainCode)
        XCTAssertFalse(
            text.contains(Hex.encode(chainCode)),
            "the chain code belongs on the card, not on the paper record"
        )
    }
}

// MARK: - Async assertion helper
/// `XCTAssertThrowsError` cannot await, so this is the async equivalent with the
/// same call shape.
func XCTAssertThrowsErrorAsync<T>(
    _ expression: () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    verify: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error to be thrown", file: file, line: line)
    } catch {
        verify(error)
    }
}
