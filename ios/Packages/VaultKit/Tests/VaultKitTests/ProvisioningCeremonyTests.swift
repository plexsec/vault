import XCTest
@testable import VaultKit

/// Drives the §4.2 ceremony against the scripted card, asserting both the happy
/// path and that every hard gate actually refuses to be skipped.
final class ProvisioningCeremonyTests: XCTestCase {

    /// All-zero 32-byte entropy produces "abandon x23 + art" (the 24-word form;
    /// "abandon x11 + about" is the 12-word form). The expected address below was
    /// produced by tools/derive and is cross-checked in
    /// testZeroEntropyAddressMatchesIndependentOracle.
    private func makeCeremony(
        card: MockSignerCard = MockSignerCard(),
        entropy: [UInt8] = [UInt8](repeating: 0, count: 32),
        date: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> ProvisioningCeremony {
        ProvisioningCeremony(
            card: card,
            entropySource: ScriptedEntropySource(bytes: entropy),
            transportDescription: "USB-C (CCID)",
            appVersion: "0.1.0-test",
            clock: { date }
        )
    }

    struct WalkResult {
        let summary: DerivedKeySummary
        let mnemonic: [String]
    }

    /// Walks steps 1-8 (preflight through derivation). Returns the derived key
    /// summary and the mnemonic, because the mnemonic step is deliberately
    /// unreachable once derivation has happened.
    private func runThroughDerivation(
        _ ceremony: ProvisioningCeremony,
        chain: SigningChain = .ethereum,
        mode: CeremonyMode = .freshGeneration,
        restoredWords: [String]? = nil
    ) async throws -> WalkResult {
        try ceremony.begin(mode: mode, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        if let restoredWords {
            try ceremony.restoreMnemonic(words: restoredWords)
        } else {
            try ceremony.generateEntropy()
            _ = try ceremony.generateMnemonic()
        }
        let words = try ceremony.mnemonicForDisplay()
        let challenge = try ceremony.transcriptionChallenge()
        try ceremony.confirmTranscription(entries: challenge.map { ($0, words[$0]) })
        let summary = try ceremony.deriveKey(for: chain)
        return WalkResult(summary: summary, mnemonic: words)
    }

    /// Steps 9-14: import, read-back, independent check, pairing, counter.
    private func completeCeremony(
        _ ceremony: ProvisioningCeremony,
        style: URTypeStyle = .keystoneLegacy,
        policy: PairingPolicy = .singleKeyOnly
    ) async throws -> CeremonyReport {
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        let address = ceremony.derivedKey!.address
        _ = try ceremony.submitIndependentCheck(address: address, source: "tools/derive (Python)")
        _ = try ceremony.buildPairingUR(style: style, policy: policy)
        _ = try await ceremony.readCounterBaseline()
        return ceremony.finish()
    }

    // MARK: Happy path

    func testFreshGenerationHappyPath() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        let walk = try await runThroughDerivation(ceremony)

        XCTAssertEqual(walk.summary.chain, .ethereum)
        XCTAssertEqual(walk.summary.address, "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb")
        XCTAssertEqual(walk.summary.path.description, "m/44'/60'/0'/0/0")

        try await ceremony.importKey()
        XCTAssertEqual(card.storedPrivateKey?.count, 32)
        XCTAssertEqual(card.storedFingerprint, Array(try Hex.decode(walk.summary.fingerprintHex)))

        let readBack = try await ceremony.verifyReadBack()
        XCTAssertTrue(readBack.matches)
        XCTAssertEqual(readBack.cardPublicKeyHex, walk.summary.publicKeyHex)
        XCTAssertEqual(readBack.addressFromCardKey, walk.summary.address)

        let check = try ceremony.submitIndependentCheck(
            address: "  0xF278CF59F82EDCF871D630F28ECC8056F25C1CDB ",
            source: "tools/derive (Python)"
        )
        XCTAssertTrue(check.matched, "comparison must be case-insensitive and whitespace tolerant")

        let ur = try ceremony.buildPairingUR(style: .keystoneLegacy)
        XCTAssertEqual(ur.type, "crypto-hdkey")
        XCTAssertNoThrow(try UR(urString: ur.string))

        let baseline = try await ceremony.readCounterBaseline()
        XCTAssertEqual(baseline, 0)
        let report = ceremony.finish()

        XCTAssertNotNil(report.completedAt)
        XCTAssertTrue(report.readBackVerified)
        XCTAssertEqual(report.counterBaseline, 0)
        XCTAssertEqual(report.address, walk.summary.address)
        XCTAssertEqual(report.pairingURType, "crypto-hdkey")
        XCTAssertFalse(report.pairingIncludedChainCode)
        XCTAssertTrue(ceremony.isFinished)

        // The card call sequence must match design.md §4.2 exactly.
        XCTAssertEqual(card.calls, [
            .inventory, .reset, .inventory, .setPINs,
            .applyPolicy(adminPIN: Array("87654321".utf8)), .inventory,
            .importSignatureKey(fingerprint: walk.summary.fingerprintHex),
            .readSignaturePublicKey, .signatureCounter,
        ])
    }

    func testBitcoinChainHappyPath() async throws {
        let ceremony = makeCeremony()
        let walk = try await runThroughDerivation(ceremony, chain: .bitcoin)
        XCTAssertTrue(walk.summary.address.hasPrefix("bc1q"))
        XCTAssertEqual(walk.summary.path.description, "m/84'/0'/0'/0/0")
        XCTAssertTrue(BitcoinAddress.isValidP2WPKH(walk.summary.address))

        let report = try await completeCeremony(ceremony)
        XCTAssertEqual(report.chain, .bitcoin)
        XCTAssertTrue(report.warnings.isEmpty, "clean run should produce no warnings")
    }

    /// design.md §8.2: recovery onto a new card must reproduce the same key.
    func testRestoreReproducesSamePublicKey() async throws {
        let generated = makeCeremony()
        let generatedWalk = try await runThroughDerivation(generated)
        let words = generatedWalk.mnemonic
        let original = generatedWalk.summary

        let restoreCard = MockSignerCard()
        let restored = makeCeremony(card: restoreCard)
        let walk = try await runThroughDerivation(
            restored,
            mode: .restoreFromMnemonic,
            restoredWords: words
        )
        let recovered = walk.summary

        XCTAssertEqual(recovered.publicKeyHex, original.publicKeyHex)
        XCTAssertEqual(recovered.address, original.address)
        XCTAssertEqual(recovered.fingerprintHex, original.fingerprintHex)

        let report = try await completeCeremony(restored)
        XCTAssertEqual(report.address, original.address)
    }

    func testRestoreRejectsInvalidMnemonic() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .restoreFromMnemonic, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        XCTAssertThrowsError(try ceremony.restoreMnemonic(words: Array(repeating: "abandon", count: 12))) { error in
            XCTAssertEqual(error as? BIP39Error, .invalidChecksum)
        }
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
            try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        }
        XCTAssertThrowsError(try ceremony.generateEntropy())
        XCTAssertThrowsError(try ceremony.generateMnemonic())
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
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        try ceremony.generateEntropy()
        _ = try ceremony.generateMnemonic()
        // The ordering gate fires first (the mnemonic step is still due), which is
        // the stronger guarantee; the `mnemonicNotConfirmed` guard is
        // defence-in-depth behind it.
        XCTAssertThrowsError(try ceremony.deriveKey(for: .ethereum)) { error in
            XCTAssertEqual(error as? CeremonyError, .stepOutOfOrder(expected: .mnemonic, actual: .derivation))
        }
    }

    func testTranscriptionMismatchIsRejected() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        try ceremony.generateEntropy()
        _ = try ceremony.generateMnemonic()
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
            algorithmAttributes: [0x13, 0x2B, 0x81, 0x04, 0x00, 0x22],
            pwStatusBytes: [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F],
            hasSignatureKey: true,
            signatureCounter: 7,
            isFactoryFresh: false
        ))
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        let inventory = try await ceremony.inspectCard()
        XCTAssertTrue(inventory.hasSignatureKey)
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("not factory-fresh") })

        // Refuses to erase a working signer without an explicit acknowledgement.
        await XCTAssertThrowsErrorAsync {
            try await ceremony.resetCard(adminPIN: Array("12345678".utf8))
        } verify: { error in
            XCTAssertEqual(error as? CeremonyError, .destructiveResetNotAcknowledged)
        }
        XCTAssertEqual(card.resetCount, 0, "the card must not be touched without acknowledgement")

        // With acknowledgement the reset proceeds.
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        XCTAssertEqual(card.resetCount, 1)
        XCTAssertEqual(ceremony.step, .pinProvisioning)
    }

    func testUnsupportedOpenPGPVersionWarns() async throws {
        let card = MockSignerCard(inventory: CardInventory(
            openPGPVersion: "3.3",
            serial: "12345678",
            isFactoryFresh: true
        ))
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("secp256k1") })
    }

    // MARK: Mandatory verification failures

    func testReadBackMismatchVoidsTheProcedureAndWipesSecrets() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()

        // A counterfeit or tampered card returning a different public key.
        card.storedPublicKeyOverride = Array(try Hex.decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ))

        await XCTAssertThrowsErrorAsync { try await ceremony.verifyReadBack() } verify: { error in
            guard case .readBackMismatch = (error as? CeremonyError) else {
                return XCTFail("expected readBackMismatch, got \(error)")
            }
        }
        XCTAssertEqual(ceremony.step, .cardInventory, "must return to card inspection")
        XCTAssertNil(ceremony.derivedKey, "derived key must be wiped")
        XCTAssertFalse(ceremony.report.readBackVerified)
    }

    func testIndependentCheckMismatchStopsTheCeremony() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()

        XCTAssertThrowsError(try ceremony.submitIndependentCheck(
            address: "0x0000000000000000000000000000000000000000",
            source: "tools/derive"
        )) { error in
            XCTAssertEqual(error as? CeremonyError, .independentCheckFailed)
        }
        XCTAssertEqual(ceremony.step, .cardInventory)
        XCTAssertEqual(ceremony.report.independentCheck?.matched, false)
    }

    func testBitcoinIndependentCheckComparison() async throws {
        let ceremony = makeCeremony()
        let walk = try await runThroughDerivation(ceremony, chain: .bitcoin)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        // Uppercase bech32 is valid and must compare equal.
        _ = try ceremony.submitIndependentCheck(address: walk.summary.address.uppercased(), source: "Coldcard")
        XCTAssertEqual(ceremony.step, .pairingExport)
    }

    func testPairingRequiresIndependentCheckFirst() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        // Ordering gate: the independent-check step is still due.
        XCTAssertThrowsError(try ceremony.buildPairingUR(style: .v2)) { error in
            XCTAssertEqual(error as? CeremonyError, .stepOutOfOrder(expected: .independentCheck, actual: .pairingExport))
        }
    }

    func testNonZeroCounterBaselineStopsTheCeremony() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        _ = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        _ = try ceremony.submitIndependentCheck(address: ceremony.derivedKey!.address, source: "tools/derive")
        _ = try ceremony.buildPairingUR(style: .keystoneLegacy)

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
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        await XCTAssertThrowsErrorAsync {
            try await ceremony.setPINs(userPIN: Array("1234".utf8), adminPIN: Array("87654321".utf8))
        }
        XCTAssertEqual(card.pinChangeCount, 0, "the card must not be touched for an invalid PIN policy")
    }

    // MARK: Pairing policy

    func testDefaultPairingPolicyOmitsChainCode() async throws {
        let ceremony = makeCeremony()
        let walk = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        _ = try ceremony.submitIndependentCheck(address: walk.summary.address, source: "tools/derive")

        let ur = try ceremony.buildPairingUR(style: .keystoneLegacy, policy: .singleKeyOnly)
        let key = try HDKey(ur: ur)
        XCTAssertNil(key.chainCode, "chain code must be omitted so no unsignable children are offered")
        XCTAssertEqual(key.keyData, walk.summary.publicKeyCompressed)
        XCTAssertEqual(key.origin?.components, walk.summary.path.components)
        XCTAssertEqual(key.useInfo?.type, 60)
        XCTAssertFalse(ceremony.report.pairingIncludedChainCode)
    }

    func testUnacknowledgedChainCodeExportIsRefused() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        _ = try ceremony.submitIndependentCheck(address: ceremony.derivedKey!.address, source: "tools/derive")
        XCTAssertThrowsError(try ceremony.buildPairingUR(
            style: .v2,
            policy: .includeChainCode(acknowledgedUnsignableChildren: false)
        )) { error in
            XCTAssertEqual(error as? CeremonyError, .pairingPolicyNotAcknowledged)
        }
    }

    func testAcknowledgedChainCodeExportCarriesWarning() async throws {
        let ceremony = makeCeremony()
        let walk = try await runThroughDerivation(ceremony)
        try await ceremony.importKey()
        _ = try await ceremony.verifyReadBack()
        _ = try ceremony.submitIndependentCheck(address: walk.summary.address, source: "tools/derive")

        let ur = try ceremony.buildPairingUR(
            style: .v2,
            policy: .includeChainCode(acknowledgedUnsignableChildren: true)
        )
        XCTAssertNotNil(try HDKey(ur: ur).chainCode)
        XCTAssertTrue(ceremony.report.pairingIncludedChainCode)
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("cannot sign") })
    }

    // MARK: Secret hygiene

    func testReportNeverContainsSecrets() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        let walk = try await runThroughDerivation(ceremony)
        let mnemonic = walk.mnemonic
        let report = try await completeCeremony(ceremony)
        let privateKeyHex = card.storedPrivateKey.map { Hex.encode($0) }

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
        if let privateKeyHex {
            XCTAssertFalse(text.contains(privateKeyHex), "report leaked the private key")
            XCTAssertFalse(json.contains(privateKeyHex), "encoded report leaked the private key")
        }
        // The mnemonic phrase itself must never appear as a contiguous string.
        XCTAssertFalse(text.contains(mnemonic.joined(separator: " ")))
    }

    private static func tokens(_ text: String) -> Set<String> {
        Set(text.lowercased()
            .split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map(String.init))
    }

    func testWipeClearsMnemonicAndDerivedKey() async throws {
        let ceremony = makeCeremony()
        _ = try await runThroughDerivation(ceremony)
        XCTAssertNotNil(ceremony.derivedKey)
        ceremony.wipe()
        XCTAssertNil(ceremony.derivedKey)
        XCTAssertThrowsError(try ceremony.mnemonicForDisplay())
    }

    func testInterruptionDuringMutatingStepForcesReinspection() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        XCTAssertEqual(ceremony.step, .reset)

        // The NFC session drops mid-`PUT DATA`: the card state is now unknown.
        card.failurePoint = .reset
        await XCTAssertThrowsErrorAsync { try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true) }
        ceremony.noteInterruption()
        XCTAssertEqual(ceremony.step, .cardInventory, "must re-inspect before retrying a mutating step")
        XCTAssertTrue(ceremony.report.warnings.contains { $0.contains("re-inspect") })
    }

    func testInterruptionDuringReadOnlyStepDoesNotRewind() async throws {
        let card = MockSignerCard()
        let ceremony = makeCeremony(card: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
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
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        let commitment = try ceremony.generateEntropy()
        XCTAssertEqual(commitment, Hex.encode(Array(SHA256.hash(entropy).prefix(4))))
        XCTAssertEqual(ceremony.report.entropyCommitmentHex, commitment)
        XCTAssertEqual(commitment.count, 8)
    }

    func testDiceRollsAreRecordedButNonAuthoritative() async throws {
        let ceremony = makeCeremony()
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        try ceremony.recordDiceRolls([1, 6, 3, 4])
        XCTAssertThrowsError(try ceremony.recordDiceRolls([7])) { error in
            XCTAssertEqual(error as? CeremonyError, .diceRollsOutOfRange)
        }
        try ceremony.generateEntropy()
        let words = try ceremony.generateMnemonic()
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
        try await ceremony.resetCard(adminPIN: Array("12345678".utf8), acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.applyPolicy()
        try ceremony.generateEntropy()
        _ = try ceremony.generateMnemonic()
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
        for expected in ["entropy commitment:", "path:", "address:", "key fingerprint:",
                         "yubikey serial:", "openpgp applet:", "signature counter baseline:",
                         "read-back verified: yes", "independent check: MATCH"] {
            XCTAssertTrue(text.contains(expected), "printout missing: \(expected)")
        }
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
