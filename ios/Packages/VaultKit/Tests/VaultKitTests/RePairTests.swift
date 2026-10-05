import XCTest
@testable import VaultKit

/// Read-only re-pair: the pairing codes are recovered from the card itself, with
/// no mnemonic, no PIN and no reset (design.md §4.2 step 7b, the read side).
///
/// The bar these tests hold the mode to is narrow and worth stating: a re-pair
/// must produce **the same bytes** a provisioning ceremony produced, or the two
/// paths disagree about which account the card owns — and it must be impossible
/// for the mode to write to the card at all, because the operator chose it
/// precisely to avoid destroying the keys.
final class RePairTests: XCTestCase {

    private func ceremony(
        for card: MockSignerCard,
        entropy: [UInt8] = [UInt8](repeating: 0, count: 32)
    ) -> ProvisioningCeremony {
        card.challengeBytes = entropy
        return ProvisioningCeremony(
            card: card,
            systemRandom: { count in SensitiveBytes(count: count) },
            transportDescription: "USB-C (CCID)",
            appVersion: "0.1.0-test",
            clock: { Date(timeIntervalSince1970: 1_700_000_000) }
        )
    }

    /// Runs a full provisioning ceremony and returns what it recorded and emitted.
    /// The codes have to be captured here rather than read off the ceremony: the
    /// teardown wipes them, and comparing against them afterwards is the point.
    private func provisionCard(
        _ card: MockSignerCard,
        entropy: [UInt8] = [UInt8](repeating: 0, count: 32)
    ) async throws -> (report: CeremonyReport, urs: [KeyAlgorithm: UR]) {
        let ceremony = ceremony(for: card, entropy: entropy)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        try await ceremony.resetCard(acknowledgingDestruction: true)
        try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await ceremony.setPINRetries()
        try await ceremony.generateEntropy()
        try ceremony.advance()
        let words = try ceremony.mnemonicForDisplay()
        try ceremony.confirmTranscription(entries: try ceremony.transcriptionChallenge().map { ($0, words[$0]) })
        _ = try ceremony.deriveKeys()
        try ceremony.advance()
        _ = try await ceremony.importAndVerify()
        try ceremony.advance()
        let urs = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
        ceremony.confirmPairingAddressMatches(true)
        try ceremony.advance()
        let report = ceremony.finish()
        return (report, urs)
    }

    /// Walks the read-only mode up to the pairing codes.
    private func rePair(_ card: MockSignerCard) async throws -> ProvisioningCeremony {
        let ceremony = ceremony(for: card)
        try ceremony.begin(mode: .rePair, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .rePairRead, "re-pair must not route through the reset step")
        _ = try await ceremony.readPairingManifestFromCard()
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .pairingExport)
        return ceremony
    }

    // MARK: The property the mode exists for

    func testRePairReproducesTheCodesTheCeremonyProduced() async throws {
        let card = MockSignerCard()
        let provisioned = try await provisionCard(card)

        let resetCountBefore = card.resetCount
        let pinChangeCountBefore = card.pinChangeCount
        let policyBefore = card.appliedPolicy
        let keysBefore = KeySlot.allCases.map { card.storedPrivateKey($0) }
        let callsBefore = card.calls.count

        let repaired = try await rePair(card)
        let reproduced = try repaired.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)

        // Byte-for-byte identical, both algorithms. A wallet that paired during
        // provisioning and a wallet that pairs from the card later must land on
        // the same account, so anything weaker than equality here is a defect.
        for algorithm in KeyAlgorithm.allCases {
            XCTAssertEqual(
                reproduced[algorithm]?.string,
                provisioned.urs[algorithm]?.string,
                "\(algorithm.displayName): the re-paired code differs from the provisioned one"
            )
        }
        XCTAssertEqual(repaired.pairingURs.count, KeyAlgorithm.allCases.count)

        // The printed record is the other thing the operator compares, so it must
        // not depend on how the codes were produced either.
        XCTAssertEqual(repaired.report.keys, provisioned.report.keys)

        // Read-only in fact, not just in intent: no destructive call was made and
        // the card's contents are untouched.
        let calls = Array(card.calls.dropFirst(callsBefore))
        XCTAssertEqual(card.resetCount, resetCountBefore)
        XCTAssertEqual(card.pinChangeCount, pinChangeCountBefore)
        XCTAssertEqual(KeySlot.allCases.map { card.storedPrivateKey($0) }, keysBefore)
        XCTAssertFalse(calls.contains(.reset))
        XCTAssertFalse(calls.contains(.setPINs))
        XCTAssertFalse(calls.contains { if case .importKey = $0 { return true }; return false })
        XCTAssertFalse(calls.contains { if case .writePairingManifest = $0 { return true }; return false })
        XCTAssertFalse(calls.contains { if case .putDataObject = $0 { return true }; return false })
        XCTAssertTrue(calls.contains(.readPairingManifest))
        XCTAssertEqual(card.appliedPolicy, policyBefore, "the re-pair must not apply a policy")

        // And no mnemonic was involved anywhere: the cryptographic material this
        // mode needs is a public key and a chain code, not a seed.
        XCTAssertNil(repaired.derivedKeys)
        XCTAssertThrowsError(try repaired.mnemonicForDisplay())

        XCTAssertEqual(repaired.report.mode, .rePair)
        XCTAssertTrue(repaired.report.readBackVerified)
        XCTAssertEqual(repaired.report.pairingManifestStored, true)
    }

    // MARK: Refusals — every one of them leaves the operator with no codes

    func testRePairRefusesACardThatNeverHeldAManifest() async throws {
        let card = MockSignerCard()
        let ceremony = try await startedRePair(card)

        await XCTAssertThrowsErrorAsync { _ = try await ceremony.readPairingManifestFromCard() } verify: { error in
            guard case CeremonyError.noPairingManifest = error else {
                return XCTFail("expected noPairingManifest, got \(error)")
            }
        }
        assertNoCodesWereProduced(ceremony)
    }

    func testRePairRefusesAnAppletWithoutThePrivateUseObject() async throws {
        let card = MockSignerCard()
        _ = try await provisionCard(card)
        // The objects are optional in the spec, so this is a card that can be
        // provisioned but can never be re-paired from.
        card.supportsPairingManifest = false

        let ceremony = try await startedRePair(card)
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.readPairingManifestFromCard() } verify: { error in
            guard case CeremonyError.noPairingManifest(let reason) = error else {
                return XCTFail("expected noPairingManifest, got \(error)")
            }
            XCTAssertTrue(reason.contains("private-use"), "the reason should name the missing object: \(reason)")
        }
        assertNoCodesWereProduced(ceremony)
    }

    func testAResetErasesTheManifestSoAResetCardCannotBeRePaired() async throws {
        let card = MockSignerCard()
        _ = try await provisionCard(card)
        XCTAssertNotNil(card.pairingManifestBytes, "the ceremony should have stored a manifest")

        // `TERMINATE DF` erases the data file. If it did not, a reset card would
        // still hand out codes for keys it no longer holds — the one failure this
        // design must not have.
        try await card.reset()
        XCTAssertNil(card.pairingManifestBytes)

        let ceremony = try await startedRePair(card)
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.readPairingManifestFromCard() } verify: { error in
            guard case CeremonyError.noPairingManifest = error else {
                return XCTFail("expected noPairingManifest, got \(error)")
            }
        }
        assertNoCodesWereProduced(ceremony)
    }

    func testRePairRefusesAManifestWrittenForAnotherWallet() async throws {
        let cardA = MockSignerCard()
        _ = try await provisionCard(cardA)
        let cardB = MockSignerCard()
        _ = try await provisionCard(cardB, entropy: [UInt8](repeating: 1, count: 32))

        // The hostile case the check exists for: a well-formed manifest, correctly
        // checksummed, describing a real wallet — just not this card's.
        let foreign = try XCTUnwrap(cardA.pairingManifestBytes)
        try await cardB.writePairingManifest(foreign, adminPIN: Array("87654321".utf8))

        let ceremony = try await startedRePair(cardB)
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.readPairingManifestFromCard() } verify: { error in
            guard case CeremonyError.pairingManifestRejected(let reason) = error else {
                return XCTFail("expected pairingManifestRejected, got \(error)")
            }
            XCTAssertTrue(reason.contains("secp256k1"), "the reason should name the key that disagreed: \(reason)")
        }
        XCTAssertNil(ceremony.pairingManifest)
        assertNoCodesWereProduced(ceremony)
    }

    func testRePairRefusesAManifestFromAnotherCard() async throws {
        let card = MockSignerCard()
        _ = try await provisionCard(card)
        // Same keys, different card: the serial is what ties a manifest to one
        // YubiKey, so this must be refused even though the keys would match.
        card.inventoryResult.serial = "DEADBEEF"

        let ceremony = try await startedRePair(card)
        await XCTAssertThrowsErrorAsync { _ = try await ceremony.readPairingManifestFromCard() } verify: { error in
            guard case CeremonyError.pairingManifestRejected(let reason) = error else {
                return XCTFail("expected pairingManifestRejected, got \(error)")
            }
            XCTAssertTrue(reason.contains("different YubiKey"), reason)
        }
        assertNoCodesWereProduced(ceremony)
    }

    func testRePairRefusesAManifestThatIsTruncatedOrAltered() async throws {
        for damage in ["truncated", "flipped"] {
            let card = MockSignerCard()
            _ = try await provisionCard(card)
            var bytes = try XCTUnwrap(card.pairingManifestBytes)
            switch damage {
            case "truncated": bytes = Array(bytes.dropLast(3))
            default:
                // One bit in the stored account key: the checksum is the only thing
                // standing between this and handing a wallet a key it cannot spend.
                bytes[12] ^= 0x01
            }
            try await card.writePairingManifest(bytes, adminPIN: Array("87654321".utf8))

            let ceremony = try await startedRePair(card)
            await XCTAssertThrowsErrorAsync { _ = try await ceremony.readPairingManifestFromCard() } verify: { error in
                guard case CeremonyError.pairingManifestRejected(let reason) = error else {
                    return XCTFail("expected pairingManifestRejected for a \(damage) manifest, got \(error)")
                }
                XCTAssertTrue(reason.contains("not a valid pairing manifest"), reason)
            }
            assertNoCodesWereProduced(ceremony)
        }
    }

    // MARK: The mode cannot write, and cannot be entered by accident

    func testRePairCannotReachAnyMutatingOperation() async throws {
        let card = MockSignerCard()
        _ = try await provisionCard(card)
        let ceremony = try await rePair(card)

        await assertStepOutOfOrder {
            try await ceremony.resetCard(acknowledgingDestruction: true)
        }
        await assertStepOutOfOrder {
            try await ceremony.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
            try await ceremony.setPINRetries()
        }
        // `importAndVerify` carries the key writes, the policy and the pairing manifest,
        // so this one assertion covers all of them for the re-pair path (amendment 32,
        // amendment 37).
        await assertStepOutOfOrder { _ = try await ceremony.importAndVerify() }

        XCTAssertEqual(card.resetCount, 1, "only the provisioning ceremony reset the card")
        XCTAssertEqual(card.pinChangeCount, 1)
        XCTAssertTrue(card.appliedPolicy, "policy was applied by provisioning, not by the re-pair")
    }

    func testAProvisioningCeremonyCannotUseTheReadOnlyPath() async throws {
        let card = MockSignerCard()
        let ceremony = ceremony(for: card)
        try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
        _ = try await ceremony.inspectCard()

        await assertStepOutOfOrder { _ = try await ceremony.readPairingManifestFromCard() }

        // …and provisioning still routes the destructive way, which is the whole
        // difference between the two modes.
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .reset)
    }

    func testRePairCannotSkipTheManifestRead() async throws {
        let card = MockSignerCard()
        _ = try await provisionCard(card)

        let ceremony = ceremony(for: card)
        try ceremony.begin(mode: .rePair, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        XCTAssertEqual(ceremony.step, .rePairRead)

        // No codes without the read-and-verify step having happened: the step is a
        // gate, not a screen.
        let error = assertThrows(try ceremony.advance())
        guard case CeremonyError.stepIncomplete(let step, _) = error else {
            return XCTFail("expected stepIncomplete, got \(error)")
        }
        XCTAssertEqual(step, .rePairRead)
        XCTAssertThrowsError(try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true))
    }

    // MARK: The route itself

    func testTheModePathsSayWhatEachCeremonyDoes() {
        for mode in [CeremonyMode.freshGeneration, .restoreFromMnemonic] {
            XCTAssertTrue(mode.path.contains(.reset))
            XCTAssertTrue(mode.path.contains(.keyImport))
        }
        // The read-only route, as data: not one step in it mutates the card, and
        // the destructive ones are absent rather than merely unused.
        let rePair = CeremonyMode.rePair.path
        XCTAssertEqual(rePair.first, .cardInventory)
        XCTAssertEqual(rePair.last, .teardown)
        XCTAssertTrue(rePair.allSatisfy { !$0.isMutatingCardState }, "re-pair must not visit a mutating step")
        XCTAssertTrue(rePair.contains(.rePairRead), "the read step must be on the route")
        XCTAssertFalse(rePair.contains(.reset))
        XCTAssertFalse(rePair.contains(.keyImport), "re-pair reads the manifest, it never writes one")

        // Every mode starts at the same shared first screen, and the progress
        // indicator counts the mode's own route rather than every step that exists.
        XCTAssertTrue(CeremonyMode.allCases.allSatisfy { $0.path.first == .cardInventory })
        XCTAssertLessThan(CeremonyMode.rePair.path.count, CeremonyMode.freshGeneration.path.count)
    }

    // MARK: Helpers

    private func startedRePair(_ card: MockSignerCard) async throws -> ProvisioningCeremony {
        let ceremony = ceremony(for: card)
        try ceremony.begin(mode: .rePair, postureConfirmed: true)
        _ = try await ceremony.inspectCard()
        try ceremony.advance()
        return ceremony
    }

    /// Nothing was handed to a wallet, and nothing can be: the step cannot advance
    /// and no code was ever built.
    private func assertNoCodesWereProduced(
        _ ceremony: ProvisioningCeremony,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(ceremony.pairingURs.isEmpty, file: file, line: line)
        XCTAssertNil(ceremony.pairingManifest, file: file, line: line)
        let error = assertThrows(try ceremony.advance())
        guard case CeremonyError.stepIncomplete(let step, _) = error else {
            return XCTFail("expected stepIncomplete, got \(error)", file: file, line: line)
        }
        XCTAssertEqual(step, .rePairRead, file: file, line: line)
    }

    @discardableResult
    private func assertThrows<T>(
        _ expression: @autoclosure () throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> Error {
        do {
            _ = try expression()
            XCTFail("expected an error to be thrown", file: file, line: line)
            return CeremonyError.notRunning
        } catch {
            return error
        }
    }

    private func assertStepOutOfOrder(
        file: StaticString = #filePath,
        line: UInt = #line,
        _ expression: () async throws -> Void
    ) async {
        do {
            try await expression()
            XCTFail("expected stepOutOfOrder", file: file, line: line)
        } catch let error as CeremonyError {
            guard case .stepOutOfOrder = error else {
                return XCTFail("expected stepOutOfOrder, got \(error)", file: file, line: line)
            }
        } catch {
            XCTFail("expected stepOutOfOrder, got \(error)", file: file, line: line)
        }
    }
}
