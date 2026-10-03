import Foundation
import XCTest

@testable import VaultKit

/// The signing ceremony: the gates, the order, and what may never happen twice.
///
/// The card is a `MockSignerCard` that signs with the key from
/// `signing_vectors.json` — signatures produced by `tools/derive`, an independent
/// implementation — so verification, low-s normalisation, recovery-value
/// computation and the export are all exercised against real cryptography rather
/// than against a stub that always agrees.
final class SigningCeremonyTests: XCTestCase {
    static let leafPath = try! DerivationPath("m/44'/0'/0'/0/0")
    static let masterFingerprint = try! Hex.decode("5436d724")
    static let cardSerial = try! Hex.decode("00000000")
    /// The mock card's user PIN ("246810").
    static let userPIN = try! Hex.decode("323436383130")

    // MARK: - Fixture plumbing

    private func makeCard(highS: Bool = false) -> MockSignerCard {
        let card = MockSignerCard(counter: 17)
        card.loadSigningFixtureKey()
        card.returnsHighS = highS
        card.pairingManifestBytes = makeManifestBytes().encoded()
        return card
    }

    /// A manifest whose secp256k1 entry *is* the card's leaf key (`childrenPath`
    /// nil, origin path the leaf), which is the shape a card provisioned at one
    /// fixed path carries once the account-level entry is resolved.
    private func makeManifestBytes(
        publicKey: [UInt8] = MockSignerCard.signingPublicKey,
        originPath: DerivationPath = SigningCeremonyTests.leafPath,
        masterFingerprint: [UInt8] = SigningCeremonyTests.masterFingerprint,
        serial: [UInt8] = SigningCeremonyTests.cardSerial
    ) -> PairingManifest {
        PairingManifest(
            cardSerial: serial,
            entries: [
                PairingManifest.Entry(
                    algorithm: .secp256k1,
                    publicKey: publicKey,
                    chainCode: [UInt8](repeating: 0x11, count: 32),
                    parentFingerprint: try! Hex.decode("6c690f3b"),
                    masterFingerprint: masterFingerprint,
                    originPath: originPath,
                    childrenPath: nil
                )
            ]
        )
    }

    /// A minimal EIP-155 legacy transaction on chain 1 carrying `data`.
    static func legacyPayload(data: [UInt8]) throws -> [UInt8] {
        try RLP.encode(.list([
            .bytes([0x01]),
            .bytes([0x01]),
            .bytes([0x52, 0x08]),
            .bytes(try Hex.decode(EVMTransactionTests.recipient)),
            .bytes([]),
            .bytes(data),
            .bytes(EVMQuantity(1).bytes),
            .bytes([]),
            .bytes([]),
        ]))
    }

    /// The EIP-155 example transaction re-built for chain 137 — the shape whose
    /// recovery value does not fit in one byte. `tools/derive` signs this exact
    /// payload (`legacy_chain_137`), so the mock card can answer it.
    static func polygonPayload() throws -> [UInt8] {
        try RLP.encode(.list([
            .bytes([0x09]),
            .bytes([0x04, 0xa8, 0x17, 0xc8, 0x00]),
            .bytes([0x52, 0x08]),
            .bytes(try Hex.decode(EVMTransactionTests.recipient)),
            .bytes([0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]),
            .bytes([]),
            .bytes(EVMQuantity(137).bytes),
            .bytes([]),
            .bytes([]),
        ]))
    }

    /// The shape MetaMask's `signTransaction` produces: no address field, the
    /// path from the master, the master fingerprint, the chain id, and the
    /// unsigned payload as `sign-data`.
    private func makeRequest(
        payloadHex: String,
        dataType: EVMSignDataType,
        chainID: EVMQuantity?,
        path: DerivationPath = SigningCeremonyTests.leafPath,
        fingerprint: UInt32? = 0x5436_d724,
        address: [UInt8]? = nil,
        requestID: [UInt8] = [UInt8](repeating: 0xab, count: 16)
    ) throws -> UR {
        let request = EthSignRequest(
            requestID: requestID,
            signData: try Hex.decode(payloadHex),
            dataType: dataType,
            chainID: chainID,
            derivationPath: URKeyPath(path: path, sourceFingerprint: fingerprint),
            address: address,
            origin: "app.uniswap.org"
        )
        return try request.ur()
    }

    private func ceremony(
        card: MockSignerCard,
        clock: @escaping () -> Date = Date.init
    ) -> SigningCeremony {
        SigningCeremony(card: card, transportDescription: "mock", appVersion: "test", clock: clock)
    }

    /// Runs everything up to the approval gate, which is where most tests start.
    @discardableResult
    private func advanceToApproval(
        _ ceremony: SigningCeremony,
        card: MockSignerCard,
        payloadHex: String = EVMTransactionTests.eip155Unsigned,
        dataType: EVMSignDataType = .transaction,
        chainID: EVMQuantity? = EVMQuantity(1),
        path: DerivationPath = SigningCeremonyTests.leafPath,
        fingerprint: UInt32? = 0x5436_d724,
        address: [UInt8]? = nil,
        confirmChain: Bool = true
    ) async throws -> SigningCeremony {
        try await ceremony.readCard()
        try ceremony.accept(
            requestUR: try makeRequest(
                payloadHex: payloadHex,
                dataType: dataType,
                chainID: chainID,
                path: path,
                fingerprint: fingerprint,
                address: address
            )
        )
        if confirmChain, let chainID {
            ceremony.confirmChainID(chainID.decimalString)
        }
        try ceremony.verifyRequest()
        return ceremony
    }

    // MARK: - The happy path

    func testSignsALegacyTransactionEndToEnd() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)

        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)

        let signature = try await ceremony.sign(userPIN: try Hex.decode("323436383130"))
        try ceremony.verifySignature(cardResponse: signature)
        let ur = try ceremony.exportSignature()

        // The card was asked to sign exactly the digest the operator approved.
        XCTAssertEqual(card.signedDigests, [try Hex.decode(digest)])
        XCTAssertEqual(card.calls.filter { if case .verifyUserPIN = $0 { return true } else { return false } }.count, 1)

        // v = chainId·2 + 35 + recid: the fixture's recid is 1 on chain 1.
        let fixture = card.signature(named: "eip155_legacy")!
        XCTAssertEqual(ur.type, "eth-signature")
        let exported = try EthSignature(ur: ur)
        XCTAssertEqual(exported.requestID, [UInt8](repeating: 0xab, count: 16))
        XCTAssertEqual(exported.signature.count, 65)
        XCTAssertEqual(exported.recoveryValueBytes, [UInt8(fixture.legacyVChain1)])
        XCTAssertEqual(exported.r.hexString, fixture.r)
        XCTAssertEqual(exported.s.hexString, fixture.s)
        XCTAssertTrue(ceremony.report.signatureVerified)
        XCTAssertEqual(ceremony.report.recoveryValue, "38")
        XCTAssertEqual(ceremony.report.counterBeforeSigning, 17)
        XCTAssertEqual(ceremony.report.counterAfterSigning, 18)
        XCTAssertEqual(ceremony.report.counterDelta, 1)
        XCTAssertEqual(ceremony.report.approvedDigest, digest)
    }

    func testSignsATypedTransactionEndToEnd() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(
            ceremony,
            card: card,
            payloadHex: EVMTransactionTests.feeMarketPayload,
            dataType: .typedTransaction
        )
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.feeMarketPayload),
            dataType: .typedTransaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        try ceremony.verifySignature(cardResponse: try await ceremony.sign(userPIN: Self.userPIN))
        let exported = try EthSignature(ur: try ceremony.exportSignature())

        // Typed transactions carry the y-parity, not an EIP-155 value.
        let fixture = card.signature(named: "fee_market")!
        XCTAssertEqual(exported.recoveryValueBytes, [UInt8(fixture.typedV)])
        XCTAssertEqual(exported.signature.count, 65)
    }

    /// Polygon's ordinary case: an EIP-1559 transaction on chain 137 signs end to end,
    /// and everything the operator is shown names the chain and its coin.
    ///
    /// Polygon needs nothing special from the signing path — its id is like any other —
    /// but "we support POL" should be a test rather than a claim, and the parts that are
    /// Polygon-specific (POL rather than ETH on the screen, a chain id above 110) are
    /// exactly the parts a reader would want pinned.
    func testSignsAPolygonTransactionEndToEnd() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        let payload = try EVMChainTests.feeMarketPayload(
            chainID: 137,
            value: EVMQuantity(1_500_000_000_000_000_000)
        )
        try await advanceToApproval(
            ceremony,
            card: card,
            payloadHex: payload.hexString,
            dataType: .typedTransaction,
            chainID: EVMQuantity(137)
        )

        let transaction = try EVMTransaction(signData: payload, dataType: .typedTransaction)
        let summary = try XCTUnwrap(ceremony.summary)
        XCTAssertEqual(summary.chain?.name, "Polygon")
        XCTAssertTrue(summary.value.contains("1.5 POL"), summary.value)
        XCTAssertFalse(summary.value.contains("ETH"), summary.value)

        try ceremony.approve(acknowledgingDigestHex: transaction.signingDigest.hexString)
        try ceremony.verifySignature(cardResponse: try await ceremony.sign(userPIN: Self.userPIN))
        let exported = try EthSignature(ur: try ceremony.exportSignature())

        XCTAssertEqual(ceremony.report.chainDisplay, "Polygon (chain id 137)")
        XCTAssertEqual(ceremony.report.nativeValueDisplay, "1.5 POL (1500000000000000000 wei)")
        XCTAssertTrue(ceremony.report.signatureVerified)
        XCTAssertEqual(ceremony.report.counterDelta, 1)
        // The signature is real: the mock returned what tools/derive signed over this
        // digest. `s` in the fixture is the raw RFC6979 value, and for this digest it is
        // already ≥ n/2 — so the ordinary Polygon path also exercises EIP-2
        // normalisation, and the recovery value that goes out is the flipped one.
        let fixture = try XCTUnwrap(card.signature(named: "fee_market_chain_137"))
        XCTAssertEqual(fixture.digest, transaction.signingDigest.hexString)
        XCTAssertTrue(ceremony.report.signatureWasLowS, "the fixture's raw s is the high form")
        XCTAssertEqual(exported.r.hexString, fixture.r)
        XCTAssertEqual(exported.s.hexString, fixture.highS, "normalised to the low form")
        XCTAssertEqual(exported.recoveryValueBytes, [UInt8(fixture.recidHighS)])
        // Typed transactions carry the y-parity, so Polygon's 1559 case fits the 65-byte
        // layout; only its legacy case needs the wider field.
        XCTAssertEqual(exported.signature.count, 65)
        XCTAssertFalse(ceremony.report.wideRecoveryValue)
        XCTAssertEqual(exported.requestID, [UInt8](repeating: 0xab, count: 16))
    }

    /// The chain table is a display convenience, and this is the test that keeps it that
    /// way: a chain id nobody has heard of is confirmed and signed exactly like a named
    /// one. If someone ever turns the table into a whitelist, this fails.
    func testAnUnknownChainIDIsStillSignable() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        let payload = try EVMChainTests.feeMarketPayload(chainID: 424242, value: EVMQuantity(1))
        try await advanceToApproval(
            ceremony,
            card: card,
            payloadHex: payload.hexString,
            dataType: .typedTransaction,
            chainID: EVMQuantity(424_242)
        )
        let transaction = try EVMTransaction(signData: payload, dataType: .typedTransaction)
        try ceremony.approve(acknowledgingDigestHex: transaction.signingDigest.hexString)
        try ceremony.verifySignature(cardResponse: try await ceremony.sign(userPIN: Self.userPIN))
        _ = try ceremony.exportSignature()

        XCTAssertTrue(ceremony.report.signatureVerified)
        XCTAssertNil(ceremony.report.chain?.name, "no name is invented for an unknown chain")
        XCTAssertEqual(ceremony.report.chainDisplay, "chain id 424242 (not a chain this app knows)")
    }

    /// A card that returns `s > n/2` must be normalised, and the recovery value
    /// must flip with it — otherwise the transaction is invalid on a rule
    /// (EIP-2) that has nothing to do with whether the signature is genuine.
    func testHighSSignatureIsNormalisedAndTheRecoveryValueFlips() async throws {
        let card = makeCard(highS: true)
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        try ceremony.verifySignature(cardResponse: try await ceremony.sign(userPIN: Self.userPIN))
        let exported = try EthSignature(ur: try ceremony.exportSignature())

        let fixture = card.signature(named: "eip155_legacy")!
        // The low-s form, with the recovery value that goes with it.
        XCTAssertEqual(exported.s.hexString, fixture.s)
        XCTAssertEqual(exported.recoveryValueBytes, [UInt8(fixture.legacyVChain1)])
        XCTAssertTrue(ceremony.report.signatureWasLowS)
    }

    /// A legacy EIP-155 transaction on a chain whose id does not fit the one-byte
    /// recovery value: the field grows rather than carrying a wrong `v`.
    func testWideRecoveryValueOnPolygon() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        let payload = try Self.polygonPayload()
        try await advanceToApproval(
            ceremony,
            card: card,
            payloadHex: payload.hexString,
            chainID: EVMQuantity(137)
        )
        let transaction = try EVMTransaction(signData: payload, dataType: .transaction)
        try ceremony.approve(acknowledgingDigestHex: transaction.signingDigest.hexString)
        try ceremony.verifySignature(cardResponse: try await ceremony.sign(userPIN: Self.userPIN))
        let exported = try EthSignature(ur: try ceremony.exportSignature())

        // 137·2 + 35 + recid is 309 or 310, so the field needs two bytes.
        XCTAssertEqual(exported.signature.count, 66)
        XCTAssertTrue(ceremony.report.wideRecoveryValue)
        var recovery: UInt64 = 0
        for byte in exported.recoveryValueBytes { recovery = recovery << 8 | UInt64(byte) }
        XCTAssertTrue([309, 310].contains(recovery), "got \(recovery)")
    }

    // MARK: - The gates

    func testSignatureIsRefusedWithoutTheOperatorsApproval() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await ceremony.sign(userPIN: Self.userPIN)
        }
        XCTAssertEqual(error as? SigningError, .wrongStep(expected: .approved, actual: .requestVerified))
        XCTAssertEqual(card.signedDigests.count, 0, "the card must not be asked to sign before approval")
    }

    /// Approving one payload must not carry over to another: the digest shown is
    /// checked against the digest to be signed.
    func testApprovalIsBoundToTheDigestThatWasShown() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        XCTAssertThrowsError(try ceremony.approve(acknowledgingDigestHex: String(repeating: "0", count: 64))) {
            guard case .signatureVerificationFailed = ($0 as? SigningError) else {
                return XCTFail("got \($0)")
            }
        }
        XCTAssertThrowsError(try ceremony.approve(acknowledgingDigestHex: ""))
    }

    /// design.md §5.2 rule 1: one transaction buys exactly one `PSO:CDS`. A retry
    /// is refused by the state machine, not by the transport.
    func testASecondSignatureForTheSameRequestIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        _ = try await ceremony.sign(userPIN: Self.userPIN)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await ceremony.sign(userPIN: Self.userPIN)
        }
        XCTAssertEqual(error as? SigningError, .signatureAlreadyAttempted)
        XCTAssertEqual(card.signedDigests.count, 1)
        XCTAssertEqual(ceremony.report.signatureAttempts, 1)
    }

    func testUnconfirmedChainIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        do {
            try await advanceToApproval(ceremony, card: card, confirmChain: false)
            XCTFail("an unconfirmed chain id must not reach approval")
        } catch {
            XCTAssertEqual(error as? SigningError, .chainNotConfirmed(chainID: "1"))
        }
        XCTAssertEqual(ceremony.step, .requestDecoded)
    }

    /// A chain the operator has confirmed once stays confirmed for the session —
    /// but the confirmation has to name the id, so it cannot be a blanket "yes".
    func testConfirmingAChainUnblocksExactlyThatChain() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await ceremony.readCard()
        try ceremony.accept(
            requestUR: try makeRequest(
                payloadHex: EVMTransactionTests.eip155Unsigned,
                dataType: .transaction,
                chainID: EVMQuantity(1)
            )
        )
        ceremony.confirmChainID("137")
        XCTAssertThrowsError(try ceremony.verifyRequest()) {
            XCTAssertEqual($0 as? SigningError, .chainNotConfirmed(chainID: "1"))
        }
        ceremony.confirmChainID("1")
        XCTAssertNoThrow(try ceremony.verifyRequest())
    }

    func testRequestForAnotherPathIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        let other = try DerivationPath("m/44'/0'/0'/0/1")
        do {
            try await advanceToApproval(ceremony, card: card, path: other)
            XCTFail("a sibling path must be refused: the card holds one key")
        } catch {
            XCTAssertEqual(
                error as? SigningError,
                .requestPathNotPinned(requested: other.description, pinned: Self.leafPath.description)
            )
        }
    }

    func testRequestFromAnotherMasterIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        do {
            try await advanceToApproval(ceremony, card: card, fingerprint: 0xdead_beef)
            XCTFail("a request from another wallet's master must be refused")
        } catch {
            XCTAssertEqual(
                error as? SigningError,
                .requestFingerprintMismatch(requested: "deadbeef", expected: "5436d724")
            )
        }
    }

    func testRequestNamingAnotherAddressIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        do {
            try await advanceToApproval(
                ceremony,
                card: card,
                address: [UInt8](repeating: 0x22, count: 20)
            )
            XCTFail("an address the card cannot sign for must be refused")
        } catch {
            guard case .requestAddressMismatch = (error as? SigningError) else {
                return XCTFail("got \(error)")
            }
        }
    }

    func testCardWithoutAManifestCannotSign() async throws {
        let card = MockSignerCard()
        card.pairingManifestBytes = nil
        let ceremony = ceremony(card: card)
        let error = await XCTAssertThrowsErrorAsync { try await ceremony.readCard() }
        XCTAssertEqual(error as? SigningError, .noPairingManifest)
    }

    /// A manifest that describes a different key is worse than no manifest: it
    /// would put an address on screen that the card cannot sign for.
    func testManifestDescribingAnotherKeyIsRefused() async throws {
        let card = MockSignerCard()
        card.loadSigningFixtureKey()
        card.pairingManifestBytes = makeManifestBytes(
            publicKey: try Secp256k1.publicKey(fromPrivateKey: [UInt8](repeating: 0x33, count: 32))
        ).encoded()
        let ceremony = ceremony(card: card)
        let error = await XCTAssertThrowsErrorAsync { try await ceremony.readCard() }
        guard case .signatureVerificationFailed = (error as? SigningError) else {
            return XCTFail("got \(String(describing: error))")
        }
    }

    func testManifestFromAnotherCardSerialIsRefused() async throws {
        let card = MockSignerCard()
        card.loadSigningFixtureKey()
        card.pairingManifestBytes = makeManifestBytes(serial: try Hex.decode("deadbeef")).encoded()
        let ceremony = ceremony(card: card)
        let error = await XCTAssertThrowsErrorAsync { try await ceremony.readCard() }
        guard case .signatureVerificationFailed = (error as? SigningError) else {
            return XCTFail("got \(String(describing: error))")
        }
    }

    // MARK: - Request shapes that must be refused

    func testNonTransactionDataTypesAreRefused() async throws {
        for dataType: EVMSignDataType in [.typedData, .personalMessage] {
            let card = makeCard()
            let ceremony = ceremony(card: card)
            try await ceremony.readCard()
            let request = EthSignRequest(
                requestID: [UInt8](repeating: 0, count: 16),
                signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
                dataType: dataType,
                chainID: EVMQuantity(1),
                derivationPath: URKeyPath(path: Self.leafPath, sourceFingerprint: 0x5436_d724),
                address: nil,
                origin: nil
            )
            XCTAssertThrowsError(try ceremony.accept(requestUR: try request.ur())) { error in
                guard case .unsupportedDataType = (error as? SigningError) else {
                    return XCTFail("\(dataType): got \(error)")
                }
            }
        }
    }

    /// The `chain-id` field and the chain id inside the payload must agree: they
    /// both decide what is signed, so a disagreement is a request to stop.
    func testChainIDMismatchBetweenFieldAndPayloadIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await ceremony.readCard()
        let request = EthSignRequest(
            requestID: [UInt8](repeating: 0, count: 16),
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction,
            chainID: EVMQuantity(137),
            derivationPath: URKeyPath(path: Self.leafPath, sourceFingerprint: 0x5436_d724),
            address: nil,
            origin: nil
        )
        XCTAssertThrowsError(try ceremony.accept(requestUR: try request.ur())) { error in
            XCTAssertEqual(error as? SigningError, .chainIDMismatch(request: "137", transaction: "1"))
        }
    }

    func testTypedRequestWithALegacyPayloadIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await ceremony.readCard()
        XCTAssertThrowsError(
            try ceremony.accept(
                requestUR: try makeRequest(
                    payloadHex: EVMTransactionTests.eip155Unsigned,
                    dataType: .typedTransaction,
                    chainID: EVMQuantity(1)
                )
            )
        )
    }

    func testWrongURTypeIsRefused() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await ceremony.readCard()
        XCTAssertThrowsError(
            try ceremony.accept(
                requestUR: try UR(type: "eth-signature", cbor: .tagged(402, .map([])))
            )
        )
    }

    func testStepsMustBeTakenInOrder() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        // accept before readCard
        let error = await XCTAssertThrowsErrorAsync {
            try ceremony.accept(
                requestUR: try makeRequest(
                    payloadHex: EVMTransactionTests.eip155Unsigned,
                    dataType: .transaction,
                    chainID: EVMQuantity(1)
                )
            )
        }
        XCTAssertEqual(error as? SigningError, .wrongStep(expected: .cardRead, actual: .notStarted))
    }

    // MARK: - Card failures

    func testMalformedCardSignatureIsRefused() async throws {
        let card = makeCard()
        card.signingBehaviour = .normal
        card.storedPublicKeyOverride[.signature] = MockSignerCard.signingPublicKey
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        _ = try await ceremony.sign(userPIN: Self.userPIN)
        XCTAssertThrowsError(try ceremony.verifySignature(cardResponse: [0x30, 0x01, 0x02])) { error in
            guard case .cardSignatureMalformed = (error as? SigningError) else {
                return XCTFail("got \(error)")
            }
        }
        XCTAssertThrowsError(try ceremony.verifySignature(cardResponse: [UInt8](repeating: 0, count: 80))) {
            XCTAssertEqual($0 as? SigningError, .signatureTooLarge(80))
        }
    }

    /// A signature that recovers a key other than the card's must not be exported.
    /// A card answering with the wrong slot's key is exactly this case.
    func testSignatureFromAnotherKeyIsRefused() async throws {
        // The card reports a key it does not sign with: the manifest agrees with
        // the reported key, so the failure has to come from the signature itself.
        let ceremonyCard = MockSignerCard(counter: 1)
        ceremonyCard.loadSigningFixtureKey()
        ceremonyCard.pairingManifestBytes = makeManifestBytes().encoded()
        ceremonyCard.storedPublicKeyOverride[.signature] = try Secp256k1.publicKey(
            fromPrivateKey: [UInt8](repeating: 0x44, count: 32)
        )
        // The manifest must still describe the key the card reports, so this
        // manifest is built from that key: the failure then has to come from the
        // signature itself.
        ceremonyCard.pairingManifestBytes = makeManifestBytes(
            publicKey: ceremonyCard.storedPublicKeyOverride[.signature]!
        ).encoded()
        let ceremony = ceremony(card: ceremonyCard)
        try await advanceToApproval(ceremony, card: ceremonyCard)
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        let response = try await ceremony.sign(userPIN: Self.userPIN)
        XCTAssertThrowsError(try ceremony.verifySignature(cardResponse: response)) { error in
            XCTAssertEqual(
                error as? SigningError,
                .signatureVerificationFailed(
                    "no recovery value 0 or 1 makes the signature recover this card's key"
                )
            )
        }
        XCTAssertNil(ceremony.signatureUR, "nothing may be exported for a signature that does not check out")
        XCTAssertFalse(ceremony.report.signatureVerified)
    }

    func testWrongPINIsReportedWithItsReason() async throws {
        let card = makeCard()
        card.signingBehaviour = .wrongPIN(retriesRemaining: 2)
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await ceremony.sign(userPIN: Self.userPIN)
        }
        guard case .pinRejected(let reason) = (error as? SigningError) else {
            return XCTFail("got \(String(describing: error))")
        }
        XCTAssertTrue(reason.lowercased().contains("pin") || reason.contains("2"), reason)
        XCTAssertEqual(card.signedDigests.count, 0)
    }

    /// A lost response is the worst case in this flow: the card may have signed.
    /// The app must not try again, and must record that it does not know.
    func testLostSignatureResponseIsNotRetried() async throws {
        let card = makeCard()
        card.failurePoint = .signatureTransport
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let digest = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        ).signingDigest.hexString
        try ceremony.approve(acknowledgingDigestHex: digest)
        let error = await XCTAssertThrowsErrorAsync {
            _ = try await ceremony.sign(userPIN: Self.userPIN)
        }
        guard case .cardSignatureMalformed = (error as? SigningError) else {
            return XCTFail("got \(String(describing: error))")
        }
        let retry = await XCTAssertThrowsErrorAsync {
            _ = try await ceremony.sign(userPIN: Self.userPIN)
        }
        XCTAssertEqual(retry as? SigningError, .signatureAlreadyAttempted)
        // The card was asked exactly once. It may well have signed — that is
        // precisely why the app must not ask again.
        XCTAssertEqual(card.signedDigests.count, 1)
        XCTAssertNotNil(ceremony.report.signingFailedReason)
    }

    // MARK: - What the operator sees

    func testSummaryIsBuiltFromTheDecodedTransaction() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(ceremony, card: card)
        let summary = try XCTUnwrap(ceremony.summary)
        XCTAssertEqual(summary.chainID, "1")
        XCTAssertEqual(summary.kind, "legacy")
        XCTAssertEqual(summary.value, "1 ETH (1000000000000000000 wei)")
        XCTAssertEqual(summary.recipient, "0x3535353535353535353535353535353535353535")
        XCTAssertNil(summary.call)
        XCTAssertNil(summary.decodeWarning, "empty calldata is not an unparsed call")
        XCTAssertEqual(summary.headline, "Send 1 ETH (1000000000000000000 wei)")

        // The rows the operator must not skim past.
        XCTAssertTrue(summary.rows.contains { $0.label == "Value" && $0.isCritical })
        XCTAssertTrue(summary.rows.contains { $0.label == "To" && $0.isCritical })
    }

    func testErc20TransferSummaryAndWarnings() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        try await advanceToApproval(
            ceremony,
            card: card,
            payloadHex: EVMTransactionTests.accessListPayload,
            dataType: .typedTransaction,
            chainID: EVMQuantity(1)
        )
        let summary = try XCTUnwrap(ceremony.summary)
        XCTAssertEqual(summary.call?.name, "transfer")
        XCTAssertEqual(summary.headline, "Send 1000000 (raw units) to 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
        XCTAssertNil(summary.decodeWarning)
        // An ERC-20 amount is raw units: the token's decimals are not in the call.
        XCTAssertTrue(summary.rows.contains { $0.value.contains("raw units") })
    }

    func testUndecodableCalldataIsFlaggedNotHidden() async throws {
        let card = makeCard()
        let ceremony = ceremony(card: card)
        // Unknown selector with well-formed ABI padding.
        let data = try Hex.decode("deadbeef") + [UInt8](repeating: 0, count: 32)
        let payload = try Self.legacyPayload(data: data)
        try await advanceToApproval(
            ceremony,
            card: card,
            payloadHex: payload.hexString,
            chainID: EVMQuantity(1)
        )
        let summary = try XCTUnwrap(ceremony.summary)
        XCTAssertNil(summary.call)
        XCTAssertEqual(summary.decodeWarning, TransactionSummary.undecodableWarning)
        XCTAssertEqual(summary.rawDataHex, "0x" + data.hexString)
        XCTAssertTrue(summary.headline.contains("Call a contract"))
    }

    func testApprovalWarningsCoverTheDangerousCalls() async throws {
        let card = makeCard()
        let first = ceremony(card: card)
        // setApprovalForAll(operator, true)
        let data = try Hex.decode("a22cb465")
            + [UInt8](repeating: 0, count: 12) + [UInt8](repeating: 0x22, count: 20)
            + [UInt8](repeating: 0, count: 31) + [0x01]
        let payload = try Self.legacyPayload(data: data)
        try await advanceToApproval(
            first,
            card: card,
            payloadHex: payload.hexString,
            chainID: EVMQuantity(1)
        )
        let warnings = first.approvalWarnings
        XCTAssertTrue(
            warnings.contains { $0.contains("control of every token") },
            "the classic drainer call must be called out: \(warnings)"
        )
        // No duplicates: each warning appears once.
        XCTAssertEqual(Set(warnings).count, warnings.count)

        // An unlimited approval is flagged as well.
        let approveData = try Hex.decode("095ea7b3")
            + [UInt8](repeating: 0, count: 12) + [UInt8](repeating: 0x22, count: 20)
            + [UInt8](repeating: 0xff, count: 32)
        let approvePayload = try Self.legacyPayload(data: approveData)
        let secondCard = makeCard()
        let second = ceremony(card: secondCard)
        try await advanceToApproval(
            second,
            card: secondCard,
            payloadHex: approvePayload.hexString,
            chainID: EVMQuantity(1)
        )
        XCTAssertTrue(second.approvalWarnings.contains { $0.contains("no limit") })
    }

    func testReportCarriesNoSecretFields() async throws {
        let report = SigningReport()
        let mirror = Mirror(reflecting: report)
        let forbidden = ["pin", "seed", "mnemonic", "privatekey", "key"]
        for child in mirror.children {
            let label = (child.label ?? "").lowercased()
            for word in forbidden {
                XCTAssertFalse(
                    label.contains(word) && label != "cardaddress" && label != "pinnedpath",
                    "SigningReport field '\(child.label ?? "")' looks secret-bearing"
                )
            }
        }
    }

    func testEveryErrorExplainsItself() {
        let errors: [SigningError] = [
            .wrongStep(expected: .approved, actual: .requestDecoded),
            .noPairingManifest,
            .requestPathNotPinned(requested: "a", pinned: "b"),
            .requestFingerprintMismatch(requested: "a", expected: "b"),
            .requestAddressMismatch(requested: "a", found: "b"),
            .chainNotConfirmed(chainID: "1"),
            .chainIDMissing,
            .unsupportedDataType("EIP-712 typed data"),
            .chainIDMismatch(request: "1", transaction: "137"),
            .signatureTooLarge(80),
            .pinRejected(reason: "3 tries left"),
            .signatureAlreadyAttempted,
            .signatureVerificationFailed("reason"),
            .cardSignatureMalformed("reason"),
        ]
        for error in errors {
            XCTAssertGreaterThan(error.userFacingDescription.count, 40, "\(error)")
        }
    }
}

/// `XCTAssertThrowsError` has no async form, so the ceremony tests need one.
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
