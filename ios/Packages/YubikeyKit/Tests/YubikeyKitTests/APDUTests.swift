import Foundation
import XCTest
@testable import YubikeyKit
import VaultKit
import YubikeyKitMock

/// Byte-level tests for the APDU layer. These run with no hardware: they assert
/// the exact command bytes the app puts on the wire and how each status word is
/// interpreted, using the simulated card as the responder.
///
/// The key-import template layout is one of the two items milestone M0 confirms
/// against a real card trace; these tests pin the bytes so the M0 diff is
/// meaningful, and the ceremony's read-back step makes a wrong layout impossible
/// to miss.
final class APDUTests: XCTestCase {

    // MARK: Golden APDUs

    func testSelectAPDUBytes() {
        let apdu = CommandAPDU(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00,
                               data: OpenPGPCard.openPGPAID, expectedLength: 0)
        XCTAssertEqual(apdu.hex, "00a4040006d2760001240100")
    }

    func testVerifyAndChangeReferenceDataAPDUBytes() {
        XCTAssertEqual(
            CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x81,
                        data: Array("123456".utf8), expectedLength: 0).hex,
            "002000810631323334353600"
        )
        XCTAssertEqual(
            CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: 0x83,
                        data: Array("12345678".utf8), expectedLength: 0).hex,
            "0020008308313233343536373800"
        )
        // CHANGE REFERENCE DATA carries old || new.
        XCTAssertEqual(
            CommandAPDU(cla: 0x00, ins: 0x24, p1: 0x00, p2: 0x81,
                        data: Array("123456".utf8) + Array("654321".utf8), expectedLength: 0).hex,
            "002400810c31323334353636353433323100"
        )
    }

    func testTerminateAndActivateAPDUBytes() {
        XCTAssertEqual(CommandAPDU(cla: 0x00, ins: 0xE6, p1: 0x00, p2: 0x00).hex, "00e60000")
        XCTAssertEqual(CommandAPDU(cla: 0x00, ins: 0x44, p1: 0x00, p2: 0x00).hex, "00440000")
    }

    func testGetDataAPDUBytes() {
        XCTAssertEqual(
            CommandAPDU(cla: 0x00, ins: 0xCA, p1: 0x00, p2: 0x6E, data: [], expectedLength: 0).hex,
            "00ca006e00"
        )
        XCTAssertEqual(
            CommandAPDU(cla: 0x00, ins: 0xCA, p1: 0x00, p2: 0x7A, data: [], expectedLength: 0).hex,
            "00ca007a00"
        )
    }

    func testGetChallengeAPDUBytes() {
        XCTAssertEqual(
            CommandAPDU(cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, expectedLength: 32).hex,
            "0084000020"
        )
    }

    func testGetChallengeReturnsHardwareRandomBytes() async throws {
        let transport = MockYubikeyTransport()
        transport.challengeBytes = [UInt8](repeating: 0xAB, count: 32)
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        let bytes = try await card.randomBytes(count: 32)
        XCTAssertTrue(bytes.isEqualTo([UInt8](repeating: 0xAB, count: 32)))
    }

    func testReadPublicKeyAPDUBytes() {
        // The CRT in the command data addresses the slot as a TLV with an empty
        // value: B6 00 (signature), A4 00 (authentication). A bare tag was
        // rejected by real hardware with 6A80.
        let signature = CommandAPDU(cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
                                    data: TLV(tag: OpenPGPDataObject.controlReferenceTemplateSignature, value: []).encoded,
                                    expectedLength: 0)
        XCTAssertEqual(signature.hex, "0047810002b60000")

        let authentication = CommandAPDU(cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
                                         data: TLV(tag: OpenPGPDataObject.controlReferenceTemplateAuthentication, value: []).encoded,
                                         expectedLength: 0)
        XCTAssertEqual(authentication.hex, "0047810002a40000")
    }

    func testUIFAndPWStatusAPDUBytes() {
        // design.md §6.5: 00 DA 00 D6 02 02 20
        let uif = CommandAPDU(cla: 0x00, ins: 0xDA, p1: 0x00, p2: 0xD6,
                              data: OpenPGPTouchPolicy.fixedEncoded, expectedLength: 0)
        XCTAssertEqual(uif.hex, "00da00d602022000")
        XCTAssertEqual(OpenPGPTouchPolicy.fixedEncoded, [0x02, 0x20])

        // The authentication slot uses the 0xD8 UIF object.
        let authenticationUIF = CommandAPDU(cla: 0x00, ins: 0xDA, p1: 0x00, p2: 0xD8,
                                            data: OpenPGPTouchPolicy.fixedEncoded, expectedLength: 0)
        XCTAssertEqual(authenticationUIF.hex, "00da00d802022000")

        // PW status is written as a single byte: the PW1 status (0x00 = PIN
        // required per signature). Max-length and retry fields are read-only via
        // this DO and are managed by the card, not by PUT DATA 0xC4.
        let pwStatus = CommandAPDU(cla: 0x00, ins: 0xDA, p1: 0x00, p2: 0xC4,
                                   data: PWStatusBytes.encode(), expectedLength: 0)
        XCTAssertEqual(pwStatus.hex, "00da00c4010000")
        XCTAssertEqual(PWStatusBytes.encode(), [PWStatusBytes.pinRequiredPerSignature])
    }

    func testKeyImportAPDUHeaderAndTemplateStructure() {
        let secret = [UInt8](repeating: 0x11, count: 32)
        let template = KeyImportTemplate.extendedHeaderList(privateKey: secret, slot: .signature)

        // 4D | len | B6 00 | 7F48 | 92 20 | 5F48 | secret
        XCTAssertEqual(Array(template.prefix(6)), [0x4D, 0x2A, 0xB6, 0x00, 0x7F, 0x48])
        XCTAssertEqual(Array(template.prefix(11)), [0x4D, 0x2A, 0xB6, 0x00, 0x7F, 0x48, 0x02, 0x92, 0x20, 0x5F, 0x48])
        XCTAssertEqual(Array(template.suffix(32)), secret)
        XCTAssertEqual(template.count, 44)

        // The full PUT DATA header is 00 DB 3F FF 2C
        let apdu = CommandAPDU(cla: 0x00, ins: 0xDB, p1: 0x3F, p2: 0xFF, data: template, expectedLength: 0)
        XCTAssertEqual(Array(apdu.bytes.prefix(5)), [0x00, 0xDB, 0x3F, 0xFF, 0x2C])

        // And the template must round-trip through the real TLV parser.
        XCTAssertEqual(MockYubikeyTransport.extractImport(template)?.slot, .signature)
        XCTAssertEqual(MockYubikeyTransport.extractImport(template)?.secret, secret)
    }

    /// The authentication slot uses CRT 0xA4; everything else about the template
    /// is identical, which is exactly what makes a slot mix-up easy to miss.
    func testAuthenticationSlotImportTemplateUsesCRT_A4() {
        let secret = [UInt8](repeating: 0x22, count: 32)
        let template = KeyImportTemplate.extendedHeaderList(privateKey: secret, slot: .authentication)

        XCTAssertEqual(Array(template.prefix(6)), [0x4D, 0x2A, 0xA4, 0x00, 0x7F, 0x48])
        XCTAssertEqual(template.count, 44)
        let extracted = MockYubikeyTransport.extractImport(template)
        XCTAssertEqual(extracted?.slot, .authentication)
        XCTAssertEqual(extracted?.secret, secret)
    }

    func testAlgorithmAttributesBytes() {
        // 0x13 ECDSA || OID 1.3.132.0.10 (secp256k1), no trailing format byte.
        XCTAssertEqual(
            KeyImportTemplate.ecdsaSecp256k1AlgorithmAttributes,
            [0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A]
        )
        // 0x16 EdDSA || GnuPG's OID for Ed25519 (1.3.6.1.4.1.11591.15.1), which is
        // what yubikit's `EcAttributes.create` sends and what this firmware accepts.
        // RFC 8410's id-Ed25519 is refused with 6A80 — a wrong OID was shipped once
        // on the strength of a broken hardware probe (amendment 29), so the bytes
        // are pinned to the reference implementation rather than to a measurement.
        XCTAssertEqual(
            KeyImportTemplate.eddsaEd25519AlgorithmAttributes,
            [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        )
        XCTAssertEqual(KeyImportTemplate.algorithmAttributes(for: .secp256k1),
                       KeyImportTemplate.ecdsaSecp256k1AlgorithmAttributes)
        XCTAssertEqual(KeyImportTemplate.algorithmAttributes(for: .ed25519),
                       KeyImportTemplate.eddsaEd25519AlgorithmAttributes)
    }

    func testSlotObjectTags() {
        XCTAssertEqual(KeySlotObjects.forSlot(.signature).controlReference, 0x00B6)
        XCTAssertEqual(KeySlotObjects.forSlot(.signature).algorithmAttributes, 0x00C1)
        XCTAssertEqual(KeySlotObjects.forSlot(.signature).fingerprint, 0x00C7)
        XCTAssertEqual(KeySlotObjects.forSlot(.signature).uif, 0x00D6)
        XCTAssertEqual(KeySlotObjects.forSlot(.authentication).controlReference, 0x00A4)
        XCTAssertEqual(KeySlotObjects.forSlot(.authentication).algorithmAttributes, 0x00C3)
        XCTAssertEqual(KeySlotObjects.forSlot(.authentication).fingerprint, 0x00C9)
        XCTAssertEqual(KeySlotObjects.forSlot(.authentication).uif, 0x00D8)
    }

    func testCreationTimeEncoding() {
        let date = Date(timeIntervalSince1970: 0x6500_0000)
        XCTAssertEqual(KeyImportTemplate.creationTime(date), [0x65, 0x00, 0x00, 0x00])
        XCTAssertEqual(KeyImportTemplate.creationTime(Date(timeIntervalSince1970: 0)), [0, 0, 0, 0])
    }

    // MARK: Status words

    func testStatusWordDecoding() {
        XCTAssertTrue(StatusWord.success.isSuccess)
        XCTAssertEqual(StatusWord(sw1: 0x61, sw2: 0x10).remainingResponseBytes, 16)
        XCTAssertEqual(StatusWord(sw1: 0x6C, sw2: 0x20).correctLe, 32)
        XCTAssertEqual(StatusWord(sw1: 0x63, sw2: 0xC2).pinRetriesRemaining, 2)
        XCTAssertNil(StatusWord(sw1: 0x63, sw2: 0x00).pinRetriesRemaining)
        XCTAssertEqual(StatusWord(sw1: 0x69, sw2: 0x83).hex, "6983")
    }

    func testStatusWordMapping() {
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x63, sw2: 0xC2), context: .verifyUserPIN),
            .pinIncorrect(retriesRemaining: 2)
        )
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x69, sw2: 0x83), context: .verifyUserPIN),
            .pinBlocked
        )
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x69, sw2: 0x83), context: .verifyAdminPIN),
            .adminPinBlocked
        )
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x69, sw2: 0x82), context: .importKey),
            .conditionsNotSatisfied
        )
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x6A, sw2: 0x80), context: .importKey),
            .keyImportRejected
        )
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x6A, sw2: 0x80), context: .setAlgorithmAttributes),
            .unsupportedFirmware
        )
        XCTAssertEqual(
            OpenPGPStatusMapper.error(for: StatusWord(sw1: 0x6D, sw2: 0x00), context: .select),
            .unsupportedFeature("instruction not supported")
        )
        XCTAssertNil(OpenPGPStatusMapper.error(for: .success, context: .select))
    }

    // MARK: TLV

    func testTLVEncodingAndParsing() throws {
        XCTAssertEqual(TLV(tag: 0x00C1, value: [0x01, 0x02]).encoded, [0xC1, 0x02, 0x01, 0x02])
        XCTAssertEqual(TLV(tag: 0x7F48, value: []).encoded, [0x7F, 0x48, 0x00])
        // 0x81 length form
        let long = TLV(tag: 0x5F48, value: [UInt8](repeating: 0xAA, count: 200))
        XCTAssertEqual(Array(long.encoded.prefix(4)), [0x5F, 0x48, 0x81, 0xC8])
        XCTAssertEqual(try TLVParser.parse(long.encoded), [long])

        let nested = TLV(tag: 0x6E, value: TLV(tag: 0x4F, value: [0x01]).encoded + TLV(tag: 0xC1, value: [0x02]).encoded)
        let parsed = try TLVParser.parse(nested.encoded)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(TLVParser.find(0x4F, in: parsed)?.value, [0x01])
        XCTAssertEqual(TLVParser.find(0xC1, in: parsed)?.value, [0x02])
        XCTAssertNil(TLVParser.find(0xC4, in: parsed))
        XCTAssertEqual(TLVParser.findAll(0xC1, in: parsed).count, 1)
    }

    func testTLVParsingRejectsTruncatedAndIndefiniteLengths() {
        XCTAssertThrowsError(try TLVParser.parse([0xC1]))
        XCTAssertThrowsError(try TLVParser.parse([0xC1, 0x05, 0x01]))
        XCTAssertThrowsError(try TLVParser.parse([0xC1, 0x80, 0x00]))   // indefinite
    }

    func testApplicationDataParsing() async throws {
        let transport = MockYubikeyTransport(serial: 0xDEAD_BEEF, openPGPVersion: "3.4")
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        let inventory = try await card.inventory()

        XCTAssertEqual(inventory.openPGPVersion, "3.4")
        XCTAssertEqual(inventory.serial, "DEADBEEF")
        XCTAssertFalse(inventory.holdsKey(in: .signature))
        XCTAssertTrue(inventory.isFactoryFresh)
        XCTAssertTrue(inventory.likelySupportsSecp256k1)
        // A factory-fresh applet reports PW1 status 0x01 ("PIN once per session"),
        // measured on hardware: `C4 07 01 7F 7F 7F 03 00 03`. So `0x00` on a card
        // is evidence the policy write ran, and it is what the app writes there.
        XCTAssertEqual(inventory.pwStatusBytes, [0x01, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03])
        XCTAssertEqual(PWStatusBytes.pw1RequiresPin(inventory.pwStatusBytes), false)
        XCTAssertEqual(inventory.retryCounters, RetryCounters(user: 3, reset: 0, admin: 3))
    }

    /// A YubiKey 5.4.x answers 6581 ("memory failure") when the public key of an
    /// *empty* slot is read — not 6A88 as most firmware does. The inventory must
    /// treat both as "no key here" rather than aborting with a bare 6581 error.
    func testInventoryTreatsRead6581AsEmptySlot() async throws {
        let transport = MockYubikeyTransport(openPGPVersion: "3.4")
        transport.readPublicKeyStatus = StatusWord(sw1: 0x65, sw2: 0x81)
        let card = OpenPGPCard(transport: transport)
        try await card.open()

        let inventory = try await card.inventory()

        XCTAssertEqual(inventory.openPGPVersion, "3.4")
        XCTAssertFalse(inventory.holdsKey(in: .signature))
        XCTAssertFalse(inventory.holdsKey(in: .authentication))
        XCTAssertTrue(inventory.isFactoryFresh)
        XCTAssertTrue(inventory.probeFailures.isEmpty)
    }

    func testVersionParsingGateForSecp256k1() {
        XCTAssertTrue(CardInventory(openPGPVersion: "3.4").likelySupportsSecp256k1)
        XCTAssertTrue(CardInventory(openPGPVersion: "4.0").likelySupportsSecp256k1)
        XCTAssertFalse(CardInventory(openPGPVersion: "3.3").likelySupportsSecp256k1)
        XCTAssertFalse(CardInventory(openPGPVersion: "2.1").likelySupportsSecp256k1)
        XCTAssertFalse(CardInventory(openPGPVersion: "unknown").likelySupportsSecp256k1)

        // isDefinitelyUnsupported distinguishes "below the floor" from "unknown".
        XCTAssertFalse(CardInventory(openPGPVersion: "3.4").isDefinitelyUnsupported)
        XCTAssertFalse(CardInventory(openPGPVersion: "4.0").isDefinitelyUnsupported)
        XCTAssertTrue(CardInventory(openPGPVersion: "3.3").isDefinitelyUnsupported)
        XCTAssertTrue(CardInventory(openPGPVersion: "2.1").isDefinitelyUnsupported)
        XCTAssertFalse(CardInventory(openPGPVersion: "unknown").isDefinitelyUnsupported)
    }

    // MARK: Exchange-layer behaviour (61xx / 6Cxx)

    func testGetResponseChainingIsHandled() async throws {
        let transport = MockYubikeyTransport()
        transport.injectedFailure = .chainedResponse
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        // The first response is 61xx; exchange() must follow up with GET RESPONSE
        // and hand back the real application data.
        let data = try await card.applicationData()
        XCTAssertGreaterThan(data.count, 0)
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00c00000") })
    }

    func testWrongLeIsCorrected() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        // Open first, so the one-shot injection is consumed by VERIFY rather than
        // by SELECT.
        try await card.open()
        transport.injectedFailure = .wrongLeOnce
        try await card.verify(pin: OpenPGPPinDefaults.admin, reference: .admin, operation: .verifyAdminPIN)
        XCTAssertEqual(transport.receivedAPDUs.filter { $0.hasPrefix("00200083") }.count, 2)
    }

    func testTransportErrorPropagates() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        transport.injectedFailure = .transportError("session invalidated")
        await XCTAssertThrowsErrorAsync { try await card.applicationData() } verify: { error in
            XCTAssertEqual(error as? CardError, .transportUnavailable("session invalidated"))
        }
    }

    // MARK: Card operations against the simulated card

    /// The reset's contract is `ykman openpgp reset`'s *sequence*, so it is pinned
    /// as APDUs rather than inferred from the effect.
    ///
    /// This is the part a future edit is most likely to "simplify" into a single
    /// `VERIFY PW3` and a terminate. That form is refused with `6982` by every card
    /// whose Admin PIN is not already blocked — i.e. by every factory-fresh card,
    /// which is exactly the card the ceremony's reset step exists for.
    func testResetBurnsBothPINCountersThenTerminates() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        let beforeReset = transport.receivedAPDUs.count

        try await card.reset()

        let sequence = Array(transport.receivedAPDUs.dropFirst(beforeReset))
        XCTAssertEqual(sequence.map { String($0.prefix(4)) }, [
            "00ca",                             // GET DATA 0xC4: how many are left
            "0020", "0020", "0020",           // PW1 burnt to zero (factory: 3)
            "0020", "0020", "0020",           // PW3 burnt to zero (factory: 3)
            "00ca",                             // read back, because 6982 explains nothing
            "00e6",                             // TERMINATE DF
            "0044",                             // ACTIVATE FILE
            "00a4",                             // re-SELECT
        ])
        // P2 is the reference: PW1 first, then PW3.
        XCTAssertEqual(sequence.prefix(7).map { String($0.prefix(8)) }, [
            "00ca00c4",
            "00200081", "00200081", "00200081",
            "00200083", "00200083", "00200083",
        ])
        // Every one of those VERIFYs is a *failure by design*: none of them carries
        // a PIN that could be accepted, so no successful verification can be what
        // makes the terminate possible.
        for apdu in sequence where apdu.hasPrefix("002000") {
            XCTAssertTrue(
                apdu.contains("0000000000000000"),
                "a reset VERIFY must burn an attempt, not verify a PIN: \(apdu)"
            )
        }
    }

    /// The state that used to need a desktop tool: PW3 already blocked.
    ///
    /// `TERMINATE DF` is permitted without any verification in exactly that state
    /// (spec 3.4.1), so the reset must still work — with no PIN, and without the
    /// operator having to know anything about the card's history.
    func testResetWorksWhenTheAdminPINIsAlreadyBlocked() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()

        // Three wrong Admin PIN entries block PW3: the state the retry-limit step
        // warns about, reached without the app's help.
        for _ in 0..<3 {
            try? await card.verify(
                pin: Array("00000000".utf8), reference: .admin, operation: .verifyAdminPIN
            )
        }
        let blocked = try await card.inventory()
        XCTAssertEqual(blocked.retryCounters?.admin, 0, "PW3 must be blocked for this test to mean anything")

        try await card.reset()

        XCTAssertFalse(transport.appletIsTerminated)
        let after = try await card.inventory()
        XCTAssertEqual(after.retryCounters, RetryCounters(user: 3, reset: 0, admin: 3))
    }

    /// A reset that cannot get the counters to zero must say so, and must say it
    /// *before* the terminate — the alternative is a `6982` from `TERMINATE DF`,
    /// which describes the applet's mood rather than the state of the card.
    func testResetReportsCountersThatWouldNotBlock() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        transport.refuseToCountFailedAttempts = true

        await XCTAssertThrowsErrorAsync { try await card.reset() } verify: { error in
            XCTAssertEqual(
                error as? CardError,
                .pinBlockingIncomplete(user: 3, admin: 3),
                "the applet's own count has to reach the caller"
            )
        }
        XCTAssertFalse(transport.appletIsTerminated, "nothing may be erased by a reset that could not start")
    }

    func testFullImportFlowAndPinErrors() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()

        var inventory = try await card.inventory()
        XCTAssertFalse(inventory.holdsKey(in: .signature))

        // The reset takes no Admin PIN at all (amendment 30).
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await card.applyPolicy(adminPIN: Array("87654321".utf8))

        inventory = try await card.inventory()
        XCTAssertEqual(PWStatusBytes.pw1RequiresPin(inventory.pwStatusBytes), true)
        XCTAssertEqual(transport.currentUIF(.signature), [0x02, 0x20])
        XCTAssertEqual(transport.currentUIF(.authentication), [0x02, 0x20])

        // No key yet.
        await XCTAssertThrowsErrorAsync { try await card.readPublicKey(slot: .signature) }

        let privateKey = SensitiveBytes(copying: [UInt8](repeating: 0x2A, count: 32))
        try await card.importKey(
            slot: .signature,
            algorithm: .secp256k1,
            privateKey: privateKey,
            fingerprint: [UInt8](repeating: 0xAB, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: Array("87654321".utf8)
        )

        let readBack = try await card.readPublicKey(slot: .signature)
        let expected = try Secp256k1.publicKey(fromPrivateKey: privateKey.materializedCopy())
        XCTAssertEqual(readBack, expected)
        XCTAssertEqual(transport.currentFingerprint(.signature), [UInt8](repeating: 0xAB, count: 20))

        // A second import onto the occupied slot must be refused, not silently
        // overwrite the key the user just provisioned.
        await XCTAssertThrowsErrorAsync {
            try await card.importKey(
                slot: .signature,
                algorithm: .secp256k1,
                privateKey: privateKey,
                fingerprint: [UInt8](repeating: 0xAB, count: 20),
                creationTime: Date(),
                adminPIN: Array("87654321".utf8)
            )
        } verify: { error in
            // The real card answers 6A80 on an occupied slot.
            XCTAssertEqual(error as? CardError, .keyImportRejected)
        }
    }

    /// `SET PIN RETRIES` is `00 F2 00 00 03 <PW1> <resetting code> <PW3>`, and the
    /// card reports the new limits back in the last three bytes of `0xC4`.
    func testSetPINRetriesAPDUBytesAndReadBack() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))

        // Factory default first: three attempts each, and none for the resetting
        // code this app never sets (hardware reports `03 00 03`).
        XCTAssertEqual(transport.currentPWStatus, [0x01, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03])

        try await card.setPINRetries(user: 7, reset: 7, admin: 7, adminPIN: Array("87654321".utf8))

        let apdu = try XCTUnwrap(transport.receivedAPDUs.last { $0.hasPrefix("00f2") })
        XCTAssertEqual(apdu, "00f2000003" + "070707" + "00")
        XCTAssertEqual(transport.currentRetryLimits.user, 7)
        XCTAssertEqual(transport.currentRetryLimits.admin, 7)
        let counters = try XCTUnwrap(PWStatusBytes.retryCounters(transport.currentPWStatus))
        XCTAssertEqual(counters, RetryCounters(user: 7, reset: 0, admin: 7))

        // A counter that has been spent refills to the new maximum on a good PIN.
        _ = try? await card.verify(pin: Array("000000".utf8), reference: .user, operation: .verifyUserPIN)
        XCTAssertEqual(PWStatusBytes.retryCounters(transport.currentPWStatus)?.user, 6)
        try await card.verify(pin: Array("123456".utf8), reference: .user, operation: .verifyUserPIN)
        XCTAssertEqual(PWStatusBytes.retryCounters(transport.currentPWStatus)?.user, 7)
    }

    /// A limit the applet cannot accept is refused before the card is asked, and
    /// the applet refuses it too (the mock mirrors `6A80`).
    func testSetPINRetriesRejectsValuesOutsideTheAppletRange() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        let before = transport.currentPWStatus

        for value in [0, 100, 256] {
            await XCTAssertThrowsErrorAsync {
                try await card.setPINRetries(user: value, reset: 3, admin: 3, adminPIN: Array("87654321".utf8))
            } verify: { error in
                XCTAssertEqual(error as? CardError, .retryCountOutOfRange(requested: value, allowed: 1...99))
            }
        }
        // Nothing reached the card.
        XCTAssertEqual(transport.currentPWStatus, before)
        XCTAssertFalse(transport.receivedAPDUs.contains { $0.hasPrefix("00f2") })
    }

    /// A wrong attributes object is refused by the card **and** by the simulation,
    /// and the error says what was refused.
    ///
    /// Two lessons are pinned here. The mock only accepts the exact bytes the
    /// firmware accepts, so a wrong OID fails a test instead of a provisioning run —
    /// except that the wrong OID here *was* in the app, and reached a real card
    /// because a hand-typed probe of mine appeared to bless it (amendment 29). And
    /// the bare `6A80` used to be reported as "firmware 5.2.3 or newer is required",
    /// which on a 5.8.0 card sends the operator looking for an upgrade they cannot
    /// install.
    func testTheWrongEd25519AlgorithmAttributesAreRefused() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))

        await XCTAssertThrowsErrorAsync {
            try await card.putData(
                tag: OpenPGPDataObject.algorithmAttributesAuthentication,
                // RFC 8410's id-Ed25519: the OID a wrong-but-plausible reading of the
                // spec produces, and the one that reached a real provisioning run.
                value: [0x16, 0x2B, 0x65, 0x70],
                operation: .setAlgorithmAttributes
            )
        } verify: { error in
            // Written through `putData` directly, so this is the raw mapping.
            XCTAssertEqual(error as? CardError, .unsupportedFirmware)
        }
        // And the key that the app does write imports fine.
        try await card.importKey(
            slot: .authentication,
            algorithm: .ed25519,
            privateKey: SensitiveBytes(copying: [UInt8](repeating: 0x5A, count: 32)),
            fingerprint: [UInt8](repeating: 0xCD, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: Array("87654321".utf8)
        )
    }

    /// A card that refuses the attributes object produces an error that names the
    /// algorithm and the slot.
    ///
    /// This is the message path a real provisioning run took: the bare `6A80` was
    /// reported as "firmware 5.2.3 or newer is required", which on a 5.8.0 card
    /// sends the operator looking for an upgrade they cannot install.
    func testARefusedAttributesObjectNamesTheAlgorithmAndSlot() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        transport.refuseAlgorithmAttributes = true

        await XCTAssertThrowsErrorAsync {
            try await card.importKey(
                slot: .authentication,
                algorithm: .ed25519,
                privateKey: SensitiveBytes(copying: [UInt8](repeating: 0x5A, count: 32)),
                fingerprint: [UInt8](repeating: 0xCD, count: 20),
                creationTime: Date(timeIntervalSince1970: 1_700_000_000),
                adminPIN: Array("87654321".utf8)
            )
        } verify: { error in
            guard case .algorithmAttributesRejected(let algorithm, let slot, _)? = error as? CardError else {
                return XCTFail("expected algorithmAttributesRejected, got \(error)")
            }
            XCTAssertEqual(algorithm, "Ed25519")
            XCTAssertEqual(slot, "Authentication slot")
        }
        XCTAssertFalse(transport.hasKey(in: .authentication), "a refused attributes write imports nothing")
    }

    /// The Ed25519 path end to end: import a 32-byte seed into the
    /// authentication slot, read it back, and check the two slots stay separate.
    func testEd25519ImportIntoAuthenticationSlot() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await card.applyPolicy(adminPIN: Array("87654321".utf8))

        // Before import, the authentication slot is empty.
        await XCTAssertThrowsErrorAsync { try await card.readPublicKey(slot: .authentication) }

        let seed = SensitiveBytes(copying: [UInt8](repeating: 0x5A, count: 32))
        try await card.importKey(
            slot: .authentication,
            algorithm: .ed25519,
            privateKey: seed,
            fingerprint: [UInt8](repeating: 0xCD, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: Array("87654321".utf8)
        )

        let readBack = try await card.readPublicKey(slot: .authentication)
        XCTAssertEqual(readBack.count, 32)
        XCTAssertEqual(readBack, try Ed25519.publicKey(fromSeed: seed.materializedCopy()))
        XCTAssertEqual(transport.currentFingerprint(.authentication), [UInt8](repeating: 0xCD, count: 20))

        // Writing secp256k1 into the signature slot must not disturb it.
        let scalar = SensitiveBytes(copying: [UInt8](repeating: 0x11, count: 32))
        try await card.importKey(
            slot: .signature,
            algorithm: .secp256k1,
            privateKey: scalar,
            fingerprint: [UInt8](repeating: 0xEF, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: Array("87654321".utf8)
        )
        // `XCTAssertEqual` takes autoclosures, which cannot await; hoist first.
        let authenticationAfter = try await card.readPublicKey(slot: .authentication)
        let signatureAfter = try await card.readPublicKey(slot: .signature)
        XCTAssertEqual(authenticationAfter, readBack)
        XCTAssertEqual(signatureAfter, try Secp256k1.publicKey(fromPrivateKey: scalar.materializedCopy()))

        // Both slots now report occupied.
        let inventory = try await card.inventory()
        XCTAssertTrue(inventory.holdsKey(in: .signature))
        XCTAssertTrue(inventory.holdsKey(in: .authentication))
        XCTAssertFalse(inventory.isFactoryFresh)
        XCTAssertEqual(inventory.algorithmAttributes[.signature],
                       KeyImportTemplate.ecdsaSecp256k1AlgorithmAttributes)
        XCTAssertEqual(inventory.algorithmAttributes[.authentication],
                       KeyImportTemplate.eddsaEd25519AlgorithmAttributes)
    }

    /// The EdDSA algorithm attributes must not be accepted for the signature
    /// slot, nor the ECDSA ones for the authentication slot.
    func testMismatchedAlgorithmAttributesAreRejected() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.reset()
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))

        // Write the EdDSA attributes into the signature slot directly.
        await XCTAssertThrowsErrorAsync {
            try await card.putData(
                tag: OpenPGPDataObject.algorithmAttributesSignature,
                value: KeyImportTemplate.eddsaEd25519AlgorithmAttributes,
                operation: .setAlgorithmAttributes
            )
        }
    }

    func testCommandsBeforeSelectAreRefused() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        // No open()/select() call.
        await XCTAssertThrowsErrorAsync { try await card.applicationData() } verify: { error in
            XCTAssertEqual(error as? CardError, .conditionsNotSatisfied)
        }
    }

    /// The same APDU sequence must be produced regardless of which transport is
    /// underneath, because both use the shared `exchange` implementation.
    func testTransportParityAcrossNFCAndUSBCWrappers() async throws {
        func trace(_ transport: YubikeyTransport) async throws -> [String] {
            let card = OpenPGPCard(transport: transport)
            try await card.open()
            try await card.reset()
            try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
            try await card.applyPolicy(adminPIN: Array("87654321".utf8))
            let scalar = SensitiveBytes(copying: [UInt8](repeating: 0x33, count: 32))
            try await card.importKey(
                slot: .signature,
                algorithm: .secp256k1,
                privateKey: scalar,
                fingerprint: [UInt8](repeating: 1, count: 20),
                creationTime: Date(timeIntervalSince1970: 0),
                adminPIN: Array("87654321".utf8)
            )
            let seed = SensitiveBytes(copying: [UInt8](repeating: 0x44, count: 32))
            try await card.importKey(
                slot: .authentication,
                algorithm: .ed25519,
                privateKey: seed,
                fingerprint: [UInt8](repeating: 2, count: 20),
                creationTime: Date(timeIntervalSince1970: 0),
                adminPIN: Array("87654321".utf8)
            )
            _ = try await card.readPublicKey(slot: .signature)
            _ = try await card.readPublicKey(slot: .authentication)
            return (transport as? MockYubikeyTransport)?.receivedAPDUs ?? []
        }

        let nfc = MockYubikeyTransport(transportName: "NFC")
        let usbc = MockYubikeyTransport(transportName: "USB-C (CCID)")
        let nfcTrace = try await trace(nfc)
        let usbcTrace = try await trace(usbc)

        XCTAssertEqual(nfcTrace, usbcTrace)
        XCTAssertFalse(nfcTrace.isEmpty)
    }
}

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
