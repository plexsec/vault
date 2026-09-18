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

    func testReadPublicKeyAPDUBytes() {
        let apdu = CommandAPDU(cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
                               data: TLV.encodeTag(OpenPGPDataObject.controlReferenceTemplateSignature),
                               expectedLength: 0)
        XCTAssertEqual(apdu.hex, "0047810001b600")
    }

    func testUIFAndPWStatusAPDUBytes() {
        // design.md §6.5: 00 DA 00 D6 02 02 20
        let uif = CommandAPDU(cla: 0x00, ins: 0xDA, p1: 0x00, p2: 0xD6,
                              data: OpenPGPTouchPolicy.fixedEncoded, expectedLength: 0)
        XCTAssertEqual(uif.hex, "00da00d602022000")
        XCTAssertEqual(OpenPGPTouchPolicy.fixedEncoded, [0x02, 0x20])

        let pwStatus = CommandAPDU(cla: 0x00, ins: 0xDA, p1: 0x00, p2: 0xC4,
                                   data: PWStatusBytes.encode(), expectedLength: 0)
        XCTAssertEqual(pwStatus.hex, "00da00c40700" + "007f007f007f" + "00")
        XCTAssertEqual(PWStatusBytes.encode().first, PWStatusBytes.pinRequiredPerSignature)
    }

    func testKeyImportAPDUHeaderAndTemplateStructure() {
        let scalar = [UInt8](repeating: 0x11, count: 32)
        let template = KeyImportTemplate.extendedHeaderList(privateKey: scalar)

        // 4D | len | B6 | len | 7F48 | len | 5F48 | 00 20 | scalar
        XCTAssertEqual(Array(template.prefix(6)), [0x4D, 0x2A, 0xB6, 0x28, 0x7F, 0x48])
        XCTAssertEqual(Array(template.suffix(34).prefix(2)), [0x00, 0x20])
        XCTAssertEqual(Array(template.suffix(32)), scalar)
        XCTAssertEqual(template.count, 44)

        // The full PUT DATA header is 00 DB 3F FF 2C
        let apdu = CommandAPDU(cla: 0x00, ins: 0xDB, p1: 0x3F, p2: 0xFF, data: template, expectedLength: 0)
        XCTAssertEqual(Array(apdu.bytes.prefix(5)), [0x00, 0xDB, 0x3F, 0xFF, 0x2C])

        // And the template must round-trip through the real TLV parser.
        XCTAssertEqual(MockYubikeyTransport.extractPrivateKey(template), scalar)
    }

    func testAlgorithmAttributesBytes() {
        // 0x13 ECDSA || OID 1.3.132.0.10 || 0x00
        XCTAssertEqual(
            KeyImportTemplate.ecdsaSecp256k1AlgorithmAttributes,
            [0x13, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x00]
        )
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
        XCTAssertFalse(inventory.hasSignatureKey)
        XCTAssertEqual(inventory.signatureCounter, 0)
        XCTAssertTrue(inventory.isFactoryFresh)
        XCTAssertTrue(inventory.likelySupportsSecp256k1)
        XCTAssertEqual(PWStatusBytes.pw1RequiresPin(inventory.pwStatusBytes), true)
    }

    func testVersionParsingGateForSecp256k1() {
        XCTAssertTrue(CardInventory(openPGPVersion: "3.4").likelySupportsSecp256k1)
        XCTAssertTrue(CardInventory(openPGPVersion: "4.0").likelySupportsSecp256k1)
        XCTAssertFalse(CardInventory(openPGPVersion: "3.3").likelySupportsSecp256k1)
        XCTAssertFalse(CardInventory(openPGPVersion: "2.1").likelySupportsSecp256k1)
        XCTAssertFalse(CardInventory(openPGPVersion: "unknown").likelySupportsSecp256k1)
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

    func testFullImportFlowAndPinErrors() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()

        var inventory = try await card.inventory()
        XCTAssertFalse(inventory.hasSignatureKey)

        // Wrong Admin PIN reports the remaining attempts.
        await XCTAssertThrowsErrorAsync {
            try await card.reset(adminPIN: Array("00000000".utf8))
        } verify: { error in
            XCTAssertEqual(error as? CardError, .pinIncorrect(retriesRemaining: 2))
        }

        try await card.reset(adminPIN: OpenPGPPinDefaults.admin)
        try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
        try await card.applyPolicy(adminPIN: Array("87654321".utf8))

        inventory = try await card.inventory()
        XCTAssertEqual(PWStatusBytes.pw1RequiresPin(inventory.pwStatusBytes), true)
        XCTAssertEqual(transport.currentUIF, [0x02, 0x20])

        // No key yet.
        await XCTAssertThrowsErrorAsync { try await card.readSignaturePublicKey() }

        let entropy = ScriptedEntropySource(repeating: 0x2A, count: 32)
        let privateKey = try entropy.randomBytes(count: 32)
        try await card.importSignatureKey(
            privateKey: privateKey,
            fingerprint: [UInt8](repeating: 0xAB, count: 20),
            creationTime: Date(timeIntervalSince1970: 1_700_000_000),
            adminPIN: Array("87654321".utf8)
        )

        let readBack = try await card.readSignaturePublicKey()
        let expected = try Secp256k1.publicKey(fromPrivateKey: privateKey.materializedCopy())
        XCTAssertEqual(readBack, expected)
        XCTAssertEqual(transport.currentFingerprint, [UInt8](repeating: 0xAB, count: 20))
        let counter = try await card.signatureCounter()
        XCTAssertEqual(counter, 0)

        // A second import onto the occupied slot must be refused, not silently
        // overwrite the key the user just provisioned.
        await XCTAssertThrowsErrorAsync {
            try await card.importSignatureKey(
                privateKey: privateKey,
                fingerprint: [UInt8](repeating: 0xAB, count: 20),
                creationTime: Date(),
                adminPIN: Array("87654321".utf8)
            )
        } verify: { error in
            XCTAssertEqual(error as? CardError, .keyImportRejected)
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

    func testCounterIsReportedAfterSimulatedExternalSignature() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        let initial = try await card.signatureCounter()
        XCTAssertEqual(initial, 0)
        transport.simulateExternalSignature()
        transport.simulateExternalSignature()
        let after = try await card.signatureCounter()
        XCTAssertEqual(after, 2)
    }

    /// The same APDU sequence must be produced regardless of which transport is
    /// underneath, because both use the shared `exchange` implementation.
    func testTransportParityAcrossNFCAndUSBCWrappers() async throws {
        func trace(_ transport: YubikeyTransport) async throws -> [String] {
            let card = OpenPGPCard(transport: transport)
            try await card.open()
            try await card.reset(adminPIN: OpenPGPPinDefaults.admin)
            try await card.setPINs(userPIN: Array("123456".utf8), adminPIN: Array("87654321".utf8))
            try await card.applyPolicy(adminPIN: Array("87654321".utf8))
            let key = try ScriptedEntropySource(repeating: 0x33, count: 32).randomBytes(count: 32)
            try await card.importSignatureKey(
                privateKey: key,
                fingerprint: [UInt8](repeating: 1, count: 20),
                creationTime: Date(timeIntervalSince1970: 0),
                adminPIN: Array("87654321".utf8)
            )
            _ = try await card.readSignaturePublicKey()
            _ = try await card.signatureCounter()
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
