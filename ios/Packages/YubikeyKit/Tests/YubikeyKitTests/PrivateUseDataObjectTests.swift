import Foundation
import XCTest
@testable import YubikeyKit
import VaultKit
import YubikeyKitMock

/// The pairing manifest lives in one of the OpenPGP applet's four private-use
/// data objects. These tests pin *which* one and why, because the choice is not
/// cosmetic: two of the four cannot be read without a PIN, and a re-pair must not
/// need one.
///
/// Measured against a real YubiKey 5C NFC (firmware 5.8.0, OpenPGP 3.4), with no
/// PIN presented:
///
/// ```
/// GET DATA 0x0101 -> 90 00   (readable, empty)
/// GET DATA 0x0102 -> 90 00   (readable, empty)   <- the manifest's home
/// GET DATA 0x0103 -> 69 82   (security status not satisfied)
/// GET DATA 0x0104 -> 69 82   (security status not satisfied)
/// ```
///
/// The mock reproduces those answers, so picking a different object fails here
/// rather than on an operator's card.
final class PrivateUseDataObjectTests: XCTestCase {

    private let adminPIN = Array("12345678".utf8)

    private func makeCard() async throws -> (OpenPGPCard, MockYubikeyTransport) {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        return (card, transport)
    }

    // MARK: The access-condition choice

    func testTheManifestObjectIsReadableWithoutAPINAndWrittenWithPW3() {
        let object = PrivateUseDataObject.pairingManifest
        XCTAssertEqual(object, .two)
        XCTAssertEqual(object.readAccess, .none, "a re-pair must not need a PIN to read")
        XCTAssertEqual(object.writeAccess, .pw3, "the Admin PIN is already verified when the ceremony writes")
    }

    /// The other three are unusable for this, and the spec's reason for having
    /// four objects is precisely that their access conditions differ.
    func testTheOtherPrivateUseObjectsCannotServeAsAManifestSlot() {
        XCTAssertEqual(PrivateUseDataObject.one.writeAccess, .pw2, "PW2 is the resetting code this app never sets")
        XCTAssertEqual(PrivateUseDataObject.three.readAccess, .pw2)
        XCTAssertEqual(PrivateUseDataObject.four.readAccess, .pw3)
        for object in PrivateUseDataObject.allCases where object != .two {
            let readableFreely = object.readAccess == .none
            let writableWithAdmin = object.writeAccess == .pw3
            XCTAssertFalse(
                readableFreely && writableWithAdmin,
                "\(object) would also work; the choice must be justified, not arbitrary"
            )
        }
    }

    func testTheSpecsSizeLimitIsWhatTheCardEnforces() {
        XCTAssertEqual(PrivateUseDataObject.maximumValueLength, 254)
    }

    // MARK: Round trip

    func testManifestRoundTripsThroughTheCard() async throws {
        let (card, transport) = try await makeCard()
        let manifest = [UInt8](repeating: 0xA5, count: 194)

        try await card.writePairingManifest(manifest, adminPIN: adminPIN)
        let readBack = try await card.readPairingManifest()

        XCTAssertEqual(readBack, manifest)
        XCTAssertEqual(
            transport.receivedAPDUs.filter { $0.hasPrefix("00da0102") }.count, 1,
            "the manifest must be a PUT DATA to 0x0102"
        )
        XCTAssertTrue(
            transport.receivedAPDUs.contains { $0.hasPrefix("00ca0102") },
            "reading it back must be a GET DATA of 0x0102"
        )
    }

    /// A never-written object is *empty*, not missing: the hardware answers
    /// `9000` with no data. Anything else would make "not yet provisioned"
    /// indistinguishable from "this card cannot do it".
    func testAnUnwrittenObjectReadsAsNilRatherThanAnError() async throws {
        let (card, transport) = try await makeCard()

        let value = try await card.readPairingManifest()

        XCTAssertNil(value)
        XCTAssertTrue(transport.receivedAPDUs.contains { $0.hasPrefix("00ca0102") })
    }

    func testWritingRequiresTheAdminPIN() async throws {
        let (card, _) = try await makeCard()

        do {
            try await card.writePairingManifest([1, 2, 3], adminPIN: Array("00000000".utf8))
            XCTFail("a wrong Admin PIN must not write")
        } catch let error as CardError {
            guard case .pinIncorrect = error else {
                return XCTFail("expected pinIncorrect, got \(error)")
            }
        }
    }

    func testAnOversizedValueIsRefusedBeforeTheCardIsTouched() async throws {
        let (card, transport) = try await makeCard()
        let tooLarge = [UInt8](repeating: 0, count: PrivateUseDataObject.maximumValueLength + 1)

        do {
            try await card.writePairingManifest(tooLarge, adminPIN: adminPIN)
            XCTFail("255 bytes cannot fit a 254-byte object")
        } catch let error as CardError {
            XCTAssertEqual(error, .dataObjectTooLarge(byteCount: 255, maximum: 254))
            XCTAssertTrue(error.isDefinitiveCardRejection, "no retry can make it fit")
        }
        XCTAssertFalse(
            transport.receivedAPDUs.contains { $0.hasPrefix("00da0102") },
            "the card must not be asked to store something that cannot fit"
        )
    }

    // MARK: Cards without the object

    func testACardWithoutPrivateUseObjectsReportsUnsupportedRatherThanEmpty() async throws {
        let (card, transport) = try await makeCard()
        transport.hasPrivateUseDataObjects = false

        do {
            _ = try await card.readPairingManifest()
            XCTFail("a card that does not implement the object must throw")
        } catch let error as CardError {
            XCTAssertEqual(error, .unsupportedFeature("this applet has no private-use data object 0x0102"))
            XCTAssertTrue(error.isDefinitiveCardRejection)
        }

        do {
            try await card.writePairingManifest([1, 2, 3], adminPIN: adminPIN)
            XCTFail("a card that does not implement the object must refuse the write")
        } catch let error as CardError {
            guard case .unsupportedFeature = error else {
                return XCTFail("expected unsupportedFeature, got \(error)")
            }
        }
    }

    /// `6D00` (instruction not supported) and `6B00` (wrong P1-P2) mean the same
    /// thing as `6A88` here, and applets differ in which they answer.
    func testEveryMissingObjectStatusWordIsTreatedAsUnsupported() {
        for (sw1, sw2) in [(UInt8(0x6A), UInt8(0x88)), (0x6D, 0x00), (0x6B, 0x00)] {
            XCTAssertTrue(
                OpenPGPCard.isMissingDataObject(sw1, sw2),
                String(format: "%02X%02X means the object is not there", sw1, sw2)
            )
        }
        XCTAssertFalse(OpenPGPCard.isMissingDataObject(0x69, 0x82), "6982 is a PIN problem, not a missing object")
        XCTAssertFalse(OpenPGPCard.isMissingDataObject(0x90, 0x00))
    }

    // MARK: Inventory

    func testInventoryReportsAnEmptyObjectAsAbsentAndAFilledOneBy() async throws {
        let (card, _) = try await makeCard()
        let empty = try await card.inventory().pairingManifest
        XCTAssertEqual(empty, .absent)

        try await card.writePairingManifest([UInt8](repeating: 7, count: 194), adminPIN: adminPIN)
        let filled = try await card.inventory().pairingManifest
        XCTAssertEqual(filled, .present(byteCount: 194))
    }

    func testInventoryReportsUnsupportedRatherThanFailing() async throws {
        let (card, transport) = try await makeCard()
        transport.hasPrivateUseDataObjects = false

        let inventory = try await card.inventory()

        XCTAssertEqual(inventory.pairingManifest, .unsupported)
        XCTAssertTrue(inventory.isFactoryFresh, "a card without the object is still a perfectly good card")
    }

    // MARK: Reset

    /// `TERMINATE DF` wipes the private-use objects with everything else. This is
    /// why the manifest is written *after* a reset and why a reset is what
    /// "forget the pairing" means for this card.
    func testResetWipesTheManifest() async throws {
        let (card, _) = try await makeCard()
        try await card.writePairingManifest([UInt8](repeating: 9, count: 32), adminPIN: adminPIN)
        let beforeReset = try await card.readPairingManifest()
        XCTAssertNotNil(beforeReset)

        try await card.reset(adminPIN: adminPIN)

        let afterReset = try await card.readPairingManifest()
        XCTAssertNil(afterReset)
        let inventory = try await card.inventory().pairingManifest
        XCTAssertEqual(inventory, .absent)
    }

    /// `TERMINATE DF` wipes the private-use objects with everything else, so an
    /// interrupted reset loses the manifest too — and the applet heals itself on
    /// the next SELECT (amendment 16), which is exactly why the manifest cannot be
    /// written *before* the reset and must not be expected to survive one.
    func testAnInterruptedResetAlsoLosesTheManifest() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)
        try await card.open()
        try await card.writePairingManifest([UInt8](repeating: 9, count: 32), adminPIN: adminPIN)

        // TERMINATE DF delivered, ACTIVATE FILE never: the operator's tap was lost.
        transport.simulateInterruptedReset()
        try await card.open()

        let afterHealing = try await card.readPairingManifest()
        XCTAssertNil(afterHealing, "a reset — even an interrupted one — is what forgets the pairing")
        let inventory = try await card.inventory().pairingManifest
        XCTAssertEqual(inventory, .absent)
    }

    /// A read on a card whose session was never opened must fail rather than
    /// return "no manifest": those two are very different answers.
    func testReadingBeforeTheAppletIsSelectedFails() async throws {
        let transport = MockYubikeyTransport()
        let card = OpenPGPCard(transport: transport)

        do {
            _ = try await card.readPairingManifest()
            XCTFail("an unopened session cannot answer")
        } catch let error as CardError {
            XCTAssertEqual(error, .conditionsNotSatisfied)
        }
    }
}
