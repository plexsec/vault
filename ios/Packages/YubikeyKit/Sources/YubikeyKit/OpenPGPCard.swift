import Foundation
import VaultKit

/// OpenPGP applet operations over a `YubikeyTransport`.
///
/// This type is the only place that knows APDU byte layouts, and it conforms to
/// VaultKit's `SignerCard` so the ceremony state machine can drive it without
/// knowing anything about ISO 7816.
public final class OpenPGPCard: SignerCard {
    public static let openPGPAID: [UInt8] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]

    private let transport: YubikeyTransport
    private var selected = false

    public init(transport: YubikeyTransport) {
        self.transport = transport
    }

    public var transportName: String { transport.transportName }

    // MARK: Session

    public func open() async throws {
        try await transport.open()
        try await select()
    }

    public func close() async {
        selected = false
        await transport.close()
    }

    // MARK: Commands

    public func select() async throws {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00,
            data: Self.openPGPAID,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .select)
        selected = true
    }

    func applicationData() async throws -> [UInt8] {
        try await getData(OpenPGPDataObject.applicationRelatedData, operation: .readApplicationData)
    }

    func securitySupportTemplate() async throws -> [UInt8] {
        try await getData(OpenPGPDataObject.securitySupportTemplate, operation: .readSecuritySupportTemplate)
    }

    public func getDataObject(_ tag: UInt16) async throws -> [UInt8] {
        try await getData(tag, operation: .readApplicationData)
    }

    /// `GET DATA` (INS 0xCA), tag in P1P2.
    public func getData(_ tag: UInt16, operation: OpenPGPOperation) async throws -> [UInt8] {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xCA,
            p1: UInt8(tag >> 8), p2: UInt8(tag & 0xFF),
            data: [],
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
        return response.data
    }

    /// `PUT DATA` (INS 0xDA / 0xDB).
    ///
    /// `P1P2 = tag` for ordinary data objects; the Extended Header List for key
    /// import uses `P1P2 = 3F FF` and INS `0xDB`, which is why the tag is passed
    /// in separately from the addressing bytes.
    @discardableResult
    public func putData(
        tag: UInt16,
        value: [UInt8],
        addressing: (p1: UInt8, p2: UInt8)? = nil,
        ins: UInt8 = 0xDA,
        operation: OpenPGPOperation
    ) async throws -> [UInt8] {
        let p1 = addressing?.p1 ?? UInt8(tag >> 8)
        let p2 = addressing?.p2 ?? UInt8(tag & 0xFF)
        let apdu = CommandAPDU(cla: 0x00, ins: ins, p1: p1, p2: p2, data: value, expectedLength: 0)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
        return response.data
    }

    public func putDataObject(_ tag: UInt16, value: [UInt8]) async throws {
        try await putData(tag: tag, value: value, operation: .applyPolicy)
    }

    // MARK: PINs

    public func verify(pin: [UInt8], reference: OpenPGPPinReference, operation: OpenPGPOperation) async throws {
        let apdu = CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: reference.rawValue, data: pin, expectedLength: 0)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
    }

    public func changeReferenceData(
        reference: OpenPGPPinReference,
        oldPIN: [UInt8],
        newPIN: [UInt8],
        operation: OpenPGPOperation
    ) async throws {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0x24, p1: 0x00, p2: reference.rawValue,
            data: oldPIN + newPIN,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
    }

    public func terminateDF() async throws {
        let apdu = CommandAPDU(cla: 0x00, ins: 0xE6, p1: 0x00, p2: 0x00, data: [], expectedLength: 0)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .terminate)
    }

    public func activateFile() async throws {
        let apdu = CommandAPDU(cla: 0x00, ins: 0x44, p1: 0x00, p2: 0x00, data: [], expectedLength: 0)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .activate)
    }

    /// `GENERATE ASYMMETRIC KEY PAIR` in read mode (`P1 = 0x81`) returns the
    /// public key in `7F49`, with the EC point in `86`.
    public func readPublicKey(controlReference: UInt16 = OpenPGPDataObject.controlReferenceTemplateSignature) async throws -> [UInt8] {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
            data: TLV.encodeTag(controlReference),
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .readPublicKey)
        let objects = try TLVParser.parse(response.data)
        guard let point = TLVParser.find(OpenPGPDataObject.ecdsaPublicPoint, in: objects) else {
            throw CardError.malformedResponse("public key template 7F49 had no EC point (86)")
        }
        return point.value
    }

    // MARK: SignerCard conformance

    public func inventory() async throws -> CardInventory {
        let applicationData = try await applicationData()
        // The security support template is optional: a card that refuses it
        // should not block the inventory.
        let sst = try? await securitySupportTemplate()
        let parsed = try OpenPGPApplicationData.parse(applicationData: applicationData, securitySupportTemplate: sst)

        // Detect an existing signature key by attempting a read. 6A88 means the
        // slot is empty, which is the only reliable signal (a fingerprint object
        // may be present-but-zero).
        var hasSignatureKey = parsed.hasSignatureKey
        do {
            _ = try await readPublicKey()
            hasSignatureKey = true
        } catch CardError.unexpectedStatusWord(let sw1, let sw2) where sw1 == 0x6A && sw2 == 0x88 {
            hasSignatureKey = false
        } catch CardError.conditionsNotSatisfied {
            hasSignatureKey = false
        }

        let counter = parsed.signatureCounter
        let fingerprintsAreZero = (parsed.fingerprintSignature?.allSatisfy { $0 == 0 } ?? true)
            && (parsed.combinedFingerprints?.allSatisfy { $0 == 0 } ?? true)

        return CardInventory(
            openPGPVersion: parsed.openPGPVersion ?? "unknown",
            manufacturer: parsed.manufacturer.map { String(format: "0x%04X", $0) },
            serial: parsed.serial.map { String(format: "%08X", $0) },
            algorithmAttributes: parsed.algorithmAttributesSignature,
            pwStatusBytes: parsed.pwStatusBytes,
            hasSignatureKey: hasSignatureKey,
            signatureCounter: counter,
            isFactoryFresh: !hasSignatureKey && fingerprintsAreZero && (counter ?? 0) == 0
        )
    }

    public func reset(adminPIN: [UInt8]) async throws {
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)
        try await terminateDF()
        try await activateFile()
        selected = false
        try await select()
    }

    public func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        // PW1 first: if PW3 fails after this, the Admin PIN is still the factory
        // default, so the operator is not locked out of the card.
        try await changeReferenceData(
            reference: .user,
            oldPIN: OpenPGPPinDefaults.user,
            newPIN: userPIN,
            operation: .changeUserPIN
        )
        try await changeReferenceData(
            reference: .admin,
            oldPIN: OpenPGPPinDefaults.admin,
            newPIN: adminPIN,
            operation: .changeAdminPIN
        )
    }

    /// Applies the mandatory policy and verifies both writes by reading back.
    ///
    /// The Admin PIN is required because `PUT DATA` of these objects is protected.
    public func applyPolicy(adminPIN: [UInt8]) async throws {
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)

        try await putData(
            tag: OpenPGPDataObject.uifSignature,
            value: OpenPGPTouchPolicy.fixedEncoded,
            operation: .applyPolicy
        )
        try await putData(
            tag: OpenPGPDataObject.pwStatusBytes,
            value: PWStatusBytes.encode(),
            operation: .applyPolicy
        )
    }

    public func importSignatureKey(privateKey: SensitiveBytes, fingerprint: [UInt8], creationTime: Date) async throws {
        var raw = privateKey.materializedCopy()
        defer { wipe(&raw) }

        // The signature slot must be empty: PUT DATA of a private key is rejected
        // on an occupied slot, and the ceremony treats that as a hard failure
        // rather than trying to work around it.
        let extendedHeaderList = KeyImportTemplate.extendedHeaderList(privateKey: raw)
        try await putData(
            tag: OpenPGPDataObject.extendedHeaderList,
            value: extendedHeaderList,
            addressing: (0x3F, 0xFF),
            ins: 0xDB,
            operation: .importKey
        )

        try await putData(
            tag: OpenPGPDataObject.algorithmAttributesSignature,
            value: KeyImportTemplate.ecdsaSecp256k1AlgorithmAttributes,
            operation: .setAlgorithmAttributes
        )

        try await putData(
            tag: OpenPGPDataObject.fingerprintSignature,
            value: KeyImportTemplate.signatureFingerprint(fingerprint),
            operation: .importKey
        )

        // Creation time is advisory metadata. The tag is the one design.md
        // specifies; if the firmware rejects it the ceremony continues, because
        // the fingerprint and the read-back comparison are the real checks.
        do {
            try await putData(
                tag: OpenPGPDataObject.creationTimeSignature,
                value: KeyImportTemplate.creationTime(creationTime),
                operation: .importKey
            )
        } catch let error as CardError {
            switch error {
            case .unexpectedStatusWord, .unsupportedFeature:
                break
            default:
                throw error
            }
        }
    }

    public func readSignaturePublicKey() async throws -> [UInt8] {
        try await readPublicKey()
    }

    public func signatureCounter() async throws -> UInt32 {
        let sst = try await securitySupportTemplate()
        let objects = try TLVParser.parse(sst)
        guard let counter = TLVParser.find(OpenPGPDataObject.signatureCounter, in: objects)?.value,
              counter.count == 3
        else {
            throw CardError.malformedResponse("security support template had no 0x93 signature counter")
        }
        return (UInt32(counter[0]) << 16) | (UInt32(counter[1]) << 8) | UInt32(counter[2])
    }

    // MARK: Status word handling

    static func check(_ response: ResponseAPDU, operation: OpenPGPOperation) throws {
        if let error = OpenPGPStatusMapper.error(for: response.status, context: operation) {
            throw error
        }
    }
}
