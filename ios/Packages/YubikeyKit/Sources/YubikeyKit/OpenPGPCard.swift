import Foundation
import VaultKit

/// OpenPGP applet operations over a `YubikeyTransport`.
///
/// This type is the only place that knows APDU byte layouts, and it conforms to
/// VaultKit's `SignerCard` so the ceremony state machine can drive it without
/// knowing anything about ISO 7816.
///
/// Every key operation is addressed by `KeySlot`; the slot-to-tag mapping lives
/// in `KeySlotObjects`. Which algorithm goes in which slot is decided above this
/// layer (`KeyAlgorithm.slot`).
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

    /// `SELECT` the OpenPGP AID, reactivating a terminated DF if necessary.
    ///
    /// `TERMINATE DF` puts the applet in the *terminated* state, where every
    /// command except `ACTIVATE FILE` is refused with `6985` (or `6285`). A reset
    /// is `TERMINATE DF` + `ACTIVATE FILE` + re-SELECT, and the ceremony's reset
    /// step runs all three in one NFC session — so a session that drops between
    /// the two leaves the card terminated, and every later session fails at
    /// SELECT until something sends `ACTIVATE FILE`.
    ///
    /// The recovery below mirrors `yubikit`'s `OpenPgpSession.__init__`, which
    /// treats those two status words on SELECT as "not activated, activate" and
    /// then re-selects. Without it, an interrupted reset needs GPG or `ykman` to
    /// recover a card this app just terminated.
    public func select() async throws {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00,
            data: Self.openPGPAID,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        if Self.isTerminatedAppletStatus(response.status) {
            try await activateFile()
            let reactivated = try await transport.exchange(apdu)
            try Self.check(reactivated, operation: .select)
            selected = true
            return
        }
        try Self.check(response, operation: .select)
        selected = true
    }

    /// The status words a *terminated* DF answers SELECT with.
    ///
    /// `6985` is `CONDITIONS OF USE NOT SATISFIED`; `6285` is `NO INPUT DATA`.
    /// Both are what yubikit recognises as "the application is not activated"
    /// (`SW.NO_INPUT_DATA`, `SW.CONDITIONS_NOT_SATISFIED`).
    static func isTerminatedAppletStatus(_ status: StatusWord) -> Bool {
        (status.sw1 == 0x69 || status.sw1 == 0x62) && status.sw2 == 0x85
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
        // TERMINATE DF is a case-1 command (no data, no Le). The previous form
        // sent a Le byte (00 E6 00 00 00), which real hardware rejected; the
        // correct form is 00 E6 00 00.
        let apdu = CommandAPDU(cla: 0x00, ins: 0xE6, p1: 0x00, p2: 0x00)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .terminate)
    }

    /// `ACTIVATE FILE` (INS 0x44) — the second half of an OpenPGP reset, and the
    /// only command a terminated DF accepts besides a re-SELECT.
    public func activateFile() async throws {
        // Case-1 command, no Le byte (00 44 00 00).
        let apdu = CommandAPDU(cla: 0x00, ins: 0x44, p1: 0x00, p2: 0x00)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .activate)
    }

    /// `GENERATE ASYMMETRIC KEY PAIR` in read mode (`P1 = 0x81`) returns the
    /// public key in `7F49`, with the EC point in `86`.
    ///
    /// The slot is addressed by the Control Reference Template sent as a **TLV
    /// with an empty value** (`B6 00` / `A4 00`). A bare tag (`B6`, Lc=01) was
    /// rejected by real hardware with `6A80`; this is the resolved form.
    ///
    /// For Ed25519 the point is the raw 32-byte Edwards point; whether the card
    /// prefixes it with `0x40` is an M0 hardware-verification item, and a
    /// non-matching encoding fails the ceremony's read-back step.
    public func readPublicKey(slot: KeySlot) async throws -> [UInt8] {
        let controlReference = KeySlotObjects.forSlot(slot).controlReference
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
            data: TLV(tag: controlReference, value: []).encoded,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .readPublicKey)
        let objects = try TLVParser.parse(response.data)
        guard let point = TLVParser.find(OpenPGPDataObject.ecdsaPublicPoint, in: objects) else {
            // A public key template without an EC point is a non-EC key: on
            // firmware older than 5.2.3 (OpenPGP applet < 3.4) the slots default
            // to RSA, whose template carries modulus (0x81) and exponent (0x82)
            // instead of the EC point (0x86).
            if TLVParser.find(OpenPGPDataObject.rsaModulus, in: objects) != nil {
                throw CardError.unsupportedKeyType("an RSA key occupies the \(slot.displayName.lowercased())")
            }
            throw CardError.malformedResponse("public key template 7F49 had no EC point (86); YubiKey firmware 5.2.3 or newer is required for secp256k1/Ed25519")
        }
        // The card returns secp256k1 points as 65-byte uncompressed (04 || X || Y),
        // whereas the app derives them as 33-byte compressed. Normalise to
        // compressed so the read-back comparison is byte-for-byte; Ed25519 points
        // (32 raw bytes) pass through unchanged.
        let pointValue = point.value
        if pointValue.count == Secp256k1.uncompressedPublicKeyLength, pointValue.first == 0x04 {
            return try Secp256k1.compressedPublicKey(fromUncompressed: pointValue)
        }
        return pointValue
    }

    // MARK: SignerCard conformance

    public func inventory() async throws -> CardInventory {
        let applicationData = try await applicationData()
        // The security support template is optional: a card that refuses it
        // should not block the inventory.
        let sst = try? await securitySupportTemplate()
        let parsed = try OpenPGPApplicationData.parse(applicationData: applicationData, securitySupportTemplate: sst)

        var attributes: [KeySlot: [UInt8]] = [:]
        if let value = parsed.algorithmAttributesSignature { attributes[.signature] = value }
        if let value = parsed.algorithmAttributesAuthentication { attributes[.authentication] = value }

        // Detect an existing key per slot by attempting a read. 6A88 ("referenced
        // data not found") means the slot is empty, which is the only reliable
        // signal — a fingerprint object may be present-but-zero.
        var occupied: Set<KeySlot> = []
        var probeFailures: [KeySlot: String] = [:]
        for slot in KeySlot.allCases {
            do {
                _ = try await readPublicKey(slot: slot)
                occupied.insert(slot)
            } catch CardError.unexpectedStatusWord(let sw1, let sw2)
                where (sw1 == 0x6A && sw2 == 0x88) || (sw1 == 0x65 && sw2 == 0x81) {
                // Empty slot. 6A88 ("referenced data not found") is what most
                // firmware answers; YubiKey 5.4.x answers 6581 ("memory failure")
                // for a slot that holds no key. Both mean "nothing here".
                continue
            } catch CardError.conditionsNotSatisfied {
                continue
            } catch CardError.unsupportedKeyType {
                // A non-EC key occupies the slot (RSA on firmware < 5.2.3). It
                // still counts as occupied so the destructive reset is gated;
                // the reset replaces it with the EC keys this app provisions.
                occupied.insert(slot)
            } catch let error as CardError {
                // Any other card-level failure while probing the slot — 6A80
                // "wrong data", 6D00 "instruction not supported", a 7F49 without
                // an EC point — must not abort the whole inventory. The
                // applet-version gate (isDefinitelyUnsupported) decides whether
                // the card can be provisioned; here we only want occupancy, so
                // record the failure and keep going so the version and serial are
                // still reported.
                probeFailures[slot] = Self.probeFailureDetail(error)
            }
        }

        let counter = parsed.signatureCounter

        return CardInventory(
            openPGPVersion: parsed.openPGPVersion ?? "unknown",
            manufacturer: parsed.manufacturer.map { String(format: "0x%04X", $0) },
            serial: parsed.serial.map { String(format: "%08X", $0) },
            algorithmAttributes: attributes,
            pwStatusBytes: parsed.pwStatusBytes,
            occupiedSlots: occupied,
            signatureCounter: counter,
            isFactoryFresh: occupied.isEmpty && (counter ?? 0) == 0,
            probeFailures: probeFailures
        )
    }

    /// Short human-readable reason for a slot-probe failure, for the inventory.
    private static func probeFailureDetail(_ error: CardError) -> String {
        switch error {
        case .unexpectedStatusWord(let sw1, let sw2):
            return String(format: "%02X%02X", sw1, sw2)
        case .unsupportedFeature(let detail):
            return detail
        case .malformedResponse(let detail):
            return detail
        default:
            return error.userFacingDescription
        }
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

    /// Applies the mandatory policy to both signing-capable slots.
    ///
    /// The Admin PIN is required because `PUT DATA` of these objects is protected.
    public func applyPolicy(adminPIN: [UInt8]) async throws {
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)

        // Touch required for every use, and not relaxable later, on both slots.
        for slot in KeySlot.allCases {
            try await putData(
                tag: KeySlotObjects.forSlot(slot).uif,
                value: OpenPGPTouchPolicy.fixedEncoded,
                operation: .applyPolicy
            )
        }
        try await putData(
            tag: OpenPGPDataObject.pwStatusBytes,
            value: PWStatusBytes.encode(),
            operation: .applyPolicy
        )
    }

    public func importKey(
        slot: KeySlot,
        algorithm: KeyAlgorithm,
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws {
        // Re-verify in THIS session: the ceremony spans several short-lived NFC
        // sessions, and VERIFY state does not survive a session boundary.
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)

        var raw = privateKey.materializedCopy()
        defer { wipe(&raw) }

        let objects = KeySlotObjects.forSlot(slot)

        // Algorithm attributes MUST be written before the key: the card needs to
        // know the curve to interpret the 32-byte key material. The previous
        // order — import first, attributes second — failed on real hardware with
        // 6A80 because the slot still carried its default RSA attributes.
        try await putData(
            tag: objects.algorithmAttributes,
            value: KeyImportTemplate.algorithmAttributes(for: algorithm),
            operation: .setAlgorithmAttributes
        )

        // The addressed slot must be empty: PUT DATA of a private key is rejected
        // on an occupied slot, and the ceremony treats that as a hard failure
        // rather than trying to work around it.
        try await putData(
            tag: OpenPGPDataObject.extendedHeaderList,
            value: KeyImportTemplate.extendedHeaderList(privateKey: raw, slot: slot),
            addressing: (0x3F, 0xFF),
            ins: 0xDB,
            operation: .importKey
        )

        try await putData(
            tag: objects.fingerprint,
            value: KeyImportTemplate.paddedFingerprint(fingerprint),
            operation: .importKey
        )

        // Creation time is advisory metadata. The tag is the one design.md
        // specifies; if the firmware rejects it the ceremony continues, because
        // the fingerprint and the read-back comparison are the real checks.
        do {
            try await putData(
                tag: objects.timestamp,
                value: KeyImportTemplate.creationTime(creationTime),
                operation: .importKey
            )
        } catch let error as CardError {
            switch error {
            case .unexpectedStatusWord, .unsupportedFeature, .keyImportRejected:
                // The generation time is advisory metadata; a card that rejects
                // it (e.g. an unknown tag) must not fail the ceremony.
                break
            default:
                throw error
            }
        }
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

    /// `GET CHALLENGE` (INS 0x84) — the card's hardware random-number generator.
    ///
    /// This is the entropy source for mnemonic generation (design.md §4.2 step 4):
    /// the 256 BIP39 entropy bits come from the YubiKey's secure element rather
    /// than the iOS CSPRNG. The exact per-call response-length limit is an M0
    /// hardware-verification item (`docs/m0-hardware-verification.md`); this
    /// requests `count` bytes in one call and fails if fewer come back.
    public func randomBytes(count: Int) async throws -> SensitiveBytes {
        let apdu = CommandAPDU(cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: [], expectedLength: count)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .getChallenge)
        guard response.data.count == count else {
            throw CardError.malformedResponse("GET CHALLENGE returned \(response.data.count) bytes, expected \(count)")
        }
        return SensitiveBytes(copying: response.data)
    }

    // MARK: Status word handling

    static func check(_ response: ResponseAPDU, operation: OpenPGPOperation) throws {
        if let error = OpenPGPStatusMapper.error(for: response.status, context: operation) {
            throw error
        }
    }
}
