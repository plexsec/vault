import Foundation
import VaultKit

/// OpenPGP smart-card data object tags (ISO 7816 / OpenPGP card spec 3.4).
///
/// Tag numbering differs between OpenPGP card 2.x and 3.x for the per-key
/// objects, so the two places this matters are called out explicitly below and
/// every write is verified by reading the object back.
public enum OpenPGPDataObject {
    // Application / cardholder data
    public static let applicationIdentifier: UInt16 = 0x004F
    public static let historicalBytes: UInt16 = 0x5F52
    public static let discretionaryData: UInt16 = 0x0073
    public static let applicationRelatedData: UInt16 = 0x006E
    public static let cardholderRelatedData: UInt16 = 0x0065
    public static let securitySupportTemplate: UInt16 = 0x007A

    // Capabilities and algorithm attributes
    public static let extendedCapabilities: UInt16 = 0x00C0
    public static let algorithmAttributesSignature: UInt16 = 0x00C1
    public static let algorithmAttributesDecryption: UInt16 = 0x00C2
    public static let algorithmAttributesAuthentication: UInt16 = 0x00C3

    // Password status
    public static let pwStatusBytes: UInt16 = 0x00C4

    // Fingerprints. 2.x used a single combined 0xC5 (three 20-byte
    // fingerprints); 3.4 defines per-key objects. This app writes 0xC7 and
    // reports whichever of 0xC5/0xC7 the card actually exposes.
    public static let fingerprintsCombined: UInt16 = 0x00C5
    public static let caFingerprints: UInt16 = 0x00C6
    public static let fingerprintSignature: UInt16 = 0x00C7
    public static let fingerprintDecryption: UInt16 = 0x00C8
    public static let fingerprintAuthentication: UInt16 = 0x00C9

    // Per-key timestamps (OpenPGP 3.4): 0xCA signature, 0xCB decryption, 0xCC auth.
    public static let timestampSignature: UInt16 = 0x00CA
    public static let timestampDecryption: UInt16 = 0x00CB
    public static let timestampAuthentication: UInt16 = 0x00CC
    /// Creation time as specified by design.md §4.2 step 6 (`0xCE`).
    ///
    /// This tag is NOT independently confirmed against the OpenPGP card spec in
    /// this codebase; the spec's per-key timestamp object is 0xCA. The write is
    /// therefore treated as advisory: it is attempted, its read-back is checked,
    /// and a rejection is recorded as a warning rather than failing the ceremony,
    /// because the fingerprint and the public-key read-back are what the security
    /// argument depends on. Resolved against real hardware in milestone M0.
    public static let creationTimeSignature: UInt16 = 0x00CE

    // Touch policy (User Interaction Flag), per slot
    public static let uifSignature: UInt16 = 0x00D6
    public static let uifDecryption: UInt16 = 0x00D7
    public static let uifAuthentication: UInt16 = 0x00D8

    // Key material containers
    public static let extendedHeaderList: UInt16 = 0x004D
    public static let controlReferenceTemplateSignature: UInt16 = 0x00B6
    public static let controlReferenceTemplateDecryption: UInt16 = 0x00B8
    public static let controlReferenceTemplateAuthentication: UInt16 = 0x00A4
    public static let privateKeyTemplate: UInt16 = 0x7F48
    public static let privateKey: UInt16 = 0x5F48
    public static let publicKeyTemplate: UInt16 = 0x7F49
    public static let ecdsaPublicPoint: UInt16 = 0x0086

    // Security support template contents
    public static let signatureCounter: UInt16 = 0x0093
}

/// The OpenPGP data objects that belong to one key slot.
///
/// Tag numbering for the per-key objects differs between OpenPGP card 2.x and
/// 3.x, which is why every write is verified by reading the object back. These
/// are the 3.4 tags the rest of this codebase already uses for the signature
/// slot, extended to the authentication slot.
public struct KeySlotObjects {
    public let slot: KeySlot
    /// Control reference template used by key import and public-key read-back.
    public let controlReference: UInt16
    public let algorithmAttributes: UInt16
    public let fingerprint: UInt16
    /// Per-key timestamp. design.md §4.2 step 6 names 0xCE for the signature
    /// slot; see `OpenPGPDataObject.creationTimeSignature` for the caveat.
    public let timestamp: UInt16
    public let uif: UInt16

    public static func forSlot(_ slot: KeySlot) -> KeySlotObjects {
        switch slot {
        case .signature:
            return KeySlotObjects(
                slot: slot,
                controlReference: OpenPGPDataObject.controlReferenceTemplateSignature,
                algorithmAttributes: OpenPGPDataObject.algorithmAttributesSignature,
                fingerprint: OpenPGPDataObject.fingerprintSignature,
                timestamp: OpenPGPDataObject.creationTimeSignature,
                uif: OpenPGPDataObject.uifSignature
            )
        case .authentication:
            return KeySlotObjects(
                slot: slot,
                controlReference: OpenPGPDataObject.controlReferenceTemplateAuthentication,
                algorithmAttributes: OpenPGPDataObject.algorithmAttributesAuthentication,
                fingerprint: OpenPGPDataObject.fingerprintAuthentication,
                timestamp: OpenPGPDataObject.timestampAuthentication,
                uif: OpenPGPDataObject.uifAuthentication
            )
        }
    }
}

/// OpenPGP card password references (`P2` of VERIFY / CHANGE REFERENCE DATA).
public enum OpenPGPPinReference: UInt8 {
    case user = 0x81          // PW1, mode 81: valid for one signature
    case userMode82 = 0x82    // PW1, mode 82: valid for one PSO:CDS
    case admin = 0x83         // PW3
    case resettingCode = 0x84 // PW2
}

/// Factory-default PINs after TERMINATE DF + ACTIVATE FILE (design.md §4.2 step 3).
public enum OpenPGPPinDefaults {
    public static let user: [UInt8] = Array("123456".utf8)
    public static let admin: [UInt8] = Array("12345678".utf8)
}

/// Touch policy (UIF) values.
///
/// The precise meaning of the policy byte is one of the items milestone M0
/// confirms against `ykman openpgp info`. v1 writes exactly what design.md
/// §6.5 specifies and verifies the read-back.
public enum OpenPGPTouchPolicy {
    /// `0x02` fixed: touch required for every use and cannot be relaxed later.
    public static let fixed: UInt8 = 0x02
    /// Encoded value for the UIF data object (2 bytes, per design.md §6.5).
    public static let fixedEncoded: [UInt8] = [0x02, 0x20]
}

/// Parsed view of the OpenPGP card's application data (GET DATA 0x6E) and
/// security support template (GET DATA 0x7A).
public struct OpenPGPApplicationData: Equatable {
    public var applicationIdentifier: [UInt8]?
    public var historicalBytes: [UInt8]?
    public var openPGPVersion: String?
    public var manufacturer: UInt16?
    public var serial: UInt32?
    public var extendedCapabilities: [UInt8]?
    public var algorithmAttributesSignature: [UInt8]?
    public var algorithmAttributesAuthentication: [UInt8]?
    public var pwStatusBytes: [UInt8]?
    public var fingerprintSignature: [UInt8]?
    public var combinedFingerprints: [UInt8]?
    public var signatureCounter: UInt32?

    public init() {}

    public static func parse(applicationData: [UInt8], securitySupportTemplate: [UInt8]? = nil) throws -> OpenPGPApplicationData {
        var result = OpenPGPApplicationData()
        let topLevel = try TLVParser.parse(applicationData)

        // The card may or may not wrap the objects in 0x6E.
        let objects: [TLV]
        if let wrapper = topLevel.first(where: { $0.tag == OpenPGPDataObject.applicationRelatedData }) {
            objects = (try? TLVParser.parse(wrapper.value)) ?? topLevel
        } else {
            objects = topLevel
        }

        result.applicationIdentifier = TLVParser.find(OpenPGPDataObject.applicationIdentifier, in: objects)?.value
        result.historicalBytes = TLVParser.find(OpenPGPDataObject.historicalBytes, in: objects)?.value
        result.extendedCapabilities = TLVParser.find(OpenPGPDataObject.extendedCapabilities, in: objects)?.value
        result.algorithmAttributesSignature = TLVParser.find(OpenPGPDataObject.algorithmAttributesSignature, in: objects)?.value
        result.algorithmAttributesAuthentication = TLVParser.find(OpenPGPDataObject.algorithmAttributesAuthentication, in: objects)?.value
        result.pwStatusBytes = TLVParser.find(OpenPGPDataObject.pwStatusBytes, in: objects)?.value
        result.fingerprintSignature = TLVParser.find(OpenPGPDataObject.fingerprintSignature, in: objects)?.value
        result.combinedFingerprints = TLVParser.find(OpenPGPDataObject.fingerprintsCombined, in: objects)?.value

        if let aid = result.applicationIdentifier {
            // AID = RID(5) || PIX prefix(3) || version(2) || manufacturer(2) || serial(4) || RFU(2)
            if aid.count >= 14 {
                let version = (Int(aid[6]) << 8) | Int(aid[7])
                result.openPGPVersion = "\((version >> 8) & 0xFF).\(version & 0xFF)"
                result.manufacturer = (UInt16(aid[8]) << 8) | UInt16(aid[9])
                result.serial = (UInt32(aid[10]) << 24) | (UInt32(aid[11]) << 16)
                    | (UInt32(aid[12]) << 8) | UInt32(aid[13])
            }
        }

        if result.openPGPVersion == nil, let historical = result.historicalBytes, historical.count >= 4 {
            // Historical bytes for the OpenPGP card carry the version as BCD.
            result.openPGPVersion = "\(historical[2] >> 4).\(historical[2] & 0x0F)"
        }

        if let sst = securitySupportTemplate {
            let sstObjects = try TLVParser.parse(sst)
            if let counter = TLVParser.find(OpenPGPDataObject.signatureCounter, in: sstObjects)?.value,
               counter.count == 3 {
                result.signatureCounter = (UInt32(counter[0]) << 16) | (UInt32(counter[1]) << 8) | UInt32(counter[2])
            }
        }

        return result
    }
}

/// The Extended Header List that `PUT DATA 3F FF` carries for key import.
///
/// Layout (OpenPGP card spec 4.4.1.1, "key import"):
///
///     PUT DATA  P1P2 = 3F FF
///     data = 4D | <CRT> | 7F48 | 5F48 | <2-byte length> <secret>
///
/// `<CRT>` selects the slot: 0xB6 for the signature slot, 0xA4 for the
/// authentication slot. The secret is a single component encoded with the same
/// 2-byte length prefix the spec uses for RSA components: the secp256k1 scalar,
/// or the 32-byte Ed25519 seed.
///
/// This exact byte layout is one of the items milestone M0 confirms against a
/// hardware APDU trace; a malformed template cannot produce a wrong key
/// silently, because the ceremony's read-back step compares the card's public
/// key with the derived one.
public enum KeyImportTemplate {
    public static func extendedHeaderList(privateKey: [UInt8], slot: KeySlot) -> [UInt8] {
        precondition(privateKey.count == 32, "secp256k1 scalars and Ed25519 seeds are 32 bytes")

        // 5F48: one component = 2-byte length prefix + secret
        var component: [UInt8] = [UInt8((privateKey.count >> 8) & 0xFF), UInt8(privateKey.count & 0xFF)]
        component.append(contentsOf: privateKey)
        let privateKeyTLV = TLV(tag: OpenPGPDataObject.privateKey, value: component)

        // 7F48: private key template wrapping the key material
        let templateTLV = TLV(tag: OpenPGPDataObject.privateKeyTemplate, value: privateKeyTLV.encoded)

        // CRT: control reference template for the addressed slot
        let crt = KeySlotObjects.forSlot(slot).controlReference
        let crtTLV = TLV(tag: crt, value: templateTLV.encoded)

        // 4D: extended header list
        return TLV(tag: OpenPGPDataObject.extendedHeaderList, value: crtTLV.encoded).encoded
    }

    /// Algorithm attributes for ECDSA over secp256k1: `0x13` (ECDSA) followed by
    /// the curve OID 1.3.132.0.10 as an ASN.1 DER-encoded object identifier.
    public static let ecdsaSecp256k1AlgorithmAttributes: [UInt8] = [
        0x13,                   // algorithm id: ECDSA
        0x2B, 0x81, 0x04, 0x00, 0x22, // OID 1.3.132.0.10 (secp256k1)
        0x00,                   // no format byte for ECDSA
    ]

    /// Algorithm attributes for EdDSA over Ed25519: `0x16` (EdDSA) followed by
    /// the OID 1.3.6.1.4.1.11591.15.1 that GnuPG uses for Ed25519.
    ///
    /// RFC 8410's `id-Ed25519` (1.3.101.112) is the other candidate; which one
    /// the applet expects is an M0 hardware-verification item, and a wrong OID
    /// fails visibly at the import or read-back step.
    public static let eddsaEd25519AlgorithmAttributes: [UInt8] = [
        0x16,                   // algorithm id: EdDSA
        0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01, // OID 1.3.6.1.4.1.11591.15.1
        0x00,                   // no format byte
    ]

    public static func algorithmAttributes(for algorithm: KeyAlgorithm) -> [UInt8] {
        switch algorithm {
        case .secp256k1: return ecdsaSecp256k1AlgorithmAttributes
        case .ed25519: return eddsaEd25519AlgorithmAttributes
        }
    }

    /// Fingerprint written for a key: 20 bytes, zero-padded from the four-byte
    /// derivation fingerprint.
    public static func paddedFingerprint(_ fingerprint: [UInt8]) -> [UInt8] {
        precondition(fingerprint.count <= 20)
        var out = fingerprint
        while out.count < 20 { out.append(0) }
        return out
    }

    /// Creation time as 4-byte big-endian Unix time.
    public static func creationTime(_ date: Date) -> [UInt8] {
        let seconds = UInt32(clamping: Int(date.timeIntervalSince1970))
        return [
            UInt8((seconds >> 24) & 0xFF),
            UInt8((seconds >> 16) & 0xFF),
            UInt8((seconds >> 8) & 0xFF),
            UInt8(seconds & 0xFF),
        ]
    }
}

/// PW status bytes (DO 0xC4): PW1 status, then max lengths for PW1, PW2, PW3.
public enum PWStatusBytes {
    /// PW1 status 0x00 = the PIN must be re-verified for every signature, which
    /// is the policy design.md §4.2 step 3 requires.
    public static let pinRequiredPerSignature: UInt8 = 0x00

    public static func encode(pw1Status: UInt8 = pinRequiredPerSignature, maxLength: Int = 127) -> [UInt8] {
        [
            pw1Status,
            UInt8((maxLength >> 8) & 0xFF), UInt8(maxLength & 0xFF),
            UInt8((maxLength >> 8) & 0xFF), UInt8(maxLength & 0xFF),
            UInt8((maxLength >> 8) & 0xFF), UInt8(maxLength & 0xFF),
        ]
    }

    public static func pw1RequiresPin(_ bytes: [UInt8]?) -> Bool? {
        guard let first = bytes?.first else { return nil }
        return first == pinRequiredPerSignature
    }
}
