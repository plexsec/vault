import Foundation

#if canImport(Security)
import Security
#endif

/// The iOS system CSPRNG (`SecRandomCopyBytes`).
///
/// Used to mix entropy with the card's hardware RNG: the two sources are XORed,
/// so that neither a backdoored card RNG nor a backdoored OS RNG alone can
/// determine the mnemonic — either one being unpredictable keeps the result
/// unpredictable.
public enum SystemCSPRNG {
    public static func randomBytes(count: Int) throws -> SensitiveBytes {
        precondition(count > 0, "requested byte count must be positive")
        let buffer = SensitiveBytes(count: count)
        let status = buffer.withUnsafeMutableBytes { raw -> Int32 in
            #if canImport(Security)
            return SecRandomCopyBytes(kSecRandomDefault, count, raw.baseAddress!)
            #else
            // Non-Apple platforms only (this package targets Apple OSes).
            for i in 0..<count { raw[i] = UInt8.random(in: 0...255) }
            return errSecSuccess
            #endif
        }
        guard status == errSecSuccess else {
            throw CeremonyError.systemEntropyUnavailable(status)
        }
        return buffer
    }
}

// MARK: - Key slots

/// An OpenPGP key slot.
///
/// The card has three (signature, decryption, authentication), but only two can
/// produce a signature, and only **one** of those — the signature slot — drives
/// the hardware signature counter that §5.2's audit depends on. That asymmetry
/// is the whole reason the algorithm-to-slot assignment is fixed rather than
/// configurable; see `KeyAlgorithm.slot` and design.md §4.3.
public enum KeySlot: String, CaseIterable, Codable, Sendable, Hashable {
    /// CRT 0xB6 / algorithm attributes 0xC1 / fingerprint 0xC7 / UIF 0xD6.
    /// Counted by `GET DATA 0x7A` → `93`.
    case signature
    /// CRT 0xA4 / algorithm attributes 0xC3 / fingerprint 0xC9 / UIF 0xD8.
    /// **No** hardware signature counter: `INTERNAL AUTHENTICATE` is not counted.
    case authentication

    public var displayName: String {
        switch self {
        case .signature: return "Signature slot"
        case .authentication: return "Authentication slot"
        }
    }

    /// Whether operations in this slot increment the OpenPGP signature counter.
    public var incrementsSignatureCounter: Bool {
        self == .signature
    }
}

// MARK: - Card abstraction

/// Everything the provisioning ceremony needs from a YubiKey.
///
/// Implemented by `YubikeyKit.OpenPGPCard` over NFC or USB-C CCID, and by a
/// scripted mock in tests. Keeping this protocol in VaultKit means the entire
/// ceremony state machine is testable with no hardware, no radio and no
/// CryptoTokenKit.
public protocol SignerCard: AnyObject {
    /// Reads application data (0x6E) and the security support template (0x7A).
    func inventory() async throws -> CardInventory

    /// Reads `count` random bytes from the card's hardware random-number
    /// generator (`GET CHALLENGE`, INS 0x84). This is the entropy source for
    /// mnemonic generation (design.md §4.2 step 4).
    func randomBytes(count: Int) async throws -> SensitiveBytes

    /// `VERIFY PW3` + `TERMINATE DF` + `ACTIVATE FILE`, then re-selects.
    /// Resets **all** slots.
    func reset(adminPIN: [UInt8]) async throws

    /// Sets PW1 (user) and PW3 (admin) via `CHANGE REFERENCE DATA`.
    func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws

    /// Applies the mandatory policy: UIF = Fixed on both signing-capable slots
    /// and PW1 status 0x00 (PIN required for every signature).
    ///
    /// The Admin PIN is required because these are protected data objects, and
    /// implementations must re-verify PW3 in this session before writing.
    func applyPolicy(adminPIN: [UInt8]) async throws

    /// Writes one key into `slot`: `PUT DATA 3F FF` with the Extended Header
    /// List for the slot's CRT, then the algorithm attributes, fingerprint and
    /// creation time.
    ///
    /// The Admin PIN is passed in rather than assumed to still be verified: a
    /// ceremony spans many short-lived NFC sessions, and VERIFY state does not
    /// survive a session boundary. Implementations must re-verify PW3 themselves.
    func importKey(
        slot: KeySlot,
        algorithm: KeyAlgorithm,
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws

    /// `GENERATE ASYMMETRIC KEY PAIR` (P1 = 0x81) for `slot` — reads the public
    /// key back out of the card without a PIN.
    func readPublicKey(slot: KeySlot) async throws -> [UInt8]

    /// `GET DATA 0x7A` -> security support template `93 03 <counter>`.
    ///
    /// This is the **signature** slot's counter; the authentication slot has
    /// none, which is why the audit covers secp256k1 only.
    func signatureCounter() async throws -> UInt32

    /// Writes a single data object (algorithm attributes, PW status, UIF,
    /// fingerprint, creation time).
    func putDataObject(_ tag: UInt16, value: [UInt8]) async throws

    /// Reads a single data object by tag.
    func getDataObject(_ tag: UInt16) async throws -> [UInt8]

    /// `GET DATA` for one of the applet's private-use data objects.
    ///
    /// `nil` means "the object is there and empty", which is what the hardware
    /// answers for a never-written object (`9000` with no data) and the state a
    /// reset leaves behind. A card that has no such object at all throws, so the
    /// two cases cannot be confused: an empty manifest is a card that can store
    /// one, a thrown error is a card that cannot.
    func readPairingManifest() async throws -> [UInt8]?

    /// `PUT DATA` for the private-use data object the pairing manifest lives in.
    ///
    /// The Admin PIN is required and must be re-verified in this session, for the
    /// same reason `importKey` does it: NFC sessions are short and VERIFY state
    /// does not survive one.
    func writePairingManifest(_ manifest: [UInt8], adminPIN: [UInt8]) async throws
}

public enum CardError: Swift.Error, Equatable {
    case transportUnavailable(String)
    case cardNotSelected
    case pinIncorrect(retriesRemaining: Int?)
    case pinBlocked
    case adminPinBlocked
    case conditionsNotSatisfied
    case unsupportedFirmware
    case keyImportRejected
    case signatureFailed
    case unexpectedStatusWord(sw1: UInt8, sw2: UInt8)
    case malformedResponse(String)
    case unsupportedFeature(String)
    case unsupportedKeyType(String)
    /// A value that cannot fit the card's storage for the object being written.
    /// Raised before the card is asked, because the answer would be the same
    /// every time: the private-use data objects hold at most 254 bytes.
    case dataObjectTooLarge(byteCount: Int, maximum: Int)

    /// User-facing text. Kept here so every surface reports the same wording.
    /// Whether this failure leaves the card in a state the ceremony cannot
    /// predict, and therefore has to re-inspect it before doing anything else.
    ///
    /// The distinction is what stops a mistyped Admin PIN from sending the
    /// operator back to the inventory screen (nothing was written), while an
    /// interrupted `PUT DATA` still forces a re-read. Anything not listed as a
    /// definitive rejection is treated as unknown, which is the conservative
    /// reading: a wrong "unknown" costs one card read, a wrong "known" could
    /// hide a half-written key.
    ///
    /// The definitive rejections are exactly the status words that mean the card
    /// *refused* the operation: a failed or blocked PIN, unmet preconditions, an
    /// unsupported algorithm or object, and a rejected key import. In each case
    /// the card answered, and answered "no".
    public var isDefinitiveCardRejection: Bool {
        switch self {
        case .pinIncorrect, .pinBlocked, .adminPinBlocked:
            return true
        case .conditionsNotSatisfied, .unsupportedFirmware, .keyImportRejected:
            return true
        case .unsupportedFeature, .unsupportedKeyType:
            return true
        case .dataObjectTooLarge:
            // Nothing was written and no retry can succeed: the value cannot fit.
            return true
        case .transportUnavailable, .cardNotSelected, .malformedResponse:
            return false
        case .unexpectedStatusWord, .signatureFailed:
            return false
        }
    }

    public var userFacingDescription: String {
        switch self {
        case .transportUnavailable(let detail):
            return "The YubiKey could not be reached (\(detail))."
        case .cardNotSelected:
            return "The OpenPGP application is not selected on this YubiKey."
        case .pinIncorrect(let retries):
            if let retries {
                return "Incorrect User PIN. Attempts remaining before lockout: \(retries)."
            }
            return "Incorrect User PIN."
        case .pinBlocked:
            return "The User PIN is blocked. Terminate and re-activate the OpenPGP applet to recover."
        case .adminPinBlocked:
            return "The Admin PIN is blocked. Recovery requires a reset, which itself needs the Admin PIN — this card can no longer be provisioned."
        case .conditionsNotSatisfied:
            return "The YubiKey refused the operation because its preconditions were not met (wrong state, or a PIN step was skipped)."
        case .unsupportedFirmware:
            return "This YubiKey's OpenPGP applet does not support the requested algorithm. Firmware 5.2.3 or newer is required."
        case .keyImportRejected:
            return "The YubiKey rejected the private key import."
        case .signatureFailed:
            return "The YubiKey reported a signing failure."
        case .unexpectedStatusWord(let sw1, let sw2):
            return String(format: "Unexpected card response %02X%02X.", sw1, sw2)
        case .malformedResponse(let detail):
            return "The card response could not be parsed: \(detail)."
        case .unsupportedFeature(let detail):
            return "Unsupported by this YubiKey: \(detail)."
        case .unsupportedKeyType(let detail):
            return "This slot holds a key this app does not support: \(detail)."
        case .dataObjectTooLarge(let byteCount, let maximum):
            return "The value is \(byteCount) bytes but this card holds at most \(maximum) in that object."
        }
    }
}

/// How the pairing-manifest step ended.
///
/// A card that cannot store a manifest is not a failure — the keys and the
/// mnemonic, which are what hold funds, are unaffected — so the step records what
/// happened and moves on. The distinction is kept in the report so the operator
/// knows whether re-pairing will need the mnemonic again.
public enum PairingManifestOutcome: Equatable, Sendable {
    case stored(PairingManifest)
    /// Not stored, with the reason, for the report and the screen.
    case declined(reason: String)

    public var manifest: PairingManifest? {
        if case .stored(let manifest) = self { return manifest }
        return nil
    }

    public var isStored: Bool { manifest != nil }
}

/// What a card's private-use data object holds — the pairing manifest slot.
///
/// This is read during inventory because it decides whether the card can be
/// re-paired without a reset. It is *not* a gate on provisioning: a card that
/// cannot store a manifest is still perfectly provisionable, it just costs the
/// operator a re-run of the ceremony (mnemonic included) the next time the
/// pairing codes are needed.
public enum PairingManifestState: Equatable, Sendable {
    /// The card refused the read of the private-use object, so it has no place to
    /// keep a manifest. Reported, never fatal.
    case unsupported
    /// Readable and empty — what a freshly reset applet looks like, because
    /// `TERMINATE DF` wipes the object with everything else.
    case absent
    case present(byteCount: Int)
    /// The read failed for some other reason, with the card's own words.
    case unreadable(String)

    public var isPresent: Bool {
        if case .present = self { return true }
        return false
    }

    public var byteCount: Int? {
        if case .present(let count) = self { return count }
        return nil
    }
}

/// What the ceremony learns about the card before touching it.
public struct CardInventory: Equatable, Sendable {
    public var openPGPVersion: String
    public var manufacturer: String?
    public var serial: String?
    /// Raw algorithm attributes per slot (0xC1 / 0xC3), where present.
    public var algorithmAttributes: [KeySlot: [UInt8]]
    /// Raw 0xC4 PW status bytes, if present.
    public var pwStatusBytes: [UInt8]?
    /// Slots that already hold a key.
    public var occupiedSlots: Set<KeySlot>
    /// `GET DATA 0x7A` -> 0x93 counter, if readable without a PIN.
    public var signatureCounter: UInt32?
    /// True when the card looks factory-fresh (no key in any slot, no counter).
    public var isFactoryFresh: Bool
    /// Slots whose public key could not be read during inventory, with the reason
    /// (status word hex or detail). An empty slot answers 6A88 and is not recorded
    /// here; this is for cards that answered the key-read with an unexpected
    /// status — e.g. 6581 on an applet that predates EC support — which must not
    /// abort the whole inventory. The applet-version gate (`isDefinitelyUnsupported`)
    /// is what decides whether such a card can be provisioned at all.
    public var probeFailures: [KeySlot: String]
    /// Whether the card's private-use data object can hold a pairing manifest,
    /// and what is in it now.
    public var pairingManifest: PairingManifestState

    public init(
        openPGPVersion: String,
        manufacturer: String? = nil,
        serial: String? = nil,
        algorithmAttributes: [KeySlot: [UInt8]] = [:],
        pwStatusBytes: [UInt8]? = nil,
        occupiedSlots: Set<KeySlot> = [],
        signatureCounter: UInt32? = nil,
        isFactoryFresh: Bool = true,
        probeFailures: [KeySlot: String] = [:],
        pairingManifest: PairingManifestState = .unsupported
    ) {
        self.openPGPVersion = openPGPVersion
        self.manufacturer = manufacturer
        self.serial = serial
        self.algorithmAttributes = algorithmAttributes
        self.pwStatusBytes = pwStatusBytes
        self.occupiedSlots = occupiedSlots
        self.signatureCounter = signatureCounter
        self.isFactoryFresh = isFactoryFresh
        self.probeFailures = probeFailures
        self.pairingManifest = pairingManifest
    }

    public func holdsKey(in slot: KeySlot) -> Bool { occupiedSlots.contains(slot) }

    /// The minimum OpenPGP applet version that supports secp256k1/Ed25519
    /// (YubiKey 5 firmware 5.2.3 or newer).
    public static let minimumOpenPGPVersion = (3, 4)

    /// secp256k1 requires OpenPGP 3.4+ applet behaviour, i.e. YubiKey 5 firmware
    /// 5.2.3 or newer. Reported rather than assumed, because the failure mode
    /// otherwise is an unexplained 6A80 at key-import time.
    public var likelySupportsSecp256k1: Bool {
        guard let version = Self.parseVersion(openPGPVersion) else { return false }
        return version >= Self.minimumOpenPGPVersion
    }

    /// True when the reported applet version is definitively below the minimum.
    /// An older applet (2.x / 3.3) cannot be provisioned with secp256k1/Ed25519
    /// at all, and its firmware is not upgradeable — the ceremony hard-gates on
    /// this rather than merely warning.
    public var isDefinitelyUnsupported: Bool {
        guard let version = Self.parseVersion(openPGPVersion) else { return false }
        return version < Self.minimumOpenPGPVersion
    }

    static func parseVersion(_ string: String) -> (Int, Int)? {
        let parts = string.split(separator: ".")
        guard parts.count >= 2, let major = Int(parts[0]), let minor = Int(parts[1]) else { return nil }
        return (major, minor)
    }
}

// MARK: - Steps

/// Ceremony steps in the order mandated by design.md §4.2.
///
/// `Comparable` is what enforces the hard gates: a step may only run when the
/// previously completed step is its immediate predecessor.
public enum CeremonyStep: Int, CaseIterable, Comparable, Codable, Sendable {
    case notStarted = 0
    case preflight
    case cardInventory
    case reset
    case pinProvisioning
    case policy
    case entropy
    case mnemonic
    case derivation
    case keyImport
    case readBackCheck
    /// Writes the pairing manifest into the card's private-use data object, so
    /// that the pairing codes can be produced again later without resetting the
    /// applet. Sits after the read-back check on purpose: nothing is advertised
    /// to a wallet until the keys it describes have been verified in the card.
    case pairingManifest
    case pairingExport
    case counterBaseline
    case teardown

    public static func < (lhs: CeremonyStep, rhs: CeremonyStep) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var title: String {
        switch self {
        case .notStarted: return "Not started"
        case .preflight: return "Preflight and consent"
        case .cardInventory: return "Inspect YubiKey"
        case .reset: return "Reset OpenPGP applet"
        case .pinProvisioning: return "Set PINs"
        case .policy: return "Apply touch and PIN policy"
        case .entropy: return "Generate entropy"
        case .mnemonic: return "Write down the mnemonic"
        case .derivation: return "Derive the signing keys"
        case .keyImport: return "Import keys into YubiKey"
        case .readBackCheck: return "Verify read-back keys"
        case .pairingManifest: return "Store the pairing manifest"
        case .pairingExport: return "Pair with the desktop wallet"
        case .counterBaseline: return "Record signature counter baseline"
        case .teardown: return "Wipe secrets and finish"
        }
    }

    /// Steps whose effect is destructive or writes to the card. A transport
    /// interruption during one of these requires re-inventorying the card before
    /// anything else happens (design.md §5.2 rule 1 forbids blind retries).
    public var isMutatingCardState: Bool {
        switch self {
        case .reset, .pinProvisioning, .policy, .keyImport, .pairingManifest: return true
        default: return false
        }
    }
}

public enum CeremonyMode: String, CaseIterable, Codable, Sendable {
    /// Fresh generation (design.md §4.2).
    case freshGeneration
    /// Recovery/restore of an existing mnemonic (design.md §8.2, §8.3 drill).
    case restoreFromMnemonic
}

public enum CeremonyError: Swift.Error, Equatable {
    case stepOutOfOrder(expected: CeremonyStep, actual: CeremonyStep)
    case stepIncomplete(step: CeremonyStep, detail: String)
    case pairingAddressNotConfirmed
    case missingAdminPIN
    case alreadyRunning
    case notRunning
    case missingEntropy
    case missingMnemonic
    case mnemonicNotConfirmed
    case transcriptionMismatch(index: Int)
    case invalidPINPolicy(String)
    case diceRollsOutOfRange
    case keysNotDerived
    case readBackMismatch(algorithm: KeyAlgorithm, local: String, card: String)
    case pairingPolicyNotAcknowledged
    case destructiveResetNotAcknowledged
    case cardNotFactoryFresh
    case counterNotZero(UInt32)
    case unsupportedRecovery(String)
    case unsupportedAlgorithm(KeyAlgorithm, String)
    case unsupportedAppletVersion(version: String)
    case systemEntropyUnavailable(Int32)

    public var userFacingDescription: String {
        switch self {
        case .stepOutOfOrder(let expected, let actual):
            return "Ceremony order violation: \(actual.title) cannot run before \(expected.title)."
        case .stepIncomplete(let step, let detail):
            return "\(step.title) is not finished: \(detail)."
        case .pairingAddressNotConfirmed:
            return "Confirm that your wallet shows the same address as this ceremony before continuing."
        case .missingAdminPIN:
            return "No Admin PIN is held for this session; the PIN step must run first."
        case .alreadyRunning: return "A ceremony is already in progress."
        case .notRunning: return "No ceremony is in progress."
        case .missingEntropy: return "No entropy has been generated yet."
        case .missingMnemonic: return "The mnemonic has not been generated yet."
        case .mnemonicNotConfirmed: return "Confirm the written-down mnemonic before continuing."
        case .transcriptionMismatch(let index):
            return "Word \(index + 1) does not match. Check the transcription against the screen."
        case .invalidPINPolicy(let detail): return detail
        case .diceRollsOutOfRange: return "Dice rolls must each be between 1 and 6."
        case .keysNotDerived: return "The signing keys have not been derived yet."
        case .readBackMismatch(let algorithm, _, _):
            return "The \(algorithm.displayName) public key read back from the YubiKey does not match the derived key. The procedure is void — restart from the card reset."
        case .pairingPolicyNotAcknowledged:
            return "The pairing code carries a chain code, which Keystone/MetaMask require. Confirm you understand that only the address shown on this screen can be signed for."
        case .destructiveResetNotAcknowledged:
            return "This YubiKey already holds a key. Resetting the OpenPGP applet will erase it, so the operation must be explicitly acknowledged."
        case .cardNotFactoryFresh:
            return "This YubiKey is not factory-fresh. Reset the OpenPGP applet first."
        case .counterNotZero(let value):
            return "The signature counter is \(value), not 0. The card may already have signed something."
        case .unsupportedRecovery(let detail):
            return "Restore is not possible here: \(detail)."
        case .unsupportedAlgorithm(let algorithm, let detail):
            return "\(algorithm.displayName) cannot be provisioned on this YubiKey: \(detail)."
        case .unsupportedAppletVersion(let version):
            return "This YubiKey's OpenPGP applet is version \(version), which does not support secp256k1 or Ed25519. A YubiKey with applet 3.4 or newer (firmware 5.2.3+) is required, and the firmware cannot be upgraded."
        case .systemEntropyUnavailable(let status):
            return "The system random-number generator failed (OSStatus \(status))."
        }
    }
}
