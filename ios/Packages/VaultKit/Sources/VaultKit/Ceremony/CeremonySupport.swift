import Foundation

// MARK: - Entropy

public enum EntropyError: Swift.Error, Equatable {
    case systemEntropyUnavailable(Int32)
    case invalidByteCount(Int)
}

/// Source of entropy for mnemonic generation.
///
/// v1 policy (design.md §4.2 step 4 as amended): the system CSPRNG is the
/// **authoritative** source. The dice ritual is recorded and displayed but is
/// explicitly non-authoritative, which is why it cannot be folded into this
/// protocol — a future dice-authoritative mode would need its own type so that
/// no call site can accidentally mix the two.
public protocol EntropySource {
    func randomBytes(count: Int) throws -> SensitiveBytes
}

#if canImport(Security)
import Security
#endif

/// `SecRandomCopyBytes` — the only entropy source used in production.
public struct SystemEntropySource: EntropySource {
    public init() {}

    public func randomBytes(count: Int) throws -> SensitiveBytes {
        guard count > 0 else { throw EntropyError.invalidByteCount(count) }
        let buffer = SensitiveBytes(count: count)
        let status = buffer.withUnsafeMutableBytes { raw -> Int32 in
            #if canImport(Security)
            return SecRandomCopyBytes(kSecRandomDefault, count, raw.baseAddress!)
            #else
            // Non-Apple platforms only (unit tests on Linux would land here).
            for i in 0..<count { raw[i] = UInt8.random(in: 0...255) }
            return errSecSuccess
            #endif
        }
        guard status == errSecSuccess else { throw EntropyError.systemEntropyUnavailable(status) }
        return buffer
    }
}

/// Deterministic source for tests. Never used outside the test target.
public struct ScriptedEntropySource: EntropySource {
    private let bytes: [UInt8]

    public init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    public init(repeating value: UInt8, count: Int) {
        self.bytes = [UInt8](repeating: value, count: count)
    }

    public func randomBytes(count: Int) throws -> SensitiveBytes {
        guard bytes.count >= count else { throw EntropyError.invalidByteCount(count) }
        return SensitiveBytes(copying: Array(bytes.prefix(count)))
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

    /// `VERIFY PW3` + `TERMINATE DF` + `ACTIVATE FILE`, then re-selects.
    func reset(adminPIN: [UInt8]) async throws

    /// Sets PW1 (user) and PW3 (admin) via `CHANGE REFERENCE DATA`.
    func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws

    /// Applies the mandatory policy: UIF = Fixed on the signature slot and
    /// PW1 status 0x00 (PIN required for every signature).
    ///
    /// The Admin PIN is required because these are protected data objects.
    func applyPolicy(adminPIN: [UInt8]) async throws

    /// `PUT DATA 3F FF` with the Extended Header List for CRT B6, then the
    /// algorithm attributes, fingerprint and creation time.
    func importSignatureKey(
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date
    ) async throws

    /// `GENERATE ASYMMETRIC KEY PAIR` (P1 = 0x81) — reads the public key back
    /// out of the card without a PIN.
    func readSignaturePublicKey() async throws -> [UInt8]

    /// `GET DATA 0x7A` -> security support template `93 03 <counter>`.
    func signatureCounter() async throws -> UInt32

    /// Writes a single data object (0xC1 algorithm attributes, 0xC4 PW status,
    /// 0xD6 UIF, 0xC7 fingerprint, 0xCE creation time).
    func putDataObject(_ tag: UInt16, value: [UInt8]) async throws

    /// Reads a single data object by tag.
    func getDataObject(_ tag: UInt16) async throws -> [UInt8]
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
    /// The card already holds a signature key and must be reset first.
    case signatureSlotOccupied
    case unsupportedFeature(String)

    /// User-facing text. Kept here so every surface reports the same wording.
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
            return "This YubiKey's OpenPGP applet does not support secp256k1. Firmware 5.2.3 or newer is required."
        case .keyImportRejected:
            return "The YubiKey rejected the private key import."
        case .signatureFailed:
            return "The YubiKey reported a signing failure."
        case .unexpectedStatusWord(let sw1, let sw2):
            return String(format: "Unexpected card response %02X%02X.", sw1, sw2)
        case .malformedResponse(let detail):
            return "The card response could not be parsed: \(detail)."
        case .signatureSlotOccupied:
            return "This YubiKey already holds a signature key. Reset the OpenPGP applet and start the ceremony again."
        case .unsupportedFeature(let detail):
            return "Unsupported by this YubiKey: \(detail)."
        }
    }
}

/// What the ceremony learns about the card before touching it.
public struct CardInventory: Equatable {
    public var openPGPVersion: String
    public var manufacturer: String?
    public var serial: String?
    /// Raw 0xC1 algorithm attributes, if present.
    public var algorithmAttributes: [UInt8]?
    /// Raw 0xC4 PW status bytes, if present.
    public var pwStatusBytes: [UInt8]?
    /// True when the card reports an existing signature key.
    public var hasSignatureKey: Bool
    /// `GET DATA 0x7A` -> 0x93 counter, if readable without a PIN.
    public var signatureCounter: UInt32?
    /// True when the card looks factory-fresh (no signature key, no fingerprints).
    public var isFactoryFresh: Bool

    public init(
        openPGPVersion: String,
        manufacturer: String? = nil,
        serial: String? = nil,
        algorithmAttributes: [UInt8]? = nil,
        pwStatusBytes: [UInt8]? = nil,
        hasSignatureKey: Bool = false,
        signatureCounter: UInt32? = nil,
        isFactoryFresh: Bool = true
    ) {
        self.openPGPVersion = openPGPVersion
        self.manufacturer = manufacturer
        self.serial = serial
        self.algorithmAttributes = algorithmAttributes
        self.pwStatusBytes = pwStatusBytes
        self.hasSignatureKey = hasSignatureKey
        self.signatureCounter = signatureCounter
        self.isFactoryFresh = isFactoryFresh
    }

    /// secp256k1 requires OpenPGP 3.4+ applet behaviour, i.e. YubiKey 5 firmware
    /// 5.2.3 or newer. Reported rather than assumed, because the failure mode
    /// otherwise is an unexplained 6A80 at key-import time.
    public var likelySupportsSecp256k1: Bool {
        guard let version = Self.parseVersion(openPGPVersion) else { return false }
        return version >= (3, 4)
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
    case independentCheck
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
        case .derivation: return "Derive the signing key"
        case .keyImport: return "Import key into YubiKey"
        case .readBackCheck: return "Verify read-back key"
        case .independentCheck: return "Independent address cross-check"
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
        case .reset, .pinProvisioning, .policy, .keyImport: return true
        default: return false
        }
    }
}

public enum CeremonyMode: String, Codable, Sendable {
    /// Fresh generation (design.md §4.2).
    case freshGeneration
    /// Recovery/restore of an existing mnemonic (design.md §8.2, §8.3 drill).
    case restoreFromMnemonic
}

public enum CeremonyError: Swift.Error, Equatable {
    case stepOutOfOrder(expected: CeremonyStep, actual: CeremonyStep)
    case missingAdminPIN
    case alreadyRunning
    case notRunning
    case missingEntropy
    case missingMnemonic
    case mnemonicNotConfirmed
    case transcriptionMismatch(index: Int)
    case invalidPINPolicy(String)
    case diceRollsOutOfRange
    case keyNotDerived
    case readBackMismatch(local: String, card: String)
    case independentCheckNotRun
    case independentCheckFailed
    case pairingPolicyNotAcknowledged
    case destructiveResetNotAcknowledged
    case cardNotFactoryFresh
    case counterNotZero(UInt32)
    case unsupportedRecovery(String)

    public var userFacingDescription: String {
        switch self {
        case .stepOutOfOrder(let expected, let actual):
            return "Ceremony order violation: \(actual.title) cannot run before \(expected.title)."
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
        case .keyNotDerived: return "The signing key has not been derived yet."
        case .readBackMismatch:
            return "The public key read back from the YubiKey does not match the derived key. The procedure is void — restart from the card reset."
        case .independentCheckNotRun:
            return "The independent address cross-check has not been completed."
        case .independentCheckFailed:
            return "The address from the independent tool does not match. Do not proceed."
        case .pairingPolicyNotAcknowledged:
            return "Exporting a chain code requires acknowledging that the derived child addresses cannot be signed by this YubiKey."
        case .destructiveResetNotAcknowledged:
            return "This YubiKey already holds a key. Resetting the OpenPGP applet will erase it, so the operation must be explicitly acknowledged."
        case .cardNotFactoryFresh:
            return "This YubiKey is not factory-fresh. Reset the OpenPGP applet first."
        case .counterNotZero(let value):
            return "The signature counter is \(value), not 0. The card may already have signed something."
        case .unsupportedRecovery(let detail):
            return "Restore is not possible here: \(detail)."
        }
    }
}
