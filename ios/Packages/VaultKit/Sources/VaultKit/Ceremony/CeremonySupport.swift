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
    /// Reads application data (0x6E) and the security support template (0x7A), and
    /// **probes both key slots** by reading each slot's public key, which is the only
    /// reliable signal for whether a slot is occupied.
    ///
    /// That probing is what an inventory is for — the destructive reset is gated on
    /// it — and it is also why the signing flow does not use it: signing knows which
    /// single slot the wallet's request names, and reads only that one
    /// (`readSigningIdentity(slot:)`).
    func inventory() async throws -> CardInventory

    /// The card's identity for **one** slot, for a flow that already knows which key
    /// it is dealing with: the serial, the stored pairing manifest, that slot's public
    /// key, and the signature counter.
    ///
    /// One session and one key, deliberately. `inventory()` would probe the other slot
    /// as well, and on NFC each session is a tap the operator pays for: the signing
    /// flow used to spend four sessions (inventory, manifest, key, counter) and read a
    /// key it had no use for (amendment 33). Implementations must do all four reads in
    /// one session so the tap is paid once.
    ///
    /// A card that refuses the manifest read, or answers with an empty object, reports
    /// `pairingManifest == nil`: both mean "this card was not paired by this app",
    /// which is the only thing the caller can act on.
    func readSigningIdentity(slot: KeySlot) async throws -> SigningCardIdentity

    /// Reads `count` random bytes from the card's hardware random-number
    /// generator (`GET CHALLENGE`, INS 0x84). This is the entropy source for
    /// mnemonic generation (design.md §4.2 step 4).
    func randomBytes(count: Int) async throws -> SensitiveBytes

    /// Blocks PW1 and PW3, then `TERMINATE DF` + `ACTIVATE FILE`, then re-selects.
    /// Resets **all** slots.
    ///
    /// No Admin PIN: the applet accepts `TERMINATE DF` without one only while PW3
    /// is already blocked, so a PIN-free reset has to block it first. Implementations
    /// mirror `ykman openpgp reset`; see `OpenPGPCard.reset()` for the sequence, and
    /// for what a reset that is cut in half leaves behind.
    func reset() async throws

    /// Sets PW1 (user) and PW3 (admin) via `CHANGE REFERENCE DATA`.
    func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws

    /// `SET PIN RETRIES`: how many wrong attempts each password tolerates before it
    /// is blocked. The Admin PIN must be verified in the same session.
    ///
    /// The applet applies one maximum per password (PW1, the resetting code, PW3);
    /// this app sets the limit the operator chose for each of the two it owns, in the
    /// one command the applet accepts (amendment 32).
    func setPINRetries(user: Int, reset: Int, admin: Int, adminPIN: [UInt8]) async throws

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

    // MARK: - Signing (design.md §5)

    /// `VERIFY PW1` **and** `PSO:CDS` over a 32-byte digest, in one card session.
    ///
    /// One method rather than two on purpose. VERIFY state belongs to a session
    /// and an NFC session lasts about a minute, so a protocol that let the caller
    /// verify in one session and sign in the next would work against the simulated
    /// card and fail on hardware with `6982`. The session lifetime is the
    /// implementation's business, not the ceremony's.
    ///
    /// Returns the card's raw response — a DER-encoded ECDSA signature. This is
    /// the one operation the card counts, which is why design.md §5.2 rule 1
    /// forbids a second attempt for the same transaction: implementations must not
    /// retry internally under any circumstances, because a lost response may still
    /// have produced a signature.
    func sign(digest: [UInt8], userPIN: [UInt8]) async throws -> [UInt8]
}

/// What the signing flow needs from one slot, read in one session.
///
/// Deliberately not `CardInventory`: an inventory answers "what does this card hold,
/// and is anything here worth destroying", which costs a public-key read per slot.
/// This answers "what is the key I am about to sign with, and what does the card say
/// it was paired for", and costs one.
public struct SigningCardIdentity: Equatable, Sendable {
    /// The card's serial, formatted as the card reports it, or `nil` when it reports
    /// none (which the report records as a weaker signature, not as a failure).
    public let serial: String?
    /// The slot's public key, normalised to the compressed form for secp256k1, or
    /// `nil` when the card reported no key — which happens when it has no pairing
    /// manifest, in which case no key is read at all (there is nothing to compare one
    /// against, and the caller's next move is the same either way).
    public let publicKey: [UInt8]?
    /// The stored pairing manifest, or `nil` when the card has none or refused to
    /// report one — both mean the card was not paired by this app.
    public let pairingManifest: [UInt8]?
    /// The **signature** slot's hardware counter. `nil` for the authentication slot
    /// (it has no counter) and when the card refuses to report it.
    public let signatureCounter: UInt32?

    public init(
        serial: String?,
        publicKey: [UInt8]?,
        pairingManifest: [UInt8]?,
        signatureCounter: UInt32?
    ) {
        self.serial = serial
        self.publicKey = publicKey
        self.pairingManifest = pairingManifest
        self.signatureCounter = signatureCounter
    }
}

public enum CardError: Swift.Error, Equatable {
    case transportUnavailable(String)
    case cardNotSelected
    case pinIncorrect(retriesRemaining: Int?)
    case pinBlocked
    case adminPinBlocked
    case conditionsNotSatisfied
    /// The reset could not block the PIN counters it needs blocked, so the applet
    /// would refuse `TERMINATE DF` (`6982`) and nothing was erased. Distinct from a
    /// transport failure because the card *has* changed: whatever attempts were
    /// burnt are gone.
    case pinBlockingIncomplete(user: UInt8, admin: UInt8)
    /// The applet refused an algorithm-attributes object (`6A80` on `PUT DATA`
    /// `0xC1`/`0xC3`). Named, because "unsupported firmware" is one of several
    /// causes and the wrong one sends the operator looking for an upgrade they
    /// cannot install.
    case algorithmAttributesRejected(algorithm: String, slot: String, detail: String)
    case unsupportedFirmware
    case keyImportRejected
    case signatureFailed
    /// `6982` on `PSO:CDS`: the applet wants PW1 verified first.
    case userPinNotVerified
    /// The card started a signature and did not finish it — most often an
    /// unanswered touch. The counter may already have moved, so this is *not* a
    /// definitive rejection: it must not be retried (design.md §5.2 rule 1).
    case touchNotCompleted
    case unexpectedStatusWord(sw1: UInt8, sw2: UInt8)
    case malformedResponse(String)
    case unsupportedFeature(String)
    case unsupportedKeyType(String)
    /// A value that cannot fit the card's storage for the object being written.
    /// Raised before the card is asked, because the answer would be the same
    /// every time: the private-use data objects hold at most 254 bytes.
    case dataObjectTooLarge(byteCount: Int, maximum: Int)
    /// A retry count the applet will not accept. Raised before the card is asked
    /// for the same reason: `SET PIN RETRIES` takes one byte per password, and the
    /// command itself is documented for 1-99.
    case retryCountOutOfRange(requested: Int, allowed: ClosedRange<Int>)

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
        case .algorithmAttributesRejected:
            // The card answered "no" to the attributes object; nothing was written.
            return true
        case .userPinNotVerified:
            // The card answered, and answered "no": nothing was signed.
            return true
        case .touchNotCompleted:
            // The signature may or may not have happened — the card began the
            // operation and the app never saw the end of it. That is exactly the
            // "unknown" case, and the one where a retry would be most dangerous.
            return false
        case .unsupportedFeature, .unsupportedKeyType:
            return true
        case .dataObjectTooLarge:
            // Nothing was written and no retry can succeed: the value cannot fit.
            return true
        case .retryCountOutOfRange:
            // Refused before the card was asked; the applet's range is known.
            return true
        case .pinBlockingIncomplete:
            // The PIN burn is the first thing a reset does, so by the time this is
            // thrown the card may already have blocked a password. "Unknown" is the
            // conservative reading, and re-reading costs one tap.
            return false
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
            // Both of these used to point at "terminate and re-activate", which is
            // not a recovery: `TERMINATE DF` erases both private keys, so the card
            // would have to be provisioned again from the mnemonic. The genuine
            // unblock is `RESET RETRY COUNTER` with the Admin PIN, which this
            // version does not implement — and saying so is the honest answer.
            return "The User PIN is blocked. Nothing can be signed until it is unblocked, which needs the Admin PIN (the card's RESET RETRY COUNTER command) — this version of the app does not do that, so plan on setting the card up again from the 24 words. Terminating the applet would erase the keys, not restore them."
        case .adminPinBlocked:
            // The applet allows `TERMINATE DF` when PW3 is blocked (spec 3.4.1:
            // "VERIFY of PW3 or Always if PW3 is blocked"). The reset step gets
            // there on its own — it blocks the PINs rather than verifying one — so
            // this card is not a dead end any more, at the cost of both keys.
            return "The Admin PIN is blocked, so this card can no longer be provisioned or re-paired with that PIN. A full applet reset brings it back, and that step needs no PIN — it blocks the PINs itself. Either way both keys are erased and the wallet has to be set up again from the 24 words."
        case .conditionsNotSatisfied:
            return "The YubiKey refused the operation because its preconditions were not met (wrong state, or a PIN step was skipped)."
        case .algorithmAttributesRejected(let algorithm, let slot, let detail):
            return "The YubiKey refused the \(algorithm) algorithm attributes for the \(slot) slot (\(detail)). The applet accepts EdDSA/Ed25519 only with GnuPG's OID, and only on firmware 5.2.3 or newer; if this card is newer, this is an app bug rather than a card limitation — and the card may now hold the other key, so reset the applet before trying again."
        case .unsupportedFirmware:
            return "This YubiKey's OpenPGP applet does not support the requested algorithm. Firmware 5.2.3 or newer is required."
        case .userPinNotVerified:
            return "The YubiKey requires its user PIN before it will sign anything. Verify the PIN, "
                + "then start again from the wallet: this request has to be signed in one attempt."
        case .touchNotCompleted:
            return "The YubiKey started signing and did not finish — most often because it was not "
                + "touched in time. The card may already have produced a signature and counted it, so "
                + "nothing will be retried here: check the signature counter on the card, then start "
                + "again from the wallet with a new request."
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
        case .retryCountOutOfRange(let requested, let allowed):
            return "This card accepts between \(allowed.lowerBound) and \(allowed.upperBound) PIN retries; \(requested) is outside that range."
        case .pinBlockingIncomplete(let user, let admin):
            return "The YubiKey did not block its PIN retry counters (\(user) attempts left on the User PIN, \(admin) on the Admin PIN), so it would refuse to terminate the applet — nothing was erased. The PINs may still be blocked or partly used up; tap reset again to finish."
        }
    }
}

/// What a card's private-use data object holds — the pairing manifest slot.
///
/// This is read during inventory because it decides whether the card can be
/// provisioned at all: the manifest is part of what the ceremony writes, and a card
/// that cannot hold one cannot report back the whole of what was written
/// (amendment 38). It is not a *preflight* gate — the inventory reports it, and the
/// write step is where a card without the object stops, because that is where the
/// write is attempted and where the operator is told which state their card is in.
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
/// The card policy the ceremony requires, stated once for the read-back.
///
/// These are the values `design.md` §4.2/§6.5 mandate, and they are what
/// `YubikeyKit` writes (`OpenPGPTouchPolicy.fixedEncoded`, the single PW1-status
/// byte). The read-back compares the card's own report against them, because a
/// write that answered `9000` and stored nothing is a real failure mode — the
/// applet discards a slot's UIF when that slot's algorithm attributes are written
/// (amendment 26).
public enum CardPolicy {
    /// UIF policy byte for "touch required for every use, not relaxable".
    public static let touchFixed: UInt8 = 0x02
    /// UIF policy byte for "no touch required" — what a factory-fresh slot reports.
    public static let touchOff: UInt8 = 0x00
    /// PW1 status: the User PIN must be re-entered for every signature.
    public static let pw1StatusPerSignature: UInt8 = 0x00
    /// The retry limits the operator may choose, inclusive. The applet itself
    /// accepts 1-99; the app offers a narrower range because the choice is a
    /// security parameter, not a preference: fewer attempts is stricter, more is
    /// more forgiving, and either way the number is how many wrong guesses stand
    /// between an attacker and this card (§9).
    public static let retryLimits = 3...10
    /// The card's factory value, and what this app writes unless told otherwise.
    /// Three attempts is what makes the PIN a real barrier on a 6-digit secret.
    public static let defaultRetryLimit = 3

    public static func isTouchFixed(_ value: UInt8?) -> Bool { value == touchFixed }

    /// Human-readable form for an error message, naming what the card said rather
    /// than only what it should have said.
    public static func describeTouchPolicy(_ value: UInt8?) -> String {
        guard let value else { return "nothing the card will report" }
        let name: String
        switch value {
        case touchOff: name = "off"
        case 0x01: name = "on (relaxable)"
        case touchFixed: name = "fixed"
        case 0x03: name = "cached"
        case 0x04: name = "cached-fixed"
        default: name = "unknown"
        }
        return "\(name) (0x\(String(format: "%02x", value)))"
    }
}

/// Remaining attempts per password, read from DO `0xC4`.
///
/// The card decrements a counter on every wrong `VERIFY` and refills it to the
/// maximum on a right one, so these are the numbers that decide when a password is
/// blocked. `SET PIN RETRIES` (INS `0xF2`) is what sets the maximum.
public struct RetryCounters: Equatable, Sendable {
    public let user: UInt8
    public let reset: UInt8
    public let admin: UInt8

    public init(user: UInt8, reset: UInt8, admin: UInt8) {
        self.user = user
        self.reset = reset
        self.admin = admin
    }
}

public struct CardInventory: Equatable, Sendable {
    public var openPGPVersion: String
    public var manufacturer: String?
    public var serial: String?
    /// Raw algorithm attributes per slot (0xC1 / 0xC3), where present.
    public var algorithmAttributes: [KeySlot: [UInt8]]
    /// Raw 0xC4 PW status bytes, if present.
    public var pwStatusBytes: [UInt8]?
    /// Remaining attempts per password, from the same object.
    public var retryCounters: RetryCounters?
    /// Touch policy (UIF) per slot, as the card reports it. Only the slots the
    /// ceremony writes appear here.
    public var touchPolicy: [KeySlot: UInt8]
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
        retryCounters: RetryCounters? = nil,
        touchPolicy: [KeySlot: UInt8] = [:],
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
        self.retryCounters = retryCounters
        self.touchPolicy = touchPolicy
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
    /// Read-only re-pair: reads the manifest out of the card and checks it
    /// against the keys the card reports. Replaces the whole destructive path in
    /// `CeremonyMode.rePair` — no reset, no PINs, no writes.
    case rePairRead
    case reset
    case pinProvisioning
    /// `SET PIN RETRIES`: how many wrong PIN attempts each password tolerates. Sits
    /// right after the PINs are set, because it is a property of those passwords:
    /// the card refills each counter to its maximum on the next successful VERIFY.
    case pinRetries
    case entropy
    case mnemonic
    case derivation
    /// Writes the whole card — both private keys, the policy that makes them safe to
    /// use, and the pairing manifest — **and reads all of it back** to check it.
    ///
    /// One step rather than three, because the writes and their proofs are one
    /// operation. Writing a slot's algorithm attributes resets that slot and the applet
    /// drops that slot's touch policy with it, so the policy write has to follow the
    /// last key write (amendment 26 measured the loss on hardware, four times; amendment
    /// 32 merged those two writes into one step so the order cannot be got wrong); the
    /// manifest has to follow the read-back, so that a card is never told to advertise a
    /// key that has not been verified to be in it; and a step boundary between any two of
    /// them is exactly where an interruption — a locked phone, an NFC session ending, the
    /// operator closing the app — leaves a card holding something the ceremony has not
    /// confirmed. The read-back covers both public keys byte-for-byte, the UIF objects,
    /// the PW1 status, the retry limits, and the manifest's bytes and binding.
    ///
    /// Nothing later in the ceremony writes to those slots except the private-use
    /// object, which does not disturb the UIF objects.
    case keyImport
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
        case .rePairRead: return "Read the pairing manifest"
        case .reset: return "Reset OpenPGP applet"
        case .pinProvisioning: return "Set PINs"
        case .pinRetries: return "Set PIN retry limits"
        case .entropy: return "Generate entropy"
        case .mnemonic: return "Write down the mnemonic"
        case .derivation: return "Derive the signing keys"
        case .keyImport: return "Import and verify the YubiKey"
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
        case .reset, .pinProvisioning, .pinRetries, .keyImport: return true
        default: return false
        }
    }
}

public enum CeremonyMode: String, CaseIterable, Codable, Sendable {
    /// Fresh generation (design.md §4.2).
    case freshGeneration
    /// Recovery/restore of an existing mnemonic (design.md §8.2, §8.3 drill).
    case restoreFromMnemonic
    /// Re-pair from the card alone: reads the manifest the provisioning ceremony
    /// wrote into the private-use data object and reproduces the pairing codes
    /// **without** resetting the applet or asking for the mnemonic.
    ///
    /// This mode cannot write: every mutating entry point is gated on the step
    /// that puts it in the ceremony, and this mode never reaches those steps.
    case rePair

    /// The steps this mode visits, in order.
    ///
    /// The UI reads it for its progress indicator, and — more importantly — it is
    /// the mode's central promise expressed as data that a test can assert on: the
    /// re-pair path contains no mutating step, because the operator chose this mode
    /// precisely so that nothing would be written.
    public var path: [CeremonyStep] {
        switch self {
        case .freshGeneration, .restoreFromMnemonic:
            // The policy is written inside the key-import step and verified by the same
            // step's read-back, so there is no policy step and no ordering to get wrong
            // (amendment 26 measured the loss on hardware; amendment 32 folded the
            // writes together, and amendment 37 folded the read-back and the pairing
            // manifest in with them).
            return [
                .cardInventory, .reset, .pinProvisioning, .pinRetries, .entropy, .mnemonic,
                .derivation, .keyImport, .pairingExport, .counterBaseline, .teardown,
            ]
        case .rePair:
            return [.cardInventory, .rePairRead, .pairingExport, .counterBaseline, .teardown]
        }
    }

    /// Short name for the operator. The app shows longer copy in the mode picker;
    /// this is what error messages use, so it must stay recognisable on its own.
    public var displayName: String {
        switch self {
        case .freshGeneration: return "new wallet"
        case .restoreFromMnemonic: return "restore"
        case .rePair: return "re-pair"
        }
    }
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
    /// The touch/PIN policy is not on the card: the write was refused, or the
    /// read-back did not report what the ceremony asked for. Either way the card
    /// must not be used as provisioned, and a second write is a blind retry.
    case policyNotApplied(detail: String)
    /// The pairing manifest is not on the card: the applet has no private-use object
    /// for it, refused the write, or did not read back what was written. It is part of
    /// what this ceremony writes, so a card without it has not been provisioned the
    /// way the ceremony promises, and the step refuses to close (amendment 38).
    case pairingManifestNotStored(detail: String)
    /// A key import failed after at least one slot had already been written, so the
    /// applet holds a half-provisioned key set. The only way forward is a reset.
    case importLeftTheCardPartlyProvisioned(slots: [String], detail: String)
    /// The requested retry limit is outside the range the app offers.
    case invalidRetryLimit(requested: Int, allowed: ClosedRange<Int>)
    /// The card accepted the retry write and reports different counters.
    case retryLimitsNotApplied(detail: String)
    case pairingPolicyNotAcknowledged
    case destructiveResetNotAcknowledged
    case cardNotFactoryFresh
    case counterNotZero(UInt32)
    case unsupportedRecovery(String)
    case unsupportedAlgorithm(KeyAlgorithm, String)
    case unsupportedAppletVersion(version: String)
    case systemEntropyUnavailable(Int32)
    /// Re-pair was asked for, but the card has nothing usable to pair from.
    case noPairingManifest(reason: String)
    /// A manifest was read but does not describe the keys in this card.
    case pairingManifestRejected(reason: String)
    case wrongCeremonyMode(expected: CeremonyMode, actual: CeremonyMode)

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
        case .policyNotApplied(let detail):
            return "The YubiKey did not accept the security policy: \(detail). This card must not be used as provisioned — restart from the card reset."
        case .pairingManifestNotStored(let detail):
            return "The pairing manifest is not on the YubiKey: \(detail) It is part of what this "
                + "ceremony writes, so this card is not provisioned the way it was promised: reset the "
                + "OpenPGP applet and run the ceremony again."
        case .importLeftTheCardPartlyProvisioned(let slots, let detail):
            return "The import failed (\(detail)) after writing the \(slots.joined(separator: " and ")) slot. The card is now half provisioned: reset the OpenPGP applet and start this ceremony again — retrying the import will be refused because that slot already holds a key."
        case .invalidRetryLimit(let requested, let allowed):
            return "Choose between \(allowed.lowerBound) and \(allowed.upperBound) PIN attempts; \(requested) is outside that range."
        case .retryLimitsNotApplied(let detail):
            return "The YubiKey did not accept the PIN retry limits: \(detail). Restart from the card reset."
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
        case .noPairingManifest(let reason):
            return "This YubiKey has no pairing manifest to read: \(reason) "
                + "Re-pairing it needs the mnemonic, so run the provisioning ceremony."
        case .pairingManifestRejected(let reason):
            return "The pairing manifest on this YubiKey was not used: \(reason) "
                + "Pairing from it would give the wallet keys this card cannot sign for."
        case .wrongCeremonyMode(let expected, let actual):
            return "This ceremony is running in \(actual.displayName) mode; that action belongs to "
                + "\(expected.displayName) mode."
        case .unsupportedAppletVersion(let version):
            return "This YubiKey's OpenPGP applet is version \(version), which does not support secp256k1 or Ed25519. A YubiKey with applet 3.4 or newer (firmware 5.2.3+) is required, and the firmware cannot be upgraded."
        case .systemEntropyUnavailable(let status):
            return "The system random-number generator failed (OSStatus \(status))."
        }
    }
}
