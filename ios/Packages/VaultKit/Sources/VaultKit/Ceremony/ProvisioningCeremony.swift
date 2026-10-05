import Foundation

/// One algorithm's entry in the ceremony record. Contains **no secrets**.
public struct KeyRecord: Equatable, Codable, Sendable {
    public var algorithm: String
    public var slot: String
    public var path: String
    /// Primary display identity: EIP-55 address (secp256k1) or public key hex
    /// (Ed25519).
    public var identity: String
    /// secp256k1 only: the EVM address derived from the same key.
    public var evmAddress: String?
    /// secp256k1 only: the native-segwit Bitcoin address derived from the same key.
    public var bitcoinAddress: String?
    public var publicKeyHex: String?
    public var fingerprintHex: String?
    public var parentFingerprintHex: String?
    public var masterFingerprintHex: String?
    public var readBackVerified: Bool = false
    public var pairingURType: String?
    public var pairingIncludedChainCode: Bool = false
    /// Origin path written into the pairing UR. For secp256k1 this is the BIP44
    /// account level (`m/44'/0'/0'`), not `path` above.
    public var pairingPath: String?
    /// `key-data` written into the pairing UR (the exported key, which for
    /// secp256k1 is the account-level key, not the leaf).
    public var pairingPublicKeyHex: String?
    /// True when the pairing UR exports an ancestor of the card's leaf key.
    public var pairingAccountLevel: Bool = false

    public var keyAlgorithm: KeyAlgorithm? { KeyAlgorithm(rawValue: algorithm) }

    public init(algorithm: KeyAlgorithm, slot: KeySlot, path: String, identity: String) {
        self.algorithm = algorithm.rawValue
        self.slot = slot.rawValue
        self.path = path
        self.identity = identity
    }
}

/// One YubiKey this ceremony wrote.
///
/// The same two keys go into every card, so the keys are recorded once, above; this is
/// about the cards themselves — which physical YubiKeys now hold that key material, in the
/// order the operator presented them. It matters for the operator's inventory of their own
/// equipment, and for the duplicate check: a card whose serial is already in `cards` has
/// been written and must not be reset again in this run.
public struct CardRecord: Equatable, Codable, Sendable {
    /// 1-based, in the order the operator presented them.
    public var order: Int
    public var serial: String?
    public var openPGPVersion: String

    public init(order: Int, serial: String?, openPGPVersion: String) {
        self.order = order
        self.serial = serial
        self.openPGPVersion = openPGPVersion
    }
}

/// Everything the ceremony records for the user's file. Contains **no secrets**:
/// it is safe to display, print, export as QR and keep alongside the steel plate.
public struct CeremonyReport: Equatable, Codable, Sendable {
    public var mode: CeremonyMode
    public var appVersion: String
    public var transport: String
    public var startedAt: Date
    public var completedAt: Date?
    /// First 8 hex digits of SHA-256(entropy) — the Appendix B record line.
    public var entropyCommitmentHex: String?
    /// Dice rolls, kept for the record only. Non-authoritative in v1.
    public var diceRolls: [Int] = []
    /// Every YubiKey this ceremony wrote, in the order the operator presented them. Empty
    /// until the first inventory, and one entry per card by the time the ceremony ends.
    public var cards: [CardRecord] = []
    /// True when the operator wrote the 24 words down and proved the transcription by
    /// back-filling three of them; false when they chose to continue without a paper backup,
    /// which the ceremony allows and records rather than assumes (amendment 40). `nil` for a
    /// restore ceremony, where the words came from an existing backup and nothing new is
    /// being written down.
    public var mnemonicBackedUp: Bool?
    /// The first card's serial and applet version, for the one place that speaks about "the
    /// card": a re-pair reads exactly one. The full list is `cards`.
    public var cardSerial: String? { cards.first?.serial }
    public var cardOpenPGPVersion: String? { cards.first?.openPGPVersion }
    /// True when a pairing manifest has been written into the card's private-use data
    /// object and read back byte-for-byte, with its binding to the card's own keys
    /// checked. There is no false: a manifest that could not be stored stops the
    /// ceremony, so a report that exists at all says true for a provisioning run
    /// (amendment 38).
    public var pairingManifestStored: Bool?
    /// Both slots reported the touch policy the ceremony asked for. Only ever set
    /// after reading the UIF objects back off the card (amendment 26).
    public var touchPolicyVerified: Bool?
    /// True when the mnemonic, the seed and both private keys were wiped from the app's
    /// memory **before** the pairing codes were produced (amendment 42). Recorded rather
    /// than assumed: it is the one line of the record that speaks about the app's own
    /// memory rather than about the card, and the operator's file should say when the
    /// private keys stopped existing outside the YubiKeys.
    public var secretsWipedBeforePairing: Bool?
    /// How many wrong entries each password tolerates, recorded only after the card
    /// reported those counters back (amendment 27). Two numbers rather than one:
    /// the User PIN is typed on every signature and the Admin PIN almost never, so
    /// the operator has to be able to spend them differently (amendment 32).
    public var userPINRetryLimit: Int?
    public var adminPINRetryLimit: Int?
    /// Ordered: secp256k1, then Ed25519. Empty until derivation.
    public var keys: [KeyRecord] = []
    public var warnings: [String] = []

    public func key(_ algorithm: KeyAlgorithm) -> KeyRecord? {
        keys.first { $0.algorithm == algorithm.rawValue }
    }

    /// True only when every provisioned key was verified by read-back.
    public var readBackVerified: Bool {
        !keys.isEmpty && keys.allSatisfy(\.readBackVerified)
    }

    /// True when any exported key carried a chain code (see `PairingPolicy`).
    public var pairingIncludedChainCode: Bool {
        keys.contains { $0.pairingIncludedChainCode }
    }

    /// Lines an operator would transcribe onto paper.
    public func printableLines() -> [String] {
        var lines: [String] = []
        lines.append("PlexVault provisioning record")
        lines.append("mode: \(mode.rawValue)")
        lines.append("app: \(appVersion)  transport: \(transport)")
        lines.append("started: \(Self.formatter.string(from: startedAt))")
        if let completedAt { lines.append("completed: \(Self.formatter.string(from: completedAt))") }
        if let entropyCommitmentHex { lines.append("entropy commitment: \(entropyCommitmentHex)") }
        if !diceRolls.isEmpty { lines.append("dice rolls (non-authoritative): \(diceRolls.map(String.init).joined())") }
        if !cards.isEmpty {
            for card in cards {
                lines.append("yubikey \(card.order) of \(cards.count) serial: \(card.serial ?? "not reported")")
                lines.append("yubikey \(card.order) openpgp applet: \(card.openPGPVersion)")
            }
        }
        if let mnemonicBackedUp {
            lines.append(
                "mnemonic written down: \(mnemonicBackedUp ? "yes" : "NO — this record is the only copy, and the keys exist only in the card(s) above")"
            )
        }
        // The two processes produce two records, and each says which half of the run it is
        // (amendment 43): a provisioning record that carries no pairing codes says so rather than
        // looking like a run that forgot them, and a pairing record names the manifest it was read
        // from instead of claiming to have written anything.
        if mode == .rePair {
            lines.append("pairing codes: read back out of the card's stored manifest by this run")
        } else if keys.allSatisfy({ $0.pairingURType == nil }) {
            lines.append("pairing codes: not produced by this run — the pairing run that follows produces its own record")
        }

        for record in keys {
            lines.append("")
            lines.append("[\(record.algorithm)] \(record.slot)")
            lines.append("path: \(record.path)")
            lines.append("public key: \(record.publicKeyHex ?? "-")")
            lines.append("key fingerprint: \(record.fingerprintHex ?? "-")")
            if let evmAddress = record.evmAddress { lines.append("evm address: \(evmAddress)") }
            if let bitcoinAddress = record.bitcoinAddress { lines.append("bitcoin address: \(bitcoinAddress)") }
            if record.evmAddress == nil, record.bitcoinAddress == nil {
                lines.append("identity: \(record.identity)")
            }
            lines.append("read-back verified: \(record.readBackVerified ? "yes" : "no")")
            if let pairingURType = record.pairingURType { lines.append("pairing UR type: \(pairingURType)") }
            if let pairingPath = record.pairingPath {
                lines.append("pairing key path: \(pairingPath)\(record.pairingAccountLevel ? " (account level)" : "") ")
            }
            if let pairingPublicKeyHex = record.pairingPublicKeyHex {
                lines.append("pairing public key: \(pairingPublicKeyHex)")
            }
            if record.pairingIncludedChainCode {
                lines.append("pairing included chain code: yes (required by Keystone/MetaMask)")
            }
        }

        // The policy and the two retry limits, as the card reported them. They belong on
        // the paper record because they are what the card will enforce years from now,
        // and because the numbers are the operator's own choice (amendments 27, 32).
        lines.append("touch policy verified on both slots: \(touchPolicyVerified == true ? "yes" : "no")")
        if secretsWipedBeforePairing == true {
            lines.append("secrets wiped from app memory before pairing: yes")
        }
        if let userPINRetryLimit, let adminPINRetryLimit {
            lines.append("PIN retry limits (PW1 / PW3): \(userPINRetryLimit) / \(adminPINRetryLimit)")
        }
        for warning in warnings { lines.append("warning: \(warning)") }
        return lines
    }

    private static let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}

/// The key material written into one pairing UR (`crypto-hdkey`).
///
/// This is deliberately separate from `DerivedKeySummary`: the export is not
/// always the leaf key the card holds. For secp256k1 it is the BIP44 **account**
/// node (`m/44'/0'/0'`) with its chain code, so that a Keystone/MetaMask wallet
/// which derives `<origin>/0/*` from the exported extended public key lands on
/// the card's leaf key. `childrenPath` is pinned to the fixed path that reaches
/// that leaf, so such a wallet presents the card's address instead of sibling
/// addresses the card cannot sign for.
public struct PairingExport: Equatable, Sendable {
    public let algorithm: KeyAlgorithm
    /// Origin path written into the UR (`crypto-keypath`, field 6).
    public let path: DerivationPath
    /// `key-data` (field 3).
    public let publicKey: [UInt8]
    /// `chain-code` (field 4). Always present. `@keystonehq/bc-ur-registry`'s
    /// `CryptoHDKey.getBip32Key()` concatenates it unconditionally, so a
    /// `crypto-hdkey` without a chain code makes MetaMask fail with
    /// "Cannot read properties of undefined (reading 'length')".
    public let chainCode: [UInt8]
    /// `parent-fingerprint` (field 8).
    public let parentFingerprintHex: String
    /// `source-fingerprint` inside `crypto-keypath` (field 6). Per key, because a
    /// wallet has two masters: secp256k1 keys are measured against the BIP32
    /// master, Ed25519 keys against the SLIP-0010 master (tools/derive computes
    /// both, and they differ).
    public let masterFingerprintHex: String
    /// `children` keypath (field 7), relative to `path`. Non-nil for secp256k1:
    /// the fixed path (`0/0`) that reaches the card's leaf, with no wildcard, so
    /// a wallet enumerating account indices cannot offer a sibling.
    public let childrenPath: DerivationPath?
    /// True when the exported key is an ancestor of the card's leaf.
    public let isAccountLevel: Bool

    public var publicKeyHex: String { publicKey.hexString }
}

/// What the operator must acknowledge before the pairing codes are produced.
///
/// A chain code is mandatory: Keystone and MetaMask both refuse a `crypto-hdkey`
/// without one (the JS `CryptoHDKey.getBip32Key()` concatenates it
/// unconditionally). The export pins the derivation to the card's single leaf
/// key, but a chain code is still a chain code: a wallet that ignores the pinned
/// `children` path can derive siblings this YubiKey cannot sign for.
/// Acknowledgement is a hard gate on `buildPairingURs`.
public enum PairingPolicy {
    public static let chainCodeWarning =
        "The pairing code carries a chain code, which Keystone/MetaMask require. "
        + "It pins the derivation to the single key on this YubiKey, but a wallet that "
        + "ignores the pinned path could offer sibling addresses this card cannot sign "
        + "for. Never send funds to any address except the ones shown on this screen."

    /// Device name written into the `name` field (BCR-2020-007 field 9) of every
    /// exported `crypto-hdkey`.
    ///
    /// This is not cosmetic. Keystone devices always set it, and MetaMask derives
    /// its keyring/device name from it:
    ///
    /// * `@keystonehq/base-eth-keyring`'s `__readCryptoHDKey` only ever restores
    ///   `this.name` from this field, and its `deserialize()` overwrites the
    ///   `"QR Hardware"` default with whatever was persisted — which is
    ///   `undefined` for a keyring that was added but never paired.
    /// * MetaMask's `getAccountLabel()` then does `name[0].toUpperCase()`, i.e.
    ///   `undefined[0]` → `Cannot read properties of undefined (reading '0')`
    ///   exactly when the operator confirms the account.
    /// * `@metamask/eth-qr-keyring`'s `Device.getName()` returns the field as-is,
    ///   so without it the device reports no name at all.
    public static let deviceName = "PlexVault"
}

/// Public summary of one derived key handed to the UI (never the private key).
public struct DerivedKeySummary: Equatable, Sendable {
    public let algorithm: KeyAlgorithm
    public let slot: KeySlot
    public let path: DerivationPath
    /// 33-byte SEC1 compressed point (secp256k1) or 32-byte raw point (Ed25519).
    public let publicKey: [UInt8]
    public let fingerprintHex: String
    public let parentFingerprintHex: String
    public let masterFingerprintHex: String
    /// Primary display identity: EIP-55 address (secp256k1) or public key hex.
    public let identity: String
    /// secp256k1 only: the EVM address derived from this same key.
    public let evmAddress: String?
    /// secp256k1 only: the native-segwit Bitcoin address derived from this key.
    public let bitcoinAddress: String?

    public var publicKeyHex: String { publicKey.hexString }
}

/// Both keys produced by one ceremony, addressed by algorithm.
public struct DerivedKeys: Equatable, Sendable {
    public let secp256k1: DerivedKeySummary
    public let ed25519: DerivedKeySummary

    public init(secp256k1: DerivedKeySummary, ed25519: DerivedKeySummary) {
        self.secp256k1 = secp256k1
        self.ed25519 = ed25519
    }

    public subscript(_ algorithm: KeyAlgorithm) -> DerivedKeySummary {
        switch algorithm {
        case .secp256k1: return secp256k1
        case .ed25519: return ed25519
        }
    }

    public var all: [DerivedKeySummary] { [secp256k1, ed25519] }
}

/// One key's read-back comparison (design.md §4.2 step 7).
public struct ReadBackResult: Equatable, Sendable {
    public let algorithm: KeyAlgorithm
    public let slot: KeySlot
    public let cardPublicKeyHex: String
    public let derivedPublicKeyHex: String
    public let matches: Bool
    /// The identity recomputed from the *card's* public key — so a mismatch is
    /// visible as two different addresses, not just two different hex strings.
    public let identityFromCardKey: String
}

/// Drives design.md §4.2 as an ordered state machine.
///
/// Hard gates are enforced here rather than in the UI: every mutating entry
/// point checks that it is the next expected step, so a compromised or buggy
/// view layer cannot skip the read-back check or sign the pairing QR before the
/// independent cross-check has run.
///
/// One ceremony provisions **both** algorithms in one pass — secp256k1 into the
/// signature slot, Ed25519 into the authentication slot — from a single BIP39
/// mnemonic. The per-key steps therefore act on both keys at once.
///
/// Secret lifetime: entropy, seed, private keys and mnemonic words live only in
/// this object and are wiped by `wipe()`, by `finish()`, and by `abort()`. An
/// interrupted ceremony is resumed by re-entering the mnemonic (restore mode) —
/// no secret is ever persisted, so there is nothing on disk to steal.
public final class ProvisioningCeremony {

    // MARK: Inputs

    private let card: SignerCard
    private let systemRandom: (Int) throws -> SensitiveBytes
    private let clock: () -> Date
    private let appVersion: String

    // MARK: Observable state

    public private(set) var mode: CeremonyMode
    public private(set) var step: CeremonyStep = .notStarted
    public private(set) var transportDescription: String
    public private(set) var inventory: CardInventory?
    public private(set) var report: CeremonyReport
    public private(set) var derivedKeys: DerivedKeys?
    public private(set) var readBackResults: [KeyAlgorithm: ReadBackResult] = [:]
    public private(set) var pairingURs: [KeyAlgorithm: UR] = [:]
    /// Key material written into each pairing UR. Not necessarily the leaf key;
    /// see `PairingExport`.
    public private(set) var pairingExports: [KeyAlgorithm: PairingExport] = [:]
    /// The manifest written into the card's private-use data object, once its bytes
    /// have been read back and its binding to the card's own keys checked. `nil` means
    /// the step has not run: a manifest that could not be stored stops the ceremony
    /// rather than leaving this nil with the step complete (amendment 38).
    public private(set) var pairingManifest: PairingManifest?

    // MARK: Secrets (wiped on every exit path)

    private var entropy: SensitiveBytes?
    private var mnemonicWords: [String] = []
    private var seed: SensitiveBytes?
    private var privateKeys: [KeyAlgorithm: SensitiveBytes] = [:]
    private var chainCodes: [KeyAlgorithm: [UInt8]] = [:]
    private var pendingDiceRolls: [Int] = []
    private var mnemonicConfirmed = false
    private var cardHeldExistingKey = false
    private var mutatingStepInFlight: CeremonyStep?
    /// How many YubiKeys the operator committed to, and which one is in front of them
    /// (0-based). Set on the `cardCount` step; `cardIndex` advances once per written card,
    /// so the per-card block of `CeremonyMode.path(cardCount:)` is walked once per card.
    public private(set) var cardCount = 1
    public private(set) var cardIndex = 0
    /// The retry limits chosen for the first card. The *policy* is one decision per
    /// ceremony — the same numbers go on every card — while each card gets its own PINs, so
    /// the UI pre-fills these and every card's write is verified against them.
    public private(set) var chosenRetryLimits: (user: Int, admin: Int)?
    /// Serials this ceremony has already written. Read at the inventory, because the step
    /// after that inventory resets the card — which would erase the keys just written to it.
    private var provisionedSerials: Set<String> = []
    /// The serial of the card whose write just completed, for the screen that reports what
    /// happened on *this* card (the view model reads it instead of caching the last card's
    /// read-back).
    public private(set) var lastWrittenCardSerial: String?
    /// Held from the PIN step onwards — the retry write, the import with its policy
    /// write, and the manifest all authenticate with it — and wiped with everything
    /// else.
    private var sessionAdminPIN: SensitiveBytes?
    /// Set only by `confirmPairingAddressMatches`; gates completion of the pairing
    /// step (design.md §4.2 step 8 requires the operator to compare addresses).
    private var pairingAddressConfirmedByOperator = false

    public init(
        card: SignerCard,
        systemRandom: @escaping (Int) throws -> SensitiveBytes = SystemCSPRNG.randomBytes,
        transportDescription: String,
        appVersion: String,
        clock: @escaping () -> Date = Date.init
    ) {
        self.card = card
        self.systemRandom = systemRandom
        self.transportDescription = transportDescription
        self.appVersion = appVersion
        self.clock = clock
        self.mode = .freshGeneration
        self.report = CeremonyReport(
            mode: .freshGeneration,
            appVersion: appVersion,
            transport: transportDescription,
            startedAt: clock()
        )
    }

    // MARK: Step sequencing

    /// Gate convention: `step` is always the step that is currently **due**.
    /// `requireCurrent(x)` therefore compares for equality, and each step method
    /// advances `step` to its successor on success. This is what makes the hard
    /// gates in design.md §4.2 impossible to skip from the view layer.
    private func requireCurrent(_ expected: CeremonyStep) throws {
        guard step == expected else {
            // expected = the step that must be completed now;
            // actual   = the step the caller tried to run.
            throw CeremonyError.stepOutOfOrder(expected: step, actual: expected)
        }
    }

    /// Completes the current step and moves to the next one.
    ///
    /// Workers that produce operator-facing output deliberately do **not** advance
    /// themselves: the operator reads the result and then calls this. Without that
    /// split, everything a step produced — the card inventory, the entropy
    /// commitment, the derived addresses, the read-back comparison, the pairing
    /// codes — was replaced by the next screen in the same render pass and never seen.
    ///
    /// Each step's precondition is checked here, so "read the card, then reset"
    /// and "confirm the wallet shows this address" cannot be skipped by the view
    /// layer.
    public func advance() throws {
        switch step {
        case .notStarted, .preflight:
            throw CeremonyError.stepOutOfOrder(expected: .cardInventory, actual: step)

        case .cardInventory:
            guard let inventory else {
                throw CeremonyError.stepIncomplete(step: .cardInventory, detail: "the YubiKey has not been read yet")
            }
            if inventory.isDefinitelyUnsupported {
                throw CeremonyError.unsupportedAppletVersion(version: inventory.openPGPVersion)
            }
            // The one place the two ceremonies diverge: re-pair reads what is
            // already in the card, provisioning overwrites it.
            step = mode == .rePair ? .rePairRead : .reset

        case .rePairRead:
            guard pairingManifest != nil else {
                throw CeremonyError.stepIncomplete(
                    step: .rePairRead,
                    detail: "the pairing manifest has not been read off the card yet"
                )
            }
            step = .pairingExport

        case .reset, .pinProvisioning, .pinRetries:
            // Action-only steps advance themselves once the card accepts them.
            throw CeremonyError.stepIncomplete(step: step, detail: "this step completes when the YubiKey accepts it")

        case .keyImport:
            // The card has been written, and the operator's Continue is what closes the
            // step. All three halves have to be present: the keys by comparison with the
            // derived ones, the policy as the card reports it, and the manifest step —
            // which records an outcome whether or not the card could store one.
            guard report.readBackVerified else {
                throw CeremonyError.stepIncomplete(step: .keyImport, detail: "the public keys have not been verified yet")
            }
            guard report.touchPolicyVerified == true else {
                throw CeremonyError.stepIncomplete(
                    step: .keyImport,
                    detail: "the touch policy has not been confirmed on the card yet"
                )
            }
            guard pairingManifest != nil else {
                throw CeremonyError.stepIncomplete(
                    step: .keyImport,
                    detail: "the pairing manifest is not on the card yet"
                )
            }
            step = stepAfterCardWritten()

        case .entropy:
            guard let entropy else {
                throw CeremonyError.stepIncomplete(step: .entropy, detail: "entropy has not been generated yet")
            }
            // The words are derived here, so "step is .mnemonic" always implies the
            // mnemonic exists. Previously the UI could reach the mnemonic step
            // with nothing to show, which is exactly the empty-list bug.
            let words = try BIP39.mnemonic(fromEntropy: entropy.materializedCopy())
            installMnemonic(words)
            step = .mnemonic

        case .mnemonic:
            throw CeremonyError.stepIncomplete(step: .mnemonic, detail: "confirm the transcription first")

        case .derivation:
            guard derivedKeys != nil else {
                throw CeremonyError.stepIncomplete(step: .derivation, detail: "the keys have not been derived yet")
            }
            step = .cardCount

        case .cardCount:
            throw CeremonyError.stepIncomplete(
                step: .cardCount,
                detail: "the number of YubiKeys has not been chosen yet"
            )

        case .wipeSecrets:
            guard secretsWiped else {
                throw CeremonyError.stepIncomplete(
                    step: .wipeSecrets,
                    detail: "the mnemonic and both private keys are still in memory"
                )
            }
            step = .pairingExport

        case .pairingExport:
            guard pairingURs.count == KeyAlgorithm.allCases.count else {
                throw CeremonyError.stepIncomplete(step: .pairingExport, detail: "the pairing codes have not been produced yet")
            }
            guard pairingAddressConfirmedByOperator else {
                throw CeremonyError.pairingAddressNotConfirmed
            }
            step = .teardown

        case .teardown:
            throw CeremonyError.stepIncomplete(step: .teardown, detail: "call finish() to close the ceremony")
        }
    }

    /// Records that the operator compared the addresses their wallet shows with
    /// the ones in the ceremony. Required before the pairing step can complete.
    public func confirmPairingAddressMatches(_ matches: Bool) {
        pairingAddressConfirmedByOperator = matches
    }

    private func advance(to next: CeremonyStep) {
        step = next
    }

    /// Where the ceremony goes once a card has been written: the next card's inventory, or
    /// the pairing export when that was the last one.
    ///
    /// The next card's pass starts from **nothing**: its read-back, its policy confirmation and
    /// its manifest are facts about *that* card, and the report's flags are the gate the write
    /// step is allowed to close on. Leaving the previous card's answers in place meant the
    /// second card's write step could be closed without a write — which is exactly what happened
    /// on hardware: the card was reset, the step showed the first card's read-back and a
    /// "Continue" button, and tapping it carried the ceremony on (amendment 41).
    private func stepAfterCardWritten() -> CeremonyStep {
        if cardIndex + 1 < cardCount {
            cardIndex += 1
            beginCardPass()
            return .cardInventory
        }
        // The keys leave memory here, before the pairing codes are produced rather than
        // after them (amendment 42).
        return .wipeSecrets
    }

    /// Clears every answer that belongs to one YubiKey's pass, so the next card's steps cannot
    /// be satisfied by the previous card's.
    private func beginCardPass() {
        inventory = nil
        cardHeldExistingKey = false
        readBackResults = [:]
        pairingManifest = nil
        report.touchPolicyVerified = nil
        report.pairingManifestStored = nil
        report.userPINRetryLimit = nil
        report.adminPINRetryLimit = nil
        for index in report.keys.indices {
            report.keys[index].readBackVerified = false
        }
    }

    /// Records an interruption (transport loss, app backgrounding).
    ///
    /// Rewinds to card inspection **only** when a mutating card operation was in
    /// flight: that is the case where the card may have received a `PUT DATA`
    /// whose effect is unknown. An interruption while merely idling between
    /// read-only steps leaves the position alone (design.md §5.2 rule 1 forbids
    /// blind retries, not resumption of reads), and a failure the card answered
    /// with a definitive rejection has already cleared the marker in
    /// `withMutatingStep`, because nothing was written.
    public func noteInterruption() {
        guard let inFlight = mutatingStepInFlight else { return }
        // A reset that stopped between blocking the PINs and terminating the
        // applet leaves a card that can neither sign nor be provisioned — but one
        // that a second tap fixes without any PIN, so the warning says which state
        // the operator is looking at rather than leaving it at "unknown".
        let warn = inFlight == .reset
            ? "Session interrupted during \(inFlight.title). The card state is unknown: a reset that stopped after blocking the PINs leaves them blocked, with the keys still in place. So re-inspect the YubiKey, then tap reset again to finish it — that needs no PIN."
            : "Session interrupted during \(inFlight.title). The card state is unknown; re-inspect the YubiKey before continuing."
        report.warnings.append(warn)
        mutatingStepInFlight = nil
        step = .cardInventory
    }

    /// Marks a mutating card operation as in flight; cleared on success, and on a
    /// failure that proves the card did not act — so that a throw leaves it
    /// pending for `noteInterruption()` exactly when the card's state is
    /// genuinely unknown.
    ///
    /// Without the second half, a mistyped PIN at the PIN-setting step would send
    /// the operator back to the inventory screen even though nothing was written;
    /// with it, only a transport failure (or an unrecognised one) rewinds. The
    /// reset does not use this helper at all: its very first act is to block the
    /// PINs, so *any* failure in it may already have changed the card.
    private func withMutatingStep<T>(_ step: CeremonyStep, _ body: () async throws -> T) async throws -> T {
        mutatingStepInFlight = step
        do {
            let result = try await body()
            mutatingStepInFlight = nil
            return result
        } catch {
            if let cardError = error as? CardError, cardError.isDefinitiveCardRejection {
                mutatingStepInFlight = nil
            }
            throw error
        }
    }

    // MARK: Step 1 — preflight

    /// `postureConfirmed` is the operator's explicit acknowledgement of the
    /// device-posture checks; the app cannot verify airplane mode or the absence
    /// of cameras itself, so it records the claim rather than implying certainty.
    public func begin(mode: CeremonyMode, postureConfirmed: Bool) throws {
        guard step == .notStarted else { throw CeremonyError.alreadyRunning }
        self.mode = mode
        report.mode = mode
        report.startedAt = clock()
        if !postureConfirmed {
            report.warnings.append("Device posture was not confirmed by the operator.")
        }
        // The keys come first (amendment 40): the operator's answer about how many cards to
        // write does not exist until the keys do, and the mnemonic step's warning depends on
        // that answer. A restore starts at the words themselves — there is nothing to generate
        // — and re-pair starts at the card it is about to read.
        switch mode {
        case .freshGeneration: advance(to: .entropy)
        case .restoreFromMnemonic: advance(to: .mnemonic)
        case .rePair: advance(to: .cardInventory)
        }
    }

    // MARK: Step 2 — card inventory

    /// Informational: reads the card and records warnings. Deliberately does NOT
    /// refuse a used YubiKey, because re-provisioning one is a normal workflow —
    /// the destructive gate lives on the reset step, which is where key material
    /// is actually erased.
    public func inspectCard() async throws -> CardInventory {
        try requireCurrent(.cardInventory)
        let result = try await card.inventory()
        // Refused before anything touches the card: the next step resets it, and resetting a
        // card this ceremony has already written would erase the keys it now holds.
        if let serial = result.serial, provisionedSerials.contains(serial) {
            throw CeremonyError.duplicateCard(serial: serial)
        }
        inventory = result
        recordCard(result)
        cardHeldExistingKey = !result.occupiedSlots.isEmpty
        for slot in KeySlot.allCases {
            if let detail = result.probeFailures[slot] {
                report.warnings.append(
                    "Could not read the \(slot.displayName.lowercased()) public key during inspection (\(detail)); treating it as unreadable."
                )
            }
        }
        if !result.isFactoryFresh {
            report.warnings.append("YubiKey was not factory-fresh: \(describe(result)).")
        }
        if result.isDefinitelyUnsupported {
            report.warnings.append(
                "OpenPGP applet version \(result.openPGPVersion) does not support secp256k1/Ed25519 (3.4 or newer is required); this YubiKey cannot be provisioned and its firmware is not upgradeable."
            )
        } else if !result.likelySupportsSecp256k1 {
            report.warnings.append(
                "OpenPGP applet version \(result.openPGPVersion) could not be confirmed to support secp256k1/Ed25519 (3.4 or newer is required)."
            )
        }
        // Deliberately does NOT advance: the inventory must stay on screen for
        // the operator to read before the destructive reset.
        return result
    }

    /// Appends a warning once; the pairing step can be re-run ("regenerate").
    private func addWarning(_ text: String) {
        guard !report.warnings.contains(text) else { return }
        report.warnings.append(text)
    }

    private func describe(_ inventory: CardInventory) -> String {
        var parts: [String] = []
        for slot in KeySlot.allCases where inventory.holdsKey(in: slot) {
            parts.append("\(slot.displayName.lowercased()) occupied")
        }
        if let attributes = inventory.algorithmAttributes[.authentication] {
            parts.append("authentication algorithm attributes \(attributes.hexString)")
        }
        return parts.isEmpty ? "unknown state" : parts.joined(separator: ", ")
    }

    // MARK: Step 3 — reset

    /// Destructive: `TERMINATE DF` + `ACTIVATE FILE` erases the keys in every
    /// slot, so a card that already held a key requires an explicit
    /// acknowledgement. This is the hard gate that prevents a stray tap from
    /// destroying a working signer.
    ///
    /// The Admin PIN is deliberately **not** asked for. The applet accepts
    /// `TERMINATE DF` without one only while PW3 is blocked, so the card layer
    /// blocks PW1 and PW3 first — the same sequence `ykman openpgp reset` runs —
    /// and terminates afterwards. Nothing is verified, so an operator who never
    /// knew the Admin PIN can still reset the card, and a card whose Admin PIN is
    /// blocked is no longer a dead end (amendment 30).
    ///
    /// This is the one mutating step that does **not** use `withMutatingStep`: the
    /// PIN burn is the first thing the card does, so a failure anywhere in the
    /// reset may already have changed it (PINs blocked, keys intact) even though
    /// the applet answered "no". Leaving the marker in flight forces the operator
    /// to re-read the card, which is the conservative reading the ceremony wants,
    /// and the way out — tap reset again — needs no PIN either.
    public func resetCard(acknowledgingDestruction: Bool = false) async throws {
        try requireCurrent(.reset)
        if cardHeldExistingKey, !acknowledgingDestruction {
            throw CeremonyError.destructiveResetNotAcknowledged
        }
        mutatingStepInFlight = .reset
        try await card.reset()
        mutatingStepInFlight = nil
        // Re-inventory after a destructive operation: never trust that the card
        // is in the expected state just because the APDU returned 9000.
        let after = try await card.inventory()
        inventory = after
        recordCard(after)
        advance(to: .pinProvisioning)
    }

    /// Keeps the report's card list in step with the card in front of the operator: one
    /// entry per card, in the order they were presented, updated in place when the same
    /// card is re-read (after a reset, for instance).
    private func recordCard(_ inventory: CardInventory) {
        let order = cardIndex + 1
        if let index = report.cards.firstIndex(where: { $0.order == order }) {
            report.cards[index].serial = inventory.serial
            report.cards[index].openPGPVersion = inventory.openPGPVersion
        } else {
            report.cards.append(
                CardRecord(order: order, serial: inventory.serial, openPGPVersion: inventory.openPGPVersion)
            )
        }
    }

    // MARK: Step 4 — PINs

    /// Policy from design.md §4.2 step 3: PW1 >= 6 digits, PW3 >= 8 digits, and
    /// the two must differ.
    public static func validatePINPolicy(userPIN: [UInt8], adminPIN: [UInt8]) -> String? {
        let userDigits = userPIN.allSatisfy { (0x30...0x39).contains($0) }
        let adminDigits = adminPIN.allSatisfy { (0x30...0x39).contains($0) }
        if userPIN.count < 6 { return "The User PIN must be at least 6 digits." }
        if userPIN.count > 127 { return "The User PIN is too long for the OpenPGP applet." }
        if !userDigits { return "The User PIN must contain digits only." }
        if adminPIN.count < 8 { return "The Admin PIN must be at least 8 digits." }
        if adminPIN.count > 127 { return "The Admin PIN is too long for the OpenPGP applet." }
        if !adminDigits { return "The Admin PIN must contain digits only." }
        if userPIN == adminPIN { return "The User PIN and Admin PIN must be different." }
        return nil
    }

    /// Progress reported so the UI can explain that locking the Admin PIN is
    /// unrecoverable. Not persisted.
    public enum PINSlot: Sendable { case user, admin }

    public enum PINPolicy {
        public static let minimumUserLength = 6
        public static let minimumAdminLength = 8
        public static let adminLockoutIsFatal = true
    }

    public func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        try requireCurrent(.pinProvisioning)
        if let problem = Self.validatePINPolicy(userPIN: userPIN, adminPIN: adminPIN) {
            throw CeremonyError.invalidPINPolicy(problem)
        }
        try await withMutatingStep(.pinProvisioning) {
            try await card.setPINs(userPIN: userPIN, adminPIN: adminPIN)
        }
        sessionAdminPIN?.zeroize()
        sessionAdminPIN = SensitiveBytes(copying: adminPIN)
        advance(to: .pinRetries)
    }

    // MARK: Step 3b — PIN retry limits (amendments 27 and 32)

    /// Sets how many wrong PIN attempts each password tolerates, and reads the
    /// counters back.
    ///
    /// Two numbers, not one: the User PIN is typed on every signature and the Admin
    /// PIN almost never, so the same number is not the right trade for both, and the
    /// card keeps the counters per password anyway. Each number is genuinely
    /// independent — the APDU carries three counters (PW1, the resetting code, PW3),
    /// so the write carries both choices and the read-back asserts both.
    ///
    /// The operator chooses each number because it is a genuine trade: it is the
    /// brute-force budget for a 6-digit PIN (design.md §9), and it is also how many
    /// typos stand between the operator and a blocked card. The consequences are
    /// stated on the step, not hidden here:
    ///
    /// * exhausting the **User PIN** stops every signature until the PIN is
    ///   unblocked, which needs the Admin PIN (`RESET RETRY COUNTER`) — and this
    ///   version of the app does not do that, so recovery means re-provisioning
    ///   from the mnemonic, which erases the keys;
    /// * exhausting the **Admin PIN** leaves the applet unusable for provisioning or
    ///   re-pairing. A full applet reset is still possible (the applet allows
    ///   `TERMINATE DF` when PW3 is blocked) and destroys the keys, so recovery is
    ///   again the mnemonic.
    ///
    /// Verified rather than assumed: the card must report the new counters back, and
    /// the read-back step later re-checks them, because a limit that only appears to
    /// be set is worse than no limit at all.
    public func setPINRetries(
        user userLimit: Int = CardPolicy.defaultRetryLimit,
        admin adminLimit: Int = CardPolicy.defaultRetryLimit
    ) async throws {
        try requireCurrent(.pinRetries)
        for limit in [userLimit, adminLimit] {
            guard CardPolicy.retryLimits.contains(limit) else {
                throw CeremonyError.invalidRetryLimit(requested: limit, allowed: CardPolicy.retryLimits)
            }
        }
        guard let adminPIN = sessionAdminPIN else { throw CeremonyError.missingAdminPIN }
        var pin = adminPIN.materializedCopy()
        defer { VaultKit.wipe(&pin) }

        try await withMutatingStep(.pinRetries) {
            // The third byte is the resetting code's counter. This app never sets a
            // resetting code, and the card reports 0 attempts for it whatever is
            // sent (measured on hardware: `03 00 03`), but the command takes all
            // three, so it carries the User PIN's number.
            try await card.setPINRetries(user: userLimit, reset: userLimit, admin: adminLimit, adminPIN: pin)
        }

        let after = try await card.inventory()
        inventory = after
        guard let counters = after.retryCounters else {
            throw CeremonyError.retryLimitsNotApplied(
                detail: "the card reports no retry counters at all"
            )
        }
        // Both counters are asserted, including the one not chosen on this step:
        // sending three bytes means the two choices travel together, so a write that
        // clobbered one of them is a failure here rather than a surprise later.
        // PW1 and PW3 are the two passwords this app sets; the resetting code's
        // counter is not ours to check (`03 00 03` on a fresh card).
        guard Int(counters.user) == userLimit, Int(counters.admin) == adminLimit else {
            throw CeremonyError.retryLimitsNotApplied(
                detail: "the card reports \(counters.user) user and \(counters.admin) admin attempts, "
                    + "not \(userLimit) and \(adminLimit)"
            )
        }
        report.userPINRetryLimit = userLimit
        report.adminPINRetryLimit = adminLimit
        chosenRetryLimits = (user: userLimit, admin: adminLimit)
        advance(to: .keyImport)
    }

    // MARK: Step 4b — how many YubiKeys (amendment 40)

    /// Records how many YubiKeys this ceremony will write, and opens the per-card block.
    ///
    /// The count is the operator's, asked after the keys exist and before any card is touched.
    /// Each card is reset, given its own PINs and the ceremony's retry limits, written and
    /// verified in its own pass; the ceremony cannot derive any of that from a card it has not
    /// seen, and it must know the count before the first card because the per-card block is
    /// what the operator is about to repeat.
    public func setCardCount(_ count: Int) throws {
        try requireCurrent(.cardCount)
        guard CardPolicy.cardCountRange.contains(count) else {
            throw CeremonyError.invalidCardCount(requested: count, allowed: CardPolicy.cardCountRange)
        }
        cardCount = count
        cardIndex = 0
        advance(to: .cardInventory)
    }

    // MARK: Step 6 — entropy

    /// Returns the commitment the operator writes down (first 8 hex digits of
    /// SHA-256(entropy)). The entropy is the XOR of the card's hardware RNG
    /// (`GET CHALLENGE`) and the iOS system CSPRNG, so that neither source alone
    /// determines the mnemonic.
    @discardableResult
    public func generateEntropy() async throws -> String {
        try requireCurrent(.entropy)
        guard mode == .freshGeneration else {
            throw CeremonyError.unsupportedRecovery("restore ceremonies do not generate new entropy")
        }
        let cardBytes = try await card.randomBytes(count: BIP39.entropyByteCount)
        let systemBytes = try systemRandom(BIP39.entropyByteCount)
        let generated = Self.mixEntropy(cardBytes, systemBytes)
        cardBytes.zeroize()
        systemBytes.zeroize()
        entropy?.zeroize()
        entropy = generated
        let commitment = Hex.encode(Array(SHA256.hash(generated.materializedCopy()).prefix(4)))
        report.entropyCommitmentHex = commitment
        // Deliberately does NOT advance: the commitment must stay on screen
        // until the operator has written it down.
        return commitment
    }

    /// XORs two equal-length secret buffers into a new one. Either input being
    /// unpredictable keeps the output unpredictable, so a backdoored card RNG or
    /// a backdoored OS RNG alone cannot determine the entropy.
    private static func mixEntropy(_ a: SensitiveBytes, _ b: SensitiveBytes) -> SensitiveBytes {
        precondition(a.count == b.count, "entropy sources must produce equal-length buffers")
        let result = SensitiveBytes(count: a.count)
        result.withUnsafeMutableBytes { out in
            a.withUnsafeBytes { lhs in
                b.withUnsafeBytes { rhs in
                    for i in 0..<a.count { out[i] = lhs[i] ^ rhs[i] }
                }
            }
        }
        return result
    }

    /// Records dice rolls. v1 makes these **non-authoritative**: they are shown
    /// and recorded but do not feed the mnemonic, which is why design.md was
    /// amended (see docs/design-amendments.md).
    public func recordDiceRolls(_ rolls: [Int]) throws {
        guard rolls.allSatisfy({ (1...6).contains($0) }) else { throw CeremonyError.diceRollsOutOfRange }
        pendingDiceRolls.append(contentsOf: rolls)
        report.diceRolls = pendingDiceRolls
        if pendingDiceRolls.count < 99 {
            report.warnings.append(
                "Fewer than 99 dice rolls recorded (\(pendingDiceRolls.count)). v1 does not derive entropy from dice in any case."
            )
        }
    }

    // MARK: Step 7 — mnemonic

    /// Restore path (design.md §8.2). Words enter app memory, are validated for
    /// checksum before any derivation, and are wiped at teardown.
    ///
    /// Callable at the entropy step: restore replaces the entropy+mnemonic pair,
    /// so no entropy commitment is recorded for a restore ceremony.
    public func restoreMnemonic(words: [String]) throws {
        guard mode == .restoreFromMnemonic else {
            throw CeremonyError.unsupportedRecovery("this ceremony is a fresh generation")
        }
        if step == .entropy { step = .mnemonic }
        guard step == .mnemonic else {
            throw CeremonyError.stepOutOfOrder(expected: step, actual: .mnemonic)
        }
        _ = try BIP39.entropy(fromMnemonic: words) // wordlist + checksum validation
        installMnemonic(words)
    }

    private func installMnemonic(_ words: [String]) {
        mnemonicWords = words
        mnemonicConfirmed = false
    }

    /// The mnemonic is only readable while the mnemonic step is active, so a
    /// later UI state cannot re-display it by accident.
    public func mnemonicForDisplay() throws -> [String] {
        guard step == .mnemonic else {
            throw CeremonyError.stepOutOfOrder(expected: step, actual: .mnemonic)
        }
        guard !mnemonicWords.isEmpty else { throw CeremonyError.missingMnemonic }
        return mnemonicWords
    }

    /// Indices to back-fill. Derived from the mnemonic itself so the challenge is
    /// available in both modes — a restore ceremony has no generated entropy.
    /// This is a transcription check, not a security boundary.
    public func transcriptionChallenge(count: Int = 3) throws -> [Int] {
        guard !mnemonicWords.isEmpty else { throw CeremonyError.missingMnemonic }
        let digest = SHA256.hash(mnemonicWords.joined(separator: " "))
        var indices: [Int] = []
        var cursor = 0
        while indices.count < count && cursor < digest.count {
            let candidate = Int(digest[cursor]) % mnemonicWords.count
            if !indices.contains(candidate) { indices.append(candidate) }
            cursor += 1
        }
        return indices.sorted()
    }

    public func confirmTranscription(entries: [(index: Int, word: String)]) throws {
        guard step == .mnemonic else {
            throw CeremonyError.stepOutOfOrder(expected: step, actual: .mnemonic)
        }
        for entry in entries {
            guard entry.index >= 0, entry.index < mnemonicWords.count else {
                throw CeremonyError.transcriptionMismatch(index: entry.index)
            }
            let expected = mnemonicWords[entry.index].lowercased()
            let actual = entry.word.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard expected == actual else {
                throw CeremonyError.transcriptionMismatch(index: entry.index)
            }
        }
        mnemonicConfirmed = true
        if mode == .freshGeneration { report.mnemonicBackedUp = true }
        advance(to: .derivation)
    }

    /// Continues without writing the 24 words down.
    ///
    /// Allowed, and recorded rather than assumed: with the words unwritten, the YubiKeys this
    /// ceremony writes are the wallet, and the operator is told so in those terms. The
    /// judgement behind allowing it is that a compulsory backup is one an operator learns to
    /// click through; what makes the choice legible is the count they just gave — one card and
    /// no backup means one device holding everything (amendment 40).
    ///
    /// Restore mode has nothing to decline: those words came from a backup that already
    /// exists, and the back-fill there is a check on the typing rather than a backup step.
    public func declineMnemonicBackup() throws {
        try requireCurrent(.mnemonic)
        guard mode == .freshGeneration else {
            throw CeremonyError.unsupportedRecovery(
                "these words came from an existing backup, so there is nothing new to write down"
            )
        }
        guard !mnemonicWords.isEmpty else { throw CeremonyError.missingMnemonic }
        mnemonicConfirmed = true
        report.mnemonicBackedUp = false
        addWarning(
            "The 24 words were not written down. They are the only way to restore these keys: if every "
                + "YubiKey provisioned in this ceremony is lost, destroyed or reset, the wallet is gone."
        )
        advance(to: .derivation)
    }

    // MARK: Step 8 — derivation

    /// Derives **both** keys from the one mnemonic and computes their identities.
    ///
    /// secp256k1 goes through BIP32 and yields both an EVM and a Bitcoin address
    /// (same key, two encodings); Ed25519 goes through SLIP-0010 and its identity
    /// is the public key itself. Only public summaries are returned; the private
    /// keys and chain codes stay inside the ceremony object until import completes.
    @discardableResult
    public func deriveKeys(passphrase: String = "") throws -> DerivedKeys {
        try requireCurrent(.derivation)
        guard mnemonicConfirmed else { throw CeremonyError.mnemonicNotConfirmed }
        guard !mnemonicWords.isEmpty else { throw CeremonyError.missingMnemonic }

        if let existing = seed { existing.zeroize() }
        let derivedSeed = try BIP39.seed(mnemonic: mnemonicWords, passphrase: passphrase)
        seed = derivedSeed

        let secp256k1 = try deriveSecp256k1(seed: derivedSeed)
        let ed25519 = try deriveEd25519(seed: derivedSeed)
        let keys = DerivedKeys(secp256k1: secp256k1, ed25519: ed25519)
        derivedKeys = keys

        report.keys = keys.all.map { summary in
            var record = KeyRecord(
                algorithm: summary.algorithm,
                slot: summary.slot,
                path: summary.path.description,
                identity: summary.identity
            )
            record.evmAddress = summary.evmAddress
            record.bitcoinAddress = summary.bitcoinAddress
            record.publicKeyHex = summary.publicKeyHex
            record.fingerprintHex = summary.fingerprintHex
            record.parentFingerprintHex = summary.parentFingerprintHex
            record.masterFingerprintHex = summary.masterFingerprintHex
            return record
        }
        // Deliberately does NOT advance: the derived identities are needed for
        // the independent cross-check two steps later.
        return keys
    }

    private func deriveSecp256k1(seed: SensitiveBytes) throws -> DerivedKeySummary {
        let master = try ExtendedPrivateKey.master(seed: seed)
        let node = try master.derived(.secp256k1Default)
        let publicKey = try node.publicKey()

        privateKeys[.secp256k1]?.zeroize()
        privateKeys[.secp256k1] = node.key
        chainCodes[.secp256k1] = node.chainCode

        // Pairing export: the BIP44 account node one level up (`m/44'/0'/0'`),
        // with its chain code. A Keystone/MetaMask wallet derives `<origin>/0/*`
        // from this extended public key; index 0 is the leaf above. The pinned
        // `children` path (`0/0`) makes such a wallet present that leaf for every
        // account index instead of sibling addresses this card cannot sign for.
        let accountPath = DerivationPath(
            components: Array(DerivationPath.secp256k1Default.components.prefix(3))
        )
        let accountNode = try master.derived(accountPath)
        pairingExports[.secp256k1] = PairingExport(
            algorithm: .secp256k1,
            path: accountPath,
            publicKey: try accountNode.publicKey(),
            chainCode: accountNode.chainCode,
            parentFingerprintHex: Hex.encode(accountNode.parentFingerprint),
            masterFingerprintHex: Hex.encode(try master.fingerprint()),
            childrenPath: DerivationPath(
                components: Array(DerivationPath.secp256k1Default.components.dropFirst(accountPath.components.count))
            ),
            isAccountLevel: true
        )

        return DerivedKeySummary(
            algorithm: .secp256k1,
            slot: .signature,
            path: .secp256k1Default,
            publicKey: publicKey,
            fingerprintHex: Hex.encode(try node.fingerprint()),
            parentFingerprintHex: Hex.encode(node.parentFingerprint),
            masterFingerprintHex: Hex.encode(try master.fingerprint()),
            identity: try EVMAddress.checksummed(fromPublicKey: publicKey),
            evmAddress: try EVMAddress.checksummed(fromPublicKey: publicKey),
            bitcoinAddress: try BitcoinAddress.p2wpkh(publicKeyCompressed: publicKey)
        )
    }

    private func deriveEd25519(seed: SensitiveBytes) throws -> DerivedKeySummary {
        let master = try ExtendedPrivateKeyEd25519.master(seed: seed)
        let node = try master.derived(.ed25519Default)
        let publicKey = try node.publicKey()
        guard publicKey.count == KeyAlgorithm.ed25519.publicKeyLength else {
            throw CeremonyError.unsupportedAlgorithm(.ed25519, "unexpected public key length \(publicKey.count)")
        }

        privateKeys[.ed25519]?.zeroize()
        privateKeys[.ed25519] = node.key
        chainCodes[.ed25519] = node.chainCode

        // Ed25519 is exported at its own path: SLIP-0010 derivation is
        // all-hardened, so a watch-only wallet cannot derive children from an
        // extended public key anyway. The chain code is still included, because a
        // `crypto-hdkey` without one crashes Keystone/MetaMask decoders.
        pairingExports[.ed25519] = PairingExport(
            algorithm: .ed25519,
            path: .ed25519Default,
            publicKey: publicKey,
            chainCode: node.chainCode,
            parentFingerprintHex: Hex.encode(node.parentFingerprint),
            masterFingerprintHex: Hex.encode(try master.fingerprint()),
            childrenPath: nil,
            isAccountLevel: false
        )

        return DerivedKeySummary(
            algorithm: .ed25519,
            slot: .authentication,
            path: .ed25519Default,
            publicKey: publicKey,
            fingerprintHex: Hex.encode(try node.fingerprint()),
            parentFingerprintHex: Hex.encode(node.parentFingerprint),
            masterFingerprintHex: Hex.encode(try master.fingerprint()),
            identity: publicKey.hexString,
            evmAddress: nil,
            bitcoinAddress: nil
        )
    }

    /// Identity string for an algorithm from an arbitrary public key. Used by the
    /// read-back step so the card's key produces the same *kind* of string as the
    /// derived key, making a mismatch human-readable.
    static func identity(for algorithm: KeyAlgorithm, publicKey: [UInt8]) throws -> String {
        switch algorithm {
        case .secp256k1: return try EVMAddress.checksummed(fromPublicKey: publicKey)
        case .ed25519: return publicKey.hexString
        }
    }

    // MARK: Step 9 — write the card and read it back (design.md §4.2 steps 6, 7, 7b)

    /// Writes everything this card holds — both private keys, the policy that makes
    /// them safe to use, and the pairing manifest — and then reads all of it back off
    /// the card and checks it.
    ///
    /// One step, so that no screen exists between a write and its proof, and so the
    /// applet's ordering requirements are not reorderable by the view layer; the order
    /// and the reason for it are in `CeremonyStep.keyImport`. Each write re-verifies the
    /// Admin PIN in its own session (`SignerCard.importKey`, `SignerCard.applyPolicy`,
    /// `SignerCard.writePairingManifest`), because VERIFY state does not survive an NFC
    /// session boundary.
    ///
    /// The failures are distinguished by the operator's next move:
    ///
    /// * a **key** that failed to import leaves the card half provisioned. The applet
    ///   refuses to overwrite an occupied slot, so "retry the import" can never work and
    ///   the card has to be reset (`importLeftTheCardPartlyProvisioned`);
    /// * a **key that reads back different** voids the procedure: everything local is
    ///   wiped and the operator is sent back to the card inspection step
    ///   (`readBackMismatch`);
    /// * a **policy** that failed to write, or that the card does not report back, stops
    ///   the ceremony without wiping (`policyNotApplied`): the keys in the card are the
    ///   right keys, and the card must not be used because the touch requirement it was
    ///   promised cannot be read back off it. The applet already refused the write once,
    ///   so a second write would be the blind retry design.md §5.2 rule 1 forbids, and
    ///   the way out of that state is the reset step;
    /// * a **manifest** that cannot be stored, or that does not read back byte-for-byte
    ///   and bind to the card's own key, stops the ceremony (`pairingManifestNotStored`):
    ///   it is part of what the step writes, so a card that cannot report it back has not
    ///   been provisioned the way the operator was told it would be.
    @discardableResult
    public func importAndVerify(creationTime: Date? = nil) async throws -> [KeyAlgorithm: ReadBackResult] {
        try requireCurrent(.keyImport)
        try await writeKeysAndPolicy(creationTime: creationTime)
        try await readBackAndCheckPolicy()
        _ = try await writePairingManifestAndCheck()
        // This card is written and verified, so its serial joins the written set (which the
        // next card's inventory checks against) and its PINs are wiped here rather than held
        // to the end of the ceremony: every card gets its own PINs (amendment 40), and a
        // secret kept past its last use is a secret kept for no reason.
        if let serial = inventory?.serial { provisionedSerials.insert(serial) }
        sessionAdminPIN?.zeroize()
        sessionAdminPIN = nil
        // This card's serial is what the next card's inventory is checked against, so it is
        // recorded here rather than when the operator advances — an interruption after this
        // point still knows which card must not be presented again.
        lastWrittenCardSerial = inventory?.serial

        // Deliberately does NOT advance: the operator has to see the card's own answer —
        // both public keys next to the ones derived here, the policy as the card reports
        // it, and the manifest's outcome — before the step closes. `advance()` is what
        // checks that all three halves ran, so nothing can move on from a card that was
        // written but not read back.
        return readBackResults
    }

    /// Both key writes and then the policy write: the first half of `importAndVerify`.
    /// Private because on its own it leaves a written card that has not been verified.
    private func writeKeysAndPolicy(creationTime: Date? = nil) async throws {
        try requireCurrent(.keyImport)
        guard let keys = derivedKeys else { throw CeremonyError.keysNotDerived }
        guard let adminPIN = sessionAdminPIN else { throw CeremonyError.missingAdminPIN }

        var pin = adminPIN.materializedCopy()
        defer { VaultKit.wipe(&pin) }
        let timestamp = creationTime ?? clock()

        do {
            try await withMutatingStep(.keyImport) {
                for summary in keys.all {
                    guard let privateKey = self.privateKeys[summary.algorithm] else {
                        throw CeremonyError.keysNotDerived
                    }
                    let fingerprint = Array(try Hex.decode(summary.fingerprintHex))
                    try await self.card.importKey(
                        slot: summary.slot,
                        algorithm: summary.algorithm,
                        privateKey: privateKey,
                        fingerprint: fingerprint,
                        creationTime: timestamp,
                        adminPIN: pin
                    )
                }
            }
        } catch {
            // The keys are written one slot at a time, so a failure on the second
            // slot leaves the first one holding a key. The applet refuses to
            // overwrite an occupied slot, which means "retry the import" can never
            // work and the operator has to be told to reset — otherwise the same
            // error repeats with no way out. This is the failure mode a real
            // provisioning run hit when the Ed25519 attributes were wrong
            // (amendment 29).
            let after = try? await card.inventory()
            let occupied = after?.occupiedSlots.map(\.displayName).sorted() ?? []
            guard !occupied.isEmpty else { throw error }
            wipe()
            step = .cardInventory
            let description = (error as? CardError)?.userFacingDescription
                ?? (error as? CeremonyError)?.userFacingDescription
                ?? "\(error)"
            throw CeremonyError.importLeftTheCardPartlyProvisioned(slots: occupied, detail: description)
        }

        // The policy, in the same step and after the last key write. It gets its own
        // mutating-step frame so that an interruption here is still reported as this
        // step being in flight — because it is the write that may have half happened.
        do {
            try await withMutatingStep(.keyImport) {
                try await self.card.applyPolicy(adminPIN: pin)
            }
        } catch let error as CardError {
            throw CeremonyError.policyNotApplied(detail: error.userFacingDescription)
        }
    }

    /// The read-back half of step 9: both public keys byte-for-byte against the keys
    /// derived here, and then the policy the card reports — the touch policy on both
    /// signing-capable slots, the PW1 status, and the PIN retry limits the operator
    /// chose.
    ///
    /// A mismatch on **either** key voids the entire procedure: everything is wiped
    /// and the operator is sent back to the card inspection step. A policy the card
    /// does not report stops the ceremony just as firmly, but it is a different
    /// failure and is reported as itself: the keys in the card are the right keys, so
    /// nothing local is wiped, and the card must not be used because the touch
    /// requirement it was promised cannot be read back off it (amendment 26). The way
    /// out of that state is the reset step, not a second write.
    ///
    /// Private because this is the proof of the write that just happened, not a step of
    /// its own (amendment 37).
    private func readBackAndCheckPolicy() async throws {
        guard let keys = derivedKeys else { throw CeremonyError.keysNotDerived }

        var results: [KeyAlgorithm: ReadBackResult] = [:]
        for summary in keys.all {
            let cardPublicKey = try await card.readPublicKey(slot: summary.slot)
            let identityFromCard = try Self.identity(for: summary.algorithm, publicKey: cardPublicKey)
            let matches = cardPublicKey == summary.publicKey
            results[summary.algorithm] = ReadBackResult(
                algorithm: summary.algorithm,
                slot: summary.slot,
                cardPublicKeyHex: cardPublicKey.hexString,
                derivedPublicKeyHex: summary.publicKeyHex,
                matches: matches,
                identityFromCardKey: identityFromCard
            )

            guard matches else {
                // Hard abort: wipe everything and send the operator back to the
                // reset step. design.md §4.2 step 7: "the entire procedure is void".
                wipe()
                step = .cardInventory
                throw CeremonyError.readBackMismatch(
                    algorithm: summary.algorithm,
                    local: summary.publicKeyHex,
                    card: cardPublicKey.hexString
                )
            }
            if let index = report.keys.firstIndex(where: { $0.algorithm == summary.algorithm.rawValue }) {
                report.keys[index].readBackVerified = true
            }
        }
        readBackResults = results

        // The policy, read off the card in the same session as the keys. A policy the
        // card does not report is not a policy: every write answered `9000` while the
        // card kept touch off, which is the failure mode this check exists for
        // (amendment 26).
        let after = try await card.inventory()
        inventory = after
        let problems = Self.policyDisagreements(
            inventory: after,
            userRetryLimit: report.userPINRetryLimit,
            adminRetryLimit: report.adminPINRetryLimit
        )
        guard problems.isEmpty else {
            throw CeremonyError.policyNotApplied(detail: problems.joined(separator: "; "))
        }
        report.touchPolicyVerified = true
        // Does NOT advance: the caller advances once the manifest has been written and
        // checked too — the step is one operation (amendment 37).
    }

    /// Everything the card has to be reporting for the policy to count as applied.
    ///
    /// Kept as one list so the step and its tests reason about the same things, and so
    /// a policy that is checked in one place and described in another cannot drift.
    static func policyDisagreements(
        inventory: CardInventory,
        userRetryLimit: Int?,
        adminRetryLimit: Int?
    ) -> [String] {
        var problems: [String] = []
        if !CardPolicy.isTouchFixed(inventory.touchPolicy[.signature]) {
            problems.append(
                "the signature slot's touch policy reads \(CardPolicy.describeTouchPolicy(inventory.touchPolicy[.signature]))"
            )
        }
        if !CardPolicy.isTouchFixed(inventory.touchPolicy[.authentication]) {
            problems.append(
                "the authentication slot's touch policy reads \(CardPolicy.describeTouchPolicy(inventory.touchPolicy[.authentication]))"
            )
        }
        if let status = inventory.pwStatusBytes, let first = status.first, first != CardPolicy.pw1StatusPerSignature {
            problems.append("the PW1 status reads 0x\(String(format: "%02x", first))")
        }
        // The retry limits were chosen earlier in the run; re-reading them here is what
        // proves the key import and the policy write did not disturb them, since this
        // is the last look at the card before the pairing codes are produced.
        if let userLimit = userRetryLimit, let adminLimit = adminRetryLimit {
            if let counters = inventory.retryCounters {
                if Int(counters.user) != userLimit || Int(counters.admin) != adminLimit {
                    problems.append(
                        "the PIN retry limits read back as \(counters.user)/\(counters.admin), "
                            + "not \(userLimit)/\(adminLimit)"
                    )
                }
            } else {
                problems.append("the card no longer reports PIN retry counters")
            }
        }
        return problems
    }

    // MARK: Step 9b — the pairing manifest (design.md §4.2 step 7b)

    /// Writes the pairing manifest into the card and reads it straight back.
    ///
    /// This is what makes the pairing codes reproducible **without resetting the
    /// applet**. A chain code cannot be read out of a YubiKey — the OpenPGP
    /// applet holds a key, not a BIP32 node (design.md §4.3) — so without this
    /// step the only way to show the codes again is to re-run the whole ceremony,
    /// which destroys the keys. The manifest stores the extended public keys a
    /// wallet needs, and storing them on the card keeps the app stateless: the only
    /// value the phone stores is the card connection (amendment 31), so a re-pair on a
    /// fresh install works.
    ///
    /// Deliberately *after* the read-back: the card must not be told to advertise a
    /// key until that key has been verified to be in it. It is inside the import step
    /// rather than after it, so that an interruption cannot leave a card that holds
    /// verified keys and no manifest without the ceremony knowing (amendment 37).
    ///
    /// **Failure here stops the ceremony** (amendment 38). The manifest is part of what
    /// this step writes, and the step's promise is that the card reports back everything
    /// it was told: a card that cannot hold the object, refuses the write, or hands back
    /// something other than what was written has not been provisioned the way the
    /// operator was told it would be. The keys and the mnemonic are unaffected — which is
    /// why this is reported as itself rather than as a lost wallet — but the card must
    /// not be used, and the way forward is the reset, because a second write would be the
    /// blind retry design.md §5.2 rule 1 forbids.
    ///
    /// Private: the third write of `importAndVerify`.
    private func writePairingManifestAndCheck() async throws -> PairingManifest {
        guard let adminPIN = sessionAdminPIN else { throw CeremonyError.missingAdminPIN }
        var pin = adminPIN.materializedCopy()
        defer { VaultKit.wipe(&pin) }

        switch inventory?.pairingManifest ?? .unsupported {
        case .unsupported:
            throw CeremonyError.pairingManifestNotStored(
                detail: "this card refused the read of its private-use data object, so there is no "
                    + "place on it for the public keys and chain codes a wallet needs."
            )
        case .unreadable(let reason):
            throw CeremonyError.pairingManifestNotStored(
                detail: "the card's pairing manifest slot could not be read (\(reason))."
            )
        case .absent, .present:
            break
        }

        guard let manifest = makePairingManifest() else {
            throw CeremonyError.stepIncomplete(
                step: .keyImport,
                detail: "the pairing export has not been built yet"
            )
        }
        let encoded = manifest.encoded()

        do {
            try await withMutatingStep(.keyImport) {
                try await card.writePairingManifest(encoded, adminPIN: pin)
            }
        } catch let error as CardError {
            throw CeremonyError.pairingManifestNotStored(
                detail: "the write was refused (\(error.userFacingDescription.lowercased()))."
            )
        }

        // Read it straight back. A write that is not read back is a write that is
        // assumed, and the whole point of this object is that a *later* session
        // can trust it.
        let readBack: [UInt8]?
        do {
            readBack = try await card.readPairingManifest()
        } catch let error as CardError {
            throw CeremonyError.pairingManifestNotStored(
                detail: "it was written but could not be read back "
                    + "(\(error.userFacingDescription.lowercased()))."
            )
        }
        guard readBack == encoded else {
            throw CeremonyError.pairingManifestNotStored(
                detail: "it did not read back byte-for-byte (wrote \(encoded.count) bytes, "
                    + "read \(readBack?.count.description ?? "nothing"))."
            )
        }

        // The check a later re-pair will repeat: derive the pinned child of the
        // stored account node and confirm it is the key physically in the card.
        // Doing it here means a manifest that could never verify is caught while
        // the mnemonic is still on screen, rather than months later.
        do {
            try manifest.verify(against: cardKeyReport(from: readBackResults))
        } catch let error as PairingManifest.VerificationError {
            throw CeremonyError.pairingManifestNotStored(
                detail: "the stored manifest does not describe the keys in this card (\(error))."
            )
        }

        pairingManifest = manifest
        report.pairingManifestStored = true
        return manifest
    }
    private func requireMode(_ expected: CeremonyMode) throws {
        guard mode == expected else {
            throw CeremonyError.wrongCeremonyMode(expected: expected, actual: mode)
        }
    }

    /// The public material the card needs in order to be re-paired later.
    private func makePairingManifest() -> PairingManifest? {
        guard derivedKeys != nil else { return nil }
        let exports = KeyAlgorithm.allCases.compactMap { pairingExports[$0] }
        guard exports.count == KeyAlgorithm.allCases.count else { return nil }

        // The serial is what ties a manifest to one card, so a manifest copied to
        // another YubiKey is refused with a reason the operator can act on.
        guard let serial = inventory?.serial,
              let serialBytes = try? Hex.decode(serial), serialBytes.count == 4
        else { return nil }
        let entries = exports.compactMap(PairingManifest.Entry.init(export:))
        guard entries.count == exports.count else { return nil }

        return PairingManifest(cardSerial: serialBytes, entries: entries)
    }

    /// What the card reports about its own keys, for a manifest check.
    private func cardKeyReport(from results: [KeyAlgorithm: ReadBackResult]) -> CardKeyReport {
        var keys: [KeyAlgorithm: [UInt8]] = [:]
        for (algorithm, result) in results {
            guard let publicKey = try? Hex.decode(result.cardPublicKeyHex) else { continue }
            keys[algorithm] = publicKey
        }
        return CardKeyReport(
            cardSerial: inventory?.serial.flatMap { try? Hex.decode($0) },
            publicKeys: keys
        )
    }

    // MARK: Step 10 — pairing export (design.md §4.2 step 8)

    /// Builds **two** URs, one per algorithm, for the desktop wallet to scan.
    ///
    /// Both carry a chain code (Keystone/MetaMask require one). secp256k1 is
    /// exported at its BIP44 account level with the children path pinned to the
    /// card's leaf, so an account-enumerating wallet shows the card's address.
    /// `chainCodeAcknowledged` is the operator's acknowledgement of
    /// `PairingPolicy.chainCodeWarning`.
    @discardableResult
    public func buildPairingURs(
        style: URTypeStyle,
        chainCodeAcknowledged: Bool
    ) throws -> [KeyAlgorithm: UR] {
        try requireCurrent(.pairingExport)
        guard !pairingExports.isEmpty else { throw CeremonyError.keysNotDerived }
        guard chainCodeAcknowledged else { throw CeremonyError.pairingPolicyNotAcknowledged }

        var urs: [KeyAlgorithm: UR] = [:]
        for algorithm in KeyAlgorithm.allCases {
            guard let export = pairingExports[algorithm] else {
                throw CeremonyError.keysNotDerived
            }
            // Per key, not per ceremony: the two keys name different masters.
            guard let sourceFingerprint = UInt32(export.masterFingerprintHex.prefix(8), radix: 16) else {
                throw CeremonyError.keysNotDerived
            }
            let origin = URKeyPath(path: export.path, sourceFingerprint: sourceFingerprint)
            // `children` is written only when the export is an ancestor of the
            // leaf: it pins a deriving wallet to the card's one signable key.
            let children = export.childrenPath.map { URKeyPath(path: $0) }
            let key = HDKey(
                keyData: export.publicKey,
                chainCode: export.chainCode,
                useInfo: CoinInfo(type: algorithm.slip44CoinType, network: 0),
                origin: origin,
                children: children,
                parentFingerprint: UInt32(export.parentFingerprintHex.prefix(8), radix: 16),
                // Field 9. Required in practice, not just decorative: see
                // `PairingPolicy.deviceName`.
                name: PairingPolicy.deviceName
            )
            let ur = try key.ur(style: style)
            urs[algorithm] = ur
            if let index = report.keys.firstIndex(where: { $0.algorithm == algorithm.rawValue }) {
                report.keys[index].pairingURType = ur.type
                report.keys[index].pairingIncludedChainCode = true
                report.keys[index].pairingPath = export.path.description
                report.keys[index].pairingPublicKeyHex = export.publicKeyHex
                report.keys[index].pairingAccountLevel = export.isAccountLevel
            }
        }
        pairingURs = urs
        addWarning(PairingPolicy.chainCodeWarning)
        // Deliberately does NOT advance: the operator must scan the codes and
        // confirm the wallet shows the same addresses first.
        return urs
    }

    public var pairingURStrings: [KeyAlgorithm: String] {
        pairingURs.mapValues(\.string)
    }

    // MARK: Step 12 — counter baseline (design.md §4.2 step 9)

    /// Read-only re-pair: recovers the pairing codes from the card alone.
    ///
    /// Nothing is written, no PIN is presented and the applet is not reset — the
    /// keys stay where they are, which is the only reason the manifest was stored
    /// in the first place. What comes back is the same public material the
    /// provisioning ceremony exported, so a wallet pairing now sees exactly the
    /// account it would have seen then.
    ///
    /// The object is treated as untrusted input until it has been checked against
    /// the keys the card reports: a stale, foreign or corrupt manifest produces an
    /// error rather than codes for a wallet that could never spend them.
    @discardableResult
    public func readPairingManifestFromCard() async throws -> PairingManifest {
        try requireCurrent(.rePairRead)
        try requireMode(.rePair)

        let stored: [UInt8]?
        do {
            stored = try await card.readPairingManifest()
        } catch let error as CardError {
            throw CeremonyError.noPairingManifest(reason: error.userFacingDescription.lowercased())
        }
        guard let encoded = stored, !encoded.isEmpty else {
            throw CeremonyError.noPairingManifest(
                reason: "the card's private-use data object is empty. It is written by a provisioning "
                    + "ceremony and erased by an applet reset, so this card was either provisioned "
                    + "before the manifest existed, or reset since."
            )
        }

        let manifest: PairingManifest
        do {
            manifest = try PairingManifest.decode(encoded)
        } catch {
            throw CeremonyError.pairingManifestRejected(
                reason: "the \(encoded.count) bytes stored on the card are not a valid pairing "
                    + "manifest (\(error))."
            )
        }

        // Ask the card first. The object's contents are a claim; the keys in the
        // slots are the fact the claim has to match.
        var publicKeys: [KeyAlgorithm: [UInt8]] = [:]
        for algorithm in KeyAlgorithm.allCases {
            do {
                publicKeys[algorithm] = try await card.readPublicKey(slot: algorithm.slot)
            } catch let error as CardError {
                throw CeremonyError.pairingManifestRejected(
                    reason: "the \(algorithm.displayName) slot did not return a public key "
                        + "(\(error.userFacingDescription.lowercased())), so the stored manifest cannot be "
                        + "checked against it."
                )
            }
        }
        let serial = (try? Hex.decode(inventory?.serial ?? "")).flatMap { $0.count == 4 ? $0 : nil }
        do {
            try manifest.verify(against: CardKeyReport(cardSerial: serial, publicKeys: publicKeys))
        } catch let error as PairingManifest.VerificationError {
            throw CeremonyError.pairingManifestRejected(reason: error.userFacingDescription)
        }

        var results: [KeyAlgorithm: ReadBackResult] = [:]
        var exports: [KeyAlgorithm: PairingExport] = [:]
        var records: [KeyRecord] = []
        for entry in manifest.entries {
            guard let cardPublicKey = publicKeys[entry.algorithm] else { continue }
            let leaf = try manifest.cardLeafPublicKey(for: entry.algorithm)
            results[entry.algorithm] = ReadBackResult(
                algorithm: entry.algorithm,
                slot: entry.algorithm.slot,
                cardPublicKeyHex: cardPublicKey.hexString,
                // The manifest's derivation, not a locally derived key: in this
                // mode the mnemonic is nowhere near the device.
                derivedPublicKeyHex: leaf.hexString,
                matches: cardPublicKey == leaf,
                identityFromCardKey: try Self.identity(for: entry.algorithm, publicKey: cardPublicKey)
            )
            exports[entry.algorithm] = PairingExport(
                algorithm: entry.algorithm,
                path: entry.originPath,
                publicKey: entry.publicKey,
                chainCode: entry.chainCode,
                parentFingerprintHex: Hex.encode(entry.parentFingerprint),
                masterFingerprintHex: Hex.encode(entry.masterFingerprint),
                childrenPath: entry.childrenPath,
                isAccountLevel: entry.childrenPath != nil
            )

            // Same record shape as a provisioning ceremony, so the printed record
            // and the wallet agree line for line.
            let leafPath = DerivationPath(
                components: entry.originPath.components + (entry.childrenPath?.components ?? [])
            )
            var record = KeyRecord(
                algorithm: entry.algorithm,
                slot: entry.algorithm.slot,
                path: leafPath.description,
                identity: try Self.identity(for: entry.algorithm, publicKey: cardPublicKey)
            )
            record.publicKeyHex = cardPublicKey.hexString
            record.fingerprintHex = Self.fingerprintHex(for: entry.algorithm, publicKey: cardPublicKey)
            // The leaf's parent, not the origin path's: the record prints the path
            // of the key in the card (`…/0/0`), so the fingerprint beside it has to
            // be that node's parent. For an export that pins children this is one
            // level below the entry's own `parentFingerprint`; it is derivable
            // because the pinned path is non-hardened.
            record.parentFingerprintHex = try manifest.cardLeafParentFingerprint(for: entry.algorithm)
                .map(Hex.encode) ?? Hex.encode(entry.parentFingerprint)
            record.masterFingerprintHex = Hex.encode(entry.masterFingerprint)
            record.readBackVerified = true
            if entry.algorithm == .secp256k1 {
                record.evmAddress = try EVMAddress.checksummed(fromPublicKey: cardPublicKey)
                record.bitcoinAddress = try BitcoinAddress.p2wpkh(publicKeyCompressed: cardPublicKey)
            }
            records.append(record)
        }

        pairingManifest = manifest
        pairingExports = exports
        readBackResults = results
        report.keys = records
        report.pairingManifestStored = true
        // Deliberately does NOT advance: the operator has to see which keys were
        // found and which addresses they produce before any code is shown.
        return manifest
    }

    /// Key fingerprint, in the convention each algorithm's derivation uses:
    /// BIP32 hashes the compressed public key, SLIP-0010 prefixes a `0x00` byte
    /// to it. The distinction matters because the provisioning record prints this
    /// value for both keys — a re-pair must print the same number the ceremony
    /// did, or the two records disagree about one of the keys they describe.
    static func fingerprintHex(for algorithm: KeyAlgorithm, publicKey: [UInt8]) -> String {
        switch algorithm {
        case .secp256k1:
            return Array(RIPEMD160.hash160(publicKey).prefix(4)).hexString
        case .ed25519:
            return Array(RIPEMD160.hash160([0x00] + publicKey).prefix(4)).hexString
        }
    }

    // MARK: The wipe before the pairing codes (design.md §4.2, the paragraph before step 8)

    /// Clears every secret out of this object and records that it happened.
    ///
    /// This is the wipe that runs **before** the pairing codes are produced: the mnemonic,
    /// the seed, both derived private keys, the per-card Admin PIN and the entropy go; the
    /// public material the pairing step has to show (public keys, chain codes, fingerprints,
    /// addresses) and the record stay, because the wallet is about to be given it.
    ///
    /// It does not advance: the step closes on the operator's Continue, like every other
    /// step that produces something for them to read (amendment 32).
    public func wipeSecrets() throws {
        try requireCurrent(.wipeSecrets)
        wipeSecretMaterial()
        report.secretsWipedBeforePairing = true
    }

    /// True when no secret of this ceremony is in memory any more: the entropy, the seed, both
    /// private keys, the mnemonic and the Admin PIN are all gone. `advance()` at `.wipeSecrets`
    /// requires it.
    ///
    /// Derived from the secrets themselves rather than set by `wipeSecrets()`, so it cannot
    /// claim a wipe that did not happen — which is the point of gating the step on it (§5.2
    /// rule 5, amendment 42). The public material (the exports, the addresses, the read-back
    /// and the record) is deliberately not part of it: the wallet is about to be given all of
    /// it.
    public var secretsWiped: Bool {
        entropy == nil && seed == nil && privateKeys.isEmpty && mnemonicWords.isEmpty
            && sessionAdminPIN == nil
    }

    private func wipeSecretMaterial() {
        entropy?.zeroize(); entropy = nil
        seed?.zeroize(); seed = nil
        for (_, key) in privateKeys { key.zeroize() }
        privateKeys = [:]
        sessionAdminPIN?.zeroize(); sessionAdminPIN = nil
        for index in mnemonicWords.indices { mnemonicWords[index] = "" }
        mnemonicWords = []
        mnemonicConfirmed = false
    }

    // MARK: Step 12 — teardown

    /// Completes the record and wipes what is left — the public pairing material and the
    /// mnemonic's last copies, which `wipeSecrets()` has already taken care of by now. An app
    /// restart is required before another ceremony (enforced by the UI, which is what
    /// `isFinished` is for).
    @discardableResult
    public func finish() -> CeremonyReport {
        report.completedAt = clock()
        let finished = report
        wipe()
        step = .teardown
        return finished
    }

    public var isFinished: Bool { step == .teardown && report.completedAt != nil }

    /// Wipes every secret in this object **and** the public pairing material. Idempotent.
    ///
    /// `derivedKeys` holds only public data, but it is cleared too: after a void
    /// procedure or an abort, no stale "paired account" may remain visible.
    public func wipe() {
        wipeSecretMaterial()
        chainCodes = [:]
        pairingURs = [:]
        pairingExports = [:]
        // The manifest is public data, but it is derived from `pairingExports`:
        // leaving a copy behind after a wipe would mean the teardown step left
        // wallet material in memory. The durable record is `report`.
        pairingManifest = nil
        provisionedSerials.removeAll()
        chosenRetryLimits = nil
        cardIndex = 0
        cardCount = 1
        derivedKeys = nil
        readBackResults = [:]
    }

    public func abort() {
        if step != .notStarted {
            report.warnings.append("Ceremony aborted at \(step.title).")
        }
        wipe()
        step = .notStarted
    }
}
