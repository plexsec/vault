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

    public var keyAlgorithm: KeyAlgorithm? { KeyAlgorithm(rawValue: algorithm) }

    public init(algorithm: KeyAlgorithm, slot: KeySlot, path: String, identity: String) {
        self.algorithm = algorithm.rawValue
        self.slot = slot.rawValue
        self.path = path
        self.identity = identity
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
    public var cardSerial: String?
    public var cardOpenPGPVersion: String?
    public var counterBaseline: UInt32?
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
        if let cardSerial { lines.append("yubikey serial: \(cardSerial)") }
        if let cardOpenPGPVersion { lines.append("openpgp applet: \(cardOpenPGPVersion)") }

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
            if record.pairingIncludedChainCode { lines.append("pairing included chain code: yes") }
        }

        if let counterBaseline { lines.append("signature counter baseline (secp256k1/signature slot): \(counterBaseline)") }
        lines.append("note: the Ed25519 key has no hardware signature counter; the counter audit covers secp256k1 only.")
        for warning in warnings { lines.append("warning: \(warning)") }
        return lines
    }

    private static let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}

/// Policy for what the pairing UR is allowed to advertise.
///
/// One YubiKey slot holds exactly one key (design.md §4.3), so neither
/// address-level key has signable children. Exporting a chain code lets a wallet
/// derive further addresses the card *cannot sign for* — it would offer accounts
/// that fail at signing time. The default is therefore to omit the chain code and
/// publish only the single key; including it requires an explicit acknowledgement.
public enum PairingPolicy: Equatable, Sendable {
    /// Single key, no chain code. Safe default.
    case singleKeyOnly
    /// Key *with* chain code, so wallets that require one accept the pairing.
    /// `acknowledgedUnsignableChildren` must be true.
    case includeChainCode(acknowledgedUnsignableChildren: Bool)

    public var includesChainCode: Bool {
        if case .includeChainCode(let acknowledged) = self { return acknowledged }
        return false
    }

    public var warning: String? {
        switch self {
        case .singleKeyOnly:
            return nil
        case .includeChainCode(let acknowledged):
            guard acknowledged else { return nil }
            return "The exported key includes a chain code. Your wallet may derive "
                + "further addresses from it, but this YubiKey cannot sign for them: "
                + "it holds one key only. Do not send funds to derived addresses."
        }
    }
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
    /// Held only between the PIN step and the policy step so that PUT DATA of the
    /// protected policy objects can authenticate. Wiped with everything else.
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
    /// codes and the counter value — was replaced by the next screen in the same
    /// render pass and never seen.
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
            step = .reset

        case .reset, .pinProvisioning, .policy, .keyImport:
            // Action-only steps advance themselves once the card accepts them.
            throw CeremonyError.stepIncomplete(step: step, detail: "this step completes when the YubiKey accepts it")

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
            step = .keyImport

        case .readBackCheck:
            guard report.readBackVerified else {
                throw CeremonyError.stepIncomplete(step: .readBackCheck, detail: "the public keys have not been verified yet")
            }
            step = .pairingExport

        case .pairingExport:
            guard pairingURs.count == KeyAlgorithm.allCases.count else {
                throw CeremonyError.stepIncomplete(step: .pairingExport, detail: "the pairing codes have not been produced yet")
            }
            guard pairingAddressConfirmedByOperator else {
                throw CeremonyError.pairingAddressNotConfirmed
            }
            step = .counterBaseline

        case .counterBaseline:
            guard report.counterBaseline != nil else {
                throw CeremonyError.stepIncomplete(step: .counterBaseline, detail: "the signature counter has not been read yet")
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

    /// Records an interruption (transport loss, app backgrounding).
    ///
    /// Rewinds to card inspection **only** when a mutating card operation was in
    /// flight: that is the case where the card may have received a `PUT DATA`
    /// whose effect is unknown. An interruption while merely idling between
    /// read-only steps leaves the position alone (design.md §5.2 rule 1 forbids
    /// blind retries, not resumption of reads).
    public func noteInterruption() {
        guard let inFlight = mutatingStepInFlight else { return }
        report.warnings.append(
            "Session interrupted during \(inFlight.title). The card state is unknown; re-inspect the YubiKey before continuing."
        )
        mutatingStepInFlight = nil
        step = .cardInventory
    }

    /// Marks a mutating card operation as in flight; cleared only on success, so
    /// a throw leaves it pending for `noteInterruption()`.
    private func withMutatingStep<T>(_ step: CeremonyStep, _ body: () async throws -> T) async throws -> T {
        mutatingStepInFlight = step
        let result = try await body()
        mutatingStepInFlight = nil
        return result
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
        advance(to: .cardInventory)
    }

    // MARK: Step 2 — card inventory

    /// Informational: reads the card and records warnings. Deliberately does NOT
    /// refuse a used YubiKey, because re-provisioning one is a normal workflow —
    /// the destructive gate lives on the reset step, which is where key material
    /// is actually erased.
    public func inspectCard() async throws -> CardInventory {
        try requireCurrent(.cardInventory)
        let result = try await card.inventory()
        inventory = result
        report.cardSerial = result.serial
        report.cardOpenPGPVersion = result.openPGPVersion
        cardHeldExistingKey = !result.occupiedSlots.isEmpty
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

    private func describe(_ inventory: CardInventory) -> String {
        var parts: [String] = []
        for slot in KeySlot.allCases where inventory.holdsKey(in: slot) {
            parts.append("\(slot.displayName.lowercased()) occupied")
        }
        if let counter = inventory.signatureCounter { parts.append("counter \(counter)") }
        if let attributes = inventory.algorithmAttributes[.signature] {
            parts.append("signature algorithm attributes \(attributes.hexString)")
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
    public func resetCard(adminPIN: [UInt8], acknowledgingDestruction: Bool = false) async throws {
        try requireCurrent(.reset)
        if cardHeldExistingKey, !acknowledgingDestruction {
            throw CeremonyError.destructiveResetNotAcknowledged
        }
        try await withMutatingStep(.reset) {
            try await card.reset(adminPIN: adminPIN)
        }
        // Re-inventory after a destructive operation: never trust that the card
        // is in the expected state just because the APDU returned 9000.
        let after = try await card.inventory()
        inventory = after
        report.cardSerial = after.serial ?? report.cardSerial
        advance(to: .pinProvisioning)
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
        advance(to: .policy)
    }

    // MARK: Step 5 — policy

    public func applyPolicy() async throws {
        try requireCurrent(.policy)
        guard let adminPIN = sessionAdminPIN else { throw CeremonyError.missingAdminPIN }
        var pin = adminPIN.materializedCopy()
        defer { VaultKit.wipe(&pin) }
        try await withMutatingStep(.policy) {
            try await card.applyPolicy(adminPIN: pin)
        }
        let after = try await card.inventory()
        inventory = after
        if let status = after.pwStatusBytes, let first = status.first, first != 0x00 {
            report.warnings.append(
                "PW1 status reads 0x\(String(format: "%02x", first)) instead of 0x00; the card may not require the PIN for every signature."
            )
        }
        advance(to: .entropy)
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

    // MARK: Step 9 — import

    /// Writes both keys: secp256k1 into the signature slot, Ed25519 into the
    /// authentication slot. Each write re-verifies the Admin PIN in its own
    /// session (see `SignerCard.importKey`).
    public func importKeys(creationTime: Date? = nil) async throws {
        try requireCurrent(.keyImport)
        guard let keys = derivedKeys else { throw CeremonyError.keysNotDerived }
        guard let adminPIN = sessionAdminPIN else { throw CeremonyError.missingAdminPIN }

        var pin = adminPIN.materializedCopy()
        defer { VaultKit.wipe(&pin) }
        let timestamp = creationTime ?? clock()

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
        advance(to: .readBackCheck)
    }

    // MARK: Step 10 — read-back (mandatory, design.md §4.2 step 7)

    /// Reads both public keys back and compares them with the derived ones. A
    /// mismatch on **either** key voids the entire procedure: everything is
    /// wiped and the operator is sent back to the card inspection step.
    @discardableResult
    public func verifyReadBack() async throws -> [KeyAlgorithm: ReadBackResult] {
        try requireCurrent(.readBackCheck)
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
        // Deliberately does NOT advance: the read-back comparison is the whole
        // point of this step and must be seen.
        return results
    }

    // MARK: Step 11 — pairing export

    /// Builds **two** URs, one per algorithm, for the desktop wallet to scan.
    /// `policy` decides whether a chain code is advertised; see `PairingPolicy`
    /// for why the default omits it.
    @discardableResult
    public func buildPairingURs(style: URTypeStyle, policy: PairingPolicy = .singleKeyOnly) throws -> [KeyAlgorithm: UR] {
        try requireCurrent(.pairingExport)
        guard let keys = derivedKeys else { throw CeremonyError.keysNotDerived }
        if case .includeChainCode(let acknowledged) = policy, !acknowledged {
            throw CeremonyError.pairingPolicyNotAcknowledged
        }
        let includeChainCode = policy.includesChainCode

        var urs: [KeyAlgorithm: UR] = [:]
        for summary in keys.all {
            let origin = URKeyPath(
                path: summary.path,
                sourceFingerprint: UInt32(summary.masterFingerprintHex.prefix(8), radix: 16) ?? 0
            )
            let key = HDKey(
                keyData: summary.publicKey,
                chainCode: includeChainCode ? chainCodes[summary.algorithm] : nil,
                useInfo: CoinInfo(type: summary.algorithm.slip44CoinType, network: 0),
                origin: origin,
                parentFingerprint: UInt32(summary.parentFingerprintHex.prefix(8), radix: 16)
            )
            let ur = try key.ur(style: style)
            urs[summary.algorithm] = ur
            if let index = report.keys.firstIndex(where: { $0.algorithm == summary.algorithm.rawValue }) {
                report.keys[index].pairingURType = ur.type
                report.keys[index].pairingIncludedChainCode = includeChainCode
            }
        }
        pairingURs = urs
        if let warning = policy.warning { report.warnings.append(warning) }
        // Deliberately does NOT advance: the operator must scan the codes and
        // confirm the wallet shows the same addresses first.
        return urs
    }

    public var pairingURStrings: [KeyAlgorithm: String] {
        pairingURs.mapValues(\.string)
    }

    // MARK: Step 12 — counter baseline (design.md §4.2 step 9)

    @discardableResult
    public func readCounterBaseline() async throws -> UInt32 {
        try requireCurrent(.counterBaseline)
        let counter = try await card.signatureCounter()
        report.counterBaseline = counter
        report.warnings.append(
            "The Ed25519 key sits in the authentication slot, which has no hardware signature counter; the counter audit covers the secp256k1 key only."
        )
        guard counter == 0 else { throw CeremonyError.counterNotZero(counter) }
        // Deliberately does NOT advance: a non-zero counter is a stop condition
        // and the operator must record the value either way.
        return counter
    }

    // MARK: Step 13 — teardown

    /// Wipes all secrets and returns the final report. An app restart is
    /// required before another ceremony (enforced by the UI, which is what
    /// `hasFinished` is for).
    @discardableResult
    public func finish() -> CeremonyReport {
        report.completedAt = clock()
        let finished = report
        wipe()
        step = .teardown
        return finished
    }

    public var isFinished: Bool { step == .teardown && report.completedAt != nil }

    /// Wipes every secret in this object. Idempotent.
    ///
    /// `derivedKeys` holds only public data, but it is cleared too: after a void
    /// procedure or an abort, no stale "paired account" may remain visible.
    public func wipe() {
        entropy?.zeroize(); entropy = nil
        seed?.zeroize(); seed = nil
        for (_, key) in privateKeys { key.zeroize() }
        privateKeys = [:]
        chainCodes = [:]
        sessionAdminPIN?.zeroize(); sessionAdminPIN = nil
        for index in mnemonicWords.indices { mnemonicWords[index] = "" }
        mnemonicWords = []
        mnemonicConfirmed = false
        pairingURs = [:]
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
