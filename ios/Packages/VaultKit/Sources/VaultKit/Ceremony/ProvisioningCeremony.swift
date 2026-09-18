import Foundation

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
    public var chain: SigningChain?
    public var derivationPath: String?
    public var address: String?
    /// BIP32 fingerprint of the imported key (first 4 bytes of HASH160(pubkey)).
    public var publicKeyFingerprintHex: String?
    public var publicKeyHex: String?
    public var cardSerial: String?
    public var cardOpenPGPVersion: String?
    public var counterBaseline: UInt32?
    public var readBackVerified: Bool = false
    public var independentCheck: IndependentCheck?
    /// True when the exported UR carried a chain code (see `PairingPolicy`).
    public var pairingIncludedChainCode: Bool = false
    public var pairingURType: String?
    public var warnings: [String] = []

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
        if let chain { lines.append("chain: \(chain.displayName)") }
        if let derivationPath { lines.append("path: \(derivationPath)") }
        if let address { lines.append("address: \(address)") }
        if let publicKeyHex { lines.append("public key (compressed): \(publicKeyHex)") }
        if let publicKeyFingerprintHex { lines.append("key fingerprint: \(publicKeyFingerprintHex)") }
        if let cardSerial { lines.append("yubikey serial: \(cardSerial)") }
        if let cardOpenPGPVersion { lines.append("openpgp applet: \(cardOpenPGPVersion)") }
        if let counterBaseline { lines.append("signature counter baseline: \(counterBaseline)") }
        lines.append("read-back verified: \(readBackVerified ? "yes" : "no")")
        if let independentCheck {
            lines.append("independent check: \(independentCheck.matched ? "MATCH" : "MISMATCH") via \(independentCheck.source)")
            lines.append("independent address: \(independentCheck.expectedAddress)")
        }
        if let pairingURType { lines.append("pairing UR type: \(pairingURType)") }
        for warning in warnings { lines.append("warning: \(warning)") }
        return lines
    }

    private static let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}

public struct IndependentCheck: Equatable, Codable, Sendable {
    public var expectedAddress: String
    public var source: String
    public var matched: Bool
    public var checkedAt: Date
}

/// Policy for what the pairing UR is allowed to advertise.
///
/// One YubiKey slot holds exactly one key (design.md §4.3), so the address-level
/// key has no signable children. Exporting a chain code lets a wallet derive
/// further addresses the card *cannot sign for* — it would offer accounts that
/// fail at signing time. The default is therefore to omit the chain code and
/// publish only the single address-level key; including it requires an explicit
/// acknowledgement.
public enum PairingPolicy: Equatable, Sendable {
    /// Single address-level key, no chain code. Safe default.
    case singleKeyOnly
    /// Address-level key *with* chain code, so wallets that require one accept
    /// the pairing. `acknowledgedUnsignableChildren` must be true.
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

/// Public summary of the derived key handed to the UI (never the private key).
public struct DerivedKeySummary: Equatable, Sendable {
    public let chain: SigningChain
    public let path: DerivationPath
    public let address: String
    public let publicKeyCompressed: [UInt8]
    public let fingerprintHex: String
    public let parentFingerprintHex: String
    public let masterFingerprintHex: String

    public var publicKeyHex: String { publicKeyCompressed.hexString }
}

/// Drives design.md §4.2 as an ordered state machine.
///
/// Hard gates are enforced here rather than in the UI: every mutating entry
/// point checks that it is the next expected step, so a compromised or buggy
/// view layer cannot skip the read-back check or sign the pairing QR before the
/// independent cross-check has run.
///
/// Secret lifetime: entropy, seed, private key and mnemonic words live only in
/// this object and are wiped by `wipe()`, by `finish()`, and by `abort()`. An
/// interrupted ceremony is resumed by re-entering the mnemonic (restore mode) —
/// no secret is ever persisted, so there is nothing on disk to steal.
public final class ProvisioningCeremony {

    // MARK: Inputs

    private let card: SignerCard
    private let entropySource: EntropySource
    private let clock: () -> Date
    private let appVersion: String

    // MARK: Observable state

    public private(set) var mode: CeremonyMode
    public private(set) var step: CeremonyStep = .notStarted
    public private(set) var transportDescription: String
    public private(set) var inventory: CardInventory?
    public private(set) var report: CeremonyReport
    public private(set) var derivedKey: DerivedKeySummary?

    // MARK: Secrets (wiped on every exit path)

    private var entropy: SensitiveBytes?
    private var mnemonicWords: [String] = []
    private var seed: SensitiveBytes?
    private var privateKey: SensitiveBytes?
    private var chainCode: [UInt8]?
    private var pendingDiceRolls: [Int] = []
    private var mnemonicConfirmed = false
    private var cardHeldExistingKey = false
    private var mutatingStepInFlight: CeremonyStep?
    /// Held only between the PIN step and the policy step so that PUT DATA of the
    /// protected policy objects can authenticate. Wiped with everything else.
    private var sessionAdminPIN: SensitiveBytes?
    private var independentCheckResult: IndependentCheck?
    private var pairingUR: UR?

    public init(
        card: SignerCard,
        entropySource: EntropySource = SystemEntropySource(),
        transportDescription: String,
        appVersion: String,
        clock: @escaping () -> Date = Date.init
    ) {
        self.card = card
        self.entropySource = entropySource
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
        cardHeldExistingKey = result.hasSignatureKey
        if !result.isFactoryFresh {
            report.warnings.append("YubiKey was not factory-fresh: \(describe(result)).")
        }
        if !result.likelySupportsSecp256k1 {
            report.warnings.append(
                "OpenPGP applet version \(result.openPGPVersion) may not support secp256k1 (3.4 or newer is required)."
            )
        }
        advance(to: .reset)
        return result
    }

    private func describe(_ inventory: CardInventory) -> String {
        var parts: [String] = []
        if inventory.hasSignatureKey { parts.append("signature key present") }
        if let counter = inventory.signatureCounter { parts.append("counter \(counter)") }
        if let attributes = inventory.algorithmAttributes {
            parts.append("algorithm attributes \(attributes.hexString)")
        }
        return parts.isEmpty ? "unknown state" : parts.joined(separator: ", ")
    }

    // MARK: Step 3 — reset

    /// Destructive: `TERMINATE DF` + `ACTIVATE FILE` erases the existing key on
    /// the signature slot, so a card that already held a key requires an explicit
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
    /// SHA-256(entropy)).
    @discardableResult
    public func generateEntropy() throws -> String {
        try requireCurrent(.entropy)
        guard mode == .freshGeneration else {
            throw CeremonyError.unsupportedRecovery("restore ceremonies do not generate new entropy")
        }
        let generated = try entropySource.randomBytes(count: BIP39.entropyByteCount)
        entropy?.zeroize()
        entropy = generated
        let commitment = Hex.encode(Array(SHA256.hash(generated.materializedCopy()).prefix(4)))
        report.entropyCommitmentHex = commitment
        advance(to: .mnemonic)
        return commitment
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

    public func generateMnemonic() throws -> [String] {
        guard let entropy else { throw CeremonyError.missingEntropy }
        let words = try BIP39.mnemonic(fromEntropy: entropy.materializedCopy())
        installMnemonic(words)
        return words
    }

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

    /// Derives the signing key for `chain` and computes the address.
    ///
    /// Only the public summary is returned; the private key and chain code stay
    /// inside the ceremony object until import completes.
    public func deriveKey(for chain: SigningChain, passphrase: String = "") throws -> DerivedKeySummary {
        try requireCurrent(.derivation)
        guard mnemonicConfirmed else { throw CeremonyError.mnemonicNotConfirmed }
        guard !mnemonicWords.isEmpty else { throw CeremonyError.missingMnemonic }

        if let existing = seed { existing.zeroize() }
        let derivedSeed = try BIP39.seed(mnemonic: mnemonicWords, passphrase: passphrase)
        seed = derivedSeed

        let master = try ExtendedPrivateKey.master(seed: derivedSeed)
        let node = try master.derived(chain.defaultPath)
        let publicKey = try node.publicKey()
        let address = try Self.address(for: chain, publicKey: publicKey)

        if let existing = privateKey { existing.zeroize() }
        privateKey = node.key
        chainCode = node.chainCode

        let summary = DerivedKeySummary(
            chain: chain,
            path: chain.defaultPath,
            address: address,
            publicKeyCompressed: publicKey,
            fingerprintHex: Hex.encode(try node.fingerprint()),
            parentFingerprintHex: Hex.encode(node.parentFingerprint),
            masterFingerprintHex: Hex.encode(try master.fingerprint())
        )
        derivedKey = summary
        report.chain = chain
        report.derivationPath = chain.defaultPath.description
        report.address = address
        report.publicKeyHex = publicKey.hexString
        report.publicKeyFingerprintHex = summary.fingerprintHex
        advance(to: .keyImport)
        return summary
    }

    static func address(for chain: SigningChain, publicKey: [UInt8]) throws -> String {
        switch chain {
        case .ethereum: return try EVMAddress.checksummed(fromPublicKey: publicKey)
        case .bitcoin: return try BitcoinAddress.p2wpkh(publicKeyCompressed: publicKey)
        }
    }

    // MARK: Step 9 — import

    public func importKey(creationTime: Date? = nil) async throws {
        try requireCurrent(.keyImport)
        guard let privateKey, let summary = derivedKey else { throw CeremonyError.keyNotDerived }
        guard let adminPIN = sessionAdminPIN else { throw CeremonyError.missingAdminPIN }
        let fingerprint = Array(try Hex.decode(summary.fingerprintHex))
        var pin = adminPIN.materializedCopy()
        defer { VaultKit.wipe(&pin) }
        try await withMutatingStep(.keyImport) {
            try await card.importSignatureKey(
                privateKey: privateKey,
                fingerprint: fingerprint,
                creationTime: creationTime ?? clock(),
                adminPIN: pin
            )
        }
        advance(to: .readBackCheck)
    }

    // MARK: Step 10 — read-back (mandatory, design.md §4.2 step 7)

    public struct ReadBackResult: Equatable, Sendable {
        public let cardPublicKeyHex: String
        public let derivedPublicKeyHex: String
        public let matches: Bool
        public let addressFromCardKey: String
    }

    @discardableResult
    public func verifyReadBack() async throws -> ReadBackResult {
        try requireCurrent(.readBackCheck)
        guard let summary = derivedKey, let chain = report.chain else { throw CeremonyError.keyNotDerived }

        let cardPublicKey = try await card.readSignaturePublicKey()
        let addressFromCard = try Self.address(for: chain, publicKey: cardPublicKey)
        let matches = cardPublicKey == summary.publicKeyCompressed

        let result = ReadBackResult(
            cardPublicKeyHex: cardPublicKey.hexString,
            derivedPublicKeyHex: summary.publicKeyHex,
            matches: matches,
            addressFromCardKey: addressFromCard
        )
        guard matches else {
            report.readBackVerified = false
            // Hard abort: wipe everything and send the operator back to the reset
            // step. design.md §4.2 step 7: "the entire procedure is void".
            wipe()
            step = .cardInventory
            throw CeremonyError.readBackMismatch(local: summary.publicKeyHex, card: cardPublicKey.hexString)
        }
        report.readBackVerified = true
        advance(to: .independentCheck)
        return result
    }

    // MARK: Step 11 — independent cross-check (mandatory)

    /// `source` names the external tool that produced the address, e.g.
    /// "tools/derive (Python, separate device)". This and the entropy commitment
    /// are the two recorded ceremony assertions.
    @discardableResult
    public func submitIndependentCheck(address: String, source: String) throws -> IndependentCheck {
        try requireCurrent(.independentCheck)
        guard let summary = derivedKey else { throw CeremonyError.keyNotDerived }

        let normalisedExpected: String
        let normalisedActual: String
        switch summary.chain {
        case .ethereum:
            normalisedExpected = EVMAddress.normalisedForComparison(summary.address)
            normalisedActual = EVMAddress.normalisedForComparison(address)
        case .bitcoin:
            normalisedExpected = BitcoinAddress.normalisedForComparison(summary.address)
            normalisedActual = BitcoinAddress.normalisedForComparison(address)
        }

        let check = IndependentCheck(
            expectedAddress: address.trimmingCharacters(in: .whitespacesAndNewlines),
            source: source,
            matched: normalisedExpected == normalisedActual,
            checkedAt: clock()
        )
        independentCheckResult = check
        report.independentCheck = check

        guard check.matched else {
            wipe()
            step = .cardInventory
            throw CeremonyError.independentCheckFailed
        }
        advance(to: .pairingExport)
        return check
    }

    // MARK: Step 12 — pairing export

    /// Builds the UR the desktop wallet scans. `policy` decides whether a chain
    /// code is advertised; see `PairingPolicy` for why the default omits it.
    @discardableResult
    public func buildPairingUR(style: URTypeStyle, policy: PairingPolicy = .singleKeyOnly) throws -> UR {
        try requireCurrent(.pairingExport)
        guard let summary = derivedKey else { throw CeremonyError.keyNotDerived }
        guard independentCheckResult?.matched == true else { throw CeremonyError.independentCheckNotRun }
        if case .includeChainCode(let acknowledged) = policy, !acknowledged {
            throw CeremonyError.pairingPolicyNotAcknowledged
        }

        let useInfo = CoinInfo(type: summary.chain.slip44CoinType, network: 0)
        let origin = URKeyPath(
            path: summary.path,
            sourceFingerprint: UInt32(summary.masterFingerprintHex.prefix(8), radix: 16) ?? 0
        )
        let key = HDKey(
            keyData: summary.publicKeyCompressed,
            chainCode: policy.includesChainCode ? chainCode : nil,
            useInfo: useInfo,
            origin: origin,
            parentFingerprint: UInt32(summary.parentFingerprintHex.prefix(8), radix: 16)
        )
        let ur = try key.ur(style: style)
        pairingUR = ur
        report.pairingIncludedChainCode = policy.includesChainCode
        report.pairingURType = ur.type
        if let warning = policy.warning { report.warnings.append(warning) }
        advance(to: .counterBaseline)
        return ur
    }

    public var pairingURString: String? { pairingUR?.string }

    // MARK: Step 13 — counter baseline (design.md §4.2 step 9)

    @discardableResult
    public func readCounterBaseline() async throws -> UInt32 {
        try requireCurrent(.counterBaseline)
        let counter = try await card.signatureCounter()
        report.counterBaseline = counter
        guard counter == 0 else { throw CeremonyError.counterNotZero(counter) }
        advance(to: .teardown)
        return counter
    }

    // MARK: Step 14 — teardown

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
    /// `derivedKey` holds only public data, but it is cleared too: after a void
    /// procedure or an abort, no stale "paired account" may remain visible.
    public func wipe() {
        entropy?.zeroize(); entropy = nil
        seed?.zeroize(); seed = nil
        privateKey?.zeroize(); privateKey = nil
        sessionAdminPIN?.zeroize(); sessionAdminPIN = nil
        chainCode = nil
        for index in mnemonicWords.indices { mnemonicWords[index] = "" }
        mnemonicWords = []
        mnemonicConfirmed = false
        pairingUR = nil
        derivedKey = nil
        independentCheckResult = nil
    }

    public func abort() {
        if step != .notStarted {
            report.warnings.append("Ceremony aborted at \(step.title).")
        }
        wipe()
        step = .notStarted
    }
}
