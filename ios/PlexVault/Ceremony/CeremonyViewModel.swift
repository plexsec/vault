import Foundation
import YubikeyKit
#if canImport(CoreNFC)
import YubikeyKitNFC
#endif
#if canImport(CryptoTokenKit)
import YubikeyKitCCID
#endif
import VaultKit

/// The app's single source of truth for a provisioning run.
///
/// Responsibilities kept deliberately narrow:
/// * owns the ceremony object and its secret lifetime,
/// * translates user intent into ceremony calls in the mandated order,
/// * surfaces typed errors as operator-readable text,
/// * holds no secret longer than the step that needs it.
///
/// It performs no cryptography and makes no policy decisions: every gate lives in
/// `ProvisioningCeremony`, so a UI bug cannot skip verification.
///
/// One run provisions **two** keys — secp256k1 and Ed25519 — from a single
/// mnemonic, so the derived-key, read-back and pairing state is keyed by
/// algorithm rather than being a single value.
@MainActor
@Observable
public final class CeremonyViewModel {

    /// Which transport the ceremony reaches the card over. Shared with the
    /// signing flow, which reaches the same card the same way.
    public typealias TransportChoice = CardTransportChoice


    public enum Phase: Equatable {
        case setup
        case running
        case finished
    }

    // MARK: Selection state

    public var transportChoice: TransportChoice = .nfc
    public var mode: CeremonyMode = .freshGeneration

    // MARK: Ceremony state

    public private(set) var phase: Phase = .setup
    public private(set) var step: CeremonyStep = .notStarted
    public private(set) var busy = false
    public private(set) var errorMessage: String?
    public private(set) var sessionActive = false

    public private(set) var inventory: CardInventory?
    public private(set) var entropyCommitment: String?
    public private(set) var mnemonic: [String] = []
    public private(set) var transcriptionChallenge: [Int] = []
    public private(set) var derivedKeys: DerivedKeys?
    public private(set) var readBack: [KeyAlgorithm: ReadBackResult] = [:]
    /// Whether the pairing manifest reached the card. `nil` before the step ran.
    public private(set) var pairingManifestStored: Bool?
    /// Why it did not, when it did not.
    public private(set) var pairingManifestNote: String?
    /// Re-pair only: the key records the card's stored manifest describes, once it
    /// has been checked against the card. Empty means the step has not run.
    public private(set) var repairedKeys: [KeyAlgorithm: KeyRecord] = [:]
    /// Re-pair only: the serial the manifest was read from, for the screen.
    public private(set) var repairedFromSerial: String?
    public private(set) var pairingURStrings: [KeyAlgorithm: String] = [:]
    public private(set) var counterBaseline: UInt32?
    public private(set) var report: CeremonyReport?

    // MARK: Form state

    public var postureConfirmed = false
    public var acknowledgeDestructiveReset = false
    public var userPIN = ""
    public var userPINConfirmation = ""
    public var adminPIN = ""
    public var adminPINConfirmation = ""
    public var diceRolls: [Int] = []
    public var backfillEntries: [Int: String] = [:]
    public var restoreWords = ""
    public var pairingStyle: URTypeStyle = .keystoneLegacy
    /// Mandatory acknowledgement of `PairingPolicy.chainCodeWarning`. The pairing
    /// UR always carries a chain code, so this gates `buildPairingURs`.
    public var acknowledgeChainCodeWarning = false
    public var pairingAddressConfirmed = false

    /// The mnemonic is hidden by default and revealed deliberately, then hidden
    /// again after `revealWindowSeconds`. Holding a finger on the screen while
    /// writing 24 words onto a steel plate is not physically possible, so
    /// hold-to-reveal was the wrong affordance; a bounded reveal window keeps the
    /// exposure short without making the screen unusable.
    public private(set) var mnemonicRevealed = false
    public private(set) var revealSecondsRemaining = 0
    public static let revealWindowSeconds = 60
    private var revealTimer: Timer?
    /// True while the screen is being mirrored or recorded. The mnemonic is
    /// hidden in that case: a screen capture of the words defeats the whole
    /// ceremony.
    public var screenIsCaptured = false {
        didSet {
            // A capture starting mid-reveal hides the words immediately.
            if screenIsCaptured { hideMnemonic() }
        }
    }

    private var ceremony: ProvisioningCeremony?

    public init() {}

    // MARK: Derived view state

    public var cardInventorySummary: [(String, String)] {
        guard let inventory else { return [] }
        var rows: [(String, String)] = [("OpenPGP applet", inventory.openPGPVersion)]
        if let manufacturer = inventory.manufacturer { rows.append(("Manufacturer", manufacturer)) }
        if let serial = inventory.serial { rows.append(("Serial", serial)) }
        if let counter = inventory.signatureCounter { rows.append(("Signature counter", "\(counter)")) }
        for slot in KeySlot.allCases {
            if let attributes = inventory.algorithmAttributes[slot] {
                rows.append(("\(slot.displayName) algorithm", attributes.hexString))
            }
            rows.append(("\(slot.displayName) key present", inventory.holdsKey(in: slot) ? "yes" : "no"))
        }
        rows.append(("Factory fresh", inventory.isFactoryFresh ? "yes" : "no"))
        return rows
    }

    /// True when the card holds a key in either signing-capable slot, which is
    /// what the destructive reset gate keys off.
    public var cardHoldsAnyKey: Bool {
        guard let inventory else { return false }
        return KeySlot.allCases.contains { inventory.holdsKey(in: $0) }
    }

    /// True when the card's OpenPGP applet is definitively below the minimum
    /// (3.4 / firmware 5.2.3), which cannot be provisioned.
    public var isUnsupportedApplet: Bool {
        inventory?.isDefinitelyUnsupported == true
    }

    public var allReadBacksSucceeded: Bool {
        KeyAlgorithm.allCases.allSatisfy { readBack[$0]?.matches == true }
    }

    public var pairingPrepared: Bool { !pairingURStrings.isEmpty }

    /// The record's entry for one algorithm.
    ///
    /// Both routes populate the record: provisioning from the derivation, re-pair
    /// from the card and the manifest on it. The pairing screen renders from here
    /// rather than from `derivedKeys` — which exists only when a mnemonic was
    /// entered, so a re-pair used to reach the pairing step with no QR code and no
    /// addresses on it.
    public func keyRecord(for algorithm: KeyAlgorithm) -> KeyRecord? {
        report?.keys.first { $0.algorithm == algorithm.rawValue }
    }

    /// True when the exported pairing key is an ancestor of the card's leaf
    /// (the secp256k1 account-level export).
    public func pairingAccountLevel(for algorithm: KeyAlgorithm) -> Bool {
        ceremony?.pairingExports[algorithm]?.isAccountLevel ?? false
    }

    // MARK: Lifecycle

    public func start() {
        guard phase == .setup else { return }
        errorMessage = nil
        // A ceremony never inherits another one's results, whatever route the
        // operator took out of the last one.
        resetTransientState()
        let card = TransportSessionCard(
            makeTransport: { [transportChoice] in Self.makeTransport(transportChoice) },
            onSessionStart: { [weak self] _ in
                Task { @MainActor in self?.sessionActive = true }
            },
            onSessionEnd: { [weak self] in
                Task { @MainActor in self?.sessionActive = false }
            }
        )
        let ceremony = ProvisioningCeremony(
            card: card,
            systemRandom: Self.systemRandom(),
            transportDescription: transportChoice.title,
            appVersion: BuildInfo.summary
        )
        self.ceremony = ceremony
        phase = .running
        do {
            try ceremony.begin(mode: mode, postureConfirmed: postureConfirmed)
            step = ceremony.step
            report = ceremony.report
        } catch {
            fail(error)
        }
    }

    /// Called when the app leaves the foreground. Marks a session interruption so
    /// a mutating step that was in flight forces a card re-inspection, and hides
    /// the mnemonic.
    public func applicationDidBackground() {
        hideMnemonic()
        ceremony?.noteInterruption()
        step = ceremony?.step ?? step
    }

    public func abort() {
        ceremony?.abort()
        ceremony = nil
        resetTransientState()
        phase = .setup
        step = .notStarted
    }

    private func resetTransientState() {
        // Everything a ceremony produces is cleared here, not just the secrets.
        // Leaving any of it behind is a correctness bug rather than a cosmetic one:
        // the screens decide what to show from these values, so a second ceremony
        // used to open on the *previous* card's inventory (offering "Continue" where
        // it should have asked for a card read) and to show the previous ceremony's
        // pairing codes, which may describe keys that are no longer on the card.
        inventory = nil
        report = nil
        entropyCommitment = nil
        mnemonic = []
        transcriptionChallenge = []
        derivedKeys = nil
        readBack = [:]
        pairingManifestStored = nil
        pairingManifestNote = nil
        repairedKeys = [:]
        repairedFromSerial = nil
        pairingURStrings = [:]
        counterBaseline = nil

        // Form state, including the gates: a stale acknowledgement would let a new
        // ceremony past a step the operator never saw this time.
        acknowledgeDestructiveReset = false
        userPIN = ""
        userPINConfirmation = ""
        adminPIN = ""
        adminPINConfirmation = ""
        backfillEntries = [:]
        restoreWords = ""
        diceRolls = []
        acknowledgeChainCodeWarning = false
        pairingAddressConfirmed = false
        mnemonicRevealed = false
        revealTimer?.invalidate()
        revealTimer = nil
        revealSecondsRemaining = 0
    }

    // MARK: Step actions

    public func inspectCard() async {
        await run { ceremony in
            self.inventory = try await ceremony.inspectCard()
            self.acknowledgeDestructiveReset = false
        }
    }

    public func resetCard() async {
        await run { ceremony in
            // No Admin PIN: the ceremony's reset blocks both PINs and terminates
            // the applet, which is what `ykman openpgp reset` does (amendment 30).
            try await ceremony.resetCard(
                acknowledgingDestruction: self.acknowledgeDestructiveReset
            )
        }
    }

    public func provisionPINs() async {
        await run { ceremony in
            guard self.userPIN == self.userPINConfirmation else {
                throw CeremonyError.invalidPINPolicy("The two User PIN entries do not match.")
            }
            guard self.adminPIN == self.adminPINConfirmation else {
                throw CeremonyError.invalidPINPolicy("The two Admin PIN entries do not match.")
            }
            guard let user = Self.pinBytes(self.userPIN), let admin = Self.pinBytes(self.adminPIN) else {
                throw CeremonyError.invalidPINPolicy("PINs must be digits only.")
            }
            try await ceremony.setPINs(userPIN: user, adminPIN: admin)
            self.userPIN = ""
            self.userPINConfirmation = ""
            self.adminPIN = ""
            self.adminPINConfirmation = ""
        }
    }

    /// The operator-chosen retry limit, defaulting to the card's factory value.
    public var pinRetryLimit: Int = CardPolicy.defaultRetryLimit

    public func setPINRetryLimits() async {
        await run { ceremony in
            try await ceremony.setPINRetries(self.pinRetryLimit)
        }
    }

    public func applyPolicy() async {
        await run { ceremony in
            try await ceremony.applyPolicy()
        }
    }

    /// Generates entropy from the YubiKey's hardware RNG. The commitment stays on
    /// screen until the operator has written it down and calls `advance()`.
    public func generateEntropy() async {
        await run { ceremony in
            self.entropyCommitment = try await ceremony.generateEntropy()
        }
    }

    /// Completes the current step. Steps that produce output call this only once
    /// the operator has read that output, which is what keeps the entropy
    /// commitment, the derived addresses, the read-back results, the pairing codes
    /// and the counter on screen.
    public func advance() {
        guard let ceremony else { return }
        errorMessage = nil
        do {
            try ceremony.advance()
            step = ceremony.step
            report = ceremony.report
            syncStepOutputs()
        } catch {
            fail(error)
        }
    }

    /// Records the operator's comparison of the wallet's addresses with the ones
    /// the ceremony shows. Required before the pairing step can complete.
    public func setPairingAddressConfirmed(_ confirmed: Bool) {
        pairingAddressConfirmed = confirmed
        ceremony?.confirmPairingAddressMatches(confirmed)
    }

    /// Pulls in output that only exists once a step has been completed — chiefly
    /// the mnemonic, which is derived when the entropy step completes.
    private func syncStepOutputs() {
        guard let ceremony else { return }
        if step == .mnemonic {
            mnemonic = (try? ceremony.mnemonicForDisplay()) ?? []
            transcriptionChallenge = (try? ceremony.transcriptionChallenge()) ?? []
            backfillEntries = [:]
            hideMnemonic()
        }
    }

    // MARK: Mnemonic reveal

    public func revealMnemonic() {
        // Never reveal while the screen is mirrored or recorded.
        guard !screenIsCaptured, !mnemonic.isEmpty else { return }
        mnemonicRevealed = true
        startRevealCountdown()
    }

    public func hideMnemonic() {
        revealTimer?.invalidate()
        revealTimer = nil
        mnemonicRevealed = false
        revealSecondsRemaining = 0
    }

    private func startRevealCountdown() {
        revealTimer?.invalidate()
        revealSecondsRemaining = Self.revealWindowSeconds
        revealTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                if self.revealSecondsRemaining <= 1 {
                    self.hideMnemonic()
                } else {
                    self.revealSecondsRemaining -= 1
                }
            }
        }
    }

    public func recordDiceRoll(_ value: Int) {
        diceRolls.append(value)
        runSync { ceremony in
            try ceremony.recordDiceRolls(self.diceRolls)
        }
    }

    public func restoreMnemonic() {
        runSync { ceremony in
            let words = self.restoreWords
                .split(whereSeparator: { $0.isWhitespace || $0 == "," })
                .map { String($0).lowercased() }
            try ceremony.restoreMnemonic(words: words)
            self.step = ceremony.step
            self.mnemonic = try ceremony.mnemonicForDisplay()
            self.transcriptionChallenge = try ceremony.transcriptionChallenge()
            self.restoreWords = ""
            self.backfillEntries = [:]
            self.hideMnemonic()
        }
    }

    public func confirmTranscription() {
        runSync { ceremony in
            let entries = self.transcriptionChallenge.map { index in
                (index: index, word: self.backfillEntries[index] ?? "")
            }
            try ceremony.confirmTranscription(entries: entries)
            self.backfillEntries = [:]
        }
    }

    public func deriveKeys() {
        runSync { ceremony in
            self.derivedKeys = try ceremony.deriveKeys()
        }
    }

    public func importKeys() async {
        await run { ceremony in
            try await ceremony.importKeys()
        }
    }

    public func verifyReadBack() async {
        await run { ceremony in
            self.readBack = try await ceremony.verifyReadBack()
        }
    }

    /// Writes the pairing manifest into the card and reads it straight back.
    /// Non-fatal by design: the keys are already verified when this runs, so a
    /// card that cannot store a manifest costs a later re-pair (with the
    /// mnemonic), not the ceremony.
    public func writePairingManifest() async {
        await run { ceremony in
            _ = try await ceremony.writePairingManifest()
            self.pairingManifestStored = ceremony.pairingManifestOutcome?.isStored
            self.pairingManifestNote = ceremony.pairingManifestOutcome.flatMap { outcome in
                if case .declined(let reason) = outcome { return reason }
                return nil
            }
        }
    }

    /// Reads the pairing manifest off the card, checks it, and records what it
    /// describes. Read-only: no PIN is requested and none can be used.
    public func readPairingManifest() async {
        await run { ceremony in
            _ = try await ceremony.readPairingManifestFromCard()
            self.repairedKeys = Dictionary(
                uniqueKeysWithValues: ceremony.report.keys.compactMap { record in
                    record.keyAlgorithm.map { ($0, record) }
                }
            )
            self.repairedFromSerial = ceremony.report.cardSerial
        }
    }

    public func buildPairingURs() {
        runSync { ceremony in
            let urs = try ceremony.buildPairingURs(
                style: self.pairingStyle,
                chainCodeAcknowledged: self.acknowledgeChainCodeWarning
            )
            self.pairingURStrings = urs.mapValues(\.string)
        }
    }

    public func readCounterBaseline() async {
        await run { ceremony in
            self.counterBaseline = try await ceremony.readCounterBaseline()
        }
    }

    public func finish() {
        guard let ceremony else { return }
        report = ceremony.finish()
        step = ceremony.step
        phase = .finished
        hideMnemonic()
        mnemonic = []
    }

    // MARK: Helpers

    private static func pinBytes(_ string: String) -> [UInt8]? {
        let digits = string.trimmingCharacters(in: .whitespaces)
        guard !digits.isEmpty, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return Array(digits.utf8)
    }

    private func run(_ body: @escaping (ProvisioningCeremony) async throws -> Void) async {
        guard let ceremony else { return }
        busy = true
        errorMessage = nil
        do {
            try await body(ceremony)
            step = ceremony.step
            report = ceremony.report
        } catch {
            // A failed step may have left a mutating operation half-done. The
            // ceremony decides whether that is the case (`noteInterruption` is a
            // no-op unless a mutating step was in flight and its outcome is
            // unknown); without this, the operator is left on the same screen
            // with the gate still armed, which invites the blind retry
            // design.md §5.2 rule 1 forbids.
            ceremony.noteInterruption()
            step = ceremony.step
            report = ceremony.report
            fail(error)
        }
        busy = false
    }

    private func runSync(_ body: (ProvisioningCeremony) throws -> Void) {
        guard let ceremony else { return }
        errorMessage = nil
        do {
            try body(ceremony)
            step = ceremony.step
            report = ceremony.report
        } catch {
            ceremony.noteInterruption()
            step = ceremony.step
            report = ceremony.report
            fail(error)
        }
    }

    private func fail(_ error: Error) {
        errorMessage = Self.describe(error)
        // A voided procedure wipes the ceremony's secrets; keep the UI consistent.
        if ceremony?.derivedKeys == nil {
            derivedKeys = nil
            readBack = [:]
        }
    }

    public static func describe(_ error: Error) -> String {
        switch error {
        case let card as CardError: return card.userFacingDescription
        case let ceremony as CeremonyError: return ceremony.userFacingDescription
        case let bip39 as BIP39Error:
            switch bip39 {
            case .invalidChecksum: return "The mnemonic checksum is invalid. Check the words and their order."
            case .unknownWord(let word): return "\"\(word)\" is not in the BIP39 English wordlist."
            case .invalidWordCount(let count): return "A mnemonic has 12, 15, 18, 21 or 24 words; this one has \(count)."
            case .invalidEntropyLength(let count): return "Unsupported entropy length: \(count) bytes."
            case .seedDerivationFailed: return "Seed derivation failed."
            }
        case let bip32 as BIP32Error:
            switch bip32 {
            case .invalidSeedLength(let count): return "Invalid seed length: \(count) bytes."
            default: return "Key derivation failed: \(bip32)."
            }
        case let slip10 as SLIP0010Error:
            switch slip10 {
            case .invalidSeedLength(let count): return "Invalid seed length: \(count) bytes."
            case .nonHardenedIndex(let index):
                return "Ed25519 derivation path component \(index) is not hardened, which SLIP-0010 forbids."
            case .depthExceeded: return "Ed25519 derivation path is too deep."
            }
        case let path as DerivationPath.ParseError:
            return "Invalid derivation path: \(path)."
        default:
            return error.localizedDescription
        }
    }

    /// System-entropy source mixed with the card's hardware RNG.
    ///
    /// In production this is `SecRandomCopyBytes`. DEBUG builds honour
    /// `-deterministic-entropy <64 hex chars>` by forcing the system side to
    /// all-zero, so the XOR result equals the card's `challengeBytes` (which the
    /// simulated card also seeds from the same flag) and the ceremony produces a
    /// known mnemonic. The hook does not exist in Release.
    private static func systemRandom() -> (Int) throws -> SensitiveBytes {
        #if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("-deterministic-entropy") {
            return { count in SensitiveBytes(count: count) }
        }
        #endif
        return SystemCSPRNG.randomBytes
    }

    private static func makeTransport(_ choice: TransportChoice) -> YubikeyTransport {
        CardTransports.make(choice)
    }
}
