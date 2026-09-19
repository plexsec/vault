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

    /// Transport options. The `simulated` case exists **only** in DEBUG builds:
    /// a release binary has no code path that can reach a simulated card, which
    /// `tools/audit-release.sh` verifies against the built product.
    public enum TransportChoice: String, CaseIterable, Identifiable {
        case nfc
        case usbC
        #if DEBUG
        case simulated
        #endif

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .nfc: return "NFC"
            case .usbC: return "USB-C"
            #if DEBUG
            case .simulated: return "Simulated (debug)"
            #endif
            }
        }

        public var detail: String {
            switch self {
            case .nfc: return "Hold the iPhone against the YubiKey when prompted. Every step asks for a fresh tap."
            case .usbC: return "Plug the YubiKey into the USB-C port and leave it in. Requires iPhone 15 or later."
            #if DEBUG
            case .simulated: return "No YubiKey required. Runs against a simulated card; never use this for a real key."
            #endif
            }
        }
    }

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
    public private(set) var pairingURStrings: [KeyAlgorithm: String] = [:]
    public private(set) var counterBaseline: UInt32?
    public private(set) var report: CeremonyReport?

    // MARK: Form state

    public var postureConfirmed = false
    public var resetAdminPIN = ""
    public var acknowledgeDestructiveReset = false
    public var userPIN = ""
    public var userPINConfirmation = ""
    public var adminPIN = ""
    public var adminPINConfirmation = ""
    public var diceRolls: [Int] = []
    public var backfillEntries: [Int: String] = [:]
    public var restoreWords = ""
    public var pairingStyle: URTypeStyle = .keystoneLegacy
    public var pairingIncludesChainCode = false
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

    public var allReadBacksSucceeded: Bool {
        KeyAlgorithm.allCases.allSatisfy { readBack[$0]?.matches == true }
    }

    public var pairingPrepared: Bool { !pairingURStrings.isEmpty }

    // MARK: Lifecycle

    public func start() {
        guard phase == .setup else { return }
        errorMessage = nil
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
            entropySource: Self.entropySource(),
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
        mnemonic = []
        derivedKeys = nil
        readBack = [:]
        pairingURStrings = [:]
        counterBaseline = nil
        entropyCommitment = nil
        backfillEntries = [:]
        mnemonicRevealed = false
        userPIN = ""
        userPINConfirmation = ""
        adminPIN = ""
        adminPINConfirmation = ""
        resetAdminPIN = ""
        restoreWords = ""
        diceRolls = []
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
            guard let pin = Self.pinBytes(self.resetAdminPIN) else {
                throw CeremonyError.invalidPINPolicy("Enter the Admin PIN (8 digits for a factory-reset key).")
            }
            try await ceremony.resetCard(
                adminPIN: pin,
                acknowledgingDestruction: self.acknowledgeDestructiveReset
            )
            self.resetAdminPIN = ""
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

    public func applyPolicy() async {
        await run { ceremony in
            try await ceremony.applyPolicy()
        }
    }

    /// Generates entropy. The commitment stays on screen until the operator has
    /// written it down and calls `advance()`.
    public func generateEntropy() {
        runSync { ceremony in
            self.entropyCommitment = try ceremony.generateEntropy()
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

    public func buildPairingURs() {
        runSync { ceremony in
            let policy: PairingPolicy = self.pairingIncludesChainCode
                ? .includeChainCode(acknowledgedUnsignableChildren: self.acknowledgeChainCodeWarning)
                : .singleKeyOnly
            let urs = try ceremony.buildPairingURs(style: self.pairingStyle, policy: policy)
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

    /// Entropy source for the ceremony.
    ///
    /// DEBUG builds honour `-deterministic-entropy <64 hex chars>` so a UI test can
    /// drive the whole ceremony, including the transcription back-fill, which is
    /// impossible with random words. Release builds always use the system CSPRNG:
    /// this hook does not exist there, and `tools/audit-release.sh` checks for its
    /// marker string in the shipped binary.
    private static func entropySource() -> EntropySource {
        #if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "-deterministic-entropy"),
           index + 1 < arguments.count,
           let bytes = try? Hex.decode(arguments[index + 1]),
           bytes.count == BIP39.entropyByteCount {
            return ScriptedEntropySource(bytes: bytes)
        }
        #endif
        return SystemEntropySource()
    }

    private static func makeTransport(_ choice: TransportChoice) -> YubikeyTransport {
        switch choice {
        case .nfc:
            #if canImport(CoreNFC)
            return NFCTagTransport()
            #else
            return UnavailableTransport(reason: "NFC is unavailable in this build.")
            #endif
        case .usbC:
            #if canImport(CryptoTokenKit)
            return SmartCardTransport()
            #else
            return UnavailableTransport(reason: "USB-C smart-card access is unavailable in this build.")
            #endif
        #if DEBUG
        case .simulated:
            return SimulatedCardTransport()
        #endif
        }
    }
}

/// Placeholder used when a transport is compiled out or unavailable, so the
/// failure is an explicit typed error rather than a crash.
public final class UnavailableTransport: YubikeyTransport {
    public let transportName = "unavailable"
    private let reason: String

    public init(reason: String) {
        self.reason = reason
    }

    public func open() async throws { throw CardError.transportUnavailable(reason) }
    public func send(_ command: CommandAPDU) async throws -> ResponseAPDU {
        throw CardError.transportUnavailable(reason)
    }
    public func close() async {}
}
