import Foundation
import SwiftUI
import VaultKit

/// The app's source of truth for one signing session.
///
/// Narrow on purpose, and the same shape as `CeremonyViewModel`: it owns the
/// ceremony, translates taps into ceremony calls in order, and turns typed errors
/// into text. It performs no cryptography and makes no policy decisions — every
/// gate lives in `SigningCeremony`, so a view bug cannot skip a check.
@MainActor
@Observable
public final class SigningViewModel {
    public enum Phase: Equatable {
        case setup
        case running
        case finished
    }

    /// Which screen of the signing flow is showing. This is presentation only: the
    /// ceremony's own step is the authority, and every action below asks the
    /// ceremony to advance rather than assuming it did.
    public enum Screen: Equatable {
        case readCard
        case scan
        case review
        case pin
        /// Waiting for the card: PIN verified, `PSO:CDS` in flight, touch pending.
        case signing
        case signature
    }

    public var transportChoice: CardTransportChoice = .nfc
    public private(set) var phase: Phase = .setup
    public private(set) var screen: Screen = .readCard
    public private(set) var busy = false
    public private(set) var errorMessage: String?
    public private(set) var sessionActive = false

    public private(set) var card: SigningCeremony.CardSnapshot?
    public private(set) var summary: TransactionSummary?
    public private(set) var approvalWarnings: [String] = []
    public private(set) var chainConfirmationNeeded: String?
    public private(set) var report: SigningReport?
    public private(set) var signatureUR: UR?
    public private(set) var counterBefore: UInt32?
    public private(set) var counterAfter: UInt32?
    /// The digest the operator must have seen. Shown, and required back from the
    /// approval, so an approval cannot drift onto a different payload.
    public private(set) var digestHex: String = ""
    public var acknowledgeTouchRule = false
    public var userPIN = ""

    /// Internal rather than public: the scan model belongs to this flow, and the
    /// ceremony — not the scanner — is what makes decisions about the request.
    let scan = QRScanModel()

    private var ceremony: SigningCeremony?
    private var scannedUR: UR?

    public init() {}

    // MARK: Derived state

    public var cardAddress: String { card?.addressHex ?? "—" }

    public var cardSerial: String { card?.serial ?? "not reported" }

    public var pinnedPath: String { card?.pinnedPath.description ?? "—" }

    /// True when the request came from a chain the operator has confirmed in this
    /// session. Nothing is persisted, so this is asked again next time.
    public var needsChainConfirmation: Bool { chainConfirmationNeeded != nil }

    /// The chain the operator is being asked to confirm, named when this app knows it.
    ///
    /// Formatting only — the gate itself is `SigningCeremony.confirmChainID`, and an
    /// unknown chain is confirmed exactly like a known one. The name exists so the
    /// prompt can be answered from the wallet's own screen rather than from memory.
    public var chainConfirmationChain: EVMChain? {
        chainConfirmationNeeded.flatMap { UInt64($0) }.map(EVMChain.init(id:))
    }

    // MARK: Lifecycle

    public func abort() {
        scan.stop()
        ceremony = nil
        scannedUR = nil
        card = nil
        summary = nil
        approvalWarnings = []
        chainConfirmationNeeded = nil
        signatureUR = nil
        report = nil
        digestHex = ""
        acknowledgeTouchRule = false
        userPIN = ""
        phase = .setup
        screen = .readCard
        errorMessage = nil
    }

    public func applicationDidBackground() {
        ceremony?.noteInterruption()
        scan.stop()
    }

    // MARK: Step 1 — read the card

    /// Reads the card's manifest and key. Read-only: no PIN, no writes.
    public func readCard() async {
        await run { ceremony in
            try await ceremony.readCard()
            self.card = ceremony.card
            self.counterBefore = ceremony.report.counterBeforeSigning
            self.screen = .scan
            await self.scan.start()
        }
    }

    // MARK: Step 2 — take the request

    /// Called by the scanner when a complete UR arrives. The ceremony decides
    /// whether it is acceptable.
    public func acceptScannedRequest() async {
        guard case .received(let ur) = scan.state else { return }
        await accept(ur)
    }

    public func accept(_ ur: UR) async {
        await run { ceremony in
            try ceremony.accept(requestUR: ur)
            self.scannedUR = ur
            self.summary = ceremony.summary
            self.digestHex = ceremony.transaction?.signingDigest.hexString ?? ""
            self.approvalWarnings = ceremony.approvalWarnings
            self.scan.stop()

            // The binding check needs the chain id confirmed first, and the
            // confirmation is the operator's, so ask for it rather than assuming.
            do {
                try ceremony.verifyRequest()
                self.screen = .review
            } catch SigningError.chainNotConfirmed(let chainID) {
                self.chainConfirmationNeeded = chainID
                self.screen = .review
            }
        }
    }

    /// The operator has looked at the chain id and confirmed it for this session.
    public func confirmChain() async {
        guard let chainID = chainConfirmationNeeded, let ceremony else { return }
        await run { _ in
            ceremony.confirmChainID(chainID)
            try ceremony.verifyRequest()
            self.chainConfirmationNeeded = nil
            self.screen = .review
        }
    }

    // MARK: Step 3 — approve

    public func approve() async {
        guard let ceremony else { return }
        await run { _ in
            try ceremony.approve(acknowledgingDigestHex: self.digestHex)
            self.screen = .pin
        }
    }

    // MARK: Step 4 — sign (once)

    /// The only route to a signature. One call, one `PSO:CDS`: the ceremony
    /// refuses a second attempt and this method never loops.
    public func sign() async {
        guard let ceremony else { return }
        guard let pin = Self.pinBytes(userPIN) else {
            errorMessage = "Enter the 6-digit user PIN you set when this YubiKey was provisioned."
            return
        }
        screen = .signing
        await run { _ in
            let response = try await ceremony.sign(userPIN: pin)
            self.userPIN = ""
            try ceremony.verifySignature(cardResponse: response)
            self.signatureUR = try ceremony.exportSignature()
            self.counterAfter = ceremony.report.counterAfterSigning
            self.report = ceremony.finish()
            self.phase = .finished
        }
        if phase != .finished {
            // Failed: back to the PIN screen, or to the report if the signature
            // could not be produced at all. The message says what to do next.
            self.screen = .pin
        }
    }

    // MARK: Helpers

    private func run(_ body: @escaping (SigningCeremony) async throws -> Void) async {
        if phase == .setup {
            let card = CardTransports.makeSessionCard(
                transportChoice,
                onSessionStart: { [weak self] _ in Task { @MainActor in self?.sessionActive = true } },
                onSessionEnd: { [weak self] in Task { @MainActor in self?.sessionActive = false } }
            )
            ceremony = SigningCeremony(
                card: card,
                transportDescription: transportChoice.title,
                appVersion: BuildInfo.summary
            )
            phase = .running
        }
        guard let ceremony else { return }
        busy = true
        errorMessage = nil
        defer { busy = false }
        do {
            try await body(ceremony)
        } catch let error as SigningError {
            errorMessage = error.userFacingDescription
            if case .signatureAlreadyAttempted = error {
                // Nothing further can be done with this request: it has to be
                // restarted from the wallet.
                self.report = ceremony.finish()
                self.phase = .finished
            }
        } catch let error as EthSignRequestError {
            errorMessage = error.userFacingDescription
        } catch let error as EVMTransactionError {
            errorMessage = Self.describe(error)
        } catch let error as CardError {
            errorMessage = error.userFacingDescription
        } catch {
            errorMessage = "\(error)"
        }
    }

    private static func describe(_ error: EVMTransactionError) -> String {
        switch error {
        case .nonCanonicalEncoding:
            return "The transaction's encoding is not canonical, so the bytes this app would sign are "
                + "not the bytes it decoded. Refusing."
        case .placeholdersNotEmpty:
            return "That is already a signed transaction, not a request to sign."
        case .dataTypeMismatch, .unsupportedTransactionType:
            return "The request's declared data type does not match its payload. Refusing rather than "
                + "guessing which one the wallet meant."
        case .wrongFieldCount(let count):
            return "The payload has \(count) fields, which is not a transaction this app can read."
        case .nonMinimalQuantity:
            return "The payload encodes a number in a non-minimal way, which would change the bytes "
                + "that get signed. Refusing."
        case .quantityTooWide(let field):
            return "The payload's \(field) is larger than the wallet itself would accept."
        case .invalidRecipientLength(let count):
            return "The recipient field is \(count) bytes; an address is 20."
        case .invalidAccessListEntry:
            return "The payload's access list is malformed."
        case .invalidStorageKeyLength(let count):
            return "An access-list storage key is \(count) bytes; they are 32."
        }
    }

    /// The user PIN is six digits by policy (design.md §4.2 step 5a). Validated
    /// here only to give a better message; the card is the authority.
    static func pinBytes(_ text: String) -> [UInt8]? {
        let digits = text.filter(\.isNumber)
        guard digits == text, (6...8).contains(digits.count) else { return nil }
        return Array(digits.utf8)
    }
}
