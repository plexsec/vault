import Foundation

/// What the operator must see before a signature is produced, and the rules that
/// decide whether it may be produced at all.
///
/// The gates live here rather than in the view layer (design.md §5.2 rule 1):
/// a screen can be skipped, an error thrown by the state machine cannot. The
/// order is deliberate — the card is read *first*, so the address that will sign
/// is on screen while the transaction is being read, not after.
public enum SigningStep: Int, CaseIterable, Comparable, Codable, Sendable {
    case notStarted = 0
    /// Read-only: the card's serial, its pairing manifest and the signature
    /// slot's public key, from which the signing address is derived.
    case cardRead
    /// The request arrived and its transaction was parsed.
    case requestDecoded
    /// The request was bound to this card: path, master fingerprint and, when the
    /// wallet sends one, address.
    case requestVerified
    /// The operator approved the summary (and, for a new chain, the chain id).
    case approved
    /// One `PSO:CDS` for this request. There is no second attempt.
    case signed
    /// The card's signature was checked to recover this card's key, and its
    /// recovery value computed.
    case verified
    /// The `eth-signature` UR exists and can be shown.
    case exported
    case done

    public static func < (lhs: SigningStep, rhs: SigningStep) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var title: String {
        switch self {
        case .notStarted: return "Not started"
        case .cardRead: return "Read the card"
        case .requestDecoded: return "Read the request"
        case .requestVerified: return "Check the request"
        case .approved: return "Approve"
        case .signed: return "Sign"
        case .verified: return "Check the signature"
        case .exported: return "Show the signature"
        case .done: return "Done"
        }
    }
}

public enum SigningError: Swift.Error, Equatable {
    case wrongStep(expected: SigningStep, actual: SigningStep)
    case noPairingManifest
    case requestPathNotPinned(requested: String, pinned: String)
    case requestFingerprintMismatch(requested: String, expected: String)
    case requestAddressMismatch(requested: String, found: String)
    case chainNotConfirmed(chainID: String)
    case chainIDMissing
    case unsupportedDataType(String)
    case chainIDMismatch(request: String, transaction: String)
    case signatureTooLarge(Int)
    case pinRejected(reason: String)
    /// A second `PSO:CDS` for the same request. design.md §5.2 rule 1: one
    /// transaction buys exactly one touch, so a retry is refused outright rather
    /// than left to the transport.
    case signatureAlreadyAttempted
    case signatureVerificationFailed(String)
    case cardSignatureMalformed(String)

    public var userFacingDescription: String {
        switch self {
        case .wrongStep(let expected, let actual):
            return "This step is out of order: expected “\(expected.title)”, but the ceremony is at "
                + "“\(actual.title)”."
        case .noPairingManifest:
            return "This YubiKey carries no pairing manifest, so the app cannot tell which account it "
                + "was paired with. Provision the card with this app (or provision it again) before "
                + "signing with it."
        case .requestPathNotPinned(let requested, let pinned):
            return "The wallet asked for the key at \(requested), but this YubiKey signs for \(pinned) "
                + "only. Refusing: a signature from another key would be useless to the wallet, and "
                + "signing the wrong account is how funds are lost."
        case .requestFingerprintMismatch(let requested, let expected):
            return "The request says it comes from master key \(requested), but this card was paired to "
                + "master key \(expected). The wallet's keyring belongs to a different wallet."
        case .requestAddressMismatch(let requested, let found):
            return "The request names account \(requested), but the key inside this YubiKey is \(found)."
        case .chainNotConfirmed(let chainID):
            return "Nothing has been signed for chain id \(chainID) on this device yet. Confirm the "
                + "chain id explicitly before signing for it."
        case .chainIDMissing:
            return "The transaction carries no chain id, so it would be replayable on every chain "
                + "and the app cannot tell which network it is for. Ask the wallet for an EIP-155 "
                + "transaction (every EVM chain has required one for years)."
        case .unsupportedDataType(let dataType):
            return "The request asks for \(dataType). This app signs transactions only; it does not "
                + "sign messages or EIP-712 typed data."
        case .chainIDMismatch(let request, let transaction):
            return "The request says chain \(request) but the transaction payload is built for chain "
                + "\(transaction). Refusing: that mismatch changes the bytes that would be signed."
        case .signatureTooLarge(let count):
            return "The card returned \(count) bytes where a signature should be at most 72. Refusing "
                + "to interpret it."
        case .pinRejected(let reason):
            return "The YubiKey rejected the PIN: \(reason)"
        case .signatureAlreadyAttempted:
            return "A signature has already been attempted for this request. One transaction permits "
                + "exactly one touch: if the signature did not come through, treat the app as "
                + "compromised, stop, and start again from the wallet with a new request."
        case .signatureVerificationFailed(let reason):
            return "The signature returned by the YubiKey does not match this card's key "
                + "(\(reason)). Nothing is shown for scanning; the wallet must not be given it."
        case .cardSignatureMalformed(let reason):
            return "The YubiKey's signature could not be read (\(reason))."
        }
    }
}

/// One signing session: one request, one card, one signature.
///
/// Purposefully not a "signer service": it holds the request it was given, it can
/// be advanced once, and after a `PSO:CDS` attempt it refuses to try again. The
/// rules of design.md §5.2 that are machine-checkable are enforced here, and the
/// ones that are not (an operator's judgement about a transaction) are surfaced
/// as gates the operator has to pass explicitly.
public final class SigningCeremony {
    public private(set) var step: SigningStep = .notStarted
    public private(set) var card: CardSnapshot?
    public private(set) var request: EthSignRequest?
    public private(set) var transaction: EVMTransaction?
    public private(set) var summary: TransactionSummary?
    public private(set) var signature: EthSignature?
    public private(set) var signatureUR: UR?
    public private(set) var report = SigningReport()
    public private(set) var warnings: [String] = []

    private let transport: SignerCard
    private let clock: () -> Date
    /// Chain ids the operator has confirmed **in this session**. Nothing is
    /// persisted — the app stores nothing (audit) — so this is stricter than
    /// design.md §5.2 rule 7's remembered list: every chain id is confirmed
    /// afresh, and an unconfirmed one is never signed for.
    private var confirmedChainIDs: Set<String> = []
    /// The digest that was actually sent to the card, so the signature can be
    /// checked against it rather than against whatever is on screen later.
    private var signedDigest: [UInt8]?
    private var hasAttemptedSignature = false
    private var verifiedSignature: (signature: ECDSASignature, recoveryValue: EVMQuantity)?

    public init(
        card: SignerCard,
        transportDescription: String,
        appVersion: String,
        clock: @escaping () -> Date = Date.init
    ) {
        self.transport = card
        self.clock = clock
        report.transport = transportDescription
        report.appVersion = appVersion
        report.startedAt = clock()
    }

    /// The card's identity as read from the card itself.
    public struct CardSnapshot: Equatable, Sendable {
        public let serial: String?
        public let address: [UInt8]
        public let addressHex: String
        public let publicKey: [UInt8]
        /// The path and master fingerprint the card was paired under.
        public let pinnedPath: DerivationPath
        public let masterFingerprintHex: String
        /// True when the pairing manifest matched the key the card reports.
        public let manifestVerified: Bool
    }

    // MARK: - Step 1: read the card

    /// Reads the card and derives the address that will sign.
    ///
    /// Read-only: no PIN, no writes, no reset. The pairing manifest is required,
    /// and it has to agree with the key the card reports — that check is what
    /// makes "this card signs for this account" a fact rather than a hope.
    public func readCard() async throws {
        try require(.notStarted)
        let inventory = try await transport.inventory()
        report.cardSerial = inventory.serial

        let storedManifest: [UInt8]?
        do {
            storedManifest = try await transport.readPairingManifest()
        } catch is CardError {
            throw SigningError.noPairingManifest
        }
        guard let encoded = storedManifest, !encoded.isEmpty else {
            throw SigningError.noPairingManifest
        }
        let manifest: PairingManifest
        do {
            manifest = try PairingManifest.decode(encoded)
        } catch {
            throw SigningError.noPairingManifest
        }

        let publicKey = try await transport.readPublicKey(slot: .signature)
        guard let entry = manifest.entry(for: .secp256k1) else { throw SigningError.noPairingManifest }

        // The key the card reports must be the key the manifest describes:
        // otherwise the manifest is stale, and the address this screen shows would
        // be an address the card cannot sign for.
        do {
            try manifest.verify(
                against: CardKeyReport(
                    cardSerial: inventory.serial.flatMap { try? Hex.decode($0) },
                    publicKeys: [.secp256k1: publicKey]
                )
            )
        } catch {
            throw SigningError.signatureVerificationFailed(
                "the pairing manifest does not match the key inside the card"
            )
        }

        // The address is derived from the card's own public key, so the screen
        // cannot show an address the card cannot sign for.
        let normalized = publicKey.count == 65
            ? try Secp256k1.compressedPublicKey(fromUncompressed: publicKey)
            : publicKey
        let address = try EVMAddress.bytes(fromPublicKey: normalized)

        let pinnedPath = entry.childrenPath.map {
            DerivationPath(components: entry.originPath.components + $0.components)
        } ?? entry.originPath

        let snapshot = CardSnapshot(
            serial: inventory.serial,
            address: address,
            addressHex: EVMAddress.checksummed(addressBytes: address),
            publicKey: normalized,
            pinnedPath: pinnedPath,
            masterFingerprintHex: entry.masterFingerprint.hexString,
            manifestVerified: true
        )
        card = snapshot
        report.cardAddress = snapshot.addressHex
        report.pinnedPath = pinnedPath.description
        report.cardSerial = inventory.serial
        report.counterBeforeSigning = try? await transport.signatureCounter()
        step = .cardRead
    }

    // MARK: - Step 2: accept the request

    /// Takes the scanned request, parses its transaction and builds the summary.
    ///
    /// Nothing here trusts the request's own `data-type`: the payload has to match
    /// it, the `chain-id` field has to agree with the chain id inside the
    /// transaction, and a request that fails either check is refused before any
    /// screen shows a number from it.
    public func accept(requestUR: UR) throws {
        try require(.cardRead)
        let request: EthSignRequest
        do {
            request = try EthSignRequest(ur: requestUR)
        } catch let error as EthSignRequestError {
            throw SigningError.unsupportedDataType(error.userFacingDescription)
        }
        guard request.dataType.isTransaction else {
            throw SigningError.unsupportedDataType(request.dataType.displayName)
        }
        let transaction = try EVMTransaction(signData: request.signData, dataType: request.dataType)

        // The `chain-id` field and the transaction's own chain id must agree:
        // they are both part of what decides the signed bytes.
        if let declared = request.chainID {
            guard let actual = transaction.chainId else {
                throw SigningError.chainIDMismatch(
                    request: declared.decimalString,
                    transaction: "none"
                )
            }
            guard declared == actual else {
                throw SigningError.chainIDMismatch(
                    request: declared.decimalString,
                    transaction: actual.decimalString
                )
            }
        }
        guard let chainID = transaction.chainId else { throw SigningError.chainIDMissing }

        self.request = request
        self.transaction = transaction
        self.summary = TransactionSummary(transaction: transaction)
        report.requestID = request.requestID?.hexString
        report.chainID = chainID.decimalString
        report.transactionType = transaction.kind.displayName
        report.recipient = transaction.checksummedRecipient ?? "(contract creation)"
        report.value = transaction.value.decimalString
        report.valueInEther = transaction.valueInEther
        report.calldataLength = transaction.data.count
        report.decodedFunction = summary?.call?.displayName
        report.requestedPath = request.path.description
        report.requestOrigin = request.origin
        step = .requestDecoded
    }

    // MARK: - Step 3: bind the request to the card

    /// Checks that this request is for *this* card, and that the operator has
    /// confirmed the chain.
    public func verifyRequest() throws {
        try require(.requestDecoded)
        guard let card, let request, let transaction else { throw SigningError.noPairingManifest }

        guard request.path == card.pinnedPath else {
            throw SigningError.requestPathNotPinned(
                requested: request.path.description,
                pinned: card.pinnedPath.description
            )
        }
        if let fingerprint = request.sourceFingerprintHex, fingerprint != card.masterFingerprintHex {
            throw SigningError.requestFingerprintMismatch(
                requested: fingerprint,
                expected: card.masterFingerprintHex
            )
        }
        if let requestedAddress = request.address,
           requestedAddress != card.address {
            throw SigningError.requestAddressMismatch(
                requested: EVMAddress.checksummed(addressBytes: requestedAddress),
                found: card.addressHex
            )
        }

        let chainID = transaction.chainId?.decimalString ?? ""
        guard confirmedChainIDs.contains(chainID) else {
            throw SigningError.chainNotConfirmed(chainID: chainID)
        }
        report.bindingVerified = true
        step = .requestVerified
    }

    /// Records the operator's explicit confirmation of one chain id, for this
    /// session. `verifyRequest` refuses every chain id that has not been through
    /// here, which is why the confirmation has to name the id.
    public func confirmChainID(_ chainID: String) {
        confirmedChainIDs.insert(chainID)
    }

    // MARK: - Step 4: the operator's approval

    /// The operator has read the summary and approved it.
    ///
    /// `transactionHashHex` is the digest the operator was shown (or compared
    /// against the wallet's own display); it is checked against the digest the app
    /// will sign, so an approval cannot be carried over to a different payload.
    public func approve(acknowledgingDigestHex: String) throws {
        try require(.requestVerified)
        guard let transaction else { throw SigningError.chainIDMissing }
        let digest = transaction.signingDigest.hexString
        guard digest.lowercased().hasPrefix(acknowledgingDigestHex.lowercased()),
              !acknowledgingDigestHex.isEmpty
        else {
            throw SigningError.signatureVerificationFailed(
                "the approved digest does not match the transaction's digest"
            )
        }
        report.approvedDigest = digest
        report.approvedAt = clock()
        step = .approved
    }

    // MARK: - Step 5: sign (exactly once)

    /// `VERIFY PW1` then `PSO:CDS` over the transaction's digest.
    ///
    /// The digest is recomputed here from the transaction that was approved, and
    /// held, so the later verification checks the signature against the bytes that
    /// were actually signed rather than against whatever is on screen.
    public func sign(userPIN: [UInt8]) async throws -> [UInt8] {
        // Checked before the step: a second attempt is refused whatever state the
        // ceremony is in, because the rule is about the card's counter, not about
        // which screen the operator is looking at.
        guard !hasAttemptedSignature else { throw SigningError.signatureAlreadyAttempted }
        try require(.approved)
        guard let transaction else { throw SigningError.chainIDMissing }
        hasAttemptedSignature = true
        report.signatureAttempts += 1

        let digest = transaction.signingDigest
        signedDigest = digest

        let response: [UInt8]
        do {
            response = try await transport.sign(digest: digest, userPIN: userPIN)
        } catch let error as CardError {
            // Whatever went wrong, the counter is read and reported: it is the only
            // evidence available about whether a signature happened, and the case
            // where the app never saw the response is exactly the case where the
            // operator needs to know.
            report.signingFailedReason = error.userFacingDescription
            report.counterAfterSigning = try? await transport.signatureCounter()
            switch error {
            case .pinIncorrect, .pinBlocked, .userPinNotVerified:
                throw SigningError.pinRejected(reason: error.userFacingDescription)
            default:
                throw SigningError.cardSignatureMalformed(error.userFacingDescription)
            }
        } catch {
            report.signingFailedReason = "\(error)"
            report.counterAfterSigning = try? await transport.signatureCounter()
            throw SigningError.cardSignatureMalformed("\(error)")
        }
        report.counterAfterSigning = try? await transport.signatureCounter()
        report.signedAt = clock()
        step = .signed
        return response
    }

    // MARK: - Step 6: check what came back

    /// Decodes the card's signature, normalises it and checks it recovers this
    /// card's key. Only then does the app know which `v` to send.
    public func verifySignature(cardResponse: [UInt8]) throws {
        try require(.signed)
        guard cardResponse.count <= 72 else { throw SigningError.signatureTooLarge(cardResponse.count) }
        guard let card, let transaction, let digest = signedDigest else {
            throw SigningError.chainIDMissing
        }
        let decoded: ECDSASignature
        do {
            decoded = try ECDSASignature.decode(cardResponse: cardResponse)
        } catch {
            throw SigningError.cardSignatureMalformed("\(error)")
        }
        let signature: ECDSASignature
        let recoveryValue: EVMQuantity
        do {
            (signature, recoveryValue) = try EVMSignature.transactionSignature(
                cardSignature: decoded,
                transaction: transaction,
                expectedAddress: card.address
            )
        } catch {
            throw SigningError.signatureVerificationFailed(
                "no recovery value 0 or 1 makes the signature recover this card's key"
            )
        }
        // Independent of the recovery search: verify with libsecp256k1 as well.
        guard try Secp256k1.verify(signature: signature, digest: digest, publicKey: card.publicKey) else {
            throw SigningError.signatureVerificationFailed("verification failed")
        }
        report.signatureVerified = true
        report.recoveryValue = recoveryValue.decimalString
        report.signatureWasLowS = signature.isLowS
        report.wideRecoveryValue = !EVMSignature.fitsInSingleByte(recoveryValue)
        self.verifiedSignature = (signature, recoveryValue)
        step = .verified
    }

    /// Builds the `eth-signature` UR. The request id is echoed verbatim: the
    /// wallet matches on it, and a signature whose id does not match is a
    /// signature the wallet will refuse.
    @discardableResult
    public func exportSignature() throws -> UR {
        try require(.verified)
        guard let request, let card = verifiedSignature else {
            throw SigningError.signatureVerificationFailed("no verified signature")
        }
        let ethSignature = EthSignature(
            requestID: request.requestID,
            r: card.signature.r,
            s: card.signature.s,
            recoveryValue: card.recoveryValue,
            origin: request.origin
        )
        let ur = try ethSignature.ur()
        self.signature = ethSignature
        self.signatureUR = ur
        report.signatureBytes = ethSignature.signature.count
        step = .done
        return ur
    }

    /// Warnings the operator must see before approving, in the order they matter.
    public var approvalWarnings: [String] {
        var warnings: [String] = []
        if let summary, let warning = summary.decodeWarning { warnings.append(warning) }
        if let call = summary?.call, call.name == "setApprovalForAll" {
            warnings.append(
                "This call hands over control of every token in this account to the address shown. "
                + "That is how most drained wallets were drained."
            )
        }
        if let call = summary?.call, call.name == "approve", call.arguments.count == 2,
           case .uint(let amount) = call.arguments[1] {
            let unlimited = amount.bytes.count >= 32
            if unlimited {
                warnings.append(
                    "This approval has no limit: the spender can take that token from this account "
                    + "until it is revoked."
                )
            }
        }
        if let transaction, transaction.maxFeePerGas == nil, transaction.kind == .legacy {
            warnings.append(
                "A legacy transaction: on chains where the fee market has changed, a stale gas price "
                + "can be ignored for a long time, or never mined."
            )
        }
        if let card, card.serial == nil {
            warnings.append("The card did not report a serial number, so this signature's coverage is weaker than usual.")
        }
        return warnings
    }

    /// Closes the session. Wipes nothing but the PIN material the caller holds;
    /// the report stays, because that is what the operator takes away.
    public func finish() -> SigningReport {
        report.finishedAt = clock()
        step = .done
        return report
    }

    /// Called when the app leaves the foreground: a signing session that is not
    /// finished cannot be resumed, because a card session cannot be either.
    public func noteInterruption() {
        report.interrupted = true
    }

    private func require(_ expected: SigningStep) throws {
        guard step == expected else {
            throw SigningError.wrongStep(expected: expected, actual: step)
        }
    }
}

/// What the operator can take away: no secrets, and the facts needed to audit
/// what the card did. The counter values are here because the counter is the only
/// evidence that a signature happened at all.
public struct SigningReport: Equatable, Sendable {
    public var transport: String = ""
    public var appVersion: String = ""
    public var cardSerial: String?
    public var cardAddress: String?
    public var pinnedPath: String?
    public var requestID: String?
    public var requestOrigin: String?
    public var requestedPath: String?
    public var chainID: String?
    public var transactionType: String?
    public var recipient: String?
    public var value: String?
    public var valueInEther: String?
    public var calldataLength: Int = 0
    public var decodedFunction: String?
    public var bindingVerified = false
    public var approvedDigest: String?
    public var signatureAttempts = 0
    public var signatureWasLowS = false
    public var wideRecoveryValue = false
    public var recoveryValue: String?
    public var signatureBytes = 0
    public var signatureVerified = false
    public var counterBeforeSigning: UInt32?
    public var counterAfterSigning: UInt32?
    public var signingFailedReason: String?
    public var interrupted = false
    public var startedAt: Date?
    public var approvedAt: Date?
    public var signedAt: Date?
    public var finishedAt: Date?

    public init() {}

    /// The counter comparison design.md §5.2 rule 4 asks for. Read by the app, so
    /// it is *evidence for the operator*, not a gate — the rule requires the
    /// comparison to be made by a party other than the one that displayed the
    /// transaction, and that means the wallet.
    public var counterDelta: Int? {
        guard let before = counterBeforeSigning, let after = counterAfterSigning else { return nil }
        return Int(after) - Int(before)
    }
}
