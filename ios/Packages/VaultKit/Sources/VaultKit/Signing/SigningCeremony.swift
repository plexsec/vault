import Foundation

/// What the operator must see before a signature is produced, and the rules that
/// decide whether it may be produced at all.
///
/// The gates live here rather than in the view layer (design.md §5.2 rule 1):
/// a screen can be skipped, an error thrown by the state machine cannot.
///
/// The order is deliberate: **the request is read first**, so the card is asked for
/// the one key the wallet named and nothing else. The previous order read the card
/// first, which meant reading *both* slots — an inventory probes each slot's public
/// key to report occupancy — and spending sessions before knowing whether the request
/// was one this app could serve at all (amendment 33).
public enum SigningStep: Int, CaseIterable, Comparable, Codable, Sendable {
    case notStarted = 0
    /// The request arrived, its transaction was parsed, and it names a key this app
    /// signs with. Nothing has been read from the card yet.
    case requestDecoded
    /// Read-only: the serial, the pairing manifest and that one slot's public key —
    /// the slot the request named — from which the signing address is derived.
    case cardRead
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
    /// A request was needed and none had been read. Only reachable by a caller that
    /// skipped the scan: the step gate refuses that first.
    case noRequestYet
    /// The card was needed and had not been read in this session.
    case cardNotReadYet
    case noPairingManifest
    case requestPathNotPinned(requested: String, pinned: String)
    case requestFingerprintMismatch(requested: String, expected: String)
    case requestAddressMismatch(requested: String, found: String)
    case chainNotConfirmed(chainID: String)
    case chainIDMissing
    case unsupportedDataType(String)
    /// The request names a key this app cannot sign with — either this app's Ed25519
    /// key (which it reads and pairs but does not sign with in this version) or a path
    /// it does not provision at all.
    ///
    /// Distinct from `requestPathNotPinned`, which is about the *card*: this one is
    /// about what the app is able to do, and it is raised **before** the card is read,
    /// so a request the app cannot serve costs no card operation (amendment 33).
    case requestPathNotSignable(requested: String, signable: String)
    /// The request could not be read at all. Carries the parser's own explanation, because the
    /// parser knows what is wrong: reporting a malformed request as a *policy* refusal ("this
    /// app does not sign messages") sends the operator looking in the wrong place — which is
    /// exactly what happened when a real wallet's request was refused for its CBOR shape
    /// (amendment 25).
    case requestNotReadable(String)
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
        case .noRequestYet:
            return "No request has been read yet, so there is no key to ask the YubiKey for. "
                + "Scan the wallet's request first."
        case .cardNotReadYet:
            return "The YubiKey has not been read in this session yet, so nothing can be checked "
                + "against the request."
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
            let chain = UInt64(chainID).map(EVMChain.init(id:))
            return "Nothing has been signed for \(chain?.summaryLine ?? "chain id \(chainID)") on "
                + "this device yet. Confirm the chain id explicitly before signing for it."
        case .chainIDMissing:
            return "The transaction carries no chain id, so it would be replayable on every chain "
                + "and the app cannot tell which network it is for. Ask the wallet for an EIP-155 "
                + "transaction (every EVM chain has required one for years)."
        case .unsupportedDataType(let dataType):
            return "The request asks for \(dataType). This app signs transactions only; it does not "
                + "sign messages or EIP-712 typed data."
        case .requestPathNotSignable(let requested, let signable):
            return "The wallet asked for the key at \(requested). This app signs with \(signable), "
                + "and it decides that before it reads the card — so nothing was read from the "
                + "YubiKey for this request. Choose the account this card signs for in the wallet "
                + "and scan again."
        case .requestNotReadable(let reason):
            return reason
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
    /// The slot the request named, decided when the request was accepted and before the
    /// card is touched. This is what keeps `readCard()` to one key (amendment 33).
    public private(set) var signingSlot: KeySlot?
    public private(set) var transaction: EVMTransaction?
    public private(set) var summary: TransactionSummary?
    public private(set) var signature: EthSignature?
    public private(set) var signatureUR: UR?
    public private(set) var report = SigningReport()
    public private(set) var warnings: [String] = []

    private let transport: SignerCard
    private let clock: () -> Date
    /// Chain ids the operator has confirmed **in this session**. Nothing about a
    /// request is persisted — the app's only stored value is the card connection
    /// (amendment 31) — so this is stricter than design.md §5.2 rule 7's remembered
    /// list: every chain id is confirmed afresh, and an unconfirmed one is never
    /// signed for.
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

    // MARK: - Step 2: read the card

    /// Reads the card **for the slot the request named**, and derives the identity that
    /// will sign.
    ///
    /// Read-only: no PIN, no writes, no reset. The pairing manifest is required, and it
    /// has to agree with the key the card reports — that check is what makes "this card
    /// signs for this account" a fact rather than a hope.
    ///
    /// One session, one key. `inventory()` is what the provisioning ceremony uses to
    /// ask "what does this card hold", and answering that costs a public-key read per
    /// slot; this flow knows which slot it needs, so it reads that one (amendment 33).
    public func readCard() async throws {
        try require(.requestDecoded)
        guard let request else { throw SigningError.noRequestYet }
        guard let slot = signingSlot else {
            throw SigningError.requestPathNotSignable(
                requested: request.path.description,
                signable: "the secp256k1 key at \(DerivationPath.secp256k1Default) only"
            )
        }

        let identity = try await transport.readSigningIdentity(slot: slot)
        report.cardSerial = identity.serial

        guard let encoded = identity.pairingManifest, !encoded.isEmpty else {
            throw SigningError.noPairingManifest
        }
        let manifest: PairingManifest
        do {
            manifest = try PairingManifest.decode(encoded)
        } catch {
            throw SigningError.noPairingManifest
        }

        let algorithm: KeyAlgorithm = slot == .signature ? .secp256k1 : .ed25519
        guard let entry = manifest.entry(for: algorithm) else { throw SigningError.noPairingManifest }
        // Only reachable when a manifest exists without a key, which this app's own
        // provisioning cannot produce: it writes the manifest after verifying both
        // keys. A card in that state has been written to by something else.
        guard let publicKey = identity.publicKey else {
            throw SigningError.signatureVerificationFailed(
                "the card reports no key in the \(slot.displayName) slot"
            )
        }

        // The key the card reports must be the key the manifest describes:
        // otherwise the manifest is stale, and the address this screen shows would
        // be an address the card cannot sign for.
        do {
            try manifest.verify(
                against: CardKeyReport(
                    cardSerial: identity.serial.flatMap { try? Hex.decode($0) },
                    publicKeys: [algorithm: publicKey]
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
            serial: identity.serial,
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
        report.cardSerial = identity.serial
        step = .cardRead
    }

    // MARK: - Step 1: accept the request

    /// Takes the scanned request, parses its transaction, and works out which key it
    /// names.
    ///
    /// Nothing here trusts the request's own `data-type`: the payload has to match
    /// it, the `chain-id` field has to agree with the chain id inside the
    /// transaction, and a request that fails either check is refused before any
    /// screen shows a number from it.
    ///
    /// The request is taken **before** the card is read, which is what lets the card
    /// read ask for the one slot this request needs (amendment 33). A request that
    /// names a key this app cannot sign with is refused here — a card read would
    /// otherwise buy a public key nobody could use.
    public func accept(requestUR: UR) throws {
        try require(.notStarted)
        let request: EthSignRequest
        do {
            request = try EthSignRequest(ur: requestUR)
        } catch let error as EthSignRequestError {
            // The parser's own words, not a policy refusal: a request this app cannot read is
            // not the same as a request it declines to sign (amendment 25).
            throw SigningError.requestNotReadable(error.userFacingDescription)
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

        // Which key the request names. This app provisions exactly two fixed paths, so
        // the request's own path decides — and it decides *before* any card access,
        // which is the point of taking the request first. Only the secp256k1 key is
        // signable in this version: the Ed25519 key is read and paired (design.md
        // §4.3) but no Ed25519 signature is produced, so a request for it is refused
        // rather than answered with a key this app would not use.
        switch request.path {
        case DerivationPath.secp256k1Default:
            signingSlot = .signature
        case DerivationPath.ed25519Default:
            throw SigningError.requestPathNotSignable(
                requested: request.path.description,
                signable: "the secp256k1 key at \(DerivationPath.secp256k1Default) only — this "
                    + "version reads and pairs the Ed25519 key, but does not sign with it yet"
            )
        default:
            throw SigningError.requestPathNotSignable(
                requested: request.path.description,
                signable: "the secp256k1 key at \(DerivationPath.secp256k1Default) only"
            )
        }

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
        try require(.cardRead)
        guard let card else { throw SigningError.cardNotReadYet }
        guard let request, let transaction else { throw SigningError.noRequestYet }

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
        // ceremony is in, because the rule is about one request and one signature,
        // not about which screen the operator is looking at.
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
            // The response is what the app has: the case where it never saw one is
            // exactly the case where the operator has to be told, and told not to
            // try again.
            report.signingFailedReason = error.userFacingDescription
            switch error {
            case .pinIncorrect, .pinBlocked, .userPinNotVerified:
                throw SigningError.pinRejected(reason: error.userFacingDescription)
            default:
                throw SigningError.cardSignatureMalformed(error.userFacingDescription)
            }
        } catch {
            report.signingFailedReason = "\(error)"
            throw SigningError.cardSignatureMalformed("\(error)")
        }
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

/// What the operator can take away: no secrets, and the facts of what the card was
/// asked to do — what was signed, for which account, and whether the signature the
/// card returned verified against the digest that was displayed.
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
    public var signingFailedReason: String?
    public var interrupted = false
    public var startedAt: Date?
    public var approvedAt: Date?
    public var signedAt: Date?
    public var finishedAt: Date?

    public init() {}

    /// The chain, named when this app knows it.
    ///
    /// Derived from `chainID` rather than stored beside it, so the two cannot disagree —
    /// and composed here rather than in the view, because a screen that appends its own
    /// unit is exactly how the record came to say ETH on a Polygon transaction.
    public var chain: EVMChain? {
        guard let chainID, let id = UInt64(chainID) else { return nil }
        return EVMChain(id: id)
    }

    /// `Polygon (chain id 137)` for the record's chain row.
    public var chainDisplay: String { chain?.displayName ?? "chain id \(chainID ?? "—")" }

    /// `1.5 POL (1500000000000000000 wei)` for the record's value row.
    public var nativeValueDisplay: String? {
        guard let valueInEther else { return nil }
        let amount = TransactionSummary.native(valueInEther, on: chain)
        return value.map { "\(amount) (\($0) wei)" } ?? amount
    }
}
