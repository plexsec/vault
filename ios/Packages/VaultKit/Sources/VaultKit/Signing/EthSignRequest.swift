import Foundation

/// `sign-data-type` of the Ethereum QR protocol (ERC-4527 / EIP-4527).
///
/// The values are the wire values. Note what the reference implementation does
/// versus what the EIP's CDDL says: the CDDL writes `data-type` as
/// `#3.401(sign-data-type)`, i.e. a tagged map, but
/// `@keystonehq/bc-ur-registry-eth` serialises a bare unsigned integer, which is
/// what MetaMask's scanner has actually been tested against. This decoder
/// accepts the bare integer and refuses the tagged form rather than guessing
/// (design.md §5.3).
public enum EVMSignDataType: UInt64, Equatable, Sendable, CaseIterable {
    case transaction = 1
    /// EIP-712 structured data. Not implemented: it needs the full EIP-712
    /// encoder, and signing it with a transaction's `v` convention would
    /// produce a signature no wallet accepts.
    case typedData = 2
    /// `personal_sign` (EIP-191). Not implemented, same reason.
    case personalMessage = 3
    /// EIP-2718 typed transaction (EIP-2930 / EIP-1559).
    case typedTransaction = 4

    public var displayName: String {
        switch self {
        case .transaction: return "legacy transaction"
        case .typedData: return "EIP-712 typed data"
        case .personalMessage: return "personal message"
        case .typedTransaction: return "typed transaction"
        }
    }

    public var isTransaction: Bool {
        self == .transaction || self == .typedTransaction
    }
}

public enum EthSignRequestError: Swift.Error, Equatable {
    case notAnEthSignRequest(type: String)
    case wrongTag(found: UInt64)
    case notAMap
    case unknownField(UInt64)
    case missingField(UInt64)
    case invalidField(UInt64)
    case unsupportedDataType(UInt64)
    case derivationPathTag(UInt64?)
    case signDataTooLarge(Int)

    public var userFacingDescription: String {
        switch self {
        case .notAnEthSignRequest(let type):
            return "That QR code is a “\(type)”, not a signing request. "
                + "Ask the wallet to show the transaction as a signing request."
        case .wrongTag(let found):
            return "The QR code carries the signing-request type name but the CBOR tag \(found), "
                + "which is not the tag a wallet uses. Refusing rather than guessing."
        case .notAMap:
            return "The signing request is not a map, so its fields cannot be read."
        case .unknownField(let key):
            return "The signing request has a field (number \(key)) this app does not implement. "
                + "Refusing rather than ignoring it: an unread field could change what the card signs."
        case .missingField(let key):
            return "The signing request is missing a required field (number \(key))."
        case .invalidField(let key):
            return "The signing request's field \(key) is malformed."
        case .unsupportedDataType(let value):
            return "The request asks for data type \(value). This app signs transactions only "
                + "(type 1 and 4); it does not sign messages or EIP-712 typed data."
        case .derivationPathTag(let tag):
            let described = tag.map { "\($0)" } ?? "no CBOR tag"
            return "The request's derivation path uses \(described) instead of the crypto-keypath "
                + "tag (304) that wallets emit. Refusing rather than guessing which path is meant."
        case .signDataTooLarge(let count):
            return "The signing request carries \(count) bytes, more than this app will display. "
                + "Refusing rather than showing a truncated view of what would be signed."
        }
    }
}

/// `eth-sign-request` (UR type `eth-sign-request`, CBOR tag 401).
///
/// The watch-only wallet builds this; the app consumes it. Fields are exactly
/// the ones the reference implementation writes:
///
/// ```
/// 1: #6.37(bytes .size 16)  request-id        (echoed back in the signature)
/// 2: bytes                  sign-data
/// 3: uint                   data-type         (1 legacy tx, 4 typed tx)
/// 4: uint                   chain-id          (omitted when 0)
/// 5: #6.304(crypto-keypath) derivation-path
/// 6: bytes .size 20         address           (absent for transactions)
/// 7: text                   origin            (absent for transactions)
/// ```
///
/// Note field 6: MetaMask's `signTransaction` does **not** send the address, only
/// the derivation path and the master fingerprint — so an address binding check
/// cannot be based on it. The path is what binds the request to the card's one
/// key, and the app displays the address it derives from the card so the
/// operator can compare it with the wallet (design.md §5.2 rule 6).
public struct EthSignRequest: Equatable, Sendable {
    public static let urType = "eth-sign-request"
    public static let cborTag: UInt64 = 401
    /// Anything larger is not going to fit in a QR exchange anyone can scan, and
    /// the display would be unusable before the crypto became the problem.
    public static let maximumSignDataLength = 16 * 1024

    public let requestID: [UInt8]?
    public let signData: [UInt8]
    public let dataType: EVMSignDataType
    public let chainID: EVMQuantity?
    public let derivationPath: URKeyPath
    public let address: [UInt8]?
    public let origin: String?

    public enum Field: UInt64 {
        case requestID = 1
        case signData = 2
        case dataType = 3
        case chainID = 4
        case derivationPath = 5
        case address = 6
        case origin = 7
    }

    public init(
        requestID: [UInt8]?,
        signData: [UInt8],
        dataType: EVMSignDataType,
        chainID: EVMQuantity?,
        derivationPath: URKeyPath,
        address: [UInt8]?,
        origin: String?
    ) {
        self.requestID = requestID
        self.signData = signData
        self.dataType = dataType
        self.chainID = chainID
        self.derivationPath = derivationPath
        self.address = address
        self.origin = origin
    }

    // MARK: - Decoding

    public init(ur: UR) throws {
        guard ur.type == Self.urType else { throw EthSignRequestError.notAnEthSignRequest(type: ur.type) }
        try self.init(cbor: ur.cbor)
    }

    public init(cbor: CBOR) throws {
        guard let tagged = cbor.taggedValue else { throw EthSignRequestError.wrongTag(found: 0) }
        guard tagged.tag == Self.cborTag else { throw EthSignRequestError.wrongTag(found: tagged.tag) }
        guard let map = tagged.value.mapValue else { throw EthSignRequestError.notAMap }

        for entry in map {
            guard let key = entry.key.unsignedValue, Field(rawValue: key) != nil else {
                throw EthSignRequestError.unknownField(entry.key.unsignedValue ?? UInt64.max)
            }
        }
        func value(_ field: Field) -> CBOR? {
            map.first { $0.key.unsignedValue == field.rawValue }?.value
        }

        guard let signDataValue = value(.signData), let signDataBytes = signDataValue.bytesValue else {
            throw EthSignRequestError.missingField(Field.signData.rawValue)
        }
        guard signDataBytes.count <= Self.maximumSignDataLength else {
            throw EthSignRequestError.signDataTooLarge(signDataBytes.count)
        }
        self.signData = [UInt8](signDataBytes)

        guard let dataTypeValue = value(.dataType), let rawDataType = dataTypeValue.unsignedValue else {
            throw EthSignRequestError.missingField(Field.dataType.rawValue)
        }
        guard let dataType = EVMSignDataType(rawValue: rawDataType) else {
            throw EthSignRequestError.unsupportedDataType(rawDataType)
        }
        self.dataType = dataType

        if let requestIDValue = value(.requestID) {
            let rawBytes = requestIDValue.taggedValue?.value.bytesValue ?? requestIDValue.bytesValue
            guard let rawBytes, rawBytes.count == 16 else {
                throw EthSignRequestError.invalidField(Field.requestID.rawValue)
            }
            self.requestID = [UInt8](rawBytes)
        } else {
            self.requestID = nil
        }

        if let chainIDValue = value(.chainID) {
            guard let raw = chainIDValue.unsignedValue, raw <= UInt64(UInt32.max) else {
                throw EthSignRequestError.invalidField(Field.chainID.rawValue)
            }
            self.chainID = EVMQuantity(raw)
        } else {
            self.chainID = nil
        }

        guard let pathValue = value(.derivationPath) else {
            throw EthSignRequestError.missingField(Field.derivationPath.rawValue)
        }
        guard let path = URKeyPath(cbor: pathValue, style: .keystoneLegacy) else {
            throw EthSignRequestError.derivationPathTag(pathValue.taggedValue?.tag)
        }
        self.derivationPath = path

        if let addressValue = value(.address) {
            guard let addressBytes = addressValue.bytesValue, addressBytes.count == EVMAddress.length else {
                throw EthSignRequestError.invalidField(Field.address.rawValue)
            }
            self.address = [UInt8](addressBytes)
        } else {
            self.address = nil
        }

        if let originValue = value(.origin) {
            guard let origin = originValue.textValue, origin.utf8.count <= 256 else {
                throw EthSignRequestError.invalidField(Field.origin.rawValue)
            }
            self.origin = origin
        } else {
            self.origin = nil
        }
    }

    /// The path as the wallet means it: the request's `crypto-keypath` is
    /// absolute from the master (MetaMask concatenates its stored `hdPath` and
    /// `childrenPath` before sending), so it is directly comparable with the
    /// card's pinned leaf path.
    public var path: DerivationPath {
        DerivationPath(components: derivationPath.components)
    }

    public var sourceFingerprintHex: String? {
        derivationPath.sourceFingerprint.map { String(format: "%08x", $0) }
    }

    // MARK: - Encoding (tests and loopback fixtures)

    public func cbor() -> CBOR {
        var entries: [CBORMapEntry] = []
        if let requestID {
            entries.append(CBORMapEntry(.unsigned(Field.requestID.rawValue), .tagged(37, .bytes(Data(requestID)))))
        }
        entries.append(CBORMapEntry(.unsigned(Field.signData.rawValue), .bytes(Data(signData))))
        entries.append(CBORMapEntry(.unsigned(Field.dataType.rawValue), .unsigned(dataType.rawValue)))
        if let chainID {
            entries.append(CBORMapEntry(.unsigned(Field.chainID.rawValue), .unsigned(chainID.uint64 ?? 0)))
        }
        entries.append(
            CBORMapEntry(.unsigned(Field.derivationPath.rawValue), derivationPath.cbor(style: .keystoneLegacy))
        )
        if let address {
            entries.append(CBORMapEntry(.unsigned(Field.address.rawValue), .bytes(Data(address))))
        }
        if let origin {
            entries.append(CBORMapEntry(.unsigned(Field.origin.rawValue), .text(origin)))
        }
        return .tagged(Self.cborTag, .map(entries))
    }

    public func ur() throws -> UR {
        try UR(type: Self.urType, cbor: cbor())
    }
}

/// `eth-signature` (UR type `eth-signature`, CBOR tag 402).
///
/// ```
/// 1: #6.37(bytes .size 16)  request-id  (required: the wallet matches on it)
/// 2: bytes                  signature  (r ‖ s ‖ v)
/// 3: text                   origin
/// ```
///
/// `signature` is 65 bytes (`r‖s‖v`) whenever the recovery value fits in one
/// byte — every typed transaction, and legacy ones up to chain id 110. A legacy
/// EIP-155 transaction on a larger chain needs `v = chainId·2 + 35 + recid`,
/// which cannot be a single byte, and MetaMask reads everything from byte 64 as
/// `v` (design.md §5.3 records this), so the field grows instead of lying.
public struct EthSignature: Equatable, Sendable {
    public static let urType = "eth-signature"
    public static let cborTag: UInt64 = 402

    public let requestID: [UInt8]?
    /// `r (32) ‖ s (32) ‖ v (1..4, minimal big-endian)`.
    public let signature: [UInt8]
    public let origin: String?

    public enum Field: UInt64 {
        case requestID = 1
        case signature = 2
        case origin = 3
    }

    public init(requestID: [UInt8]?, signature: [UInt8], origin: String? = nil) {
        self.requestID = requestID
        self.signature = signature
        self.origin = origin
    }

    /// Assembles `r ‖ s ‖ v` from the two halves the card returned and the
    /// recovery value the app computed. `recoveryValue` is the *transaction's*
    /// v (EIP-155 form for legacy, y-parity for typed), not the raw recid.
    public init(requestID: [UInt8]?, r: [UInt8], s: [UInt8], recoveryValue: EVMQuantity, origin: String? = nil) {
        self.init(
            requestID: requestID,
            signature: r + s + recoveryValue.bytes,
            origin: origin
        )
    }

    public init(ur: UR) throws {
        guard ur.type == Self.urType else { throw EthSignRequestError.notAnEthSignRequest(type: ur.type) }
        guard let tagged = ur.cbor.taggedValue, tagged.tag == Self.cborTag else {
            throw EthSignRequestError.wrongTag(found: ur.cbor.taggedValue?.tag ?? 0)
        }
        guard let map = tagged.value.mapValue else { throw EthSignRequestError.notAMap }
        for entry in map {
            guard let key = entry.key.unsignedValue, Field(rawValue: key) != nil else {
                throw EthSignRequestError.unknownField(entry.key.unsignedValue ?? UInt64.max)
            }
        }
        func value(_ field: Field) -> CBOR? {
            map.first { $0.key.unsignedValue == field.rawValue }?.value
        }
        guard let signatureValue = value(.signature), let signatureBytes = signatureValue.bytesValue,
              signatureBytes.count >= 65, signatureBytes.count <= 68
        else { throw EthSignRequestError.missingField(Field.signature.rawValue) }
        guard let requestIDValue = value(.requestID) else {
            throw EthSignRequestError.missingField(Field.requestID.rawValue)
        }
        let requestIDBytes = requestIDValue.taggedValue?.value.bytesValue ?? requestIDValue.bytesValue
        guard let requestIDBytes, requestIDBytes.count == 16 else {
            throw EthSignRequestError.invalidField(Field.requestID.rawValue)
        }
        self.init(
            requestID: [UInt8](requestIDBytes),
            signature: [UInt8](signatureBytes),
            origin: value(.origin)?.textValue
        )
    }

    public var r: [UInt8] { Array(signature[0..<32]) }
    public var s: [UInt8] { Array(signature[32..<64]) }
    public var recoveryValueBytes: [UInt8] { Array(signature[64...]) }

    public func cbor() -> CBOR {
        var entries: [CBORMapEntry] = []
        if let requestID {
            entries.append(CBORMapEntry(.unsigned(Field.requestID.rawValue), .tagged(37, .bytes(Data(requestID)))))
        }
        entries.append(CBORMapEntry(.unsigned(Field.signature.rawValue), .bytes(Data(signature))))
        if let origin {
            entries.append(CBORMapEntry(.unsigned(Field.origin.rawValue), .text(origin)))
        }
        return .tagged(Self.cborTag, .map(entries))
    }

    public func ur() throws -> UR {
        try UR(type: Self.urType, cbor: cbor())
    }
}
