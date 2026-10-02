import Foundation

/// A big-endian unsigned integer of arbitrary width, in the minimal encoding
/// that RLP and Ethereum both require.
///
/// Quantities come off the wire as byte strings whose width is not fixed:
/// `0x0186a0` and `0x86a0` are the same number and only the second is legal
/// (leading zeros are rejected). Zero is the empty byte string. The whole
/// transaction model is built on that rule rather than on `UInt64`, because
/// `value` and `gasPrice` are 256-bit fields and a truncated display of the
/// amount of money being moved would be the worst kind of bug here.
public struct EVMQuantity: Equatable, Hashable, Sendable {
    /// Minimal big-endian magnitude. Empty means zero.
    public let bytes: [UInt8]

    public static let zero = EVMQuantity(unchecked: [])

    private init(unchecked bytes: [UInt8]) { self.bytes = bytes }

    /// Strict: rejects leading zeros, which are a second encoding of a number
    /// that is already represented minimally elsewhere in the same fields.
    public init(minimalBytes: [UInt8]) throws {
        if minimalBytes.first == 0, !minimalBytes.isEmpty {
            throw EVMTransactionError.nonMinimalQuantity
        }
        self.bytes = minimalBytes
    }

    public init(_ value: UInt64) {
        var out: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            out.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        self.bytes = out
    }

    public var isZero: Bool { bytes.isEmpty }

    /// Fits in a `UInt64`, or `nil`. Callers that need a bound (a nonce index, a
    /// gas limit) must not silently wrap.
    public var uint64: UInt64? {
        guard bytes.count <= 8 else { return nil }
        var value: UInt64 = 0
        for byte in bytes { value = value << 8 | UInt64(byte) }
        return value
    }

    /// `0x`-prefixed, minimal, lowercase. Zero is `0x0`.
    public var hexString: String { "0x" + (bytes.isEmpty ? "0" : Hex.encode(bytes)) }

    /// Exact decimal, arbitrary width. Repeated division by ten on the byte
    /// array: O(n²) on at most 40 bytes, and trivially auditable.
    public var decimalString: String {
        guard !bytes.isEmpty else { return "0" }
        var digits: [UInt8] = []
        var remainder = bytes
        while !remainder.isEmpty {
            var quotient: [UInt8] = []
            var carry: UInt32 = 0
            for byte in remainder {
                let dividend = carry << 8 | UInt32(byte)
                let digit = dividend / 10
                carry = dividend % 10
                if !quotient.isEmpty || digit != 0 { quotient.append(UInt8(digit)) }
            }
            digits.append(UInt8(carry))
            remainder = quotient
        }
        return String(decoding: digits.reversed().map { $0 + 0x30 }, as: UTF8.self)
    }

    /// Fixed-point rendering with `decimals` places, exact (no rounding) — the
    /// decimal string is split, never divided in binary floating point.
    public func decimalString(decimals: Int) -> String {
        let digits = decimalString
        guard decimals > 0 else { return digits }
        var padded = digits
        if padded.count <= decimals {
            padded = String(repeating: "0", count: decimals - padded.count + 1) + padded
        }
        let split = padded.index(padded.endIndex, offsetBy: -decimals)
        let whole = String(padded[padded.startIndex..<split])
        let fraction = String(padded[split...])
        let trimmed = String(fraction.reversed().drop { $0 == "0" }.reversed())
        return trimmed.isEmpty ? whole : "\(whole).\(trimmed)"
    }

    /// Two quantities compared as unsigned big-endian magnitudes.
    public static func < (lhs: EVMQuantity, rhs: EVMQuantity) -> Bool {
        if lhs.bytes.count != rhs.bytes.count { return lhs.bytes.count < rhs.bytes.count }
        for (left, right) in zip(lhs.bytes, rhs.bytes) where left != right {
            return left < right
        }
        return false
    }
}

public extension EVMQuantity {
    /// Exact schoolbook multiplication by a `UInt64`, wide enough that the
    /// product cannot be truncated (`m` bytes × 8 bytes ≤ `m + 8` bytes).
    /// Used for `gasLimit × gasPrice`; both operands are bounded by
    /// `EVMTransaction`'s own field-width checks.
    func multiplied(by multiplier: UInt64) -> EVMQuantity {
        guard !bytes.isEmpty, multiplier != 0 else { return .zero }
        var result = [UInt8](repeating: 0, count: bytes.count + 8)
        var index = result.count
        var carry: UInt64 = 0
        for byte in bytes.reversed() {
            index -= 1
            let (high, low) = UInt64(byte).multipliedFullWidth(by: multiplier)
            let (sum, overflow) = low.addingReportingOverflow(carry)
            result[index] = UInt8(sum & 0xff)
            // Everything above the byte that was just written continues into the
            // next digit: the top half of the product, the rest of `sum`, and the
            // carry out of the addition.
            carry = high &+ (sum >> 8) &+ (overflow ? 1 : 0)
        }
        var remaining = carry
        while remaining > 0, index > 0 {
            index -= 1
            result[index] = UInt8(remaining & 0xff)
            remaining >>= 8
        }
        var trimmed = Array(result[index...])
        while trimmed.count > 1, trimmed.first == 0 { trimmed.removeFirst() }
        if trimmed == [0] { trimmed = [] }
        return (try? EVMQuantity(minimalBytes: trimmed)) ?? .zero
    }
}

/// One EIP-2930 access-list entry.
public struct EVMAccessListEntry: Equatable, Sendable {
    public let address: [UInt8]
    public let storageKeys: [[UInt8]]

    public init(address: [UInt8], storageKeys: [[UInt8]]) {
        self.address = address
        self.storageKeys = storageKeys
    }
}

public enum EVMTransactionError: Swift.Error, Equatable {
    /// The `data-type` field described a payload this decoder will not read.
    case dataTypeMismatch
    case unsupportedTransactionType(UInt8)
    case wrongFieldCount(Int)
    case nonMinimalQuantity
    case quantityTooWide(field: String)
    case invalidRecipientLength(Int)
    case invalidAccessListEntry
    case invalidStorageKeyLength(Int)
    /// The EIP-155 placeholders of the legacy form were not empty, so this is a
    /// *signed* transaction rather than a request to sign.
    case placeholdersNotEmpty
    /// `encode(decode(x)) != x` — the only failure that matters for the display
    /// guarantee, because it means the bytes we would hash are not the bytes we
    /// decoded.
    case nonCanonicalEncoding
}

/// An unsigned EVM transaction, as sent by a watch-only wallet.
///
/// See design.md §5.3 for the wire shapes this accepts. The model keeps the
/// original bytes (`signData`), the field-by-field decoding (`rawItems` is
/// rebuilt from the fields and compared against them) and the digest that will
/// be handed to the card — so "the operator approves what the card signs" is a
/// property of the type, not of the code path that happens to build it.
public struct EVMTransaction: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        /// Pre-EIP-2718: six items, or nine with EIP-155 replay protection.
        case legacy
        /// EIP-2930, type byte `0x01`.
        case accessList
        /// EIP-1559, type byte `0x02`.
        case feeMarket

        public var displayName: String {
            switch self {
            case .legacy: return "legacy"
            case .accessList: return "EIP-2930 (access list)"
            case .feeMarket: return "EIP-1559 (fee market)"
            }
        }

        /// The EIP-2718 envelope type byte, or `nil` for legacy.
        public var typeByte: UInt8? {
            switch self {
            case .legacy: return nil
            case .accessList: return 0x01
            case .feeMarket: return 0x02
            }
        }
    }

    public let kind: Kind
    /// Absent only for a legacy transaction that predates EIP-155 replay
    /// protection — that form hashes six fields and signs with v = 27/28.
    public let chainId: EVMQuantity?
    public let nonce: EVMQuantity
    /// Legacy and EIP-2930 only.
    public let gasPrice: EVMQuantity?
    /// EIP-1559 only.
    public let maxPriorityFeePerGas: EVMQuantity?
    public let maxFeePerGas: EVMQuantity?
    public let gasLimit: EVMQuantity
    /// `nil` means contract creation (the recipient field was empty).
    public let to: [UInt8]?
    public let value: EVMQuantity
    public let data: [UInt8]
    public let accessList: [EVMAccessListEntry]
    /// Exactly the bytes received, and exactly the bytes that are hashed.
    public let signData: [UInt8]

    /// True when the legacy form carried the EIP-155 `chainId, 0, 0` tail.
    public var usesEIP155: Bool { kind == .legacy && chainId != nil }

    /// keccak256 over `signData`. Nothing else in the app hashes a transaction.
    public var signingDigest: [UInt8] { Keccak256.hash(signData) }

    // MARK: - Decoding

    /// Decodes `sign-data`. `dataType` is the request's own declaration and is
    /// cross-checked, not trusted: a legacy payload announced as a typed one is
    /// refused rather than displayed as something it is not.
    public init(signData: [UInt8], dataType: EVMSignDataType) throws {
        switch dataType {
        case .transaction:
            try self.init(legacySignData: signData, typedPayload: nil)
        case .typedTransaction:
            guard let typeByte = signData.first else { throw EVMTransactionError.wrongFieldCount(0) }
            try self.init(legacySignData: nil, typedPayload: (typeByte, Array(signData.dropFirst())))
        case .typedData, .personalMessage:
            throw EVMTransactionError.dataTypeMismatch
        }
    }

    private init(legacySignData: [UInt8]?, typedPayload: (UInt8, [UInt8])?) throws {
        if let typedPayload {
            let kind: Kind
            switch typedPayload.0 {
            case 0x01: kind = .accessList
            case 0x02: kind = .feeMarket
            default: throw EVMTransactionError.unsupportedTransactionType(typedPayload.0)
            }
            let items = try RLP.decodeList(typedPayload.1)
            guard items.count == (kind == .accessList ? 8 : 9) else {
                throw EVMTransactionError.wrongFieldCount(items.count)
            }
            self.kind = kind
            self.chainId = try Self.quantity(items[0], field: "chainId")
            self.nonce = try Self.quantity(items[1], field: "nonce")
            if kind == .accessList {
                self.gasPrice = try Self.quantity(items[2], field: "gasPrice")
                self.maxPriorityFeePerGas = nil
                self.maxFeePerGas = nil
                self.gasLimit = try Self.quantity(items[3], field: "gasLimit")
                self.to = try Self.recipient(items[4])
                self.value = try Self.quantity(items[5], field: "value")
                self.data = try Self.itemBytes(items[6])
                self.accessList = try Self.accessList(items[7])
            } else {
                self.gasPrice = nil
                self.maxPriorityFeePerGas = try Self.quantity(items[2], field: "maxPriorityFeePerGas")
                self.maxFeePerGas = try Self.quantity(items[3], field: "maxFeePerGas")
                self.gasLimit = try Self.quantity(items[4], field: "gasLimit")
                self.to = try Self.recipient(items[5])
                self.value = try Self.quantity(items[6], field: "value")
                self.data = try Self.itemBytes(items[7])
                self.accessList = try Self.accessList(items[8])
            }
            self.signData = [typedPayload.0] + RLP.encode(.list(items))
        } else if let legacySignData {
            let items = try RLP.decodeList(legacySignData)
            // Six fields is pre-EIP-155; nine is the EIP-155 form whose last
            // three slots carry the chain id and two empty placeholders.
            guard items.count == 6 || items.count == 9 else {
                throw EVMTransactionError.wrongFieldCount(items.count)
            }
            self.kind = .legacy
            self.nonce = try Self.quantity(items[0], field: "nonce")
            self.gasPrice = try Self.quantity(items[1], field: "gasPrice")
            self.gasLimit = try Self.quantity(items[2], field: "gasLimit")
            self.to = try Self.recipient(items[3])
            self.value = try Self.quantity(items[4], field: "value")
            self.data = try Self.itemBytes(items[5])
            if items.count == 9 {
                self.chainId = try Self.quantity(items[6], field: "chainId")
                // Non-empty r/s would mean this is a signed transaction, and
                // signing it again is not something to attempt.
                guard try Self.itemBytes(items[7]).isEmpty, try Self.itemBytes(items[8]).isEmpty else {
                    throw EVMTransactionError.placeholdersNotEmpty
                }
            } else {
                self.chainId = nil
            }
            self.maxPriorityFeePerGas = nil
            self.maxFeePerGas = nil
            self.accessList = []
            self.signData = legacySignData
        } else {
            throw EVMTransactionError.wrongFieldCount(0)
        }

        try checkFieldWidths()

        // The display guarantee, enforced rather than assumed: rebuilding the
        // input from the decoded fields must reproduce it byte for byte. This is
        // what stops a future field from being decoded for display and then
        // dropped from the bytes that get hashed.
        guard RLP.encode(.list(rawItems())) == payloadBytes() else {
            throw EVMTransactionError.nonCanonicalEncoding
        }
    }

    // MARK: - Re-encoding

    /// The RLP list, the EIP-2718 type byte excluded.
    private func rawItems() -> [RLP.Item] {
        switch kind {
        case .legacy:
            var items: [RLP.Item] = [
                .bytes(nonce.bytes),
                .bytes(gasPrice?.bytes ?? []),
                .bytes(gasLimit.bytes),
                .bytes(to ?? []),
                .bytes(value.bytes),
                .bytes(data),
            ]
            if let chainId {
                items.append(.bytes(chainId.bytes))
                items.append(.bytes([]))
                items.append(.bytes([]))
            }
            return items
        case .accessList:
            return [
                .bytes(chainId?.bytes ?? []),
                .bytes(nonce.bytes),
                .bytes(gasPrice?.bytes ?? []),
                .bytes(gasLimit.bytes),
                .bytes(to ?? []),
                .bytes(value.bytes),
                .bytes(data),
                .list(rawAccessList()),
            ]
        case .feeMarket:
            return [
                .bytes(chainId?.bytes ?? []),
                .bytes(nonce.bytes),
                .bytes(maxPriorityFeePerGas?.bytes ?? []),
                .bytes(maxFeePerGas?.bytes ?? []),
                .bytes(gasLimit.bytes),
                .bytes(to ?? []),
                .bytes(value.bytes),
                .bytes(data),
                .list(rawAccessList()),
            ]
        }
    }

    private func rawAccessList() -> [RLP.Item] {
        accessList.map { entry in
            .list([.bytes(entry.address), .list(entry.storageKeys.map { .bytes($0) })])
        }
    }

    /// The signed payload without the EIP-2718 type byte.
    private func payloadBytes() -> [UInt8] {
        kind == .legacy ? signData : Array(signData.dropFirst())
    }

    // MARK: - Field readers

    private static func itemBytes(_ item: RLP.Item) throws -> [UInt8] {
        guard case .bytes(let bytes) = item else { throw EVMTransactionError.wrongFieldCount(-1) }
        return bytes
    }

    private static func quantity(_ item: RLP.Item, field: String) throws -> EVMQuantity {
        try EVMQuantity(minimalBytes: try itemBytes(item))
    }

    /// Empty or a 20-byte address; anything else is not a transaction this app
    /// can display honestly.
    private static func recipient(_ item: RLP.Item) throws -> [UInt8]? {
        let bytes = try itemBytes(item)
        if bytes.isEmpty { return nil }
        guard bytes.count == EVMAddress.length else {
            throw EVMTransactionError.invalidRecipientLength(bytes.count)
        }
        return bytes
    }

    private static func accessList(_ item: RLP.Item) throws -> [EVMAccessListEntry] {
        guard case .list(let entries) = item else { throw EVMTransactionError.invalidAccessListEntry }
        return try entries.map { entry in
            guard case .list(let fields) = entry, fields.count == 2 else {
                throw EVMTransactionError.invalidAccessListEntry
            }
            let address = try itemBytes(fields[0])
            guard address.count == EVMAddress.length else {
                throw EVMTransactionError.invalidAccessListEntry
            }
            guard case .list(let keys) = fields[1] else {
                throw EVMTransactionError.invalidAccessListEntry
            }
            let storageKeys = try keys.map { key -> [UInt8] in
                let bytes = try itemBytes(key)
                guard bytes.count == 32 else {
                    throw EVMTransactionError.invalidStorageKeyLength(bytes.count)
                }
                return bytes
            }
            return EVMAccessListEntry(address: address, storageKeys: storageKeys)
        }
    }

    /// The bounds the consumer enforces (ethereumjs `_validateCannotExceedMaxInteger`).
    /// Signing a transaction the wallet will then refuse helps nobody, and these
    /// bounds also keep every displayed number finite.
    private func checkFieldWidths() throws {
        func check(_ quantity: EVMQuantity?, _ field: String, _ limit: Int) throws {
            guard let quantity else { return }
            guard quantity.bytes.count <= limit else {
                throw EVMTransactionError.quantityTooWide(field: field)
            }
        }
        try check(nonce, "nonce", 8)
        try check(gasLimit, "gasLimit", 8)
        try check(gasPrice, "gasPrice", 32)
        try check(maxFeePerGas, "maxFeePerGas", 32)
        try check(maxPriorityFeePerGas, "maxPriorityFeePerGas", 32)
        try check(value, "value", 32)
        try check(chainId, "chainId", 8)
    }

    // MARK: - Display

    public var valueInEther: String { value.decimalString(decimals: 18) }

    public var gasPriceInGwei: String? { gasPrice.map(Self.gwei) }
    public var maxFeePerGasInGwei: String? { maxFeePerGas.map(Self.gwei) }
    public var maxPriorityFeePerGasInGwei: String? { maxPriorityFeePerGas.map(Self.gwei) }

    /// 1 gwei = 10⁹ wei, rendered exactly.
    private static func gwei(_ quantity: EVMQuantity) -> String {
        quantity.decimalString(decimals: 9)
    }

    /// Highest possible fee: `gasLimit × (maxFeePerGas or gasPrice)`.
    public var maximumFeeInEther: String? {
        guard let price = maxFeePerGas ?? gasPrice, let gas = gasLimit.uint64 else { return nil }
        return price.multiplied(by: gas).decimalString(decimals: 18)
    }

    public var checksummedRecipient: String? {
        to.map { EVMAddress.checksummed(addressBytes: $0) }
    }
}
