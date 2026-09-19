import Foundation

/// Which naming/tag generation to emit.
///
/// BCR-2020-007 was revised: `crypto-hdkey`/`crypto-keypath`/`crypto-coin-info`
/// with tags 303/304/305 became `hdkey`/`keypath`/`coin-info` with tags
/// 40303/40304/40305. The v1 names are deprecated but are what Keystone-derived
/// wallets (MetaMask's QR hardware flow, Rabby, BlueWallet) actually parse, so
/// both are supported and the choice is surfaced in the pairing screen.
public enum URTypeStyle: String, CaseIterable, Codable, Sendable {
    /// Deprecated v1 names/tags — the MetaMask/Keystone-compatible wire format.
    case keystoneLegacy
    /// Current BCR-2020-007 v2 names/tags.
    case v2

    public var displayName: String {
        switch self {
        case .keystoneLegacy: return "crypto-hdkey (legacy, MetaMask/Keystone)"
        case .v2: return "hdkey (current spec)"
        }
    }

    var hdKeyType: String {
        switch self {
        case .keystoneLegacy: return "crypto-hdkey"
        case .v2: return "hdkey"
        }
    }

    var hdKeyTag: UInt64 {
        switch self {
        case .keystoneLegacy: return 303
        case .v2: return 40303
        }
    }

    var keyPathType: String {
        switch self {
        case .keystoneLegacy: return "crypto-keypath"
        case .v2: return "keypath"
        }
    }

    var keyPathTag: UInt64 {
        switch self {
        case .keystoneLegacy: return 304
        case .v2: return 40304
        }
    }

    var coinInfoType: String {
        switch self {
        case .keystoneLegacy: return "crypto-coin-info"
        case .v2: return "coin-info"
        }
    }

    var coinInfoTag: UInt64 {
        switch self {
        case .keystoneLegacy: return 305
        case .v2: return 40305
        }
    }

    var allTypeNames: [String] { [hdKeyType, keyPathType, coinInfoType] }
}

public enum URTypeError: Swift.Error, Equatable {
    case unexpectedType(String)
    case missingField(UInt64)
    case invalidField(UInt64)
    case unsupportedTag(UInt64)
}

/// `coininfo` per BCR-2020-007. `type` is a SLIP-44 coin type with the high bit
/// cleared; `network` is a coin-specific network identifier.
public struct CoinInfo: Equatable {
    /// SLIP-44 coin type. Default (BTC) is 0 and is omitted on the wire.
    public var type: UInt32
    /// 0 = mainnet. Omitted on the wire when 0.
    public var network: Int

    public init(type: UInt32, network: Int = 0) {
        self.type = type
        self.network = network
    }

    func cbor(style: URTypeStyle) -> CBOR {
        var entries: [CBORMapEntry] = []
        if type != 0 {
            entries.append(CBORMapEntry(.unsigned(1), .unsigned(UInt64(type))))
        }
        if network != 0 {
            entries.append(CBORMapEntry(.unsigned(2), .unsigned(UInt64(network))))
        }
        return .tagged(style.coinInfoTag, .map(entries))
    }

    init?(cbor: CBOR, style: URTypeStyle) {
        guard let tagged = cbor.taggedValue, tagged.tag == style.coinInfoTag,
              let map = tagged.value.mapValue
        else { return nil }
        let type = map.first { $0.key.unsignedValue == 1 }?.value.unsignedValue ?? 0
        let network = map.first { $0.key.unsignedValue == 2 }?.value.unsignedValue ?? 0
        self.init(type: UInt32(type), network: Int(network))
    }
}

/// `keypath` per BCR-2020-007: components plus optional source fingerprint/depth.
public struct URKeyPath: Equatable {
    public var components: [DerivationPath.Component]
    public var sourceFingerprint: UInt32?
    public var depth: UInt8?

    public init(components: [DerivationPath.Component], sourceFingerprint: UInt32? = nil, depth: UInt8? = nil) {
        self.components = components
        self.sourceFingerprint = sourceFingerprint
        self.depth = depth
    }

    public init(path: DerivationPath, sourceFingerprint: UInt32? = nil, depth: UInt8? = nil) {
        self.init(components: path.components, sourceFingerprint: sourceFingerprint, depth: depth)
    }

    func cbor(style: URTypeStyle) -> CBOR {
        var componentValues: [CBOR] = []
        componentValues.reserveCapacity(components.count * 2)
        for component in components {
            switch component {
            case .hardened(let value):
                componentValues.append(.unsigned(UInt64(value)))
                componentValues.append(.trueValue)
            case .normal(let value):
                componentValues.append(.unsigned(UInt64(value)))
                componentValues.append(.falseValue)
            }
        }
        var entries: [CBORMapEntry] = [CBORMapEntry(.unsigned(1), .array(componentValues))]
        if let sourceFingerprint {
            entries.append(CBORMapEntry(.unsigned(2), .unsigned(UInt64(sourceFingerprint))))
        }
        if let depth {
            entries.append(CBORMapEntry(.unsigned(3), .unsigned(UInt64(depth))))
        }
        return .tagged(style.keyPathTag, .map(entries))
    }

    init?(cbor: CBOR, style: URTypeStyle) {
        guard let tagged = cbor.taggedValue, tagged.tag == style.keyPathTag,
              let map = tagged.value.mapValue,
              let componentsValue = map.first(where: { $0.key.unsignedValue == 1 })?.value.arrayValue,
              componentsValue.count % 2 == 0
        else { return nil }

        var parsed: [DerivationPath.Component] = []
        parsed.reserveCapacity(componentsValue.count / 2)
        for index in stride(from: 0, to: componentsValue.count, by: 2) {
            guard let value = componentsValue[index].unsignedValue,
                  let hardened = componentsValue[index + 1].boolValue
            else { return nil }
            parsed.append(hardened ? .hardened(UInt32(value)) : .normal(UInt32(value)))
        }

        let fingerprint = map.first { $0.key.unsignedValue == 2 }?.value.unsignedValue
        let depth = map.first { $0.key.unsignedValue == 3 }?.value.unsignedValue
        self.init(
            components: parsed,
            sourceFingerprint: fingerprint.map { UInt32($0) },
            depth: depth.map { UInt8($0) }
        )
    }
}

/// `hdkey` per BCR-2020-007 (v1 `crypto-hdkey` / v2 `hdkey`).
///
/// Only the fields this app produces or consumes are modelled; unknown keys are
/// preserved so a round trip does not silently drop data.
///
/// Two algorithms are carried by this one type. The curve is discriminated by
/// the length of `key-data` (33 bytes = compressed secp256k1 point, 32 bytes =
/// raw Ed25519 point) and reinforced by `use-info` (SLIP-44 coin type 0 vs 501).
/// BCR-2020-007 defines no explicit curve field, so this is the convention this
/// project relies on; it is listed as an interop item in
/// docs/m0-hardware-verification.md.
public struct HDKey: Equatable {
    public var isMaster: Bool
    public var isPrivate: Bool
    /// 33 bytes: compressed SEC1 public key (secp256k1), or 32 bytes: raw
    /// Ed25519 public key, or `0x00 || ser256(k)` when private.
    public var keyData: [UInt8]
    /// Present only when further children may be derived *from this key*.
    public var chainCode: [UInt8]?
    public var useInfo: CoinInfo?
    public var origin: URKeyPath?
    public var children: URKeyPath?
    public var parentFingerprint: UInt32?
    public var name: String?
    public var note: String?

    public init(
        isMaster: Bool = false,
        isPrivate: Bool = false,
        keyData: [UInt8],
        chainCode: [UInt8]? = nil,
        useInfo: CoinInfo? = nil,
        origin: URKeyPath? = nil,
        children: URKeyPath? = nil,
        parentFingerprint: UInt32? = nil,
        name: String? = nil,
        note: String? = nil
    ) {
        self.isMaster = isMaster
        self.isPrivate = isPrivate
        self.keyData = keyData
        self.chainCode = chainCode
        self.useInfo = useInfo
        self.origin = origin
        self.children = children
        self.parentFingerprint = parentFingerprint
        self.name = name
        self.note = note
    }

    public enum ValidationError: Swift.Error, Equatable {
        case invalidKeyDataLength(Int)
        case invalidChainCodeLength(Int)
        case missingChainCodeForMaster
    }

    public func validate() throws {
        // 33 = compressed secp256k1 point; 32 = raw Ed25519 point.
        guard keyData.count == 33 || keyData.count == 32 else {
            throw ValidationError.invalidKeyDataLength(keyData.count)
        }
        if let chainCode, chainCode.count != 32 {
            throw ValidationError.invalidChainCodeLength(chainCode.count)
        }
        // Per BCR-2020-007 the `master-key` form is `(is-master, key-data,
        // chain-code)`: it carries private key material (0x00 || ser256(k)) but
        // does NOT set `is-private`. Published test vector 1 relies on this, so
        // is-master must not imply is-private.
        if isMaster, chainCode == nil {
            throw ValidationError.missingChainCodeForMaster
        }
    }

    /// True when `key-data` is a raw 32-byte Ed25519 point rather than a
    /// 33-byte compressed secp256k1 point.
    public var isEd25519: Bool { keyData.count == 32 }

    func cbor(style: URTypeStyle) -> CBOR {
        var entries: [CBORMapEntry] = []
        if isMaster {
            entries.append(CBORMapEntry(.unsigned(1), .trueValue))
        }
        if isPrivate {
            entries.append(CBORMapEntry(.unsigned(2), .trueValue))
        }
        entries.append(CBORMapEntry(.unsigned(3), .bytes(Data(keyData))))
        if let chainCode {
            entries.append(CBORMapEntry(.unsigned(4), .bytes(Data(chainCode))))
        }
        if let useInfo {
            entries.append(CBORMapEntry(.unsigned(5), useInfo.cbor(style: style)))
        }
        if let origin {
            entries.append(CBORMapEntry(.unsigned(6), origin.cbor(style: style)))
        }
        if let children {
            entries.append(CBORMapEntry(.unsigned(7), children.cbor(style: style)))
        }
        if let parentFingerprint {
            entries.append(CBORMapEntry(.unsigned(8), .unsigned(UInt64(parentFingerprint))))
        }
        if let name {
            entries.append(CBORMapEntry(.unsigned(9), .text(name)))
        }
        if let note {
            entries.append(CBORMapEntry(.unsigned(10), .text(note)))
        }
        return .map(entries)
    }

    init(cbor: CBOR, style: URTypeStyle) throws {
        guard let map = cbor.mapValue else { throw URTypeError.invalidField(0) }
        let lookup: (UInt64) -> CBOR? = { key in
            map.first { $0.key.unsignedValue == key }?.value
        }

        guard let keyData = lookup(3)?.bytesValue else { throw URTypeError.missingField(3) }
        self.isMaster = lookup(1)?.boolValue ?? false
        self.isPrivate = lookup(2)?.boolValue ?? false
        self.keyData = [UInt8](keyData)
        self.chainCode = lookup(4)?.bytesValue.map { [UInt8]($0) }
        self.parentFingerprint = lookup(8)?.unsignedValue.map { UInt32($0) }
        self.name = lookup(9)?.textValue
        self.note = lookup(10)?.textValue

        if let useInfoValue = lookup(5) {
            guard let parsed = CoinInfo(cbor: useInfoValue, style: style) else {
                throw URTypeError.invalidField(5)
            }
            self.useInfo = parsed
        }
        if let originValue = lookup(6) {
            guard let parsed = URKeyPath(cbor: originValue, style: style) else {
                throw URTypeError.invalidField(6)
            }
            self.origin = parsed
        }
        if let childrenValue = lookup(7) {
            guard let parsed = URKeyPath(cbor: childrenValue, style: style) else {
                throw URTypeError.invalidField(7)
            }
            self.children = parsed
        }
    }

    /// Integer CBOR keys this implementation understands. Anything else is
    /// reported so callers can refuse rather than silently drop data
    /// (design.md §6.4 — the Desktop must alarm on unknown UR fields).
    public static let knownFieldKeys: Set<UInt64> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    public static func unknownFieldKeys(in cbor: CBOR) -> [UInt64] {
        guard let map = cbor.mapValue else { return [] }
        return map.compactMap { entry in
            guard let key = entry.key.unsignedValue, !knownFieldKeys.contains(key) else { return nil }
            return key
        }
    }
}

// MARK: - UR bridging

public extension HDKey {
    func ur(style: URTypeStyle) throws -> UR {
        try validate()
        return try UR(type: style.hdKeyType, cbor: cbor(style: style))
    }

    init(ur: UR) throws {
        guard let style = URTypeStyle.allCases.first(where: { $0.hdKeyType == ur.type }) else {
            throw URTypeError.unexpectedType(ur.type)
        }
        try self.init(cbor: ur.cbor, style: style)
    }
}
