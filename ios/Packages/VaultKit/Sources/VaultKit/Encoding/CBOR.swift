import Foundation

/// A minimal deterministic CBOR (dCBOR) codec: exactly the subset BC-UR needs.
///
/// Determinism rules enforced here (required for UR interoperability):
/// * shortest-form integer/string/array/map headers (no indefinite lengths),
/// * map keys sorted bytewise by their encoded form,
/// * definite-length byte and text strings,
/// * only the simple values that appear in practice (false/true/null/undefined).
///
/// This is a *codec*, not a general CBOR library; unsupported inputs are
/// rejected rather than coerced.
public struct CBORMapEntry: Equatable {
    public let key: CBOR
    public let value: CBOR

    public init(_ key: CBOR, _ value: CBOR) {
        self.key = key
        self.value = value
    }
}

public indirect enum CBOR: Equatable {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([CBORMapEntry])
    case tagged(UInt64, CBOR)
    case simple(UInt8)

    public static let falseValue = CBOR.simple(20)
    public static let trueValue = CBOR.simple(21)
    public static let nullValue = CBOR.simple(22)
    public static let undefinedValue = CBOR.simple(23)

    public enum DecodingError: Swift.Error, Equatable {
        case unexpectedEnd
        case unsupportedMajorType(UInt8)
        case indefiniteLengthNotSupported
        case invalidUTF8
        case trailingBytes
        case nestingTooDeep
        case invalidSimpleValue(UInt8)
    }
}

// MARK: - Encoding

public extension CBOR {
    /// Deterministic CBOR serialisation.
    var cborData: Data {
        var out = Data()
        encode(into: &out, depth: 0)
        return out
    }

    private func encode(into out: inout Data, depth: Int) {
        precondition(depth < 32, "CBOR nesting too deep")
        switch self {
        case .unsigned(let value):
            CBOR.writeHeader(major: 0, value: value, into: &out)
        case .negative(let value):
            // CBOR negative integers encode as -1 - n.
            precondition(value < 0)
            CBOR.writeHeader(major: 1, value: UInt64(-1 - value), into: &out)
        case .bytes(let data):
            CBOR.writeHeader(major: 2, value: UInt64(data.count), into: &out)
            out.append(data)
        case .text(let string):
            let utf8 = Data(string.utf8)
            CBOR.writeHeader(major: 3, value: UInt64(utf8.count), into: &out)
            out.append(utf8)
        case .array(let items):
            CBOR.writeHeader(major: 4, value: UInt64(items.count), into: &out)
            for item in items {
                item.encode(into: &out, depth: depth + 1)
            }
        case .map(let entries):
            CBOR.writeHeader(major: 5, value: UInt64(entries.count), into: &out)
            // dCBOR: keys sorted by their encoded bytes. Without this, the same
            // logical structure would produce different UR strings and break
            // byte-for-byte comparison against the published test vectors.
            let keyed = entries.map { (key: $0.key.cborData, entry: $0) }
            let sorted = keyed.sorted { lhs, rhs in
                lhs.key.lexicographicallyPrecedes(rhs.key)
            }
            for item in sorted {
                item.entry.key.encode(into: &out, depth: depth + 1)
                item.entry.value.encode(into: &out, depth: depth + 1)
            }
        case .tagged(let tag, let value):
            CBOR.writeHeader(major: 6, value: tag, into: &out)
            value.encode(into: &out, depth: depth + 1)
        case .simple(let value):
            // Major type 7: simple values 20-23 (false/true/null/undefined) encode
            // directly as 0xF4-0xF7. Omitting the 0xE0 prefix here silently
            // produces a small *unsigned integer* instead of a boolean, which is
            // a completely different CBOR value.
            if value < 24 {
                out.append(0xE0 | value)
            } else {
                out.append(0xF8)
                out.append(value)
            }
        }
    }

    private static func writeHeader(major: UInt8, value: UInt64, into out: inout Data) {
        let prefix = major << 5
        switch value {
        case 0..<24:
            out.append(prefix | UInt8(value))
        case 24..<0x100:
            out.append(prefix | 24)
            out.append(UInt8(value))
        case 0x100..<0x10000:
            out.append(prefix | 25)
            out.append(UInt8((value >> 8) & 0xff))
            out.append(UInt8(value & 0xff))
        case 0x10000..<0x1_0000_0000:
            out.append(prefix | 26)
            out.append(UInt8((value >> 24) & 0xff))
            out.append(UInt8((value >> 16) & 0xff))
            out.append(UInt8((value >> 8) & 0xff))
            out.append(UInt8(value & 0xff))
        default:
            out.append(prefix | 27)
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((value >> UInt64(shift)) & 0xff))
            }
        }
    }
}

// MARK: - Decoding

public extension CBOR {
    init(_ data: Data) throws {
        var decoder = Decoder(data: data)
        let value = try decoder.decodeValue(depth: 0)
        guard decoder.isAtEnd else { throw DecodingError.trailingBytes }
        self = value
    }

    init(_ bytes: [UInt8]) throws {
        try self.init(Data(bytes))
    }

    private struct Decoder {
        let data: Data
        var offset: Int = 0

        init(data: Data) {
            self.data = data
        }

        var isAtEnd: Bool { offset >= data.count }

        mutating func readByte() throws -> UInt8 {
            guard offset < data.count else { throw DecodingError.unexpectedEnd }
            let byte = data[data.startIndex + offset]
            offset += 1
            return byte
        }

        mutating func read(_ count: Int) throws -> Data {
            guard count >= 0, offset + count <= data.count else { throw DecodingError.unexpectedEnd }
            let start = data.startIndex + offset
            let slice = data[start..<(start + count)]
            offset += count
            return Data(slice)
        }

        mutating func readUInt(additional: UInt8) throws -> UInt64 {
            switch additional {
            case 0..<24:
                return UInt64(additional)
            case 24:
                return UInt64(try readByte())
            case 25:
                let bytes = try read(2)
                return UInt64(bytes[bytes.startIndex]) << 8 | UInt64(bytes[bytes.startIndex + 1])
            case 26:
                let bytes = try read(4)
                var value: UInt64 = 0
                for i in 0..<4 { value = value << 8 | UInt64(bytes[bytes.startIndex + i]) }
                return value
            case 27:
                let bytes = try read(8)
                var value: UInt64 = 0
                for i in 0..<8 { value = value << 8 | UInt64(bytes[bytes.startIndex + i]) }
                return value
            case 31:
                throw DecodingError.indefiniteLengthNotSupported
            default:
                throw DecodingError.unsupportedMajorType(additional)
            }
        }

        mutating func decodeValue(depth: Int) throws -> CBOR {
            guard depth < 32 else { throw DecodingError.nestingTooDeep }
            let initial = try readByte()
            let major = initial >> 5
            let additional = initial & 0x1f

            switch major {
            case 0:
                return .unsigned(try readUInt(additional: additional))
            case 1:
                let magnitude = try readUInt(additional: additional)
                guard magnitude <= UInt64(Int64.max) else { throw DecodingError.unsupportedMajorType(1) }
                return .negative(-1 - Int64(magnitude))
            case 2:
                let length = try readUInt(additional: additional)
                guard length <= UInt64(Int.max) else { throw DecodingError.unsupportedMajorType(2) }
                return .bytes(try read(Int(length)))
            case 3:
                let length = try readUInt(additional: additional)
                guard length <= UInt64(Int.max) else { throw DecodingError.unsupportedMajorType(3) }
                let raw = try read(Int(length))
                guard let string = String(data: raw, encoding: .utf8) else { throw DecodingError.invalidUTF8 }
                return .text(string)
            case 4:
                let count = try readUInt(additional: additional)
                guard count <= 65_536 else { throw DecodingError.nestingTooDeep }
                var items: [CBOR] = []
                items.reserveCapacity(Int(count))
                for _ in 0..<count {
                    items.append(try decodeValue(depth: depth + 1))
                }
                return .array(items)
            case 5:
                let count = try readUInt(additional: additional)
                guard count <= 65_536 else { throw DecodingError.nestingTooDeep }
                var entries: [CBORMapEntry] = []
                entries.reserveCapacity(Int(count))
                for _ in 0..<count {
                    let key = try decodeValue(depth: depth + 1)
                    let value = try decodeValue(depth: depth + 1)
                    entries.append(CBORMapEntry(key, value))
                }
                return .map(entries)
            case 6:
                let tag = try readUInt(additional: additional)
                let value = try decodeValue(depth: depth + 1)
                return .tagged(tag, value)
            default:
                switch additional {
                case 20, 21, 22, 23:
                    return .simple(additional)
                case 24:
                    let value = try readByte()
                    return .simple(value)
                case 31:
                    throw DecodingError.indefiniteLengthNotSupported
                default:
                    throw DecodingError.invalidSimpleValue(additional)
                }
            }
        }
    }
}

// MARK: - Typed accessors

public extension CBOR {
    var unsignedValue: UInt64? {
        if case .unsigned(let value) = self { return value }
        return nil
    }

    var signedValue: Int64? {
        switch self {
        case .unsigned(let value): return value <= UInt64(Int64.max) ? Int64(value) : nil
        case .negative(let value): return value
        default: return nil
        }
    }

    var bytesValue: Data? {
        if case .bytes(let data) = self { return data }
        return nil
    }

    var textValue: String? {
        if case .text(let string) = self { return string }
        return nil
    }

    var arrayValue: [CBOR]? {
        if case .array(let items) = self { return items }
        return nil
    }

    var mapValue: [CBORMapEntry]? {
        if case .map(let entries) = self { return entries }
        return nil
    }

    var taggedValue: (tag: UInt64, value: CBOR)? {
        if case .tagged(let tag, let value) = self { return (tag, value) }
        return nil
    }

    var boolValue: Bool? {
        switch self {
        case .simple(20): return false
        case .simple(21): return true
        default: return nil
        }
    }

    /// Numeric lookup in a map whose keys are unsigned integers.
    subscript(unsignedKey key: UInt64) -> CBOR? {
        guard case .map(let entries) = self else { return nil }
        return entries.first { $0.key.unsignedValue == key }?.value
    }
}

/// Types that can be lowered to CBOR. Mirrors the small part of the Blockchain
/// Commons `CBOREncodable` surface that the ported UR sources rely on.
public protocol CBOREncodable {
    var cbor: CBOR { get }
}

public protocol CBORDecodable {
    init(cbor: CBOR) throws
}

extension UInt64: CBOREncodable {
    public var cbor: CBOR { .unsigned(self) }
}

extension UInt32: CBOREncodable {
    public var cbor: CBOR { .unsigned(UInt64(self)) }
}

extension UInt8: CBOREncodable {
    public var cbor: CBOR { .unsigned(UInt64(self)) }
}

extension Int: CBOREncodable {
    public var cbor: CBOR { self >= 0 ? .unsigned(UInt64(self)) : .negative(Int64(self)) }
}

extension String: CBOREncodable {
    public var cbor: CBOR { .text(self) }
}

extension Data: CBOREncodable {
    public var cbor: CBOR { .bytes(self) }
}

extension Bool: CBOREncodable {
    public var cbor: CBOR { self ? .trueValue : .falseValue }
}

extension Array: CBOREncodable where Element: CBOREncodable {
    public var cbor: CBOR { .array(map(\.cbor)) }
}
