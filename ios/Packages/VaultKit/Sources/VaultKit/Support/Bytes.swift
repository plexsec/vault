import Foundation

/// Hex encoding/decoding. Non-secret data only; secret material must never be
/// converted to a `String` (see `SensitiveBytes`).
public enum Hex {
    private static let digits = Array("0123456789abcdef".utf8)
    private static let upperDigits = Array("0123456789ABCDEF".utf8)

    public static func encode(_ bytes: [UInt8]) -> String {
        encode(bytes, digits)
    }

    public static func encode(_ bytes: Data) -> String {
        encode([UInt8](bytes), digits)
    }

    public static func encodeUpper(_ bytes: [UInt8]) -> String {
        encode(bytes, upperDigits)
    }

    private static func encode(_ bytes: [UInt8], _ table: [UInt8]) -> String {
        var out = [UInt8]()
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(table[Int(b >> 4)])
            out.append(table[Int(b & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    public enum Error: Swift.Error, Equatable {
        case oddLength
        case invalidCharacter
    }

    public static func decode(_ string: String) throws -> [UInt8] {
        try decode(string, allowPrefix: false)
    }

    /// Accepts an optional `0x` / `0X` prefix (used for user-entered addresses/hashes).
    public static func decodeUserInput(_ string: String) throws -> [UInt8] {
        try decode(string, allowPrefix: true)
    }

    private static func decode(_ string: String, allowPrefix: Bool) throws -> [UInt8] {
        var scalars = Array(string.utf8)
        if allowPrefix, scalars.count >= 2, scalars[0] == 0x30, scalars[1] == 0x78 || scalars[1] == 0x58 {
            scalars.removeFirst(2)
        }
        guard scalars.count % 2 == 0 else { throw Error.oddLength }
        var out = [UInt8]()
        out.reserveCapacity(scalars.count / 2)
        var index = 0
        while index < scalars.count {
            guard let hi = nibble(scalars[index]), let lo = nibble(scalars[index + 1]) else {
                throw Error.invalidCharacter
            }
            out.append(hi << 4 | lo)
            index += 2
        }
        return out
    }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }
}

extension Array where Element == UInt8 {
    public var hexString: String { Hex.encode(self) }
}

extension Data {
    /// Lowercase hex. Present because the ported BC-UR sources use it.
    public var hex: String { Hex.encode(self) }
}

// NOTE: `UInt32.serialized` (big-endian 4 bytes) and the generic `deserialize(_:_:)`
// helper are provided by the ported BC-UR sources in UR/Bytewords.swift, which
// carries its own `Serializable` protocol adapted from DCBOR. They are
// deliberately not redefined here to avoid an ambiguous redeclaration.

/// CRC-32/ISO-HDLC (reflected, polynomial 0xEDB88320), as used by BC Bytewords.
public enum CRC32 {
    static let table: [UInt32] = {
        (0...255).map { i -> UInt32 in
            (0..<8).reduce(UInt32(i)) { c, _ in
                (c % 2 == 0) ? (c >> 1) : (0xEDB88320 ^ (c >> 1))
            }
        }
    }()

    public static func checksum(_ data: Data) -> UInt32 {
        ~(data.reduce(~UInt32(0)) { crc, byte in
            (crc >> 8) ^ table[(Int(crc) ^ Int(byte)) & 0xFF]
        })
    }

    public static func checksum(_ data: [UInt8]) -> UInt32 {
        checksum(Data(data))
    }

    public static func checksum(_ string: String) -> UInt32 {
        checksum(Data(string.utf8))
    }
}

extension String {
    var utf8Data: Data { Data(utf8) }

    func chunked(into size: Int) -> [String] {
        var result: [String] = []
        var chunk = ""
        for c in self {
            chunk.append(c)
            if chunk.count == size {
                result.append(chunk)
                chunk = ""
            }
        }
        if !chunk.isEmpty { result.append(chunk) }
        return result
    }
}
