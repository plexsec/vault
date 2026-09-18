import Foundation

/// Bech32 / Bech32m (BIP-173 / BIP-350). Only Bech32 (witness version 0) is
/// used by this app for P2WPKH addresses, but Bech32m is implemented because
/// the checksum constant differs and mixing them up silently produces invalid
/// addresses.
public enum Bech32 {
    public enum Encoding {
        case bech32
        case bech32m

        var constant: UInt32 {
            switch self {
            case .bech32: return 1
            case .bech32m: return 0x2bc830a3
            }
        }
    }

    public enum Error: Swift.Error, Equatable {
        case invalidCharacter
        case invalidSeparator
        case invalidChecksum
        case invalidLength
        case invalidPadding
        case invalidHrp
    }

    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)

    public static func encode(hrp: String, data: [UInt8], encoding: Encoding = .bech32) -> String {
        precondition(!hrp.isEmpty)
        let checksum = createChecksum(hrp: hrp, data: data, encoding: encoding)
        var out = hrp.lowercased() + "1"
        for value in data + checksum {
            out.append(Character(UnicodeScalar(charset[Int(value)])))
        }
        return out
    }

    public static func decode(_ string: String) throws -> (hrp: String, data: [UInt8], encoding: Encoding) {
        let lowered = string.lowercased()
        guard lowered == string || string.uppercased() == string else { throw Error.invalidCharacter }
        guard lowered.count <= 90 else { throw Error.invalidLength }

        guard let separator = lowered.lastIndex(of: "1") else { throw Error.invalidSeparator }
        let hrp = String(lowered[lowered.startIndex..<separator])
        let dataPart = String(lowered[lowered.index(after: separator)...])
        guard !hrp.isEmpty, dataPart.count >= 6 else { throw Error.invalidLength }

        // BIP-173: every HRP character must be in the printable ASCII range
        // 33...126. Without this check a string containing spaces or control
        // characters decodes as if the HRP were valid.
        for scalar in hrp.unicodeScalars {
            guard scalar.value >= 33, scalar.value <= 126 else { throw Error.invalidHrp }
        }

        var values: [UInt8] = []
        values.reserveCapacity(dataPart.count)
        for character in dataPart.utf8 {
            guard let index = charset.firstIndex(of: character) else { throw Error.invalidCharacter }
            values.append(UInt8(index))
        }

        let payload = Array(values.dropLast(6))
        let checksum = Array(values.suffix(6))
        let polymod = polymod(expand(hrp) + values)
        let encoding: Encoding
        switch polymod {
        case Encoding.bech32.constant: encoding = .bech32
        case Encoding.bech32m.constant: encoding = .bech32m
        default: throw Error.invalidChecksum
        }
        _ = checksum
        return (hrp, payload, encoding)
    }

    /// General power-of-2 base conversion (BIP-173 reference behaviour).
    public static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) throws -> [UInt8] {
        var accumulator: UInt32 = 0
        var bits = 0
        var out: [UInt8] = []
        let maxValue = UInt32((1 << to) - 1)

        for value in data {
            guard (UInt32(value) >> from) == 0 else { throw Error.invalidPadding }
            accumulator = (accumulator << from) | UInt32(value)
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((accumulator >> bits) & maxValue))
            }
        }

        if pad {
            if bits > 0 {
                out.append(UInt8((accumulator << (to - bits)) & maxValue))
            }
        } else {
            guard bits < from, (accumulator << (to - bits)) & maxValue == 0 else {
                throw Error.invalidPadding
            }
        }
        return out
    }

    private static func expand(_ hrp: String) -> [UInt8] {
        let bytes = Array(hrp.utf8)
        return bytes.map { $0 >> 5 } + [0] + bytes.map { $0 & 31 }
    }

    private static func createChecksum(hrp: String, data: [UInt8], encoding: Encoding) -> [UInt8] {
        let values = expand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let polymod = polymod(values) ^ encoding.constant
        return (0..<6).map { UInt8((polymod >> (5 * (5 - $0))) & 31) }
    }

    private static let generator: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var checksum: UInt32 = 1
        for value in values {
            let top = checksum >> 25
            checksum = (checksum & 0x1ffffff) << 5 ^ UInt32(value)
            for i in 0..<5 where (top >> UInt32(i)) & 1 == 1 {
                checksum ^= generator[i]
            }
        }
        return checksum
    }
}
