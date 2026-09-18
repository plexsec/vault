import Foundation

/// Base58 and Base58Check (Bitcoin's alphabet + 4-byte double-SHA256 checksum).
/// Used to reproduce BIP32's `xprv`/`xpub` serialisation byte-for-byte, which is
/// what lets the published BIP32 test vectors be used as end-to-end tests of
/// depth, parent fingerprint, child number, chain code and key data.
public enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    public enum Error: Swift.Error, Equatable {
        case invalidCharacter
        case invalidChecksum
        case tooShort
    }

    public static func encode(_ bytes: [UInt8]) -> String {
        var zeros = 0
        for byte in bytes {
            if byte == 0 { zeros += 1 } else { break }
        }

        var digits: [UInt8] = []
        digits.reserveCapacity(bytes.count * 138 / 100 + 1)
        for byte in bytes {
            var carry = Int(byte)
            for i in 0..<digits.count {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }

        var out = String(repeating: "1", count: zeros)
        for digit in digits.reversed() {
            out.append(Character(UnicodeScalar(alphabet[Int(digit)])))
        }
        return out
    }

    public static func decode(_ string: String) throws -> [UInt8] {
        var zeros = 0
        for character in string {
            if character == "1" { zeros += 1 } else { break }
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(string.count * 733 / 1000 + 1)
        for character in string.utf8 {
            guard let value = alphabet.firstIndex(of: character) else {
                throw Error.invalidCharacter
            }
            var carry = Int(value)
            for i in 0..<bytes.count {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xff))
                carry >>= 8
            }
        }

        return [UInt8](repeating: 0, count: zeros) + bytes.reversed()
    }

    public static func encodeCheck(_ payload: [UInt8]) -> String {
        let checksum = Array(SHA256.hash(SHA256.hash(payload)).prefix(4))
        return encode(payload + checksum)
    }

    public static func decodeCheck(_ string: String) throws -> [UInt8] {
        let decoded = try decode(string)
        guard decoded.count >= 5 else { throw Error.tooShort }
        let payload = Array(decoded.dropLast(4))
        let checksum = Array(decoded.suffix(4))
        let expected = Array(SHA256.hash(SHA256.hash(payload)).prefix(4))
        guard checksum == expected else { throw Error.invalidChecksum }
        return payload
    }
}
