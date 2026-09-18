import Foundation

public enum AddressError: Swift.Error, Equatable {
    case invalidPublicKey
    case invalidAddress
    case unsupportedNetwork
}

/// Ethereum address derivation and EIP-55 checksumming.
public enum EVMAddress {
    public static let length = 20

    /// Address bytes from a SEC1 public key (compressed or uncompressed).
    /// The keccak input is the 64-byte X||Y body, i.e. the uncompressed key
    /// with its 0x04 prefix removed.
    public static func bytes(fromPublicKey publicKey: [UInt8]) throws -> [UInt8] {
        let uncompressed: [UInt8]
        switch publicKey.count {
        case Secp256k1.compressedPublicKeyLength:
            uncompressed = try Secp256k1.uncompressedPublicKey(fromCompressed: publicKey)
        case Secp256k1.uncompressedPublicKeyLength:
            uncompressed = publicKey
        default:
            throw AddressError.invalidPublicKey
        }
        precondition(uncompressed[0] == 0x04)
        let digest = Keccak256.hash(Array(uncompressed[1...]))
        return Array(digest.suffix(length))
    }

    /// `0x`-prefixed EIP-55 checksummed address.
    public static func checksummed(fromPublicKey publicKey: [UInt8]) throws -> String {
        checksummed(addressBytes: try bytes(fromPublicKey: publicKey))
    }

    /// EIP-55: uppercase a hex digit when the corresponding keccak256 nibble is >= 8.
    public static func checksummed(addressBytes: [UInt8]) -> String {
        precondition(addressBytes.count == length)
        let lower = Hex.encode(addressBytes)
        let hash = Keccak256.hash(Array(lower.utf8))
        var out = "0x"
        out.reserveCapacity(42)
        for (index, character) in lower.enumerated() {
            let nibble = index % 2 == 0 ? (hash[index / 2] >> 4) : (hash[index / 2] & 0x0f)
            if character.isNumber || nibble < 8 {
                out.append(character)
            } else {
                out.append(Character(character.uppercased()))
            }
        }
        return out
    }

    /// Validates length, hex and EIP-55 placement. Accepts an all-lowercase or
    /// all-uppercase address as valid-but-unchecksummed, matching common tooling.
    public static func isValid(_ string: String) -> Bool {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") else { return false }
        let body = String(trimmed.dropFirst(2))
        guard body.count == length * 2 else { return false }
        guard let bytes = try? Hex.decode(body) else { return false }
        guard bytes.count == length else { return false }

        let expected = checksummed(addressBytes: bytes)
        let expectedBody = String(expected.dropFirst(2))
        if body == body.lowercased() || body == body.uppercased() { return true }
        return body == expectedBody
    }

    /// Normalises user input for byte-for-byte comparison in the §4.2 step 6b
    /// cross-check (case-insensitive, `0x` optional, whitespace stripped).
    public static func normalisedForComparison(_ string: String) -> String {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return trimmed.hasPrefix("0x") ? String(trimmed.dropFirst(2)) : trimmed
    }
}

public enum BitcoinNetwork: String, Sendable {
    case mainnet
    case testnet

    public var bech32HRP: String {
        switch self {
        case .mainnet: return "bc"
        case .testnet: return "tb"
        }
    }
}

/// Bitcoin address derivation. Only native segwit P2WPKH is needed: the
/// provisioning ceremony derives at `m/84'/0'/0'/0/0` (design.md §4.2 step 6).
public enum BitcoinAddress {
    public static func p2wpkh(publicKeyCompressed: [UInt8], network: BitcoinNetwork = .mainnet) throws -> String {
        guard publicKeyCompressed.count == Secp256k1.compressedPublicKeyLength else {
            throw AddressError.invalidPublicKey
        }
        let program = RIPEMD160.hash160(publicKeyCompressed)
        precondition(program.count == 20)

        // Witness version 0 + 20-byte program, converted to 5-bit groups.
        let data = try Bech32.convertBits([0] + program, from: 8, to: 5, pad: true)
        return Bech32.encode(hrp: network.bech32HRP, data: data, encoding: .bech32)
    }

    /// Case-insensitive structural validation (bech32 + witness v0 + 20 bytes).
    ///
    /// The witness version and the program are encoded as ONE 5-bit stream, so
    /// they cannot be split before converting back to bytes: a 21-byte payload
    /// (version + 20-byte program) becomes 34 five-bit groups, and dropping the
    /// first group would leave a 165-bit stream that fails the padding check.
    public static func isValidP2WPKH(_ string: String, network: BitcoinNetwork = .mainnet) -> Bool {
        guard let decoded = try? Bech32.decode(string.trimmingCharacters(in: .whitespaces)) else { return false }
        guard decoded.hrp == network.bech32HRP, decoded.encoding == .bech32 else { return false }
        guard let bytes = try? Bech32.convertBits(decoded.data, from: 5, to: 8, pad: false) else {
            return false
        }
        return bytes.count == 21 && bytes[0] == 0
    }

    public static func normalisedForComparison(_ string: String) -> String {
        string.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
