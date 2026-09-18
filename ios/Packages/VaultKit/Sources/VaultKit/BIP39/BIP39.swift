import Foundation

public enum BIP39Error: Swift.Error, Equatable {
    case invalidEntropyLength(Int)
    case invalidWordCount(Int)
    case unknownWord(String)
    case invalidChecksum
    case seedDerivationFailed
}

/// BIP39 mnemonic generation and seed derivation.
///
/// English wordlist only. Non-English input is rejected rather than guessed at,
/// because a silently mismatched wordlist would change the recovered key.
///
/// The passphrase is fixed to the empty string in v1 wherever the app calls
/// this API; the parameter exists so the restrictions are explicit at the call
/// site rather than implicit (see `CeremonyEntropy.passphrasePolicy`).
public enum BIP39 {
    public static let wordCount = 24
    public static let entropyByteCount = 32
    public static let allowedWordCounts = [12, 15, 18, 21, 24]

    public static var wordlist: [String] { BIP39Wordlist.english }

    /// entropy -> mnemonic (BIP39 §"Generating the mnemonic").
    public static func mnemonic(fromEntropy entropy: [UInt8]) throws -> [String] {
        guard [16, 20, 24, 28, 32].contains(entropy.count) else {
            throw BIP39Error.invalidEntropyLength(entropy.count)
        }

        let checksumBits = entropy.count * 8 / 32
        let hash = SHA256.hash(entropy)

        var bits = [Bool]()
        bits.reserveCapacity(entropy.count * 8 + checksumBits)
        for byte in entropy {
            for shift in stride(from: 7, through: 0, by: -1) {
                bits.append((byte >> UInt8(shift)) & 1 == 1)
            }
        }
        for index in 0..<checksumBits {
            let byte = hash[index / 8]
            let shift = 7 - (index % 8)
            bits.append((byte >> UInt8(shift)) & 1 == 1)
        }

        let wordCount = bits.count / 11
        var words: [String] = []
        words.reserveCapacity(wordCount)
        for wordIndex in 0..<wordCount {
            var value = 0
            for bitIndex in 0..<11 {
                value = (value << 1) | (bits[wordIndex * 11 + bitIndex] ? 1 : 0)
            }
            words.append(BIP39Wordlist.english[value])
        }
        return words
    }

    /// mnemonic -> entropy, with checksum verification.
    public static func entropy(fromMnemonic words: [String]) throws -> [UInt8] {
        guard allowedWordCounts.contains(words.count) else {
            throw BIP39Error.invalidWordCount(words.count)
        }

        var bits = [Bool]()
        bits.reserveCapacity(words.count * 11)
        for word in words {
            guard let index = BIP39Wordlist.index[word] else {
                throw BIP39Error.unknownWord(word)
            }
            for shift in stride(from: 10, through: 0, by: -1) {
                bits.append((index >> shift) & 1 == 1)
            }
        }

        let checksumBits = words.count * 11 / 33
        let entropyBits = words.count * 11 - checksumBits
        var entropy = [UInt8](repeating: 0, count: entropyBits / 8)
        for (index, bit) in bits.prefix(entropyBits).enumerated() where bit {
            entropy[index / 8] |= UInt8(1 << (7 - (index % 8)))
        }

        let expectedChecksum = SHA256.hash(entropy)
        for index in 0..<checksumBits {
            let bit = bits[entropyBits + index]
            let byte = expectedChecksum[index / 8]
            let shift = 7 - (index % 8)
            let expected = (byte >> UInt8(shift)) & 1 == 1
            guard bit == expected else { throw BIP39Error.invalidChecksum }
        }

        return entropy
    }

    public static func isValidMnemonic(_ words: [String]) -> Bool {
        (try? entropy(fromMnemonic: words)) != nil
    }

    /// NFKD normalisation, required by BIP39 for both the mnemonic and the
    /// passphrase. For the English wordlist this is a no-op; for a user-supplied
    /// passphrase it is not.
    public static func normalize(_ string: String) -> String {
        string.decomposedStringWithCompatibilityMapping
    }

    public static func seed(mnemonic words: [String], passphrase: String = "") throws -> SensitiveBytes {
        let normalizedMnemonic = normalize(words.joined(separator: " "))
        let normalizedPassphrase = normalize(passphrase)
        let salt = "mnemonic" + normalizedPassphrase

        var derived = try PBKDF2.hmacSHA512(
            password: Array(normalizedMnemonic.utf8),
            salt: Array(salt.utf8),
            iterations: 2048,
            keyLength: 64
        )
        // `SensitiveBytes` copies before this runs, so the flat intermediate is
        // scrubbed on every exit path including a thrown copy failure.
        defer { wipe(&derived) }
        return SensitiveBytes(copying: derived)
    }
}
