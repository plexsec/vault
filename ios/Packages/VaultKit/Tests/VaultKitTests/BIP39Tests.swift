import XCTest
@testable import VaultKit

final class BIP39Tests: XCTestCase {

    /// The committed wordlist must be byte-identical to the official BIP39
    /// English list. Any edit to the generated Swift file breaks this.
    func testWordlistMatchesOfficialFileHash() throws {
        let fixture = try FixtureLoader.data("bip39_english", extension: "txt")
        XCTAssertEqual(
            Hex.encode(SHA256.hash(fixture)),
            BIP39Wordlist.englishFileSHA256,
            "BIP39 english.txt fixture was modified"
        )
        XCTAssertEqual(BIP39Wordlist.english.count, 2048)
        XCTAssertEqual(Set(BIP39Wordlist.english).count, 2048, "duplicate words in wordlist")

        // The Swift array must equal the fixture words, in order.
        let words = try FixtureLoader.text("bip39_english", extension: "txt")
            .split(separator: "\n")
            .map(String.init)
            .filter { !$0.isEmpty }
        XCTAssertEqual(words, BIP39Wordlist.english)
        XCTAssertEqual(BIP39.wordCount, 24)
    }

    /// Official Trezor vectors: entropy <-> mnemonic <-> seed (passphrase TREZOR).
    func testOfficialTrezorVectors() throws {
        guard let root = try FixtureLoader.json("bip39_trezor_vectors", extension: "json") as? [String: Any],
              let english = root["english"] as? [[String]]
        else {
            return XCTFail("malformed bip39 fixture")
        }
        XCTAssertEqual(english.count, 24)

        for entry in english {
            let entropyHex = entry[0]
            let mnemonic = entry[1]
            let seedHex = entry[2]
            let words = mnemonic.split(separator: " ").map(String.init)
            let entropy = Array(try Hex.decode(entropyHex))

            XCTAssertEqual(try BIP39.mnemonic(fromEntropy: entropy), words, "mnemonic for \(entropyHex)")
            XCTAssertEqual(try BIP39.entropy(fromMnemonic: words), entropy, "entropy for \(mnemonic.prefix(24))")
            XCTAssertTrue(BIP39.isValidMnemonic(words))

            let seed = try BIP39.seed(mnemonic: words, passphrase: "TREZOR")
            XCTAssertEqual(
                Hex.encode(seed.materializedCopy()),
                seedHex,
                "seed for \(mnemonic.prefix(24))"
            )
        }
    }

    func testChecksumRejection() {
        // "abandon" x12 is valid; changing the last word to another 12th word
        // that keeps the checksum invalid must be rejected.
        let valid = Array(repeating: "abandon", count: 11) + ["about"]
        XCTAssertTrue(BIP39.isValidMnemonic(valid))

        let invalid = Array(repeating: "abandon", count: 12)
        XCTAssertFalse(BIP39.isValidMnemonic(invalid), "abandon x12 must fail the checksum")

        let tampered = Array(repeating: "abandon", count: 11) + ["aback"]
        XCTAssertFalse(BIP39.isValidMnemonic(tampered))
    }

    func testUnknownWordAndWordCountRejection() {
        XCTAssertThrowsError(try BIP39.entropy(fromMnemonic: Array(repeating: "notaword", count: 12))) { error in
            XCTAssertEqual(error as? BIP39Error, .unknownWord("notaword"))
        }
        XCTAssertThrowsError(try BIP39.entropy(fromMnemonic: ["abandon", "about"])) { error in
            XCTAssertEqual(error as? BIP39Error, .invalidWordCount(2))
        }
        XCTAssertThrowsError(try BIP39.mnemonic(fromEntropy: [UInt8](repeating: 0, count: 17))) { error in
            XCTAssertEqual(error as? BIP39Error, .invalidEntropyLength(17))
        }
    }

    /// Non-English wordlists must be rejected rather than silently mis-derived.
    func testNonEnglishWordsAreRejected() {
        let chinese = "的 的 的 的 的 的 的 的 的 的 的 的".split(separator: " ").map(String.init)
        XCTAssertFalse(BIP39.isValidMnemonic(chinese))
        XCTAssertThrowsError(try BIP39.entropy(fromMnemonic: chinese))
    }

    /// 24 words = 256 bits of entropy + 8 bits of checksum.
    func testGeneratedMnemonicRoundTripAndLength() throws {
        var entropy = [UInt8](repeating: 0, count: BIP39.entropyByteCount)
        for i in 0..<entropy.count { entropy[i] = UInt8(i &* 7 &+ 3) }
        let words = try BIP39.mnemonic(fromEntropy: entropy)
        XCTAssertEqual(words.count, 24)
        XCTAssertEqual(try BIP39.entropy(fromMnemonic: words), entropy)
    }

    func testNormalisationIsNFKD() {
        // "é" precomposed vs decomposed must normalise to the same string.
        let precomposed = "caf\u{00E9}"
        let decomposed = "cafe\u{0301}"
        XCTAssertEqual(BIP39.normalize(precomposed), BIP39.normalize(decomposed))
    }
}
