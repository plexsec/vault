import XCTest
@testable import VaultKit

final class AddressTests: XCTestCase {

    // MARK: EVM / EIP-55

    /// EIP-55 reference vectors (from the EIP itself).
    func testEIP55ChecksumVectors() throws {
        let vectors = [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ]
        for vector in vectors {
            let bytes = Array(try Hex.decode(String(vector.dropFirst(2))))
            XCTAssertEqual(EVMAddress.checksummed(addressBytes: bytes), vector)
            XCTAssertTrue(EVMAddress.isValid(vector))
        }
    }

    /// The canonical all-abandon mnemonic address; also checked against the
    /// independent Python oracle in BIP32Tests and against public tooling.
    func testKnownEthereumAddress() throws {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(separator: " ").map(String.init)
        let seed = try BIP39.seed(mnemonic: words)
        let node = try ExtendedPrivateKey.master(seed: seed).derived(.secp256k1Default)
        let address = try EVMAddress.checksummed(fromPublicKey: node.publicKey())
        XCTAssertEqual(address, "0x030821f53C79461511bCf64367eCc9D013060408")
        XCTAssertTrue(EVMAddress.isValid(address))
    }

    func testEIP55RejectsBadChecksumPlacement() {
        // Same hex, wrong capitalisation: must fail strict validation.
        XCTAssertFalse(EVMAddress.isValid("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))
        // All-lowercase is accepted as unchecksummed-but-valid.
        XCTAssertTrue(EVMAddress.isValid("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
        // Wrong length / non-hex.
        XCTAssertFalse(EVMAddress.isValid("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beae"))
        XCTAssertFalse(EVMAddress.isValid("0xZZaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
        XCTAssertFalse(EVMAddress.isValid("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"))
    }

    func testEVMAddressFromCompressedAndUncompressedMatch() throws {
        let compressed = Array(try Hex.decode("0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"))
        let uncompressed = try Secp256k1.uncompressedPublicKey(fromCompressed: compressed)
        XCTAssertEqual(try EVMAddress.bytes(fromPublicKey: compressed), try EVMAddress.bytes(fromPublicKey: uncompressed))
    }

    func testComparisonNormalisation() {
        XCTAssertEqual(
            EVMAddress.normalisedForComparison("  0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n"),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        )
        XCTAssertEqual(
            EVMAddress.normalisedForComparison("9858effd232b4033e47d90003d41ec34ecaeda94"),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        )
    }

    // MARK: Bech32 / P2WPKH

    /// BIP-173 valid checksum vectors, loaded from a fixture generated directly
    /// from the BIP so a transcription error in the test cannot masquerade as an
    /// implementation bug (this happened: a hand-typed vector had 78 `q`s where
    /// the spec has 82).
    func testBIP173ValidVectors() throws {
        let vectors = try bech32Vectors()
        XCTAssertEqual(vectors.valid.count, 7)
        for string in vectors.valid {
            XCTAssertNoThrow(try Bech32.decode(string), "should be valid: \(string)")
        }
    }

    /// BIP-173 invalid checksum/HRP vectors, with the spec's stated reason.
    func testBIP173InvalidVectors() throws {
        let vectors = try bech32Vectors()
        XCTAssertEqual(vectors.invalid.count, 12)
        for entry in vectors.invalid {
            XCTAssertThrowsError(
                try Bech32.decode(entry.string),
                "should be invalid (\(entry.reason)): \(entry.string.debugDescription)"
            )
        }
    }

    private struct Bech32Vectors {
        let valid: [String]
        let invalid: [(string: String, reason: String)]
    }

    private func bech32Vectors() throws -> Bech32Vectors {
        guard let root = try FixtureLoader.json("bech32_vectors", extension: "json") as? [String: Any],
              let valid = root["valid_checksum_strings"] as? [String],
              let invalid = root["invalid_checksum_strings"] as? [[String: String]]
        else {
            throw FixtureLoader.FixtureError.missing("bech32_vectors.json")
        }
        return Bech32Vectors(
            valid: valid,
            invalid: invalid.map { ($0["string"] ?? "", $0["reason"] ?? "") }
        )
    }

    /// BIP-173 P2WPKH address vectors, checked against the derived key that
    /// produces them rather than hardcoded hashes.
    func testP2WPKHRoundTripAndValidation() throws {
        let compressed = Array(try Hex.decode("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"))
        let address = try BitcoinAddress.p2wpkh(publicKeyCompressed: compressed)
        XCTAssertEqual(address, "bc1qrqva0xkc0fu4rr4m30vvt4725esa7gsughzjxww")
        XCTAssertTrue(BitcoinAddress.isValidP2WPKH(address))
        XCTAssertTrue(BitcoinAddress.isValidP2WPKH(address.uppercased()))
        XCTAssertFalse(BitcoinAddress.isValidP2WPKH(address, network: .testnet))

        let testnet = try BitcoinAddress.p2wpkh(publicKeyCompressed: compressed, network: .testnet)
        XCTAssertTrue(testnet.hasPrefix("tb1"))
        XCTAssertTrue(BitcoinAddress.isValidP2WPKH(testnet, network: .testnet))

        // Flip one character -> must fail validation.
        var broken = Array(address)
        broken[broken.count - 1] = broken[broken.count - 1] == "q" ? "p" : "q"
        XCTAssertFalse(BitcoinAddress.isValidP2WPKH(String(broken)))
    }

    func testBech32ChecksumConstantsDiffer() throws {
        // Bech32 and Bech32m must not validate each other's checksums.
        let data = try Bech32.convertBits([0] + [UInt8](repeating: 1, count: 20), from: 8, to: 5, pad: true)
        let v0 = Bech32.encode(hrp: "bc", data: data, encoding: .bech32)
        let m0 = Bech32.encode(hrp: "bc", data: data, encoding: .bech32m)
        XCTAssertNotEqual(v0, m0)
        XCTAssertEqual(try Bech32.decode(v0).encoding, .bech32)
        XCTAssertEqual(try Bech32.decode(m0).encoding, .bech32m)
    }

    // MARK: Base58 / Base58Check

    func testBase58RoundTripAndLeadingZeros() throws {
        XCTAssertEqual(Base58.encode([]), "")
        XCTAssertEqual(Base58.encode([0]), "1")
        XCTAssertEqual(Base58.encode([0, 0, 0]), "111")
        XCTAssertEqual(Base58.encode(Array("Hello World!".utf8)), "2NEpo7TZRRrLZSi2U")
        XCTAssertEqual(try Base58.decode("2NEpo7TZRRrLZSi2U"), Array("Hello World!".utf8))
        XCTAssertEqual(try Base58.decode("111"), [0, 0, 0])
        XCTAssertEqual(try Base58.decode(Base58.encode([0, 1, 2, 3, 4])), [0, 1, 2, 3, 4])
        XCTAssertThrowsError(try Base58.decode("0"))   // '0' not in the alphabet
        XCTAssertThrowsError(try Base58.decode("O"))   // 'O' not in the alphabet
    }

    func testBase58CheckRejectsCorruptedChecksum() throws {
        let payload: [UInt8] = [0x04, 0x88, 0xAD, 0xE4, 0x00] + [UInt8](repeating: 0xAB, count: 32)
        let encoded = Base58.encodeCheck(payload)
        XCTAssertEqual(try Base58.decodeCheck(encoded), payload)
        var corrupted = Array(encoded)
        corrupted[corrupted.count - 1] = corrupted[corrupted.count - 1] == "1" ? "2" : "1"
        XCTAssertThrowsError(try Base58.decodeCheck(String(corrupted)))
    }
}
