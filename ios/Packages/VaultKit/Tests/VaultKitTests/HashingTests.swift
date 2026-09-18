import XCTest
@testable import VaultKit

/// Known-answer tests for every hash primitive. These are the foundation of the
/// whole scheme: if SHA-512/HMAC/PBKDF2 are wrong the mnemonic is wrong, and if
/// Keccak-256 is wrong the EVM address is wrong.
final class HashingTests: XCTestCase {

    // MARK: SHA-256 (FIPS 180-4 / NIST CAVP)

    func testSHA256KnownAnswers() {
        XCTAssertEqual(
            SHA256.hashHex([]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        XCTAssertEqual(
            SHA256.hashHex(Array("abc".utf8)),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        XCTAssertEqual(
            SHA256.hashHex(Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
    }

    /// Exercises the multi-block streaming path and the 64-bit length field.
    func testSHA256MillionA() {
        let million = [UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000)
        XCTAssertEqual(
            SHA256.hashHex(million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )
    }

    // MARK: SHA-512

    func testSHA512KnownAnswers() {
        XCTAssertEqual(
            Hex.encode(SHA512.hash([])),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
          + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        XCTAssertEqual(
            Hex.encode(SHA512.hash(Array("abc".utf8))),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    }

    // MARK: HMAC-SHA512 (RFC 4231)

    func testHMACSHA512RFC4231() {
        let key = [UInt8](repeating: 0x0b, count: 20)
        XCTAssertEqual(
            Hex.encode(HMACSHA512.authenticate(key: key, message: Array("Hi There".utf8))),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
          + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        )

        // Test case 2: key "Jefe", data "what do ya want for nothing?"
        XCTAssertEqual(
            Hex.encode(HMACSHA512.authenticate(key: Array("Jefe".utf8), message: Array("what do ya want for nothing?".utf8))),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
          + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        )

        // Key longer than the block size must be hashed down first.
        let longKey = [UInt8](repeating: 0xaa, count: 131)
        let digest = HMACSHA512.authenticate(key: longKey, message: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8))
        XCTAssertEqual(
            Hex.encode(digest),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
          + "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        )
    }

    // MARK: PBKDF2-HMAC-SHA512 via the BIP39 seed vector

    /// Anchors SHA-512 + HMAC + PBKDF2 together against the official BIP39 vector.
    func testPBKDF2MatchesBIP39SeedVector() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let seed = try PBKDF2.hmacSHA512(
            password: Array(mnemonic.utf8),
            salt: Array("mnemonicTREZOR".utf8),
            iterations: 2048,
            keyLength: 64
        )
        XCTAssertEqual(
            Hex.encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
          + "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        )
    }

    // MARK: RIPEMD-160 (Bosselaers reference vectors)

    func testRIPEMD160KnownAnswers() {
        XCTAssertEqual(Hex.encode(RIPEMD160.hash([])), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
        XCTAssertEqual(Hex.encode(RIPEMD160.hash(Array("a".utf8))), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe")
        XCTAssertEqual(Hex.encode(RIPEMD160.hash(Array("abc".utf8))), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        XCTAssertEqual(Hex.encode(RIPEMD160.hash(Array("message digest".utf8))), "5d0689ef49d2fae572b881b123a85ffa21595f36")
        XCTAssertEqual(
            Hex.encode(RIPEMD160.hash(Array("abcdefghijklmnopqrstuvwxyz".utf8))),
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
        )
        XCTAssertEqual(
            Hex.encode(RIPEMD160.hash(Array("12345678901234567890123456789012345678901234567890123456789012345678901234567890".utf8))),
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
        )
    }

    // MARK: Keccak-256 (Ethereum padding, NOT NIST SHA3-256)

    func testKeccak256KnownAnswers() {
        XCTAssertEqual(
            Hex.encode(Keccak256.hash([])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        )
        XCTAssertEqual(
            Hex.encode(Keccak256.hash(Array("abc".utf8))),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        )
        XCTAssertEqual(
            Hex.encode(Keccak256.hash(Array("testing".utf8))),
            "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"
        )
        // Must NOT equal SHA3-256("abc"), which is a different padding.
        XCTAssertNotEqual(
            Hex.encode(Keccak256.hash(Array("abc".utf8))),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )
    }

    // MARK: CRC32 (BC Bytewords)

    func testCRC32KnownAnswers() {
        XCTAssertEqual(CRC32.checksum(""), 0x00000000)
        XCTAssertEqual(CRC32.checksum("123456789"), 0xCBF43926)
        XCTAssertEqual(CRC32.checksum("The quick brown fox jumps over the lazy dog"), 0x414FA339)
    }
}
