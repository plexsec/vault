import XCTest
@testable import VaultKit

/// RFC 8032 §7.1 known-answer tests for the vendored TweetNaCl Ed25519.
///
/// These are the only reason the signing paths exist in `Ed25519`: v1 never
/// signs with the Ed25519 key on the phone (the YubiKey does), so the signature
/// vectors are what pin the vendored implementation as a whole.
final class Ed25519Tests: XCTestCase {

    /// (secret key, public key, message, signature) from RFC 8032 §7.1.
    private static let rfc8032Vectors: [(seed: String, publicKey: String, message: String, signature: String)] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                + "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    ]

    func testRFC8032KnownAnswers() throws {
        for (index, vector) in Self.rfc8032Vectors.enumerated() {
            let seed = try Hex.decode(vector.seed)
            let message = try Hex.decode(vector.message)
            let expectedPublicKey = try Hex.decode(vector.publicKey)
            let expectedSignature = try Hex.decode(vector.signature)

            let publicKey = try Ed25519.publicKey(fromSeed: seed)
            XCTAssertEqual(
                publicKey.hexString, expectedPublicKey.hexString,
                "RFC 8032 vector \(index + 1): public key derivation"
            )

            let signature = try Ed25519.sign(message: message, seed: seed)
            XCTAssertEqual(
                signature.hexString, expectedSignature.hexString,
                "RFC 8032 vector \(index + 1): signature"
            )

            XCTAssertTrue(
                Ed25519.verify(signature: signature, message: message, publicKey: publicKey),
                "RFC 8032 vector \(index + 1): verification"
            )
        }
    }

    func testVerifyRejectsTamperedSignatureAndMessage() throws {
        let seed = try Hex.decode(Self.rfc8032Vectors[1].seed)
        let message = try Hex.decode(Self.rfc8032Vectors[1].message)
        let publicKey = try Ed25519.publicKey(fromSeed: seed)
        let signature = try Ed25519.sign(message: message, seed: seed)

        var tamperedSignature = signature
        tamperedSignature[0] ^= 0x01
        XCTAssertFalse(Ed25519.verify(signature: tamperedSignature, message: message, publicKey: publicKey))

        var tamperedMessage = message
        tamperedMessage[0] ^= 0x01
        XCTAssertFalse(Ed25519.verify(signature: signature, message: tamperedMessage, publicKey: publicKey))

        var wrongKey = publicKey
        wrongKey[0] ^= 0x01
        XCTAssertFalse(Ed25519.verify(signature: signature, message: message, publicKey: wrongKey))
    }

    /// Exercises the multi-block hash path (the KATs above are all < 128 bytes).
    func testSignVerifyOverLongMessage() throws {
        let seed = [UInt8](repeating: 0x42, count: 32)
        let publicKey = try Ed25519.publicKey(fromSeed: seed)
        let message = (0..<1023).map { UInt8($0 % 251) }

        let signature = try Ed25519.sign(message: message, seed: seed)
        XCTAssertEqual(signature.count, Ed25519.signatureLength)
        XCTAssertTrue(Ed25519.verify(signature: signature, message: message, publicKey: publicKey))
    }

    func testSeedLengthIsEnforced() throws {
        XCTAssertThrowsError(try Ed25519.publicKey(fromSeed: [UInt8](repeating: 0, count: 31))) { error in
            XCTAssertEqual(error as? Ed25519Error, .invalidSeedLength(31))
        }
        XCTAssertThrowsError(try Ed25519.publicKey(fromSeed: [UInt8](repeating: 0, count: 64))) { error in
            XCTAssertEqual(error as? Ed25519Error, .invalidSeedLength(64))
        }
    }

    /// The seed is what SLIP-0010 derives, so an all-zero seed must still yield a
    /// well-formed, non-zero public key.
    func testZeroSeedProducesWellFormedKey() throws {
        let publicKey = try Ed25519.publicKey(fromSeed: [UInt8](repeating: 0, count: 32))
        XCTAssertEqual(publicKey.count, 32)
        XCTAssertTrue(publicKey.contains { $0 != 0 })
    }
}
