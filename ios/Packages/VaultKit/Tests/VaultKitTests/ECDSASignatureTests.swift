import Foundation
import XCTest

@testable import VaultKit

/// Signatures: DER from the card, low-s normalisation, and recovery.
///
/// The vector is EIP-155's own example transaction. Its digest is printed in the
/// EIP, its signature and recovery value are in the signed transaction, and the
/// address it recovers (`0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f`) was confirmed
/// by an independent implementation — a pure-Python `ecrecover` written for
/// `tools/derive`, which shares no code with libsecp256k1.
final class ECDSASignatureTests: XCTestCase {
    static let digest = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    static let r = "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
    static let s = "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    static let recoveryValue = 37
    static let sender = "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"

    private func signature() throws -> ECDSASignature {
        try ECDSASignature(r: try Hex.decode(Self.r), s: try Hex.decode(Self.s))
    }

    // MARK: - Recovery

    func testRecoveryOfTheEIP155Example() throws {
        let digest = try Hex.decode(Self.digest)
        let uncompressed = try Secp256k1.recoverPublicKey(
            signature: try signature(),
            digest: digest,
            recoveryID: 0
        )
        XCTAssertEqual(uncompressed.count, 65)
        XCTAssertEqual(uncompressed[0], 0x04)
        XCTAssertEqual(try EVMAddress.bytes(fromPublicKey: uncompressed).hexString, Self.sender)
    }

    func testRecoveryIDSearchFindsTheEIP155Signer() throws {
        let expected = try Hex.decode(Self.sender)
        let found = try EVMSignature.recoveryID(
            signature: try signature(),
            digest: try Hex.decode(Self.digest),
            expectedAddress: expected
        )
        // v = 37 on chain 1 means recid = 37 - 35 - 2.
        XCTAssertEqual(found, UInt8(Self.recoveryValue - 35 - 2))
    }

    /// A signature that recovers a *different* key must be reported, not
    /// silently returned: this is the check that catches a card signing with the
    /// wrong slot or a digest that is not the one the operator approved.
    func testRecoveryIDSearchRejectsAnotherAddress() throws {
        let other = try Hex.decode("1111111111111111111111111111111111111111")
        XCTAssertThrowsError(
            try EVMSignature.recoveryID(
                signature: try signature(),
                digest: try Hex.decode(Self.digest),
                expectedAddress: other
            )
        ) { error in
            XCTAssertEqual(error as? EVMSignature.Error, .signatureDoesNotMatchKey)
        }
    }

    func testVerification() throws {
        let digest = try Hex.decode(Self.digest)
        let publicKey = try Secp256k1.recoverPublicKey(signature: try signature(), digest: digest, recoveryID: 0)
        XCTAssertTrue(try Secp256k1.verify(signature: try signature(), digest: digest, publicKey: publicKey))

        // A different message must not verify.
        var other = digest
        other[0] ^= 0x01
        XCTAssertFalse(try Secp256k1.verify(signature: try signature(), digest: other, publicKey: publicKey))

        // Nor must a different key.
        let stranger = try Secp256k1.publicKey(fromPrivateKey: [UInt8](repeating: 0x11, count: 32))
        XCTAssertFalse(try Secp256k1.verify(signature: try signature(), digest: digest, publicKey: stranger))
    }

    // MARK: - Low-s

    func testEIP155ExampleIsAlreadyLowS() throws {
        let signature = try signature()
        XCTAssertTrue(signature.isLowS)
        let (normalised, flipped) = signature.normalisedLowS()
        XCTAssertEqual(normalised, signature)
        XCTAssertFalse(flipped)
    }

    /// `(r, n-s)` verifies for the same key and message, which is exactly why
    /// EIP-2 forbids it. Normalising must produce the low-s form and the search
    /// must then find the *other* recovery id — one search over both ids covers
    /// the parity flip, so the caller never has to track it.
    func testHighSNormalisationFlipsTheRecoveryID() throws {
        let highS = try ECDSASignature(r: try Hex.decode(Self.r), s: ECDSASignature.subtract(
            ECDSASignature.curveOrder,
            try Hex.decode(Self.s)
        ))
        XCTAssertFalse(highS.isLowS)

        let (normalised, flipped) = highS.normalisedLowS()
        XCTAssertTrue(flipped)
        XCTAssertEqual(normalised, try signature())
        XCTAssertTrue(normalised.isLowS)

        // The high-s form recovers the same address, but under recovery id 1.
        let expected = try Hex.decode(Self.sender)
        XCTAssertEqual(
            try EVMSignature.recoveryID(
                signature: highS,
                digest: try Hex.decode(Self.digest),
                expectedAddress: expected
            ),
            1
        )
    }

    func testScalarsAreValidated() throws {
        XCTAssertThrowsError(try ECDSASignature(r: [0x01], s: try Hex.decode(Self.s)))
        XCTAssertThrowsError(try ECDSASignature(r: try Hex.decode(Self.r), s: [UInt8](repeating: 0, count: 32))) {
            XCTAssertEqual($0 as? ECDSASignature.Error, .zeroScalar)
        }
        XCTAssertThrowsError(
            try ECDSASignature(r: ECDSASignature.curveOrder, s: try Hex.decode(Self.s))
        ) {
            XCTAssertEqual($0 as? ECDSASignature.Error, .scalarOutOfRange)
        }
    }

    // MARK: - DER

    func testDERRoundTrip() throws {
        let der = Self.encodeDER(r: try Hex.decode(Self.r), s: try Hex.decode(Self.s))
        XCTAssertEqual(der[0], 0x30)
        XCTAssertEqual(try ECDSASignature.decodeDER(der), try signature())
        XCTAssertEqual(try ECDSASignature.decode(cardResponse: der), try signature())
    }

    /// The card's response is DER per the OpenPGP specification; a bare 64-byte
    /// `r ‖ s` is accepted as well because the two forms cannot be confused.
    func testBareSixtyFourByteResponseIsAccepted() throws {
        let raw = try Hex.decode(Self.r) + (try Hex.decode(Self.s))
        XCTAssertEqual(try ECDSASignature.decode(cardResponse: raw), try signature())
        XCTAssertThrowsError(try ECDSASignature.decode(cardResponse: Array(raw.prefix(63)))) {
            XCTAssertEqual($0 as? ECDSASignature.Error, .unexpectedCardResponse(length: 63))
        }
    }

    func testMalformedDERIsRefused() throws {
        let r = try Hex.decode(Self.r)
        let s = try Hex.decode(Self.s)
        func refuse(_ name: String, _ der: [UInt8]) {
            XCTAssertThrowsError(try ECDSASignature.decodeDER(der), name) { error in
                guard case .malformedDER = (error as? ECDSASignature.Error) else {
                    return XCTFail("\(name): got \(error)")
                }
            }
        }
        refuse("not a sequence", [0x31, 0x02, 0x01, 0x01])
        refuse("trailing byte", Self.encodeDER(r: r, s: s) + [0x00])
        refuse("negative integer", [0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01])
        // 0x00 prefix that is not needed to keep the value positive.
        refuse("non-minimal integer", [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])
        // Long form for a length that fits the short form.
        refuse("long form length", [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
        refuse("truncated", [0x30, 0x06, 0x02, 0x01, 0x01])
    }

    // MARK: - Ethereum's v

    func testRecoveryValueForEachTransactionShape() throws {
        let legacy = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        )
        // chain 1, recid 0 -> 37
        XCTAssertEqual(try EVMSignature.value(for: legacy, recoveryID: 0), EVMQuantity(37))
        XCTAssertEqual(try EVMSignature.value(for: legacy, recoveryID: 1), EVMQuantity(38))

        let typed = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.feeMarketPayload),
            dataType: .typedTransaction
        )
        XCTAssertEqual(try EVMSignature.value(for: typed, recoveryID: 0), EVMQuantity(0))
        XCTAssertEqual(try EVMSignature.value(for: typed, recoveryID: 1), EVMQuantity(1))

        // Polygon's chain id: the EIP-155 value no longer fits in one byte, which
        // is why the signature field can grow (design.md §5.3).
        let polygon = try EVMTransaction(
            signData: try Self.signDataWithChainID(137),
            dataType: .transaction
        )
        let value = try EVMSignature.value(for: polygon, recoveryID: 1)
        XCTAssertEqual(value, EVMQuantity(310))
        XCTAssertFalse(EVMSignature.fitsInSingleByte(value))
        XCTAssertTrue(EVMSignature.fitsInSingleByte(EVMQuantity(255)))
    }

    func testTransactionSignatureBundlesNormalisationAndValue() throws {
        let transaction = try EVMTransaction(
            signData: try Hex.decode(EVMTransactionTests.eip155Unsigned),
            dataType: .transaction
        )
        let (signature, value) = try EVMSignature.transactionSignature(
            cardSignature: try signature(),
            transaction: transaction,
            expectedAddress: try Hex.decode(Self.sender)
        )
        XCTAssertEqual(signature, try self.signature())
        XCTAssertEqual(value, EVMQuantity(37))
    }

    // MARK: - Helpers

    /// The EIP-155 form of the example transaction with a different chain id.
    static func signDataWithChainID(_ chainID: UInt64) throws -> [UInt8] {
        try RLP.encode(.list([
            .bytes([0x09]),
            .bytes([0x04, 0xa8, 0x17, 0xc8, 0x00]),
            .bytes([0x52, 0x08]),
            .bytes(try Hex.decode(EVMTransactionTests.recipient)),
            .bytes([0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]),
            .bytes([]),
            .bytes(EVMQuantity(chainID).bytes),
            .bytes([]),
            .bytes([]),
        ]))
    }

    /// Minimal DER encoding, used to build the card's response shape in tests.
    static func encodeDER(r: [UInt8], s: [UInt8]) -> [UInt8] {
        func integer(_ value: [UInt8]) -> [UInt8] {
            var bytes = value
            while bytes.count > 1, bytes.first == 0 { bytes.removeFirst() }
            if bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }
            return [0x02, UInt8(bytes.count)] + bytes
        }
        let body = integer(r) + integer(s)
        return [0x30, UInt8(body.count)] + body
    }
}
