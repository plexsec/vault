import Foundation
import XCTest

@testable import VaultKit

/// The two UR types of the Ethereum QR protocol: `eth-sign-request` (401) and
/// `eth-signature` (402).
///
/// The field layout is taken from `@keystonehq/bc-ur-registry-eth` (the library
/// MetaMask's QR keyring uses), not from the EIP's CDDL, because the two disagree:
/// the CDDL writes `data-type` as a tagged map, while the implementation writes a
/// bare integer. A request built the way the implementation builds one is decoded
/// here; a request built the way the CDDL describes one is refused.
final class EthSignRequestTests: XCTestCase {
    private static let requestID = try! Hex.decode("0102030405060708090a0b0c0d0e0f10")
    private static let path = try! DerivationPath("m/44'/0'/0'/0/0")
    private static let masterFingerprint: UInt32 = 0x5436_d724

    private func makeRequest(
        signData: [UInt8]? = nil,
        dataType: EVMSignDataType = .transaction,
        chainID: EVMQuantity? = EVMQuantity(1),
        address: [UInt8]? = nil,
        origin: String? = nil
    ) throws -> EthSignRequest {
        let resolvedSignData = try signData ?? Hex.decode(EVMTransactionTests.eip155Unsigned)
        return EthSignRequest(
            requestID: Self.requestID,
            signData: resolvedSignData,
            dataType: dataType,
            chainID: chainID,
            derivationPath: URKeyPath(path: Self.path, sourceFingerprint: Self.masterFingerprint),
            address: address,
            origin: origin
        )
    }

    // MARK: - Round trip

    func testRequestRoundTrip() throws {
        let request = try makeRequest(origin: "app.uniswap.org")
        let ur = try request.ur()
        let decoded = try EthSignRequest(ur: ur)
        XCTAssertEqual(decoded, request)
        XCTAssertEqual(decoded.path, Self.path)
        XCTAssertEqual(decoded.sourceFingerprintHex, "5436d724")
        XCTAssertEqual(decoded.dataType, .transaction)
        XCTAssertEqual(decoded.chainID, EVMQuantity(1))
    }

    func testSignatureRoundTrip() throws {
        let signature = EthSignature(
            requestID: Self.requestID,
            r: try Hex.decode(ECDSASignatureTests.r),
            s: try Hex.decode(ECDSASignatureTests.s),
            recoveryValue: EVMQuantity(37)
        )
        XCTAssertEqual(signature.signature.count, 65, "v fits in one byte here")

        let decoded = try EthSignature(ur: try signature.ur())
        XCTAssertEqual(decoded.requestID, Self.requestID)
        XCTAssertEqual(decoded.signature, signature.signature)
        XCTAssertEqual(decoded.r, try Hex.decode(ECDSASignatureTests.r))
        XCTAssertEqual(decoded.s, try Hex.decode(ECDSASignatureTests.s))
        XCTAssertEqual(decoded.recoveryValueBytes, [37])
    }

    /// A legacy EIP-155 transaction on a chain with a large id needs a recovery
    /// value that does not fit in a byte; the field grows rather than lying, and
    /// MetaMask reads everything from byte 64 as `v`.
    func testSignatureCarriesAWideRecoveryValue() throws {
        let signature = EthSignature(
            requestID: Self.requestID,
            r: try Hex.decode(ECDSASignatureTests.r),
            s: try Hex.decode(ECDSASignatureTests.s),
            recoveryValue: EVMQuantity(310)
        )
        XCTAssertEqual(signature.signature.count, 66)
        let decoded = try EthSignature(ur: try signature.ur())
        XCTAssertEqual(decoded.recoveryValueBytes, [0x01, 0x36])
    }

    /// The UR strings the app produces must be decodable by the reference
    /// implementation's own shape: `ur:eth-signature/...` with bytewords.
    func testSignatureUREncodes() throws {
        let signature = EthSignature(
            requestID: Self.requestID,
            r: try Hex.decode(ECDSASignatureTests.r),
            s: try Hex.decode(ECDSASignatureTests.s),
            recoveryValue: EVMQuantity(1)
        )
        let ur = try signature.ur()
        XCTAssertEqual(ur.type, "eth-signature")
        XCTAssertTrue(ur.string.hasPrefix("ur:eth-signature/"))
        XCTAssertEqual(try EthSignature(ur: UR(urString: ur.string)), signature)
    }

    // MARK: - Refusals

    private func refuse(_ name: String, _ cbor: CBOR, _ expectation: (EthSignRequestError) -> Bool) {
        XCTAssertThrowsError(try EthSignRequest(cbor: cbor), name) { error in
            guard let error = error as? EthSignRequestError else {
                return XCTFail("\(name): unexpected error \(error)")
            }
            XCTAssertTrue(expectation(error), "\(name): got \(error)")
        }
    }

    func testWrongURTypeIsRefused() throws {
        let request = try makeRequest()
        XCTAssertThrowsError(try EthSignRequest(ur: UR(type: "eth-signature", cbor: try request.ur().cbor))) {
            XCTAssertEqual($0 as? EthSignRequestError, .notAnEthSignRequest(type: "eth-signature"))
        }
    }

    func testOnlyAWrongTagIsRefused() throws {
        // The tag is nominal: the type name is in the UR, and wallets send the payload bare.
        // Accepting the untagged form is what makes a real MetaMask request readable at all
        // (amendment 25); an empty one still fails, for the honest reason.
        refuse("untagged, empty", .map([])) { $0 == .missingField(2) }
        refuse("tag 402 on a request", .tagged(402, .map([]))) { $0 == .wrongTag(found: 402) }
        refuse("tag 0", .tagged(0, .map([]))) { $0 == .wrongTag(found: 0) }
        // The expected tag is tolerated, for encoders that do add it.
        XCTAssertThrowsError(try EthSignRequest(cbor: .tagged(401, .map([])))) {
            XCTAssertEqual($0 as? EthSignRequestError, .missingField(2))
        }
    }

    func testUnknownFieldIsRefused() throws {
        var entries: [CBORMapEntry] = [
            CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
            CBORMapEntry(.unsigned(3), .unsigned(1)),
            CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
            CBORMapEntry(.unsigned(11), .text("future field")),
        ]
        refuse("field 11", .tagged(EthSignRequest.cborTag, .map(entries))) { $0 == .unknownField(11) }
        entries.removeLast()
        XCTAssertNoThrow(try EthSignRequest(cbor: .tagged(EthSignRequest.cborTag, .map(entries))))
    }

    func testMissingFieldsAreRefused() throws {
        refuse("no map", .tagged(EthSignRequest.cborTag, .unsigned(1))) { $0 == .notAMap }
        refuse("no sign-data", .tagged(EthSignRequest.cborTag, .map([]))) { $0 == .missingField(2) }
        refuse(
            "no data-type",
            .tagged(EthSignRequest.cborTag, .map([CBORMapEntry(.unsigned(2), .bytes(Data([0x01])))]))
        ) {
            $0 == .missingField(3)
        }
        refuse(
            "no derivation path",
            .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                CBORMapEntry(.unsigned(3), .unsigned(1)),
            ]))
        ) {
            $0 == .missingField(5)
        }
    }

    func testUnsupportedDataTypesAreRefused() throws {
        for raw in [UInt64(0), 5, 255] {
            refuse(
                "data-type \(raw)",
                .tagged(EthSignRequest.cborTag, .map([
                    CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                    CBORMapEntry(.unsigned(3), .unsigned(raw)),
                    CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
                ]))
            ) { $0 == .unsupportedDataType(raw) }
        }
        // 2 and 3 exist in the protocol but are not transactions: they are
        // decoded, then refused by the transaction decoder rather than here.
        for raw in [UInt64(2), 3] {
            let request = try EthSignRequest(cbor: .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                CBORMapEntry(.unsigned(3), .unsigned(raw)),
                CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
            ])))
            XCTAssertFalse(request.dataType.isTransaction)
            XCTAssertThrowsError(try EVMTransaction(signData: request.signData, dataType: request.dataType))
        }
    }

    /// The CDDL's tagged form of `data-type` is refused, not guessed at: the
    /// reference implementation writes a bare integer, and a request that
    /// disagrees with every implementation in the wild is a request to stop.
    func testTaggedDataTypeIsRefused() throws {
        refuse(
            "tagged data-type",
            .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                CBORMapEntry(.unsigned(3), .tagged(EthSignRequest.cborTag, .map([CBORMapEntry(.unsigned(1), .unsigned(1))]))),
                CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
            ]))
        ) { $0 == .missingField(3) }
    }

    func testDerivationPathTagIsChecked() throws {
        // The v2 `keypath` tag (40304) is not what wallets emit for a signing
        // request, and the path is what binds the request to the card's key.
        refuse(
            "keypath tag 40304",
            .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                CBORMapEntry(.unsigned(3), .unsigned(1)),
                CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .v2)),
            ]))
        ) { $0 == .derivationPathTag(40304) }
    }

    func testFieldShapesAreChecked() throws {
        // A 15-byte request id.
        refuse(
            "15-byte request id",
            .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(1), .bytes(Data([UInt8](repeating: 0, count: 15)))),
                CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                CBORMapEntry(.unsigned(3), .unsigned(1)),
                CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
            ]))
        ) { $0 == .invalidField(1) }

        // A 19-byte address.
        refuse(
            "19-byte address",
            .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(2), .bytes(Data([0x01]))),
                CBORMapEntry(.unsigned(3), .unsigned(1)),
                CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
                CBORMapEntry(.unsigned(6), .bytes(Data([UInt8](repeating: 0, count: 19)))),
            ]))
        ) { $0 == .invalidField(6) }
    }

    func testOversizedSignDataIsRefused() throws {
        let huge = [UInt8](repeating: 0xab, count: EthSignRequest.maximumSignDataLength + 1)
        refuse(
            "oversized sign-data",
            .tagged(EthSignRequest.cborTag, .map([
                CBORMapEntry(.unsigned(2), .bytes(Data(huge))),
                CBORMapEntry(.unsigned(3), .unsigned(1)),
                CBORMapEntry(.unsigned(5), URKeyPath(path: Self.path).cbor(style: .keystoneLegacy)),
            ]))
        ) { $0 == .signDataTooLarge(huge.count) }
    }

    func testSignatureWithoutRequestIDIsRefused() throws {
        // MetaMask matches the response to the request by request id and throws
        // without it, so a signature missing it is a signature nobody can use.
        let cbor = CBOR.tagged(EthSignature.cborTag, .map([
            CBORMapEntry(.unsigned(2), .bytes(Data([UInt8](repeating: 0x11, count: 65)))),
        ]))
        XCTAssertThrowsError(try EthSignature(ur: UR(type: "eth-signature", cbor: cbor))) { error in
            XCTAssertEqual(error as? EthSignRequestError, .missingField(1))
        }
    }

    /// Every error must be printable: they are what the operator sees when a
    /// wallet sends something the app will not sign.
    func testErrorsExplainThemselves() {
        let errors: [EthSignRequestError] = [
            .notAnEthSignRequest(type: "crypto-hdkey"),
            .wrongTag(found: 402),
            .notAMap,
            .unknownField(11),
            .missingField(5),
            .invalidField(6),
            .unsupportedDataType(2),
            .derivationPathTag(40304),
            .signDataTooLarge(20000),
        ]
        for error in errors {
            XCTAssertFalse(error.userFacingDescription.isEmpty)
            XCTAssertGreaterThan(error.userFacingDescription.count, 30)
        }
    }
}
