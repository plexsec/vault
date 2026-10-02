import Foundation
import XCTest

@testable import VaultKit

/// Transaction decoding, against the EIP-155 example and against payloads whose
/// digests were computed by an independent implementation (`tools/derive`'s
/// pycryptodome Keccak and a hand-written RLP encoder).
final class EVMTransactionTests: XCTestCase {
    /// EIP-155's own example: nonce 9, 20 gwei, 21000 gas, 1 ETH to 0x3535…35.
    /// The unsigned form and the signing hash are both printed in the EIP.
    static let eip155Unsigned =
        "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
    static let eip155Digest = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    static let recipient = "3535353535353535353535353535353535353535"

    /// EIP-1559: chain 1, nonce 7, 1.5 gwei tip, 30 gwei cap, 21000 gas, 1 ETH.
    static let feeMarketPayload =
        "02f001078459682f008506fc23ac008252089470997970c51812dc3a010c7d01b50e0d17dc79c8"
        + "880de0b6b3a764000080c0"
    static let feeMarketDigest = "b28e48247c132650294459b31a5ad7e4e9ad187abb0f984388629b2c29e27e85"

    /// EIP-2930 with ERC-20 `transfer` calldata and one access-list entry.
    static let accessListPayload =
        "01f8a101038504a817c8008275309470997970c51812dc3a010c7d01b50e0d17dc79c880b844"
        + "a9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
        + "00000000000000000000000000000000000000000000000000000000000f4240"
        + "f838f7946b175474e89094c44da98b954eedeac495271d0fe1a01111111111111111111111111111111111111111111111111111111111111111"
    static let accessListDigest = "ffda134128f580ee2061c44fd17f6aac36bd2032386fd593de3900cb046dadd1"

    // MARK: - Legacy (EIP-155)

    func testEIP155ExampleDecodesToTheDocumentedFields() throws {
        let transaction = try EVMTransaction(
            signData: try Hex.decode(Self.eip155Unsigned),
            dataType: .transaction
        )
        XCTAssertEqual(transaction.kind, .legacy)
        XCTAssertEqual(transaction.chainId, EVMQuantity(1))
        XCTAssertEqual(transaction.nonce, EVMQuantity(9))
        XCTAssertEqual(transaction.gasPrice, EVMQuantity(20_000_000_000))
        XCTAssertEqual(transaction.gasLimit, EVMQuantity(21_000))
        XCTAssertEqual(transaction.to?.hexString, Self.recipient)
        XCTAssertEqual(transaction.value, EVMQuantity(1_000_000_000_000_000_000))
        XCTAssertEqual(transaction.data, [])
        XCTAssertTrue(transaction.usesEIP155)
        XCTAssertEqual(transaction.accessList, [])
        XCTAssertEqual(transaction.signingDigest.hexString, Self.eip155Digest)
    }

    func testEIP155ExampleDisplay() throws {
        let transaction = try EVMTransaction(
            signData: try Hex.decode(Self.eip155Unsigned),
            dataType: .transaction
        )
        XCTAssertEqual(transaction.valueInEther, "1")
        XCTAssertEqual(transaction.gasPriceInGwei, "20")
        // 21000 × 20 gwei = 420000 gwei = 0.00042 ETH
        XCTAssertEqual(transaction.maximumFeeInEther, "0.00042")
        XCTAssertEqual(transaction.checksummedRecipient, "0x3535353535353535353535353535353535353535")
        XCTAssertNil(transaction.maxFeePerGas)
    }

    /// The signed form of the same transaction is not a signing request.
    func testSignedLegacyTransactionIsRefused() throws {
        let signed =
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025"
            + "a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
            + "a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        XCTAssertThrowsError(try EVMTransaction(signData: try Hex.decode(signed), dataType: .transaction)) { error in
            XCTAssertEqual(error as? EVMTransactionError, .placeholdersNotEmpty)
        }
    }

    /// Six-item legacy is the pre-EIP-155 form: no chain id, v = 27/28.
    func testPreEIP155LegacyFormDecodes() throws {
        let payload = try RLP.encode(.list([
            .bytes([0x01]),
            .bytes([0x02]),
            .bytes([0x03]),
            .bytes(try Hex.decode(Self.recipient)),
            .bytes([]),
            .bytes([]),
        ]))
        let transaction = try EVMTransaction(signData: payload, dataType: .transaction)
        XCTAssertEqual(transaction.kind, .legacy)
        XCTAssertNil(transaction.chainId)
        XCTAssertFalse(transaction.usesEIP155)
    }

    // MARK: - Typed (EIP-2718)

    func testFeeMarketTransactionDecodes() throws {
        let transaction = try EVMTransaction(
            signData: try Hex.decode(Self.feeMarketPayload),
            dataType: .typedTransaction
        )
        XCTAssertEqual(transaction.kind, .feeMarket)
        XCTAssertEqual(transaction.chainId, EVMQuantity(1))
        XCTAssertEqual(transaction.nonce, EVMQuantity(7))
        XCTAssertEqual(transaction.maxPriorityFeePerGas, EVMQuantity(1_500_000_000))
        XCTAssertEqual(transaction.maxFeePerGas, EVMQuantity(30_000_000_000))
        XCTAssertNil(transaction.gasPrice)
        XCTAssertEqual(transaction.gasLimit, EVMQuantity(21_000))
        XCTAssertEqual(transaction.value, EVMQuantity(1_000_000_000_000_000_000))
        XCTAssertEqual(transaction.signingDigest.hexString, Self.feeMarketDigest)
        XCTAssertEqual(transaction.maxFeePerGasInGwei, "30")
        XCTAssertEqual(transaction.maxPriorityFeePerGasInGwei, "1.5")
    }

    func testAccessListTransactionDecodes() throws {
        let transaction = try EVMTransaction(
            signData: try Hex.decode(Self.accessListPayload),
            dataType: .typedTransaction
        )
        XCTAssertEqual(transaction.kind, .accessList)
        XCTAssertEqual(transaction.gasPrice, EVMQuantity(20_000_000_000))
        XCTAssertNil(transaction.maxFeePerGas)
        XCTAssertEqual(transaction.data.count, 68)
        XCTAssertEqual(Array(transaction.data.prefix(4)).hexString, "a9059cbb")
        XCTAssertEqual(transaction.accessList.count, 1)
        XCTAssertEqual(
            transaction.accessList.first?.address.hexString,
            "6b175474e89094c44da98b954eedeac495271d0f"
        )
        XCTAssertEqual(transaction.accessList.first?.storageKeys.first?.count, 32)
        XCTAssertEqual(transaction.signingDigest.hexString, Self.accessListDigest)
    }

    // MARK: - What must be refused

    private func refuse(
        _ description: String,
        _ signData: [UInt8],
        dataType: EVMSignDataType = .transaction,
        _ expectation: (EVMTransactionError) -> Bool = { _ in true }
    ) throws {
        XCTAssertThrowsError(try EVMTransaction(signData: signData, dataType: dataType), description) { error in
            // A malformed payload may be refused by the RLP layer or by the
            // transaction layer; both are refusals.
            guard let error = error as? EVMTransactionError else {
                return XCTFail("\(description): unexpected error \(error)")
            }
            XCTAssertTrue(expectation(error), "\(description): got \(error)")
        }
    }

    func testNonCanonicalRLPIsRefused() throws {
        func refuseRLP(_ name: String, _ bytes: [UInt8], _ expected: RLP.Error) {
            XCTAssertThrowsError(try EVMTransaction(signData: bytes, dataType: .transaction), name) { error in
                XCTAssertEqual(error as? RLP.Error, expected, name)
            }
        }
        // 0x81 0x00 is the one-byte string for 0x00, which RLP encodes as 0x00.
        refuseRLP("non-canonical single byte", [0x81, 0x00], .nonCanonicalSingleByte)
        // A long form length that fits the short form.
        refuseRLP("long form for a short length", [0xf8, 0x01, 0x80], .nonCanonicalLength)
        // A length with leading zeros.
        refuseRLP("padded length", [0xb8, 0x00], .nonCanonicalLengthPadding)
        refuseRLP("truncated", [0x83, 0x01], .truncated)
    }

    func testLeadingZeroQuantitiesAreRefused() throws {
        // nonce = 0x00 rather than the empty byte string.
        let payload = try RLP.encode(.list([
            .bytes([0x00]),
            .bytes([0x01]),
            .bytes([0x02]),
            .bytes(try Hex.decode(Self.recipient)),
            .bytes([]),
            .bytes([]),
        ]))
        try refuse("leading zero nonce", payload) { $0 == .nonMinimalQuantity }
    }

    func testWrongFieldCountIsRefused() throws {
        for count in [0, 5, 7, 8, 10] {
            let payload = try RLP.encode(.list((0..<count).map { _ in RLP.Item.bytes([]) }))
            try refuse("\(count)-field payload", payload) { $0 == .wrongFieldCount(count) }
        }
    }

    func testRecipientLengthIsChecked() throws {
        let payload = try RLP.encode(.list([
            .bytes([]), .bytes([]), .bytes([]),
            .bytes([UInt8](repeating: 0x11, count: 21)),
            .bytes([]), .bytes([]),
        ]))
        try refuse("21-byte recipient", payload) { $0 == .invalidRecipientLength(21) }
    }

    func testMalformedAccessListIsRefused() throws {
        // EIP-2930 with a 32-byte storage key instead of 20-byte address.
        let payload = try RLP.encode(.list([
            .bytes([0x01]), .bytes([]), .bytes([0x01]), .bytes([0x02]),
            .bytes(try Hex.decode(Self.recipient)), .bytes([]), .bytes([]),
            .list([.list([.bytes([UInt8](repeating: 0x11, count: 19)), .list([])])]),
        ]))
        try refuse("short access-list address", [0x01] + payload, dataType: .typedTransaction) {
            $0 == .invalidAccessListEntry
        }

        let badKey = try RLP.encode(.list([
            .bytes([0x01]), .bytes([]), .bytes([0x01]), .bytes([0x02]),
            .bytes(try Hex.decode(Self.recipient)), .bytes([]), .bytes([]),
            .list([.list([.bytes([UInt8](repeating: 0x11, count: 20)), .list([.bytes([0x00])])])]),
        ]))
        try refuse("31-byte storage key", [0x01] + badKey, dataType: .typedTransaction) {
            $0 == .invalidStorageKeyLength(1)
        }
    }

    func testUnsupportedTypedTransactionTypeIsRefused() throws {
        // 0x03 is EIP-4844, which this app does not decode.
        try refuse("type 0x03", [0x03] + (try RLP.encode(.list([]))), dataType: .typedTransaction) {
            $0 == .unsupportedTransactionType(3)
        }
    }

    /// The `data-type` field is cross-checked against the payload shape.
    func testDataTypeMismatchIsRefused() throws {
        try refuse(
            "legacy payload declared typed",
            try Hex.decode(Self.eip155Unsigned),
            dataType: .typedTransaction
        ) {
            if case .unsupportedTransactionType = $0 { return true }
            return false
        }
        // A typed payload declared as legacy: the EIP-2718 type byte becomes a
        // stray item in front of the list, which the RLP layer refuses.
        XCTAssertThrowsError(
            try EVMTransaction(
                signData: try Hex.decode(Self.feeMarketPayload),
                dataType: .transaction
            ),
            "typed payload declared legacy"
        ) { error in
            XCTAssertEqual(error as? RLP.Error, .trailingBytes)
        }
        // Types 2 and 3 are not transactions at all.
        try refuse("typed data", [0x02], dataType: .typedData) { $0 == .dataTypeMismatch }
        try refuse("personal message", [], dataType: .personalMessage) { $0 == .dataTypeMismatch }
    }

    func testOverWideFieldsAreRefused() throws {
        let wideValue = [UInt8](repeating: 0x11, count: 33)
        let payload = try RLP.encode(.list([
            .bytes([]), .bytes([]), .bytes([]),
            .bytes(try Hex.decode(Self.recipient)),
            .bytes(wideValue),
            .bytes([]),
        ]))
        try refuse("33-byte value", payload) { $0 == .quantityTooWide(field: "value") }
    }

    // MARK: - Display arithmetic

    func testQuantityDecimalConversion() throws {
        XCTAssertEqual(EVMQuantity.zero.decimalString, "0")
        XCTAssertEqual(EVMQuantity(1_000_000_000_000_000_000).decimalString, "1000000000000000000")
        XCTAssertEqual(EVMQuantity(1_000_000_000_000_000_000).decimalString(decimals: 18), "1")
        XCTAssertEqual(EVMQuantity(1).decimalString(decimals: 18), "0.000000000000000001")
        XCTAssertEqual(EVMQuantity(1_500_000_000).decimalString(decimals: 9), "1.5")
        XCTAssertEqual(EVMQuantity(0).decimalString(decimals: 18), "0")
        // A 256-bit value survives conversion exactly.
        let maximal = try EVMQuantity(minimalBytes: [UInt8](repeating: 0xff, count: 32))
        XCTAssertEqual(
            maximal.decimalString,
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        )
        XCTAssertEqual(EVMQuantity(21_000).multiplied(by: 20_000_000_000).decimalString(decimals: 18), "0.00042")
    }

    func testQuantityMinimalEncoding() throws {
        XCTAssertThrowsError(try EVMQuantity(minimalBytes: [0x00])) { error in
            XCTAssertEqual(error as? EVMTransactionError, .nonMinimalQuantity)
        }
        XCTAssertThrowsError(try EVMQuantity(minimalBytes: [0x00, 0x01]))
        XCTAssertEqual(try EVMQuantity(minimalBytes: []), .zero)
        XCTAssertEqual(EVMQuantity.zero.hexString, "0x0")
        XCTAssertEqual(EVMQuantity(255).hexString, "0xff")
        XCTAssertNil(try EVMQuantity(minimalBytes: [UInt8](repeating: 0xff, count: 9)).uint64)
        XCTAssertEqual(EVMQuantity(UInt64.max).uint64, UInt64.max)
    }

    /// Re-encoding is the guarantee that the displayed fields are the hashed
    /// bytes, so it is checked for every transaction shape the app accepts.
    func testReEncodingReproducesTheInput() throws {
        for (payload, dataType) in [
            (Self.eip155Unsigned, EVMSignDataType.transaction),
            (Self.feeMarketPayload, EVMSignDataType.typedTransaction),
            (Self.accessListPayload, EVMSignDataType.typedTransaction),
        ] {
            let bytes = try Hex.decode(payload)
            let transaction = try EVMTransaction(signData: bytes, dataType: dataType)
            XCTAssertEqual(transaction.signData, bytes)
            XCTAssertEqual(transaction.signingDigest, Keccak256.hash(bytes))
        }
    }
}
