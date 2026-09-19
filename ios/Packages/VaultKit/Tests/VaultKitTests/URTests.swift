import XCTest
@testable import VaultKit

/// BC-UR conformance. The two `hdkey` vectors below are published in
/// BCR-2020-007 with their exact CBOR hex and the exact `ur:` string, so a
/// passing test validates deterministic CBOR encoding, Bytewords (including the
/// CRC32 trailer) and single-part UR assembly simultaneously.
final class URTests: XCTestCase {

    // MARK: Published BCR-2020-007 test vectors

    private static let masterKeyHex =
        "a301f503582100e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        + "045820873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"

    private static let masterKeyUR =
        "ur:hdkey/otadykaxhdclaevswfdmjpfswpwkahcywspsmndwmusoskprbbehetchsnpfcybbmwrhchspfxjeecaahdcxltfszmlyrtdlgmhfcnzcctvwcmkbpsftgonbgauefsehgrqzdmvodizmweemtlaybakiylat"

    private static let derivedKeyHex =
        "a5035821026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6"
        + "045820ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85"
        + "05d99d71a10201"
        + "06d99d70a1018a182cf501f501f500f401f4"
        + "081ae9181cf3"

    private static let derivedKeyUR =
        "ur:hdkey/onaxhdclaojlvoechgferkdpqdiabdrflawshlhdmdcemtfnlrctghchbdolvwsednvdztbgolaahdcxtottgostdkhfdahdlykkecbbweskrymwflvdylgerkloswtbrpfdbsticmwylklpahtantjsoyaoadamtantjooyadlecsdwykadykadykaewkadwkaycywlcscewfjnkpvllt"

    func testMasterKeyVectorEncodesToPublishedCBORAndUR() throws {
        let keyData = Array(try Hex.decode("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"))
        let chainCode = Array(try Hex.decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"))
        let key = HDKey(isMaster: true, keyData: keyData, chainCode: chainCode)

        XCTAssertEqual(key.cbor(style: .v2).cborData.hex, Self.masterKeyHex)
        XCTAssertEqual(try key.ur(style: .v2).string, Self.masterKeyUR)
    }

    func testDerivedKeyVectorEncodesToPublishedCBORAndUR() throws {
        let keyData = Array(try Hex.decode("026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6"))
        let chainCode = Array(try Hex.decode("ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85"))
        let key = HDKey(
            keyData: keyData,
            chainCode: chainCode,
            useInfo: CoinInfo(type: 0, network: 1),
            origin: URKeyPath(components: [
                .hardened(44), .hardened(1), .hardened(1), .normal(0), .normal(1),
            ]),
            parentFingerprint: 3_910_671_603
        )

        XCTAssertEqual(key.cbor(style: .v2).cborData.hex, Self.derivedKeyHex)
        XCTAssertEqual(try key.ur(style: .v2).string, Self.derivedKeyUR)
    }

    func testPublishedVectorsDecodeBackToTheSameStructure() throws {
        for (hex, urString) in [(Self.masterKeyHex, Self.masterKeyUR), (Self.derivedKeyHex, Self.derivedKeyUR)] {
            let ur = try UR(urString: urString)
            XCTAssertEqual(ur.cbor.cborData.hex, hex)
            let decoded = try HDKey(ur: ur)
            XCTAssertEqual(try decoded.ur(style: .v2).string, urString)
            XCTAssertEqual(decoded.knownFieldKeysCheck(), [])
        }
    }

    // MARK: Bytewords (BCR-2020-012)

    func testBytewordsChecksumIsCRC32BigEndian() {
        let message = Data("hello world".utf8)
        let checksum = Bytewords.checksum(of: message)
        XCTAssertEqual(checksum.count, 4)
        let expected = CRC32.checksum(message)
        XCTAssertEqual(Array(checksum), [
            UInt8((expected >> 24) & 0xff),
            UInt8((expected >> 16) & 0xff),
            UInt8((expected >> 8) & 0xff),
            UInt8(expected & 0xff),
        ])
    }

    func testBytewordsRoundTripStyles() throws {
        for length in [1, 2, 5, 32, 100, 1000] {
            let payload = Data((0..<length).map { UInt8($0 % 251) })
            for style in [Bytewords.Style.standard, .uri, .minimal] {
                let encoded = Bytewords.encode(payload, style: style)
                XCTAssertEqual(try Bytewords.decode(encoded, style: style), payload, "style \(style) length \(length)")
            }
        }
    }

    func testBytewordsRejectsCorruptedChecksum() throws {
        let payload = Data("integrity".utf8)
        let encoded = Bytewords.encode(payload, style: .minimal)
        // Swap two characters in the final checksum word.
        var characters = Array(encoded)
        characters[characters.count - 1] = characters[characters.count - 1] == "y" ? "z" : "y"
        XCTAssertThrowsError(try Bytewords.decode(String(characters), style: .minimal))
    }

    // MARK: CBOR determinism

    func testCBORMapsAreDeterministicallyOrdered() {
        let unsorted = CBOR.map([
            CBORMapEntry(.unsigned(8), .unsigned(1)),
            CBORMapEntry(.unsigned(3), .bytes(Data([1, 2, 3]))),
            CBORMapEntry(.unsigned(1), .trueValue),
        ])
        let sorted = CBOR.map([
            CBORMapEntry(.unsigned(1), .trueValue),
            CBORMapEntry(.unsigned(3), .bytes(Data([1, 2, 3]))),
            CBORMapEntry(.unsigned(8), .unsigned(1)),
        ])
        XCTAssertEqual(unsorted.cborData, sorted.cborData)
        XCTAssertEqual(unsorted.cborData.hex, "a301f503430102030801")
    }

    func testCBORIntegerEncodingUsesShortestForm() {
        XCTAssertEqual(CBOR.unsigned(0).cborData.hex, "00")
        XCTAssertEqual(CBOR.unsigned(23).cborData.hex, "17")
        XCTAssertEqual(CBOR.unsigned(24).cborData.hex, "1818")
        XCTAssertEqual(CBOR.unsigned(255).cborData.hex, "18ff")
        XCTAssertEqual(CBOR.unsigned(256).cborData.hex, "190100")
        XCTAssertEqual(CBOR.unsigned(65536).cborData.hex, "1a00010000")
        XCTAssertEqual(CBOR.unsigned(4_294_967_296).cborData.hex, "1b0000000100000000")
        XCTAssertEqual(CBOR.negative(-1).cborData.hex, "20")
        XCTAssertEqual(CBOR.negative(-24).cborData.hex, "37")
    }

    func testCBORRoundTripOfNestedStructures() throws {
        let value = CBOR.map([
            CBORMapEntry(.unsigned(1), .array([.unsigned(1), .trueValue, .text("x")])),
            CBORMapEntry(.unsigned(2), .tagged(40305, .map([CBORMapEntry(.unsigned(2), .unsigned(1))]))),
            CBORMapEntry(.unsigned(3), .bytes(Data(repeating: 0xAB, count: 40))),
            CBORMapEntry(.unsigned(4), .nullValue),
        ])
        let encoded = value.cborData
        XCTAssertEqual(try CBOR(encoded), value)
    }

    func testCBORRejectsIndefiniteLengthsAndTrailingBytes() {
        // 0x9f = indefinite-length array
        XCTAssertThrowsError(try CBOR(Data([0x9f, 0xff])))
        // valid `00` followed by junk
        XCTAssertThrowsError(try CBOR(Data([0x00, 0x00])))
        XCTAssertThrowsError(try CBOR(Data([])))
    }

    // MARK: Single-part and multi-part UR round trips

    func testSinglePartURRoundTrip() throws {
        let key = HDKey(
            keyData: Array(try Hex.decode("026fe2355745bb2db3630bbc80ef5d58951c963c841f54170ba6e5c12be7fc12a6")),
            chainCode: Array(try Hex.decode("ced155c72456255881793514edc5bd9447e7f74abb88c6d6b6480fd016ee8c85")),
            useInfo: CoinInfo(type: 60, network: 0),
            origin: URKeyPath(path: .secp256k1Default),
            parentFingerprint: 0x1234_5678
        )
        for style in URTypeStyle.allCases {
            let ur = try key.ur(style: style)
            let string = ur.string
            XCTAssertTrue(string.hasPrefix("ur:\(style.hdKeyType)/"))
            let decoded = try UR(urString: string)
            XCTAssertEqual(decoded, ur)
            XCTAssertEqual(try HDKey(ur: decoded), key)
        }
    }

    /// An Ed25519 key is 32 bytes of raw point rather than a 33-byte compressed
    /// secp256k1 key, and BCR-2020-007 has no explicit curve field: the length
    /// (plus `use-info`) is what distinguishes them.
    func testEd25519HDKeyRoundTrip() throws {
        let key = HDKey(
            keyData: Array(try Hex.decode("f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7")),
            chainCode: Array(try Hex.decode("fb304a2a20f3d97f5240150cd6261a3f7d52e0981381f2c1f935d124d827de83")),
            useInfo: CoinInfo(type: 501, network: 0),
            origin: URKeyPath(path: .ed25519Default),
            parentFingerprint: 0x0FDB_C659
        )
        XCTAssertEqual(key.keyData.count, 32)
        XCTAssertTrue(key.isEd25519)
        XCTAssertNoThrow(try key.validate())

        for style in URTypeStyle.allCases {
            let ur = try key.ur(style: style)
            let decoded = try UR(urString: ur.string)
            XCTAssertEqual(try HDKey(ur: decoded), key)
            XCTAssertEqual(try HDKey(ur: decoded).useInfo?.type, 501)
        }

        // A 31-byte key-data is neither a valid secp256k1 nor Ed25519 key.
        XCTAssertThrowsError(try HDKey(keyData: [UInt8](repeating: 1, count: 31)).validate())
    }

    func testMultiPartAnimatedURRoundTripWithOutOfOrderReception() throws {
        // A payload large enough to force fragmentation under a realistic
        // QR-sized frame budget.
        let payload = Data((0..<2048).map { UInt8($0 % 256) })
        let ur = try UR(type: "bytes", cbor: .bytes(payload))
        let encoder = UREncoder(ur, maxFragmentLen: 120, minFragmentLen: 20)
        XCTAssertFalse(encoder.isSinglePart)
        XCTAssertGreaterThan(encoder.seqLen, 1)

        // Generate more parts than the minimum (fountain codes) and feed them in
        // reverse order to prove out-of-order tolerance.
        var parts: [String] = []
        for _ in 0..<(encoder.seqLen + 3) {
            parts.append(encoder.nextPart())
        }
        let decoder = URDecoder()
        for part in parts.reversed() {
            decoder.receivePart(part)
            if case .success(let decoded)? = decoder.result {
                XCTAssertEqual(try decoded.cbor.bytesValue, payload)
                XCTAssertGreaterThan(decoder.processedPartsCount, 0)
                return
            }
        }
        XCTFail("multi-part UR did not decode; received \(decoder.receivedFragmentIndexes.count) fragments")
    }

    func testMultiPartSequenceComponentsAreOneBased() throws {
        let payload = Data(repeating: 0x5A, count: 600)
        let ur = try UR(type: "bytes", cbor: .bytes(payload))
        let encoder = UREncoder(ur, maxFragmentLen: 60, minFragmentLen: 20)
        let first = encoder.nextPart()
        let components = first.split(separator: "/")
        XCTAssertEqual(components[0], "ur:bytes")
        let seq = components[1].split(separator: "-")
        XCTAssertEqual(seq[0], "1", "first part must be numbered 1, not 0")
        XCTAssertEqual(Int(seq[1]), encoder.seqLen)
    }

    func testURRejectsUnexpectedTypeAndBadScheme() throws {
        XCTAssertThrowsError(try UR(urString: "ur:crypto-hdkey/otadykax"))
        XCTAssertThrowsError(try UR(urString: "bs:bytes/abcdef"))
        XCTAssertThrowsError(try UR(urString: "ur:URTYPES/abcdef"))
    }

    // MARK: Unknown-field alarm (design.md §6.4)

    func testUnknownHDKeyFieldsAreReportedNotDropped() {
        let withUnknown = CBOR.map([
            CBORMapEntry(.unsigned(3), .bytes(Data(repeating: 0x02, count: 33))),
            CBORMapEntry(.unsigned(42), .text("exfiltration channel")),
            CBORMapEntry(.unsigned(99), .unsigned(1)),
        ])
        XCTAssertEqual(HDKey.unknownFieldKeys(in: withUnknown).sorted(), [42, 99])
    }

    func testURTypeStyleTableMatchesPublishedTags() {
        XCTAssertEqual(URTypeStyle.v2.hdKeyTag, 40303)
        XCTAssertEqual(URTypeStyle.v2.keyPathTag, 40304)
        XCTAssertEqual(URTypeStyle.v2.coinInfoTag, 40305)
        XCTAssertEqual(URTypeStyle.keystoneLegacy.hdKeyTag, 303)
        XCTAssertEqual(URTypeStyle.keystoneLegacy.keyPathTag, 304)
        XCTAssertEqual(URTypeStyle.keystoneLegacy.coinInfoTag, 305)
        XCTAssertEqual(URTypeStyle.keystoneLegacy.hdKeyType, "crypto-hdkey")
        XCTAssertEqual(URTypeStyle.v2.hdKeyType, "hdkey")
    }
}

private extension HDKey {
    /// Convenience for the round-trip test.
    func knownFieldKeysCheck() -> [UInt64] {
        HDKey.unknownFieldKeys(in: cbor(style: .v2))
    }
}
