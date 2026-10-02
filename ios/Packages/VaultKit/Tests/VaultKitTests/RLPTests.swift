import Foundation
import XCTest

@testable import VaultKit

/// RLP against the published reference vectors.
///
/// The valid set exercises every length form; the invalid set is the reference's
/// own catalogue of encodings that must be refused. The second half is the part
/// that matters here: the app hashes the exact bytes it decoded, so an encoding
/// this decoder accepts but the reference rejects would be a way to make a
/// displayed transaction differ from the signed one.
final class RLPTests: XCTestCase {
    private static let subdirectory = "Fixtures/RLPTests"

    func testPublishedValidVectors() throws {
        let vectors = try load("rlptest")
        XCTAssertEqual(vectors.count, 28, "the reference suite has 28 valid vectors")

        for (name, vector) in vectors.sorted(by: { $0.key < $1.key }) {
            guard let input = vector["in"], let output = vector["out"] as? String else {
                return XCTFail("vector \(name) is malformed")
            }
            let item = try Self.item(fromJSON: input, name: name)
            let encoded = try Self.hex(output)

            XCTAssertEqual(RLP.encode(item), encoded, "encoding of \(name)")
            XCTAssertEqual(try RLP.decode(encoded), item, "decoding of \(name)")
            // Re-encoding what was decoded must reproduce the input exactly: this
            // is the property the transaction display depends on.
            XCTAssertEqual(RLP.encode(try RLP.decode(encoded)), encoded, "round trip of \(name)")
        }
    }

    func testPublishedInvalidVectorsAreRefused() throws {
        let vectors = try load("invalidRLPTest")
        XCTAssertEqual(vectors.count, 26, "the reference suite has 26 invalid vectors")

        for (name, vector) in vectors.sorted(by: { $0.key < $1.key }) {
            guard let output = vector["out"] as? String else {
                return XCTFail("vector \(name) is malformed")
            }
            let bytes = try Self.hex(output)
            XCTAssertThrowsError(try RLP.decode(bytes), "\(name) must be refused") { error in
                // Any refusal is acceptable, but it must be one of ours rather
                // than a crash or a decode that happened to be ignored.
                XCTAssertTrue(error is RLP.Error, "\(name) refused with \(error)")
            }
        }
    }

    /// The two ends of the short/long length boundary, which is where an
    /// off-by-one in the length prefix hides.
    func testLongFormBoundary() {
        for length in [54, 55, 56, 57] {
            let payload = [UInt8](repeating: 0xab, count: length)
            let encoded = RLP.encode(.bytes(payload))
            if length < 56 {
                XCTAssertEqual(encoded.first, 0x80 + UInt8(length), "short form for \(length)")
            } else {
                XCTAssertEqual(encoded.first, 0xb8, "long form for \(length)")
                XCTAssertEqual(encoded[1], UInt8(length))
            }
            XCTAssertEqual(try? RLP.decode(encoded), .bytes(payload), "round trip of \(length)")
        }
    }

    func testSingleByteEncoding() {
        XCTAssertEqual(RLP.encode(.bytes([0x00])), [0x00])
        XCTAssertEqual(RLP.encode(.bytes([0x7f])), [0x7f])
        XCTAssertEqual(RLP.encode(.bytes([0x80])), [0x81, 0x80])
        XCTAssertEqual(RLP.encode(.bytes([])), [0x80])
        XCTAssertEqual(RLP.encode(.list([])), [0xc0])
        XCTAssertEqual(RLP.encode(.list([.list([]), .list([.list([])])])), [0xc3, 0xc0, 0xc1, 0xc0])
    }

    func testEmptyInputIsRefused() {
        XCTAssertThrowsError(try RLP.decode([])) { error in
            XCTAssertEqual(error as? RLP.Error, .emptyInput)
        }
    }

    func testTrailingBytesAreRefused() {
        XCTAssertThrowsError(try RLP.decode([0x80, 0x80])) { error in
            XCTAssertEqual(error as? RLP.Error, .trailingBytes)
        }
    }

    func testDecodeListRejectsAByteString() {
        XCTAssertThrowsError(try RLP.decodeList([0x83, 0x64, 0x6f, 0x67])) { error in
            XCTAssertEqual(error as? RLP.Error, .expectedList)
        }
    }

    func testNestingDepthIsBounded() {
        // 32 nested single-item lists: encodable in principle, refused because
        // nothing legitimate is that deep.
        var item = RLP.Item.bytes([])
        for _ in 0..<32 { item = .list([item]) }
        let encoded = RLP.encode(item)
        XCTAssertThrowsError(try RLP.decode(encoded)) { error in
            XCTAssertEqual(error as? RLP.Error, .nestingTooDeep)
        }
    }

    // MARK: - Helpers

    private func load(_ name: String) throws -> [String: [String: Any]] {
        let json = try FixtureLoader.json(name, extension: "json", subdirectory: Self.subdirectory)
        guard let vectors = json as? [String: [String: Any]] else {
            throw FixtureLoader.FixtureError.notUTF8("\(name).json is not a vector map")
        }
        return vectors
    }

    /// The reference suite's conventions: a `#`-prefixed string is a decimal
    /// integer, any other string is UTF-8 text, a number is an integer and an
    /// array is a list.
    static func item(fromJSON value: Any, name: String) throws -> RLP.Item {
        switch value {
        case let string as String:
            if string.hasPrefix("#") {
                return .bytes(try minimalBytes(decimal: String(string.dropFirst())))
            }
            return .bytes(Array(string.utf8))
        case let number as NSNumber:
            return .bytes(try minimalBytes(decimal: String(UInt64(truncating: number))))
        case let array as [Any]:
            return .list(try array.map { try item(fromJSON: $0, name: name) })
        default:
            throw FixtureLoader.FixtureError.notUTF8("\(name): unsupported JSON value \(value)")
        }
    }

    static func hex(_ string: String) throws -> [UInt8] {
        var text = string
        if text.hasPrefix("0x") || text.hasPrefix("0X") { text.removeFirst(2) }
        if text.isEmpty { return [] }
        return try Hex.decode(text)
    }

    /// Decimal string to minimal big-endian bytes, by repeated multiply-and-add.
    static func minimalBytes(decimal: String) throws -> [UInt8] {
        var bytes: [UInt8] = []
        for character in decimal {
            guard let digit = character.wholeNumberValue, (0...9).contains(digit) else {
                throw FixtureLoader.FixtureError.notUTF8("not a decimal integer: \(decimal)")
            }
            var carry = digit
            for index in stride(from: bytes.count - 1, through: 0, by: -1) {
                let value = Int(bytes[index]) * 10 + carry
                bytes[index] = UInt8(value & 0xff)
                carry = value >> 8
            }
            while carry > 0 {
                bytes.insert(UInt8(carry & 0xff), at: 0)
                carry >>= 8
            }
        }
        while bytes.first == 0 { bytes.removeFirst() }
        return bytes
    }
}
