import Foundation

/// An ECDSA signature over secp256k1: two 32-byte scalars.
///
/// This is what comes back from the YubiKey (as DER) and what goes into the
/// `eth-signature` UR (as `r ‖ s ‖ v`). The type keeps the two halves separate
/// because everything that can go wrong with a signature happens to one half at a
/// time: a short `r`, an `s` above `n/2`, a zero value.
public struct ECDSASignature: Equatable, Sendable {
    /// 32 bytes, big-endian.
    public let r: [UInt8]
    /// 32 bytes, big-endian.
    public let s: [UInt8]

    public enum Error: Swift.Error, Equatable {
        case wrongScalarLength(Int)
        case zeroScalar
        case scalarOutOfRange
        case malformedDER(reason: String)
        case unexpectedCardResponse(length: Int)
    }

    /// Order of the secp256k1 group.
    public static let curveOrder: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    ]

    /// `n/2`, the low-s threshold both Ethereum (EIP-2) and Bitcoin standardness
    /// require. A signature above it is malleable: `(r, n-s)` verifies for the
    /// same message and key, so a transaction's hash would not be unique.
    public static let halfCurveOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ]

    public init(r: [UInt8], s: [UInt8]) throws {
        guard r.count == 32 else { throw Error.wrongScalarLength(r.count) }
        guard s.count == 32 else { throw Error.wrongScalarLength(s.count) }
        guard !r.allSatisfy({ $0 == 0 }), !s.allSatisfy({ $0 == 0 }) else { throw Error.zeroScalar }
        guard Self.compare(r, Self.curveOrder) < 0, Self.compare(s, Self.curveOrder) < 0 else {
            throw Error.scalarOutOfRange
        }
        self.r = r
        self.s = s
    }

    // MARK: - Card responses

    /// Decodes what the OpenPGP applet returns from `PSO:CDS`.
    ///
    /// The OpenPGP card specification has ECDSA signatures returned as a DER
    /// `SEQUENCE { r INTEGER, s INTEGER }`, and that is what YubiKey firmware
    /// implements. A bare 64-byte `r ‖ s` is accepted as well, because the two
    /// forms cannot be confused — DER starts with `0x30`, which cannot be the
    /// first byte of a `r` that is both valid and less than `n`... it *could* be,
    /// so the raw form is only tried after DER parsing has failed, and which form
    /// was seen is reported to the caller for the hardware check.
    public static func decode(cardResponse: [UInt8]) throws -> ECDSASignature {
        if let der = try? decodeDER(cardResponse) { return der }
        if cardResponse.count == 64 {
            return try ECDSASignature(
                r: Array(cardResponse[0..<32]),
                s: Array(cardResponse[32..<64])
            )
        }
        throw Error.unexpectedCardResponse(length: cardResponse.count)
    }

    /// Strict DER: one `SEQUENCE` of exactly two minimally-encoded positive
    /// `INTEGER`s and nothing after it.
    public static func decodeDER(_ der: [UInt8]) throws -> ECDSASignature {
        var cursor = Cursor(der)
        guard try cursor.byte() == 0x30 else { throw Error.malformedDER(reason: "not a SEQUENCE") }
        let bodyLength = try cursor.length()
        let bodyEnd = cursor.offset + bodyLength
        guard bodyEnd == der.count else {
            throw Error.malformedDER(reason: "SEQUENCE length \(bodyLength) does not match \(der.count) bytes")
        }
        let r = try decodeInteger(&cursor)
        let s = try decodeInteger(&cursor)
        guard cursor.offset == bodyEnd else { throw Error.malformedDER(reason: "trailing bytes") }
        return try ECDSASignature(r: r, s: s)
    }

    private static func decodeInteger(_ cursor: inout Cursor) throws -> [UInt8] {
        guard try cursor.byte() == 0x02 else { throw Error.malformedDER(reason: "expected INTEGER") }
        let length = try cursor.length()
        guard length > 0 else { throw Error.malformedDER(reason: "empty INTEGER") }
        let bytes = try cursor.bytes(length)
        // A leading zero is only legal to keep the value positive, and a negative
        // value is never a valid scalar.
        if bytes[0] & 0x80 != 0 { throw Error.malformedDER(reason: "negative INTEGER") }
        var value = bytes
        if value.count > 1, value[0] == 0x00 {
            value.removeFirst()
            guard value[0] & 0x80 != 0 else {
                throw Error.malformedDER(reason: "non-minimal INTEGER")
            }
        }
        // Left-pad to 32 bytes; anything longer is out of range for secp256k1 and
        // is rejected by the initialiser rather than truncated.
        guard value.count <= 32 else { throw Error.scalarOutOfRange }
        return [UInt8](repeating: 0, count: 32 - value.count) + value
    }

    private struct Cursor {
        let bytes: [UInt8]
        var offset = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        mutating func byte() throws -> UInt8 {
            guard offset < bytes.count else { throw Error.malformedDER(reason: "truncated") }
            defer { offset += 1 }
            return bytes[offset]
        }

        /// DER short/long form length, minimal.
        mutating func length() throws -> Int {
            let first = try byte()
            if first < 0x80 { return Int(first) }
            let count = Int(first & 0x7f)
            guard count >= 1, count <= 3 else { throw Error.malformedDER(reason: "unsupported length form") }
            let lengthBytes = try bytes(count)
            guard lengthBytes[0] != 0 else { throw Error.malformedDER(reason: "non-minimal length") }
            var value = 0
            for byte in lengthBytes { value = value << 8 | Int(byte) }
            guard value > 0x7f else { throw Error.malformedDER(reason: "long form for a short length") }
            return value
        }

        mutating func bytes(_ count: Int) throws -> [UInt8] {
            guard count >= 0, offset + count <= bytes.count else {
                throw Error.malformedDER(reason: "truncated")
            }
            defer { offset += count }
            return Array(bytes[offset..<(offset + count)])
        }
    }

    // MARK: - Low-s

    /// True when `s <= n/2`.
    public var isLowS: Bool { Self.compare(s, Self.halfCurveOrder) <= 0 }

    /// `(r, n - s)` when `s > n/2`, plus whether that changed anything.
    ///
    /// Negating `s` flips the recovered point's y parity, so callers must flip the
    /// recovery value too — that is why the flag is returned rather than the
    /// caller checking `isLowS` itself.
    public func normalisedLowS() -> (signature: ECDSASignature, flipped: Bool) {
        guard !isLowS else { return (self, false) }
        let negated = Self.subtract(Self.curveOrder, s)
        // `s` is in (n/2, n), so `n - s` is in (0, n/2): both scalars stay valid.
        guard let normalised = try? ECDSASignature(r: r, s: negated) else { return (self, false) }
        return (normalised, true)
    }

    // MARK: - Byte comparison helpers

    /// Unsigned big-endian comparison of equal-width magnitudes.
    static func compare(_ lhs: [UInt8], _ rhs: [UInt8]) -> Int {
        precondition(lhs.count == rhs.count)
        for (left, right) in zip(lhs, rhs) where left != right {
            return left < right ? -1 : 1
        }
        return 0
    }

    /// `lhs - rhs` for equal-width big-endian magnitudes with `lhs >= rhs`.
    static func subtract(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: lhs.count)
        var borrow = 0
        for index in stride(from: lhs.count - 1, through: 0, by: -1) {
            let difference = Int(lhs[index]) - Int(rhs[index]) - borrow
            if difference < 0 {
                result[index] = UInt8(difference + 256)
                borrow = 1
            } else {
                result[index] = UInt8(difference)
                borrow = 0
            }
        }
        return result
    }
}
