import Foundation

/// Recursive Length Prefix (Ethereum's serialisation), strict.
///
/// Strictness is the whole point here, not a style choice. The signing ceremony
/// displays fields decoded from these bytes and then hashes *the same bytes*: if
/// a decode could accept two different encodings of the same transaction, or
/// accept bytes whose re-encoding differs from the input, then what the operator
/// reads on screen and what the card signs could diverge. So this decoder
/// refuses every non-minimal form — a length in a long form that fits the short
/// form, a length with leading zero bytes, a single byte < 0x80 encoded as a
/// one-byte string — and callers compare `encode(decode(x)) == x` on top.
public enum RLP {
    public indirect enum Item: Equatable, Sendable {
        /// A byte string. Empty is legal and encodes as `0x80`.
        case bytes([UInt8])
        /// A list, possibly empty (`0xc0`).
        case list([Item])
    }

    public enum Error: Swift.Error, Equatable {
        case emptyInput
        case truncated
        case trailingBytes
        /// A long-form length that fits in the short form.
        case nonCanonicalLength
        /// A length with leading zero bytes.
        case nonCanonicalLengthPadding
        /// A single byte below 0x80 encoded as a one-byte string.
        case nonCanonicalSingleByte
        /// Length prefix longer than the payload could ever be.
        case lengthOutOfRange
        case nestingTooDeep
        case expectedList
    }

    /// EVM transactions nest a handful of levels at most. A deep input is either
    /// corrupt or hostile, and refusing it keeps the decoder's stack bounded.
    public static let maximumDepth = 24

    // MARK: - Encoding

    public static func encode(_ item: Item) -> [UInt8] {
        var out: [UInt8] = []
        append(item, to: &out)
        return out
    }

    private static func append(_ item: Item, to out: inout [UInt8]) {
        switch item {
        case .bytes(let bytes):
            if bytes.count == 1, bytes[0] < 0x80 {
                out.append(bytes[0])
                return
            }
            appendLength(bytes.count, base: 0x80, to: &out)
            out.append(contentsOf: bytes)
        case .list(let items):
            var body: [UInt8] = []
            for child in items { append(child, to: &body) }
            appendLength(body.count, base: 0xc0, to: &out)
            out.append(contentsOf: body)
        }
    }

    private static func appendLength(_ length: Int, base: UInt8, to out: inout [UInt8]) {
        precondition(length >= 0)
        if length < 56 {
            out.append(base + UInt8(length))
            return
        }
        let encoded = minimalBigEndian(UInt64(length))
        // A payload this large cannot be encoded in RLP's 8-byte length field.
        precondition(encoded.count <= 8, "RLP payload length out of range")
        out.append(base + 55 + UInt8(encoded.count))
        out.append(contentsOf: encoded)
    }

    private static func minimalBigEndian(_ value: UInt64) -> [UInt8] {
        var out: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            out.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        return out
    }

    // MARK: - Decoding

    public static func decode(_ input: [UInt8]) throws -> Item {
        var decoder = Decoder(input)
        let item = try decoder.decodeItem(depth: 0)
        guard decoder.isAtEnd else { throw Error.trailingBytes }
        return item
    }

    /// Decodes a single top-level list. Every EVM transaction — typed or legacy —
    /// is one, so callers that want a transaction rarely want a bare `Item`.
    public static func decodeList(_ input: [UInt8]) throws -> [Item] {
        guard case .list(let items) = try decode(input) else { throw Error.expectedList }
        return items
    }

    private struct Decoder {
        let input: [UInt8]
        var offset = 0

        init(_ input: [UInt8]) { self.input = input }

        var isAtEnd: Bool { offset >= input.count }

        mutating func decodeItem(depth: Int) throws -> Item {
            guard depth < maximumDepth else { throw Error.nestingTooDeep }
            guard offset < input.count else { throw Error.emptyInput }
            let prefix = input[offset]
            offset += 1

            switch prefix {
            case 0x00...0x7f:
                return .bytes([prefix])

            case 0x80...0xb7:
                let length = Int(prefix - 0x80)
                let payload = try read(length)
                // 0x81 0x00..0x7f has a shorter encoding.
                if length == 1, payload[0] < 0x80 { throw Error.nonCanonicalSingleByte }
                return .bytes(payload)

            case 0xb8...0xbf:
                let length = try readLongLength(additional: Int(prefix - 0xb7))
                guard length >= 56 else { throw Error.nonCanonicalLength }
                return .bytes(try read(length))

            case 0xc0...0xf7:
                let length = Int(prefix - 0xc0)
                return .list(try decodeListPayload(length: length, depth: depth))

            default:
                let length = try readLongLength(additional: Int(prefix - 0xf7))
                guard length >= 56 else { throw Error.nonCanonicalLength }
                return .list(try decodeListPayload(length: length, depth: depth))
            }
        }

        private mutating func decodeListPayload(length: Int, depth: Int) throws -> [Item] {
            let end = try payloadEnd(length)
            var items: [Item] = []
            while offset < end {
                items.append(try decodeItem(depth: depth + 1))
            }
            guard offset == end else { throw Error.lengthOutOfRange }
            return items
        }

        private mutating func readLongLength(additional: Int) throws -> Int {
            guard additional >= 1, additional <= 8 else { throw Error.lengthOutOfRange }
            let bytes = try read(additional)
            // A length is an unsigned big-endian integer; leading zeros are not
            // a shorter encoding of the same value, they are a different input
            // that would hash differently.
            guard bytes[0] != 0 else { throw Error.nonCanonicalLengthPadding }
            var length: UInt64 = 0
            for byte in bytes { length = length << 8 | UInt64(byte) }
            guard length <= UInt64(Int.max) else { throw Error.lengthOutOfRange }
            return Int(length)
        }

        private mutating func read(_ count: Int) throws -> [UInt8] {
            let end = try payloadEnd(count)
            let payload = Array(input[offset..<end])
            offset = end
            return payload
        }

        /// Validates that `count` bytes remain, without consuming them.
        private func payloadEnd(_ count: Int) throws -> Int {
            guard count >= 0, count <= input.count - offset else { throw Error.truncated }
            return offset + count
        }
    }
}
