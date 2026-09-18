import Foundation

/// BER-TLV encoding and parsing, as used by the OpenPGP smart card.
///
/// Only definite-length, short-form-plus-2-byte lengths are needed: the largest
/// object this app reads or writes is the key import at ~41 bytes and the
/// largest it parses is the application data at a few hundred bytes.
public struct TLV: Equatable {
    public let tag: UInt16
    public let value: [UInt8]

    public init(tag: UInt16, value: [UInt8]) {
        self.tag = tag
        self.value = value
    }

    /// `tag || length || value`.
    public var encoded: [UInt8] {
        var out = TLV.encodeTag(tag)
        out.append(contentsOf: TLV.encodeLength(value.count))
        out.append(contentsOf: value)
        return out
    }

    public static func encodeTag(_ tag: UInt16) -> [UInt8] {
        tag <= 0xFF ? [UInt8(tag)] : [UInt8(tag >> 8), UInt8(tag & 0xFF)]
    }

    public static func encodeLength(_ length: Int) -> [UInt8] {
        precondition(length >= 0 && length <= 0xFFFF, "length out of range for this encoder")
        if length <= 0x7F {
            return [UInt8(length)]
        }
        if length <= 0xFF {
            return [0x81, UInt8(length)]
        }
        return [0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
    }

    /// Whether a tag's first byte indicates a constructed (nested) object.
    public static func isConstructed(_ tag: UInt16) -> Bool {
        (UInt8(tag >> 8) & 0x20) != 0
    }
}

public enum TLVError: Swift.Error, Equatable {
    case truncated(offset: Int)
    case lengthOverflow(offset: Int)
}

/// Parses a BER-TLV byte string into a flat list of top-level objects.
/// Nested objects are not recursed into automatically; callers use
/// `TLV.children(of:)` when they need to descend.
public enum TLVParser {
    public static func parse(_ bytes: [UInt8]) throws -> [TLV] {
        var result: [TLV] = []
        var index = 0
        while index < bytes.count {
            let (tlv, next) = try parseOne(bytes, at: index)
            result.append(tlv)
            index = next
        }
        return result
    }

    static func parseOne(_ bytes: [UInt8], at start: Int) throws -> (TLV, Int) {
        var index = start
        guard index < bytes.count else { throw TLVError.truncated(offset: start) }

        // Tag: one or two bytes. Multi-byte tags have the low 5 bits of the first
        // byte set to 0x1F.
        var tag: UInt16 = UInt16(bytes[index])
        index += 1
        if (bytes[start] & 0x1F) == 0x1F {
            guard index < bytes.count else { throw TLVError.truncated(offset: start) }
            tag = (tag << 8) | UInt16(bytes[index])
            index += 1
        }

        guard index < bytes.count else { throw TLVError.truncated(offset: start) }
        let firstLengthByte = bytes[index]
        index += 1

        var length = 0
        if firstLengthByte <= 0x7F {
            length = Int(firstLengthByte)
        } else if firstLengthByte == 0x80 {
            // Indefinite length: not used by the OpenPGP card.
            throw TLVError.lengthOverflow(offset: index - 1)
        } else {
            let count = Int(firstLengthByte & 0x7F)
            guard count <= 3, index + count <= bytes.count else {
                throw TLVError.lengthOverflow(offset: index - 1)
            }
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[index])
                index += 1
            }
        }

        guard index + length <= bytes.count else { throw TLVError.truncated(offset: index) }
        let value = Array(bytes[index..<(index + length)])
        return (TLV(tag: tag, value: value), index + length)
    }

    /// Parses the value of a constructed TLV as a list of child objects.
    public static func children(of tlv: TLV) throws -> [TLV] {
        try parse(tlv.value)
    }

    /// Depth-first search for the first object with `tag`.
    public static func find(_ tag: UInt16, in tlv: TLV) -> TLV? {
        search(tag, in: tlv.value)
    }

    /// Depth-first search across a flat list.
    public static func find(_ tag: UInt16, in tlvs: [TLV]) -> TLV? {
        for tlv in tlvs {
            if tlv.tag == tag { return tlv }
            if let found = search(tag, in: tlv.value) { return found }
        }
        return nil
    }

    private static func search(_ tag: UInt16, in value: [UInt8]) -> TLV? {
        guard let children = try? parse(value) else { return nil }
        for child in children {
            if child.tag == tag { return child }
            if let found = search(tag, in: child.value) { return found }
        }
        return nil
    }

    /// Collects all objects with `tag` at any depth.
    public static func findAll(_ tag: UInt16, in tlvs: [TLV]) -> [TLV] {
        var out: [TLV] = []
        for tlv in tlvs {
            if tlv.tag == tag { out.append(tlv) }
            if let children = try? parse(tlv.value) {
                out.append(contentsOf: findAll(tag, in: children))
            }
        }
        return out
    }
}
