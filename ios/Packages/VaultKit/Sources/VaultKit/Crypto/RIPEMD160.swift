import Foundation

/// RIPEMD-160 (ISO/IEC 10118-3), needed for Bitcoin's HASH160 (SHA-256 followed
/// by RIPEMD-160) in P2WPKH addresses and BIP32 key fingerprints.
public struct RIPEMD160Hasher {
    private static let rLeft: [Int] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]

    private static let rRight: [Int] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]

    private static let sLeft: [UInt32] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]

    private static let sRight: [UInt32] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]

    private static let kLeft: [UInt32] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    private static let kRight: [UInt32] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    private var h: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    private var block = [UInt8](repeating: 0, count: 64)
    private var blockCount = 0
    private var totalBytes: UInt64 = 0
    private var finalized = false

    public init() {}

    public mutating func update(_ bytes: [UInt8]) {
        precondition(!finalized)
        absorb(bytes)
    }

    public mutating func update(_ data: Data) { update([UInt8](data)) }

    private mutating func absorb(_ bytes: [UInt8]) {
        totalBytes &+= UInt64(bytes.count)
        var offset = 0
        while offset < bytes.count {
            let take = min(64 - blockCount, bytes.count - offset)
            for i in 0..<take {
                block[blockCount + i] = bytes[offset + i]
            }
            blockCount += take
            offset += take
            if blockCount == 64 {
                compress()
                blockCount = 0
            }
        }
    }

    public mutating func finalize() -> [UInt8] {
        precondition(!finalized)
        let bitLength = totalBytes &* 8
        var padding: [UInt8] = [0x80]
        let remainder = Int((totalBytes &+ 1) % 64)
        let zeroCount = remainder <= 56 ? 56 - remainder : 120 - remainder
        padding.append(contentsOf: [UInt8](repeating: 0, count: zeroCount))
        for shift in stride(from: 0, through: 56, by: 8) {
            padding.append(UInt8((bitLength >> UInt64(shift)) & 0xff))
        }
        absorb(padding)
        precondition(blockCount == 0)
        finalized = true

        var out = [UInt8]()
        out.reserveCapacity(20)
        for word in h {
            out.append(UInt8(word & 0xff))
            out.append(UInt8((word >> 8) & 0xff))
            out.append(UInt8((word >> 16) & 0xff))
            out.append(UInt8((word >> 24) & 0xff))
        }
        return out
    }

    private mutating func compress() {
        var x = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            let o = i * 4
            x[i] = UInt32(block[o]) | UInt32(block[o + 1]) << 8 | UInt32(block[o + 2]) << 16 | UInt32(block[o + 3]) << 24
        }

        var al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4]
        var ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4]

        for j in 0..<80 {
            let round = j / 16

            var tl = al &+ f(round, bl, cl, dl) &+ x[Self.rLeft[j]] &+ Self.kLeft[round]
            tl = rotl(tl, Self.sLeft[j]) &+ el
            al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl

            var tr = ar &+ f(4 - round, br, cr, dr) &+ x[Self.rRight[j]] &+ Self.kRight[round]
            tr = rotl(tr, Self.sRight[j]) &+ er
            ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr
        }

        let t = h[1] &+ cl &+ dr
        h[1] = h[2] &+ dl &+ er
        h[2] = h[3] &+ el &+ ar
        h[3] = h[4] &+ al &+ br
        h[4] = h[0] &+ bl &+ cr
        h[0] = t
    }

    @inline(__always)
    private func f(_ round: Int, _ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        switch round {
        case 0: return x ^ y ^ z
        case 1: return (x & y) | (~x & z)
        case 2: return (x | ~y) ^ z
        case 3: return (x & z) | (y & ~z)
        default: return x ^ (y | ~z)
        }
    }

    @inline(__always)
    private func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x << n) | (x >> (32 - n))
    }
}

public enum RIPEMD160 {
    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = RIPEMD160Hasher()
        hasher.update(bytes)
        return hasher.finalize()
    }

    public static func hash(_ data: Data) -> [UInt8] { hash([UInt8](data)) }

    /// Bitcoin's HASH160: RIPEMD-160(SHA-256(data)).
    public static func hash160(_ bytes: [UInt8]) -> [UInt8] {
        hash(SHA256.hash(bytes))
    }
}
