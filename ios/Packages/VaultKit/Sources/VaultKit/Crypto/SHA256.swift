import Foundation

/// FIPS 180-4 SHA-256, implemented in-repo (no CryptoKit dependency) so the
/// whole hash surface used for key derivation is reviewable in one place and
/// testable against published vectors.
public struct SHA256Hasher {
    private static let k: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    private var h: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]
    private var block = [UInt8](repeating: 0, count: 64)
    private var blockCount = 0
    private var totalBytes: UInt64 = 0
    private var finalized = false

    public init() {}

    public mutating func update(_ bytes: [UInt8]) {
        precondition(!finalized)
        absorb(bytes)
    }

    /// Padding absorption path: must not be gated on `finalized`, because
    /// `finalize()` feeds the padding through it.
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

    public mutating func update(_ data: Data) {
        update([UInt8](data))
    }

    public mutating func update(_ string: String) {
        update([UInt8](string.utf8))
    }

    public mutating func finalize() -> [UInt8] {
        precondition(!finalized)
        let bitLength = totalBytes &* 8
        var padding: [UInt8] = [0x80]
        let remainder = Int((totalBytes &+ 1) % 64)
        let zeroCount = remainder <= 56 ? 56 - remainder : 120 - remainder
        padding.append(contentsOf: [UInt8](repeating: 0, count: zeroCount))
        for shift in stride(from: 56, through: 0, by: -8) {
            padding.append(UInt8((bitLength >> UInt64(shift)) & 0xff))
        }
        absorb(padding)
        precondition(blockCount == 0)
        finalized = true

        var out = [UInt8]()
        out.reserveCapacity(32)
        for word in h {
            out.append(UInt8((word >> 24) & 0xff))
            out.append(UInt8((word >> 16) & 0xff))
            out.append(UInt8((word >> 8) & 0xff))
            out.append(UInt8(word & 0xff))
        }
        return out
    }

    private mutating func compress() {
        var w = [UInt32](repeating: 0, count: 64)
        for i in 0..<16 {
            let o = i * 4
            w[i] = UInt32(block[o]) << 24 | UInt32(block[o + 1]) << 16 | UInt32(block[o + 2]) << 8 | UInt32(block[o + 3])
        }
        for i in 16..<64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
        }

        var a = h[0], b = h[1], c = h[2], d = h[3]
        var e = h[4], f = h[5], g = h[6], hh = h[7]

        for i in 0..<64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            let ch = (e & f) ^ (~e & g)
            let temp1 = hh &+ s1 &+ ch &+ Self.k[i] &+ w[i]
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ maj
            hh = g; g = f; f = e
            e = d &+ temp1
            d = c; c = b; b = a
            a = temp1 &+ temp2
        }

        h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
        h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
    }

    @inline(__always)
    private func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
        (x >> n) | (x << (32 - n))
    }
}

public enum SHA256 {
    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = SHA256Hasher()
        hasher.update(bytes)
        return hasher.finalize()
    }

    public static func hash(_ data: Data) -> [UInt8] {
        hash([UInt8](data))
    }

    public static func hash(_ string: String) -> [UInt8] {
        hash([UInt8](string.utf8))
    }

    public static func hashHex(_ bytes: [UInt8]) -> String {
        Hex.encode(hash(bytes))
    }
}
