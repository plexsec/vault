import Foundation

/// FIPS 180-4 SHA-512 plus HMAC-SHA512 (RFC 2104) and PBKDF2-HMAC-SHA512
/// (RFC 8018), which together are exactly what BIP39 needs. Implemented in-repo
/// alongside SHA-256 rather than pulled from CryptoKit.
public struct SHA512Hasher {
    private static let k: [UInt64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]

    private var h: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
    private var block = [UInt8](repeating: 0, count: 128)
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
            let take = min(128 - blockCount, bytes.count - offset)
            for i in 0..<take {
                block[blockCount + i] = bytes[offset + i]
            }
            blockCount += take
            offset += take
            if blockCount == 128 {
                compress()
                blockCount = 0
            }
        }
    }

    public mutating func update(_ data: Data) { update([UInt8](data)) }

    public mutating func finalize() -> [UInt8] {
        precondition(!finalized)
        // 128-bit length in bits; the high 64 bits are zero for any input we
        // will ever hash, but they are written explicitly for spec fidelity.
        let lowBits = totalBytes &* 8
        let highBits: UInt64 = totalBytes >> 61
        var padding: [UInt8] = [0x80]
        let remainder = Int((totalBytes &+ 1) % 128)
        let zeroCount = remainder <= 112 ? 112 - remainder : 240 - remainder
        padding.append(contentsOf: [UInt8](repeating: 0, count: zeroCount))
        for shift in stride(from: 56, through: 0, by: -8) {
            padding.append(UInt8((highBits >> UInt64(shift)) & 0xff))
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            padding.append(UInt8((lowBits >> UInt64(shift)) & 0xff))
        }
        absorb(padding)
        precondition(blockCount == 0)
        finalized = true

        var out = [UInt8]()
        out.reserveCapacity(64)
        for word in h {
            for shift in stride(from: 56, through: 0, by: -8) {
                out.append(UInt8((word >> UInt64(shift)) & 0xff))
            }
        }
        return out
    }

    private mutating func compress() {
        var w = [UInt64](repeating: 0, count: 80)
        for i in 0..<16 {
            let o = i * 8
            var v: UInt64 = 0
            for j in 0..<8 {
                v = (v << 8) | UInt64(block[o + j])
            }
            w[i] = v
        }
        for i in 16..<80 {
            let s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7)
            let s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
        }

        var a = h[0], b = h[1], c = h[2], d = h[3]
        var e = h[4], f = h[5], g = h[6], hh = h[7]

        for i in 0..<80 {
            let s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41)
            let ch = (e & f) ^ (~e & g)
            let temp1 = hh &+ s1 &+ ch &+ Self.k[i] &+ w[i]
            let s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39)
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
    private func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 {
        (x >> n) | (x << (64 - n))
    }
}

public enum SHA512 {
    public static func hash(_ bytes: [UInt8]) -> [UInt8] {
        var hasher = SHA512Hasher()
        hasher.update(bytes)
        return hasher.finalize()
    }

    public static func hash(_ data: Data) -> [UInt8] { hash([UInt8](data)) }
    public static func hash(_ string: String) -> [UInt8] { hash([UInt8](string.utf8)) }
}

/// HMAC-SHA512 (RFC 2104). Block size 128 bytes, 64-byte output.
public enum HMACSHA512 {
    public static let blockSize = 128

    public static func authenticate(key: [UInt8], message: [UInt8]) -> [UInt8] {
        var normalizedKey = key
        if normalizedKey.count > blockSize {
            normalizedKey = SHA512.hash(normalizedKey)
        }
        if normalizedKey.count < blockSize {
            normalizedKey.append(contentsOf: [UInt8](repeating: 0, count: blockSize - normalizedKey.count))
        }

        var innerPad = [UInt8](repeating: 0x36, count: blockSize)
        var outerPad = [UInt8](repeating: 0x5c, count: blockSize)
        for i in 0..<blockSize {
            innerPad[i] ^= normalizedKey[i]
            outerPad[i] ^= normalizedKey[i]
        }

        var inner = SHA512Hasher()
        inner.update(innerPad)
        inner.update(message)
        let innerDigest = inner.finalize()

        var outer = SHA512Hasher()
        outer.update(outerPad)
        outer.update(innerDigest)

        let result = outer.finalize()

        // Scrub key-derived material.
        wipe(&normalizedKey)
        wipe(&innerPad)
        wipe(&outerPad)

        return result
    }
}

/// PBKDF2-HMAC-SHA512 (RFC 8018). Used only for BIP39 seed derivation.
public enum PBKDF2 {
    public enum Error: Swift.Error, Equatable { case invalidIterationCount, invalidKeyLength }

    public static func hmacSHA512(
        password: [UInt8],
        salt: [UInt8],
        iterations: Int,
        keyLength: Int
    ) throws -> [UInt8] {
        guard iterations > 0 else { throw Error.invalidIterationCount }
        guard keyLength > 0 else { throw Error.invalidKeyLength }

        let hashLength = 64
        let blockCount = (keyLength + hashLength - 1) / hashLength
        var derived = [UInt8]()
        derived.reserveCapacity(blockCount * hashLength)

        for blockIndex in 1...blockCount {
            var saltBlock = salt
            saltBlock.append(UInt8((blockIndex >> 24) & 0xff))
            saltBlock.append(UInt8((blockIndex >> 16) & 0xff))
            saltBlock.append(UInt8((blockIndex >> 8) & 0xff))
            saltBlock.append(UInt8(blockIndex & 0xff))

            var u = HMACSHA512.authenticate(key: password, message: saltBlock)
            var accumulator = u
            if iterations > 1 {
                for _ in 2...iterations {
                    u = HMACSHA512.authenticate(key: password, message: u)
                    for i in 0..<accumulator.count {
                        accumulator[i] ^= u[i]
                    }
                }
            }
            derived.append(contentsOf: accumulator)
            wipe(&u)
            wipe(&accumulator)
            wipe(&saltBlock)
        }

        let result = Array(derived.prefix(keyLength))
        wipe(&derived)
        return result
    }
}
