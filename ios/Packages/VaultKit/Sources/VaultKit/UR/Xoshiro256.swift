//
// Ported from Blockchain Commons URKit (Sources/URKit/Fountain/Xoshiro256.swift)
// https://github.com/BlockchainCommons/URKit
// Licensed under the "BSD-2-Clause Plus Patent License"; see LICENSE-URKit.txt
//
// Adaptation for VaultKit: CryptoKit's SHA256Digest is replaced by VaultKit's
// in-repo SHA256 so that this package has no CryptoKit dependency. The generator
// itself is unmodified (public domain, Blackman & Vigna). The unused `jump()` and
// `longJump()` helpers were dropped because VaultKit never runs parallel
// generator streams.
//

import Foundation

// http://xoshiro.di.unimi.it/xoshiro256starstar.c

/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

/* This is xoshiro256** 1.0, one of our all-purpose, rock-solid
   generators. It has excellent (sub-ns) speed, a state (256 bits) that is
   large enough for any parallel application, and it passes all tests we
   are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */
final class Xoshiro256: RandomNumberGenerator {
    var state: [UInt64]

    init(state: [UInt64]) {
        assert(state.count == 4)
        self.state = state
    }

    /// Seeds from a 32-byte SHA-256 digest (little-endian 64-bit lanes).
    convenience init(digest: [UInt8]) {
        precondition(digest.count == 32)
        var s = [UInt64](repeating: 0, count: 4)
        for i in 0..<4 {
            let o = i * 8
            var v: UInt64 = 0
            for n in 0..<8 {
                v <<= 8
                v |= UInt64(digest[o + n])
            }
            s[i] = v
        }
        self.init(state: s)
    }

    convenience init(seed: Data) {
        self.init(digest: SHA256.hash(seed))
    }

    convenience init(string: String) {
        self.init(seed: string.utf8Data)
    }

    convenience init(crc32: UInt32) {
        self.init(seed: crc32.serialized)
    }

    func next() -> UInt64 {
        func rotl(_ x: UInt64, _ k: Int) -> UInt64 {
            (x << k) | (x >> (64 - k))
        }

        let result = rotl(state[1] &* 5, 7) &* 9
        let t = state[1] << 17

        state[2] ^= state[0]
        state[3] ^= state[1]
        state[1] ^= state[2]
        state[0] ^= state[3]

        state[2] ^= t

        state[3] = rotl(state[3], 45)

        return result
    }

    func nextDouble() -> Double {
        Double(next()) / (Double(UInt64.max) + 1)
    }

    func nextInt(in range: Range<Int>) -> Int {
        Int(nextDouble() * Double(range.count)) + range.lowerBound
    }

    func nextInt(in range: ClosedRange<Int>) -> Int {
        Int(nextDouble() * Double(range.count)) + range.lowerBound
    }

    func nextByte() -> UInt8 {
        UInt8(nextInt(in: 0 ... 255))
    }

    func nextData(count: Int) -> Data {
        let bytes = (0 ..< count).map { _ in nextByte() }
        return Data(bytes)
    }
}
