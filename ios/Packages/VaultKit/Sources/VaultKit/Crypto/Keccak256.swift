import Foundation

/// Keccak-256 as used by Ethereum (original Keccak padding `0x01`, NOT the NIST
/// SHA3-256 padding `0x06`). This distinction is why Bitcoin Core's `sha3.cpp`
/// could not be vendored for EVM address derivation.
///
/// Rate 1088 bits (136 bytes), capacity 512 bits, 32-byte output.
public enum Keccak256 {
    private static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    /// Rotation offsets, indexed by lane `x + 5y`.
    private static let rotations: [UInt32] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ]

    private static let rate = 136

    public static func hash(_ message: [UInt8]) -> [UInt8] {
        var state = [UInt64](repeating: 0, count: 25)

        // pad10*1 with the original Keccak domain byte 0x01.
        //
        // Careful boundary case: when the message ends exactly at the last byte
        // of a rate block, the leading `1` bit and the trailing `1` bit land in
        // the SAME byte, which makes the whole padding a single 0x81 byte inside
        // that block. Naively "append 0x01, then pad to rate-1, then append
        // 0x80" starts a spurious extra block here and produces a wrong digest
        // for messages whose length is `rate - 1 (mod rate)`. The multiblock
        // differential fixture covers lengths 135 and 271 for exactly this.
        let padLen = rate - (message.count % rate)
        var padded = message
        if padLen == 1 {
            padded.append(0x81)
        } else {
            padded.append(0x01)
            padded.append(contentsOf: [UInt8](repeating: 0, count: padLen - 2))
            padded.append(0x80)
        }

        var offset = 0
        while offset < padded.count {
            for lane in 0..<(rate / 8) {
                let base = offset + lane * 8
                var value: UInt64 = 0
                for i in 0..<8 {
                    value |= UInt64(padded[base + i]) << UInt64(8 * i)
                }
                state[lane] ^= value
            }
            permute(&state)
            offset += rate
        }

        var out = [UInt8]()
        out.reserveCapacity(32)
        for lane in 0..<4 {
            for i in 0..<8 {
                out.append(UInt8((state[lane] >> UInt64(8 * i)) & 0xff))
            }
        }
        return out
    }

    public static func hash(_ data: Data) -> [UInt8] { hash([UInt8](data)) }
    public static func hash(_ string: String) -> [UInt8] { hash([UInt8](string.utf8)) }

    private static func permute(_ state: inout [UInt64]) {
        var c = [UInt64](repeating: 0, count: 5)
        var d = [UInt64](repeating: 0, count: 5)
        var b = [UInt64](repeating: 0, count: 25)

        for round in 0..<24 {
            // Theta
            for x in 0..<5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            }
            for x in 0..<5 {
                d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
            }
            for x in 0..<5 {
                for y in 0..<5 {
                    state[x + 5 * y] ^= d[x]
                }
            }

            // Rho and Pi
            for x in 0..<5 {
                for y in 0..<5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], rotations[x + 5 * y])
                }
            }

            // Chi
            for x in 0..<5 {
                for y in 0..<5 {
                    state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
                }
            }

            // Iota
            state[0] ^= roundConstants[round]
        }
    }

    @inline(__always)
    private static func rotl(_ x: UInt64, _ n: UInt32) -> UInt64 {
        n == 0 ? x : (x << n) | (x >> (64 - n))
    }
}
