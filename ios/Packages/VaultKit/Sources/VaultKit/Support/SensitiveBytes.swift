import Foundation
import Darwin

/// A fixed-capacity heap buffer for secret material (entropy, mnemonic seed,
/// BIP32 private keys, PINs).
///
/// Design rules enforced by this type (design.md §9.1 property 1):
///
/// * Secrets never cross into `String`, `Array`, `Data` or `Codable`. The only
///   way out is `withUnsafeBytes`, which the crypto layer consumes directly.
///   `materializedCopy()` exists for the few places that genuinely need a flat
///   buffer (C interop, tests) and each call site is reviewed.
/// * `zeroize()` uses `memset_s`, which the optimiser may not elide, and is
///   called on every exit path: explicit call, `deinit`, and app backgrounding.
/// * Comparison is constant-time with respect to contents.
///
/// What this type does NOT do: it cannot prevent the OS from paging memory to
/// disk or from writing a crash/Jetsam dump. `mlock` is unreliable on iOS, so
/// the design accepts that residual risk and instead minimises the window in
/// which a secret exists at all (see `CeremonyState`).
public final class SensitiveBytes {
    private let storage: UnsafeMutableRawPointer
    public let count: Int
    private var zeroized = false

    public init(count: Int) {
        precondition(count > 0)
        self.count = count
        self.storage = UnsafeMutableRawPointer.allocate(byteCount: count, alignment: 8)
        _ = memset_s(storage, count, 0, count)
    }

    /// Copies from a byte sequence, then the caller is responsible for wiping
    /// its own copy (or passing a buffer it does not retain).
    public init(copying bytes: [UInt8]) {
        precondition(!bytes.isEmpty)
        self.count = bytes.count
        self.storage = UnsafeMutableRawPointer.allocate(byteCount: bytes.count, alignment: 8)
        bytes.withUnsafeBytes { src in
            _ = memcpy(storage, src.baseAddress!, bytes.count)
        }
    }

    deinit {
        zeroize()
        storage.deallocate()
    }

    public func zeroize() {
        guard !zeroized else { return }
        _ = memset_s(storage, count, 0, count)
        zeroized = true
    }

    @inline(__always)
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: storage, count: count))
    }

    @inline(__always)
    public func withUnsafeMutableBytes<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: storage, count: count))
    }

    /// Explicit, auditable escape hatch: returns a flat copy of the secret.
    /// Callers MUST wipe the returned array when done (`wipe(&array)`).
    public func materializedCopy() -> [UInt8] {
        [UInt8](UnsafeRawBufferPointer(start: storage, count: count))
    }

    /// Constant-time equality over the full length.
    public func isEqualTo(_ other: SensitiveBytes) -> Bool {
        guard count == other.count else { return false }
        var diff: UInt8 = 0
        withUnsafeBytes { a in
            other.withUnsafeBytes { b in
                for i in 0..<count {
                    diff |= a[i] ^ b[i]
                }
            }
        }
        return diff == 0
    }

    /// Constant-time comparison against a non-secret byte buffer (used when the
    /// user re-enters a value for confirmation).
    public func isEqualTo(_ bytes: [UInt8]) -> Bool {
        guard count == bytes.count else { return false }
        var diff: UInt8 = 0
        withUnsafeBytes { a in
            for i in 0..<count {
                diff |= a[i] ^ bytes[i]
            }
        }
        return diff == 0
    }
}

/// Overwrites a byte array in place. Used to scrub non-`SensitiveBytes`
/// intermediate buffers (HMAC blocks, derived tweaks) on the way out.
@inline(__always)
public func wipe(_ bytes: inout [UInt8]) {
    guard !bytes.isEmpty else { return }
    bytes.withUnsafeMutableBytes { raw in
        _ = memset_s(raw.baseAddress!, raw.count, 0, raw.count)
    }
}

/// Best-effort scrub for `Data` values holding secret material. `Data` may share
/// storage, so this is a mitigation and not a guarantee; prefer `SensitiveBytes`.
@inline(__always)
public func wipe(_ data: inout Data) {
    guard !data.isEmpty else { return }
    data.withUnsafeMutableBytes { raw in
        _ = memset_s(raw.baseAddress!, raw.count, 0, raw.count)
    }
}
