import Foundation

public enum SLIP0010Error: Swift.Error, Equatable {
    case invalidSeedLength(Int)
    /// SLIP-0010 forbids non-hardened derivation for Ed25519.
    case nonHardenedIndex(UInt32)
    case depthExceeded
}

/// SLIP-0010 hierarchical derivation for Ed25519.
///
/// Deliberately a sibling of `ExtendedPrivateKey` rather than a branch inside
/// it: SLIP-0010 differs from BIP32 in more than the curve. The "private key" is
/// the 32-byte seed itself (not a scalar), the master function uses the string
/// `"ed25519 seed"`, the child HMAC has no public-key branch at all, and
/// **non-hardened derivation is not defined** — a normal component is rejected
/// rather than silently hardened, because silently deriving a different key than
/// the caller asked for is the failure mode this codebase consistently refuses.
///
/// Only the private side exists: the app derives once and imports into the
/// YubiKey, and a watch-only Ed25519 `ckd_pub` is not needed for provisioning.
public struct ExtendedPrivateKeyEd25519 {
    public let depth: UInt8
    public let parentFingerprint: [UInt8]
    public let childNumber: UInt32
    public let chainCode: [UInt8]
    /// The 32-byte Ed25519 seed. This is secret material.
    public let key: SensitiveBytes

    init(depth: UInt8, parentFingerprint: [UInt8], childNumber: UInt32, chainCode: [UInt8], key: SensitiveBytes) {
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childNumber = childNumber
        self.chainCode = chainCode
        self.key = key
    }

    /// `I = HMAC-SHA512(Key = "ed25519 seed", Data = S)`; `IL` is the master
    /// seed and `IR` the master chain code.
    ///
    /// SLIP-0010 accepts 128-512 bits of seed, matching BIP32; the BIP39 seed is
    /// 64 bytes.
    public static func master(seed: SensitiveBytes) throws -> ExtendedPrivateKeyEd25519 {
        guard (16...64).contains(seed.count) else { throw SLIP0010Error.invalidSeedLength(seed.count) }

        var seedBytes = seed.materializedCopy()
        defer { wipe(&seedBytes) }

        let i = HMACSHA512.authenticate(key: Array("ed25519 seed".utf8), message: seedBytes)
        let il = Array(i[0..<32])
        let ir = Array(i[32..<64])

        return ExtendedPrivateKeyEd25519(
            depth: 0,
            parentFingerprint: [0, 0, 0, 0],
            childNumber: 0,
            chainCode: ir,
            key: SensitiveBytes(copying: il)
        )
    }

    /// Compressed Ed25519 public key (32 bytes) for this seed.
    public func publicKey() throws -> [UInt8] {
        var raw = key.materializedCopy()
        defer { wipe(&raw) }
        return try Ed25519.publicKey(fromSeed: raw)
    }

    /// The first four bytes of HASH160(serP(K)) where `serP(K)` is the
    /// serialised public key. SLIP-0010 serialises an Ed25519 public key as
    /// `0x00 || key`, and its published fingerprints are computed over that
    /// 33-byte form, so the leading zero is part of the convention (confirmed
    /// against both SLIP-0010 Ed25519 vectors).
    ///
    /// This is the same rule as BIP32's, applied to the algorithm's own public
    /// key serialisation; the secp256k1 side hashes the 33-byte SEC1 point.
    /// The card's EdDSA fingerprint object (0xC9) may expect something else;
    /// see docs/m0-hardware-verification.md.
    public func fingerprint() throws -> [UInt8] {
        Array(RIPEMD160.hash160([0x00] + (try publicKey())).prefix(4))
    }

    /// Derives a single child. `index` must already include the hardened bit.
    public func child(_ index: UInt32) throws -> ExtendedPrivateKeyEd25519 {
        guard index >= 0x8000_0000 else { throw SLIP0010Error.nonHardenedIndex(index) }
        guard depth < 255 else { throw SLIP0010Error.depthExceeded }

        var data = [UInt8]()
        data.reserveCapacity(37)
        data.append(0x00)
        var raw = key.materializedCopy()
        defer { wipe(&raw) }
        data.append(contentsOf: raw)
        data.append(UInt8((index >> 24) & 0xff))
        data.append(UInt8((index >> 16) & 0xff))
        data.append(UInt8((index >> 8) & 0xff))
        data.append(UInt8(index & 0xff))

        let i = HMACSHA512.authenticate(key: chainCode, message: data)
        let il = Array(i[0..<32])
        let ir = Array(i[32..<64])

        return ExtendedPrivateKeyEd25519(
            depth: depth + 1,
            parentFingerprint: try fingerprint(),
            childNumber: index,
            chainCode: ir,
            key: SensitiveBytes(copying: il)
        )
    }

    /// Derives along a path. Every component must be hardened.
    public func derived(_ path: DerivationPath) throws -> ExtendedPrivateKeyEd25519 {
        var current = self
        for component in path.components {
            guard component.isHardened else {
                throw SLIP0010Error.nonHardenedIndex(component.index)
            }
            current = try current.child(component.index)
        }
        return current
    }
}
