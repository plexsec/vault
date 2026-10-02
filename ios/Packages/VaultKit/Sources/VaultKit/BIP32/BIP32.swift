import Foundation

public enum BIP32Error: Swift.Error, Equatable {
    case invalidSeedLength(Int)
    case invalidMasterKey
    /// BIP32 specifies "proceed with the next value for i" when a child key is
    /// invalid. This implementation surfaces the condition instead of silently
    /// shifting the index, because silently deriving a different address than
    /// the user asked for is worse than failing loudly. Probability ~2^-127.
    case invalidChildKey(index: UInt32)
    case depthExceeded
    case invalidSerialization
}

/// Network version bytes for BIP32 serialisation.
public struct BIP32Version: Equatable, Sendable {
    public let privatePrefix: [UInt8]
    public let publicPrefix: [UInt8]
    public let name: String

    public static let mainnet = BIP32Version(
        privatePrefix: [0x04, 0x88, 0xAD, 0xE4],
        publicPrefix: [0x04, 0x88, 0xB2, 0x1E],
        name: "mainnet"
    )

    public static let testnet = BIP32Version(
        privatePrefix: [0x04, 0x35, 0x83, 0x94],
        publicPrefix: [0x04, 0x35, 0x87, 0xCF],
        name: "testnet"
    )

    public static let all: [BIP32Version] = [.mainnet, .testnet]

    /// Version whose private prefix matches, if any.
    public static func matchingPrivatePrefix(_ bytes: [UInt8]) -> BIP32Version? {
        all.first { $0.privatePrefix == bytes }
    }

    /// Version whose public prefix matches, if any.
    public static func matchingPublicPrefix(_ bytes: [UInt8]) -> BIP32Version? {
        all.first { $0.publicPrefix == bytes }
    }
}

/// Read-only parsing and validation of a serialised BIP32 extended key.
///
/// The app uses this to verify a public key a user transcribes or scans.
/// Validation covers the BIP32 "invalid extended key" rules that test vector 5
/// exercises: unknown version, version/key-data mismatch, malformed key prefix,
/// out-of-range private scalar, unparseable public point, and depth 0 with a
/// non-zero parent fingerprint or child number.
public struct ExtendedKeyPayload: Equatable {
    public let versionPrefix: [UInt8]
    public let version: BIP32Version?
    public let isPrivate: Bool
    public let depth: UInt8
    public let parentFingerprint: [UInt8]
    public let childNumber: UInt32
    public let chainCode: [UInt8]
    /// 33 bytes: compressed public key, or `0x00 || ser256(k)` when private.
    public let keyData: [UInt8]

    public enum ValidationError: Swift.Error, Equatable {
        case wrongLength(Int)
        case invalidChecksum
        case unknownVersion
        case versionKeyDataMismatch
        case invalidKeyPrefix(UInt8)
        case invalidPrivateScalar
        case invalidPublicPoint
        case zeroDepthWithNonZeroParent
        case zeroDepthWithNonZeroIndex
    }

    public static func decode(_ base58: String) throws -> ExtendedKeyPayload {
        let payload: [UInt8]
        do {
            payload = try Base58.decodeCheck(base58.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            throw ValidationError.invalidChecksum
        }
        return try parse(payload)
    }

    public static func parse(_ payload: [UInt8]) throws -> ExtendedKeyPayload {
        guard payload.count == 78 else { throw ValidationError.wrongLength(payload.count) }

        let versionPrefix = Array(payload[0..<4])
        let depth = payload[4]
        let parentFingerprint = Array(payload[5..<9])
        let childNumber = UInt32(payload[9]) << 24 | UInt32(payload[10]) << 16
            | UInt32(payload[11]) << 8 | UInt32(payload[12])
        let chainCode = Array(payload[13..<45])
        let keyData = Array(payload[45..<78])

        let privateVersion = BIP32Version.matchingPrivatePrefix(versionPrefix)
        let publicVersion = BIP32Version.matchingPublicPrefix(versionPrefix)
        guard privateVersion != nil || publicVersion != nil else {
            throw ValidationError.unknownVersion
        }
        let isPrivate = privateVersion != nil

        // Version and key-data must agree; a mismatch is the first vector-5 case.
        if isPrivate {
            guard keyData[0] == 0x00 else { throw ValidationError.versionKeyDataMismatch }
            guard Secp256k1.isValidPrivateKey(Array(keyData[1...])) else {
                throw ValidationError.invalidPrivateScalar
            }
        } else {
            guard keyData[0] == 0x02 || keyData[0] == 0x03 else {
                throw ValidationError.invalidKeyPrefix(keyData[0])
            }
            guard (try? Secp256k1.uncompressedPublicKey(fromCompressed: keyData)) != nil else {
                throw ValidationError.invalidPublicPoint
            }
        }

        // A depth-0 key is a master key: it can have no parent and no index.
        if depth == 0 {
            guard parentFingerprint == [0, 0, 0, 0] else {
                throw ValidationError.zeroDepthWithNonZeroParent
            }
            guard childNumber == 0 else { throw ValidationError.zeroDepthWithNonZeroIndex }
        }

        return ExtendedKeyPayload(
            versionPrefix: versionPrefix,
            version: isPrivate ? privateVersion : publicVersion,
            isPrivate: isPrivate,
            depth: depth,
            parentFingerprint: parentFingerprint,
            childNumber: childNumber,
            chainCode: chainCode,
            keyData: keyData
        )
    }

    /// Compressed public key, available for both private and public payloads.
    public func publicKey() throws -> [UInt8] {
        if isPrivate {
            return try Secp256k1.publicKey(fromPrivateKey: Array(keyData[1...]))
        }
        return keyData
    }
}

/// BIP32 extended key operations, private side.
///
/// The private side is what the provisioning ceremony needs: it derives a key
/// once, imports it into the YubiKey, and compares the card's public key against
/// the key it just derived. `ExtendedPublicKey` below adds the public-only
/// (`ckd_pub`) half for the pairing manifest, which is read back off a card that
/// no longer has the mnemonic available.
public struct ExtendedPrivateKey {
    public let depth: UInt8
    public let parentFingerprint: [UInt8]
    public let childNumber: UInt32
    public let chainCode: [UInt8]
    public let key: SensitiveBytes

    init(depth: UInt8, parentFingerprint: [UInt8], childNumber: UInt32, chainCode: [UInt8], key: SensitiveBytes) {
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childNumber = childNumber
        self.chainCode = chainCode
        self.key = key
    }

    /// BIP32 master key generation: I = HMAC-SHA512("Bitcoin seed", seed).
    ///
    /// BIP32 accepts seeds of 128-512 bits (16-64 bytes); the published test
    /// vector 1 uses a 16-byte seed, so requiring exactly 64 bytes here would
    /// reject a spec-conformant input.
    public static func master(seed: SensitiveBytes) throws -> ExtendedPrivateKey {
        guard (16...64).contains(seed.count) else { throw BIP32Error.invalidSeedLength(seed.count) }

        var seedBytes = seed.materializedCopy()
        defer { wipe(&seedBytes) }

        let i = HMACSHA512.authenticate(key: Array("Bitcoin seed".utf8), message: seedBytes)
        let il = Array(i[0..<32])
        let ir = Array(i[32..<64])

        guard Secp256k1.isValidPrivateKey(il) else {
            var scratch = il
            wipe(&scratch)
            throw BIP32Error.invalidMasterKey
        }

        return ExtendedPrivateKey(
            depth: 0,
            parentFingerprint: [0, 0, 0, 0],
            childNumber: 0,
            chainCode: ir,
            key: SensitiveBytes(copying: il)
        )
    }

    /// Compressed SEC1 public key for this key.
    public func publicKey() throws -> [UInt8] {
        var raw = key.materializedCopy()
        defer { wipe(&raw) }
        return try Secp256k1.publicKey(fromPrivateKey: raw)
    }

    /// BIP32 key fingerprint: first four bytes of HASH160(compressed public key).
    public func fingerprint() throws -> [UInt8] {
        Array(RIPEMD160.hash160(try publicKey()).prefix(4))
    }

    /// Derives a single child. `index` must already include the hardened bit.
    public func child(_ index: UInt32) throws -> ExtendedPrivateKey {
        guard depth < 255 else { throw BIP32Error.depthExceeded }

        let hardened = index >= 0x8000_0000
        var data = [UInt8]()
        data.reserveCapacity(37)

        if hardened {
            data.append(0x00)
            var raw = key.materializedCopy()
            defer { wipe(&raw) }
            data.append(contentsOf: raw)
        } else {
            data.append(contentsOf: try publicKey())
        }
        data.append(UInt8((index >> 24) & 0xff))
        data.append(UInt8((index >> 16) & 0xff))
        data.append(UInt8((index >> 8) & 0xff))
        data.append(UInt8(index & 0xff))

        let i = HMACSHA512.authenticate(key: chainCode, message: data)
        let il = Array(i[0..<32])
        let ir = Array(i[32..<64])

        let childKey: SensitiveBytes
        do {
            childKey = try Secp256k1.tweakAdd(privateKey: key, tweak: il)
        } catch {
            throw BIP32Error.invalidChildKey(index: index)
        }

        return ExtendedPrivateKey(
            depth: depth + 1,
            parentFingerprint: try fingerprint(),
            childNumber: index,
            chainCode: ir,
            key: childKey
        )
    }

    public func derived(_ path: DerivationPath) throws -> ExtendedPrivateKey {
        var current = self
        for index in path.indices {
            current = try current.child(index)
        }
        return current
    }

    /// Serialises to `xprv`/`tprv` (Base58Check). Byte-for-byte compatible with
    /// BIP32 so the published test vectors apply directly.
    public func serialized(version: BIP32Version) throws -> String {
        var payload = version.privatePrefix
        payload.append(depth)
        payload.append(contentsOf: parentFingerprint)
        payload.append(UInt8((childNumber >> 24) & 0xff))
        payload.append(UInt8((childNumber >> 16) & 0xff))
        payload.append(UInt8((childNumber >> 8) & 0xff))
        payload.append(UInt8(childNumber & 0xff))
        payload.append(contentsOf: chainCode)
        payload.append(0x00)
        var raw = key.materializedCopy()
        defer { wipe(&raw) }
        payload.append(contentsOf: raw)
        return Base58.encodeCheck(payload)
    }

    /// Public half, serialised as `xpub`/`tpub`.
    public func serializedPublic(version: BIP32Version) throws -> String {
        var payload = version.publicPrefix
        payload.append(depth)
        payload.append(contentsOf: parentFingerprint)
        payload.append(UInt8((childNumber >> 24) & 0xff))
        payload.append(UInt8((childNumber >> 16) & 0xff))
        payload.append(UInt8((childNumber >> 8) & 0xff))
        payload.append(UInt8(childNumber & 0xff))
        payload.append(contentsOf: chainCode)
        payload.append(contentsOf: try publicKey())
        return Base58.encodeCheck(payload)
    }
}

/// BIP32 extended key, public side — `ckd_pub` and nothing else.
///
/// This type exists for one job: a pairing manifest read off a YubiKey holds an
/// extended public key, and the only way to show that it describes the key
/// *inside that card* — without the mnemonic, which the card does not have and
/// the phone does not store — is to derive the pinned child from it and compare
/// the result against the public key the card reports for its own slot.
///
/// Hardened children are refused rather than approximated: they cannot be
/// derived from a public key at all, and returning a plausible-looking wrong key
/// would defeat the comparison this type exists to make.
public struct ExtendedPublicKey: Equatable {
    public let depth: UInt8
    public let parentFingerprint: [UInt8]
    public let childNumber: UInt32
    public let chainCode: [UInt8]
    /// 33-byte compressed SEC1 public key.
    public let publicKey: [UInt8]

    public enum PublicDerivationError: Swift.Error, Equatable {
        /// A hardened component in a public-only path (`m/44'` and friends).
        case hardenedComponent(UInt32)
        case invalidPoint
        case invalidChildKey(index: UInt32)
        case depthExceeded
    }

    public init(
        publicKey: [UInt8],
        chainCode: [UInt8],
        depth: UInt8 = 0,
        parentFingerprint: [UInt8] = [0, 0, 0, 0],
        childNumber: UInt32 = 0
    ) throws {
        guard publicKey.count == Secp256k1.compressedPublicKeyLength else {
            throw PublicDerivationError.invalidPoint
        }
        // Parsing rejects a point that is not on the curve; without this an
        // off-curve "public key" would be carried around until it either failed
        // to derive or, worse, compared equal to something it is not. The
        // library's own error is mapped so callers only ever see this type.
        do {
            _ = try Secp256k1.uncompressedPublicKey(fromCompressed: publicKey)
        } catch {
            throw PublicDerivationError.invalidPoint
        }
        guard chainCode.count == 32 else { throw BIP32Error.invalidSerialization }
        self.publicKey = publicKey
        self.chainCode = chainCode
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childNumber = childNumber
    }

    /// First four bytes of HASH160 of this key — the same value BIP32 writes as
    /// the *parent* fingerprint of a child.
    public func fingerprint() -> [UInt8] {
        Array(RIPEMD160.hash160(publicKey).prefix(4))
    }

    /// Derives a single **non-hardened** child. `index` must not carry the
    /// hardened bit.
    public func child(_ index: UInt32) throws -> ExtendedPublicKey {
        guard depth < 255 else { throw PublicDerivationError.depthExceeded }
        guard index < 0x8000_0000 else { throw PublicDerivationError.hardenedComponent(index) }

        var data = publicKey
        data.append(UInt8((index >> 24) & 0xff))
        data.append(UInt8((index >> 16) & 0xff))
        data.append(UInt8((index >> 8) & 0xff))
        data.append(UInt8(index & 0xff))

        let i = HMACSHA512.authenticate(key: chainCode, message: data)
        let il = Array(i[0..<32])
        let ir = Array(i[32..<64])

        let childPoint: [UInt8]
        do {
            childPoint = try Secp256k1.tweakAdd(publicKey: publicKey, tweak: il)
        } catch {
            throw PublicDerivationError.invalidChildKey(index: index)
        }

        return try ExtendedPublicKey(
            publicKey: childPoint,
            chainCode: ir,
            depth: depth + 1,
            parentFingerprint: fingerprint(),
            childNumber: index
        )
    }

    public func derived(_ path: DerivationPath) throws -> ExtendedPublicKey {
        var current = self
        for index in path.indices {
            current = try current.child(index)
        }
        return current
    }
}
