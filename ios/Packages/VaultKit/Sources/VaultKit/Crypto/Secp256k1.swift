import Csecp256k1
import Foundation

public enum Secp256k1Error: Swift.Error, Equatable {
    case contextUnavailable
    case invalidPrivateKey
    case invalidPublicKey
    case invalidTweak
    case resultOutOfRange
}

/// Holds the libsecp256k1 context.
///
/// The context is never randomised and no signing entry point is exposed by this
/// module: v1 is a provisioning-only app, so no ECDSA signature is ever produced
/// (design.md §3.2 — the signing flow is v2). That keeps the attack surface of
/// this wrapper to point arithmetic only.
final class Secp256k1Context {
    static let shared = Secp256k1Context()

    let raw: OpaquePointer

    private init() {
        guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_NONE)) else {
            preconditionFailure("libsecp256k1 context allocation failed")
        }
        raw = context
    }

    deinit {
        secp256k1_context_destroy(raw)
    }
}

/// Minimal secp256k1 surface required for BIP32 derivation and public-key
/// serialisation. Deliberately excludes signing, recovery, ECDH and Schnorr.
public enum Secp256k1 {
    public static let compressedPublicKeyLength = 33
    public static let uncompressedPublicKeyLength = 65

    /// Compressed (33-byte, SEC1) public key for a 32-byte private key.
    public static func publicKey(fromPrivateKey privateKey: [UInt8]) throws -> [UInt8] {
        guard privateKey.count == 32 else { throw Secp256k1Error.invalidPrivateKey }
        let context = Secp256k1Context.shared.raw

        var publicKey = secp256k1_pubkey()
        let created = privateKey.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_create(context, &publicKey, buffer.baseAddress!)
        }
        guard created == 1 else { throw Secp256k1Error.invalidPrivateKey }

        var output = [UInt8](repeating: 0, count: compressedPublicKeyLength)
        var outputLength = output.count
        let serialized = output.withUnsafeMutableBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_serialize(
                context,
                buffer.baseAddress!,
                &outputLength,
                &publicKey,
                UInt32(SECP256K1_EC_COMPRESSED)
            )
        }
        guard serialized == 1, outputLength == compressedPublicKeyLength else {
            throw Secp256k1Error.invalidPublicKey
        }
        return output
    }

    /// Expands a SEC1 compressed key to the 65-byte uncompressed form that
    /// Ethereum hashes for address derivation.
    public static func uncompressedPublicKey(fromCompressed compressed: [UInt8]) throws -> [UInt8] {
        guard compressed.count == compressedPublicKeyLength else { throw Secp256k1Error.invalidPublicKey }
        let context = Secp256k1Context.shared.raw

        var publicKey = secp256k1_pubkey()
        let parsed = compressed.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_parse(context, &publicKey, buffer.baseAddress!, compressed.count)
        }
        guard parsed == 1 else { throw Secp256k1Error.invalidPublicKey }

        var output = [UInt8](repeating: 0, count: uncompressedPublicKeyLength)
        var outputLength = output.count
        let serialized = output.withUnsafeMutableBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_serialize(
                context,
                buffer.baseAddress!,
                &outputLength,
                &publicKey,
                UInt32(SECP256K1_EC_UNCOMPRESSED)
            )
        }
        guard serialized == 1, outputLength == uncompressedPublicKeyLength else {
            throw Secp256k1Error.invalidPublicKey
        }
        return output
    }

    /// Compresses a 65-byte uncompressed SEC1 key (04 || X || Y) to the 33-byte
    /// compressed form. The OpenPGP card returns uncompressed points on read-back
    /// while the app derives compressed ones, so this is the normalisation step.
    public static func compressedPublicKey(fromUncompressed uncompressed: [UInt8]) throws -> [UInt8] {
        guard uncompressed.count == uncompressedPublicKeyLength, uncompressed.first == 0x04 else {
            throw Secp256k1Error.invalidPublicKey
        }
        let context = Secp256k1Context.shared.raw

        var publicKey = secp256k1_pubkey()
        let parsed = uncompressed.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_parse(context, &publicKey, buffer.baseAddress!, uncompressed.count)
        }
        guard parsed == 1 else { throw Secp256k1Error.invalidPublicKey }

        var output = [UInt8](repeating: 0, count: compressedPublicKeyLength)
        var outputLength = output.count
        let serialized = output.withUnsafeMutableBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_serialize(
                context,
                buffer.baseAddress!,
                &outputLength,
                &publicKey,
                UInt32(SECP256K1_EC_COMPRESSED)
            )
        }
        guard serialized == 1, outputLength == compressedPublicKeyLength else {
            throw Secp256k1Error.invalidPublicKey
        }
        return output
    }

    /// `privateKey + tweak (mod n)`. Throws when the tweak is out of range or the
    /// sum is zero, which is exactly the BIP32 "invalid child" condition.
    ///
    /// The result is a fresh `SensitiveBytes`; the caller owns wiping it.
    public static func tweakAdd(privateKey: SensitiveBytes, tweak: [UInt8]) throws -> SensitiveBytes {
        guard tweak.count == 32 else { throw Secp256k1Error.invalidTweak }
        let context = Secp256k1Context.shared.raw

        let result = SensitiveBytes(count: 32)
        privateKey.withUnsafeBytes { source in
            result.withUnsafeMutableBytes { destination in
                _ = memcpy(destination.baseAddress!, source.baseAddress!, 32)
            }
        }

        let ok = result.withUnsafeMutableBytes { buffer -> Int32 in
            tweak.withUnsafeBufferPointer { tweakBuffer -> Int32 in
                secp256k1_ec_seckey_tweak_add(
                    context,
                    buffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    tweakBuffer.baseAddress!
                )
            }
        }
        guard ok == 1 else {
            result.zeroize()
            throw Secp256k1Error.resultOutOfRange
        }
        return result
    }

    public static func isValidPrivateKey(_ privateKey: [UInt8]) -> Bool {
        guard privateKey.count == 32 else { return false }
        let context = Secp256k1Context.shared.raw
        return privateKey.withUnsafeBufferPointer { buffer in
            secp256k1_ec_seckey_verify(context, buffer.baseAddress!) == 1
        }
    }
}
