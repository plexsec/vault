import Csecp256k1
import Foundation

public enum Secp256k1Error: Swift.Error, Equatable {
    case contextUnavailable
    case invalidPrivateKey
    case invalidPublicKey
    case invalidTweak
    case resultOutOfRange
    case invalidSignature
    case recoveryFailed
}

/// Holds the libsecp256k1 context.
///
/// The context is never randomised. Since v0.2 the vendored library also compiles
/// libsecp256k1's recovery module, because the signing flow has to recover a public
/// key from a signature to decide which `v` to return and to check the card's
/// output. Point arithmetic, verification and recovery are the whole surface this
/// wrapper exposes: **no entry point that takes a secret key is reachable from
/// Swift**, so the app cannot sign with an in-memory key even by mistake, and
/// `tools/audit-release.sh` asserts that no signing symbol is referenced. The one
/// secret-key call in this file is BIP32's `tweakAdd`, which derives a child key
/// during provisioning and never produces a signature.
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

/// Minimal secp256k1 surface: BIP32 derivation, public-key serialisation,
/// signature verification and public-key recovery (`ecrecover`, which is what
/// determines a signature's `v`). Deliberately excludes signing, ECDH and
/// Schnorr — see the note on `Secp256k1Context`.
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

    /// `publicKey + tweak·G`. This is the public half of BIP32 child
    /// derivation (`ckd_pub`), used to check that an extended public key read
    /// back off a card really does reach the key inside it.
    ///
    /// Throws when the tweak is out of range or the sum is the point at
    /// infinity — the BIP32 "invalid child" condition, which the private side
    /// reports as `Secp256k1Error.resultOutOfRange`.
    public static func tweakAdd(publicKey compressed: [UInt8], tweak: [UInt8]) throws -> [UInt8] {
        guard compressed.count == compressedPublicKeyLength else { throw Secp256k1Error.invalidPublicKey }
        guard tweak.count == 32 else { throw Secp256k1Error.invalidTweak }
        let context = Secp256k1Context.shared.raw

        var publicKey = secp256k1_pubkey()
        let parsed = compressed.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_parse(context, &publicKey, buffer.baseAddress!, compressed.count)
        }
        guard parsed == 1 else { throw Secp256k1Error.invalidPublicKey }

        let tweaked = tweak.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_tweak_add(context, &publicKey, buffer.baseAddress!)
        }
        guard tweaked == 1 else { throw Secp256k1Error.resultOutOfRange }

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

    public static func isValidPrivateKey(_ privateKey: [UInt8]) -> Bool {
        guard privateKey.count == 32 else { return false }
        let context = Secp256k1Context.shared.raw
        return privateKey.withUnsafeBufferPointer { buffer in
            secp256k1_ec_seckey_verify(context, buffer.baseAddress!) == 1
        }
    }

    // MARK: - Verification and recovery (v0.2 signing flow)

    /// Recovers the public key that produced `signature` over `digest`.
    ///
    /// `recoveryID` is the two-bit recovery value (0...3) as secp256k1 defines it,
    /// not Ethereum's `v`. Returns the 65-byte uncompressed point (`04 ‖ X ‖ Y`),
    /// which is the form Ethereum hashes for an address. Throws when the signature
    /// is inconsistent with the recovery id, which is how a wrong `v` is detected:
    /// with four ids at most one recovers the key we expect.
    public static func recoverPublicKey(
        signature: ECDSASignature,
        digest: [UInt8],
        recoveryID: UInt8
    ) throws -> [UInt8] {
        guard digest.count == 32 else { throw Secp256k1Error.invalidSignature }
        guard recoveryID < 4 else { throw Secp256k1Error.invalidSignature }
        let context = Secp256k1Context.shared.raw

        var recoverable = secp256k1_ecdsa_recoverable_signature()
        let compact = signature.r + signature.s
        let parsed = compact.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &recoverable,
                buffer.baseAddress!,
                Int32(recoveryID)
            )
        }
        guard parsed == 1 else { throw Secp256k1Error.invalidSignature }

        var publicKey = secp256k1_pubkey()
        let recovered = digest.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ecdsa_recover(context, &publicKey, &recoverable, buffer.baseAddress!)
        }
        guard recovered == 1 else { throw Secp256k1Error.recoveryFailed }

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

    /// Whether `signature` verifies against `publicKey` (compressed or
    /// uncompressed) over `digest`.
    ///
    /// This is the independent check on what the card returned: the app recovers
    /// the key from the signature anyway, and verification here means a card that
    /// returns a valid-looking signature for the wrong key cannot produce a
    /// signature the app will hand to a wallet.
    public static func verify(
        signature: ECDSASignature,
        digest: [UInt8],
        publicKey: [UInt8]
    ) throws -> Bool {
        guard digest.count == 32 else { throw Secp256k1Error.invalidSignature }
        let context = Secp256k1Context.shared.raw

        var parsedKey = secp256k1_pubkey()
        let parsed = publicKey.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ec_pubkey_parse(context, &parsedKey, buffer.baseAddress!, publicKey.count)
        }
        guard parsed == 1 else { throw Secp256k1Error.invalidPublicKey }

        let compact = signature.r + signature.s
        var parsedSignature = secp256k1_ecdsa_signature()
        let signatureParsed = compact.withUnsafeBufferPointer { buffer -> Int32 in
            secp256k1_ecdsa_signature_parse_compact(context, &parsedSignature, buffer.baseAddress!)
        }
        guard signatureParsed == 1 else { throw Secp256k1Error.invalidSignature }

        return digest.withUnsafeBufferPointer { buffer -> Bool in
            secp256k1_ecdsa_verify(context, &parsedSignature, buffer.baseAddress!, &parsedKey) == 1
        }
    }
}
