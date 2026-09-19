import Ced25519
import Foundation

public enum Ed25519Error: Swift.Error, Equatable {
    case invalidSeedLength(Int)
    case invalidPublicKeyLength(Int)
    case invalidSignatureLength(Int)
    case keygenFailed
    case signingFailed
}

/// Ed25519 (RFC 8032) over the vendored TweetNaCl implementation.
///
/// Scope note, mirroring `Secp256k1`: the Ed25519 private key lives on the
/// YubiKey's authentication slot and is never held by this app after the
/// import step, so no ceremony path signs with it. `publicKey(fromSeed:)` is
/// what the ceremony needs (read-back comparison and the independent
/// cross-check); `sign`/`verify` exist so the vendored implementation can be
/// pinned against the published RFC 8032 vectors, which is the only reason the
/// message-signing code path is exercised at all.
public enum Ed25519 {
    public static let seedLength = 32
    public static let publicKeyLength = 32
    public static let signatureLength = 64

    /// Ed25519 public key for a 32-byte seed (the SLIP-0010 / BIP39 derivation
    /// output). The seed is the secret; the returned public key is not.
    public static func publicKey(fromSeed seed: [UInt8]) throws -> [UInt8] {
        guard seed.count == seedLength else { throw Ed25519Error.invalidSeedLength(seed.count) }

        var publicKey = [UInt8](repeating: 0, count: publicKeyLength)
        // sk is seed || pk: TweetNaCl's secret-key layout. Wiped on every exit.
        var secretKey = [UInt8](repeating: 0, count: 64)
        defer { wipe(&secretKey) }

        let status = seed.withUnsafeBufferPointer { seedBuffer -> Int32 in
            publicKey.withUnsafeMutableBufferPointer { publicBuffer -> Int32 in
                secretKey.withUnsafeMutableBufferPointer { secretBuffer -> Int32 in
                    vault_ed25519_seed_keypair(
                        publicBuffer.baseAddress!,
                        secretBuffer.baseAddress!,
                        seedBuffer.baseAddress!
                    )
                }
            }
        }
        guard status == 0 else { throw Ed25519Error.keygenFailed }
        return publicKey
    }

    /// Detached Ed25519 signature over `message`.
    ///
    /// Note that Ed25519 signs the message itself and hashes it internally; it
    /// is NOT hash-then-sign. Callers must not pass a precomputed digest and
    /// expect an ECDSA-shaped flow.
    public static func sign(message: [UInt8], seed: [UInt8]) throws -> [UInt8] {
        guard seed.count == seedLength else { throw Ed25519Error.invalidSeedLength(seed.count) }

        let publicKey = try publicKey(fromSeed: seed)
        var secretKey = seed
        secretKey.append(contentsOf: publicKey)
        defer { wipe(&secretKey) }

        var signedMessage = [UInt8](repeating: 0, count: message.count + signatureLength)
        var signedLength: UInt64 = 0

        let status = signedMessage.withUnsafeMutableBufferPointer { signedBuffer -> Int32 in
            secretKey.withUnsafeBufferPointer { secretBuffer -> Int32 in
                message.withUnsafeBufferPointer { messageBuffer -> Int32 in
                    vault_ed25519_sign(
                        signedBuffer.baseAddress!,
                        &signedLength,
                        message.count == 0 ? nil : messageBuffer.baseAddress!,
                        UInt64(message.count),
                        secretBuffer.baseAddress!
                    )
                }
            }
        }
        guard status == 0, signedLength == UInt64(message.count + signatureLength) else {
            throw Ed25519Error.signingFailed
        }
        return Array(signedMessage.prefix(signatureLength))
    }

    /// Verifies a detached signature. Returns false rather than throwing: a bad
    /// signature is an expected result, not an error condition.
    public static func verify(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard signature.count == signatureLength else { return false }
        guard publicKey.count == publicKeyLength else { return false }

        var signedMessage = signature
        signedMessage.append(contentsOf: message)
        var opened = [UInt8](repeating: 0, count: signedMessage.count)
        var openedLength: UInt64 = 0

        let status = opened.withUnsafeMutableBufferPointer { openedBuffer -> Int32 in
            signedMessage.withUnsafeBufferPointer { signedBuffer -> Int32 in
                publicKey.withUnsafeBufferPointer { publicBuffer -> Int32 in
                    vault_ed25519_sign_open(
                        openedBuffer.baseAddress!,
                        &openedLength,
                        signedBuffer.baseAddress!,
                        UInt64(signedMessage.count),
                        publicBuffer.baseAddress!
                    )
                }
            }
        }
        return status == 0 && openedLength == UInt64(message.count)
    }
}
