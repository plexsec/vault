import Foundation

/// What the app does with the card's signature: check it recovers the key we
/// provisioned, and work out the `v` the requesting wallet expects.
///
/// This is the part of the flow that turns "the YubiKey produced some bytes" into
/// "these bytes are a signature by the key this app paired, for the transaction
/// the operator just read". Both halves matter: a card that signs with the wrong
/// slot, or a wallet that asked for a path the card cannot sign for, produce
/// signatures that are *valid* and useless — and the recovery check is the only
/// thing that notices.
public enum EVMSignature {
    public enum Error: Swift.Error, Equatable {
        /// No recovery value 0 or 1 makes the signature recover the address the
        /// app provisioned. Either the card signed with a different key, or the
        /// digest is not the one that was approved.
        case signatureDoesNotMatchKey
        case notASignableRequest
    }

    /// The recovery id (0 or 1) for which `signature` recovers `expectedAddress`.
    ///
    /// Ethereum's `v` is this value mapped through the transaction's convention,
    /// so getting it right is not cosmetic: it is the only thing that tells a
    /// wallet which public key to recover, and a wrong `v` makes the transaction
    /// invalid while looking perfectly well-formed.
    public static func recoveryID(
        signature: ECDSASignature,
        digest: [UInt8],
        expectedAddress: [UInt8]
    ) throws -> UInt8 {
        for candidate: UInt8 in [0, 1] {
            guard let uncompressed = try? Secp256k1.recoverPublicKey(
                signature: signature,
                digest: digest,
                recoveryID: candidate
            ) else { continue }
            if let address = try? EVMAddress.bytes(fromPublicKey: uncompressed), address == expectedAddress {
                return candidate
            }
        }
        throw Error.signatureDoesNotMatchKey
    }

    /// Normalises `signature` to low-s, finds its recovery id and returns the
    /// recovery value (`v`) the transaction requires.
    ///
    /// Low-s is normalised *before* the recovery id is searched, which removes the
    /// parity bookkeeping entirely: `(r, n-s)` recovers the same key under the
    /// other recovery id, so a single search over both ids covers both forms.
    /// EIP-2 requires low-s, and both Ethereum and Bitcoin reject a transaction
    /// whose `s` is above `n/2`.
    public static func transactionSignature(
        cardSignature: ECDSASignature,
        transaction: EVMTransaction,
        expectedAddress: [UInt8]
    ) throws -> (signature: ECDSASignature, recoveryValue: EVMQuantity) {
        let (signature, _) = cardSignature.normalisedLowS()
        let digest = transaction.signingDigest
        let recoveryID = try recoveryID(
            signature: signature,
            digest: digest,
            expectedAddress: expectedAddress
        )
        let recoveryValue = try value(for: transaction, recoveryID: recoveryID)
        return (signature, recoveryValue)
    }

    /// The `v` a wallet expects for this transaction shape (design.md §5.3):
    ///
    /// * typed (EIP-2930/1559) — the y-parity itself, `0` or `1`;
    /// * legacy with EIP-155 — `chainId·2 + 35 + recid`, which is the value that
    ///   goes into the `v` slot of the serialised transaction and therefore the
    ///   value a wallet needs. It exceeds one byte for chain ids above 110, and
    ///   the caller is responsible for emitting it in the wider signature form;
    /// * legacy without EIP-155 — `27 + recid`.
    public static func value(for transaction: EVMTransaction, recoveryID: UInt8) throws -> EVMQuantity {
        switch transaction.kind {
        case .accessList, .feeMarket:
            return EVMQuantity(UInt64(recoveryID))
        case .legacy:
            if let chainId = transaction.chainId {
                return chainId.multiplied(by: 2).adding(UInt64(35 + recoveryID))
            }
            return EVMQuantity(UInt64(27 + recoveryID))
        }
    }

    /// True when the recovery value fits in the one byte the 65-byte signature
    /// layout has for it.
    public static func fitsInSingleByte(_ recoveryValue: EVMQuantity) -> Bool {
        recoveryValue.bytes.count <= 1
    }
}

public extension EVMQuantity {
    /// Byte-wise addition of a small constant. Used for EIP-155 `v`, where the
    /// arithmetic is trivial but the operand width is not.
    func adding(_ value: UInt64) -> EVMQuantity {
        var addend: [UInt8] = []
        var remaining = value
        while remaining > 0 {
            addend.insert(UInt8(remaining & 0xff), at: 0)
            remaining >>= 8
        }
        let width = max(bytes.count, addend.count) + 1
        var result = [UInt8](repeating: 0, count: width)
        var carry = 0
        var index = width - 1
        let left = [UInt8](repeating: 0, count: width - bytes.count) + bytes
        let right = [UInt8](repeating: 0, count: width - addend.count) + addend
        while index >= 0 {
            let sum = Int(left[index]) + Int(right[index]) + carry
            result[index] = UInt8(sum & 0xff)
            carry = sum >> 8
            index -= 1
        }
        while result.count > 1, result.first == 0 { result.removeFirst() }
        if result == [0] { result = [] }
        return (try? EVMQuantity(minimalBytes: result)) ?? .zero
    }
}
