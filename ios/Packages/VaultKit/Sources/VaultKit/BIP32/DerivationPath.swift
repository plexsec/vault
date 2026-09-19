import Foundation

/// A BIP32 derivation path such as `m/44'/60'/0'/0/0`.
public struct DerivationPath: Equatable, Hashable, Sendable, CustomStringConvertible {
    public enum Component: Equatable, Hashable, Sendable {
        case hardened(UInt32)
        case normal(UInt32)

        /// The 32-bit child index with the hardened bit applied.
        public var index: UInt32 {
            switch self {
            case .hardened(let value): return value | 0x8000_0000
            case .normal(let value): return value
            }
        }

        public var isHardened: Bool {
            if case .hardened = self { return true }
            return false
        }
    }

    public enum ParseError: Swift.Error, Equatable {
        case empty
        case missingMasterPrefix
        case invalidComponent(String)
        case indexOutOfRange(String)
    }

    public let components: [Component]

    public init(components: [Component]) {
        self.components = components
    }

    /// Parses `m`, `m/0`, `m/44'/60'/0'/0/0`. Accepts `'` or `h`/`H` for hardened.
    public init(_ string: String) throws {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw ParseError.empty }

        var parts = trimmed.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard let first = parts.first, first == "m" || first == "M" else {
            throw ParseError.missingMasterPrefix
        }
        parts.removeFirst()

        var parsed: [Component] = []
        parsed.reserveCapacity(parts.count)
        for part in parts {
            guard !part.isEmpty else { throw ParseError.invalidComponent(part) }
            var body = part
            var hardened = false
            if let last = body.last, last == "'" || last == "h" || last == "H" {
                hardened = true
                body.removeLast()
            }
            guard let value = UInt32(body), value < 0x8000_0000 else {
                throw ParseError.indexOutOfRange(part)
            }
            parsed.append(hardened ? .hardened(value) : .normal(value))
        }
        self.components = parsed
    }

    public var description: String {
        guard !components.isEmpty else { return "m" }
        let body = components.map { component -> String in
            switch component {
            case .hardened(let value): return "\(value)'"
            case .normal(let value): return "\(value)"
            }
        }.joined(separator: "/")
        return "m/" + body
    }

    /// Child indices with the hardened bit applied, ready for `ExtendedPrivateKey.child(_:)`.
    public var indices: [UInt32] { components.map(\.index) }

    // MARK: Standard paths used by this app

    /// The single secp256k1 path. One YubiKey slot holds exactly one key, and
    /// that one key serves every secp256k1 chain, so the path is deliberately
    /// NOT chain-specific: SLIP-44 coin type 0 is used as the neutral value
    /// rather than 60 (Ethereum) or 84 (Bitcoin), either of which would claim
    /// the key belongs to one chain. See design.md §4.3.
    public static let secp256k1Default = try! DerivationPath("m/44'/0'/0'/0/0")

    /// The single Ed25519 path, in SLIP-0010 form. Every component is hardened
    /// because SLIP-0010 does not define non-hardened derivation for Ed25519.
    public static let ed25519Default = try! DerivationPath("m/44'/501'/0'/0'")
}

/// Account-level ancestors used when describing an HD key in a UR.
public extension DerivationPath {
    /// The prefix of `count` components, e.g. the account level of a key path.
    func prefix(_ count: Int) -> DerivationPath {
        DerivationPath(components: Array(components.prefix(count)))
    }

    var accountLevel: DerivationPath {
        components.count >= 3 ? prefix(3) : self
    }
}

/// Signature algorithm a ceremony provisions. One YubiKey signing-capable slot
/// holds exactly one key, so the model is "one algorithm per slot" rather than
/// "one chain per slot": every chain that uses the algorithm shares the key.
public enum KeyAlgorithm: String, CaseIterable, Codable, Sendable {
    /// ECDSA over secp256k1: EVM chains, Bitcoin and the other secp256k1 chains.
    case secp256k1
    /// Ed25519 (EdDSA): Solana, Cardano, Polkadot, NEAR, Sui, Aptos and friends.
    case ed25519

    public var displayName: String {
        switch self {
        case .secp256k1: return "ECDSA secp256k1"
        case .ed25519: return "Ed25519"
        }
    }

    /// One fixed path per algorithm; see `DerivationPath.secp256k1Default`.
    public var defaultPath: DerivationPath {
        switch self {
        case .secp256k1: return .secp256k1Default
        case .ed25519: return .ed25519Default
        }
    }

    /// SLIP-44 coin type, with the hardened bit removed (used by the UR
    /// `coin-info` type, per BCR-2020-007). 501 is the registration for Solana,
    /// taken as the reference Ed25519 chain; the identity this app displays is
    /// chain-agnostic regardless (design.md §6.4).
    public var slip44CoinType: UInt32 {
        switch self {
        case .secp256k1: return 0
        case .ed25519: return 501
        }
    }

    /// The OpenPGP key slot this algorithm is written to. Fixed by design: the
    /// signature slot is the only one that increments the hardware signature
    /// counter, so secp256k1 — the algorithm whose chains this scheme audits —
    /// takes it, and Ed25519 takes the authentication slot.
    public var slot: KeySlot {
        switch self {
        case .secp256k1: return .signature
        case .ed25519: return .authentication
        }
    }

    /// Length of the public key as stored on the card and exported.
    public var publicKeyLength: Int {
        switch self {
        case .secp256k1: return 33   // SEC1 compressed
        case .ed25519: return 32     // raw Edwards point
        }
    }
}
