import Foundation

/// A BIP32 derivation path such as `m/44'/60'/0'/0/0`.
public struct DerivationPath: Equatable, Hashable, CustomStringConvertible {
    public enum Component: Equatable, Hashable {
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

    // MARK: Standard paths used by this app (design.md §4.2 step 6)

    public static let evmDefault = try! DerivationPath("m/44'/60'/0'/0/0")
    public static let bitcoinBIP84Default = try! DerivationPath("m/84'/0'/0'/0/0")
}

/// Account-level ancestors used when describing an HD key in a UR.
public extension DerivationPath {
    /// The prefix of `count` components, e.g. the account level of an EVM path.
    func prefix(_ count: Int) -> DerivationPath {
        DerivationPath(components: Array(components.prefix(count)))
    }

    var accountLevel: DerivationPath {
        components.count >= 3 ? prefix(3) : self
    }
}

/// Chain-agnostic role of a provisioning ceremony. One YubiKey signature slot
/// holds exactly one key, so a ceremony targets exactly one of these.
public enum SigningChain: String, CaseIterable, Codable, Sendable {
    case ethereum
    case bitcoin

    public var displayName: String {
        switch self {
        case .ethereum: return "Ethereum (EVM)"
        case .bitcoin: return "Bitcoin (native segwit)"
        }
    }

    public var defaultPath: DerivationPath {
        switch self {
        case .ethereum: return .evmDefault
        case .bitcoin: return .bitcoinBIP84Default
        }
    }

    /// SLIP-44 coin type, with the hardened bit removed (used by the UR
    /// `coin-info` type, per BCR-2020-007).
    public var slip44CoinType: UInt32 {
        switch self {
        case .ethereum: return 60
        case .bitcoin: return 0
        }
    }
}
