import Foundation

/// A chain id, and the labels an operator recognises for it.
///
/// The screen has to name the asset it is asking the operator to approve. A summary that
/// says "1.5 ETH" for a Polygon transaction is wrong about the thing being approved, and
/// "chain id 137" on its own asks the operator to remember what 137 is — which is exactly
/// the sort of memory the screen exists to replace.
///
/// Two rules, both deliberate:
///
/// * **This table is a display convenience and never a gate.** Nothing in the signing path
///   consults it to decide anything. An unknown chain id is still signable: an app that
///   signed only the chains its author happened to list would refuse legitimate networks,
///   and the check that matters is the id against the wallet's own screen — which is why
///   `displayName` always carries the number.
/// * **An unknown chain gets no symbol rather than a default.** Defaulting to ETH is how
///   the summary came to mislabel Polygon in the first place. Same principle as the card
///   layer's "an unclassified failure is not a retry": when in doubt, say less.
public struct EVMChain: Equatable, Sendable {
    public let id: UInt64
    /// The chain's name, or `nil` when this app does not know the chain id.
    public let name: String?
    /// The native coin's ticker, or `nil` when this app does not know it.
    public let nativeSymbol: String?

    public init(id: UInt64) {
        self.id = id
        let entry = Self.known[id]
        self.name = entry?.name
        self.nativeSymbol = entry?.nativeSymbol
    }

    private init(id: UInt64, name: String, nativeSymbol: String) {
        self.id = id
        self.name = name
        self.nativeSymbol = nativeSymbol
    }

    /// How the chain is named in a row. Always carries the id, so it can be compared with
    /// the wallet even when this app knows the name.
    public var displayName: String {
        name.map { "\($0) (chain id \(id))" } ?? "chain id \(id) (not a chain this app knows)"
    }

    /// The same, plus what the fees are paid in. Used where the operator is deciding
    /// whether this is the network they meant rather than reading a table.
    public var summaryLine: String {
        nativeSymbol.map { "\(displayName), native token \($0)" } ?? displayName
    }

    /// `"1.5 POL"`, or `"1.5 native"` when the symbol is unknown: a number with no unit
    /// claim is better than a number with the wrong one. The exact wei figure is shown
    /// beside it either way.
    public func amount(_ value: String) -> String {
        "\(value) \(nativeSymbol ?? "native")"
    }

    /// The chains this app can name.
    ///
    /// Every entry is a chain whose native coin ticker is settled public knowledge;
    /// nothing here is inferred, and an absent entry degrades to the chain id alone
    /// rather than to a guess. Polygon's coin is spelled POL because that is what the
    /// September 2024 migration renamed it to, and because what a wallet shows now is
    /// what the operator will be comparing against.
    ///
    /// Every EVM chain's native coin has 18 decimals, which is why the display can divide
    /// wei by 10¹⁸ (`EVMTransaction.valueInEther`) on any of them. A chain that broke that
    /// assumption would need the divisor to become a per-chain field; the wei value is
    /// displayed alongside the formatted one so the exact integer is never out of sight.
    ///
    /// Adding an entry is a display change only. It cannot make a chain signable or
    /// unsignable, because no decision is made from this table.
    public static let known: [UInt64: EVMChain] = [
        1: EVMChain(id: 1, name: "Ethereum", nativeSymbol: "ETH"),
        10: EVMChain(id: 10, name: "OP Mainnet", nativeSymbol: "ETH"),
        56: EVMChain(id: 56, name: "BNB Smart Chain", nativeSymbol: "BNB"),
        100: EVMChain(id: 100, name: "Gnosis", nativeSymbol: "xDAI"),
        137: EVMChain(id: 137, name: "Polygon", nativeSymbol: "POL"),
        324: EVMChain(id: 324, name: "zkSync Era", nativeSymbol: "ETH"),
        8453: EVMChain(id: 8453, name: "Base", nativeSymbol: "ETH"),
        42161: EVMChain(id: 42161, name: "Arbitrum One", nativeSymbol: "ETH"),
        43114: EVMChain(id: 43114, name: "Avalanche C-Chain", nativeSymbol: "AVAX"),
        59144: EVMChain(id: 59144, name: "Linea", nativeSymbol: "ETH"),
        534352: EVMChain(id: 534352, name: "Scroll", nativeSymbol: "ETH"),
        11155111: EVMChain(id: 11155111, name: "Sepolia", nativeSymbol: "ETH"),
        80002: EVMChain(id: 80002, name: "Polygon Amoy", nativeSymbol: "POL"),
    ]
}
