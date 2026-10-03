import Foundation

/// A decoded ABI value, only ever produced by a check that succeeded.
///
/// Amounts stay raw integers. A token's number of decimals is *not* in the call
/// data — it is a property of the contract, which this app cannot query — so
/// rendering an ERC-20 amount as "1.5 tokens" would be a guess dressed up as a
/// fact. The screen shows the raw units and says so.
public enum ABIValue: Equatable, Sendable {
    case address([UInt8])
    case uint(EVMQuantity)
    case boolean(Bool)

    public var displayText: String {
        switch self {
        case .address(let bytes): return EVMAddress.checksummed(addressBytes: bytes)
        case .uint(let quantity): return "\(quantity.decimalString) (raw units)"
        case .boolean(let value): return value ? "true" : "false"
        }
    }
}

/// A function call decoded from transaction calldata.
public struct ABICall: Equatable, Sendable {
    /// The four-byte selector, always present.
    public let selector: [UInt8]
    /// The function name when the selector is one this app knows, otherwise `nil`.
    public let name: String?
    /// One entry per parameter, in order.
    public let arguments: [ABIValue]
    /// The parameter list, e.g. `address, uint256`.
    public let signature: String?

    public var isDecoded: Bool { name != nil }

    /// Text for a screen that must not overstate what it knows.
    public var displayName: String {
        guard let name, let signature else { return "unrecognised function" }
        return "\(name)(\(signature))"
    }
}

/// A deliberately small ABI decoder.
///
/// Scope is the honest part. This decodes a fixed list of function calls — the
/// ones that move tokens or hand over approval, which is what an operator most
/// needs to see and what a drainer is most likely to hide behind — and refuses
/// everything else to the raw-hex display rather than guessing. The wording for
/// that case is fixed by design.md §5.2 rule 5: the app displays parsed content
/// and never rewrites it.
public enum ABIDecoder {
    /// Selector -> (name, parameter types). Types are the ones this decoder can
    /// actually decode and check, not the full ABI grammar.
    static let functions: [String: (name: String, types: [ABIParameterType])] = [
        "a9059cbb": ("transfer", [.address, .uint]),
        "095ea7b3": ("approve", [.address, .uint]),
        "23b872dd": ("transferFrom", [.address, .address, .uint]),
        "39509351": ("increaseAllowance", [.address, .uint]),
        "a457c2d7": ("decreaseAllowance", [.address, .uint]),
        "a22cb465": ("setApprovalForAll", [.address, .boolean]),
        "42842e0e": ("safeTransferFrom", [.address, .address, .uint]),
        "2e1a7d4d": ("withdraw", [.uint]),
        "d0e30db0": ("deposit", []),
    ]

    public enum ABIParameterType: Equatable, Sendable {
        case address
        case uint
        case boolean

        public var displayName: String {
            switch self {
            case .address: return "address"
            case .uint: return "uint256"
            case .boolean: return "bool"
            }
        }
    }

    /// Decodes `data`. Returns `nil` when the data is not a call this decoder can
    /// read *exactly* — an unknown selector, a length that does not match the
    /// parameter list, or a word whose padding is not zero.
    public static func decode(_ data: [UInt8]) -> ABICall? {
        guard data.count >= 4 else { return nil }
        let selector = Array(data[0..<4])
        guard let function = functions[selector.hexString] else { return nil }
        let body = Array(data.dropFirst(4))
        guard body.count == function.types.count * 32 else { return nil }

        var arguments: [ABIValue] = []
        for (index, type) in function.types.enumerated() {
            let word = Array(body[(index * 32)..<((index + 1) * 32)])
            guard let value = decode(word: word, as: type) else { return nil }
            arguments.append(value)
        }
        return ABICall(
            selector: selector,
            name: function.name,
            arguments: arguments,
            signature: function.types.map(\.displayName).joined(separator: ", ")
        )
    }

    private static func decode(word: [UInt8], as type: ABIParameterType) -> ABIValue? {
        switch type {
        case .address:
            // The high 12 bytes must be zero; a non-zero high half is not a
            // padded address, and printing its low 20 bytes would be inventing one.
            guard word[0..<12].allSatisfy({ $0 == 0 }) else { return nil }
            return .address(Array(word[12..<32]))
        case .uint:
            // ABI words are left-padded to 32 bytes, so the leading zeros are the
            // padding, not a non-minimal integer: strip them before the quantity
            // type's own minimality check.
            var magnitude = word
            while magnitude.count > 1, magnitude.first == 0 { magnitude.removeFirst() }
            if magnitude == [0] { magnitude = [] }
            guard let quantity = try? EVMQuantity(minimalBytes: magnitude) else { return nil }
            return .uint(quantity)
        case .boolean:
            guard word[0..<31].allSatisfy({ $0 == 0 }), word[31] <= 1 else { return nil }
            return .boolean(word[31] == 1)
        }
    }
}

/// Everything the confirmation screen shows about one transaction.
///
/// Built from the parsed `EVMTransaction` and nothing else, so the screen cannot
/// display a field the transaction does not have, and the money-moving parts are
/// singled out: the recipient, the value and — for a token call — the amount and
/// who it goes to.
public struct TransactionSummary: Equatable, Sendable {
    public struct Row: Equatable, Sendable {
        public let label: String
        public let value: String
        /// Rows the operator must not skim past get emphasis on the screen.
        public let isCritical: Bool
    }

    public let kind: String
    /// The chain, when the transaction carries an id this app can name.
    public let chain: EVMChain?
    public let nonce: String
    public let recipient: String
    public let value: String
    public let rows: [Row]
    public let call: ABICall?
    public let rawDataHex: String
    /// Non-nil whenever part of the transaction could not be decoded exactly.
    public let decodeWarning: String?
    /// Kept for the headline: whether money moves, and whether calldata is a call.
    private let valueQuantity: EVMQuantity
    private let isContractCreation: Bool

    public static let undecodableWarning =
        "Unable to parse — proceed with caution. The recipient receives a call this app cannot "
        + "read; the raw data below is what the card will sign."

    /// The chain id as it appears on screen, or `—` when the transaction has none.
    public var chainID: String { chain.map { $0.id.description } ?? "—" }

    /// An amount of the chain's native coin. With no chain id there is no symbol to claim,
    /// so it is called what it is.
    static func native(_ value: String, on chain: EVMChain?) -> String {
        chain?.amount(value) ?? "\(value) native"
    }

    public init(transaction: EVMTransaction) {
        self.valueQuantity = transaction.value
        self.isContractCreation = transaction.to == nil
        let chain = transaction.chainId?.uint64.map(EVMChain.init(id:))
        self.kind = transaction.kind.displayName
        self.chain = chain
        self.nonce = transaction.nonce.decimalString
        self.recipient = transaction.checksummedRecipient
            ?? "contract creation (no recipient)"
        self.value = "\(Self.native(transaction.valueInEther, on: chain)) "
            + "(\(transaction.value.decimalString) wei)"
        self.rawDataHex = transaction.data.isEmpty ? "" : "0x" + transaction.data.hexString

        let call = ABIDecoder.decode(transaction.data)
        self.call = call
        if transaction.data.isEmpty {
            self.decodeWarning = nil
        } else if call == nil {
            self.decodeWarning = Self.undecodableWarning
        } else {
            self.decodeWarning = nil
        }

        var rows: [Row] = [
            Row(label: "Type", value: transaction.kind.displayName, isCritical: false),
            Row(
                label: "Chain",
                value: chain?.displayName ?? "no chain id — replayable on every chain",
                isCritical: false
            ),
            Row(label: "Nonce", value: transaction.nonce.decimalString, isCritical: false),
            Row(
                label: transaction.to == nil ? "Recipient" : "To",
                value: transaction.to.map { EVMAddress.checksummed(addressBytes: $0) }
                    ?? "contract creation (no recipient)",
                isCritical: true
            ),
            Row(
                label: "Value",
                value: Self.native(transaction.valueInEther, on: chain),
                isCritical: !transaction.value.isZero
            ),
            Row(label: "Gas limit", value: transaction.gasLimit.decimalString, isCritical: false),
        ]
        if let gasPrice = transaction.gasPriceInGwei {
            rows.append(Row(label: "Gas price", value: "\(gasPrice) gwei", isCritical: false))
        }
        if let maximumFee = transaction.maxFeePerGasInGwei {
            rows.append(Row(label: "Max fee per gas", value: "\(maximumFee) gwei", isCritical: false))
        }
        if let priorityFee = transaction.maxPriorityFeePerGasInGwei {
            rows.append(Row(label: "Max priority fee", value: "\(priorityFee) gwei", isCritical: false))
        }
        if let maximum = transaction.maximumFeeInEther {
            rows.append(
                Row(label: "Maximum fee", value: Self.native(maximum, on: chain), isCritical: false)
            )
        }
        if !transaction.accessList.isEmpty {
            let count = transaction.accessList.reduce(0) { $0 + $1.storageKeys.count }
            rows.append(
                Row(
                    label: "Access list",
                    value: "\(transaction.accessList.count) address(es), \(count) storage key(s)",
                    isCritical: false
                )
            )
        }
        if let call {
            rows.append(Row(label: "Function", value: call.displayName, isCritical: true))
            for (index, argument) in call.arguments.enumerated() {
                rows.append(
                    Row(label: "  argument \(index + 1)", value: argument.displayText, isCritical: false)
                )
            }
        } else if !transaction.data.isEmpty {
            rows.append(
                Row(
                    label: "Function",
                    value: "unrecognised (\(transaction.data.count) bytes)",
                    isCritical: true
                )
            )
        }
        self.rows = rows
    }

    /// The one-line answer to "what will this do?", used as the screen's headline.
    ///
    /// Written from the decoded arguments, never from the raw bytes: a headline is
    /// the part of the screen people read, so it has to be derived from something
    /// that was checked.
    public var headline: String {
        if let call {
            let arguments = call.arguments
            switch call.name {
            case "transfer" where arguments.count == 2:
                return "Send \(arguments[1].displayText) to \(arguments[0].displayText)"
            case "safeTransferFrom" where arguments.count == 3:
                return "Send \(arguments[2].displayText) to \(arguments[1].displayText)"
            case "transferFrom" where arguments.count == 3:
                return "Move \(arguments[2].displayText) from \(arguments[0].displayText) "
                    + "to \(arguments[1].displayText)"
            case "approve", "increaseAllowance", "decreaseAllowance":
                guard arguments.count == 2 else { return call.displayName }
                return "Let \(arguments[0].displayText) spend \(arguments[1].displayText)"
            case "setApprovalForAll" where arguments.count == 2:
                return arguments[1].displayText == "true"
                    ? "Give \(arguments[0].displayText) control of every token in this account"
                    : "Revoke \(arguments[0].displayText)'s control of this account's tokens"
            default:
                return call.displayName
            }
        }
        if !valueQuantity.isZero {
            return "Send \(value)"
        }
        return isContractCreation ? "Deploy a contract" : "Call a contract"
    }
}
