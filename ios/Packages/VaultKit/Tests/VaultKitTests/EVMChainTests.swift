import Foundation
import XCTest

@testable import VaultKit

/// Chain naming, and the asset label on the screens that ask for an approval.
///
/// The defect this locks down: the summary used to append a literal `ETH` to every value
/// and every fee, so a Polygon transaction was displayed as "1.5 ETH". Polygon's native
/// coin is POL, and the number the operator is asked to approve has to be denominated in
/// the right thing — a screen that misnames the asset is wrong about what is being signed
/// even when every other field is right.
final class EVMChainTests: XCTestCase {

    // MARK: - The table

    func testPolygonIsNamedAndItsCoinIsPOL() {
        let polygon = EVMChain(id: 137)
        XCTAssertEqual(polygon.name, "Polygon")
        XCTAssertEqual(polygon.nativeSymbol, "POL")
        XCTAssertEqual(polygon.displayName, "Polygon (chain id 137)")
        XCTAssertEqual(polygon.summaryLine, "Polygon (chain id 137), native token POL")
        XCTAssertEqual(polygon.amount("1.5"), "1.5 POL")
    }

    func testEthereumKeepsItsSymbol() {
        XCTAssertEqual(EVMChain(id: 1).nativeSymbol, "ETH")
        XCTAssertEqual(EVMChain(id: 1).amount("1"), "1 ETH")
    }

    /// Polygon's own testnet is POL too, and a chain that merely *uses* ETH as its gas
    /// token is not Ethereum.
    func testChainsThatAreNotEthereumAreNotCalledEthereum() {
        XCTAssertEqual(EVMChain(id: 80002).nativeSymbol, "POL")
        XCTAssertEqual(EVMChain(id: 56).nativeSymbol, "BNB")
        XCTAssertEqual(EVMChain(id: 43114).nativeSymbol, "AVAX")
        XCTAssertEqual(EVMChain(id: 100).nativeSymbol, "xDAI")
        // These are L2s that settle in ETH, so ETH is the correct label for them.
        XCTAssertEqual(EVMChain(id: 10).nativeSymbol, "ETH")
        XCTAssertEqual(EVMChain(id: 42161).nativeSymbol, "ETH")
        XCTAssertEqual(EVMChain(id: 8453).nativeSymbol, "ETH")
    }

    /// The regression: an unknown chain must not be given a symbol at all. Defaulting to
    /// ETH is precisely the bug this file exists for, so the default is "no claim".
    func testAnUnknownChainGetsNoNameAndNoSymbol() {
        let unknown = EVMChain(id: 424242)
        XCTAssertNil(unknown.name)
        XCTAssertNil(unknown.nativeSymbol)
        XCTAssertEqual(unknown.displayName, "chain id 424242 (not a chain this app knows)")
        XCTAssertEqual(unknown.amount("2"), "2 native")
    }

    /// Every entry has to be usable on screen, and the ids have to be the keys — a typo'd
    /// key would silently mislabel a chain, which is the one failure mode that matters
    /// here.
    func testTheTableIsInternallyConsistent() {
        for (key, chain) in EVMChain.known {
            XCTAssertEqual(key, chain.id, "entry \(key) is filed under the wrong id")
            XCTAssertFalse(chain.name?.isEmpty ?? true, "chain \(key) has no name")
            XCTAssertFalse(chain.nativeSymbol?.isEmpty ?? true, "chain \(key) has no symbol")
            XCTAssertEqual(chain.displayName, "\(chain.name ?? "") (chain id \(key))")
        }
    }

    // MARK: - The summary the operator reads

    /// A Polygon transaction — legacy, since that is the case where the recovery value
    /// also widens — must be denominated in POL everywhere, and must never mention ETH.
    func testPolygonLegacySummaryIsDenominatedInPOL() throws {
        let transaction = try EVMTransaction(
            signData: try SigningCeremonyTests.polygonPayload(),
            dataType: .transaction
        )
        let summary = TransactionSummary(transaction: transaction)

        XCTAssertEqual(summary.chain?.name, "Polygon")
        XCTAssertEqual(summary.chainID, "137")
        XCTAssertFalse(summary.value.contains("ETH"), "a Polygon value must not be called ETH")
        XCTAssertTrue(summary.value.hasSuffix("wei)"), summary.value)
        XCTAssertTrue(summary.value.contains(" POL ("), summary.value)

        let rows = Dictionary(uniqueKeysWithValues: summary.rows.map { ($0.label, $0.value) })
        XCTAssertEqual(rows["Chain"], "Polygon (chain id 137)")
        XCTAssertNil(rows["Chain id"], "the named row replaces the bare id row")
        XCTAssertEqual(rows["Value"]?.contains("ETH"), false)
        XCTAssertEqual(try XCTUnwrap(rows["Value"]).contains(" POL"), true)
        // The headline is what an operator skims, so it carries the unit too.
        XCTAssertTrue(summary.headline.contains("POL"), summary.headline)
    }

    /// EIP-1559 is what Polygon actually sends, and it is the case with fee rows.
    func testPolygonFeeMarketSummaryIsDenominatedInPOL() throws {
        let transaction = try EVMTransaction(
            signData: try Self.polygonFeeMarketPayload(),
            dataType: .typedTransaction
        )
        let summary = TransactionSummary(transaction: transaction)
        let rows = Dictionary(uniqueKeysWithValues: summary.rows.map { ($0.label, $0.value) })

        XCTAssertEqual(rows["Chain"], "Polygon (chain id 137)")
        XCTAssertEqual(rows["Value"], "0 POL")
        XCTAssertEqual(try XCTUnwrap(rows["Maximum fee"]).hasSuffix(" POL"), true)
        XCTAssertEqual(try XCTUnwrap(rows["Max fee per gas"]).hasSuffix(" gwei"), true)
        for row in summary.rows {
            XCTAssertFalse(row.value.contains("ETH"), "\(row.label) says ETH on Polygon: \(row.value)")
        }
    }

    /// On a chain this app cannot name, the label says `native` and never guesses.
    func testUnknownChainSummaryClaimsNoSymbol() throws {
        let transaction = try EVMTransaction(
            signData: try Self.feeMarketPayload(chainID: 424242, value: EVMQuantity(2_000_000_000_000_000_000)),
            dataType: .typedTransaction
        )
        let summary = TransactionSummary(transaction: transaction)
        let rows = Dictionary(uniqueKeysWithValues: summary.rows.map { ($0.label, $0.value) })

        XCTAssertEqual(rows["Chain"], "chain id 424242 (not a chain this app knows)")
        XCTAssertEqual(rows["Value"], "2 native")
        XCTAssertFalse(summary.value.contains("ETH"))
        for row in summary.rows {
            XCTAssertFalse(row.value.contains("ETH"), "\(row.label) invented a symbol: \(row.value)")
        }
    }

    /// A transaction with no chain id is refused by the ceremony before anyone sees a
    /// summary, but the summary itself must not pretend it knows the chain.
    func testSummaryWithoutAChainIDClaimsNoSymbol() throws {
        let transaction = try EVMTransaction(
            signData: try Self.legacyPayload(chainID: nil, value: EVMQuantity(1_000_000_000_000_000_000)),
            dataType: .transaction
        )
        let summary = TransactionSummary(transaction: transaction)
        XCTAssertNil(summary.chain)
        XCTAssertEqual(summary.chainID, "—")
        XCTAssertTrue(summary.value.hasPrefix("1 native"), summary.value)
        XCTAssertEqual(
            summary.rows.first { $0.label == "Chain" }?.value,
            "no chain id — replayable on every chain"
        )
    }

    // MARK: - The record

    /// The record is composed in the library rather than by the view, so the unit cannot
    /// drift from the chain the way the view's literal `ETH` did.
    func testTheRecordNamesTheChainAndItsCoin() {
        var report = SigningReport()
        report.chainID = "137"
        report.valueInEther = "1.5"
        report.value = "1500000000000000000"

        XCTAssertEqual(report.chain?.nativeSymbol, "POL")
        XCTAssertEqual(report.chainDisplay, "Polygon (chain id 137)")
        XCTAssertEqual(report.nativeValueDisplay, "1.5 POL (1500000000000000000 wei)")
    }

    func testTheRecordOnAnUnknownChainClaimsNoSymbol() {
        var report = SigningReport()
        report.chainID = "424242"
        report.valueInEther = "0"
        report.value = "0"

        XCTAssertNil(report.chain?.nativeSymbol)
        XCTAssertEqual(report.chainDisplay, "chain id 424242 (not a chain this app knows)")
        XCTAssertEqual(report.nativeValueDisplay, "0 native (0 wei)")
    }

    /// The confirmation prompt is where the operator decides whether this is the network
    /// they meant, so the refusal to sign until they confirm has to say which chain.
    func testTheUnconfirmedChainMessageNamesTheChain() {
        let message = SigningError.chainNotConfirmed(chainID: "137").userFacingDescription
        XCTAssertTrue(message.contains("Polygon (chain id 137)"), message)
        XCTAssertTrue(message.contains("native token POL"), message)

        let unknown = SigningError.chainNotConfirmed(chainID: "424242").userFacingDescription
        XCTAssertTrue(unknown.contains("chain id 424242"), unknown)
        XCTAssertFalse(unknown.contains("ETH"), unknown)
    }

    // MARK: - Payloads

    /// `0x02 ‖ RLP([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList])`
    static func polygonFeeMarketPayload() throws -> [UInt8] {
        try feeMarketPayload(chainID: 137, value: EVMQuantity(0))
    }

    /// The fields match `tools/derive`'s `fee_market` helper, so the digests these
    /// payloads produce are the ones the mock card has real signatures for.
    static func feeMarketPayload(
        chainID: UInt64,
        value: EVMQuantity,
        to: [UInt8]? = try? Hex.decode(EVMTransactionTests.recipient)
    ) throws -> [UInt8] {
        [0x02] + (try RLP.encode(.list([
            .bytes(EVMQuantity(chainID).bytes),
            .bytes([0x01]),
            .bytes(EVMQuantity(1_000_000_000).bytes),
            .bytes(EVMQuantity(30_000_000_000).bytes),
            .bytes([0x52, 0x08]),
            .bytes(to ?? []),
            .bytes(value.bytes),
            .bytes([]),
            .list([]),
        ])))
    }

    /// `RLP([nonce, gasPrice, gas, to, value, data])`, with the EIP-155 tail when a chain
    /// id is given.
    static func legacyPayload(chainID: UInt64?, value: EVMQuantity) throws -> [UInt8] {
        var items: [RLP.Item] = [
            .bytes([0x01]),
            .bytes(EVMQuantity(4_000_000_000).bytes),
            .bytes([0x52, 0x08]),
            .bytes(try Hex.decode(EVMTransactionTests.recipient)),
            .bytes(value.bytes),
            .bytes([]),
        ]
        if let chainID {
            items.append(.bytes(EVMQuantity(chainID).bytes))
            items.append(.bytes([]))
            items.append(.bytes([]))
        }
        return try RLP.encode(.list(items))
    }
}
