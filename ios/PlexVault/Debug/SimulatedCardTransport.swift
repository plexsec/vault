#if DEBUG
import Foundation
import VaultKit
import YubikeyKit

/// DEBUG-only bridge to the package's simulated YubiKey.
///
/// Both this file and `MockYubikeyTransport.swift` are excluded from Release:
/// this one by `#if DEBUG`, the mock by `EXCLUDED_SOURCE_FILE_NAMES` in
/// project.yml. The mock is compiled into the app target rather than linked as a
/// package product, because linking the product left its symbols in the shipped
/// binary. `tools/audit-release.sh` asserts the marker strings are absent.
///
/// The simulation is a real APDU responder rather than a stub that answers
/// "success": it enforces PIN verification, refuses a second key import into an
/// occupied slot, and returns 6A88 when no key is present, so the DEBUG flow
/// exercises the same code paths the real card does.
@available(iOS 26.0, *)
final class SimulatedCardTransport: YubikeyTransport {
    let transportName = "Simulated YubiKey (debug)"

    /// A real YubiKey keeps its PINs and keys on the card between NFC taps, but
    /// `TransportSessionCard` opens a *fresh* transport for every step. Sharing
    /// one mock behind every `SimulatedCardTransport` instance reproduces that
    /// physical persistence: without it each step would see a factory-fresh card
    /// and the Admin PIN set by the PIN step would already be gone by the time
    /// `applyPolicy` verifies it.
    private static let shared: MockYubikeyTransport = simulatedCards[0]

    /// DEBUG-only: the number of simulated cards in the reader, from `-simulated-cards <n>`.
    /// One by default.
    ///
    /// A real reader holds one card at a time and the operator swaps it, so this is a *test*
    /// affordance rather than a simulation of the hardware: it exists so the UI test can run a
    /// two-YubiKey ceremony, which is the path a hardware run found broken (amendment 41).
    private static let cardCount: Int = {
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "-simulated-cards"),
           index + 1 < arguments.count,
           let count = Int(arguments[index + 1]) {
            return max(1, count)
        }
        return 1
    }()

    /// The simulated reader's cards. Each is a whole applet with its own serial, its own PINs and
    /// its own slots — and, because `TransportSessionCard` opens a fresh transport per step, they
    /// are handed out through `current` rather than per transport instance.
    private static let simulatedCards: [MockYubikeyTransport] = {
        var result: [MockYubikeyTransport] = []
        for index in 0..<cardCount {
            let mock = MockYubikeyTransport(
                transportName: "Simulated YubiKey (debug)",
                serial: 0x00DE_71A5 + UInt32(index),
                openPGPVersion: "3.4"
            )
            // DEBUG-only deterministic entropy for the UI tests: GET CHALLENGE
            // returns these bytes instead of random data, so the ceremony produces a
            // known mnemonic. Compiled out of Release entirely.
            let arguments = ProcessInfo.processInfo.arguments
            if let argumentIndex = arguments.firstIndex(of: "-deterministic-entropy"),
               argumentIndex + 1 < arguments.count,
               let bytes = try? Hex.decode(arguments[argumentIndex + 1]),
               bytes.count == BIP39.entropyByteCount {
                mock.challengeBytes = bytes
            }
            result.append(mock)
        }
        return result
    }()

    /// Which card the reader is holding, and the point at which the next one is handed over.
    ///
    /// The hand-over happens on the **inventory read** of a card that is already written, and
    /// nowhere else: that is the moment the ceremony asks for the next YubiKey, and it is the only
    /// moment the *write step itself* must not be interrupted — the read-back that follows the
    /// manifest write is still an operation on the card that was just written, and a rotation there
    /// made the write step fail against an empty card (which is how this affordance was got wrong
    /// the first time).
    private static var cardIndex = 0
    private static var current: MockYubikeyTransport { simulatedCards[cardIndex] }

    private static func handOverTheNextCardIfThisOneIsWritten() {
        if cardIndex + 1 < simulatedCards.count {
            cardIndex += 1
        }
    }

    /// The operator has swapped the card in the reader: the ceremony calls this when one card's
    /// pass is complete and the next YubiKey is asked for. A real reader needs no telling — it
    /// simply has a different card in it — and inferring the swap from what the card holds is not
    /// possible: the write step reads its own manifest back after writing it, so "this card looks
    /// written" is true *before* the pass is over (amendment 41).
    public static func cardWasSwapped() { handOverTheNextCardIfThisOneIsWritten() }

    private var inner: MockYubikeyTransport { Self.current }

    func open() async throws { try await inner.open() }

    func send(_ command: CommandAPDU) async throws -> ResponseAPDU { try await inner.send(command) }

    func close() async { await inner.close() }
}
#endif
