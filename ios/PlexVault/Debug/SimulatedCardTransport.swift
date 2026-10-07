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
        // `-reset-simulated-card` clears what a previous launch saved, so a UI test starts on a
        // factory-fresh reader. Without it the saved cards are restored, which is what makes a
        // provisioned simulated wallet survive a relaunch.
        let shouldReset = ProcessInfo.processInfo.arguments
            .contains(SimulatedCardStore.resetLaunchArgument)
        if shouldReset { SimulatedCardStore.resetAll() }

        // DEBUG-only: a wait on `PSO:CDS`, so the signing screen's "touch the YubiKey" prompt is on
        // screen long enough for a test to see it. Zero unless `-simulated-touch-delay-ms` is set.
        let touchDelay = SimulatedCardTransport.simulatedTouchDelay()

        var result: [MockYubikeyTransport] = []
        for index in 0..<cardCount {
            let mock = MockYubikeyTransport(
                transportName: "Simulated YubiKey (debug)",
                serial: 0x00DE_71A5 + UInt32(index),
                openPGPVersion: "3.4"
            )
            SimulatedCardTransport.applyDeterministicEntropy(to: mock)
            if let touchDelay { mock.touchDelay = touchDelay }
            // The card the developer left in the reader. Restored here rather than in the
            // transport's `open()` because the mock is the shared, process-wide applet: every
            // fresh `SimulatedCardTransport` talks to this one instance.
            if !shouldReset, let state = SimulatedCardStore.load(index: index) {
                mock.persistentState = state
            }
            result.append(mock)
        }
        return result
    }()

    /// DEBUG-only deterministic entropy for the UI tests: `GET CHALLENGE` returns these bytes
    /// instead of random data, so the ceremony produces a known mnemonic. Compiled out of Release
    /// entirely.
    private static func applyDeterministicEntropy(to mock: MockYubikeyTransport) {
        let arguments = ProcessInfo.processInfo.arguments
        guard let argumentIndex = arguments.firstIndex(of: "-deterministic-entropy"),
              argumentIndex + 1 < arguments.count,
              let bytes = try? Hex.decode(arguments[argumentIndex + 1]),
              bytes.count == BIP39.entropyByteCount
        else { return }
        mock.challengeBytes = bytes
    }

    /// DEBUG-only: the wait `-simulated-touch-delay-ms <n>` puts on `PSO:CDS`, modelling the wait
    /// for a touch. `nil` when the argument is absent or not a positive number.
    private static func simulatedTouchDelay() -> Duration? {
        let arguments = ProcessInfo.processInfo.arguments
        guard let index = arguments.firstIndex(of: "-simulated-touch-delay-ms"),
              index + 1 < arguments.count,
              let milliseconds = Int(arguments[index + 1]),
              milliseconds > 0
        else { return nil }
        return .milliseconds(milliseconds)
    }

    /// Puts the reader back to a factory-fresh card: forgets what was saved and empties the applet
    /// in memory, so the next ceremony sees a blank card. The "Reset card" button on the device
    /// screen calls this; `-reset-simulated-card` does the same thing before the first screen.
    ///
    /// The in-memory half is what makes the button take effect now rather than at the next launch:
    /// the cards are process-wide, so clearing the saved data alone would leave the card in the
    /// reader exactly as it was.
    static func resetCard() {
        SimulatedCardStore.resetAll()
        cardIndex = 0
        for mock in simulatedCards {
            mock.persistentState = MockYubikeyTransport.PersistentState()
            applyDeterministicEntropy(to: mock)
        }
    }

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

    /// Saves the applet after the session that just ended. `TransportSessionCard` closes every
    /// session on both the success and the error path, so one write per session covers every
    /// mutation the ceremony makes — and not one per APDU, which would put a plist write in the
    /// middle of the protocol.
    func close() async {
        await inner.close()
        SimulatedCardStore.save(inner.persistentState, index: Self.cardIndex)
    }
}

/// The DEBUG simulated card's state, saved between launches.
///
/// A real YubiKey keeps its PINs, keys and stored objects when the phone is put down; the
/// simulated one used to forget everything at process exit, so every relaunch meant provisioning
/// the fake wallet again. This keeps the durable applet state
/// (`MockYubikeyTransport.PersistentState`) in `UserDefaults`, under one namespaced key per
/// simulated card.
///
/// DEBUG-only in two senses: this whole file is wrapped in `#if DEBUG`, and the card it belongs to
/// is excluded from Release by `project.yml` (check 1 of `tools/audit-release.sh` asserts a release
/// bundle cannot reach a simulated card). Check 3 of that audit names this file and asserts it is
/// DEBUG-gated, lives in the Debug directory, and reaches for no secret-bearing API. Everything it
/// stores belongs to the *simulated* applet — test material, and never a real key.
///
/// Deliberately not `@AppStorage`: the audit greps for persistence APIs by name, and a property
/// wrapper would hide this site from the check whose job is to notice it.
enum SimulatedCardStore {
    /// Namespaced, because `UserDefaults` is one shared dictionary per app. One key per card
    /// index, so a two-card run restores both cards in order.
    static let keyPrefix = "com.plexsec.vault.simulated-card"

    /// Clears the saved cards before the first screen. The UI tests pass it so a walk that
    /// provisions the simulated card does not change what the next test sees.
    static let resetLaunchArgument = "-reset-simulated-card"

    private static func key(for index: Int) -> String { "\(keyPrefix).\(index)" }

    static func load(
        index: Int,
        defaults: UserDefaults = .standard
    ) -> MockYubikeyTransport.PersistentState? {
        guard let data = defaults.data(forKey: key(for: index)) else { return nil }
        return try? JSONDecoder().decode(MockYubikeyTransport.PersistentState.self, from: data)
    }

    static func save(
        _ state: MockYubikeyTransport.PersistentState,
        index: Int,
        defaults: UserDefaults = .standard
    ) {
        guard let data = try? JSONEncoder().encode(state) else { return }
        defaults.set(data, forKey: key(for: index))
        // The wipe closes the process with `exit(0)`, which does not run the app lifecycle, so the
        // flush that would normally happen at termination cannot be relied on — the same reason
        // `PendingPairingStore` synchronizes its flag. Saves are per session, not per APDU.
        _ = defaults.synchronize()
    }

    static func resetAll(defaults: UserDefaults = .standard) {
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix(keyPrefix) {
            defaults.removeObject(forKey: key)
        }
        _ = defaults.synchronize()
    }
}
#endif
