#if DEBUG || REVIEW_DEMO
import Foundation
import VaultKit
import YubikeyKit

/// Bridge to the package's simulated YubiKey. Compiled into DEBUG builds **and into the App
/// Store build**, deliberately (amendment 51).
///
/// App Review has no YubiKey 5 NFC, and an app whose only real card is hardware they do not
/// have is an app they cannot review. The released binary therefore carries a card that needs
/// no hardware, offered on the card-connection screen and labelled as a demo there and on every
/// screen that names the connection afterwards.
///
/// What still does not ship is the *test apparatus* around it. The launch arguments
/// (`-deterministic-entropy`, `-simulated-cards`, `-simulated-touch-delay-ms`,
/// `-reset-simulated-card`) are DEBUG-only, so a released build cannot be seeded with a known
/// mnemonic, given more cards than a reader could hold, or made to wait on a pretend touch.
/// Check 1 of `tools/audit-release.sh` asserts both halves: the card is present, the hooks are
/// not.
///
/// The simulation is a real APDU responder rather than a stub that answers "success": it
/// enforces PIN verification, refuses a second key import into an occupied slot, and returns
/// 6A88 when no key is present, so the flow exercises the same code paths the real card does.
/// What it cannot do is produce a valid signature — `MockYubikeyTransport.computeDigitalSignature`
/// returns one only for the single digest a DEBUG-only vector table holds, and a fabricated DER
/// otherwise, which the signing ceremony's own verification refuses. That is the fact that makes
/// the demo card unfit for a real wallet rather than merely discouraged, and it is recorded in
/// amendment 51 rather than papered over.
@available(iOS 26.0, *)
final class SimulatedCardTransport: YubikeyTransport {
    let transportName = "Simulated YubiKey (demo)"

    /// A real YubiKey keeps its PINs and keys on the card between NFC taps, but
    /// `TransportSessionCard` opens a *fresh* transport for every step. Sharing
    /// one mock behind every `SimulatedCardTransport` instance reproduces that
    /// physical persistence: without it each step would see a factory-fresh card
    /// and the Admin PIN set by the PIN step would already be gone by the time
    /// `applyPolicy` verifies it.
    private static let shared: MockYubikeyTransport = simulatedCards[0]

    /// The number of simulated cards in the reader, from `-simulated-cards <n>` — a DEBUG-only
    /// *test* affordance, one card otherwise.
    ///
    /// A real reader holds one card at a time and the operator swaps it, so the argument is
    /// not a simulation of hardware: it exists so the UI test can run a two-YubiKey ceremony,
    /// which is the path a hardware run found broken (amendment 41). A released build always
    /// holds one, which is also all a reviewer could swap.
    private static let cardCount: Int = {
        #if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "-simulated-cards"),
           index + 1 < arguments.count,
           let count = Int(arguments[index + 1]) {
            return max(1, count)
        }
        #endif
        return 1
    }()

    /// The simulated reader's cards. Each is a whole applet with its own serial, its own PINs and
    /// its own slots — and, because `TransportSessionCard` opens a fresh transport per step, they
    /// are handed out through `current` rather than per transport instance.
    private static let simulatedCards: [MockYubikeyTransport] = {
        // `-reset-simulated-card` clears what a previous launch saved, so a UI test starts on a
        // factory-fresh reader. Without it the saved cards are restored, which is what makes a
        // provisioned simulated wallet survive a relaunch — and that restoration is the part a
        // released build keeps: a reviewer who provisions the demo card and comes back later
        // finds it still there, exactly as a YubiKey would be.
        let restoreSavedCards: Bool
        #if DEBUG
        let shouldReset = ProcessInfo.processInfo.arguments
            .contains(SimulatedCardStore.resetLaunchArgument)
        if shouldReset { SimulatedCardStore.resetAll() }
        restoreSavedCards = !shouldReset
        // DEBUG-only: a wait on `PSO:CDS`, so the signing screen's "touch the YubiKey" prompt is on
        // screen long enough for a test to see it. Zero unless `-simulated-touch-delay-ms` is set.
        let touchDelay = SimulatedCardTransport.simulatedTouchDelay()
        #else
        restoreSavedCards = true
        #endif

        var result: [MockYubikeyTransport] = []
        for index in 0..<cardCount {
            let mock = MockYubikeyTransport(
                transportName: "Simulated YubiKey (demo)",
                serial: 0x00DE_71A5 + UInt32(index),
                openPGPVersion: "3.4"
            )
            #if DEBUG
            SimulatedCardTransport.applyDeterministicEntropy(to: mock)
            if let touchDelay { mock.touchDelay = touchDelay }
            #endif
            // The card the developer left in the reader. Restored here rather than in the
            // transport's `open()` because the mock is the shared, process-wide applet: every
            // fresh `SimulatedCardTransport` talks to this one instance.
            if restoreSavedCards, let state = SimulatedCardStore.load(index: index) {
                mock.persistentState = state
            }
            result.append(mock)
        }
        return result
    }()

    #if DEBUG
    /// DEBUG-only deterministic entropy for the UI tests: `GET CHALLENGE` returns these bytes
    /// instead of random data, so the ceremony produces a known mnemonic. A released build has no
    /// such path — its demo card's entropy is the mock's default challenge, XORed with the iOS
    /// CSPRNG by the ceremony, and no launch argument can reach in and fix it.
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
    #endif

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
            #if DEBUG
            applyDeterministicEntropy(to: mock)
            #endif
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

/// The simulated card's state, saved between launches.
///
/// A real YubiKey keeps its PINs, keys and stored objects when the phone is put down; the
/// simulated one would otherwise forget everything at process exit, so every relaunch meant
/// provisioning the fake wallet again. This keeps the durable applet state
/// (`MockYubikeyTransport.PersistentState`) in `UserDefaults`, under one namespaced key per
/// simulated card.
///
/// It is a persistence site in the *released* build too, now that the demo card ships
/// (amendment 51), and that is worth stating plainly: what it stores is the simulated applet's
/// own state — the demo wallet's keys among it — and nothing else. Those keys are not a real
/// wallet's and cannot sign anything a wallet would accept (see `SimulatedCardTransport`), which
/// is why this is not the secret-at-rest that check 3 of `tools/audit-release.sh` exists to
/// catch. Everything it stores belongs to the fake applet; a real key never reaches this file.
///
/// Deliberately not `@AppStorage`: the audit greps for persistence APIs by name, and a property
/// wrapper would hide this site from the check whose job is to notice it.
enum SimulatedCardStore {
    /// Namespaced, because `UserDefaults` is one shared dictionary per app. One key per card
    /// index, so a two-card run restores both cards in order.
    static let keyPrefix = "com.plexsec.vault.simulated-card"

    /// Clears the saved cards before the first screen. The UI tests pass it so a walk that
    /// provisions the simulated card does not change what the next test sees.
    ///
    /// DEBUG-only, and it has to be: a released build that could be told to wipe its own demo
    /// card by a launch argument would be carrying a test hook, which is the half of check 1 of
    /// `tools/audit-release.sh` that still has to fail. The *button* that resets the card is not
    /// gated this way — a reviewer can reset the demo card from the screen, which is the point.
    #if DEBUG
    static let resetLaunchArgument = "-reset-simulated-card"
    #endif

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
