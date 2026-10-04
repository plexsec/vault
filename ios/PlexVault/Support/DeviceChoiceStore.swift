import Foundation
import SwiftUI

/// The one thing this app remembers between launches: which connection the card is
/// reached through.
///
/// **This is the only persistence site in the product.** Everything else the app
/// handles is either secret (the mnemonic, the PINs), re-derivable (the card's keys,
/// the pairing manifest) or deliberately forgotten between sessions (the confirmed
/// chain ids), and `tools/audit-release.sh` fails the build if any other persistence
/// API appears in the app or the ceremony layer. What is stored here is one of
/// `CardTransportChoice`'s raw values under one namespaced key, so the state can be
/// read, and cleared, by hand.
///
/// Deliberately *not* `@AppStorage`: the audit greps for persistence APIs by name, and
/// a property wrapper would hide this one exception from the check whose job is to
/// notice it.
///
/// A tampered value cannot weaken anything, which is what makes the exception
/// acceptable at all. The choice selects a *channel*, not a policy: check 1 of the
/// audit asserts that a release build contains no simulated transport to be redirected
/// to, and both real values reach the same card through the same gates. The worst a
/// wrong value does is send the operator to the wrong reader, which shows up as a card
/// that cannot be found — visible at once, and fixed on the screen it came from.
@MainActor
@Observable
final class DeviceChoiceStore {
    /// Namespaced, because `UserDefaults` is one shared dictionary per app. The value
    /// is a `CardTransportChoice` raw value.
    static let defaultsKey = "com.plexsec.vault.device-choice"

    private let defaults: UserDefaults

    /// The stored choice, or `nil` when there is none.
    ///
    /// `nil` is a real state — a fresh install — and is not the same as "NFC". The
    /// connection is the one thing the app cannot detect for itself, so it asks rather
    /// than assuming. A stored value this build does not know (a release build reading
    /// `"simulated"`, say) is treated as no choice as well, so the operator is asked
    /// again instead of being handed a default silently.
    private(set) var storedChoice: CardTransportChoice?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.storedChoice = defaults
            .string(forKey: Self.defaultsKey)
            .flatMap(CardTransportChoice.init(rawValue:))
        #if DEBUG
        applyLaunchArguments()
        #endif
    }

    /// True once the operator has chosen. This is what closes the device screen on first
    /// launch, and what stops the flows being opened with nothing but the fallback.
    var hasChosen: Bool { storedChoice != nil }

    /// What the flows use. Falls back to NFC so that a transport always exists; the
    /// device screen is what stands between that fallback and a ceremony, because
    /// nothing opens a flow until `hasChosen`.
    var choice: CardTransportChoice { storedChoice ?? .nfc }

    /// Records the choice. Called by the device screen as soon as a row is picked, so
    /// there is no separate save step to forget.
    func choose(_ choice: CardTransportChoice) {
        storedChoice = choice
        defaults.set(choice.rawValue, forKey: Self.defaultsKey)
    }

    /// Forgets the choice, so the app asks again. Not reachable from the UI: it exists
    /// for the UI tests (`-reset-device-choice`) and for a future "reset this app".
    func forget() {
        storedChoice = nil
        defaults.removeObject(forKey: Self.defaultsKey)
    }

    #if DEBUG
    /// UI-test hooks, in the same spirit as `-deterministic-entropy`: DEBUG-only, so a
    /// release build can neither be seeded nor have its stored choice cleared by an
    /// argument.
    ///
    /// * `-reset-device-choice` forgets the stored value, so the app starts as a first
    ///   run and the device screen has to be answered.
    /// * `-device-choice <rawValue>` stores a choice before the first screen, so a test
    ///   that is about something else does not have to walk this one first. An
    ///   unrecognised value is ignored rather than stored, which keeps the "unknown
    ///   value means ask again" rule true for the hook too.
    private func applyLaunchArguments() {
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("-reset-device-choice") {
            forget()
            return
        }
        if let index = arguments.firstIndex(of: "-device-choice"),
           index + 1 < arguments.count,
           let choice = CardTransportChoice(rawValue: arguments[index + 1]) {
            choose(choice)
        }
    }
    #endif
}
