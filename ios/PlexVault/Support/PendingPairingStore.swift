import Foundation
import SwiftUI

/// The second thing this app remembers between launches: that a provisioning run stopped
/// between the wipe and the pairing codes, and that the next launch starts in the pairing
/// process rather than on the home screen.
///
/// One `Bool` under one namespaced key. **No pairing material is stored**, and neither is the
/// record of the run that just finished: the codes are rebuilt from the card's own manifest by
/// the read-only pairing route — which is what that object exists for — and the two processes
/// produce their own records (amendment 43). `tools/audit-release.sh` asserts all of that: this
/// file is one of exactly two named persistence sites, it holds one key and nothing else, and it
/// must not mention the words, key material or a pairing export.
///
/// The value survives a process exit, which is the point: the wipe closes the app (the operator
/// asked for it, and the ceremony's in-memory state dies with the process), so "pair the wallet"
/// has to be reachable without it. Being wrong about this value is bounded either way — it can
/// only send the operator to a read-only screen they can leave, and a stale `true` costs one
/// dismissed flow, not a decision about keys.
///
/// Deliberately *not* `@AppStorage`, for the same reason as `DeviceChoiceStore`: the audit greps
/// for persistence APIs by name, and a property wrapper would hide this exception from the check
/// whose job is to notice it.
@MainActor
@Observable
final class PendingPairingStore {
    /// Namespaced, because `UserDefaults` is one shared dictionary per app. The value is a
    /// `Bool`.
    static let defaultsKey = "com.plexsec.vault.pending-pairing"

    private let defaults: UserDefaults

    /// True from the wipe until the pairing step has been completed (or the operator left the
    /// pairing process deliberately).
    private(set) var isPending: Bool

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.isPending = defaults.bool(forKey: Self.defaultsKey)
        #if DEBUG
        applyLaunchArguments()
        #endif
    }

    /// Set at the wipe, immediately before the app closes itself.
    ///
    /// `synchronize()` is the one thing in this file that is not merely a `set`: the process is
    /// about to be terminated by `exit(0)`, which does not run the app lifecycle, and a flag that
    /// is lost there would drop the operator on the home screen with no pairing flow and no
    /// explanation. It is called for the exit path only, not for ordinary `set`s.
    func markPending() {
        isPending = true
        defaults.set(true, forKey: Self.defaultsKey)
        _ = defaults.synchronize()
    }

    /// Cleared when the pairing process completes the pairing step, and when the operator leaves
    /// that process deliberately (so a card that cannot be re-paired does not drag them back in
    /// on every launch).
    func clear() {
        isPending = false
        defaults.removeObject(forKey: Self.defaultsKey)
        _ = defaults.synchronize()
    }

    #if DEBUG
    /// UI-test and developer hooks, in the same spirit as `-reset-device-choice`.
    ///
    /// * `-reset-pending-pairing` clears the value before the first screen. The flag is set by a
    ///   *real* wipe and survives the process, so a test that walked a ceremony to the wipe would
    ///   otherwise leave every later test launching into the pairing process instead of the home
    ///   screen.
    /// * `-pending-pairing` sets it, which is how the post-exit launch is reached by hand (to look
    ///   at that screen in a simulator) without driving a whole run to the wipe. The automated
    ///   route is the real one: the exit test taps through the alert and relaunches.
    private func applyLaunchArguments() {
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("-reset-pending-pairing") {
            clear()
            return
        }
        if arguments.contains("-pending-pairing") {
            markPending()
        }
    }
    #endif
}
