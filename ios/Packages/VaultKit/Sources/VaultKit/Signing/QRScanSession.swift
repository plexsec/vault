import Foundation

/// The scanner's state, and what each lifecycle event does to it.
///
/// The rule this exists to encode: **`scanning` is a claim that the camera is on.** A
/// cancel has to withdraw that claim (`.idle` means "not running, a start may begin").
/// Leaving the claim standing is bug #1 in this file's history: the operator cancelled
/// while the camera was live, came back, and got no picture at all, because `start()` saw
/// `scanning`, concluded the camera must already be running, and quietly did nothing.
///
/// A second event has the same shape: the app going to the background stops the camera, so
/// returning to the foreground has to be able to start it again — which again means the
/// state must not still say `scanning`.
///
/// Pure, and tested on macOS, for the same reason `NFCSessionPolicy` is (YubikeyKit): a
/// camera is needed to *see* the failure, but the rule that was wrong does not need one,
/// and a rule that can only be checked by holding a phone is a rule that breaks again.
/// `QRScanModel` in the app is then a thin AVFoundation shell over this: it owns the
/// capture session, the fountain decoder and the counters, and asks this type what to do.
public struct QRScanSession: Equatable, Sendable {

    public enum State: Equatable, Sendable {
        /// Not running, and a start may begin.
        case idle
        /// The camera is running and no complete request has arrived.
        case scanning
        /// A complete request is in hand. Kept on screen until the operator leaves the flow:
        /// restarting over it would hide the thing they are about to act on.
        case received(UR)
        /// The camera could not be used, with the reason to show. Kept for the same reason —
        /// a refused permission must stay visible rather than be silently retried.
        case failed(String)
    }

    public private(set) var state: State = .idle

    public init() {}

    /// The operator asked for the camera. Returns whether it should actually be started:
    /// `false` when it is already running, or when a result or a failure is on screen,
    /// since starting over either would hide it.
    ///
    /// Claiming `scanning` here (rather than at the end) is deliberate: from this point the
    /// app has decided a camera is wanted, and every exit path — refusal, failure, cancel —
    /// has to say what happened to that decision.
    public mutating func begin() -> Bool {
        switch state {
        case .idle:
            state = .scanning
            return true
        case .scanning, .received, .failed:
            return false
        }
    }

    /// The camera is being stopped — a cancel, or the app leaving the foreground.
    ///
    /// Withdraws the `scanning` claim; a result or a failure stays on screen, because the
    /// operator still has to read it.
    public mutating func suspend() {
        if case .scanning = state { state = .idle }
    }

    /// Leaving the flow. Everything decoded so far goes with it: the next request is a
    /// different message with its own sequence numbers, and a request left over from the
    /// previous visit is not something to hand the ceremony.
    public mutating func reset() {
        state = .idle
    }

    /// A complete UR arrived. Called from the decoding path, which only runs while there is
    /// something to decode.
    public mutating func received(_ ur: UR) {
        state = .received(ur)
    }

    /// The camera cannot be used, with the reason to show the operator.
    public mutating func failed(_ reason: String) {
        state = .failed(reason)
    }
}
