import Foundation

/// How a transport should behave *between* CoreNFC reader sessions, and how a
/// failed session should be described.
///
/// This lives in the transport-agnostic target, not next to the CoreNFC code, for
/// two reasons:
///
/// 1. CoreNFC has no simulator, so anything inside `NFCTagTransport` can only be
///    checked on a device. The constants and the retry decision below are the
///    difference between a ceremony that completes and one that dies with an
///    opaque "Session invalidated unexpectedly", so they are pinned by tests that
///    run on macOS.
/// 2. A reader session that ends *unexpectedly* is a property of iOS, not of the
///    YubiKey. Keeping the classification here makes it obvious that the failure
///    is a transport race and not a card rejection.
public enum NFCSessionPolicy {

    /// How long to wait after a reader session is invalidated before beginning
    /// the next one.
    ///
    /// iOS fails a reader session that is begun while the previous session's
    /// sheet is still being dismissed, reporting `NFCReaderError` 202
    /// ("Session invalidated unexpectedly"). The card is not at fault and the
    /// previous session succeeded — the next one simply started too early. This
    /// matters here because the ceremony opens a **fresh session per card
    /// operation** (`TransportSessionCard`), and several steps perform two
    /// operations back to back with no operator interaction between them:
    /// `reset` → `inventory`, `applyPolicy` → `inventory`, and both keys' imports
    /// and read-backs.
    ///
    /// Yubico's own YubiKit hard-codes the same two seconds for the same reason
    /// (`YubiKit/YubiKit/Connection/SmartCard/NFCSmartCardConnection.swift`):
    ///
    /// > iOS fails a reader session begun while the previous session's sheet is
    /// > still being dismissed (NFCReaderError 202, "Session invalidated
    /// > unexpectedly"), so wait this long after an invalidation before
    /// > beginning a new session.
    ///
    /// `sessionCooldown: DispatchTimeInterval = .seconds(2)`
    public static let cooldown: TimeInterval = 2.0

    /// Attempts allowed when *beginning* a session, including the first. A
    /// transient 202/203 must not abort a step; a permanent condition (no NFC
    /// hardware, the operator never presents a key) still surfaces.
    public static let maximumBeginAttempts = 3

    /// How long `close()` waits for the system to confirm a session is gone
    /// before giving up. A delegate callback that never arrives must not wedge
    /// the ceremony; the confirmation only gates the next session's start, and
    /// the cooldown above still applies from the moment the invalidation was
    /// requested.
    public static let invalidationWaitTimeout: TimeInterval = 3.0

    /// How a reader session ended. Codes 200–203 are Apple's
    /// `NFCReaderError.Code.readerSessionInvalidationError*` cases, which
    /// describe *how the session ended* rather than what the card said. Anything
    /// else is deliberately left unclassified rather than guessed at.
    public enum SessionFailureKind: Sendable, Equatable {
        /// 200 — the operator dismissed the NFC sheet.
        case cancelledByOperator
        /// 201 — the session hit the system time limit before a tag was read.
        case timedOut
        /// 202 — the session was torn down, or a new one was begun before the
        /// previous one had been dismissed.
        case sessionEndedUnexpectedly
        /// 203 — only one reader session may run at a time.
        case systemBusy
        case other
    }

    public static func kind(forCode code: Int?) -> SessionFailureKind {
        switch code {
        case 200: return .cancelledByOperator
        case 201: return .timedOut
        case 202: return .sessionEndedUnexpectedly
        case 203: return .systemBusy
        default: return .other
        }
    }

    /// Whether beginning a session should be retried after the cooldown.
    ///
    /// Only the two races are retryable. Operator cancellation and the system
    /// timeout are *decisions*, not races: retrying them would paper over the
    /// operator's own action or an absent key, and design.md §5.2 rule 1 forbids
    /// blind retries.
    public static func isRetryableOnBegin(_ kind: SessionFailureKind) -> Bool {
        switch kind {
        case .sessionEndedUnexpectedly, .systemBusy: return true
        case .cancelledByOperator, .timedOut, .other: return false
        }
    }

    /// Seconds still to wait before beginning the next session, given when the
    /// last one was invalidated.
    ///
    /// `nil` means "no session has been invalidated in this transport yet".
    public static func cooldownRemaining(
        lastInvalidation: DispatchTime?,
        now: DispatchTime = .now()
    ) -> TimeInterval {
        guard let lastInvalidation else { return 0 }
        let then = lastInvalidation.uptimeNanoseconds
        let current = now.uptimeNanoseconds
        // A non-monotonic reading would otherwise underflow; treating it as "no
        // time has passed" is the conservative reading.
        guard current > then else { return cooldown }
        let elapsed = TimeInterval(current - then) / 1_000_000_000
        return max(0, cooldown - elapsed)
    }

    /// Operator-facing reason for a session that ended, used verbatim inside
    /// `CardError.transportUnavailable`.
    ///
    /// Each kind gets its own wording so the operator — and the log — can tell
    /// "the card refused" from "the session ended" from "you cancelled". The
    /// single string "Session invalidated unexpectedly" used to cover all of
    /// them, which made a transport race indistinguishable from a card problem.
    public static func message(for kind: SessionFailureKind, fallback: String) -> String {
        switch kind {
        case .cancelledByOperator:
            return "the NFC session was cancelled before the YubiKey was read"
        case .timedOut:
            return "the NFC session timed out; hold the iPhone against the YubiKey and try again"
        case .sessionEndedUnexpectedly:
            return "the NFC session ended unexpectedly, so this operation did not complete; hold the iPhone against the YubiKey and try again"
        case .systemBusy:
            return "iOS refused a new NFC session because the previous one had not finished shutting down; wait a moment and try again"
        case .other:
            return fallback
        }
    }

    /// As `message(for:fallback:)`, for an error whose CoreNFC code is known at
    /// the call site (`(error as? NFCReaderError)?.code.rawValue`). The code is
    /// passed in rather than sniffed from the `NSError` domain so this file needs
    /// no CoreNFC import.
    public static func describe(_ error: Error, code: Int? = nil) -> String {
        message(for: kind(forCode: code), fallback: error.localizedDescription)
    }
}
