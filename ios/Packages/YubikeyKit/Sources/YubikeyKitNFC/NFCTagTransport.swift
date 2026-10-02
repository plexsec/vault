// CoreNFC exists only on iOS/iPadOS. The whole file is guarded so the package
// still builds and tests on macOS, where the ceremony and APDU layer are tested.
#if canImport(CoreNFC)

import CoreNFC
import Foundation
import VaultKit
import YubikeyKit

/// NFC transport: CoreNFC ISO 7816 tag sessions against the OpenPGP AID.
///
/// Constraints this type exists to handle:
/// * CoreNFC has no simulator, so this file is only ever exercised on a device.
/// * The reader session has a hard system timeout (~60 s). It is NOT retried
///   automatically *once an operation has been sent*: design.md §5.2 rule 1
///   forbids blind retries, and the ceremony decides whether a retry is safe
///   after re-inspecting the card.
/// * iOS fails a session begun while the previous session's sheet is still being
///   dismissed (`NFCReaderError` 202). The ceremony opens one session per card
///   operation and several steps perform two operations back to back, so the
///   transport waits for a session to be confirmed gone and then holds a
///   cooldown before beginning the next one. The constants and the retry
///   decision live in `NFCSessionPolicy`, which is unit-tested on macOS.
/// * `select-identifiers` in Info.plist must declare the OpenPGP AID, otherwise
///   iOS will not surface the tag to the session.
@available(iOS 26.0, *)
public final class NFCTagTransport: NSObject, YubikeyTransport {
    public let transportName = "NFC"

    private var session: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var openContinuation: CheckedContinuation<Void, Error>?
    /// Callers waiting for "the current reader session is fully gone".
    private var invalidationWaiters: [CheckedContinuation<Void, Never>] = []
    /// Guards the continuation bookkeeping above. Delegate callbacks arrive on the
    /// session's own queue while `open()`/`close()` run on the caller's, and
    /// resuming a continuation twice traps — so the handoff is serialised.
    private let continuationLock = NSLock()
    /// When the last reader session was invalidated. Gates the next `begin()`:
    /// see `NFCSessionPolicy.cooldown`.
    private var lastInvalidation: DispatchTime?
    private let alertMessage: String

    public init(alertMessage: String = "Hold the top of the iPhone against the YubiKey") {
        self.alertMessage = alertMessage
        super.init()
    }

    public func open() async throws {
        guard NFCTagReaderSession.readingAvailable else {
            throw CardError.transportUnavailable("NFC is not available on this device")
        }
        var attempt = 0
        while true {
            attempt += 1
            await waitForCooldown()
            do {
                try await beginSession()
                return
            } catch let failure as NFCSessionBeginFailure {
                let kind = NFCSessionPolicy.kind(forCode: failure.code)
                let lastAttempt = attempt >= NFCSessionPolicy.maximumBeginAttempts
                guard !lastAttempt, NFCSessionPolicy.isRetryableOnBegin(kind) else {
                    throw CardError.transportUnavailable(
                        NFCSessionPolicy.message(for: kind, fallback: failure.description)
                    )
                }
                // A 202/203 here means iOS refused *this* session's start, not
                // that the card or the previous operation failed. Wait out the
                // cooldown and try again.
            }
        }
    }

    /// The uninterruptible part of `open()`: arm the continuation, create the
    /// session, begin it. Failures are a `NFCSessionBeginFailure` carrying the
    /// CoreNFC code so `open()` can decide whether to retry.
    private func beginSession() async throws {
        try await withCheckedThrowingContinuation { continuation in
            setOpenContinuation(continuation)
            guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil) else {
                setOpenContinuation(nil)
                continuation.resume(throwing: CardError.transportUnavailable("could not create an NFC reader session"))
                return
            }
            session.alertMessage = self.alertMessage
            self.session = session
            session.begin()
        }
    }

    /// Holds `NFCSessionPolicy.cooldown` after the previous session was
    /// invalidated, so the next `begin()` cannot race its dismissal.
    private func waitForCooldown() async {
        let remaining = NFCSessionPolicy.cooldownRemaining(lastInvalidation: lastInvalidation)
        guard remaining > 0 else { return }
        try? await Task.sleep(for: .seconds(remaining))
    }

    public func send(_ command: CommandAPDU) async throws -> ResponseAPDU {
        guard let tag else { throw CardError.transportUnavailable("no NFC tag in session") }
        // Use the structured initializer, not the raw-bytes `data:` form: the raw
        // form's parsing of a trailing Le byte (especially Le = 0x00) is
        // ambiguous and was reported as 6581 (card memory failure) on real
        // hardware. Map the ISO 7816 Le field explicitly: -1 = no Le,
        // 256 = Le 0x00 (maximum length).
        let apdu = NFCISO7816APDU(
            instructionClass: command.cla,
            instructionCode: command.ins,
            p1Parameter: command.p1,
            p2Parameter: command.p2,
            data: Data(command.data),
            expectedResponseLength: command.expectedLength.map { $0 == 0 ? 256 : $0 } ?? -1
        )
        return try await withCheckedThrowingContinuation { continuation in
            tag.sendCommand(apdu: apdu) { data, sw1, sw2, error in
                if let error {
                    continuation.resume(throwing: CardError.transportUnavailable(
                        NFCSessionPolicy.describe(error, code: Self.readerErrorCode(error))
                    ))
                    return
                }
                // `data` is non-optional in the current CoreNFC signature.
                continuation.resume(returning: ResponseAPDU(
                    data: [UInt8](data),
                    status: StatusWord(sw1: sw1, sw2: sw2)
                ))
            }
        }
    }

    /// Ends the session, waiting for iOS to confirm it is gone.
    ///
    /// The wait is what makes the *next* `open()` reliable: invalidating and
    /// returning immediately is exactly the race that produces `NFCReaderError`
    /// 202 on the following session. Bounded by
    /// `NFCSessionPolicy.invalidationWaitTimeout` so a missing delegate callback
    /// cannot wedge the ceremony.
    public func close() async {
        guard let session else { return }
        self.session = nil
        tag = nil
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            addInvalidationWaiter(continuation)
            session.invalidate()
            scheduleInvalidationTimeout()
        }
    }

    /// Ends the session with the user-visible success message and a green tick.
    public func finish(message: String) {
        guard let session else { return }
        session.alertMessage = message
        self.session = nil
        tag = nil
        session.invalidate()
    }

    // MARK: Invalidation bookkeeping

    private func setOpenContinuation(_ continuation: CheckedContinuation<Void, Error>?) {
        continuationLock.lock()
        defer { continuationLock.unlock() }
        openContinuation = continuation
    }

    private func takeOpenContinuation() -> CheckedContinuation<Void, Error>? {
        continuationLock.lock()
        defer { continuationLock.unlock() }
        let continuation = openContinuation
        openContinuation = nil
        return continuation
    }

    private func addInvalidationWaiter(_ continuation: CheckedContinuation<Void, Never>) {
        continuationLock.lock()
        defer { continuationLock.unlock() }
        invalidationWaiters.append(continuation)
    }

    /// Releases everyone waiting on `close()`. Called from
    /// `didInvalidateWithError` and from the timeout; draining the array under the
    /// lock makes it resume-once whatever the order.
    private func resumeInvalidationWaiters() {
        continuationLock.lock()
        let waiters = invalidationWaiters
        invalidationWaiters = []
        continuationLock.unlock()
        for waiter in waiters { waiter.resume() }
    }

    /// Best-effort backstop so a delegate callback that never arrives cannot hang
    /// `close()` forever. It only releases waiters; it does not touch the session
    /// or the card.
    private func scheduleInvalidationTimeout() {
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(NFCSessionPolicy.invalidationWaitTimeout))
            self?.resumeInvalidationWaiters()
        }
    }

    private static func readerErrorCode(_ error: Error) -> Int? {
        (error as? NFCReaderError)?.code.rawValue
    }

    /// A session that ended before a tag was connected. Carries the CoreNFC code
    /// so the retry decision is made from the actual reason rather than from
    /// matching on a localized string.
    private struct NFCSessionBeginFailure: Error {
        let code: Int?
        let description: String
    }
}

@available(iOS 26.0, *)
extension NFCTagTransport: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        lastInvalidation = .now()
        tag = nil
        self.session = nil
        if let continuation = takeOpenContinuation() {
            // We were still waiting for a tap: this is a *begin* failure, and
            // `open()` decides whether it is worth retrying.
            continuation.resume(throwing: NFCSessionBeginFailure(
                code: Self.readerErrorCode(error),
                description: NFCSessionPolicy.describe(error, code: Self.readerErrorCode(error))
            ))
        }
        resumeInvalidationWaiters()
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first else { return }
        guard case .iso7816(let iso7816Tag) = first else {
            session.invalidate(errorMessage: "Unsupported tag type; expected an ISO 7816 smart card.")
            return
        }
        session.connect(to: first) { [weak self] error in
            guard let self else { return }
            if let error {
                session.invalidate(errorMessage: error.localizedDescription)
                return
            }
            // The session can have ended while the connection was in flight; a
            // stale tag would only fail later, in `send`.
            guard self.session === session else { return }
            self.tag = iso7816Tag
            self.takeOpenContinuation()?.resume(returning: ())
        }
    }
}

#endif
