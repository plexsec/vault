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
///   automatically: design.md §5.2 rule 1 forbids blind retries, and the ceremony
///   decides whether a retry is safe after re-inspecting the card.
/// * `select-identifiers` in Info.plist must declare the OpenPGP AID, otherwise
///   iOS will not surface the tag to the session.
@available(iOS 26.0, *)
public final class NFCTagTransport: NSObject, YubikeyTransport {
    public let transportName = "NFC"

    private var session: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var openContinuation: CheckedContinuation<Void, Error>?
    private let alertMessage: String

    public init(alertMessage: String = "Hold the top of the iPhone against the YubiKey") {
        self.alertMessage = alertMessage
        super.init()
    }

    public func open() async throws {
        guard NFCTagReaderSession.readingAvailable else {
            throw CardError.transportUnavailable("NFC is not available on this device")
        }
        try await withCheckedThrowingContinuation { continuation in
            self.openContinuation = continuation
            guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil) else {
                self.openContinuation = nil
                continuation.resume(throwing: CardError.transportUnavailable("could not create an NFC reader session"))
                return
            }
            session.alertMessage = self.alertMessage
            self.session = session
            session.begin()
        }
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
                    continuation.resume(throwing: CardError.transportUnavailable(error.localizedDescription))
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

    public func close() async {
        session?.invalidate()
        session = nil
        tag = nil
        openContinuation = nil
    }

    /// Ends the session with the user-visible success message and a green tick.
    public func finish(message: String) {
        session?.alertMessage = message
        session?.invalidate()
        session = nil
        tag = nil
    }
}

@available(iOS 26.0, *)
extension NFCTagTransport: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        tag = nil
        let continuation = openContinuation
        openContinuation = nil
        self.session = nil
        continuation?.resume(throwing: CardError.transportUnavailable(error.localizedDescription))
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
            self.tag = iso7816Tag
            let continuation = self.openContinuation
            self.openContinuation = nil
            continuation?.resume(returning: ())
        }
    }
}

#endif
