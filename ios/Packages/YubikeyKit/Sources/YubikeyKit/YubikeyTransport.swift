import Foundation
import VaultKit

/// A byte-level channel to a YubiKey's OpenPGP applet.
///
/// Implemented by the CoreNFC transport, the CryptoTokenKit USB-C transport and
/// (for tests and DEBUG UI work) a scripted transport. Everything above this
/// protocol is transport-agnostic: the ceremony produces identical APDU traces
/// over NFC and USB-C, which `TransportParityTests` asserts.
public protocol YubikeyTransport: AnyObject {
    /// Human-readable description recorded in the ceremony report.
    var transportName: String { get }

    /// Prepares the transport. For NFC this starts a reader session and waits for
    /// the user to tap the key; for USB-C it selects and opens the smart-card slot.
    func open() async throws

    /// Sends one command APDU and returns the response, including any `61xx`
    /// GET RESPONSE round trips and `6Cxx` Le corrections.
    func send(_ command: CommandAPDU) async throws -> ResponseAPDU

    /// Ends the session. Must be safe to call more than once.
    func close() async
}

public extension YubikeyTransport {
    /// ISO 7816-4 response chaining, shared by every transport so the behaviour
    /// cannot diverge between NFC and USB-C.
    ///
    /// * `61 xx`: `xx` further bytes are available -> GET RESPONSE.
    /// * `6C xx`: wrong Le -> re-issue the same APDU with `Le = xx`.
    func exchange(_ command: CommandAPDU) async throws -> ResponseAPDU {
        var response = try await send(command)

        if let correctLe = response.status.correctLe {
            let retried = CommandAPDU(
                cla: command.cla,
                ins: command.ins,
                p1: command.p1,
                p2: command.p2,
                data: command.data,
                expectedLength: correctLe
            )
            response = try await send(retried)
        }

        var accumulated = response.data
        var guardCounter = 0
        while let remaining = response.status.remainingResponseBytes {
            guardCounter += 1
            guard guardCounter <= 32 else { throw CardError.malformedResponse("response chaining did not terminate") }
            let getResponse = CommandAPDU(cla: 0x00, ins: 0xC0, p1: 0x00, p2: 0x00, expectedLength: remaining)
            let next = try await send(getResponse)
            accumulated.append(contentsOf: next.data)
            response = ResponseAPDU(data: accumulated, status: next.status)
        }
        return ResponseAPDU(data: accumulated, status: response.status)
    }
}

/// Maps OpenPGP status words onto typed errors (design.md §6.5).
public enum OpenPGPStatusMapper {
    public static func error(
        for status: StatusWord,
        context: OpenPGPOperation,
        precedingError: CardError? = nil
    ) -> CardError? {
        if status.isSuccess { return nil }

        switch (status.sw1, status.sw2) {
        case (0x63, let sw2) where (sw2 & 0xF0) == 0xC0:
            return .pinIncorrect(retriesRemaining: Int(sw2 & 0x0F))
        case (0x69, 0x83):
            // Authentication method blocked.
            switch context {
            case .verifyAdminPIN, .changeAdminPIN, .terminate: return .adminPinBlocked
            default: return .pinBlocked
            }
        case (0x69, 0x82):
            // Security status not satisfied: the applet wants a PIN it has not
            // been given. For a signature that means PW1 was not verified.
            switch context {
            case .computeSignature: return .userPinNotVerified
            default: return .conditionsNotSatisfied
            }
        case (0x69, 0x85):
            // Conditions of use not satisfied. On a YubiKey with a touch policy
            // this is what an unfinished touch looks like, but the exact status
            // word for an unanswered touch is an M0 item
            // (docs/m0-hardware-verification.md): the app reports it as a
            // conditions failure and does not retry either way.
            switch context {
            case .computeSignature: return .touchNotCompleted
            default: return .conditionsNotSatisfied
            }
        case (0x64, 0x00), (0x66, 0x00):
            // Execution error / no information: the card began the operation and
            // did not finish it. The counter may already have moved.
            switch context {
            case .computeSignature: return .touchNotCompleted
            default: return .unexpectedStatusWord(sw1: status.sw1, sw2: status.sw2)
            }
        case (0x6A, 0x80):
            switch context {
            case .importKey: return .keyImportRejected
            case .setAlgorithmAttributes: return .unsupportedFirmware
            default: return .unexpectedStatusWord(sw1: status.sw1, sw2: status.sw2)
            }
        case (0x6A, 0x88):
            // Referenced data not found: used to detect "no key in this slot".
            return .unexpectedStatusWord(sw1: status.sw1, sw2: status.sw2)
        case (0x6D, 0x00):
            return .unsupportedFeature("instruction not supported")
        default:
            _ = precedingError
            return .unexpectedStatusWord(sw1: status.sw1, sw2: status.sw2)
        }
    }
}

/// Which operation produced a status word; some status words are only
/// interpretable in context (e.g. `6983` means PW1 blocked or PW3 blocked).
public enum OpenPGPOperation: String, Sendable {
    case select
    case readApplicationData
    case verifyUserPIN
    case verifyAdminPIN
    case changeUserPIN
    case changeAdminPIN
    case terminate
    case activate
    case applyPolicy
    /// `SET PIN RETRIES` (INS `0xF2`): how many wrong PIN attempts each password
    /// tolerates before it is blocked. Firmware ≥ 4.3.1; on YubiKey 4/5 the PINs
    /// themselves are left alone, unlike the old NEO applet, which reset them.
    case setPinRetries
    case setAlgorithmAttributes
    case importKey
    case readPublicKey
    case getChallenge
    /// Reading the private-use data object that holds the pairing manifest. Read
    /// access on that object requires no PIN, which is what makes a re-pair
    /// possible on a card nobody has a PIN for.
    case readPairingManifest
    /// Writing it. Requires PW3, which the ceremony has already verified.
    case writePairingManifest
    /// `PSO:CDS` — the one operation that consumes a touch and must never be
    /// attempted twice for one request (design.md §5.2 rule 1).
    case computeSignature
}
