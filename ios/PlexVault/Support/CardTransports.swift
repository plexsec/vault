import Foundation
import VaultKit
import YubikeyKit
#if canImport(CoreNFC)
import YubikeyKitNFC
#endif
#if canImport(CryptoTokenKit)
import YubikeyKitCCID
#endif

/// Where the card can be reached from.
///
/// Shared by both flows — provisioning and signing reach the same card the same
/// way — and the `simulated` case exists **only** in DEBUG builds: a release
/// binary has no code path that can reach a simulated card, which
/// `tools/audit-release.sh` verifies against the built product.
public enum CardTransportChoice: String, CaseIterable, Identifiable {
    case nfc
    case usbC
    #if DEBUG
    case simulated
    #endif

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .nfc: return "NFC"
        case .usbC: return "USB-C"
        #if DEBUG
        case .simulated: return "Simulated (debug)"
        #endif
        }
    }

    public var detail: String {
        switch self {
        case .nfc:
            return "Hold the iPhone against the YubiKey when prompted. Every step asks for a fresh tap."
        case .usbC:
            return "Plug the YubiKey into the USB-C port and leave it in. Requires iPhone 15 or later. Disable the YubiKey's OTP interface first (ykman config usb --disable OTP) or the keyboard will not appear."
        #if DEBUG
        case .simulated:
            return "No YubiKey required. Runs against a simulated card; never use this for a real key."
        #endif
        }
    }

    /// How a signature is completed on this transport, for the screen that asks
    /// the operator to do it. The touch warning is not decoration: design.md §5.2
    /// rule 2 says a second touch for the same transaction means stop.
    public var signingPrompt: String {
        switch self {
        case .nfc: return "Hold the iPhone against the YubiKey, then touch the gold contact."
        case .usbC: return "Touch the gold contact on the YubiKey."
        #if DEBUG
        case .simulated: return "The simulated card needs no touch."
        #endif
        }
    }
}

enum CardTransports {
    static func make(_ choice: CardTransportChoice) -> YubikeyTransport {
        switch choice {
        case .nfc:
            #if canImport(CoreNFC)
            return NFCTagTransport()
            #else
            return UnavailableTransport(reason: "NFC is unavailable in this build.")
            #endif
        case .usbC:
            #if canImport(CryptoTokenKit)
            return SmartCardTransport()
            #else
            return UnavailableTransport(reason: "USB-C smart-card access is unavailable in this build.")
            #endif
        #if DEBUG
        case .simulated:
            return SimulatedCardTransport()
        #endif
        }
    }

    /// A card that opens a fresh session per operation, which is what both
    /// ceremonies need: an NFC session lasts about a minute and VERIFY state does
    /// not survive one.
    static func makeSessionCard(
        _ choice: CardTransportChoice,
        onSessionStart: (@Sendable (String) -> Void)? = nil,
        onSessionEnd: (@Sendable () -> Void)? = nil
    ) -> TransportSessionCard {
        TransportSessionCard(
            makeTransport: { make(choice) },
            onSessionStart: onSessionStart,
            onSessionEnd: onSessionEnd
        )
    }
}

/// Placeholder used when a transport is compiled out or unavailable, so the
/// failure is an explicit typed error rather than a crash.
public final class UnavailableTransport: YubikeyTransport {
    public let transportName = "unavailable"
    private let reason: String

    public init(reason: String) {
        self.reason = reason
    }

    public func open() async throws { throw CardError.transportUnavailable(reason) }
    public func send(_ command: CommandAPDU) async throws -> ResponseAPDU {
        throw CardError.transportUnavailable(reason)
    }
    public func close() async {}
}
