import Foundation
import UIKit
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
/// way — and the `simulated` case is compiled into **two** kinds of build: DEBUG
/// builds, where it is what the tests and a developer drive a ceremony with, and the
/// App Store build, where it is the only way App Review can use an app whose real card
/// is a YubiKey they do not have (amendment 51). What a Release build still does not
/// carry is the *test hooks* that surround it — `-deterministic-entropy`,
/// `-simulated-cards`, `-simulated-touch-delay-ms`, `-reset-simulated-card` — and check 1
/// of `tools/audit-release.sh` asserts their absence from the shipped bundle.
public enum CardTransportChoice: String, CaseIterable, Identifiable {
    case nfc
    case usbC
    #if DEBUG || REVIEW_DEMO
    case simulated
    #endif

    public var id: String { rawValue }

    /// The connections **this device** can offer, in the order the screen lists them.
    ///
    /// NFC is the iPhone's reader; no iPad has one, so the row is removed there rather than
    /// left in place to fail when it is tapped. USB-C smart-card access works on both, and the
    /// simulated card is simulated wherever it runs. The check is the idiom and not
    /// `NFCTagReaderSession.readingAvailable`: that would also hide NFC on a simulator, where
    /// the UI tests choose it.
    @MainActor
    public static var available: [CardTransportChoice] {
        allCases.filter { choice in
            if choice == .nfc { return UIDevice.current.userInterfaceIdiom != .pad }
            return true
        }
    }

    public var title: String {
        switch self {
        case .nfc: return "NFC"
        case .usbC: return "USB-C"
        #if DEBUG || REVIEW_DEMO
        case .simulated: return "Simulated card (demo)"
        #endif
        }
    }

    public var detail: String {
        switch self {
        case .nfc:
            return "Hold the iPhone against the YubiKey when prompted. Every step asks for a fresh tap."
        case .usbC:
            return "Plug the YubiKey into the USB-C port and leave it in. Requires iPhone 15 or later. Disable the YubiKey's OTP interface first (ykman config usb --disable OTP) or the keyboard will not appear."
        #if DEBUG || REVIEW_DEMO
        case .simulated:
            return "No YubiKey needed: this card is simulated inside the app, so the whole flow can "
                + "be walked without hardware. Never use it for a wallet that matters — the keys are "
                + "not on a YubiKey, and what comes out of it is not a real signature."
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
        #if DEBUG || REVIEW_DEMO
        case .simulated: return "The simulated card needs no touch."
        #endif
        }
    }

    /// The headline for the wait while the card produces the signature.
    ///
    /// The wait is almost entirely the touch: with a touch policy on the signature slot the card
    /// computes nothing until the gold contact is touched, so a screen that only shows a spinner is
    /// asking the operator to guess. It is therefore an instruction, in the connection's own words.
    /// The simulated card is the one connection with nothing to touch, and it says so rather than
    /// asking for a touch that would never come.
    public var signingTouchPrompt: String {
        switch self {
        case .nfc, .usbC: return "Touch the YubiKey now"
        #if DEBUG || REVIEW_DEMO
        case .simulated: return "Waiting for the simulated card"
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
        #if DEBUG || REVIEW_DEMO
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
