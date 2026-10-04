import Foundation
import SwiftUI
#if canImport(CryptoTokenKit)
import YubikeyKitCCID
#endif

/// Whether the card is physically there, for the one connection the app can tell.
///
/// Only USB-C has a presence signal: the reader either reports a card in its slot or it
/// does not. NFC cannot be sensed passively — the phone's field is only on during a
/// session, so there is nothing to ask between them — and the simulated card always
/// exists. `presence` is therefore `nil` for those two, which means "no signal" rather
/// than "absent": the icon then stays neutral instead of claiming something it cannot
/// know.
@MainActor
@Observable
final class CardPresence {
    /// `nil` until the first answer arrives, and for a connection with no presence signal
    /// at all (see above).
    private(set) var presence: Bool?

    /// Watches the chosen connection until the task is cancelled.
    ///
    /// Structured on purpose — driven from `.task(id:)`, so changing the connection or
    /// leaving the screen cancels it. Nothing here opens a card session: `isCardPresent`
    /// only reads the slot's state, so it cannot collide with an operation the operator
    /// starts on the next screen.
    func watch(_ choice: CardTransportChoice) async {
        presence = nil
        guard choice == .usbC else { return }
        while !Task.isCancelled {
            let present = await Self.isCardPresent()
            guard !Task.isCancelled else { return }
            presence = present
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private static func isCardPresent() async -> Bool {
        #if canImport(CryptoTokenKit)
        return await SmartCardTransport.isCardPresent()
        #else
        // No CryptoTokenKit in this build means no USB-C reader to ask.
        return false
        #endif
    }
}
