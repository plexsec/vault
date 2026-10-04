import SwiftUI

/// The YubiKey, drawn rather than borrowed from SF Symbols — there is no YubiKey symbol,
/// and what the operator needs at a glance is *which key, over which connection*: the body
/// is the key (a rounded rectangle with its touch button on it), the badge in the corner is
/// the connection, and the colour answers "is it there?".
///
/// The colour is the reason the badge is on the button at all. On USB-C the reader reports
/// whether a card is in its slot, so the icon goes green when the YubiKey is plugged in and
/// grey when it is not. NFC cannot be sensed passively — the phone's field is only on during
/// a session — so it keeps the normal tint instead of pretending to know.
struct YubiKeyGlyph: View {
    let choice: CardTransportChoice
    /// `true`/`false` when the app can tell, `nil` when the connection has no presence
    /// signal at all (`CardPresence`).
    let isPresent: Bool?

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            key
            badge
        }
        .frame(width: 26, height: 26)
        // The button carries the description: one element, one label.
        .accessibilityHidden(true)
    }

    private var key: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 4, style: .continuous)
                .strokeBorder(tint, lineWidth: 1.6)
                .frame(width: 15, height: 22)
            Circle()
                .fill(tint)
                .frame(width: 5, height: 5)
                .offset(y: -2)
        }
    }

    private var badge: some View {
        Image(systemName: choice.glyphBadge)
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(tint)
            .padding(2)
            .background(Circle().fill(.background))
    }

    private var tint: Color {
        switch isPresent {
        case .some(true): return .green
        case .some(false): return .secondary
        case .none: return .accentColor
        }
    }
}

extension CardTransportChoice {
    /// What sits in the corner of the glyph: the connection, not the key.
    var glyphBadge: String {
        switch self {
        case .nfc: return "dot.radiowaves.left.and.right"
        case .usbC: return "cable.connector"
        #if DEBUG
        case .simulated: return "ladybug"
        #endif
        }
    }

    /// The home screen's button description: what the app will use, and what the app can
    /// tell about it.
    ///
    /// Composed here rather than in the view because it is the button's accessible name
    /// *and* what the UI tests assert — the presence clause is the only observable part of
    /// the icon's colour.
    func connectionLabel(isPresent: Bool?) -> String {
        switch (self, isPresent) {
        case (.usbC, .some(true)): return "Card connection: USB-C, YubiKey inserted"
        case (.usbC, .some(false)): return "Card connection: USB-C, no YubiKey detected"
        default: return "Card connection: \(title)"
        }
    }
}
