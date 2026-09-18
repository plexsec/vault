import SwiftUI

/// Numeric secret entry. Deliberately not a `TextField`: no paste, no autofill,
/// no password-manager or keyboard suggestion, and no autocorrection history.
/// This matters for PINs and, above all, for mnemonic words.
struct SecretEntryField: View {
    let title: String
    let prompt: String
    @Binding var text: String
    var isNumeric = false
    var length: Int?

    @State private var revealed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title).font(.subheadline.weight(.medium))
                Spacer()
                Button(revealed ? "Hide" : "Show") { revealed.toggle() }
                    .font(.caption)
                    .buttonStyle(.plain)
                    .foregroundStyle(.tint)
            }

            HStack(spacing: 8) {
                Group {
                    if revealed {
                        TextField(prompt, text: $text)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    } else {
                        SecureField(prompt, text: $text)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .keyboardType(isNumeric ? .numberPad : .asciiCapable)
                .textContentType(.oneTimeCode)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

                if let length {
                    Text("\(text.count)/\(length)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(text.count == length ? .green : .secondary)
                }
            }
        }
    }
}

/// Hold-to-reveal for the mnemonic. The words stay covered unless the operator
/// is actively pressing, and are hidden entirely while the screen is captured.
struct HoldToReveal<Content: View>: View {
    let isCaptured: Bool
    @ViewBuilder let content: () -> Content

    @State private var pressing = false

    var body: some View {
        ZStack {
            content()
                .opacity(pressing && !isCaptured ? 1 : 0)

            if isCaptured {
                VStack(spacing: 8) {
                    Image(systemName: "eye.slash.fill").font(.largeTitle)
                    Text("Screen recording detected. The mnemonic stays hidden.")
                        .multilineTextAlignment(.center)
                }
                .padding()
                .foregroundStyle(.secondary)
            } else if !pressing {
                VStack(spacing: 8) {
                    Image(systemName: "hand.tap.fill").font(.largeTitle)
                    Text("Press and hold to reveal the 24 words")
                        .multilineTextAlignment(.center)
                }
                .padding()
                .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .contentShape(Rectangle())
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in pressing = true }
                .onEnded { _ in pressing = false }
        )
    }
}
