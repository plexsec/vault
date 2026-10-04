import SwiftUI

/// The device choice: how this iPhone reaches the YubiKey, asked once.
///
/// The choice lives here rather than on each flow's setup screen because it is the one
/// setting that belongs to the *phone*, not to a ceremony. Both flows reach the same
/// card the same way, so a picker in each of them was two places to get it wrong — and
/// a transport switched in the middle of a ceremony is how a step ends up talking to a
/// card the operator is not holding.
///
/// The screen appears on first launch, before the home screen will open anything, and
/// from the home screen's "Change" button afterwards.
struct DeviceChoiceView: View {
    let device: DeviceChoiceStore
    /// True when this screen is the way into the app, so the action cannot be used
    /// until something has been chosen. False when it was opened from the home screen to
    /// change the choice, where leaving without changing anything is legitimate.
    let isFirstRun: Bool
    let onDone: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header
                    choices
                    storageNote
                }
                .padding()
            }
            .navigationTitle("Card connection")
            .navigationBarTitleDisplayMode(.inline)
            .safeAreaInset(edge: .bottom) { actionBar }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("How is your YubiKey connected?")
                .font(.title3.weight(.semibold))
            Text(
                isFirstRun
                    ? "Asked once, then remembered. Both real connections reach the same card with the same "
                        + "checks — this is the one thing the app cannot work out for itself."
                    : "This takes effect the next time a card session opens. Change it whenever the YubiKey "
                        + "moves to a different reader."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    private var choices: some View {
        VStack(spacing: 10) {
            ForEach(CardTransportChoice.allCases) { choice in
                ChoiceRow(
                    title: choice.title,
                    detail: choice.detail,
                    isSelected: device.storedChoice == choice,
                    identifier: "device-choice-\(choice.title)"
                ) {
                    // Stored on the tap rather than on "Done": the row *is* the choice,
                    // so there is no second step that could disagree with the first.
                    device.choose(choice)
                }
            }
        }
    }

    private var storageNote: some View {
        Text(
            "The choice is kept on this iPhone. It is the only thing the app remembers between launches: "
                + "no key material, no pairing material, and nothing about your wallet."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    /// Pinned, so the gate is visible without scrolling — the same shape as the
    /// ceremony's setup screen, which states why its action is disabled rather than
    /// appearing to ignore a tap.
    private var actionBar: some View {
        VStack(spacing: 6) {
            Button {
                onDone()
            } label: {
                Text(isFirstRun ? "Continue" : "Done")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isFirstRun && !device.hasChosen)
            .accessibilityIdentifier("device-done")

            if isFirstRun && !device.hasChosen {
                Text("Choose the connection your YubiKey will be read through to continue.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(.horizontal)
        .padding(.top, 8)
        .padding(.bottom, 4)
        .background(.bar)
    }
}

/// A selectable row: a radio-style row that is a real button for VoiceOver and for UI
/// tests, addressed by an identifier the caller supplies (which selection it belongs to
/// matters to the tests, so it is not derived from the title).
struct ChoiceRow: View {
    let title: String
    let detail: String?
    let isSelected: Bool
    let identifier: String
    let select: () -> Void

    var body: some View {
        Button(action: select) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.callout.weight(.medium))
                    if let detail {
                        Text(detail).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isSelected ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // Label override + selected trait, applied directly to the button. Wrapping the
        // button in `.accessibilityElement(children: .ignore)` instead replaces the
        // element entirely, so it stops being a button and can no longer be addressed as
        // one.
        .accessibilityLabel(title)
        .accessibilityAddTraits(isSelected ? [.isSelected] : [])
        .accessibilityIdentifier(identifier)
    }
}
