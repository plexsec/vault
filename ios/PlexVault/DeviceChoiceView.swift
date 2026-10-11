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

    /// Whether the "Reset card" confirmation is up. The button exists only where the
    /// simulated card does — DEBUG and the App Store build alike.
    @State private var showingSimulatedReset = false

    /// The confirmation is inside the same condition as the button, because its action resets a
    /// type that only those builds compile; the rest of the screen is the same in all of them.
    @ViewBuilder
    var body: some View {
        #if DEBUG || REVIEW_DEMO
        content.alert("Reset the simulated card?", isPresented: $showingSimulatedReset) {
            Button("Reset", role: .destructive) { SimulatedCardTransport.resetCard() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This erases the simulated card's keys, PINs and stored manifest. A wallet paired "
                    + "to it will not sign again until the card is provisioned once more."
            )
        }
        #else
        content
        #endif
    }

    private var content: some View {
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
            ForEach(CardTransportChoice.available) { choice in
                ChoiceRow(
                    title: choice.title,
                    detail: choice.detail,
                    isSelected: device.storedChoice == choice,
                    identifier: "device-choice-\(choice.title)"
                ) {
                    // Stored on the tap rather than on "Done": the row *is* the choice,
                    // so there is no second step that could disagree with the first.
                    device.choose(choice)
                } accessory: {
                    #if DEBUG || REVIEW_DEMO
                    if choice == .simulated {
                        resetSimulatedCard
                    }
                    #endif
                }
            }
        }
    }

    #if DEBUG || REVIEW_DEMO
    /// The reset control: the simulated card is the only card whose keys can be thrown away for
    /// free, so it is the only row that offers to.
    private var resetSimulatedCard: some View {
        Button("Reset card") { showingSimulatedReset = true }
            .font(.caption.weight(.semibold))
            .buttonStyle(.bordered)
            .controlSize(.small)
            .accessibilityIdentifier("reset-simulated-card")
            .padding(.trailing, 12)
            .padding(.top, 12)
    }
    #endif

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
///
/// The optional trailing `accessory` sits *beside* the button, not inside it: a button nested in
/// another button never receives the tap, and the one accessory in the app — "Reset card" on the
/// simulated row — has to be a control separate from choosing the connection.
struct ChoiceRow<Accessory: View>: View {
    let title: String
    let detail: String?
    let isSelected: Bool
    let identifier: String
    let select: () -> Void
    @ViewBuilder let accessory: () -> Accessory

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
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

            accessory()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(isSelected ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
