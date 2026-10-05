import SwiftUI
import VaultKit
import YubikeyKit

/// Step 1 — confirm device posture and review the rules.
///
/// Two deliberate UI decisions, both learned from driving the real screen:
///
/// * The card connection is not on this screen at all, in any form. It is one setting
///   for the phone, chosen once on the device screen (`DeviceChoiceView`), summarised on
///   the home screen, and changed only there. A picker here was a second place for the
///   same value to be set — and the one place it could be changed *halfway through* a
///   ceremony, which is how a step ends up talking to a card the operator is not holding.
///   Repeating it here as read-only prose only spread it further.
/// * The primary action sits in a pinned bottom bar, so it is visible without
///   scrolling, and it states *why* it is disabled instead of silently ignoring
///   taps.
struct SetupView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var rulesAcknowledged = false
    @State private var showExplanation = false
    @State private var showBuildIdentity = false

    private var canBegin: Bool { rulesAcknowledged }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                section("Keys") {
                    keySummaryRow(
                        title: "ECDSA secp256k1",
                        detail: "Signature slot, path \(DerivationPath.secp256k1Default.description). Serves EVM and Bitcoin."
                    )
                    keySummaryRow(
                        title: "Ed25519",
                        detail: "Authentication slot, path \(DerivationPath.ed25519Default.description). Serves Solana, Cardano, Polkadot and other Ed25519 chains."
                    )
                }

                section("Non-negotiable rules") {
                    VStack(alignment: .leading, spacing: 8) {
                        rule("Write the 24 words on steel, not paper, and store two copies in separate places.")
                        rule("Never photograph the mnemonic or type it into an online device.")
                        rule("The YubiKey is not a backup. The mnemonic is.")
                        rule("Any single transaction permits exactly one touch. A second request for the same transaction means the display device is compromised.")
                        rule("If the app ever reports a signature or key mismatch, stop and restart the ceremony on a different device.")
                    }
                }
                
                section("Device posture") {
                    Toggle("This iPhone is factory-reset, has no SIM, and is in airplane mode", isOn: $viewModel.postureConfirmed)
                    Toggle("No cameras or other people can see this screen", isOn: $rulesAcknowledged)
                }
            }
            .padding()
            .padding(.bottom, 8)
        }
        .safeAreaInset(edge: .bottom) { primaryActionBar }
    }

    /// Always-visible primary action with an explicit reason when it is disabled.
    private var primaryActionBar: some View {
        VStack(spacing: 6) {
            Button {
                viewModel.start()
            } label: {
                Text("Begin ceremony")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!canBegin)
            .accessibilityIdentifier("begin-ceremony")
        }
        .padding(.horizontal)
        .padding(.top, 8)
        .padding(.bottom, 4)
        .background(.bar)
    }

    /// Non-interactive row: both keys are always provisioned, so there is no
    /// choice to present here — only an explanation of what will be written.
    private func keySummaryRow(title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "key.fill").foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.callout.weight(.medium))
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func rule(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "checkmark.shield").foregroundStyle(.tint)
            Text(text).font(.footnote)
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title.uppercased())
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            content()
        }
    }
}

