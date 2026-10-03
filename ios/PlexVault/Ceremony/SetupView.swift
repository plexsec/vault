import SwiftUI
import VaultKit
import YubikeyKit

/// Step 1 — choose transport, confirm device posture, review the rules.
///
/// Two deliberate UI decisions, both learned from driving the real screen:
///
/// * Selection is made with explicit, tappable rows rather than a `Picker`. An
///   `.inline` picker outside a `Form`/`List` renders as a **wheel** on iOS 26 —
///   a 216pt spinning control whose selected value is already the default, so
///   tapping it appears to do nothing. Rows are unambiguous and, unlike a wheel,
///   are real buttons for VoiceOver and for UI tests.
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
                header

                // Explanatory and reference material is collapsed by default: the
                // controls a user must operate come first, so the screen does not
                // require scrolling past prose to reach the primary action.
                section("What this does") {
                    DisclosureGroup("How this works", isExpanded: $showExplanation) {
                        Text("""
                        Creates a 24-word mnemonic, imports both keys (secp256k1 + \
                        Ed25519) into the YubiKey, verifies them by read-back, and \
                        exports the public keys. Offline — it never signs.
                        """)
                        .font(.callout)
                        .padding(.top, 6)
                    }
                    .font(.callout.weight(.medium))
                }

                section("Transport") {
                    ForEach(CeremonyViewModel.TransportChoice.allCases) { choice in
                        ChoiceRow(
                            title: choice.title,
                            detail: choice.detail,
                            isSelected: viewModel.transportChoice == choice
                        ) {
                            viewModel.transportChoice = choice
                        }
                    }
                }

                section("Keys") {
                    keySummaryRow(
                        title: "ECDSA secp256k1",
                        detail: "Signature slot, path \(DerivationPath.secp256k1Default.description). Serves EVM and Bitcoin."
                    )
                    keySummaryRow(
                        title: "Ed25519",
                        detail: "Authentication slot, path \(DerivationPath.ed25519Default.description). Serves Solana, Cardano, Polkadot and other Ed25519 chains."
                    )
                    Text("Both keys come from one mnemonic. Only the signature slot has a hardware counter.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                section("Device posture") {
                    Toggle("This iPhone is factory-reset, has no SIM, and is in airplane mode", isOn: $viewModel.postureConfirmed)
                    Toggle("No cameras or other people can see this screen", isOn: $rulesAcknowledged)
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

                section("Build identity") {
                    DisclosureGroup(isExpanded: $showBuildIdentity) {
                        VStack(alignment: .leading, spacing: 8) {
                            KeyValueRows(rows: [
                                ("Version", BuildInfo.version),
                                ("Binary SHA-256", BuildInfo.binarySHA256 ?? "unavailable"),
                            ])
                            Text("Compare this hash against the published reproducible-build hash before writing down any words.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.top, 6)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Build identity").font(.callout.weight(.medium))
                            Text(BuildInfo.shortHash)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
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

            if !canBegin {
                Text("Tick \"No cameras or other people can see this screen\" to continue.")
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

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Minimum-trust air-gapped signer").font(.title3.weight(.semibold))
            Text("YubiKey 5 (OpenPGP) + offline iPhone")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Label(viewModel.mode.setupTitle, systemImage: viewModel.mode.setupSystemImage)
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.tint)
        }
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

/// A selectable row.
///
/// Exposed to accessibility (and to UI tests) as a button labelled with just its
/// title, plus the `selected` trait — rather than a button whose label is the
/// title concatenated with its description, which reads badly in VoiceOver and
/// makes the element impossible to address by name.
struct ChoiceRow: View {
    let title: String
    let detail: String?
    let isSelected: Bool
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
        // Label override + selected trait, applied directly to the button.
        // Wrapping the button in `.accessibilityElement(children: .ignore)`
        // instead replaces the element entirely, so it stops being a button and
        // can no longer be addressed as one.
        .accessibilityLabel(title)
        .accessibilityAddTraits(isSelected ? [.isSelected] : [])
        .accessibilityIdentifier("choice-\(title)")
    }
}
