import SwiftUI
import VaultKit
import YubikeyKit

/// Step 1 — choose transport and mode, confirm device posture, review the rules.
struct SetupView: View {
    @Bindable var viewModel: CeremonyViewModel
    @State private var rulesAcknowledged = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header

                section("What this does") {
                    Text("""
                    This app provisions a YubiKey as an air-gapped signer. It creates a \
                    24-word BIP39 mnemonic, derives one signing key from it, imports that \
                    key into the YubiKey's OpenPGP applet, verifies the import by reading \
                    the public key back, and exports the public key for your desktop \
                    wallet. It never signs anything, and it never needs a network.
                    """)
                    .font(.callout)
                }

                section("Transport") {
                    ForEach(CeremonyViewModel.TransportChoice.allCases) { choice in
                        TransportRow(
                            choice: choice,
                            isSelected: viewModel.transportChoice == choice,
                            select: { viewModel.transportChoice = choice }
                        )
                    }
                }

                section("Mode") {
                    Picker("Mode", selection: $viewModel.mode) {
                        Text("Generate a new wallet").tag(CeremonyMode.freshGeneration)
                        Text("Restore from a mnemonic").tag(CeremonyMode.restoreFromMnemonic)
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                    if viewModel.mode == .restoreFromMnemonic {
                        Text("Restore re-imports an existing mnemonic into a fresh YubiKey. The words are typed into this app, so use a device you trust.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                section("Chain") {
                    Picker("Chain", selection: $viewModel.chain) {
                        ForEach(SigningChain.allCases, id: \.self) { chain in
                            Text(chain.displayName).tag(chain)
                        }
                    }
                    .pickerStyle(.segmented)
                    Text("One YubiKey signature slot holds exactly one key, so a ceremony provisions one address. Path: \(viewModel.chain.defaultPath.description)")
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
                    KeyValueRows(rows: [
                        ("Version", BuildInfo.version),
                        ("Binary SHA-256", BuildInfo.binarySHA256 ?? "unavailable"),
                    ])
                    Text("Compare this hash against the published reproducible-build hash before writing down any words.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Button {
                    viewModel.start()
                } label: {
                    Text("Begin ceremony").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!rulesAcknowledged)
                .padding(.top, 8)
            }
            .padding()
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Minimum-trust air-gapped signer").font(.title3.weight(.semibold))
            Text("YubiKey 5 (OpenPGP) + offline iPhone")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
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

private struct TransportRow: View {
    let choice: CeremonyViewModel.TransportChoice
    let isSelected: Bool
    let select: () -> Void

    var body: some View {
        Button(action: select) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(choice.title).font(.callout.weight(.medium))
                    Text(choice.detail).font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isSelected ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
    }
}
