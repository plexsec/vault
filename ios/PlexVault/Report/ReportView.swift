import SwiftUI
import UIKit
import VaultKit

/// Final screen: the redacted provisioning record, plus export and the printed
/// checklist from design.md Appendix B.
struct ReportView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let report = viewModel.report {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("Provisioning complete", systemImage: "checkmark.seal.fill")
                            .font(.headline)
                            .foregroundStyle(.green)
                        Text("Keep this record with your steel plate. It contains no secrets.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    ReportBody(report: report)

                    VStack(spacing: 8) {
                        ShareLink(item: report.printableLines().joined(separator: "\n")) {
                            Label("Share the record", systemImage: "square.and.arrow.up")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)

                        Button {
                            UIPasteboard.general.string = report.printableLines().joined(separator: "\n")
                        } label: {
                            Label("Copy to clipboard", systemImage: "doc.on.doc")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                }

                ChecklistView(report: viewModel.report)

                Button {
                    viewModel.abort()
                } label: {
                    Text("Provision another wallet").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 4)
            }
            .padding()
        }
        .overlay(alignment: .bottom) {
            Text("Restart the app before provisioning another wallet.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(6)
                .frame(maxWidth: .infinity)
                .background(.bar)
        }
    }
}

struct ReportBody: View {
    let report: CeremonyReport

    var rows: [(String, String)] {
        var rows: [(String, String)] = []
        rows.append(("Mode", report.mode == .freshGeneration ? "fresh generation" : "restore from mnemonic"))
        rows.append(("App", report.appVersion))
        rows.append(("Transport", report.transport))
        if let commitment = report.entropyCommitmentHex { rows.append(("Entropy commitment", commitment)) }
        if !report.diceRolls.isEmpty {
            rows.append(("Dice rolls (non-authoritative)", report.diceRolls.map(String.init).joined()))
        }
        if let chain = report.chain { rows.append(("Chain", chain.displayName)) }
        if let path = report.derivationPath { rows.append(("Path", path)) }
        if let address = report.address { rows.append(("Address", address)) }
        if let key = report.publicKeyHex { rows.append(("Public key", key)) }
        if let fingerprint = report.publicKeyFingerprintHex { rows.append(("Key fingerprint", fingerprint)) }
        if let serial = report.cardSerial { rows.append(("YubiKey serial", serial)) }
        if let version = report.cardOpenPGPVersion { rows.append(("OpenPGP applet", version)) }
        if let counter = report.counterBaseline { rows.append(("Counter baseline", "\(counter)")) }
        rows.append(("Read-back verified", report.readBackVerified ? "yes" : "NO"))
        if let check = report.independentCheck {
            rows.append(("Independent check", check.matched ? "MATCH" : "MISMATCH"))
            rows.append(("Checked with", check.source))
            rows.append(("Address entered", check.expectedAddress))
        }
        if let type = report.pairingURType { rows.append(("Pairing UR type", type)) }
        rows.append(("Chain code exported", report.pairingIncludedChainCode ? "yes" : "no"))
        return rows
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            KeyValueRows(rows: rows)
            if !report.warnings.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Warnings").font(.footnote.weight(.semibold))
                    ForEach(Array(report.warnings.enumerated()), id: \.offset) { _, warning in
                        Text("• \(warning)").font(.caption).foregroundStyle(.orange)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.orange.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
        }
    }
}

/// design.md Appendix B as a live checklist: the items the app can attest to are
/// ticked automatically, and the ones that require a human or another device are
/// left for the operator to tick.
struct ChecklistView: View {
    let report: CeremonyReport?
    @State private var manual: Set<String> = []

    private var automated: [(String, Bool)] {
        [
            ("YubiKey reset (applet terminated and re-activated)", report?.cardOpenPGPVersion != nil),
            ("Touch policy fixed and PW1 status 0x00 written", report != nil),
            ("Entropy commitment recorded", report?.entropyCommitmentHex != nil),
            ("Mnemonic transcribed and back-fill check passed", report?.derivationPath != nil),
            ("Public key read back from YubiKey matches the derived key", report?.readBackVerified == true),
            ("Independent address cross-check passed", report?.independentCheck?.matched == true),
            ("Signature counter baseline is 0", report?.counterBaseline == 0),
        ]
    }

    private let manualItems = [
        "iPhone factory-reset, no SIM, airplane mode",
        "App build hash matches the published reproducible-build hash",
        "Mnemonic engraved on steel, two copies in separate locations",
        "No cameras in the generation environment",
        "Small-value test transaction verified and confirmed on-chain",
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Appendix B checklist").font(.subheadline.weight(.semibold))

            ForEach(Array(automated.enumerated()), id: \.offset) { _, item in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: item.1 ? "checkmark.square.fill" : "square")
                        .foregroundStyle(item.1 ? .green : .secondary)
                    Text(item.0).font(.footnote)
                }
            }

            Divider()

            ForEach(manualItems, id: \.self) { item in
                Button {
                    if manual.contains(item) { manual.remove(item) } else { manual.insert(item) }
                } label: {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: manual.contains(item) ? "checkmark.square.fill" : "square")
                            .foregroundStyle(manual.contains(item) ? .green : .secondary)
                        Text(item).font(.footnote).multilineTextAlignment(.leading)
                        Spacer(minLength: 0)
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
