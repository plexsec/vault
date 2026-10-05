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
            }
            .padding()
        }
        // The way out is pinned, like every other primary action in this app. It used
        // to be the last item of the scroll content — under a report that runs to three
        // screens of keys, addresses and checklist — with the "restart the app" note
        // drawn *over* it as an overlay. The end-to-end re-pair test reached that button
        // and tapped it without leaving the screen: a primary action the operator has to
        // scroll for is a primary action that can be missed. The note belongs to the bar,
        // under the button, where it explains it.
        .safeAreaInset(edge: .bottom) { exitBar }
    }

    private var exitBar: some View {
        VStack(spacing: 6) {
            Button {
                viewModel.abort()
            } label: {
                Text("Provision another wallet").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

            Text("Restart the app before provisioning another wallet.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.horizontal)
        .padding(.top, 8)
        .padding(.bottom, 4)
        .background(.bar)
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
        if let serial = report.cardSerial { rows.append(("YubiKey serial", serial)) }
        if let version = report.cardOpenPGPVersion { rows.append(("OpenPGP applet", version)) }
        rows.append(("Read-back verified (both keys)", report.readBackVerified ? "yes" : "NO"))

        for record in report.keys {
            let label = record.keyAlgorithm?.displayName ?? record.algorithm
            rows.append(("\(label) slot", record.slot))
            rows.append(("\(label) path", record.path))
            if let evm = record.evmAddress { rows.append(("\(label) EVM address", evm)) }
            if let btc = record.bitcoinAddress { rows.append(("\(label) Bitcoin address", btc)) }
            if record.evmAddress == nil { rows.append(("\(label) public key", record.publicKeyHex ?? "-")) }
            rows.append(("\(label) fingerprint", record.fingerprintHex ?? "-"))
            rows.append(("\(label) read-back verified", record.readBackVerified ? "yes" : "NO"))
            if let type = record.pairingURType { rows.append(("\(label) pairing UR type", type)) }
            if let pairingPath = record.pairingPath {
                rows.append(("\(label) pairing key path", pairingPath + (record.pairingAccountLevel ? " (account level)" : "")))
            }
        }

        // The two retry limits, as the card reported them back (amendment 27); they are
        // separate numbers because the two passwords are used differently
        // (amendment 32).
        if let userLimit = report.userPINRetryLimit {
            rows.append(("User PIN retry limit (PW1)", "\(userLimit)"))
        }
        if let adminLimit = report.adminPINRetryLimit {
            rows.append(("Admin PIN retry limit (PW3)", "\(adminLimit)"))
        }
        rows.append(("Touch policy verified on both slots", report.touchPolicyVerified == true ? "yes" : "NO"))
        rows.append(("Chain code exported", report.pairingIncludedChainCode ? "yes (required by Keystone/MetaMask)" : "no"))
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
            // Ticked by the read-back that confirmed the card reports the policy, not by
            // the mere existence of a report: a policy the card does not report is not a
            // policy (amendment 26).
            ("Touch policy fixed and PW1 status 0x00 read back from the card", report?.touchPolicyVerified == true),
            (
                "PIN retry limits set and read back (User / Admin)",
                report?.userPINRetryLimit != nil && report?.adminPINRetryLimit != nil
            ),
            ("Entropy commitment recorded", report?.entropyCommitmentHex != nil),
            ("Mnemonic transcribed and back-fill check passed", !(report?.keys.isEmpty ?? true)),
            ("Both public keys read back from YubiKey match the derived keys", report?.readBackVerified == true),
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
