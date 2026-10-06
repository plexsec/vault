import Photos
import SwiftUI
import UIKit
import VaultKit

/// Final screen: the redacted provisioning record, plus export.
struct ReportView: View {
    @Bindable var viewModel: CeremonyViewModel

    /// Whether the confirmation for "Quit & Reopen App" is up. The action ends the process, so it is
    /// confirmed rather than fired by a single tap on a screen the operator is still reading.
    @State private var showingQuitConfirmation = false

    var body: some View {
        ScrollView {
            CeremonyRecordContent(report: viewModel.report)
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
        // Quitting is the one way out of a finished run, and it ends the process, so it is asked
        // about first: the operator is still reading the record. This replaced the alert that used
        // to fire at the wipe itself — the wipe no longer closes anything (amendment 45).
        .alert("Quit and reopen the app?", isPresented: $showingQuitConfirmation) {
            Button("Quit & Reopen", role: .destructive) { viewModel.exitForPairing() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The app closes. Reopen it to pair the wallet: the next launch goes straight to pairing and reads the codes back out of the YubiKey's stored manifest. Nothing was written to or erased from the card.")
        }
    }

    private var exitBar: some View {
        VStack(spacing: 6) {
            if viewModel.pairingIsPending {
                Button {
                    showingQuitConfirmation = true
                } label: {
                    Label("Quit & Reopen App", systemImage: "link")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Text("Pairing is the second process and has its own record. Quitting and reopening the app goes straight to it: it reads the codes back out of the YubiKey (no mnemonic, nothing secret).")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                Text("The run is complete. Quit the app and reopen it to provision another wallet.")
                    .font(.caption2)
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

/// The record itself — the mode's heading, the rows and the export buttons — without the screen it
/// sits on.
///
/// Two screens show it now: `ReportView`, which is the provisioning process's record and carries
/// the confirmed exit, and the pairing process's merged Finish step, which shows the record in
/// place of a screen of its own and returns to the home screen from there (amendment 46).
struct CeremonyRecordContent: View {
    let report: CeremonyReport?

    /// The outcome of the last "Save to Photos", shown in an alert. `nil` when none is up.
    @State private var saveOutcome: String?
    @State private var showingSaveOutcome = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let report {
                CeremonyRecordPage(report: report)

                VStack(spacing: 8) {
                    Button {
                        saveToPhotos(report)
                    } label: {
                        Label("Save to Photos", systemImage: "photo.on.rectangle.angled")
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
        }
        .alert("Save to Photos", isPresented: $showingSaveOutcome) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(saveOutcome ?? "")
        }
    }

    /// Saves the record to the photo library as an image of the **whole** record, not the part that
    /// fits on screen: the record is three screens of keys, addresses and serials, and a capture of
    /// the viewport would be missing most of what the operator is filing.
    ///
    /// Add-only (`PHPhotoLibrary` `.addOnly`): the app never reads the library, and what it writes is
    /// the public material the operator is already told to keep.
    private func saveToPhotos(_ report: CeremonyReport) {
        guard let image = Self.recordImage(report) else {
            reportOutcome("The record could not be rendered as an image.")
            return
        }
        PHPhotoLibrary.requestAuthorization(for: .addOnly) { status in
            guard status == .authorized else {
                reportOutcome("Photos access is off. Allow “Add Photos Only” for PlexVault in Settings, then try again.")
                return
            }
            PHPhotoLibrary.shared().performChanges {
                PHAssetChangeRequest.creationRequestForAsset(from: image)
            } completionHandler: { success, _ in
                reportOutcome(success
                    ? "The record was saved to Photos."
                    : "The record could not be saved to Photos.")
            }
        }
    }

    /// The authorization callback and the change callback arrive on their own queues; the alert is
    /// main-actor UI.
    private func reportOutcome(_ message: String) {
        DispatchQueue.main.async {
            saveOutcome = message
            showingSaveOutcome = true
        }
    }

    /// The record as an image: the heading and the rows at a fixed width on white, in light
    /// appearance, so a saved record reads the same whatever theme the phone is in.
    @MainActor
    private static func recordImage(_ report: CeremonyReport) -> UIImage? {
        let page = CeremonyRecordPage(report: report)
            .padding(24)
            .frame(width: 720, alignment: .leading)
            .background(Color.white)
            .environment(\.colorScheme, .light)
        let renderer = ImageRenderer(content: page)
        renderer.scale = 3
        return renderer.uiImage
    }
}

/// The record as a page — the heading and the rows, with no controls — shared by the on-screen
/// record and the image that `Save to Photos` writes.
struct CeremonyRecordPage: View {
    let report: CeremonyReport

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Label(
                    report.mode == .rePair ? "Pairing complete" : "Provisioning complete",
                    systemImage: "checkmark.seal.fill"
                )
                .font(.headline)
                .foregroundStyle(.green)
                Text(report.mode == .rePair
                    ? "Keep this with the provisioning record: it is the public material the wallet was given, read back out of the YubiKey."
                    : "Keep this record with your steel plate. It contains no secrets.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            ReportBody(report: report)
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
        if report.cards.isEmpty {
            rows.append(("YubiKey serial", report.cardSerial ?? "not reported"))
        } else {
            for card in report.cards {
                let label = report.cards.count > 1 ? "YubiKey \(card.order) of \(report.cards.count)" : "YubiKey"
                rows.append(("\(label) serial", card.serial ?? "not reported"))
                rows.append(("\(label) OpenPGP applet", card.openPGPVersion))
            }
        }
        if let backedUp = report.mnemonicBackedUp {
            rows.append((
                "Mnemonic written down",
                backedUp ? "yes — transcription checked" : "NO — the cards above are the only copy"
            ))
        }
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

