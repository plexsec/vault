import SwiftUI
import VaultKit

/// Root of the signing flow.
///
/// The view layer renders `viewModel.screen` and forwards taps; it cannot skip a
/// check because the gates live in `SigningCeremony`. What it *can* do is make the
/// dangerous parts unmissable: the address, the recipient, the value and the
/// warnings sit above the fold, and the one-touch rule is stated before the card
/// is asked to sign rather than after something goes wrong.
struct SigningRootView: View {
    @Bindable var viewModel: SigningViewModel
    let onExit: () -> Void

    var body: some View {
        NavigationStack {
            Group {
                switch viewModel.phase {
                case .setup:
                    setupView
                case .running:
                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            if let message = viewModel.errorMessage {
                                SigningErrorBanner(message: message)
                            }
                            if viewModel.sessionActive {
                                SessionBanner(transport: viewModel.transportChoice.title)
                            }
                            runningContent
                        }
                        .padding()
                    }
                    .scrollDismissesKeyboard(.interactively)
                case .finished:
                    SigningReportView(viewModel: viewModel, onExit: onExit)
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(viewModel.phase == .finished ? "Done" : "Cancel") {
                        if viewModel.phase == .finished { onExit() } else { viewModel.abort() }
                    }
                }
                if viewModel.phase == .running {
                    ToolbarItem(placement: .topBarTrailing) {
                        Text(progressLabel).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                if viewModel.phase == .running { PrivacyFooter() }
            }
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { Self.dismissKeyboard() }
                        .accessibilityIdentifier("dismiss-keyboard")
                }
            }
        }
    }

    private var title: String {
        switch viewModel.phase {
        case .setup: return "Sign a transaction"
        case .running:
            switch viewModel.screen {
            case .readCard: return "Read the YubiKey"
            case .scan: return "Scan the request"
            case .review: return "Check the transaction"
            case .pin: return "Approve and sign"
            case .signing: return "Signing"
            case .signature: return "Signature"
            }
        case .finished: return "Signing record"
        }
    }

    private var progressLabel: String {
        switch viewModel.screen {
        case .readCard: return "1/5"
        case .scan: return "2/5"
        case .review: return "3/5"
        case .pin, .signing: return "4/5"
        case .signature: return "5/5"
        }
    }

    // MARK: Setup

    private var setupView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Read the YubiKey first")
                    .font(.title3.bold())
                Text(
                    "This app reads the key inside the YubiKey and shows you the account it signs for. "
                    + "Nothing is written to the card, and no PIN is needed to read it."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)

                if let message = viewModel.errorMessage {
                    SigningErrorBanner(message: message)
                }

                Text("Card connection").font(.headline)
                ForEach(CardTransportChoice.allCases) { choice in
                    ChoiceRow(
                        title: choice.title,
                        detail: choice.detail,
                        isSelected: viewModel.transportChoice == choice
                    ) {
                        viewModel.transportChoice = choice
                    }
                    .accessibilityIdentifier("sign-choice-\(choice.title)")
                }

                Button {
                    Task { await viewModel.readCard() }
                } label: {
                    if viewModel.busy {
                        ProgressView()
                    } else {
                        Text("Read the YubiKey")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.busy)
                .accessibilityIdentifier("read-card")
            }
            .padding()
        }
    }

    // MARK: Running

    @ViewBuilder
    private var runningContent: some View {
        cardSummary
        switch viewModel.screen {
        case .readCard, .scan:
            ScanningView(
                model: viewModel.scan,
                headline: "Scan the wallet's request",
                detail: "In MetaMask, choose your QR hardware account and confirm the transaction, then "
                    + "point this camera at the animated code."
            )
            #if DEBUG
            DebugSampleRequestButton { ur in
                Task { await viewModel.accept(ur) }
            }
            #endif
        case .review:
            reviewView
        case .pin, .signing:
            pinView
        case .signature:
            signatureView
        }
    }

    private var cardSummary: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("This YubiKey signs for").font(.footnote).foregroundStyle(.secondary)
            Text(viewModel.cardAddress)
                .font(.callout.monospaced())
                .textSelection(.enabled)
                .accessibilityIdentifier("signing-address")
            Text("Path \(viewModel.pinnedPath) · serial \(viewModel.cardSerial)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("Check this against the account shown in your wallet before approving anything.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color.secondary.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: Review

    @ViewBuilder
    private var reviewView: some View {
        if let summary = viewModel.summary {
            VStack(alignment: .leading, spacing: 12) {
                Text(summary.headline)
                    .font(.headline)
                    .accessibilityIdentifier("summary-headline")

                ForEach(Array(summary.rows.enumerated()), id: \.offset) { _, row in
                    HStack(alignment: .top) {
                        Text(row.label)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .frame(width: 130, alignment: .leading)
                        Text(row.value)
                            .font(row.isCritical ? .footnote.bold() : .footnote)
                            .textSelection(.enabled)
                    }
                    .accessibilityElement(children: .combine)
                }

                if !summary.rawDataHex.isEmpty {
                    DisclosureGroup("Raw transaction data (\(summary.rawDataHex.count / 2) bytes)") {
                        Text(summary.rawDataHex)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                    }
                }

                ForEach(viewModel.approvalWarnings, id: \.self) { warning in
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }

                if let chainID = viewModel.chainConfirmationNeeded {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Chain id \(chainID) has not been used on this device in this session.")
                            .font(.footnote)
                        Text("Nothing has been signed for that chain yet here, so confirm the id against your wallet before continuing.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Button("Confirm chain id \(chainID)") {
                            Task { await viewModel.confirmChain() }
                        }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("confirm-chain")
                    }
                    .padding(10)
                    .background(Color.orange.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                } else {
                    Text("Digest to be signed")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(viewModel.digestHex)
                        .font(.caption2.monospaced())
                        .textSelection(.enabled)
                        .accessibilityIdentifier("signing-digest")

                    Button("Approve and continue") {
                        Task { await viewModel.approve() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.busy)
                    .accessibilityIdentifier("approve-transaction")
                }
            }
        }
    }

    // MARK: PIN and signing

    @ViewBuilder
    private var pinView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("One transaction, one touch").font(.headline)
            Text(
                "The YubiKey will sign this transaction once. If the signature does not come through, "
                + "do not tap again: stop, and start over from the wallet with a new request. An app "
                + "that asks for a second touch is an app you should not trust."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)

            Toggle("I understand that this will be signed once", isOn: $viewModel.acknowledgeTouchRule)
                .accessibilityIdentifier("acknowledge-touch-rule")

            SecretEntryField(
                title: "User PIN",
                prompt: "6 digits",
                text: $viewModel.userPIN,
                isNumeric: true,
                length: 6
            )
            Text("The PIN you set when this YubiKey was provisioned. It is used once, in the card "
                + "session that produces this signature, and is never stored.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Button {
                Task { await viewModel.sign() }
            } label: {
                if viewModel.busy {
                    ProgressView()
                } else {
                    Text("Sign with the YubiKey")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.busy || !viewModel.acknowledgeTouchRule)
            .accessibilityIdentifier("sign-transaction")

            Text(viewModel.transportChoice.signingPrompt)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Signature

    @ViewBuilder
    private var signatureView: some View {
        if let ur = viewModel.signatureUR {
            VStack(alignment: .leading, spacing: 12) {
                Label("Signed by \(viewModel.cardAddress)", systemImage: "checkmark.seal.fill")
                    .font(.headline)
                    .foregroundStyle(.green)
                Text("In your wallet, choose “Scan” and point it at this code. The wallet will verify the signature against the account before broadcasting.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                AnimatedURView(ur: ur, maxFragmentLength: 120, framesPerSecond: 4)
                    .frame(maxWidth: .infinity)
                if let before = viewModel.counterBefore, let after = viewModel.counterAfter {
                    Text("Signature counter on the card: \(before) → \(after)")
                        .font(.footnote.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private static func dismissKeyboard() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    }
}

struct SigningErrorBanner: View {
    let message: String

    var body: some View {
        Label(message, systemImage: "exclamationmark.triangle")
            .font(.footnote)
            .foregroundStyle(.red)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.red.opacity(0.1))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .accessibilityIdentifier("signing-error")
    }
}

/// What the operator takes away: the account, the transaction, the digest, and
/// what the card's counter did. Nothing secret, and nothing that only exists on
/// this phone.
struct SigningReportView: View {
    @Bindable var viewModel: SigningViewModel
    let onExit: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let ur = viewModel.signatureUR {
                    Label("Signature produced", systemImage: "checkmark.seal.fill")
                        .font(.headline)
                        .foregroundStyle(.green)
                    AnimatedURView(ur: ur, maxFragmentLength: 120, framesPerSecond: 4)
                        .frame(maxWidth: .infinity)
                    Text("Show this to the wallet again at any time while this screen is open.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else if let message = viewModel.errorMessage {
                    SigningErrorBanner(message: message)
                }

                if let report = viewModel.report {
                    Text("Record").font(.headline)
                    ReportRows(rows: rows(for: report))
                }

                Button("Finished") { onExit() }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("finish-signing")
            }
            .padding()
        }
    }

    private func rows(for report: SigningReport) -> [(String, String)] {
        var rows: [(String, String)] = [
            ("Transport", report.transport),
            ("Card serial", report.cardSerial ?? "not reported"),
            ("Signs for", report.cardAddress ?? "—"),
            ("Key path", report.pinnedPath ?? "—"),
            ("Chain id", report.chainID ?? "—"),
            ("Transaction", report.transactionType ?? "—"),
            ("To", report.recipient ?? "—"),
            ("Value", report.valueInEther.map { "\($0) ETH" } ?? "—"),
            ("Function", report.decodedFunction ?? "not decoded"),
            ("Request id", report.requestID ?? "—"),
            ("Digest", report.approvedDigest ?? "—"),
            ("Signature attempts", "\(report.signatureAttempts)"),
            ("Signature verified", report.signatureVerified ? "yes" : "no"),
            ("Recovery value (v)", report.recoveryValue ?? "—"),
            ("Counter before", report.counterBeforeSigning.map(String.init) ?? "—"),
            ("Counter after", report.counterAfterSigning.map(String.init) ?? "—"),
        ]
        if let delta = report.counterDelta {
            rows.append((
                "Counter change",
                delta == 1 ? "1 (one signature)"
                    : "\(delta) — more than one signature happened; investigate"
            ))
        }
        if let reason = report.signingFailedReason {
            rows.append(("Card reported", reason))
        }
        if report.interrupted {
            rows.append(("Interrupted", "the app left the foreground during this session"))
        }
        return rows
    }
}

struct ReportRows: View {
    let rows: [(String, String)]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                HStack(alignment: .top) {
                    Text(row.0).font(.caption).foregroundStyle(.secondary)
                        .frame(width: 130, alignment: .leading)
                    Text(row.1).font(.caption.monospaced()).textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
            }
        }
    }
}

#if DEBUG
/// DEBUG-only path used by the UI tests and for a dry run with no wallet at hand.
/// It builds a request from a fixed transaction and the deterministic mnemonic's
/// master fingerprint, so the flow can be driven end to end in a simulator; it is
/// compiled out of Release, and `tools/audit-release.sh` checks the marker strings
/// are absent from the shipped bundle.
struct DebugSampleRequestButton: View {
    let onRequest: (UR) -> Void
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button("Use a sample request (debug)") {
                do {
                    onRequest(try SampleSigningRequest.make())
                } catch {
                    failure = "\(error)"
                }
            }
            .buttonStyle(.bordered)
            .accessibilityIdentifier("use-sample-request")
            if let failure {
                Text(failure).font(.caption).foregroundStyle(.red)
            }
            Text("Debug builds only: a fixed 1 ETH transfer on chain 1, for exercising the screens without a wallet.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

enum SampleSigningRequest {
    /// The EIP-155 example transaction, as MetaMask would send it for the
    /// deterministic test mnemonic's account.
    static let eip155Unsigned =
        "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
    static let path = try! DerivationPath("m/44'/0'/0'/0/0")
    /// The BIP32 master fingerprint of the all-zero mnemonic the simulated card
    /// generates, which is what its pairing manifest carries.
    static let masterFingerprint: UInt32 = 0x5436_d724

    static func make() throws -> UR {
        let request = EthSignRequest(
            requestID: try Hex.decode("00112233445566778899aabbccddeeff"),
            signData: try Hex.decode(eip155Unsigned),
            dataType: .transaction,
            chainID: EVMQuantity(1),
            derivationPath: URKeyPath(path: path, sourceFingerprint: masterFingerprint),
            address: nil,
            origin: "debug sample"
        )
        return try request.ur()
    }
}
#endif
