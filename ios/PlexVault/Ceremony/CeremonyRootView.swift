import SwiftUI
import VaultKit
import YubikeyKit

/// Root of the provisioning flow.
///
/// The view layer is intentionally thin: it renders `viewModel.step` and forwards
/// taps. It cannot skip a step, because the ordering gates live in
/// `ProvisioningCeremony` and every action here simply calls the corresponding
/// ceremony method.
struct CeremonyRootView: View {
    @Bindable var viewModel: CeremonyViewModel

    var body: some View {
        NavigationStack {
            Group {
                switch viewModel.phase {
                case .setup:
                    SetupView(viewModel: viewModel)
                case .running:
                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            if let message = viewModel.errorMessage {
                                ErrorBanner(message: message)
                            }
                            if viewModel.sessionActive {
                                SessionBanner(transport: viewModel.transportChoice.title)
                            }
                            stepContent
                        }
                        .padding()
                    }
                    // The back-fill and address fields sit above the step's action:
                    // without this the keyboard covers the action until the user
                    // reaches for the keyboard's Done button.
                    .scrollDismissesKeyboard(.interactively)
                case .finished:
                    ReportView(viewModel: viewModel)
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if viewModel.phase != .setup {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Abort", role: .destructive) { viewModel.abort() }
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        StepProgressBadge(step: viewModel.step, mode: viewModel.mode)
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                if viewModel.phase == .running {
                    PrivacyFooter()
                }
            }
            // The PIN fields use `.numberPad`, which has no return key: without an
            // explicit dismiss the keyboard covers the lower part of the form and
            // cannot be closed at all.
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { Self.dismissKeyboard() }
                        .accessibilityIdentifier("dismiss-keyboard")
                }
            }
        }
    }

    private static func dismissKeyboard() {
        UIApplication.shared.sendAction(
            #selector(UIResponder.resignFirstResponder),
            to: nil,
            from: nil,
            for: nil
        )
    }

    private var title: String {
        switch viewModel.phase {
        case .setup: return "Provision wallet"
        case .running: return viewModel.step.title
        case .finished: return "Provisioning record"
        }
    }

    @ViewBuilder
    private var stepContent: some View {
        switch viewModel.step {
        case .notStarted, .preflight, .cardInventory:
            InventoryStepView(viewModel: viewModel)
        case .rePairRead:
            RepairStepView(viewModel: viewModel)
        case .reset:
            ResetStepView(viewModel: viewModel)
        case .pinProvisioning:
            PINStepView(viewModel: viewModel)
        case .pinRetries:
            RetryLimitStepView(viewModel: viewModel)
        case .policy:
            PolicyStepView(viewModel: viewModel)
        case .entropy:
            EntropyStepView(viewModel: viewModel)
        case .mnemonic:
            MnemonicStepView(viewModel: viewModel)
        case .derivation:
            DerivationStepView(viewModel: viewModel)
        case .keyImport:
            ImportStepView(viewModel: viewModel)
        case .readBackCheck:
            ReadBackStepView(viewModel: viewModel)
        case .pairingManifest:
            ManifestStepView(viewModel: viewModel)
        case .pairingExport:
            PairingStepView(viewModel: viewModel)
        case .counterBaseline:
            CounterStepView(viewModel: viewModel)
        case .teardown:
            TeardownStepView(viewModel: viewModel)
        }
    }
}

// MARK: - Shared chrome

/// Consistent step layout: what this step does, why it matters, the action, and
/// an optional note about what happens next.
struct StepScaffold<Content: View>: View {
    let why: String
    let caution: String?
    let actionTitle: String
    let isBusy: Bool
    let isEnabled: Bool
    let secondaryTitle: String?
    let secondaryAction: (() -> Void)?
    let action: () -> Void
    @ViewBuilder let content: () -> Content

    /// `content` is the last parameter so call sites can use trailing-closure
    /// syntax for the step body while `action` stays an explicit labelled
    /// argument.
    init(
        why: String,
        caution: String? = nil,
        actionTitle: String,
        isBusy: Bool = false,
        isEnabled: Bool = true,
        secondaryTitle: String? = nil,
        secondaryAction: (() -> Void)? = nil,
        action: @escaping () -> Void,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.why = why
        self.caution = caution
        self.actionTitle = actionTitle
        self.isBusy = isBusy
        self.isEnabled = isEnabled
        self.secondaryTitle = secondaryTitle
        self.secondaryAction = secondaryAction
        self.action = action
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(why)
                .font(.callout)
                .foregroundStyle(.secondary)

            if let caution {
                Label(caution, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }

            content()

            VStack(spacing: 8) {
                Button(action: action) {
                    HStack {
                        if isBusy { ProgressView().controlSize(.small) }
                        Text(actionTitle)
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!isEnabled || isBusy)

                if let secondaryTitle, let secondaryAction {
                    Button(secondaryTitle, action: secondaryAction)
                        .frame(maxWidth: .infinity)
                        .buttonStyle(.bordered)
                }
            }
            .padding(.top, 4)
        }
    }
}

struct ErrorBanner: View {
    let message: String

    var body: some View {
        Label {
            Text(message).font(.callout)
        } icon: {
            Image(systemName: "xmark.octagon.fill")
        }
        .foregroundStyle(.red)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct SessionBanner: View {
    let transport: String

    var body: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(transport == "NFC" ? "NFC session open — hold the key against the top of the iPhone" : "Talking to the YubiKey…")
                .font(.footnote)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct StepProgressBadge: View {
    let step: CeremonyStep
    /// The progress is the mode's own path, not the union of all steps: re-pair
    /// visits five of them, and counting the reset it will never run would tell
    /// the operator they are at the start of a long ceremony.
    let mode: CeremonyMode

    var body: some View {
        let path = mode.path
        let total = max(1, path.count)
        let current = (path.firstIndex(of: step) ?? 0) + 1
        Text("\(min(current, total))/\(total)")
            .font(.caption.monospacedDigit())
            .foregroundStyle(.secondary)
    }
}

struct PrivacyFooter: View {
    var body: some View {
        Text("One transaction = one touch. If any screen ever asks for a second touch for the same transaction, treat the app as compromised and stop.")
            .font(.caption2)
            .multilineTextAlignment(.center)
            .foregroundStyle(.secondary)
            .padding(.horizontal)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity)
            .background(.bar)
    }
}

struct KeyValueRows: View {
    let rows: [(String, String)]

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                HStack(alignment: .firstTextBaseline) {
                    Text(row.0).foregroundStyle(.secondary)
                    Spacer(minLength: 12)
                    Text(row.1).multilineTextAlignment(.trailing).textSelection(.enabled)
                }
                .font(.footnote)
                .padding(.vertical, 6)
                if index < rows.count - 1 { Divider() }
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

/// Monospaced, selectable, chunked display for addresses and hashes so a human
/// can compare them character by character without losing their place.
struct AddressDisplay: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
