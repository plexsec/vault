import SwiftUI
import VaultKit

/// The app's front door.
///
/// Two things can be done with a YubiKey here — provision it, or sign with an
/// already-provisioned one — and they are separate flows with separate state, so
/// they are separate screens rather than one screen with a mode switch. The
/// signing side deliberately cannot provision: `SigningCeremony` has no write
/// path, and `CashCeremony`'s writes are reachable only from the provisioning
/// flow (design.md §5/§4.2).
///
/// Provisioning is reached through the three entries in "Wallet & Key
/// Management", which stay collapsed until tapped so the home screen does not
/// stack three near-identical cards under the title. Each entry picks the
/// ceremony's mode before the provisioning flow opens.
///
/// The device choice is above both routes: on first launch this screen is not shown at
/// all until the operator has said how the YubiKey is connected, because the connection is
/// the one thing the app cannot work out for itself. Afterwards it lives behind the YubiKey
/// button on the title line, which shows the key it will use, how it is connected, and — on
/// USB-C — whether the key is plugged in.
struct HomeView: View {
    /// Owned by the app so a scene-phase change can reach both flows.
    let ceremonyViewModel: CeremonyViewModel
    let signingViewModel: SigningViewModel
    let deviceChoice: DeviceChoiceStore
    let presence: CardPresence
    @State private var route: Route
    /// True while the device screen is the way *into* the app, so it cannot be left
    /// without an answer. Set when the route was decided at construction, and cleared
    /// when the operator comes back to change the choice.
    @State private var deviceIsFirstRun: Bool

    private enum Route: Equatable {
        case home
        case provisioning
        case signing
        case device
    }

    /// The first screen is decided here rather than in `onAppear`, so a first run never
    /// renders the home screen for a frame and then replaces it.
    init(
        ceremonyViewModel: CeremonyViewModel,
        signingViewModel: SigningViewModel,
        deviceChoice: DeviceChoiceStore,
        presence: CardPresence
    ) {
        self.ceremonyViewModel = ceremonyViewModel
        self.signingViewModel = signingViewModel
        self.deviceChoice = deviceChoice
        self.presence = presence
        let needsChoice = !deviceChoice.hasChosen
        _route = State(initialValue: needsChoice ? .device : .home)
        _deviceIsFirstRun = State(initialValue: needsChoice)
    }

    var body: some View {
        switch route {
        case .home:
            home
        case .provisioning:
            CeremonyRootView(viewModel: ceremonyViewModel, onExit: { route = .home })
                .onChange(of: ceremonyViewModel.phase) { _, phase in
                    // The provisioning flow's own back button returns here; keep
                    // the route in step so the home screen does not reappear on top
                    // of a running ceremony.
                    if phase == .setup { route = .home }
                }
        case .signing:
            SigningRootView(viewModel: signingViewModel, onExit: { route = .home })
        case .device:
            DeviceChoiceView(device: deviceChoice, isFirstRun: deviceIsFirstRun) {
                deviceIsFirstRun = false
                route = .home
            }
        }
    }

    private var home: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    // The button sits on the title line rather than in a navigation bar.
                    // The bar was an empty strip *above* the title, so the icon floated
                    // higher than anything it belongs to; here it is centred on the title's
                    // own line box.
                    HStack(alignment: .center) {
                        Text("PlexVault").font(.largeTitle.bold())
                        Spacer(minLength: 12)
                        deviceButton
                    }
                    Text(BuildInfo.summary).font(.caption).foregroundStyle(.secondary)
                }

                RouteCard(
                    title: "Sign a transaction",
                    detail: "Scan the unsigned transaction, check what it does, and sign it with one touch.",
                    systemImage: "signature",
                    identifier: "route-signing"
                ) {
                    signingViewModel.abort()
                    route = .signing
                }

                WalletKeyManagementSection { mode in
                    ceremonyViewModel.abort()
                    ceremonyViewModel.mode = mode
                    route = .provisioning
                }

                Text("Signing never writes to the card — every signature needs the PIN and a touch.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            .padding()
        }
        // Polls the USB-C slot while that is the chosen connection, and stops the moment the
        // choice changes or this screen goes away — the card's presence is only interesting
        // here.
        .task(id: deviceChoice.choice) {
            await presence.watch(deviceChoice.choice)
        }
    }

    /// The YubiKey button: the key the app will use, the connection it is on, and — where it
    /// can be known — whether it is plugged in.
    private var deviceButton: some View {
        Button {
            deviceIsFirstRun = false
            route = .device
        } label: {
            YubiKeyGlyph(choice: deviceChoice.choice, isPresent: presence.presence)
        }
        .accessibilityLabel(deviceChoice.choice.connectionLabel(isPresent: presence.presence))
        .accessibilityHint("Change how the YubiKey is connected")
        .accessibilityIdentifier("device-button")
    }
}
private struct RouteCard: View {
    let title: String
    let detail: String
    let systemImage: String
    let identifier: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: systemImage)
                    .font(.title2)
                    .frame(width: 32)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.headline)
                    Text(detail).font(.footnote).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.secondary.opacity(0.1))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier)
    }
}

/// Presentation copy for the three provisioning modes, shared by the home screen
/// (where the operator picks one) and the setup screen (which confirms the pick).
extension CeremonyMode {
    /// The operator-facing title, shown on the home-screen entry and in the setup
    /// header once a mode has been chosen.
    var setupTitle: String {
        switch self {
        case .freshGeneration: return "Generate a new wallet"
        case .restoreFromMnemonic: return "Restore from a mnemonic"
        case .rePair: return "Pair a wallet"
        }
    }

    /// One-line explanation of what the mode does, shown under the home-screen
    /// entry.
    var setupDetail: String {
        switch self {
        case .freshGeneration:
            return "New 24-word mnemonic and both signing keys."
        case .restoreFromMnemonic:
            return "Re-import both keys from an existing mnemonic into a fresh YubiKey."
        case .rePair:
            return "Export pairing codes to link a wallet. Read-only."
        }
    }

    /// Symbol for the home-screen entry and the setup header.
    var setupSystemImage: String {
        switch self {
        case .freshGeneration: return "sparkles"
        case .restoreFromMnemonic: return "arrow.clockwise"
        case .rePair: return "link"
        }
    }
}

/// The three wallet operations, collapsed under one heading on the home screen.
///
/// Collapsed by default so the home screen stays about the two things it can do —
/// provision and sign — without three near-identical cards stacked under the title.
/// Tapping the heading reveals the three entries; each one routes straight into the
/// provisioning flow with its mode pre-selected.
private struct WalletKeyManagementSection: View {
    @State private var isExpanded = false
    let select: (CeremonyMode) -> Void

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "key.horizontal")
                        .font(.title2)
                        .frame(width: 32)
                    Text("Wallet & Key Management").font(.headline)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                }
                .padding()
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("wallet-key-management")

            if isExpanded {
                Divider().padding(.horizontal)
                ForEach(Array(CeremonyMode.allCases.enumerated()), id: \.element) { index, mode in
                    ModeEntryRow(mode: mode) { select(mode) }
                    if index < CeremonyMode.allCases.count - 1 {
                        Divider().padding(.leading, 56)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

/// One mode inside the collapsed wallet section. Rendered as a row because it sits
/// inside the section card rather than as its own card.
private struct ModeEntryRow: View {
    let mode: CeremonyMode
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: mode.setupSystemImage)
                    .font(.title2)
                    .frame(width: 32)
                VStack(alignment: .leading, spacing: 4) {
                    Text(mode.setupTitle).font(.headline)
                    Text(mode.setupDetail).font(.footnote).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("wallet-mode-\(mode.setupTitle)")
    }
}
