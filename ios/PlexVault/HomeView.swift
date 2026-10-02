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
struct HomeView: View {
    /// Owned by the app so a scene-phase change can reach both flows.
    let ceremonyViewModel: CeremonyViewModel
    let signingViewModel: SigningViewModel
    @State private var route: Route = .home

    private enum Route: Equatable {
        case home
        case provisioning
        case signing
    }

    var body: some View {
        switch route {
        case .home:
            home
        case .provisioning:
            CeremonyRootView(viewModel: ceremonyViewModel)
                .onChange(of: ceremonyViewModel.phase) { _, phase in
                    // The provisioning flow's own back button returns here; keep
                    // the route in step so the home screen does not reappear on top
                    // of a running ceremony.
                    if phase == .setup { route = .home }
                }
        case .signing:
            SigningRootView(viewModel: signingViewModel, onExit: { route = .home })
        }
    }

    private var home: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("PlexVault").font(.largeTitle.bold())
                        Text(BuildInfo.summary).font(.caption).foregroundStyle(.secondary)
                    }

                    RouteCard(
                        title: "Set up a YubiKey",
                        detail: "Reset a card, generate or restore the wallet, import both keys, verify them by "
                            + "reading them back, and export the pairing codes for your desktop wallet.",
                        systemImage: "key.horizontal",
                        identifier: "route-provisioning"
                    ) {
                        ceremonyViewModel.abort()
                        route = .provisioning
                    }

                    RouteCard(
                        title: "Sign a transaction",
                        detail: "Read the card, scan the unsigned transaction from your wallet, check what it "
                            + "actually does, sign it with one touch, and show the signature back to the wallet.",
                        systemImage: "signature",
                        identifier: "route-signing"
                    ) {
                        signingViewModel.abort()
                        route = .signing
                    }

                    Text(
                        "Signing never writes to the card and never needs your mnemonic: the key stays inside "
                        + "the YubiKey, and every signature needs the user PIN and a touch."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
        }
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
