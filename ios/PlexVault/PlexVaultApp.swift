import SwiftUI
import UIKit
import VaultKit

@main
struct PlexVaultApp: App {
    /// The one thing the app remembers between launches, created here so both flows and
    /// the home screen read the same value (`DeviceChoiceStore`).
    @State private var device: DeviceChoiceStore
    @State private var viewModel: CeremonyViewModel
    @State private var signingViewModel: SigningViewModel
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let device = DeviceChoiceStore()
        _device = State(initialValue: device)
        _viewModel = State(initialValue: CeremonyViewModel(device: device))
        _signingViewModel = State(initialValue: SigningViewModel(device: device))
    }

    var body: some Scene {
        WindowGroup {
            HomeView(
                ceremonyViewModel: viewModel,
                signingViewModel: signingViewModel,
                deviceChoice: device
            )
                .onChange(of: scenePhase) { _, phase in
                    viewModel.screenIsCaptured = Self.activeScreen?.isCaptured ?? false
                    if phase == .active {
                        // The scanner's camera session does not survive the background, so
                        // it is started again when the operator comes back to it.
                        Task { await signingViewModel.applicationDidForeground() }
                    } else {
                        signingViewModel.applicationDidBackground()
                        // Leaving the foreground is treated as an interruption: a
                        // mutating APDU may have been in flight, and the mnemonic
                        // must not stay on screen behind the app switcher.
                        viewModel.applicationDidBackground()
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
                    viewModel.screenIsCaptured = Self.activeScreen?.isCaptured ?? false
                }
        }
    }

    /// `UIScreen.main` is deprecated in iOS 26; resolve the screen through the
    /// active window scene instead.
    private static var activeScreen: UIScreen? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }?
            .screen
    }
}
