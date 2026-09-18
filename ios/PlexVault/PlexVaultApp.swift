import SwiftUI
import UIKit
import VaultKit

@main
struct PlexVaultApp: App {
    @State private var viewModel = CeremonyViewModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            CeremonyRootView(viewModel: viewModel)
                .onChange(of: scenePhase) { _, phase in
                    viewModel.screenIsCaptured = Self.activeScreen?.isCaptured ?? false
                    if phase != .active {
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
