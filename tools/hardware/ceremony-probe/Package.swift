// swift-tools-version: 6.0
import PackageDescription

// A macOS-only probe that drives the **app's own** provisioning ceremony and the app's
// **own** USB-C CCID transport against a real YubiKey in the reader.
//
// It exists because the ceremony is otherwise only exercised by the simulator (which cannot
// reach a card at all) and by unit tests (which cannot reach a card either), so a defect that
// only shows up between two cards — amendment 41 — got as far as a hardware run before anyone
// saw it. `docs/m0-hardware-verification.md` item 20 records what it checks and what it found.
//
// Not part of the app's build, and deliberately not wired into `tools/verify.sh`: it needs a
// card, a reader and a signing step (see the README in this directory).
let package = Package(
    name: "ceremony-probe",
    platforms: [.macOS("14.0")],
    dependencies: [
        .package(path: "../../../ios/Packages/YubikeyKit"),
        .package(path: "../../../ios/Packages/VaultKit"),
    ],
    targets: [
        .executableTarget(
            name: "ceremony-probe",
            dependencies: [
                .product(name: "VaultKit", package: "VaultKit"),
                .product(name: "YubikeyKit", package: "YubikeyKit"),
                .product(name: "YubikeyKitCCID", package: "YubikeyKit"),
            ],
            path: "Sources/ceremony-probe",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // The smallest possible check that the card is reachable from this Mac at all: open the
        // slot, select the OpenPGP applet, read one data object. Useful first when the probe
        // reports that the smart-card subsystem is unavailable — that is an entitlement problem
        // (see the README), not a card problem.
        .executableTarget(
            name: "slot-probe",
            dependencies: [
                .product(name: "YubikeyKit", package: "YubikeyKit"),
                .product(name: "YubikeyKitCCID", package: "YubikeyKit"),
            ],
            path: "Sources/slot-probe",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
