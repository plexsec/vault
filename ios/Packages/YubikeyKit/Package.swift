// swift-tools-version: 6.0
import PackageDescription

// YubikeyKit holds the ISO 7816 / OpenPGP APDU layer and the two transports this
// app supports: NFC (CoreNFC) and USB-C (CryptoTokenKit CCID).
//
// There is deliberately NO Lightning / MFi accessory transport: the YubiKey 5Ci
// path depended on a vendor SDK that YubiKit 4.x dropped, and USB-C replaces it
// using only Apple frameworks.
let package = Package(
    name: "YubikeyKit",
    platforms: [
        .iOS("26.0"),
        .macOS("14.0"),
    ],
    products: [
        .library(name: "YubikeyKit", targets: ["YubikeyKit"]),
        .library(name: "YubikeyKitNFC", targets: ["YubikeyKitNFC"]),
        .library(name: "YubikeyKitCCID", targets: ["YubikeyKitCCID"]),
        .library(name: "YubikeyKitMock", targets: ["YubikeyKitMock"]),
    ],
    dependencies: [
        .package(path: "../VaultKit"),
    ],
    targets: [
        // Pure protocol layer: no CoreNFC, no CryptoTokenKit, so it builds and
        // tests on macOS.
        .target(
            name: "YubikeyKit",
            dependencies: [.product(name: "VaultKit", package: "VaultKit")],
            path: "Sources/YubikeyKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // CoreNFC ISO 7816 transport (iOS device only; CoreNFC has no simulator).
        .target(
            name: "YubikeyKitNFC",
            dependencies: ["YubikeyKit"],
            path: "Sources/YubikeyKitNFC",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // USB-C CCID transport via CryptoTokenKit smart-card slots.
        .target(
            name: "YubikeyKitCCID",
            dependencies: ["YubikeyKit"],
            path: "Sources/YubikeyKitCCID",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        // Scripted card used by DEBUG UI work and by the app's previews. Never
        // linked into a Release build (the app target links it only in Debug).
        .target(
            name: "YubikeyKitMock",
            dependencies: ["YubikeyKit"],
            path: "Sources/YubikeyKitMock",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "YubikeyKitTests",
            dependencies: ["YubikeyKit", "YubikeyKitMock"],
            path: "Tests/YubikeyKitTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
