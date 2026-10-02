// swift-tools-version: 6.0
import PackageDescription

// VaultKit is deliberately dependency-free apart from the two vendored C
// targets (libsecp256k1 and TweetNaCl). Everything else (SHA-2, HMAC, PBKDF2,
// RIPEMD-160, Keccak-256, BIP39, BIP32, SLIP-0010, Base58Check, bech32,
// deterministic CBOR, BC-UR) is implemented or ported in-repo so the whole
// surface can be reviewed in one place.
//
// Swift language mode 5 is used on purpose: this package holds raw pointers to
// secret material, and mode 5 keeps that explicit rather than papering over it
// with Sendable conformances that would be unsound for a mutable secret buffer.
let package = Package(
    name: "VaultKit",
    platforms: [
        .iOS("26.0"),
        .macOS("14.0"),
    ],
    products: [
        .library(name: "VaultKit", targets: ["VaultKit"]),
    ],
    targets: [
        // Vendored bitcoin-core libsecp256k1 v0.8.0. See Sources/Csecp256k1/VENDORED.txt
        // for provenance, the exact file list, and the disabled configuration knobs.
        // `ENABLE_MODULE_RECOVERY` compiles libsecp256k1's own recovery module,
        // which the signing flow needs to determine a signature's recovery value
        // (`v`) and to check that a signature really came from the card's key.
        // Signing with an in-memory key stays impossible at the Swift layer: the
        // wrapper exposes recover/verify only (see Crypto/Secp256k1.swift).
        .target(
            name: "Csecp256k1",
            path: "Sources/Csecp256k1",
            // `main_impl.h` is not compiled on its own; `src/secp256k1.c`
            // includes it when ENABLE_MODULE_RECOVERY is defined. Excluding it
            // from the target's file list is how that is expressed to SwiftPM.
            exclude: ["src/modules/recovery/main_impl.h"],
            publicHeadersPath: "include",
            cSettings: [.define("ENABLE_MODULE_RECOVERY")]
        ),
        // Vendored TweetNaCl 20140427 (public domain) plus a project-owned shim.
        // See Sources/Ced25519/VENDORED.txt: tweetnacl.c is compiled exactly once,
        // from vault_ed25519.c, so it is excluded here.
        .target(
            name: "Ced25519",
            path: "Sources/Ced25519",
            exclude: ["tweetnacl.c", "VENDORED.txt"],
            publicHeadersPath: "include"
        ),
        .target(
            name: "VaultKit",
            dependencies: ["Csecp256k1", "Ced25519"],
            path: "Sources/VaultKit",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "VaultKitTests",
            dependencies: ["VaultKit"],
            path: "Tests/VaultKitTests",
            resources: [.copy("Fixtures")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
