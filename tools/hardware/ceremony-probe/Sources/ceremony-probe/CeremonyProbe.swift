// Drives the app's own provisioning ceremony — and the app's own USB-C CCID transport — against a
// real YubiKey in the reader on this Mac.
//
// **This is a probe, not a provisioning tool.** It resets the card it is given, sets its own PINs,
// prints the generated mnemonic to the terminal and declines the paper backup (the record says so).
// Use a card whose contents do not matter, and reset it afterwards.
//
// Why it exists: the ceremony is otherwise only exercised by the simulator (which cannot reach a
// card) and by unit tests (which cannot reach one either). That gap let a defect live where nothing
// could see it — with the card count at 2, the second card was reset and never written (amendment
// 41). What this probe adds is not more APDU replay: it is the shipping state machine, the shipping
// screens' decisions (drawn from the same view-model calls), and the shipping transport.
//
// After **each** pass it asks the card directly — not through the ceremony — what it holds, so a
// ceremony that reports success it did not achieve is caught here rather than in a wallet.
//
// Usage:
//   swift run ceremony-probe [--cards N] [--slot NAME]
//
// See the README in this directory for the signing step the smart-card subsystem requires.

import Foundation
import VaultKit
import YubikeyKit
import YubikeyKitCCID

// MARK: - Output

func say(_ line: String = "") {
    print(line)
    fflush(stdout)
}

func step(_ line: String) { say("\n▸ \(line)") }

func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

// MARK: - The run

@available(macOS 14.0, *)
func run(cards: Int, slotName: String?) async throws {
    // **One transport per session.** `TransportSessionCard` opens a fresh transport for every
    // operation, exactly as the app does (`CardTransports.make`), and that shape is not optional:
    // a shared `SmartCardTransport` that is opened again for the next operation hangs on the second
    // `beginSession()`, which looks exactly like a wedged reader.
    let inner = TransportSessionCard(makeTransport: {
        SmartCardTransport(preferredSlotNames: slotName.map { [$0] } ?? [])
    })

    say("Transport: USB-C (CCID), one session per operation (as the app does)")
    say("Card as it is now:")
    let before = try await inner.inventory()
    say("  serial \(before.serial ?? "not reported")  applet \(before.openPGPVersion)  factory fresh: \(before.isFactoryFresh)")
    for slot in KeySlot.allCases {
        say("  \(slot.displayName): occupied \(before.holdsKey(in: slot))")
    }

    // The second pass onward reports a serial the card does not have: see `SerialSwappingCard`.
    let card = SerialSwappingCard(inner: inner, serialFor: { pass in
        pass == 0 ? nil : String(format: "%08X", 0xF0F0_F0F0 + UInt32(pass))
    })
    let ceremony = ProvisioningCeremony(
        card: card,
        transportDescription: "USB-C (CCID, ceremony-probe)",
        appVersion: "ceremony-probe"
    )

    step("Keys: entropy from the card's RNG, then the mnemonic and the derivation")
    try ceremony.begin(mode: .freshGeneration, postureConfirmed: true)
    let commitment = try await ceremony.generateEntropy()
    say("  entropy commitment: \(commitment)")
    try ceremony.advance()
    let words = try ceremony.mnemonicForDisplay()
    say("  mnemonic (this is a probe; a real ceremony would have you write these down):")
    say("    \(words.joined(separator: " "))")
    // The probe has no steel plate, and the backup is optional by design: decline it, so the
    // record says plainly that no paper copy exists.
    try ceremony.declineMnemonicBackup()
    let keys = try ceremony.deriveKeys()
    say("  secp256k1 \(keys.secp256k1.evmAddress ?? "-")  \(keys.secp256k1.publicKeyHex)")
    say("  ed25519   \(keys.ed25519.identity)")
    try ceremony.advance()
    try ceremony.setCardCount(cards)
    say("  cards this run will write: \(ceremony.cardCount)")

    // Per-card PINs, deliberately different for each pass: the app's own path is that every card
    // gets its own (amendment 40), and a probe that reused one would not notice if it did not.
    let pins = [
        (user: "246810", admin: "87654321"),
        (user: "135790", admin: "12345678"),
        (user: "112233", admin: "99887766"),
    ]

    for index in 0..<cards {
        card.startPass(index)
        step("Card \(index + 1) of \(cards)")

        let inventory = try await ceremony.inspectCard()
        say("  inventory: serial \(inventory.serial ?? "-")  signature occupied=\(inventory.holdsKey(in: .signature)) auth=\(inventory.holdsKey(in: .authentication))")
        try ceremony.advance()

        say("  reset…")
        try await ceremony.resetCard(acknowledgingDestruction: true)

        let pin = pins[min(index, pins.count - 1)]
        say("  PINs: user \(pin.user) (\(pin.user.count) digits), admin \(pin.admin) (\(pin.admin.count) digits)")
        try await ceremony.setPINs(userPIN: Array(pin.user.utf8), adminPIN: Array(pin.admin.utf8))

        say("  retry limits: 4 / 4…")
        try await ceremony.setPINRetries(user: 4, admin: 4)

        say("  write and verify (keys, then the policy, then the manifest, then read all of it back)…")
        let readBack = try await ceremony.importAndVerify()
        for algorithm in KeyAlgorithm.allCases {
            guard let result = readBack[algorithm] else { continue }
            say("    \(algorithm.displayName): card \(result.cardPublicKeyHex.prefix(16))… matches derived: \(result.matches)")
        }
        try ceremony.advance()
        say("  the ceremony is now at: \(ceremony.step.title)")

        // Independent of the ceremony, and of the view model: what does the card itself say?
        let after = try await inner.inventory()
        let uif = KeySlot.allCases
            .compactMap { slot in after.touchPolicy[slot].map { (slot.displayName, String(format: "%02x", $0)) } }
            .map { "\($0.0)=\($0.1)" }
            .joined(separator: " ")
        let pw1 = after.pwStatusBytes?.first.map { String(format: "%02x", $0) } ?? "-"
        say("  card reports: signature occupied=\(after.holdsKey(in: .signature)) auth=\(after.holdsKey(in: .authentication))  UIF \(uif)  PW1 \(pw1)")
        say("  manifest on card: \(try await inner.readPairingManifest().map { "\($0.count) bytes" } ?? "none")")
        for slot in KeySlot.allCases {
            let key = try await inner.readPublicKey(slot: slot)
            let expected = slot == .signature ? keys.secp256k1.publicKey : keys.ed25519.publicKey
            say("  \(slot.displayName) public key \(hex(key))")
            say("    \(key == expected ? "== the key derived here ✔" : "!= the key derived here ✘")")
        }
    }

    // The pairing codes and the record, so the probe covers the whole ceremony rather than stopping
    // at the write step.
    _ = try ceremony.buildPairingURs(style: .keystoneLegacy, chainCodeAcknowledged: true)
    ceremony.confirmPairingAddressMatches(true)
    try ceremony.advance()
    let report = ceremony.finish()

    step("Report")
    for line in report.printableLines() { say("  \(line)") }

    step("Afterwards")
    let lastPIN = pins[min(cards - 1, pins.count - 1)]
    say("  The card holds the keys of the last pass (user PIN \(lastPIN.user), admin PIN \(lastPIN.admin)).")
    say("  Reset it before using it for anything real:  ykman openpgp reset -f")
}

// MARK: - Entry point

@main
struct Main {
    static func main() async {
        var cards = 1
        var slotName: String?
        var arguments = Array(CommandLine.arguments.dropFirst())
        while let first = arguments.first {
            arguments.removeFirst()
            switch first {
            case "--cards":
                cards = Int(arguments.first ?? "") ?? 1
                if !arguments.isEmpty { arguments.removeFirst() }
            case "--slot":
                slotName = arguments.first
                if !arguments.isEmpty { arguments.removeFirst() }
            default:
                say("usage: ceremony-probe [--cards N] [--slot NAME]")
                return
            }
        }
        guard #available(macOS 14.0, *) else {
            say("macOS 14 or newer is required for the CryptoTokenKit transport.")
            return
        }
        do {
            try await run(cards: max(1, cards), slotName: slotName)
            say("\n✔ probe finished")
        } catch {
            say("\n✘ probe failed: \(error)")
            if let ceremonyError = error as? CeremonyError {
                say("  \(ceremonyError.userFacingDescription)")
            }
            if let cardError = error as? CardError {
                say("  \(cardError.userFacingDescription)")
            }
            exit(1)
        }
    }
}
