// The smallest check that a YubiKey is reachable from this Mac at all: open the smart-card slot,
// select the OpenPGP applet, read one data object and print the status words.
//
// Run this first when `ceremony-probe` reports "the smart-card subsystem is unavailable": that is
// almost always the `com.apple.security.smartcard` entitlement missing from the binary (see the
// README in this directory), not a problem with the card or the reader.
//
// Usage: swift run slot-probe

import CryptoTokenKit
import Foundation

let selectOpenPGP: [UInt8] = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00]
let getApplicationData: [UInt8] = [0x00, 0xCA, 0x00, 0x6E, 0x00]

func hex(_ bytes: some Collection<UInt8>) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

@available(macOS 14.0, *)
func probe() async {
    guard let manager = TKSmartCardSlotManager.default else {
        print("✘ no smart-card subsystem: is this binary signed with com.apple.security.smartcard?")
        print("  system_profiler SPSmartCardsDataType should list a reader with a YubiKey in it.")
        return
    }
    print("slots: \(manager.slotNames)")
    for name in manager.slotNames {
        guard let slot = await manager.getSlot(withName: name) else { continue }
        print("slot \(name): state \(slot.state.rawValue)")
        guard let card = await slot.makeSmartCard() else {
            print("  no card in this slot")
            continue
        }
        do {
            try await card.beginSession()
        } catch {
            print("  beginSession failed: \(error)")
            continue
        }
        // What the app's own transport sets: no extended length, no chaining, CLA 0.
        card.useExtendedLength = false
        card.useCommandChaining = false
        card.cla = 0x00
        for (label, apdu) in [("SELECT OpenPGP", selectOpenPGP), ("GET DATA 0x6E", getApplicationData)] {
            do {
                let response = try await card.transmit(Data(apdu))
                let bytes = [UInt8](response)
                let statusWord = hex(bytes.suffix(2))
                print("  \(label): \(bytes.count) bytes, SW \(statusWord)")
                if statusWord == "613b" || statusWord.hasPrefix("61") {
                    print("    (the applet has more to say: `61xx` is answered with GET RESPONSE)")
                }
            } catch {
                print("  \(label) failed: \(error)")
            }
        }
        card.endSession()
    }
}

if #available(macOS 14.0, *) {
    await probe()
} else {
    print("macOS 14 or newer is required for the CryptoTokenKit transport.")
}
