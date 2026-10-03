// Built wherever CryptoTokenKit exists, which is iOS **and macOS**. The USB-C
// CCID path is the app's, but the same code compiles and runs on a Mac, which is
// the only way a hardware check can drive the *shipping* transport instead of a
// desktop APDU replay (docs/m0-hardware-verification.md item 18). No call site
// needs a platform branch: with the macOS 26 SDK, `getSlot(withName:)` and
// `makeSmartCard()` are async on both platforms, so the code below is unchanged.
#if canImport(CryptoTokenKit)

import CryptoTokenKit
import Foundation
import VaultKit
import YubikeyKit

/// USB-C transport: the YubiKey presents itself as a CCID smart card, which
/// CryptoTokenKit exposes as a `TKSmartCard` slot.
///
/// Why this replaced the YubiKey 5Ci / Lightning path:
/// * `TKSmartCard` is an Apple framework, so no MFi agreement or vendor SDK is
///   needed — the 5Ci route required a Yubico SDK that YubiKit 4.x dropped.
/// * A wired session has no artificial timeout and gives more reliable touch
///   confirmation than NFC.
/// * Requires a USB-C iPhone (15 or later) or USB-C iPad.
///
/// This transport deliberately uses the **low-level** `TKSmartCard.transmit(_:)`
/// rather than the high-level `send(ins:p1:p2:data:le:)`. The high-level call
/// throws when the card returns any status word other than 0x9000, which would
/// destroy the status-word-driven logic this app depends on: `63Cx` (PIN retries
/// remaining), `6983` (blocked), `6A88` (no key present) and `6Cxx` (wrong Le)
/// are all meaningful results, not transport failures. `transmit` returns the
/// raw response including SW1SW2 and only fails on actual communication errors.
///
/// Behaviour that milestone M0 must confirm on hardware: whether a directly
/// attached (rather than reader-hosted) CCID device is enumerated without an
/// additional entitlement, and whether the polling fallback below is needed.
@available(iOS 26.0, macOS 14.0, *)
public final class SmartCardTransport: YubikeyTransport {
    public let transportName = "USB-C (CCID)"

    private let preferredSlotNames: [String]
    private var card: TKSmartCard?
    private let discoveryTimeout: TimeInterval
    private let pollInterval: Duration

    public init(
        preferredSlotNames: [String] = [],
        discoveryTimeout: TimeInterval = 10,
        pollInterval: Duration = .milliseconds(250)
    ) {
        self.preferredSlotNames = preferredSlotNames
        self.discoveryTimeout = discoveryTimeout
        self.pollInterval = pollInterval
    }

    public func open() async throws {
        guard let slotManager = TKSmartCardSlotManager.default else {
            throw CardError.transportUnavailable("the smart-card subsystem is unavailable on this device")
        }

        let deadline = Date().addingTimeInterval(discoveryTimeout)
        repeat {
            // `slotNames` is re-read every iteration: a YubiKey plugged in after
            // the app launched must still be discovered. `TKSmartCardSlot.state`
            // observation is not available on every OS version, hence polling.
            for name in orderedCandidates(from: slotManager.slotNames) {
                guard let slot = await slotManager.getSlot(withName: name) else { continue }
                guard let smartCard = await slot.makeSmartCard() else { continue }
                do {
                    try await smartCard.beginSession()
                } catch {
                    continue
                }
                // v1 never sends an extended-length or chained APDU (the largest
                // command is ~41 bytes), and both are left off to avoid firmware
                // quirks in the card's T=1 handling.
                smartCard.useExtendedLength = false
                smartCard.useCommandChaining = false
                smartCard.cla = 0x00
                card = smartCard
                return
            }
            try? await Task.sleep(for: pollInterval)
        } while Date() < deadline

        throw CardError.transportUnavailable(
            "no YubiKey found on USB-C. Confirm the key is plugged in and that its CCID interface is enabled (`ykman config usb --list` should list CCID)."
        )
    }

    private func orderedCandidates(from names: [String]) -> [String] {
        guard !preferredSlotNames.isEmpty else { return names }
        let preferred = names.filter { name in
            preferredSlotNames.contains { name.localizedCaseInsensitiveContains($0) }
        }
        let rest = names.filter { !preferred.contains($0) }
        return preferred + rest
    }

    public func send(_ command: CommandAPDU) async throws -> ResponseAPDU {
        guard let card, card.isValid else {
            throw CardError.transportUnavailable("the YubiKey was removed")
        }
        let raw = try await card.transmit(Data(command.bytes))
        do {
            return try ResponseAPDU(bytes: [UInt8](raw))
        } catch {
            throw CardError.malformedResponse("response was shorter than a status word")
        }
    }

    public func close() async {
        card?.endSession()
        card = nil
    }

    /// Diagnostic used by the UI when nothing is found, so the operator gets an
    /// actionable message instead of a bare failure.
    public func describeAvailableSlots() async -> [String] {
        guard let slotManager = TKSmartCardSlotManager.default else { return [] }
        var out: [String] = []
        for name in slotManager.slotNames {
            let slot = await slotManager.getSlot(withName: name)
            out.append("\(name) [\(slot.map { String(describing: $0.state) } ?? "unknown")]")
        }
        return out
    }
}

#endif
