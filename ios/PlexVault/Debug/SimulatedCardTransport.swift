#if DEBUG
import Foundation
import VaultKit
import YubikeyKit

/// DEBUG-only bridge to the package's simulated YubiKey.
///
/// Both this file and `MockYubikeyTransport.swift` are excluded from Release:
/// this one by `#if DEBUG`, the mock by `EXCLUDED_SOURCE_FILE_NAMES` in
/// project.yml. The mock is compiled into the app target rather than linked as a
/// package product, because linking the product left its symbols in the shipped
/// binary. `tools/audit-release.sh` asserts the marker strings are absent.
///
/// The simulation is a real APDU responder rather than a stub that answers
/// "success": it enforces PIN verification, refuses a second key import into an
/// occupied slot, and returns 6A88 when no key is present, so the DEBUG flow
/// exercises the same code paths the real card does.
@available(iOS 26.0, *)
final class SimulatedCardTransport: YubikeyTransport {
    let transportName = "Simulated YubiKey (debug)"

    /// A real YubiKey keeps its PINs and keys on the card between NFC taps, but
    /// `TransportSessionCard` opens a *fresh* transport for every step. Sharing
    /// one mock behind every `SimulatedCardTransport` instance reproduces that
    /// physical persistence: without it each step would see a factory-fresh card
    /// and the Admin PIN set by the PIN step would already be gone by the time
    /// `applyPolicy` verifies it.
    private static let shared = MockYubikeyTransport(
        transportName: "Simulated YubiKey (debug)",
        serial: 0x00DE_71A5,
        openPGPVersion: "3.4"
    )

    private let inner = SimulatedCardTransport.shared

    func open() async throws { try await inner.open() }
    func send(_ command: CommandAPDU) async throws -> ResponseAPDU { try await inner.send(command) }
    func close() async { await inner.close() }
}
#endif
