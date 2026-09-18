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

    private let inner = MockYubikeyTransport(
        transportName: "Simulated YubiKey (debug)",
        serial: 0x00DE_71A5,
        openPGPVersion: "3.4"
    )

    func open() async throws { try await inner.open() }
    func send(_ command: CommandAPDU) async throws -> ResponseAPDU { try await inner.send(command) }
    func close() async { await inner.close() }
}
#endif
