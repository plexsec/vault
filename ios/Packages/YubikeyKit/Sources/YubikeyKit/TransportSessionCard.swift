import Foundation
import VaultKit

/// Wraps a transport factory so that every `SignerCard` operation runs in its own
/// freshly opened session.
///
/// This exists because of a hard physical constraint: an NFC reader session lasts
/// about 60 seconds, while a provisioning ceremony involves typing PINs, writing
/// down 24 words and cross-checking an address — minutes at least. A single
/// session cannot span the ceremony, and VERIFY state does not survive a session
/// boundary, which is why the protected writes re-verify the Admin PIN
/// themselves (`applyPolicy`, `importKey`).
///
/// For USB-C the extra open/close is cheap; for the simulated transport it is a
/// no-op. The important property is that the ceremony code cannot accidentally
/// depend on cross-step session state.
public final class TransportSessionCard: SignerCard {
    public typealias TransportFactory = () -> YubikeyTransport

    private let makeTransport: TransportFactory
    private let onSessionStart: (@Sendable (String) -> Void)?
    private let onSessionEnd: (@Sendable () -> Void)?

    public init(
        makeTransport: @escaping TransportFactory,
        onSessionStart: (@Sendable (String) -> Void)? = nil,
        onSessionEnd: (@Sendable () -> Void)? = nil
    ) {
        self.makeTransport = makeTransport
        self.onSessionStart = onSessionStart
        self.onSessionEnd = onSessionEnd
    }

    /// Runs `body` inside a fresh session.
    public func withSession<T>(_ body: (OpenPGPCard) async throws -> T) async throws -> T {
        let transport = makeTransport()
        let card = OpenPGPCard(transport: transport)
        onSessionStart?(transport.transportName)
        do {
            try await card.open()
        } catch {
            await card.close()
            onSessionEnd?()
            throw error
        }
        do {
            let result = try await body(card)
            await card.close()
            onSessionEnd?()
            return result
        } catch {
            await card.close()
            onSessionEnd?()
            throw error
        }
    }

    // MARK: SignerCard

    public func inventory() async throws -> CardInventory {
        try await withSession { try await $0.inventory() }
    }

    public func reset(adminPIN: [UInt8]) async throws {
        try await withSession { try await $0.reset(adminPIN: adminPIN) }
    }

    public func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        try await withSession { try await $0.setPINs(userPIN: userPIN, adminPIN: adminPIN) }
    }

    public func applyPolicy(adminPIN: [UInt8]) async throws {
        try await withSession { try await $0.applyPolicy(adminPIN: adminPIN) }
    }

    public func setPINRetries(user: Int, reset: Int, admin: Int, adminPIN: [UInt8]) async throws {
        try await withSession {
            try await $0.setPINRetries(user: user, reset: reset, admin: admin, adminPIN: adminPIN)
        }
    }

    /// VERIFY PW1 and PSO:CDS **in the same session**: VERIFY state does not
    /// survive a session boundary, so splitting them would fail on hardware with
    /// `6982` while passing against a card that keeps state in memory.
    ///
    /// No retry loop, and none is possible: `withSession` runs the two APDUs once
    /// and any error propagates. A lost response may still have produced a
    /// signature, and design.md §5.2 rule 1 forbids asking again.
    public func sign(digest: [UInt8], userPIN: [UInt8]) async throws -> [UInt8] {
        try await withSession { card in
            try await card.verifyUserPIN(userPIN)
            return try await card.computeDigitalSignature(digest: digest)
        }
    }

    public func importKey(
        slot: KeySlot,
        algorithm: KeyAlgorithm,
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws {
        try await withSession {
            try await $0.importKey(
                slot: slot,
                algorithm: algorithm,
                privateKey: privateKey,
                fingerprint: fingerprint,
                creationTime: creationTime,
                adminPIN: adminPIN
            )
        }
    }

    public func readPublicKey(slot: KeySlot) async throws -> [UInt8] {
        try await withSession { try await $0.readPublicKey(slot: slot) }
    }

    public func signatureCounter() async throws -> UInt32 {
        try await withSession { try await $0.signatureCounter() }
    }

    public func randomBytes(count: Int) async throws -> SensitiveBytes {
        try await withSession { try await $0.randomBytes(count: count) }
    }

    public func putDataObject(_ tag: UInt16, value: [UInt8]) async throws {
        try await withSession { try await $0.putDataObject(tag, value: value) }
    }

    public func getDataObject(_ tag: UInt16) async throws -> [UInt8] {
        try await withSession { try await $0.getDataObject(tag) }
    }

    /// Each of these opens its own session like every other card operation. For
    /// the manifest that is not incidental: the write re-verifies PW3 inside the
    /// session, and the read is the one card operation a re-pair performs at all,
    /// so it must work with no PIN entered and no prior session.
    public func readPairingManifest() async throws -> [UInt8]? {
        try await withSession { try await $0.readPairingManifest() }
    }

    public func writePairingManifest(_ manifest: [UInt8], adminPIN: [UInt8]) async throws {
        try await withSession { try await $0.writePairingManifest(manifest, adminPIN: adminPIN) }
    }
}
