import Foundation
import VaultKit

/// A second card, without a second card: every operation goes to the card in the reader, and the
/// **serial** is what the probe changes for the passes after the first.
///
/// One physical YubiKey is enough to exercise the multi-card path, because the serial is the only
/// thing the ceremony uses to tell one card from another — it is what the duplicate check compares
/// against, and what each card's pairing manifest carries. Everything else the probe does is real:
/// the reset, the PINs, the imports, the policy and the manifest all go to the hardware.
///
/// This is a probe affordance and not a claim about the app: a real reader has one card in it, and
/// `ProvisioningCeremony.inspectCard` refuses a serial it has already written in the same run.
@available(macOS 14.0, *)
final class SerialSwappingCard: SignerCard {
    private let inner: SignerCard
    private let serialFor: (Int) -> String?
    private var pass = 0

    /// - Parameter serialFor: the serial to report for pass `n` (0-based), or `nil` to report what
    ///   the card really says.
    init(inner: SignerCard, serialFor: @escaping (Int) -> String?) {
        self.inner = inner
        self.serialFor = serialFor
    }

    func startPass(_ index: Int) { pass = index }

    func inventory() async throws -> CardInventory {
        var result = try await inner.inventory()
        if let serial = serialFor(pass) { result.serial = serial }
        return result
    }

    func readSigningIdentity(slot: KeySlot) async throws -> SigningCardIdentity {
        try await inner.readSigningIdentity(slot: slot)
    }

    func randomBytes(count: Int) async throws -> SensitiveBytes { try await inner.randomBytes(count: count) }

    func reset() async throws { try await inner.reset() }

    func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        try await inner.setPINs(userPIN: userPIN, adminPIN: adminPIN)
    }

    func setPINRetries(user: Int, reset: Int, admin: Int, adminPIN: [UInt8]) async throws {
        try await inner.setPINRetries(user: user, reset: reset, admin: admin, adminPIN: adminPIN)
    }

    func applyPolicy(adminPIN: [UInt8]) async throws { try await inner.applyPolicy(adminPIN: adminPIN) }

    func importKey(
        slot: KeySlot,
        algorithm: KeyAlgorithm,
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws {
        try await inner.importKey(
            slot: slot,
            algorithm: algorithm,
            privateKey: privateKey,
            fingerprint: fingerprint,
            creationTime: creationTime,
            adminPIN: adminPIN
        )
    }

    func readPublicKey(slot: KeySlot) async throws -> [UInt8] { try await inner.readPublicKey(slot: slot) }

    func putDataObject(_ tag: UInt16, value: [UInt8]) async throws {
        try await inner.putDataObject(tag, value: value)
    }

    func getDataObject(_ tag: UInt16) async throws -> [UInt8] { try await inner.getDataObject(tag) }

    func readPairingManifest() async throws -> [UInt8]? { try await inner.readPairingManifest() }

    func writePairingManifest(_ manifest: [UInt8], adminPIN: [UInt8]) async throws {
        try await inner.writePairingManifest(manifest, adminPIN: adminPIN)
    }

    func sign(digest: [UInt8], userPIN: [UInt8]) async throws -> [UInt8] {
        try await inner.sign(digest: digest, userPIN: userPIN)
    }
}
