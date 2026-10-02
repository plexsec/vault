import Foundation
@testable import VaultKit

/// Scripted YubiKey used by the ceremony tests. Records every call so tests can
/// assert the exact APDU-level sequence the ceremony produced, and can be told
/// to fail at a chosen point.
///
/// It models both signing-capable slots independently, so a ceremony that writes
/// the wrong key into a slot (or reads the wrong slot back) fails here rather
/// than passing silently.
final class MockSignerCard: SignerCard {

    enum Call: Equatable {
        case inventory
        case reset
        case setPINs
        case applyPolicy(adminPIN: [UInt8])
        case importKey(slot: KeySlot, algorithm: KeyAlgorithm, fingerprint: String)
        case readPublicKey(slot: KeySlot)
        case signatureCounter
        case randomBytes(count: Int)
        case putDataObject(tag: UInt16)
        case getDataObject(tag: UInt16)
    }

    /// Failure injection.
    enum FailurePoint: Equatable {
        case none
        case inventory
        /// The card answered with a definitive rejection (a wrong PIN).
        case reset
        /// The card never answered: the session dropped mid-reset, so the
        /// card's state is unknown.
        case resetTransport
        case setPINs
        case applyPolicy
        case keyImport
        case readPublicKey
        case counter
        case challenge
    }

    private(set) var calls: [Call] = []
    var failurePoint: FailurePoint = .none

    // Card state
    var inventoryResult: CardInventory
    var storedPublicKeyOverride: [KeySlot: [UInt8]] = [:]
    var counterValue: UInt32
    /// Random bytes returned by `randomBytes`. Defaults to all-zero so the
    /// derived keys match the `Expected` values in the tests.
    var challengeBytes: [UInt8] = [UInt8](repeating: 0, count: 32)
    private(set) var storedPrivateKeys: [KeySlot: [UInt8]] = [:]
    private(set) var storedFingerprints: [KeySlot: [UInt8]] = [:]
    private(set) var storedCreationTime: Date?
    private(set) var dataObjects: [UInt16: [UInt8]] = [:]
    private(set) var appliedPolicy = false
    private(set) var resetCount = 0
    private(set) var pinChangeCount = 0
    /// The Admin PIN last provisioned, used to model per-session VERIFY state.
    private(set) var lastSetAdminPIN: [UInt8] = Array("12345678".utf8)

    init(
        inventory: CardInventory = MockSignerCard.factoryFreshCard,
        counter: UInt32 = 0
    ) {
        self.inventoryResult = inventory
        self.counterValue = counter
    }

    static let factoryFreshCard = CardInventory(
        openPGPVersion: "3.4",
        manufacturer: "Yubico",
        serial: "00000000",
        pwStatusBytes: [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F],
        occupiedSlots: [],
        signatureCounter: 0,
        isFactoryFresh: true
    )

    /// Convenience accessors for assertions.
    func storedPrivateKey(_ slot: KeySlot) -> [UInt8]? { storedPrivateKeys[slot] }
    func storedFingerprint(_ slot: KeySlot) -> [UInt8]? { storedFingerprints[slot] }
    func hasKey(in slot: KeySlot) -> Bool { storedPrivateKeys[slot] != nil }

    // MARK: SignerCard

    func inventory() async throws -> CardInventory {
        calls.append(.inventory)
        if failurePoint == .inventory { throw CardError.transportUnavailable("mock") }
        var result = inventoryResult
        // A key present in the injected inventory counts as pre-existing until a
        // reset clears it, mirroring a real card that already holds a key.
        result.occupiedSlots.formUnion(storedPrivateKeys.keys)
        result.signatureCounter = counterValue
        return result
    }

    func reset(adminPIN: [UInt8]) async throws {
        calls.append(.reset)
        if failurePoint == .reset { throw CardError.pinIncorrect(retriesRemaining: 2) }
        if failurePoint == .resetTransport {
            throw CardError.transportUnavailable("the NFC session ended unexpectedly, so this operation did not complete")
        }
        resetCount += 1
        storedPrivateKeys = [:]
        storedFingerprints = [:]
        dataObjects = [:]
        inventoryResult.occupiedSlots = []
        inventoryResult.isFactoryFresh = true
        counterValue = 0
    }

    func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        calls.append(.setPINs)
        if failurePoint == .setPINs { throw CardError.conditionsNotSatisfied }
        pinChangeCount += 1
        lastSetAdminPIN = adminPIN
    }

    func applyPolicy(adminPIN: [UInt8]) async throws {
        calls.append(.applyPolicy(adminPIN: adminPIN))
        if failurePoint == .applyPolicy { throw CardError.unexpectedStatusWord(sw1: 0x6A, sw2: 0x80) }
        appliedPolicy = true
        // Both signing-capable slots get the touch policy; 0xC4 is global.
        dataObjects[0xD6] = [0x02, 0x20]
        dataObjects[0xD8] = [0x02, 0x20]
        dataObjects[0xC4] = [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F]
        inventoryResult.pwStatusBytes = [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F]
    }

    func importKey(
        slot: KeySlot,
        algorithm: KeyAlgorithm,
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws {
        calls.append(.importKey(slot: slot, algorithm: algorithm, fingerprint: fingerprint.hexString))
        // Mirrors a real card: a new session must re-verify the Admin PIN.
        guard adminPIN == lastSetAdminPIN else {
            throw CardError.conditionsNotSatisfied
        }
        if failurePoint == .keyImport { throw CardError.keyImportRejected }
        // A real card answers 0x6A80, which the status mapper turns into
        // keyImportRejected; the mock mirrors that rather than inventing a case.
        if storedPrivateKeys[slot] != nil { throw CardError.keyImportRejected }
        storedPrivateKeys[slot] = privateKey.materializedCopy()
        storedFingerprints[slot] = fingerprint
        storedCreationTime = creationTime
        inventoryResult.occupiedSlots.insert(slot)
        inventoryResult.isFactoryFresh = false
    }

    func readPublicKey(slot: KeySlot) async throws -> [UInt8] {
        calls.append(.readPublicKey(slot: slot))
        if failurePoint == .readPublicKey { throw CardError.conditionsNotSatisfied }
        if let override = storedPublicKeyOverride[slot] { return override }
        guard let secret = storedPrivateKeys[slot] else { throw CardError.conditionsNotSatisfied }
        switch slot {
        case .signature:
            return try Secp256k1.publicKey(fromPrivateKey: secret)
        case .authentication:
            return try Ed25519.publicKey(fromSeed: secret)
        }
    }

    func signatureCounter() async throws -> UInt32 {
        calls.append(.signatureCounter)
        if failurePoint == .counter { throw CardError.transportUnavailable("mock") }
        return counterValue
    }

    func randomBytes(count: Int) async throws -> SensitiveBytes {
        calls.append(.randomBytes(count: count))
        if failurePoint == .challenge { throw CardError.transportUnavailable("mock") }
        var bytes = challengeBytes
        while bytes.count < count { bytes.append(0) }
        return SensitiveBytes(copying: Array(bytes.prefix(count)))
    }

    func putDataObject(_ tag: UInt16, value: [UInt8]) async throws {
        calls.append(.putDataObject(tag: tag))
        dataObjects[tag] = value
    }

    func getDataObject(_ tag: UInt16) async throws -> [UInt8] {
        calls.append(.getDataObject(tag: tag))
        guard let value = dataObjects[tag] else {
            throw CardError.unexpectedStatusWord(sw1: 0x6A, sw2: 0x88)
        }
        return value
    }
}
