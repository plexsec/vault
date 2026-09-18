import Foundation
@testable import VaultKit

/// Scripted YubiKey used by the ceremony tests. Records every call so tests can
/// assert the exact APDU-level sequence the ceremony produced, and can be told
/// to fail at a chosen point.
final class MockSignerCard: SignerCard {

    enum Call: Equatable {
        case inventory
        case reset
        case setPINs
        case applyPolicy(adminPIN: [UInt8])
        case importSignatureKey(fingerprint: String)
        case readSignaturePublicKey
        case signatureCounter
        case putDataObject(tag: UInt16)
        case getDataObject(tag: UInt16)
    }

    /// Failure injection.
    enum FailurePoint: Equatable {
        case none
        case inventory
        case reset
        case setPINs
        case applyPolicy
        case keyImport
        case readPublicKey
        case counter
    }

    private(set) var calls: [Call] = []
    var failurePoint: FailurePoint = .none

    // Card state
    var inventoryResult: CardInventory
    var storedPublicKeyOverride: [UInt8]?
    var counterValue: UInt32
    private(set) var storedPrivateKey: [UInt8]?
    private(set) var storedFingerprint: [UInt8]?
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
        algorithmAttributes: nil,
        pwStatusBytes: [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F],
        hasSignatureKey: false,
        signatureCounter: 0,
        isFactoryFresh: true
    )

    // MARK: SignerCard

    func inventory() async throws -> CardInventory {
        calls.append(.inventory)
        if failurePoint == .inventory { throw CardError.transportUnavailable("mock") }
        var result = inventoryResult
        // A key present in the injected inventory counts as pre-existing until a
        // reset clears it, mirroring a real card that already holds a key.
        result.hasSignatureKey = storedPrivateKey != nil || inventoryResult.hasSignatureKey
        result.signatureCounter = counterValue
        return result
    }

    func reset(adminPIN: [UInt8]) async throws {
        calls.append(.reset)
        if failurePoint == .reset { throw CardError.pinIncorrect(retriesRemaining: 2) }
        resetCount += 1
        storedPrivateKey = nil
        storedFingerprint = nil
        dataObjects = [:]
        inventoryResult.hasSignatureKey = false
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
        dataObjects[0xD6] = [0x02, 0x20]
        dataObjects[0xC4] = [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F]
        inventoryResult.pwStatusBytes = [0x00, 0x06, 0x00, 0x7F, 0x00, 0x7F]
    }

    func importSignatureKey(
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws {
        calls.append(.importSignatureKey(fingerprint: fingerprint.hexString))
        // Mirrors a real card: a new session must re-verify the Admin PIN.
        guard adminPIN == lastSetAdminPIN else {
            throw CardError.conditionsNotSatisfied
        }
        if failurePoint == .keyImport { throw CardError.keyImportRejected }
        if storedPrivateKey != nil { throw CardError.signatureSlotOccupied }
        let raw = privateKey.materializedCopy()
        storedPrivateKey = raw
        storedFingerprint = fingerprint
        storedCreationTime = creationTime
        inventoryResult.hasSignatureKey = true
        inventoryResult.isFactoryFresh = false
    }

    func readSignaturePublicKey() async throws -> [UInt8] {
        calls.append(.readSignaturePublicKey)
        if failurePoint == .readPublicKey { throw CardError.conditionsNotSatisfied }
        if let override = storedPublicKeyOverride { return override }
        guard let storedPrivateKey else { throw CardError.conditionsNotSatisfied }
        return try Secp256k1.publicKey(fromPrivateKey: storedPrivateKey)
    }

    func signatureCounter() async throws -> UInt32 {
        calls.append(.signatureCounter)
        if failurePoint == .counter { throw CardError.transportUnavailable("mock") }
        return counterValue
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
