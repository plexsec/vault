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
        case setPINRetries(user: Int, admin: Int)
        case importKey(slot: KeySlot, algorithm: KeyAlgorithm, fingerprint: String)
        case readPublicKey(slot: KeySlot)
        case signatureCounter
        case randomBytes(count: Int)
        case putDataObject(tag: UInt16)
        case getDataObject(tag: UInt16)
        case readPairingManifest
        case writePairingManifest(byteCount: Int)
        case verifyUserPIN
        case computeDigitalSignature(digestHex: String)
        case signInSession(digestHex: String)
    }

    /// Failure injection.
    enum FailurePoint: Equatable {
        case none
        case inventory
        /// The reset could not block the PIN counters it needs blocked: the card
        /// answered, but it is changed (attempts burnt) rather than erased.
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
        case pairingManifest
        /// The card has no private-use data object to write to (an applet that
        /// does not implement the optional objects).
        case pairingManifestUnsupported
        /// `PSO:CDS` failed after the applet had been asked to sign: the response
        /// was lost. Whatever the card did, the app never saw it.
        case signatureTransport
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
    /// The pairing manifest as the card holds it. `nil` is a never-written
    /// (empty) object, which is what a reset leaves behind. Tests seed it directly
    /// to model a card provisioned by an earlier version or by another app.
    var pairingManifestBytes: [UInt8]?
    /// Mirrors `CardInventory.pairingManifest`; `false` makes the read throw the
    /// way a card without the optional objects does.
    var supportsPairingManifest = true
    /// When set, `readPairingManifest` returns this instead of what was written,
    /// modelling storage that silently keeps something else (or truncates).
    var pairingManifestReadBackOverride: [UInt8]?
    private(set) var resetCount = 0
    private(set) var pinChangeCount = 0
    /// The Admin PIN last provisioned, used to model per-session VERIFY state.
    private(set) var lastSetAdminPIN: [UInt8] = Array("12345678".utf8)
    /// The user PIN last provisioned. `VERIFY PW1` succeeds only against this.
    private(set) var lastSetUserPIN: [UInt8] = Array("246810".utf8)

    // MARK: Signing state

    /// How the card behaves when asked to sign.
    enum SigningBehaviour: Equatable {
        case normal
        /// The PIN is wrong; the card reports the retries it has left.
        case wrongPIN(retriesRemaining: Int)
        /// PW1 is blocked (`6983`); no PIN will work until a reset.
        case pinBlocked
        /// `6982`: the applet wants a PIN it has not been given in this session.
        case pinNotVerified
        /// The card answered `6985`: the touch (UIF) was not completed in time.
        case touchNotCompleted
    }

    var signingBehaviour: SigningBehaviour = .normal
    /// Real cards may return `s > n/2`. The app must normalise it, so the mock can
    /// be told to mimic that.
    var returnsHighS = false
    /// Digests the card was asked to sign, in order. The ceremony must call this
    /// exactly once per request (design.md §5.2 rule 1).
    private(set) var signedDigests: [[UInt8]] = []
    /// PINs presented to `VERIFY PW1`.
    private(set) var presentedPINs: [[UInt8]] = []

    /// Signatures produced by `tools/derive` (an independent implementation), so
    /// the ceremony's verification path is exercised for real rather than against
    /// a stub. See `signing_vectors.json` and PROVENANCE in the fixtures directory.
    struct SigningFixture: Decodable {
        struct Signature: Decodable {
            let name: String
            let digest: String
            let r: String
            let s: String
            let highS: String
            let recid: UInt8
            let recidHighS: UInt8
            let der: String
            let derHighS: String
            let legacyVChain1: UInt64
            let typedV: UInt64

            enum CodingKeys: String, CodingKey {
                case name, digest, r, s, recid, der
                case highS = "high_s"
                case recidHighS = "recid_high_s"
                case derHighS = "der_high_s"
                case legacyVChain1 = "legacy_v_chain_1"
                case typedV = "typed_v"
            }
        }

        let publicKeyCompressed: String
        let address: String
        let signatures: [Signature]

        enum CodingKeys: String, CodingKey {
            case publicKeyCompressed, address, signatures
        }
    }

    static let signingFixture: SigningFixture = {
        guard let data = try? FixtureLoader.data("signing_vectors", extension: "json"),
              let fixture = try? JSONDecoder().decode(SigningFixture.self, from: data)
        else {
            preconditionFailure("signing_vectors.json is missing or malformed")
        }
        return fixture
    }()

    static var signingPublicKey: [UInt8] { [UInt8](try! Hex.decode(signingFixture.publicKeyCompressed)) }

    /// Makes this card look like one provisioned with the fixture key: the
    /// signature slot holds it and the inventory reports it.
    func loadSigningFixtureKey() {
        storedPublicKeyOverride[.signature] = Self.signingPublicKey
        inventoryResult.occupiedSlots.insert(.signature)
        inventoryResult.isFactoryFresh = false
    }

    func signature(named name: String) -> SigningFixture.Signature? {
        Self.signingFixture.signatures.first { $0.name == name }
    }

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
        pwStatusBytes: [0x00, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03],
        retryCounters: RetryCounters(user: 3, reset: 0, admin: 3),
        // A factory-fresh applet reports `off` for every slot; the policy write's
        // whole job is to make this read `fixed`, and the ceremony reads it back.
        touchPolicy: [.signature: CardPolicy.touchOff, .authentication: CardPolicy.touchOff],
        occupiedSlots: [],
        signatureCounter: 0,
        isFactoryFresh: true,
        // A YubiKey answers `9000` with no data for a private-use object that has
        // never been written, so a factory-fresh card is `.absent`, not
        // `.unsupported`: the tests must exercise the write path, and the
        // degraded path is covered by setting `.unsupported` explicitly.
        pairingManifest: .absent
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

    func reset() async throws {
        calls.append(.reset)
        // The PIN burn is the reset's first act, so "the card refused" is not a
        // failure mode this step has any more: the representative failure is that
        // the counters did not reach zero, which leaves the card changed but not
        // erased (and is classified as an unknown outcome for that reason).
        if failurePoint == .reset { throw CardError.pinBlockingIncomplete(user: 2, admin: 0) }
        if failurePoint == .resetTransport {
            throw CardError.transportUnavailable("the NFC session ended unexpectedly, so this operation did not complete")
        }
        resetCount += 1
        storedPrivateKeys = [:]
        storedFingerprints = [:]
        dataObjects = [:]
        retryLimitUser = 3
        retryLimitAdmin = 3
        inventoryResult.retryCounters = RetryCounters(user: 3, reset: 0, admin: 3)
        // `TERMINATE DF` erases the whole data file, private-use objects included.
        // A mock that kept the manifest across a reset would let a re-pair test
        // pass on a card that in reality has nothing left to pair from. The
        // *capability* survives, though: an applet with no private-use objects
        // still has none after a reset, it is merely empty of data.
        pairingManifestBytes = nil
        inventoryResult.pairingManifest = supportsPairingManifest ? .absent : .unsupported
        inventoryResult.occupiedSlots = []
        inventoryResult.isFactoryFresh = true
        counterValue = 0
    }

    func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        calls.append(.setPINs)
        if failurePoint == .setPINs { throw CardError.conditionsNotSatisfied }
        pinChangeCount += 1
        lastSetAdminPIN = adminPIN
        lastSetUserPIN = userPIN
    }

    /// The retry maximum per password, as the real card holds it after `F2`. Two
    /// numbers, because the applet keeps one counter per password (amendment 32).
    var retryLimitUser = 3
    var retryLimitAdmin = 3
    /// When set, the card answers `9000` to `SET PIN RETRIES` and keeps the old
    /// counters — the failure the read-back in the ceremony exists to catch.
    var retryWritesAreIgnored = false

    func setPINRetries(user: Int, reset: Int, admin: Int, adminPIN: [UInt8]) async throws {
        calls.append(.setPINRetries(user: user, admin: admin))
        // Mirrors the applet: the range is checked before the card is touched.
        for value in [user, reset, admin] {
            guard (1...99).contains(value) else {
                throw CardError.retryCountOutOfRange(requested: value, allowed: 1...99)
            }
        }
        guard !retryWritesAreIgnored else { return }
        retryLimitUser = user
        retryLimitAdmin = admin
        inventoryResult.retryCounters = RetryCounters(
            user: UInt8(user), reset: 0, admin: UInt8(admin)
        )
    }

    func applyPolicy(adminPIN: [UInt8]) async throws {
        calls.append(.applyPolicy(adminPIN: adminPIN))
        if failurePoint == .applyPolicy { throw CardError.unexpectedStatusWord(sw1: 0x6A, sw2: 0x80) }
        appliedPolicy = true
        // Both signing-capable slots get the touch policy; 0xC4 is global.
        dataObjects[0xD6] = [0x02, 0x20]
        dataObjects[0xD8] = [0x02, 0x20]
        dataObjects[0xC4] = [0x00, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03]
        inventoryResult.pwStatusBytes = [0x00, 0x7F, 0x7F, 0x7F, 0x03, 0x00, 0x03]
        // A card that answers `9000` to the UIF writes and stores nothing is the
        // failure the read-back exists to catch, and it is not hypothetical: the
        // applet really discards a slot's policy when that slot's algorithm
        // attributes are written (amendment 26). `uifWritesAreIgnored` reproduces
        // it so the ceremony's gate can be tested.
        guard !uifWritesAreIgnored else { return }
        inventoryResult.touchPolicy[.signature] = 0x02
        inventoryResult.touchPolicy[.authentication] = 0x02
    }

    /// When set, the policy writes answer `9000` and change nothing.
    var uifWritesAreIgnored = false
    /// When set, only this slot's import fails — which models the real case that
    /// matters: one key written, the other refused.
    var refuseImportForSlot: KeySlot?

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
        if failurePoint == .keyImport || refuseImportForSlot == slot {
            throw CardError.keyImportRejected
        }
        // A real card answers 0x6A80, which the status mapper turns into
        // keyImportRejected; the mock mirrors that rather than inventing a case.
        if storedPrivateKeys[slot] != nil { throw CardError.keyImportRejected }
        storedPrivateKeys[slot] = privateKey.materializedCopy()
        storedFingerprints[slot] = fingerprint
        storedCreationTime = creationTime
        inventoryResult.occupiedSlots.insert(slot)
        inventoryResult.isFactoryFresh = false
        // Writing a slot's algorithm attributes resets that slot, and the applet
        // drops its touch policy with it. Verified on real hardware, and the
        // reason the ceremony applies the policy *after* the import: with the old
        // order this line is what silently turned touch off on a provisioned card.
        inventoryResult.touchPolicy[slot] = CardPolicy.touchOff
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

    /// Models the real constraint: the PIN is verified and the digest signed in
    /// one session, and the PIN retry counter is decremented by the card itself.
    func sign(digest: [UInt8], userPIN: [UInt8]) async throws -> [UInt8] {
        calls.append(.signInSession(digestHex: digest.hexString))
        try await verifyUserPIN(userPIN)
        return try await computeDigitalSignature(digest: digest)
    }

    func verifyUserPIN(_ pin: [UInt8]) async throws {
        calls.append(.verifyUserPIN)
        presentedPINs.append(pin)
        switch signingBehaviour {
        case .wrongPIN(let retriesRemaining):
            throw CardError.pinIncorrect(retriesRemaining: retriesRemaining)
        case .pinBlocked:
            throw CardError.pinBlocked
        case .pinNotVerified:
            throw CardError.conditionsNotSatisfied
        case .touchNotCompleted, .normal:
            break
        }
        guard pin == lastSetUserPIN else {
            throw CardError.pinIncorrect(retriesRemaining: 2)
        }
    }

    func computeDigitalSignature(digest: [UInt8]) async throws -> [UInt8] {
        calls.append(.computeDigitalSignature(digestHex: digest.hexString))
        signedDigests.append(digest)
        switch signingBehaviour {
        case .touchNotCompleted:
            throw CardError.conditionsNotSatisfied
        case .pinNotVerified:
            throw CardError.conditionsNotSatisfied
        case .wrongPIN, .pinBlocked, .normal:
            break
        }
        if failurePoint == .signatureTransport { throw CardError.transportUnavailable("mock") }
        guard let signature = Self.signingFixture.signatures.first(where: { $0.digest == digest.hexString }) else {
            // A digest the fixture generator never signed: a real card would sign
            // it, but a test that reaches this point is testing the wrong thing.
            throw CardError.signatureFailed
        }
        // The card increments its counter when it signs, which is what makes the
        // counter evidence that a signature happened.
        counterValue += 1
        let der = returnsHighS ? signature.derHighS : signature.der
        return try Hex.decode(der)
    }

    func readPairingManifest() async throws -> [UInt8]? {
        calls.append(.readPairingManifest)
        if failurePoint == .pairingManifestUnsupported || !supportsPairingManifest {
            throw CardError.unsupportedFeature("this applet has no private-use data object 0x0102")
        }
        if failurePoint == .pairingManifest { throw CardError.transportUnavailable("mock") }
        return pairingManifestReadBackOverride ?? pairingManifestBytes
    }

    func writePairingManifest(_ manifest: [UInt8], adminPIN: [UInt8]) async throws {
        calls.append(.writePairingManifest(byteCount: manifest.count))
        if failurePoint == .pairingManifestUnsupported || !supportsPairingManifest {
            throw CardError.unsupportedFeature("this applet has no private-use data object 0x0102")
        }
        if failurePoint == .pairingManifest { throw CardError.transportUnavailable("mock") }
        // Models the write's real failure mode: PUT DATA of a private-use object
        // requires PW3, and the ceremony re-verifies it in this session.
        guard adminPIN == lastSetAdminPIN else {
            throw CardError.pinIncorrect(retriesRemaining: 2)
        }
        pairingManifestBytes = manifest
        inventoryResult.pairingManifest = .present(byteCount: manifest.count)
    }
}
