import Foundation
import VaultKit
import YubikeyKit

/// A simulated OpenPGP card with both signing-capable slots.
///
/// Two distinct purposes, both important:
///
/// 1. It drives the app's DEBUG-only "simulated YubiKey" mode so the whole
///    ceremony can be exercised on a phone with no key present.
/// 2. It is a real APDU responder, so the byte-level protocol layer
///    (`OpenPGPCard`, TLV encoding, status-word mapping, `61xx`/`6Cxx`
///    handling) is tested end to end without hardware.
///
/// It is deliberately NOT a stub that returns success for everything: it
/// enforces PIN verification, refuses `PUT DATA` on an occupied slot, returns
/// `6A88` when no key is present, checks that the algorithm attributes match the
/// key that was imported, and can be told to inject transport failures. A mock
/// that always succeeds would give false confidence in the ceremony.
public final class MockYubikeyTransport: YubikeyTransport {
    public enum InjectedFailure: Equatable {
        case none
        case transportError(String)
        /// Respond with `61xx` once before the real data, to exercise GET RESPONSE.
        case chainedResponse
        /// Respond with `6Cxx` once, to exercise the Le correction path.
        case wrongLeOnce
    }

    /// Per-slot key material and metadata.
    private struct SlotState {
        var privateKey: [UInt8]?
        var algorithm: KeyAlgorithm?
        var algorithmAttributes: [UInt8]?
        var fingerprint: [UInt8] = [UInt8](repeating: 0, count: 20)
        var uif: [UInt8] = [0x00, 0x20]

        var isOccupied: Bool { privateKey != nil }
    }

    public let transportName: String
    private let accessoryDelay: Duration

    // Card state
    private var isSelected = false
    private var userPIN: [UInt8] = OpenPGPPinDefaults.user
    private var adminPIN: [UInt8] = OpenPGPPinDefaults.admin
    private var pw1Verified = false
    private var pw3Verified = false
    private var userRetriesRemaining = 3
    private var adminRetriesRemaining = 3
    private var slots: [KeySlot: SlotState] = [.signature: SlotState(), .authentication: SlotState()]
    private var pwStatus: [UInt8] = [0x00, 0x00, 0x7F, 0x00, 0x7F, 0x00, 0x7F]
    public private(set) var signatureCounter: UInt32 = 0
    private let serial: UInt32
    private let openPGPVersion: String

    /// Every APDU received, for trace assertions.
    public private(set) var receivedAPDUs: [String] = []
    /// When set for a slot, `GENERATE ASYMMETRIC KEY PAIR` returns this key
    /// instead of the one corresponding to the imported secret — i.e. a
    /// counterfeit or tampered card that does not hold the key it claims to.
    public var storedPublicKeyOverride: [KeySlot: [UInt8]] = [:]
    public var injectedFailure: InjectedFailure = .none
    /// Random bytes returned by `GET CHALLENGE` (INS 0x84). Defaults to all-zero
    /// so tests and the DEBUG simulated card are reproducible; the app's DEBUG
    /// card overrides it via `-deterministic-entropy`, and a real card always
    /// answers from its hardware RNG.
    public var challengeBytes: [UInt8] = [UInt8](repeating: 0, count: 32)
    private var didInjectOnce = false
    private var pendingChainedData: [UInt8]?

    public init(
        transportName: String = "Simulated YubiKey",
        serial: UInt32 = 0x00AB_CDEF,
        openPGPVersion: String = "3.4",
        responseDelay: Duration = .zero
    ) {
        self.transportName = transportName
        self.serial = serial
        self.openPGPVersion = openPGPVersion
        self.accessoryDelay = responseDelay
    }

    // MARK: YubikeyTransport

    public func open() async throws {
        isSelected = false
    }

    public func close() async {
        isSelected = false
    }

    public func send(_ command: CommandAPDU) async throws -> ResponseAPDU {
        receivedAPDUs.append(command.hex)
        if accessoryDelay != .zero { try? await Task.sleep(for: accessoryDelay) }

        switch injectedFailure {
        case .transportError(let detail):
            throw CardError.transportUnavailable(detail)
        case .chainedResponse where !didInjectOnce:
            didInjectOnce = true
            let real = try respond(to: command)
            pendingChainedData = real.data
            return ResponseAPDU(data: [], status: StatusWord(sw1: 0x61, sw2: UInt8(min(real.data.count, 255))))
        case .wrongLeOnce where !didInjectOnce && !command.data.isEmpty:
            didInjectOnce = true
            return ResponseAPDU(data: [], status: StatusWord(sw1: 0x6C, sw2: UInt8(command.data.count)))
        default:
            break
        }

        // GET RESPONSE after an injected 61xx.
        if command.ins == 0xC0, let pending = pendingChainedData {
            pendingChainedData = nil
            return ResponseAPDU(data: pending, status: .success)
        }

        return try respond(to: command)
    }

    // MARK: APDU dispatch

    private func respond(to command: CommandAPDU) throws -> ResponseAPDU {
        if command.ins == 0xC0 { return ResponseAPDU(data: [], status: .success) }

        switch (command.ins, command.p1, command.p2) {
        case (0xA4, _, _):
            return select(command)
        case (0xCA, _, _):
            return try getData(command)
        case (0xDA, _, _), (0xDB, _, _):
            return try putData(command)
        case (0x20, _, _):
            return verify(command)
        case (0x24, _, _):
            return changeReferenceData(command)
        case (0xE6, _, _):
            guard pw3Verified else { return status(0x69, 0x82) }
            resetApplet()
            return status(0x90, 0x00)
        case (0x44, _, _):
            guard !isSelected else { return status(0x69, 0x85) }
            isSelected = true
            return status(0x90, 0x00)
        case (0x47, _, _):
            return try readPublicKey(command)
        case (0x84, _, _):
            return try getChallenge(command)
        default:
            return status(0x6D, 0x00)
        }
    }

    private func select(_ command: CommandAPDU) -> ResponseAPDU {
        guard command.data == OpenPGPCard.openPGPAID else { return status(0x6A, 0x82) }
        isSelected = true
        return ResponseAPDU(data: [0x6F, 0x00], status: .success)
    }

    private func requireSelected() throws -> ResponseAPDU? {
        isSelected ? nil : status(0x69, 0x82)
    }

    private func getData(_ command: CommandAPDU) throws -> ResponseAPDU {
        if let error = try requireSelected() { return error }
        let tag = UInt16(command.p1) << 8 | UInt16(command.p2)

        switch tag {
        case OpenPGPDataObject.applicationRelatedData:
            return ResponseAPDU(data: applicationRelatedData(), status: .success)
        case OpenPGPDataObject.securitySupportTemplate:
            let counter: [UInt8] = [
                UInt8((signatureCounter >> 16) & 0xFF),
                UInt8((signatureCounter >> 8) & 0xFF),
                UInt8(signatureCounter & 0xFF),
            ]
            let inner = TLV(tag: OpenPGPDataObject.signatureCounter, value: counter).encoded
            return ResponseAPDU(data: TLV(tag: 0x007A, value: inner).encoded, status: .success)
        case OpenPGPDataObject.algorithmAttributesSignature, OpenPGPDataObject.algorithmAttributesAuthentication:
            guard let slot = Self.slot(forAlgorithmAttributesTag: tag),
                  let attributes = slots[slot]?.algorithmAttributes
            else { return status(0x6A, 0x88) }
            return ResponseAPDU(data: attributes, status: .success)
        case OpenPGPDataObject.pwStatusBytes:
            return ResponseAPDU(data: pwStatus, status: .success)
        case OpenPGPDataObject.uifSignature, OpenPGPDataObject.uifAuthentication:
            guard let slot = Self.slot(forUIFTag: tag), let uif = slots[slot]?.uif else {
                return status(0x6A, 0x88)
            }
            return ResponseAPDU(data: uif, status: .success)
        case OpenPGPDataObject.fingerprintSignature, OpenPGPDataObject.fingerprintAuthentication:
            guard let slot = Self.slot(forFingerprintTag: tag), let fingerprint = slots[slot]?.fingerprint else {
                return status(0x6A, 0x88)
            }
            return ResponseAPDU(data: fingerprint, status: .success)
        default:
            return status(0x6A, 0x88)
        }
    }

    private func applicationRelatedData() -> [UInt8] {
        // AID layout: RID(5) | PIX "01"(1) | version(2) | manufacturer(2) | serial(4) | RFU(2)
        var aid = OpenPGPCard.openPGPAID          // 6 bytes: D2 76 00 01 24 01
        let versionParts = openPGPVersion.split(separator: ".").compactMap { UInt8($0) }
        aid.append(contentsOf: [versionParts.first ?? 3, versionParts.count > 1 ? versionParts[1] : 4])
        aid.append(contentsOf: [0x00, 0x00])      // manufacturer
        aid.append(contentsOf: [
            UInt8((serial >> 24) & 0xFF), UInt8((serial >> 16) & 0xFF),
            UInt8((serial >> 8) & 0xFF), UInt8(serial & 0xFF),
        ])
        aid.append(contentsOf: [0x00, 0x00])      // RFU

        var discretionary = TLV(tag: OpenPGPDataObject.extendedCapabilities, value: [0x7F]).encoded
        for slot in KeySlot.allCases {
            let objects = KeySlotObjects.forSlot(slot)
            if let attributes = slots[slot]?.algorithmAttributes {
                discretionary += TLV(tag: objects.algorithmAttributes, value: attributes).encoded
            }
            if let fingerprint = slots[slot]?.fingerprint {
                discretionary += TLV(tag: objects.fingerprint, value: fingerprint).encoded
            }
        }
        discretionary += TLV(tag: OpenPGPDataObject.pwStatusBytes, value: pwStatus).encoded

        var contents = TLV(tag: OpenPGPDataObject.applicationIdentifier, value: aid).encoded
        contents += TLV(tag: OpenPGPDataObject.historicalBytes, value: [0x00, 0x73, 0x00, 0x00]).encoded
        contents += TLV(tag: OpenPGPDataObject.discretionaryData, value: discretionary).encoded

        return TLV(tag: OpenPGPDataObject.applicationRelatedData, value: contents).encoded
    }

    private func putData(_ command: CommandAPDU) throws -> ResponseAPDU {
        if let error = try requireSelected() { return error }
        guard pw3Verified else { return status(0x69, 0x82) }

        // Key import: P1P2 = 3F FF. The CRT inside the header selects the slot.
        if command.p1 == 0x3F, command.p2 == 0xFF {
            guard let (slot, secret) = Self.extractImport(command.data) else { return status(0x6A, 0x80) }
            guard slots[slot]?.isOccupied == false else { return status(0x6A, 0x80) }

            // The key must be valid for its slot's algorithm. The slot is fixed,
            // so which algorithm arrives here is determined by the CRT tag.
            let algorithm: KeyAlgorithm = slot == .signature ? .secp256k1 : .ed25519
            switch algorithm {
            case .secp256k1:
                guard Secp256k1.isValidPrivateKey(secret) else { return status(0x6A, 0x80) }
            case .ed25519:
                guard secret.count == 32 else { return status(0x6A, 0x80) }
            }
            slots[slot]?.privateKey = secret
            slots[slot]?.algorithm = algorithm
            return status(0x90, 0x00)
        }

        let tag = UInt16(command.p1) << 8 | UInt16(command.p2)
        switch tag {
        case OpenPGPDataObject.algorithmAttributesSignature, OpenPGPDataObject.algorithmAttributesAuthentication:
            guard let slot = Self.slot(forAlgorithmAttributesTag: tag) else { return status(0x6A, 0x88) }
            // The attributes must match the algorithm whose key was just written,
            // so a slot/algorithm mix-up fails here rather than silently.
            let expectedFirst: UInt8 = slot == .signature ? 0x13 : 0x16
            guard command.data.first == expectedFirst else { return status(0x6A, 0x80) }
            slots[slot]?.algorithmAttributes = command.data
        case OpenPGPDataObject.fingerprintSignature, OpenPGPDataObject.fingerprintAuthentication:
            guard let slot = Self.slot(forFingerprintTag: tag) else { return status(0x6A, 0x88) }
            guard command.data.count == 20 else { return status(0x6A, 0x80) }
            slots[slot]?.fingerprint = command.data
        case OpenPGPDataObject.pwStatusBytes:
            guard command.data.count == 7 else { return status(0x6A, 0x80) }
            pwStatus = command.data
        case OpenPGPDataObject.uifSignature, OpenPGPDataObject.uifAuthentication:
            guard let slot = Self.slot(forUIFTag: tag) else { return status(0x6A, 0x88) }
            slots[slot]?.uif = command.data
        case OpenPGPDataObject.creationTimeSignature, OpenPGPDataObject.timestampAuthentication:
            // The simulation accepts the tags design.md specifies.
            break
        default:
            return status(0x6A, 0x88)
        }
        return status(0x90, 0x00)
    }

    private static func slot(forAlgorithmAttributesTag tag: UInt16) -> KeySlot? {
        switch tag {
        case OpenPGPDataObject.algorithmAttributesSignature: return .signature
        case OpenPGPDataObject.algorithmAttributesAuthentication: return .authentication
        default: return nil
        }
    }

    private static func slot(forFingerprintTag tag: UInt16) -> KeySlot? {
        switch tag {
        case OpenPGPDataObject.fingerprintSignature: return .signature
        case OpenPGPDataObject.fingerprintAuthentication: return .authentication
        default: return nil
        }
    }

    private static func slot(forUIFTag tag: UInt16) -> KeySlot? {
        switch tag {
        case OpenPGPDataObject.uifSignature: return .signature
        case OpenPGPDataObject.uifAuthentication: return .authentication
        default: return nil
        }
    }

    /// Walks `4D -> <CRT> -> 7F48 -> 5F48` and returns the slot and secret.
    public static func extractImport(_ data: [UInt8]) -> (slot: KeySlot, secret: [UInt8])? {
        guard let objects = try? TLVParser.parse(data),
              let header = TLVParser.find(OpenPGPDataObject.extendedHeaderList, in: objects)
        else { return nil }

        let crt = KeySlot.allCases.first { slot in
            TLVParser.find(KeySlotObjects.forSlot(slot).controlReference, in: [header]) != nil
        }
        guard let slot = crt,
              let crtTLV = TLVParser.find(KeySlotObjects.forSlot(slot).controlReference, in: [header]),
              let template = TLVParser.find(OpenPGPDataObject.privateKeyTemplate, in: [crtTLV]),
              let key = TLVParser.find(OpenPGPDataObject.privateKey, in: [template]),
              key.value.count >= 2
        else { return nil }

        // First two bytes are the component length prefix.
        let declaredLength = Int(key.value[0]) << 8 | Int(key.value[1])
        guard declaredLength == 32, key.value.count == 34 else { return nil }
        return (slot, Array(key.value[2...]))
    }

    private func verify(_ command: CommandAPDU) -> ResponseAPDU {
        let reference = command.p2
        if reference == OpenPGPPinReference.admin.rawValue {
            guard adminRetriesRemaining > 0 else { return status(0x69, 0x83) }
            guard command.data == adminPIN else {
                adminRetriesRemaining -= 1
                return status(0x63, UInt8(0xC0 | adminRetriesRemaining))
            }
            pw3Verified = true
            adminRetriesRemaining = 3
            return status(0x90, 0x00)
        }
        guard userRetriesRemaining > 0 else { return status(0x69, 0x83) }
        guard command.data == userPIN else {
            userRetriesRemaining -= 1
            return status(0x63, UInt8(0xC0 | userRetriesRemaining))
        }
        pw1Verified = true
        userRetriesRemaining = 3
        return status(0x90, 0x00)
    }

    private func changeReferenceData(_ command: CommandAPDU) -> ResponseAPDU {
        let reference = command.p2
        let (old, new): ([UInt8], [UInt8])
        if reference == OpenPGPPinReference.user.rawValue {
            guard command.data.count >= 6 else { return status(0x6A, 0x80) }
            old = Array(command.data.prefix(userPIN.count))
            new = Array(command.data.dropFirst(userPIN.count))
            guard old == userPIN else { return status(0x63, 0xC2) }
            userPIN = new
            userRetriesRemaining = 3
            pw1Verified = false
            return status(0x90, 0x00)
        }
        guard command.data.count >= 8 else { return status(0x6A, 0x80) }
        old = Array(command.data.prefix(adminPIN.count))
        new = Array(command.data.dropFirst(adminPIN.count))
        guard old == adminPIN else { return status(0x63, 0xC2) }
        adminPIN = new
        adminRetriesRemaining = 3
        // CHANGE REFERENCE DATA for PW3 leaves PW3 verified, as on real cards.
        pw3Verified = true
        return status(0x90, 0x00)
    }

    private func readPublicKey(_ command: CommandAPDU) throws -> ResponseAPDU {
        if let error = try requireSelected() { return error }

        // The CRT arrives as the command data, encoded as a TLV with an empty
        // value (tag || length 0): B6 00 for the signature slot, A4 00 for auth.
        let requested = command.data
        guard let slot = KeySlot.allCases.first(where: {
            TLV(tag: KeySlotObjects.forSlot($0).controlReference, value: []).encoded == requested
        }) else { return status(0x6A, 0x88) }

        guard let state = slots[slot], let secret = state.privateKey, let algorithm = state.algorithm else {
            return status(0x6A, 0x88)
        }

        let publicKey: [UInt8]
        if let override = storedPublicKeyOverride[slot] {
            publicKey = override
        } else {
            switch algorithm {
            case .secp256k1: publicKey = try Secp256k1.publicKey(fromPrivateKey: secret)
            case .ed25519: publicKey = try Ed25519.publicKey(fromSeed: secret)
            }
        }

        let point = TLV(tag: OpenPGPDataObject.ecdsaPublicPoint, value: publicKey).encoded
        let template = TLV(tag: OpenPGPDataObject.publicKeyTemplate, value: point).encoded
        return ResponseAPDU(data: template, status: .success)
    }

    private func getChallenge(_ command: CommandAPDU) throws -> ResponseAPDU {
        if let error = try requireSelected() { return error }
        let count = command.expectedLength ?? 0
        guard count > 0, challengeBytes.count >= count else { return status(0x6A, 0x80) }
        return ResponseAPDU(data: Array(challengeBytes.prefix(count)), status: .success)
    }

    private func resetApplet() {
        userPIN = OpenPGPPinDefaults.user
        adminPIN = OpenPGPPinDefaults.admin
        pw1Verified = false
        pw3Verified = false
        userRetriesRemaining = 3
        adminRetriesRemaining = 3
        slots = [.signature: SlotState(), .authentication: SlotState()]
        pwStatus = [0x00, 0x00, 0x7F, 0x00, 0x7F, 0x00, 0x7F]
        signatureCounter = 0
        isSelected = false
    }

    // MARK: Test affordances

    /// Simulates a signature the card made without the desktop knowing, which is
    /// what the counter audit is designed to catch.
    public func simulateExternalSignature() {
        signatureCounter += 1
    }

    public var currentPWStatus: [UInt8] { pwStatus }
    public func currentUIF(_ slot: KeySlot) -> [UInt8] { slots[slot]?.uif ?? [] }
    public func currentFingerprint(_ slot: KeySlot) -> [UInt8] { slots[slot]?.fingerprint ?? [] }
    public func hasKey(in slot: KeySlot) -> Bool { slots[slot]?.isOccupied ?? false }
    public func storedPrivateKey(_ slot: KeySlot) -> [UInt8]? { slots[slot]?.privateKey }

    private func status(_ sw1: UInt8, _ sw2: UInt8) -> ResponseAPDU {
        ResponseAPDU(data: [], status: StatusWord(sw1: sw1, sw2: sw2))
    }
}
