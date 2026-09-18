import Foundation
import VaultKit
import YubikeyKit

/// A simulated OpenPGP card.
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
/// `6A88` when no key is present, and can be told to inject transport failures.
/// A mock that always succeeds would give false confidence in the ceremony.
public final class MockYubikeyTransport: YubikeyTransport {
    public enum InjectedFailure: Equatable {
        case none
        case transportError(String)
        /// Respond with `61xx` once before the real data, to exercise GET RESPONSE.
        case chainedResponse
        /// Respond with `6Cxx` once, to exercise the Le correction path.
        case wrongLeOnce
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
    private var signatureKey: [UInt8]?
    private var fingerprint: [UInt8] = [UInt8](repeating: 0, count: 20)
    private var algorithmAttributes: [UInt8]?
    private var pwStatus: [UInt8] = [0x00, 0x00, 0x7F, 0x00, 0x7F, 0x00, 0x7F]
    private var uifSignature: [UInt8] = [0x00, 0x20]
    public private(set) var signatureCounter: UInt32 = 0
    private let serial: UInt32
    private let openPGPVersion: String

    /// Every APDU received, for trace assertions.
    public private(set) var receivedAPDUs: [String] = []
    /// When set, `GENERATE ASYMMETRIC KEY PAIR` returns this key instead of the
    /// one corresponding to the imported scalar — i.e. a counterfeit or tampered
    /// card that does not hold the key it claims to.
    public var storedPublicKeyOverride: [UInt8]?
    public var injectedFailure: InjectedFailure = .none
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
        case OpenPGPDataObject.algorithmAttributesSignature:
            guard let algorithmAttributes else { return status(0x6A, 0x88) }
            return ResponseAPDU(data: algorithmAttributes, status: .success)
        case OpenPGPDataObject.pwStatusBytes:
            return ResponseAPDU(data: pwStatus, status: .success)
        case OpenPGPDataObject.uifSignature:
            return ResponseAPDU(data: uifSignature, status: .success)
        case OpenPGPDataObject.fingerprintSignature:
            return ResponseAPDU(data: fingerprint, status: .success)
        default:
            return status(0x6A, 0x88)
        }
    }

    private func applicationRelatedData() -> [UInt8] {
        // AID: RID(5) | PIX prefix(3) | version(2) | manufacturer(2) | serial(4) | RFU(2)
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
        if let algorithmAttributes {
            discretionary += TLV(tag: OpenPGPDataObject.algorithmAttributesSignature, value: algorithmAttributes).encoded
        }
        discretionary += TLV(tag: OpenPGPDataObject.pwStatusBytes, value: pwStatus).encoded
        discretionary += TLV(tag: OpenPGPDataObject.fingerprintSignature, value: fingerprint).encoded

        var contents = TLV(tag: OpenPGPDataObject.applicationIdentifier, value: aid).encoded
        contents += TLV(tag: OpenPGPDataObject.historicalBytes, value: [0x00, 0x73, 0x00, 0x00]).encoded
        contents += TLV(tag: OpenPGPDataObject.discretionaryData, value: discretionary).encoded

        return TLV(tag: OpenPGPDataObject.applicationRelatedData, value: contents).encoded
    }

    private func putData(_ command: CommandAPDU) throws -> ResponseAPDU {
        if let error = try requireSelected() { return error }
        guard pw3Verified else { return status(0x69, 0x82) }

        // Key import: P1P2 = 3F FF
        if command.p1 == 0x3F, command.p2 == 0xFF {
            guard signatureKey == nil else { return status(0x6A, 0x80) }
            guard let scalar = Self.extractPrivateKey(command.data) else { return status(0x6A, 0x80) }
            guard Secp256k1.isValidPrivateKey(scalar) else { return status(0x6A, 0x80) }
            signatureKey = scalar
            return status(0x90, 0x00)
        }

        let tag = UInt16(command.p1) << 8 | UInt16(command.p2)
        switch tag {
        case OpenPGPDataObject.algorithmAttributesSignature:
            guard command.data.first == 0x13 else { return status(0x6A, 0x80) }
            algorithmAttributes = command.data
        case OpenPGPDataObject.fingerprintSignature:
            guard command.data.count == 20 else { return status(0x6A, 0x80) }
            fingerprint = command.data
        case OpenPGPDataObject.pwStatusBytes:
            guard command.data.count == 7 else { return status(0x6A, 0x80) }
            pwStatus = command.data
        case OpenPGPDataObject.uifSignature:
            uifSignature = command.data
        case OpenPGPDataObject.creationTimeSignature:
            // The simulation accepts the tag design.md specifies.
            break
        default:
            return status(0x6A, 0x88)
        }
        return status(0x90, 0x00)
    }

    /// Walks 4D -> B6 -> 7F48 -> 5F48 and returns the scalar.
    public static func extractPrivateKey(_ data: [UInt8]) -> [UInt8]? {
        guard let objects = try? TLVParser.parse(data),
              let header = TLVParser.find(OpenPGPDataObject.extendedHeaderList, in: objects),
              let crt = TLVParser.find(OpenPGPDataObject.controlReferenceTemplateSignature, in: [header]),
              let template = TLVParser.find(OpenPGPDataObject.privateKeyTemplate, in: [crt]),
              let key = TLVParser.find(OpenPGPDataObject.privateKey, in: [template]),
              key.value.count >= 2
        else { return nil }
        // First two bytes are the component length prefix.
        let declaredLength = Int(key.value[0]) << 8 | Int(key.value[1])
        guard declaredLength == 32, key.value.count == 34 else { return nil }
        return Array(key.value[2...])
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
        guard let signatureKey else { return status(0x6A, 0x88) }
        let publicKey = try storedPublicKeyOverride ?? Secp256k1.publicKey(fromPrivateKey: signatureKey)
        let point = TLV(tag: OpenPGPDataObject.ecdsaPublicPoint, value: publicKey).encoded
        let template = TLV(tag: OpenPGPDataObject.publicKeyTemplate, value: point).encoded
        return ResponseAPDU(data: template, status: .success)
    }

    private func resetApplet() {
        userPIN = OpenPGPPinDefaults.user
        adminPIN = OpenPGPPinDefaults.admin
        pw1Verified = false
        pw3Verified = false
        userRetriesRemaining = 3
        adminRetriesRemaining = 3
        signatureKey = nil
        fingerprint = [UInt8](repeating: 0, count: 20)
        algorithmAttributes = nil
        pwStatus = [0x00, 0x00, 0x7F, 0x00, 0x7F, 0x00, 0x7F]
        uifSignature = [0x00, 0x20]
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
    public var currentUIF: [UInt8] { uifSignature }
    public var currentFingerprint: [UInt8] { fingerprint }
    public var hasKey: Bool { signatureKey != nil }

    private func status(_ sw1: UInt8, _ sw2: UInt8) -> ResponseAPDU {
        ResponseAPDU(data: [], status: StatusWord(sw1: sw1, sw2: sw2))
    }
}
