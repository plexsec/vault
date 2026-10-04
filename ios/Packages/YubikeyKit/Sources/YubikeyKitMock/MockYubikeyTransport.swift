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
    /// The retry *maximum* per password, as `SET PIN RETRIES` sets it. A fresh
    /// applet reports 3 for all three (measured on hardware: `03 00 03`).
    private var userRetryLimit = 3
    private var adminRetryLimit = 3
    private var userRetriesRemaining = 3
    private var adminRetriesRemaining = 3
    private var slots: [KeySlot: SlotState] = [.signature: SlotState(), .authentication: SlotState()]
    /// The PW1 status byte as *written* (0x00 = PIN per signature, 0x01 = once per
    /// session). The card accepts only this byte on write; the maximum lengths and
    /// the retry counters in the seven-byte read-back are the card's own.
    private var pw1Status: [UInt8] = [0x01]
    /// The resetting code is never set by this app, and hardware reports 0 attempts
    /// for a password that does not exist (`03 00 03` for PW1/RC/PW3).
    private let resetRetriesRemaining: UInt8 = 0
    /// True between `TERMINATE DF` and `ACTIVATE FILE`. A real applet in this
    /// state is wiped and deactivated: it answers `6985` to everything except
    /// `ACTIVATE FILE` and a re-SELECT. Modelled because an interrupted reset
    /// (TERMINATE sent, ACTIVATE never delivered) leaves exactly this behind.
    private var isAppletTerminated = false
    /// Status word `SELECT` answers while the applet is terminated. `6985` is
    /// what YubiKey firmware 5.4.x reports; `6285` is the other form the
    /// OpenPGP spec allows and that yubikit also accepts.
    public var terminatedSelectStatusWord = StatusWord(sw1: 0x69, sw2: 0x85)
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

    /// Models an applet that rejects a wrong-PIN `VERIFY` *without* counting it —
    /// firmware that treats the value as malformed (`6A80`) rather than as a failed
    /// attempt. A PIN burn cannot tell that apart from a counted rejection except by
    /// reading `0xC4` back, so this is how the reset's read-back is exercised
    /// without hardware. Default off: real cards count a wrong PIN.
    public var refuseToCountFailedAttempts = false
    /// When set, `GENERATE ASYMMETRIC KEY PAIR` (read) answers with this status
    /// word instead of the key, simulating an applet that cannot read EC keys
    /// (e.g. firmware < 5.2.3 answering 6581).
    public var readPublicKeyStatus: StatusWord?
    /// Private-use data objects (0x0101–0x0104), exactly as the card would hold
    /// them. Empty for a never-written object, which on real hardware answers
    /// `9000` with no data rather than `6A88`.
    private var privateUseDataObjects: [UInt16: [UInt8]] = [:]
    /// When false, the applet has no private-use objects at all and answers
    /// `6A88` — what an applet that does not implement the optional objects does.
    /// Defaults to true because YubiKey 5 does implement them.
    public var hasPrivateUseDataObjects = true
    /// Stands in for PW2 (the resetting code), which this app never sets. The
    /// spec puts two of the four objects behind it; leaving it unset is what the
    /// real cards this app writes look like.
    public var pw2Verified = false

    /// What the card holds in the pairing manifest's object, for trace assertions.
    public var storedPairingManifest: [UInt8]? { privateUseDataObjects[OpenPGPDataObject.privateUse2] }
    /// Random bytes returned by `GET CHALLENGE` (INS 0x84). Defaults to all-zero
    /// so tests and the DEBUG simulated card are reproducible; the app's DEBUG
    /// card overrides it via `-deterministic-entropy`, and a real card always
    /// answers from its hardware RNG.
    public var challengeBytes: [UInt8] = [UInt8](repeating: 0, count: 32)
    /// When set, the next `PSO:CDS` answers `6985` as an unfinished touch does.
    public var touchNotCompleted = false
    /// When set, `PSO:CDS` answers `6983`: PW1 blocked by too many failures.
    public var userPinBlockedForSigning = false
    /// The digest of the last signature this card produced, if any.
    public private(set) var lastSignedDigest: [UInt8]?
    /// How many signatures this card has been asked to produce. The app must ask
    /// exactly once per request (design.md §5.2 rule 1).
    public private(set) var signatureRequestCount = 0
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
        // A session boundary loses VERIFY state on real hardware — the
        // application note is explicit that PW1/PW3 verification does not survive
        // one, and design.md §4.2 relies on that. Modelling it is what makes a
        // "verify in one session, sign in the next" bug fail here instead of on a
        // card, where the symptom is an unexplained 6982.
        pw1Verified = false
        pw3Verified = false
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

        // A terminated DF accepts only ACTIVATE FILE and a re-SELECT.
        if isAppletTerminated, command.ins != 0x44, command.ins != 0xA4 {
            return status(0x69, 0x85)
        }

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
        case (0xF2, _, _):
            return setPinRetries(command)
        case (0xE6, _, _):
            // Spec 3.4.1: "VERIFY of PW3 or Always if PW3 is blocked". The mock has
            // to model the exception or a PIN-free reset could not be tested at
            // all — and, worse, a reset sequence that real hardware refuses would
            // pass here. `ykman openpgp reset` reaches this branch by burning the
            // counter first; `OpenPGPCard.reset()` does the same.
            guard pw3Verified || adminRetriesRemaining == 0 else { return status(0x69, 0x82) }
            resetApplet()
            // TERMINATE DF wipes the applet *and* deactivates the DF; only
            // ACTIVATE FILE brings it back.
            isAppletTerminated = true
            return status(0x90, 0x00)
        case (0x44, _, _):
            // ACTIVATE FILE is accepted on a terminated DF regardless of the
            // selection state, and is what clears the terminated state.
            guard isAppletTerminated || !isSelected else { return status(0x69, 0x85) }
            isAppletTerminated = false
            isSelected = true
            return status(0x90, 0x00)
        case (0x47, _, _):
            return try readPublicKey(command)
        case (0x84, _, _):
            return try getChallenge(command)
        case (0x2A, _, _):
            return computeDigitalSignature(command)
        default:
            return status(0x6D, 0x00)
        }
    }

    private func select(_ command: CommandAPDU) -> ResponseAPDU {
        guard command.data == OpenPGPCard.openPGPAID else { return status(0x6A, 0x82) }
        guard !isAppletTerminated else {
            return ResponseAPDU(data: [], status: terminatedSelectStatusWord)
        }
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
            return ResponseAPDU(data: pwStatusReadback, status: .success)
        case OpenPGPDataObject.uifSignature, OpenPGPDataObject.uifAuthentication:
            guard let slot = Self.slot(forUIFTag: tag), let uif = slots[slot]?.uif else {
                return status(0x6A, 0x88)
            }
            return ResponseAPDU(data: uif, status: .success)
        case OpenPGPDataObject.privateUse1, OpenPGPDataObject.privateUse2,
             OpenPGPDataObject.privateUse3, OpenPGPDataObject.privateUse4:
            // The access conditions are the whole point of having four of these,
            // so the mock enforces them instead of handing out whatever is
            // asked for: a ceremony that picks the wrong object has to fail here
            // and not on an operator's card.
            guard hasPrivateUseDataObjects else { return status(0x6A, 0x88) }
            guard Self.privateUseObject(tag)?.readAccess != .pw3 || pw3Verified else {
                return status(0x69, 0x82)
            }
            guard Self.privateUseObject(tag)?.readAccess != .pw2 || pw2Verified else {
                return status(0x69, 0x82)
            }
            return ResponseAPDU(data: privateUseDataObjects[tag] ?? [], status: .success)
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
            // The real applet carries the UIF objects inside 0x6E (seen on a
            // YubiKey 5C NFC: `... d6 02 00 20 d7 02 00 20 d8 02 00 20 d9 02 00 20`),
            // which is what lets the policy read-back cost no extra round trip.
            if let uif = slots[slot]?.uif {
                discretionary += TLV(tag: objects.uif, value: uif).encoded
            }
        }
        discretionary += TLV(tag: OpenPGPDataObject.pwStatusBytes, value: pwStatusReadback).encoded

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
            guard !refuseAlgorithmAttributes else { return status(0x6A, 0x80) }
            // The attributes must be exactly the ones this firmware accepts for
            // that slot's algorithm — not merely start with the right algorithm
            // id. Real hardware (YubiKey 5C NFC, firmware 5.8.0) rejects an
            // EdDSA/Ed25519 attributes object that carries GnuPG's OID with
            // `6A80`, and accepts RFC 8410's. Checking the bytes here is what
            // makes that a failing test rather than a failed provisioning run.
            let algorithm: KeyAlgorithm = slot == .signature ? .secp256k1 : .ed25519
            guard command.data == KeyImportTemplate.algorithmAttributes(for: algorithm) else {
                return status(0x6A, 0x80)
            }
            slots[slot]?.algorithmAttributes = command.data
            // Writing a slot's algorithm attributes is a key-slot reset: the
            // applet drops that slot's touch policy with it. Observed on hardware
            // (amendment 26) and reported for `gpg keytocard` in ykman#693: a
            // policy applied *before* the import is gone afterwards. Modelling
            // this is the whole reason the ceremony applies the policy last.
            slots[slot]?.uif = OpenPGPTouchPolicy.offEncoded
        case OpenPGPDataObject.fingerprintSignature, OpenPGPDataObject.fingerprintAuthentication:
            guard let slot = Self.slot(forFingerprintTag: tag) else { return status(0x6A, 0x88) }
            guard command.data.count == 20 else { return status(0x6A, 0x80) }
            slots[slot]?.fingerprint = command.data
        case OpenPGPDataObject.pwStatusBytes:
            guard command.data.count == 1 else { return status(0x6A, 0x80) }
            pw1Status = command.data
        case OpenPGPDataObject.uifSignature, OpenPGPDataObject.uifAuthentication:
            guard let slot = Self.slot(forUIFTag: tag) else { return status(0x6A, 0x88) }
            // A card that answers `9000` and stores nothing is exactly the failure
            // this flag reproduces, so the ceremony's read-back can be tested.
            guard !uifWritesAreIgnored else { return status(0x90, 0x00) }
            slots[slot]?.uif = command.data
        case OpenPGPDataObject.generationTimeSignature, OpenPGPDataObject.generationTimeAuthentication:
            // The simulation accepts the tags design.md specifies.
            break
        case OpenPGPDataObject.privateUse1, OpenPGPDataObject.privateUse2,
             OpenPGPDataObject.privateUse3, OpenPGPDataObject.privateUse4:
            guard hasPrivateUseDataObjects else { return status(0x6A, 0x88) }
            guard let object = Self.privateUseObject(tag) else { return status(0x6A, 0x88) }
            // PW3 is already verified at the top of putData; the other two
            // conditions are the ones that differ per object.
            guard object.writeAccess == .pw3 || (object.writeAccess == .pw2 && pw2Verified) else {
                return status(0x69, 0x82)
            }
            guard command.data.count <= PrivateUseDataObject.maximumValueLength else {
                // The spec's limit is 254 bytes; a real applet rejects more.
                return status(0x6A, 0x80)
            }
            privateUseDataObjects[tag] = command.data
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

    private static func slot(forUIFTag tag: UInt16) -> KeySlot? {        switch tag {
        case OpenPGPDataObject.uifSignature: return .signature
        case OpenPGPDataObject.uifAuthentication: return .authentication
        default: return nil
        }
    }

    /// Walks `4D -> <CRT 00> | 7F48 | 5F48` and returns the slot and secret.
    public static func extractImport(_ data: [UInt8]) -> (slot: KeySlot, secret: [UInt8])? {
        guard let objects = try? TLVParser.parse(data),
              let header = TLVParser.find(OpenPGPDataObject.extendedHeaderList, in: objects),
              let children = try? TLVParser.parse(header.value)
        else { return nil }

        // The CRT is an empty-value TLV: B6 00 / A4 00.
        guard let slot = KeySlot.allCases.first(where: { slot in
            children.contains(TLV(tag: KeySlotObjects.forSlot(slot).controlReference, value: []))
        }) else { return nil }

        // 5F48 holds the raw 32-byte secret directly.
        guard let key = TLVParser.find(OpenPGPDataObject.privateKey, in: children),
              key.value.count == 32
        else { return nil }

        return (slot, key.value)
    }

    /// `PSO:CDS`. Models the protocol behaviour the app depends on, not the
    /// arithmetic: PW1 must have been verified **in this session**, the signature
    /// slot must hold a key, an unsatisfied touch policy answers `6985`, and a
    /// produced signature increments the counter. The bytes are a deterministic
    /// DER pair derived from the digest — VaultKit's own tests check real
    /// signatures against published vectors, so this fake stays a fake.
    private func computeDigitalSignature(_ command: CommandAPDU) -> ResponseAPDU {
        guard command.data.count == 32 else { return status(0x6A, 0x80) }
        // Security conditions first: that is the usual ISO 7816 order, and the
        // order the app relies on to tell "no PIN" from "no key". The exact order
        // a YubiKey uses is an item for the hardware check
        // (docs/m0-hardware-verification.md), so this is documented, not assumed
        // to be universal.
        guard pw1Verified else { return status(0x69, 0x82) }
        guard slots[.signature]?.isOccupied == true else { return status(0x6A, 0x88) }
        if touchNotCompleted {
            // With UIF set the applet waits for a touch; when that wait ends the
            // card has not produced a signature. The exact status word is an M0
            // item, and 6985 is what the app maps to "conditions not satisfied".
            touchNotCompleted = false
            return status(0x69, 0x85)
        }
        guard !userPinBlockedForSigning else { return status(0x69, 0x83) }
        signatureCounter += 1
        signatureRequestCount += 1
        lastSignedDigest = command.data
        // A *real* signature when one was generated for this digest, so a flow that
        // verifies what the card returned — as the signing ceremony does — can be
        // exercised without a card. The key behind it is the deterministic one the
        // DEBUG simulated app is provisioned with, which is a published BIP39 test
        // vector: secret to nobody, and generated by tools/derive.
        #if DEBUG
        if let der = SimulatedSigningVectors.signatures[command.data.hexString],
           let bytes = try? Hex.decode(der) {
            return ResponseAPDU(data: bytes, status: .success)
        }
        #endif
        return ResponseAPDU(data: Self.derSignature(for: command.data), status: .success)
    }

    /// A DER `SEQUENCE { INTEGER r, INTEGER s }` derived from the digest, so the
    /// bytes differ per request but are reproducible.
    static func derSignature(for digest: [UInt8]) -> [UInt8] {
        func scalar(_ seed: UInt8) -> [UInt8] {
            var value = digest.map { $0 &+ seed }
            if value[0] & 0x80 != 0 { value.insert(0x00, at: 0) }
            while value.count > 1, value.first == 0 { value.removeFirst() }
            return [0x02, UInt8(value.count)] + value
        }
        let body = scalar(0x01) + scalar(0x02)
        return [0x30, UInt8(body.count)] + body
    }

    private func verify(_ command: CommandAPDU) -> ResponseAPDU {
        let reference = command.p2
        if reference == OpenPGPPinReference.admin.rawValue {
            guard adminRetriesRemaining > 0 else { return status(0x69, 0x83) }
            guard command.data == adminPIN else {
                if refuseToCountFailedAttempts { return status(0x6A, 0x80) }
                adminRetriesRemaining -= 1
                return status(0x63, UInt8(0xC0 | adminRetriesRemaining))
            }
            pw3Verified = true
            adminRetriesRemaining = adminRetryLimit
            return status(0x90, 0x00)
        }
        guard userRetriesRemaining > 0 else { return status(0x69, 0x83) }
        guard command.data == userPIN else {
            if refuseToCountFailedAttempts { return status(0x6A, 0x80) }
            userRetriesRemaining -= 1
            return status(0x63, UInt8(0xC0 | userRetriesRemaining))
        }
        pw1Verified = true
        userRetriesRemaining = userRetryLimit
        return status(0x90, 0x00)
    }

    /// `SET PIN RETRIES` (INS 0xF2): three bytes, PW1 / reset code / PW3, each the
    /// *maximum* number of wrong attempts. Requires PW3 verified in the same
    /// session. The real applet accepts 1-99; the counters refill to the new value
    /// on the next successful VERIFY.
    private func setPinRetries(_ command: CommandAPDU) -> ResponseAPDU {
        guard pw3Verified else { return status(0x69, 0x82) }
        guard command.p1 == 0x00, command.p2 == 0x00, command.data.count == 3 else {
            return status(0x6A, 0x80)
        }
        guard command.data.allSatisfy({ (1...99).contains(Int($0)) }) else {
            return status(0x6A, 0x80)
        }
        userRetryLimit = Int(command.data[0])
        adminRetryLimit = Int(command.data[2])
        userRetriesRemaining = userRetryLimit
        adminRetriesRemaining = adminRetryLimit
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
            userRetriesRemaining = userRetryLimit
            pw1Verified = false
            return status(0x90, 0x00)
        }
        guard command.data.count >= 8 else { return status(0x6A, 0x80) }
        old = Array(command.data.prefix(adminPIN.count))
        new = Array(command.data.dropFirst(adminPIN.count))
        guard old == adminPIN else { return status(0x63, 0xC2) }
        adminPIN = new
        adminRetriesRemaining = adminRetryLimit
        // CHANGE REFERENCE DATA for PW3 leaves PW3 verified, as on real cards.
        pw3Verified = true
        return status(0x90, 0x00)
    }

    private func readPublicKey(_ command: CommandAPDU) throws -> ResponseAPDU {
        if let error = try requireSelected() { return error }
        if let readPublicKeyStatus { return ResponseAPDU(data: [], status: readPublicKeyStatus) }

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
            case .secp256k1:
                // Real cards return the EC point as 65-byte uncompressed
                // (04 || X || Y); OpenPGPCard.readPublicKey compresses it.
                let compressed = try Secp256k1.publicKey(fromPrivateKey: secret)
                publicKey = try Secp256k1.uncompressedPublicKey(fromCompressed: compressed)
            case .ed25519:
                publicKey = try Ed25519.publicKey(fromSeed: secret)
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

    /// The `VaultKit` enumeration is the single source of truth for which object
    /// has which access condition, so the mock cannot drift from the real card's
    /// documented behaviour.
    static func privateUseObject(_ tag: UInt16) -> PrivateUseDataObject? {
        PrivateUseDataObject(rawValue: tag)
    }

    private func resetApplet() {
        userPIN = OpenPGPPinDefaults.user
        adminPIN = OpenPGPPinDefaults.admin
        pw1Verified = false
        pw3Verified = false
        userRetryLimit = 3
        adminRetryLimit = 3
        userRetriesRemaining = 3
        adminRetriesRemaining = 3
        slots = [.signature: SlotState(), .authentication: SlotState()]
        // The factory default is 0x01 ("PIN once per session"), not the 0x00 the
        // ceremony writes. Observed on real hardware: a freshly terminated applet
        // reads `01 7F 7F 7F 03 00 03`, which is how the policy write can
        // be told apart from a card that was never configured.
        pw1Status = [0x01]
        signatureCounter = 0
        // TERMINATE DF wipes the private-use objects along with everything else,
        // which is why the manifest has to be written *after* a reset and why a
        // reset is what "forget the pairing" means for this card.
        privateUseDataObjects = [:]
        isSelected = false
    }

    // MARK: Test affordances

    /// True while the simulated applet is in the terminated state.
    public var appletIsTerminated: Bool { isAppletTerminated }

    /// Puts the simulated applet where an interrupted reset leaves it: wiped and
    /// deactivated by `TERMINATE DF`, with `ACTIVATE FILE` never delivered.
    public func simulateInterruptedReset() {
        resetApplet()
        isAppletTerminated = true
    }

    /// Simulates a signature the card made without the desktop knowing, which is
    /// what the counter audit is designed to catch.
    public func simulateExternalSignature() {
        signatureCounter += 1
    }

    /// What the card reports for DO 0xC4: the PW1 status byte, the three maximum
    /// lengths, then the three remaining-attempt counters.
    public var pwStatusReadback: [UInt8] {
        pw1Status
            + [0x7F, 0x7F, 0x7F]
            + [UInt8(userRetriesRemaining), resetRetriesRemaining, UInt8(adminRetriesRemaining)]
    }

    public var currentPWStatus: [UInt8] { pwStatusReadback }
    /// The maximum attempts per password, as `SET PIN RETRIES` configured them.
    public var currentRetryLimits: (user: Int, admin: Int) { (userRetryLimit, adminRetryLimit) }
    public func currentUIF(_ slot: KeySlot) -> [UInt8] { slots[slot]?.uif ?? [] }

    /// When set, `PUT DATA` of a UIF object answers `9000` and stores nothing.
    ///
    /// This is the failure mode the touch-policy read-back exists to catch, and it
    /// is not hypothetical: the ceremony used to write the policy before the key
    /// import, and the applet's key-slot reset then discarded it while reporting
    /// success at every step (amendment 26).
    public var uifWritesAreIgnored = false

    /// When set, every algorithm-attributes write answers `6A80`. Models a card (or
    /// a firmware/curve combination) that refuses the attributes object, which is
    /// what happened to a real provisioning run and what the named
    /// `algorithmAttributesRejected` error exists for (amendment 29).
    public var refuseAlgorithmAttributes = false
    public func currentFingerprint(_ slot: KeySlot) -> [UInt8] { slots[slot]?.fingerprint ?? [] }
    public func hasKey(in slot: KeySlot) -> Bool { slots[slot]?.isOccupied ?? false }
    public func storedPrivateKey(_ slot: KeySlot) -> [UInt8]? { slots[slot]?.privateKey }

    private func status(_ sw1: UInt8, _ sw2: UInt8) -> ResponseAPDU {
        ResponseAPDU(data: [], status: StatusWord(sw1: sw1, sw2: sw2))
    }
}
