import Foundation
import VaultKit

/// OpenPGP applet operations over a `YubikeyTransport`.
///
/// This type is the only place that knows APDU byte layouts, and it conforms to
/// VaultKit's `SignerCard` so the ceremony state machine can drive it without
/// knowing anything about ISO 7816.
///
/// Every key operation is addressed by `KeySlot`; the slot-to-tag mapping lives
/// in `KeySlotObjects`. Which algorithm goes in which slot is decided above this
/// layer (`KeyAlgorithm.slot`).
public final class OpenPGPCard: SignerCard {
    public static let openPGPAID: [UInt8] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]

    private let transport: YubikeyTransport
    private var selected = false

    public init(transport: YubikeyTransport) {
        self.transport = transport
    }

    public var transportName: String { transport.transportName }

    // MARK: Session

    public func open() async throws {
        try await transport.open()
        try await select()
    }

    public func close() async {
        selected = false
        await transport.close()
    }

    // MARK: Commands

    /// `SELECT` the OpenPGP AID, reactivating a terminated DF if necessary.
    ///
    /// `TERMINATE DF` puts the applet in the *terminated* state, where every
    /// command except `ACTIVATE FILE` is refused with `6985` (or `6285`). A reset
    /// is `TERMINATE DF` + `ACTIVATE FILE` + re-SELECT, and the ceremony's reset
    /// step runs all three in one NFC session — so a session that drops between
    /// the two leaves the card terminated, and every later session fails at
    /// SELECT until something sends `ACTIVATE FILE`.
    ///
    /// The recovery below mirrors `yubikit`'s `OpenPgpSession.__init__`, which
    /// treats those two status words on SELECT as "not activated, activate" and
    /// then re-selects. Without it, an interrupted reset needs GPG or `ykman` to
    /// recover a card this app just terminated.
    public func select() async throws {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00,
            data: Self.openPGPAID,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        if Self.isTerminatedAppletStatus(response.status) {
            try await activateFile()
            let reactivated = try await transport.exchange(apdu)
            try Self.check(reactivated, operation: .select)
            selected = true
            return
        }
        try Self.check(response, operation: .select)
        selected = true
    }

    /// The status words a *terminated* DF answers SELECT with.
    ///
    /// `6985` is `CONDITIONS OF USE NOT SATISFIED`; `6285` is `NO INPUT DATA`.
    /// Both are what yubikit recognises as "the application is not activated"
    /// (`SW.NO_INPUT_DATA`, `SW.CONDITIONS_NOT_SATISFIED`).
    static func isTerminatedAppletStatus(_ status: StatusWord) -> Bool {
        (status.sw1 == 0x69 || status.sw1 == 0x62) && status.sw2 == 0x85
    }

    func applicationData() async throws -> [UInt8] {
        try await getData(OpenPGPDataObject.applicationRelatedData, operation: .readApplicationData)
    }

    func securitySupportTemplate() async throws -> [UInt8] {
        try await getData(OpenPGPDataObject.securitySupportTemplate, operation: .readSecuritySupportTemplate)
    }

    public func getDataObject(_ tag: UInt16) async throws -> [UInt8] {
        try await getData(tag, operation: .readApplicationData)
    }

    // MARK: Pairing manifest (private-use data object)

    /// `GET DATA 0x0102` — the applet's second private-use object.
    ///
    /// The value is read, never derived: it is whatever a previous ceremony wrote
    /// there. `nil` means the object is present and empty, which is what the
    /// hardware answers for one that has never been written (measured: `9000`
    /// with no data, not `6A88`) and the state a reset leaves behind, because
    /// `TERMINATE DF` wipes it along with the keys.
    ///
    /// A card that has no such object at all is a different case and throws
    /// `.unsupportedFeature`, so "this card cannot store a manifest" never looks
    /// like "this card has not been given one yet".
    public func readPairingManifest() async throws -> [UInt8]? {
        do {
            let value = try await getData(OpenPGPDataObject.privateUse2, operation: .readPairingManifest)
            return value.isEmpty ? nil : value
        } catch let error as CardError {
            switch error {
            case .unexpectedStatusWord(let sw1, let sw2) where Self.isMissingDataObject(sw1, sw2):
                throw CardError.unsupportedFeature("this applet has no private-use data object 0x0102")
            default:
                throw error
            }
        }
    }

    /// `PUT DATA 0x0102` — stores the pairing manifest in the card.
    ///
    /// This is the one write that keeps a card re-pairable without a reset: the
    /// manifest holds the extended public keys a wallet needs, which the applet
    /// itself cannot supply because it stores a key rather than a BIP32 node.
    ///
    /// Writing requires PW3 and the object is readable without any PIN, which is
    /// exactly the access-condition pair that makes a later re-pair possible
    /// without asking the operator for a PIN (see `PrivateUseDataObject`).
    ///
    /// There is deliberately no "clear" counterpart: emptying the object is what
    /// a reset does, and a ceremony that finds itself wanting to clear a manifest
    /// is really wanting to start over.
    public func writePairingManifest(_ manifest: [UInt8], adminPIN: [UInt8]) async throws {
        guard manifest.count <= PrivateUseDataObject.maximumValueLength else {
            throw CardError.dataObjectTooLarge(
                byteCount: manifest.count,
                maximum: PrivateUseDataObject.maximumValueLength
            )
        }
        // Re-verify in THIS session, as everywhere else: the ceremony spans
        // short-lived NFC sessions and VERIFY state does not survive one.
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)
        do {
            try await putData(
                tag: OpenPGPDataObject.privateUse2,
                value: manifest,
                operation: .writePairingManifest
            )
        } catch let error as CardError {
            // Same vocabulary as the read: a card that has no such object says so,
            // rather than surfacing a bare status word the operator cannot act on.
            switch error {
            case .unexpectedStatusWord(let sw1, let sw2) where Self.isMissingDataObject(sw1, sw2):
                throw CardError.unsupportedFeature("this applet has no private-use data object 0x0102")
            default:
                throw error
            }
        }
    }

    /// Status words that mean "there is no such data object here": 6A88
    /// (referenced data not found), 6D00 (instruction not supported) and 6B00
    /// (wrong P1-P2). All three have been seen from applets that do not implement
    /// the optional private-use objects.
    static func isMissingDataObject(_ sw1: UInt8, _ sw2: UInt8) -> Bool {
        (sw1 == 0x6A && sw2 == 0x88) || (sw1 == 0x6D && sw2 == 0x00) || (sw1 == 0x6B && sw2 == 0x00)
    }

    /// `GET DATA` (INS 0xCA), tag in P1P2.
    public func getData(_ tag: UInt16, operation: OpenPGPOperation) async throws -> [UInt8] {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xCA,
            p1: UInt8(tag >> 8), p2: UInt8(tag & 0xFF),
            data: [],
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
        return response.data
    }

    /// `PUT DATA` (INS 0xDA / 0xDB).
    ///
    /// `P1P2 = tag` for ordinary data objects; the Extended Header List for key
    /// import uses `P1P2 = 3F FF` and INS `0xDB`, which is why the tag is passed
    /// in separately from the addressing bytes.
    @discardableResult
    public func putData(
        tag: UInt16,
        value: [UInt8],
        addressing: (p1: UInt8, p2: UInt8)? = nil,
        ins: UInt8 = 0xDA,
        operation: OpenPGPOperation
    ) async throws -> [UInt8] {
        let p1 = addressing?.p1 ?? UInt8(tag >> 8)
        let p2 = addressing?.p2 ?? UInt8(tag & 0xFF)
        let apdu = CommandAPDU(cla: 0x00, ins: ins, p1: p1, p2: p2, data: value, expectedLength: 0)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
        return response.data
    }

    public func putDataObject(_ tag: UInt16, value: [UInt8]) async throws {
        try await putData(tag: tag, value: value, operation: .applyPolicy)
    }

    // MARK: PINs

    public func verify(pin: [UInt8], reference: OpenPGPPinReference, operation: OpenPGPOperation) async throws {
        let apdu = CommandAPDU(cla: 0x00, ins: 0x20, p1: 0x00, p2: reference.rawValue, data: pin, expectedLength: 0)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
    }

    /// `VERIFY PW1` (P2 = 0x81) — the user PIN, which is what signs.
    public func verifyUserPIN(_ pin: [UInt8]) async throws {
        try await verify(pin: pin, reference: .user, operation: .verifyUserPIN)
    }

    /// `VERIFY PW1` then `PSO:CDS`, on **this** session.
    ///
    /// This is the `SignerCard` entry point for signing. It exists as one method
    /// because VERIFY state belongs to a session: a caller that verified on one
    /// session and signed on another would get `6982` from real hardware.
    public func sign(digest: [UInt8], userPIN: [UInt8]) async throws -> [UInt8] {
        try await verifyUserPIN(userPIN)
        return try await computeDigitalSignature(digest: digest)
    }

    /// `PSO:CDS` (INS 0x2A, P1 = 0x9E, P2 = 0x9A) over a 32-byte digest.
    ///
    /// The applet signs the digest directly (no further hashing), which is what
    /// makes the "compute the digest in the app, pass it in" contract work
    /// (design.md §6.1). Returns the card's raw response: a DER-encoded ECDSA
    /// signature for secp256k1.
    ///
    /// **Deliberately no retry, at any layer.** A lost response may still mean the
    /// card signed and incremented its counter, so a second attempt for the same
    /// request is forbidden by design (design.md §5.2 rule 1) — the ceremony's job
    /// is to refuse it, and this method's is not to make it easy.
    public func computeDigitalSignature(digest: [UInt8]) async throws -> [UInt8] {
        guard digest.count == 32 else {
            throw CardError.malformedResponse(
                "PSO:CDS takes a single 32-byte digest, got \(digest.count) bytes"
            )
        }
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0x2A,
            p1: 0x9E, p2: 0x9A,
            data: digest,
            // Le = 0x00 (256) covers the largest response this can produce: 72
            // bytes of DER for a secp256k1 signature.
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .computeSignature)
        return response.data
    }

    public func changeReferenceData(
        reference: OpenPGPPinReference,
        oldPIN: [UInt8],
        newPIN: [UInt8],
        operation: OpenPGPOperation
    ) async throws {
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0x24, p1: 0x00, p2: reference.rawValue,
            data: oldPIN + newPIN,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: operation)
    }

    /// `TERMINATE DF` (INS 0xE6) — wipes the applet and deactivates the DF.
    ///
    /// **Access condition** (spec 3.4.1): "VERIFY of PW3 or Always if PW3 is
    /// blocked". So this command needs an Admin PIN verification *unless* the
    /// applet's PW3 counter is already at zero, which is the clause
    /// `reset()` uses to reset a card without asking for a PIN at all.
    ///
    /// This method sends the command and nothing else: the access condition is
    /// the caller's business, and `reset()` is the only caller that should ever
    /// make this destructive call.
    public func terminateDF() async throws {
        // TERMINATE DF is a case-1 command (no data, no Le). The previous form
        // sent a Le byte (00 E6 00 00 00), which real hardware rejected; the
        // correct form is 00 E6 00 00.
        let apdu = CommandAPDU(cla: 0x00, ins: 0xE6, p1: 0x00, p2: 0x00)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .terminate)
    }

    /// `ACTIVATE FILE` (INS 0x44) — the second half of an OpenPGP reset, and the
    /// only command a terminated DF accepts besides a re-SELECT.
    public func activateFile() async throws {
        // Case-1 command, no Le byte (00 44 00 00).
        let apdu = CommandAPDU(cla: 0x00, ins: 0x44, p1: 0x00, p2: 0x00)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .activate)
    }

    /// `GENERATE ASYMMETRIC KEY PAIR` in read mode (`P1 = 0x81`) returns the
    /// public key in `7F49`, with the EC point in `86`.
    ///
    /// The slot is addressed by the Control Reference Template sent as a **TLV
    /// with an empty value** (`B6 00` / `A4 00`). A bare tag (`B6`, Lc=01) was
    /// rejected by real hardware with `6A80`; this is the resolved form.
    ///
    /// For Ed25519 the point is the raw 32-byte Edwards point; whether the card
    /// prefixes it with `0x40` is an M0 hardware-verification item, and a
    /// non-matching encoding fails the ceremony's read-back step.
    public func readPublicKey(slot: KeySlot) async throws -> [UInt8] {
        let controlReference = KeySlotObjects.forSlot(slot).controlReference
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0x47, p1: 0x81, p2: 0x00,
            data: TLV(tag: controlReference, value: []).encoded,
            expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .readPublicKey)
        let objects = try TLVParser.parse(response.data)
        guard let point = TLVParser.find(OpenPGPDataObject.ecdsaPublicPoint, in: objects) else {
            // A public key template without an EC point is a non-EC key: on
            // firmware older than 5.2.3 (OpenPGP applet < 3.4) the slots default
            // to RSA, whose template carries modulus (0x81) and exponent (0x82)
            // instead of the EC point (0x86).
            if TLVParser.find(OpenPGPDataObject.rsaModulus, in: objects) != nil {
                throw CardError.unsupportedKeyType("an RSA key occupies the \(slot.displayName.lowercased())")
            }
            throw CardError.malformedResponse("public key template 7F49 had no EC point (86); YubiKey firmware 5.2.3 or newer is required for secp256k1/Ed25519")
        }
        // The card returns secp256k1 points as 65-byte uncompressed (04 || X || Y),
        // whereas the app derives them as 33-byte compressed. Normalise to
        // compressed so the read-back comparison is byte-for-byte; Ed25519 points
        // (32 raw bytes) pass through unchanged.
        let pointValue = point.value
        if pointValue.count == Secp256k1.uncompressedPublicKeyLength, pointValue.first == 0x04 {
            return try Secp256k1.compressedPublicKey(fromUncompressed: pointValue)
        }
        return pointValue
    }

    // MARK: SignerCard conformance

    /// The serial number from the application data, without `inventory()`'s work.
    ///
    /// `inventory()` probes both key slots to report occupancy, which is what an
    /// inventory is for and what a flow that only needs the card's identity must not
    /// pay for (amendment 33).
    func cardSerial() async throws -> String? {
        let parsed = try OpenPGPApplicationData.parse(
            applicationData: try await applicationData(),
            securitySupportTemplate: nil
        )
        return parsed.serial.map { String(format: "%08X", $0) }
    }

    /// One slot's key and everything the signing flow reads around it, from **one**
    /// session and **one** key read: see `SignerCard.readSigningIdentity(slot:)`.
    ///
    /// A card with no pairing manifest is reported without a key read: this app cannot
    /// use a key without the manifest that describes it, so reading one would spend the
    /// operator's tap on an answer nobody acts on. (The serial is read with `try?` for
    /// the same reason — a card that does not report one is recorded as a weaker
    /// signature, not as a failure — and a dead transport is caught by the key read
    /// rather than being reported as a missing manifest.)
    public func readSigningIdentity(slot: KeySlot) async throws -> SigningCardIdentity {
        let serial = (try? await cardSerial()) ?? nil
        guard let manifest = (try? await readPairingManifest()) ?? nil else {
            return SigningCardIdentity(
                serial: serial,
                publicKey: nil,
                pairingManifest: nil,
                signatureCounter: nil
            )
        }
        let publicKey = try await readPublicKey(slot: slot)
        // Only the signature slot has a hardware counter; asking the other slot for one
        // would be a card operation with a known-empty answer.
        let counter = slot == .signature ? ((try? await signatureCounter()) ?? nil) : nil
        return SigningCardIdentity(
            serial: serial,
            publicKey: publicKey,
            pairingManifest: manifest,
            signatureCounter: counter
        )
    }

    public func inventory() async throws -> CardInventory {
        let applicationData = try await applicationData()
        // The security support template is optional: a card that refuses it
        // should not block the inventory.
        let sst = try? await securitySupportTemplate()
        let parsed = try OpenPGPApplicationData.parse(applicationData: applicationData, securitySupportTemplate: sst)

        var attributes: [KeySlot: [UInt8]] = [:]
        if let value = parsed.algorithmAttributesSignature { attributes[.signature] = value }
        if let value = parsed.algorithmAttributesAuthentication { attributes[.authentication] = value }

        // Detect an existing key per slot by attempting a read. 6A88 ("referenced
        // data not found") means the slot is empty, which is the only reliable
        // signal — a fingerprint object may be present-but-zero.
        var occupied: Set<KeySlot> = []
        var probeFailures: [KeySlot: String] = [:]
        for slot in KeySlot.allCases {
            do {
                _ = try await readPublicKey(slot: slot)
                occupied.insert(slot)
            } catch CardError.unexpectedStatusWord(let sw1, let sw2)
                where (sw1 == 0x6A && sw2 == 0x88) || (sw1 == 0x65 && sw2 == 0x81) {
                // Empty slot. 6A88 ("referenced data not found") is what most
                // firmware answers; YubiKey 5.4.x answers 6581 ("memory failure")
                // for a slot that holds no key. Both mean "nothing here".
                continue
            } catch CardError.conditionsNotSatisfied {
                continue
            } catch CardError.unsupportedKeyType {
                // A non-EC key occupies the slot (RSA on firmware < 5.2.3). It
                // still counts as occupied so the destructive reset is gated;
                // the reset replaces it with the EC keys this app provisions.
                occupied.insert(slot)
            } catch let error as CardError {
                // Any other card-level failure while probing the slot — 6A80
                // "wrong data", 6D00 "instruction not supported", a 7F49 without
                // an EC point — must not abort the whole inventory. The
                // applet-version gate (isDefinitelyUnsupported) decides whether
                // the card can be provisioned; here we only want occupancy, so
                // record the failure and keep going so the version and serial are
                // still reported.
                probeFailures[slot] = Self.probeFailureDetail(error)
            }
        }

        let counter = parsed.signatureCounter

        // Whether this card can hold a manifest decides whether the pairing codes
        // can ever be produced again without a reset, so it is worth one extra
        // APDU here instead of a surprise at the end of a ceremony. It is not a
        // gate: a card that cannot store one is still provisionable.
        let pairingManifest: PairingManifestState
        do {
            if let value = try await readPairingManifest() {
                pairingManifest = .present(byteCount: value.count)
            } else {
                pairingManifest = .absent
            }
        } catch CardError.unsupportedFeature {
            pairingManifest = .unsupported
        } catch let error as CardError {
            pairingManifest = .unreadable(error.userFacingDescription)
        }

        return CardInventory(
            openPGPVersion: parsed.openPGPVersion ?? "unknown",
            manufacturer: parsed.manufacturer.map { String(format: "0x%04X", $0) },
            serial: parsed.serial.map { String(format: "%08X", $0) },
            algorithmAttributes: attributes,
            pwStatusBytes: parsed.pwStatusBytes,
            retryCounters: parsed.retryCounters,
            touchPolicy: [
                .signature: parsed.uifSignature?.first,
                .authentication: parsed.uifAuthentication?.first,
            ].compactMapValues { $0 },
            occupiedSlots: occupied,
            signatureCounter: counter,
            isFactoryFresh: occupied.isEmpty && (counter ?? 0) == 0,
            probeFailures: probeFailures,
            pairingManifest: pairingManifest
        )
    }

    /// Short human-readable reason for a slot-probe failure, for the inventory.
    private static func probeFailureDetail(_ error: CardError) -> String {
        switch error {
        case .unexpectedStatusWord(let sw1, let sw2):
            return String(format: "%02X%02X", sw1, sw2)
        case .unsupportedFeature(let detail):
            return detail
        case .malformedResponse(let detail):
            return detail
        default:
            return error.userFacingDescription
        }
    }

    // MARK: Reset

    /// A deliberately wrong PIN, sent to burn a retry counter (see `reset()`).
    ///
    /// All-zero, the same value `yubikit`'s `OpenPgpSession.reset()` sends
    /// (`_INVALID_PIN`). It cannot be a *correct* PIN — the applet's PINs are
    /// digits and this app never sets an all-zero one — and it is eight bytes,
    /// which is a legal length for both PW1 and PW3, so the applet counts it as a
    /// failed attempt instead of rejecting it as malformed (a malformed `VERIFY`
    /// is rejected *without* decrementing a counter, which would leave the reset
    /// unable to do its job — see the read-back in `blockPINRetryCounters()`).
    static let invalidPIN: [UInt8] = [UInt8](repeating: 0x00, count: 8)

    /// `ykman openpgp reset`, command for command: block both PINs, then
    /// `TERMINATE DF`, `ACTIVATE FILE` and a re-SELECT.
    ///
    /// **No Admin PIN is asked for, and none can be given.** The applet's access
    /// condition for `TERMINATE DF` is "VERIFY of PW3, or Always if PW3 is
    /// blocked", so on a card whose Admin PIN still works the only PIN-free route
    /// is to block PW3 *first* and terminate afterwards. That is what `yubikit`
    /// does — its `reset()` logs "Ensure the User and Admin PINs are blocked"
    /// before sending `TERMINATE` — and this method is a deliberate mirror of it,
    /// including burning PW1, which the access condition does not require and the
    /// reference implementation does anyway.
    ///
    /// The cost is recorded rather than hidden: the reset **begins** by making the
    /// card unusable. If the session drops after the burn and before the
    /// terminate, the card is left with both PINs blocked and its keys in place —
    /// it can neither sign nor be provisioned until the reset is finished.
    /// Finishing needs no PIN either (PW3 is blocked, which is exactly what
    /// `TERMINATE DF` wants), so tapping again recovers; saying so is the caller's
    /// job (`CeremonyStep.reset`'s interruption warning does).
    ///
    /// An earlier version verified the caller's Admin PIN here instead. That could
    /// not reset a card whose Admin PIN was blocked — the one state in which the
    /// applet deliberately drops the requirement — and asked the operator for a
    /// credential the reset is about to destroy (amendment 30).
    public func reset() async throws {
        try await blockPINRetryCounters()
        try await terminateDF()
        try await activateFile()
        selected = false
        try await select()
    }

    /// The first half of a reset: send wrong PINs until PW1 and PW3 are blocked.
    ///
    /// Every APDU here is *meant* to fail, so the answers are discarded — `63Cx`
    /// is the applet counting down, `6983` means that password is blocked already.
    /// A transport failure is **not** discarded: a broken session is not a
    /// rejected PIN, and it has to reach the caller.
    ///
    /// The counters are read first, so exactly as many attempts are burnt as the
    /// card says are left, and read *back* afterwards. Without the read-back, a
    /// rejection the applet declined to count would surface as `6982` on
    /// `TERMINATE DF` — a status word that says nothing about what the card now
    /// is. Same reasoning as the `SET PIN RETRIES` read-back (amendment 27).
    func blockPINRetryCounters() async throws {
        let before = try await retryCounters()
        for (reference, remaining) in [
            (OpenPGPPinReference.user, before.user),
            (OpenPGPPinReference.admin, before.admin),
        ] {
            for _ in 0..<Int(remaining) {
                let apdu = CommandAPDU(
                    cla: 0x00, ins: 0x20, p1: 0x00, p2: reference.rawValue,
                    data: Self.invalidPIN, expectedLength: 0
                )
                _ = try await transport.exchange(apdu)
            }
        }
        let after = try await retryCounters()
        guard after.user == 0, after.admin == 0 else {
            throw CardError.pinBlockingIncomplete(user: after.user, admin: after.admin)
        }
    }

    /// Remaining attempts per password, from DO `0xC4`.
    private func retryCounters() async throws -> RetryCounters {
        let bytes = try await getDataObject(OpenPGPDataObject.pwStatusBytes)
        guard let counters = PWStatusBytes.retryCounters(bytes) else {
            throw CardError.malformedResponse("DO 0xC4 did not report the PIN retry counters")
        }
        return counters
    }

    public func setPINs(userPIN: [UInt8], adminPIN: [UInt8]) async throws {
        // PW1 first: if PW3 fails after this, the Admin PIN is still the factory
        // default, so the operator is not locked out of the card.
        try await changeReferenceData(
            reference: .user,
            oldPIN: OpenPGPPinDefaults.user,
            newPIN: userPIN,
            operation: .changeUserPIN
        )
        try await changeReferenceData(
            reference: .admin,
            oldPIN: OpenPGPPinDefaults.admin,
            newPIN: adminPIN,
            operation: .changeAdminPIN
        )
    }

    /// Applies the mandatory policy to both signing-capable slots.
    ///
    /// The Admin PIN is required because `PUT DATA` of these objects is protected.
    public func applyPolicy(adminPIN: [UInt8]) async throws {
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)

        // Touch required for every use, and not relaxable later, on both slots.
        for slot in KeySlot.allCases {
            try await putData(
                tag: KeySlotObjects.forSlot(slot).uif,
                value: OpenPGPTouchPolicy.fixedEncoded,
                operation: .applyPolicy
            )
        }
        try await putData(
            tag: OpenPGPDataObject.pwStatusBytes,
            value: PWStatusBytes.encode(),
            operation: .applyPolicy
        )
    }

    /// `SET PIN RETRIES` (INS `0xF2`, `P1P2 = 0000`): how many wrong attempts each
    /// password tolerates before it blocks.
    ///
    /// The three values are, in order, PW1, the resetting code and PW3. The Admin
    /// PIN must be verified **in this session** — VERIFY state does not survive a
    /// session boundary — and the command needs firmware 4.3.1 or newer.
    ///
    /// YubiKey 4/5 leave the PIN values alone; the old NEO applet reset all three
    /// passwords to their factory defaults when the counters changed, which is why
    /// `ykman` still warns about it for applet versions below 4.0. This app never
    /// runs against such an applet (the version gate refuses them), and the
    /// read-back in `ProvisioningCeremony.setPINRetries` is what would catch it if
    /// the assumption were ever wrong: the counter it reads back would not match.
    public func setPINRetries(
        user: Int,
        reset: Int,
        admin: Int,
        adminPIN: [UInt8]
    ) async throws {
        // The applet's documented range, checked before the card is asked: the
        // answer would be the same every time (`6A80`), and a wrong argument is not
        // worth a card round trip.
        for value in [user, reset, admin] {
            guard (1...99).contains(value) else {
                throw CardError.retryCountOutOfRange(requested: value, allowed: 1...99)
            }
        }
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)
        let apdu = CommandAPDU(
            cla: 0x00, ins: 0xF2, p1: 0x00, p2: 0x00,
            data: [UInt8(user), UInt8(reset), UInt8(admin)], expectedLength: 0
        )
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .setPinRetries)
    }

    public func importKey(
        slot: KeySlot,
        algorithm: KeyAlgorithm,
        privateKey: SensitiveBytes,
        fingerprint: [UInt8],
        creationTime: Date,
        adminPIN: [UInt8]
    ) async throws {
        // Re-verify in THIS session: the ceremony spans several short-lived NFC
        // sessions, and VERIFY state does not survive a session boundary.
        try await verify(pin: adminPIN, reference: .admin, operation: .verifyAdminPIN)

        var raw = privateKey.materializedCopy()
        defer { wipe(&raw) }

        let objects = KeySlotObjects.forSlot(slot)

        // Algorithm attributes MUST be written before the key: the card needs to
        // know the curve to interpret the 32-byte key material. The previous
        // order — import first, attributes second — failed on real hardware with
        // 6A80 because the slot still carried its default RSA attributes.
        do {
            try await putData(
                tag: objects.algorithmAttributes,
                value: KeyImportTemplate.algorithmAttributes(for: algorithm),
                operation: .setAlgorithmAttributes
            )
        } catch let error as CardError {
            // Name the algorithm and the slot: a bare `6A80` here is reported as
            // "unsupported firmware", which is one of several causes and not the
            // one an operator can act on (amendment 29).
            throw CardError.algorithmAttributesRejected(
                algorithm: algorithm.displayName,
                slot: slot.displayName,
                detail: error.userFacingDescription
            )
        }

        // The addressed slot must be empty: PUT DATA of a private key is rejected
        // on an occupied slot, and the ceremony treats that as a hard failure
        // rather than trying to work around it.
        try await putData(
            tag: OpenPGPDataObject.extendedHeaderList,
            value: KeyImportTemplate.extendedHeaderList(privateKey: raw, slot: slot),
            addressing: (0x3F, 0xFF),
            ins: 0xDB,
            operation: .importKey
        )

        try await putData(
            tag: objects.fingerprint,
            value: KeyImportTemplate.paddedFingerprint(fingerprint),
            operation: .importKey
        )

        // Creation time is advisory metadata. The tag is the one design.md
        // specifies; if the firmware rejects it the ceremony continues, because
        // the fingerprint and the read-back comparison are the real checks.
        do {
            try await putData(
                tag: objects.timestamp,
                value: KeyImportTemplate.creationTime(creationTime),
                operation: .importKey
            )
        } catch let error as CardError {
            switch error {
            case .unexpectedStatusWord, .unsupportedFeature, .keyImportRejected:
                // The generation time is advisory metadata; a card that rejects
                // it (e.g. an unknown tag) must not fail the ceremony.
                break
            default:
                throw error
            }
        }
    }

    public func signatureCounter() async throws -> UInt32 {
        let sst = try await securitySupportTemplate()
        let objects = try TLVParser.parse(sst)
        guard let counter = TLVParser.find(OpenPGPDataObject.signatureCounter, in: objects)?.value,
              counter.count == 3
        else {
            throw CardError.malformedResponse("security support template had no 0x93 signature counter")
        }
        return (UInt32(counter[0]) << 16) | (UInt32(counter[1]) << 8) | UInt32(counter[2])
    }

    /// `GET CHALLENGE` (INS 0x84) — the card's hardware random-number generator.
    ///
    /// This is the entropy source for mnemonic generation (design.md §4.2 step 4):
    /// the 256 BIP39 entropy bits come from the YubiKey's secure element rather
    /// than the iOS CSPRNG. The exact per-call response-length limit is an M0
    /// hardware-verification item (`docs/m0-hardware-verification.md`); this
    /// requests `count` bytes in one call and fails if fewer come back.
    public func randomBytes(count: Int) async throws -> SensitiveBytes {
        let apdu = CommandAPDU(cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: [], expectedLength: count)
        let response = try await transport.exchange(apdu)
        try Self.check(response, operation: .getChallenge)
        guard response.data.count == count else {
            throw CardError.malformedResponse("GET CHALLENGE returned \(response.data.count) bytes, expected \(count)")
        }
        return SensitiveBytes(copying: response.data)
    }

    // MARK: Status word handling

    static func check(_ response: ResponseAPDU, operation: OpenPGPOperation) throws {
        if let error = OpenPGPStatusMapper.error(for: response.status, context: operation) {
            throw error
        }
    }
}
