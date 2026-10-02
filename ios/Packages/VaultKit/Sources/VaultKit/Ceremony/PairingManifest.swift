import Foundation

/// The four "private use" data objects of the OpenPGP card applet (spec §4.3.1).
///
/// The spec makes these optional and announces them in Extended Capabilities;
/// YubiKey 5 implements them, which `docs/m0-hardware-verification.md` records as
/// measured, not assumed. Each one is a plain byte string of up to 254 bytes
/// ("can be used to store any information").
///
/// The four exist precisely because their access conditions differ, and that
/// difference decides which one is usable. Measured on firmware 5.8.0 — empty
/// objects answer `9000` for the two readable without a PIN, and `6982` for the
/// two that need one:
///
/// | object | read      | write | usable for a manifest?                     |
/// |--------|-----------|-------|--------------------------------------------|
/// | 0x0101 | no PIN    | PW2   | no — PW2 is the resetting code, unset here |
/// | 0x0102 | no PIN    | PW3   | **yes** — read free, written with the admin PIN the ceremony already verified |
/// | 0x0103 | PW2       | PW2   | no — a re-pair must not need a PIN to read  |
/// | 0x0104 | PW3       | PW3   | no — same reason                            |
public enum PrivateUseDataObject: UInt16, CaseIterable, Sendable {
    case one = 0x0101
    case two = 0x0102
    case three = 0x0103
    case four = 0x0104

    /// The spec's per-object limit: "max. 254 (dec.) bytes".
    public static let maximumValueLength = 254

    /// Which secret, if any, must have been presented for the operation.
    public enum AccessCondition: Equatable, Sendable {
        case none
        /// PW2 — the resetting code, which this app never sets.
        case pw2
        /// PW3 — the Admin PIN.
        case pw3
    }

    public var readAccess: AccessCondition {
        switch self {
        case .one, .two: return .none
        case .three: return .pw2
        case .four: return .pw3
        }
    }

    public var writeAccess: AccessCondition {
        switch self {
        case .one: return .pw2
        case .two: return .pw3
        case .three: return .pw2
        case .four: return .pw3
        }
    }

    /// The object the pairing manifest lives in.
    ///
    /// It is the only one of the four that is both readable with no PIN and
    /// writable with the Admin PIN. The read half is what makes a re-pair
    /// possible at all — an operator who has to re-pair a wallet should not have
    /// to find a PIN for a card that is only being read — and the write half is
    /// free, because the ceremony has already verified PW3 by the time it writes.
    ///
    /// `PrivateUseDataObjectTests` pins both halves of that, so swapping this to
    /// 0x0103 (which reads as `6982` on hardware) fails a test instead of failing
    /// on a card.
    public static let pairingManifest: PrivateUseDataObject = .two
}

/// The public key material a card needs in order to be re-paired without being
/// reset, and without the mnemonic ever being typed again.
///
/// # Why this exists
///
/// A pairing code is a `crypto-hdkey` UR, and every one of them carries a chain
/// code. The YubiKey cannot supply that chain code: the OpenPGP applet stores a
/// key, not a BIP32 node (design.md §4.3), and the chain code lives only in the
/// node derived from the mnemonic. Without this manifest the only way to show
/// the pairing codes again is to re-run the whole ceremony — which resets the
/// applet and destroys the keys.
///
/// # What is stored, and what that costs
///
/// Only public material: the secp256k1 **account** extended public key (the same
/// key a Keystone/MetaMask wallet is handed), the Ed25519 key with its chain
/// code, the master fingerprint, and the card's serial. Nothing here is secret,
/// and the public key in the card's signature slot is already readable without a
/// PIN (`GENERATE ASYMMETRIC KEY PAIR P1=81` is "read always"), so the marginal
/// exposure is the chain code and the fingerprint.
///
/// It is stored as **public** data deliberately. Anyone who reads it learns what
/// the desktop wallet is told anyway; it is not a signing capability, and the
/// card still requires PIN and touch for every signature.
///
/// # Why the verification is the interesting part
///
/// A manifest that is merely *present* proves nothing: it could be stale, from
/// another card, or corrupted. So a re-pair derives the pinned child of the
/// stored account node and compares it with the public key the card reports for
/// its own signature slot — see `cardLeafPublicKey(for:)` and
/// `verify(against:)`. That binds the manifest to the key physically inside the
/// card using nothing but public derivation.
public struct PairingManifest: Equatable, Sendable {
    /// Bumped if the encoding below ever changes; a reader must refuse a version
    /// it does not know rather than guess at the layout.
    public static let currentVersion: UInt8 = 1

    public struct Entry: Equatable, Sendable {
        public let algorithm: KeyAlgorithm
        /// 33 bytes for secp256k1's account node, 32 for Ed25519.
        public let publicKey: [UInt8]
        public let chainCode: [UInt8]
        public let parentFingerprint: [UInt8]
        /// The path written into the UR's `origin` field.
        public let originPath: DerivationPath
        /// `children` — present only when the exported key is an ancestor of the
        /// card's leaf, which is how a deriving wallet is pinned to the one key
        /// the card can actually sign with.
        public let childrenPath: DerivationPath?

        public init(
            algorithm: KeyAlgorithm,
            publicKey: [UInt8],
            chainCode: [UInt8],
            parentFingerprint: [UInt8],
            originPath: DerivationPath,
            childrenPath: DerivationPath?
        ) {
            self.algorithm = algorithm
            self.publicKey = publicKey
            self.chainCode = chainCode
            self.parentFingerprint = parentFingerprint
            self.originPath = originPath
            self.childrenPath = childrenPath
        }

        /// Parses an export's hex fields back into bytes. Failable rather than
        /// throwing because a malformed fingerprint here means "do not write a
        /// manifest", not "abort a ceremony whose keys are already in the card".
        public init?(export: PairingExport) {
            guard let parentFingerprint = try? Hex.decode(export.parentFingerprintHex),
                  parentFingerprint.count == 4
            else { return nil }
            self.algorithm = export.algorithm
            self.publicKey = export.publicKey
            self.chainCode = export.chainCode
            self.parentFingerprint = parentFingerprint
            self.originPath = export.path
            self.childrenPath = export.childrenPath
        }
    }

    public let version: UInt8
    /// The card this manifest was written for, from the OpenPGP application data.
    public let cardSerial: [UInt8]
    /// The BIP32 master fingerprint, which every exported key names as its
    /// `source-fingerprint`. Keystone refuses a key without one.
    public let masterFingerprint: [UInt8]
    public let entries: [Entry]

    public init(
        version: UInt8 = PairingManifest.currentVersion,
        cardSerial: [UInt8],
        masterFingerprint: [UInt8],
        entries: [Entry]
    ) {
        self.version = version
        self.cardSerial = cardSerial
        self.masterFingerprint = masterFingerprint
        self.entries = entries
    }

    public func entry(for algorithm: KeyAlgorithm) -> Entry? {
        entries.first { $0.algorithm == algorithm }
    }

    // MARK: - Encoding

    public enum DecodeError: Swift.Error, Equatable {
        case tooShort(Int)
        case unknownVersion(UInt8)
        case badChecksum
        case malformed(String)
    }

    /// Fixed-layout, checksummed, self-describing.
    ///
    /// ```text
    /// version(1) | cardSerial(4) | masterFingerprint(4) |
    ///   entry* | checksum(4)
    ///
    /// entry := algorithm(1) | pubkeyLen(1) | pubkey | chainCode(32) |
    ///          parentFingerprint(4) | originCount(1) | origin(4 each) |
    ///          childrenCount(1) | children(4 each)
    /// ```
    ///
    /// The paths are stored rather than assumed to be the ones this version of
    /// the app happens to use, because the whole point of the manifest is to be
    /// read back by a *later* build: a future version that moves a path must
    /// still re-pair a card written by this one.
    ///
    /// Two entries encode to 194 bytes, comfortably inside the 254-byte limit;
    /// `PairingManifestTests` asserts that a full manifest still fits.
    public func encoded() -> [UInt8] {
        var out: [UInt8] = [version]
        out += cardSerial
        out += masterFingerprint
        for entry in entries {
            out.append(entry.algorithm.manifestTag)
            out.append(UInt8(entry.publicKey.count))
            out += entry.publicKey
            out += entry.chainCode
            out += entry.parentFingerprint
            out.append(UInt8(entry.originPath.components.count))
            for component in entry.originPath.components {
                out += Self.uint32Bytes(component.index)
            }
            let children = entry.childrenPath?.components ?? []
            out.append(UInt8(children.count))
            for component in children {
                out += Self.uint32Bytes(component.index)
            }
        }
        out += Array(SHA256.hash(out).prefix(4))
        return out
    }

    public static func decode(_ bytes: [UInt8]) throws -> PairingManifest {
        guard bytes.count >= 4 + 1 + 4 + 4 + 4 else { throw DecodeError.tooShort(bytes.count) }

        let body = Array(bytes.dropLast(4))
        let checksum = Array(bytes.suffix(4))
        // The checksum is checked before any field is trusted: a truncated or
        // corrupted object must fail here rather than decode into a manifest
        // whose paths happen to parse.
        guard Array(SHA256.hash(body).prefix(4)) == checksum else { throw DecodeError.badChecksum }

        var cursor = Cursor(body)
        let version = try cursor.byte()
        guard version == PairingManifest.currentVersion else { throw DecodeError.unknownVersion(version) }
        let serial = try cursor.bytes(4)
        let masterFingerprint = try cursor.bytes(4)

        var entries: [Entry] = []
        while cursor.remaining > 0 {
            let tag = try cursor.byte()
            guard let algorithm = KeyAlgorithm(manifestTag: tag) else {
                throw DecodeError.malformed("unknown algorithm tag 0x\(String(format: "%02x", tag))")
            }
            let publicKeyLength = Int(try cursor.byte())
            let publicKey = try cursor.bytes(publicKeyLength)
            let chainCode = try cursor.bytes(32)
            let parentFingerprint = try cursor.bytes(4)
            let originPath = DerivationPath(components: try cursor.path())
            let childrenComponents = try cursor.path()
            let childrenPath = childrenComponents.isEmpty ? nil : DerivationPath(components: childrenComponents)

            guard publicKeyLength == algorithm.publicKeyLength else {
                throw DecodeError.malformed(
                    "\(algorithm.rawValue) public key is \(publicKeyLength) bytes, expected \(algorithm.publicKeyLength)"
                )
            }
            guard entries.allSatisfy({ $0.algorithm != algorithm }) else {
                throw DecodeError.malformed("duplicate \(algorithm.rawValue) entry")
            }
            entries.append(
                Entry(
                    algorithm: algorithm,
                    publicKey: publicKey,
                    chainCode: chainCode,
                    parentFingerprint: parentFingerprint,
                    originPath: originPath,
                    childrenPath: childrenPath
                )
            )
        }
        guard !entries.isEmpty else { throw DecodeError.malformed("no key entries") }

        return PairingManifest(
            version: version,
            cardSerial: serial,
            masterFingerprint: masterFingerprint,
            entries: entries
        )
    }

    // MARK: - Verification

    public enum VerificationError: Swift.Error, Equatable {
        case missingEntry(KeyAlgorithm)
        /// The manifest was read from a different card than the one in hand.
        case cardSerialMismatch(manifest: String, card: String)
        /// The manifest does not describe the key in this card's slot.
        case cardKeyMismatch(algorithm: KeyAlgorithm, expected: String, found: String)
        case derivationFailed(KeyAlgorithm)
    }

    /// The public key this manifest's entry must match inside the card.
    ///
    /// * secp256k1 — the entry is the account node, so the answer is its pinned
    ///   child (`childrenPath`), which is the key in the signature slot. A future
    ///   export that shipped the leaf itself still verifies: with no `children`
    ///   the entry *is* the leaf.
    /// * Ed25519 — the entry is already the leaf; SLIP-0010 is all-hardened, so
    ///   nothing below it can be derived from a public key and the comparison is
    ///   direct.
    public func cardLeafPublicKey(for algorithm: KeyAlgorithm) throws -> [UInt8] {
        guard let entry = entry(for: algorithm) else { throw VerificationError.missingEntry(algorithm) }
        guard let children = entry.childrenPath else { return entry.publicKey }

        let node = try ExtendedPublicKey(
            publicKey: entry.publicKey,
            chainCode: entry.chainCode,
            depth: UInt8(min(entry.originPath.components.count, 255)),
            parentFingerprint: entry.parentFingerprint,
            childNumber: entry.originPath.components.last?.index ?? 0
        )
        do {
            return try node.derived(children).publicKey
        } catch {
            throw VerificationError.derivationFailed(algorithm)
        }
    }

    /// Checks the manifest against the keys the card actually reports.
    ///
    /// This is the check that makes the manifest worth reading. Without it a
    /// re-pair would hand the wallet whatever extended public key the object
    /// happened to contain, and a wallet would happily derive — and show the
    /// operator — addresses this card cannot sign for.
    public func verify(against card: CardKeyReport) throws {
        guard !entries.isEmpty else { throw VerificationError.missingEntry(.secp256k1) }
        if let cardSerial = card.cardSerial, cardSerial != self.cardSerial {
            throw VerificationError.cardSerialMismatch(
                manifest: Hex.encode(self.cardSerial),
                card: Hex.encode(cardSerial)
            )
        }
        for entry in entries {
            guard let reported = card.publicKeys[entry.algorithm] else { continue }
            let expected = try cardLeafPublicKey(for: entry.algorithm)
            guard expected == reported else {
                throw VerificationError.cardKeyMismatch(
                    algorithm: entry.algorithm,
                    expected: Hex.encode(expected),
                    found: Hex.encode(reported)
                )
            }
        }
    }
}

/// What the card says about the keys in its slots, for a manifest check.
public struct CardKeyReport: Equatable, Sendable {
    public let cardSerial: [UInt8]?
    public let publicKeys: [KeyAlgorithm: [UInt8]]

    public init(cardSerial: [UInt8]?, publicKeys: [KeyAlgorithm: [UInt8]]) {
        self.cardSerial = cardSerial
        self.publicKeys = publicKeys
    }
}

// MARK: - Helpers

extension KeyAlgorithm {
    /// One byte identifying the algorithm inside a manifest. Deliberately not
    /// the raw-value string: the manifest is a byte format, and a renamed enum
    /// case must not silently change it.
    var manifestTag: UInt8 {
        switch self {
        case .secp256k1: return 0x01
        case .ed25519: return 0x02
        }
    }

    init?(manifestTag: UInt8) {
        switch manifestTag {
        case 0x01: self = .secp256k1
        case 0x02: self = .ed25519
        default: return nil
        }
    }
}

extension PairingManifest {
    static func uint32Bytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff),
        ]
    }

    /// Read cursor that refuses to run off the end. Every accessor that can fail
    /// throws `DecodeError.malformed` rather than trapping, because these bytes
    /// come off a card.
    struct Cursor {
        private let bytes: [UInt8]
        private var offset: Int

        init(_ bytes: [UInt8]) {
            self.bytes = bytes
            self.offset = 0
        }

        var remaining: Int { bytes.count - offset }

        mutating func byte() throws -> UInt8 {
            guard remaining >= 1 else { throw DecodeError.malformed("truncated") }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func bytes(_ count: Int) throws -> [UInt8] {
            guard count >= 0, remaining >= count else {
                throw DecodeError.malformed("truncated: wanted \(count), have \(remaining)")
            }
            defer { offset += count }
            return Array(bytes[offset..<(offset + count)])
        }

        mutating func path() throws -> [DerivationPath.Component] {
            let count = Int(try byte())
            var components: [DerivationPath.Component] = []
            components.reserveCapacity(count)
            for _ in 0..<count {
                let raw = try bytes(4)
                let index = UInt32(raw[0]) << 24 | UInt32(raw[1]) << 16 | UInt32(raw[2]) << 8 | UInt32(raw[3])
                components.append(
                    index >= 0x8000_0000 ? .hardened(index & 0x7fff_ffff) : .normal(index)
                )
            }
            return components
        }
    }
}
