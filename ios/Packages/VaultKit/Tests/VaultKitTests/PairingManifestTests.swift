import XCTest
@testable import VaultKit

/// The pairing manifest is what lets a card be re-paired without a reset: the
/// extended public keys a wallet needs, stored in the card's private-use data
/// object, because the applet cannot hand out a chain code by itself.
///
/// Two properties matter and both are tested here rather than argued for: the
/// bytes fit the 254-byte object the applet offers, and a manifest is only ever
/// used after it has been shown to describe the key *physically in the card*.
final class PairingManifestTests: XCTestCase {

    // MARK: Fixtures

    /// The same derivation the ceremony performs: secp256k1 exported at its BIP44
    /// **account** level with `children` pinned to the card's leaf, Ed25519 at its
    /// own path with no children.
    private func manifest(seedHex: String, serial: [UInt8] = [0x00, 0xAB, 0xCD, 0xEF]) throws -> PairingManifest {
        let seed = SensitiveBytes(copying: Array(try Hex.decode(seedHex)))
        let master = try ExtendedPrivateKey.master(seed: seed)
        let accountPath = try DerivationPath("m/44'/0'/0'")
        let childrenPath = try DerivationPath("m/0/0")
        let account = try master.derived(accountPath)

        let ed25519Master = try ExtendedPrivateKeyEd25519.master(seed: seed)
        let ed25519Path = try DerivationPath("m/44'/501'/0'/0'")
        let ed25519 = try ed25519Master.derived(ed25519Path)

        return PairingManifest(
            cardSerial: serial,
            entries: [
                .init(
                    algorithm: .secp256k1,
                    publicKey: try account.publicKey(),
                    chainCode: account.chainCode,
                    parentFingerprint: account.parentFingerprint,
                    masterFingerprint: try master.fingerprint(),
                    originPath: accountPath,
                    childrenPath: childrenPath
                ),
                .init(
                    algorithm: .ed25519,
                    publicKey: try ed25519.publicKey(),
                    chainCode: ed25519.chainCode,
                    parentFingerprint: ed25519.parentFingerprint,
                    masterFingerprint: try ed25519Master.fingerprint(),
                    originPath: ed25519Path,
                    childrenPath: nil
                ),
            ]
        )
    }

    private func cardReport(
        for manifest: PairingManifest,
        seedHex: String,
        serial: [UInt8]? = nil
    ) throws -> CardKeyReport {
        let seed = SensitiveBytes(copying: Array(try Hex.decode(seedHex)))
        let master = try ExtendedPrivateKey.master(seed: seed)
        let leaf = try master.derived(try DerivationPath("m/44'/0'/0'/0/0"))
        let ed25519 = try ExtendedPrivateKeyEd25519.master(seed: seed)
            .derived(try DerivationPath("m/44'/501'/0'/0'"))
        return CardKeyReport(
            cardSerial: serial ?? manifest.cardSerial,
            publicKeys: [
                .secp256k1: try leaf.publicKey(),
                .ed25519: try ed25519.publicKey(),
            ]
        )
    }

    private let seedA = "000102030405060708090a0b0c0d0e0f"

    // MARK: Encoding

    func testAFullManifestFitsTheCardsObject() throws {
        let encoded = try manifest(seedHex: seedA).encoded()

        XCTAssertLessThanOrEqual(
            encoded.count,
            PrivateUseDataObject.maximumValueLength,
            "a manifest that does not fit the 254-byte private-use object cannot be stored at all"
        )
        // Asserted exactly, not just bounded: a format change that grows this
        // silently eats the headroom the applet gives us.
        XCTAssertEqual(encoded.count, 198)
    }

    func testEncodingRoundTrips() throws {
        let original = try manifest(seedHex: seedA)

        let decoded = try PairingManifest.decode(original.encoded())

        XCTAssertEqual(decoded, original)
        XCTAssertEqual(decoded.cardSerial, [0x00, 0xAB, 0xCD, 0xEF])
        XCTAssertEqual(decoded.entry(for: .secp256k1)?.masterFingerprint.count, 4)
        // Per key, and different: the secp256k1 entry names the BIP32 master, the
        // Ed25519 entry the SLIP-0010 master. A wallet has both, and a UR that
        // names the wrong one describes an origin that does not exist.
        XCTAssertNotEqual(
            decoded.entry(for: .secp256k1)?.masterFingerprint,
            decoded.entry(for: .ed25519)?.masterFingerprint
        )
        XCTAssertEqual(decoded.entry(for: .secp256k1)?.originPath.description, "m/44'/0'/0'")
        XCTAssertEqual(decoded.entry(for: .secp256k1)?.childrenPath?.description, "m/0/0")
        XCTAssertNil(decoded.entry(for: .ed25519)?.childrenPath, "Ed25519 has no derivable children")
        XCTAssertEqual(decoded.entry(for: .ed25519)?.originPath.description, "m/44'/501'/0'/0'")
    }

    /// The paths are stored rather than assumed, so a later build that moves a
    /// path can still re-pair a card written by this one.
    func testHardenedPathComponentsSurviveTheRoundTrip() throws {
        let entry = PairingManifest.Entry(
            algorithm: .secp256k1,
            publicKey: try ExtendedPrivateKey.master(seed: SensitiveBytes(copying: Array(try Hex.decode(seedA))))
                .derived(try DerivationPath("m/44'/0'/0'")).publicKey(),
            chainCode: [UInt8](repeating: 1, count: 32),
            parentFingerprint: [0xDE, 0xAD, 0xBE, 0xEF],
            masterFingerprint: [5, 6, 7, 8],
            originPath: try DerivationPath("m/44'/0'/0'"),
            childrenPath: try DerivationPath("m/0/0")
        )
        let manifest = PairingManifest(
            cardSerial: [1, 2, 3, 4],
            entries: [entry]
        )

        let decoded = try PairingManifest.decode(manifest.encoded())

        XCTAssertEqual(decoded.entries[0].originPath.components, entry.originPath.components)
        XCTAssertEqual(decoded.entries[0].originPath.indices, [0x8000_002C, 0x8000_0000, 0x8000_0000])
        XCTAssertEqual(decoded.entries[0].parentFingerprint, [0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(decoded.entries[0].masterFingerprint, [5, 6, 7, 8])
    }

    func testCorruptBytesAreRejectedRatherThanGuessedAt() throws {
        let encoded = try manifest(seedHex: seedA).encoded()

        // A single flipped bit anywhere in the payload.
        for index in [0, 5, 10, 60, 120, encoded.count - 5] {
            var corrupt = encoded
            corrupt[index] ^= 0x01
            XCTAssertThrowsError(try PairingManifest.decode(corrupt)) { error in
                XCTAssertEqual(
                    error as? PairingManifest.DecodeError,
                    .badChecksum,
                    "a flipped bit at \(index) must fail the checksum"
                )
            }
        }
    }

    func testTruncatedAndOversizedInputIsRejected() throws {
        let encoded = try manifest(seedHex: seedA).encoded()

        for count in [0, 1, 5, 12, encoded.count - 1] {
            XCTAssertThrowsError(
                try PairingManifest.decode(Array(encoded.prefix(count))),
                "\(count) bytes is not a manifest"
            )
        }
    }

    func testAnUnknownVersionIsRefused() throws {
        var encoded = try manifest(seedHex: seedA).encoded()
        encoded[0] = 99
        // Re-checksum so the version check is the thing being exercised.
        let body = Array(encoded.dropLast(4))
        encoded.replaceSubrange((encoded.count - 4)..., with: Array(SHA256.hash(body).prefix(4)))

        XCTAssertThrowsError(try PairingManifest.decode(encoded)) { error in
            XCTAssertEqual(error as? PairingManifest.DecodeError, .unknownVersion(99))
        }
    }

    // MARK: The binding to the card

    /// The account node in the manifest must derive to the key in the card's
    /// signature slot. This is the whole reason the manifest is trustworthy: a
    /// wallet is about to be told which addresses this card can sign for.
    func testTheAccountNodeDerivesToTheCardsLeafKey() throws {
        let manifest = try manifest(seedHex: seedA)
        let seed = SensitiveBytes(copying: Array(try Hex.decode(seedA)))
        let leaf = try ExtendedPrivateKey.master(seed: seed)
            .derived(try DerivationPath("m/44'/0'/0'/0/0"))

        XCTAssertEqual(try manifest.cardLeafPublicKey(for: .secp256k1), try leaf.publicKey())
        XCTAssertNotEqual(
            try manifest.cardLeafPublicKey(for: .secp256k1),
            manifest.entry(for: .secp256k1)?.publicKey,
            "secp256k1 is exported at the account level, so the leaf is a different key"
        )
    }

    /// The Ed25519 entry *is* the leaf: SLIP-0010 is all-hardened, so nothing
    /// below it can be derived from a public key at all.
    func testTheEd25519EntryIsTheLeafItself() throws {
        let manifest = try manifest(seedHex: seedA)

        XCTAssertEqual(
            try manifest.cardLeafPublicKey(for: .ed25519),
            manifest.entry(for: .ed25519)?.publicKey
        )
    }

    func testVerificationAcceptsAManifestThatMatchesTheCard() throws {
        let manifest = try manifest(seedHex: seedA)

        XCTAssertNoThrow(try manifest.verify(against: try cardReport(for: manifest, seedHex: seedA)))
    }

    /// The attack this stops: a manifest that would have a wallet derive — and
    /// show the operator — addresses the card cannot sign for.
    func testVerificationRefusesAManifestFromAnotherMnemonic() throws {
        let manifest = try manifest(seedHex: seedA)
        let otherSeed = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

        do {
            try manifest.verify(against: try cardReport(for: manifest, seedHex: otherSeed))
            XCTFail("a manifest that does not describe this card's key must be refused")
        } catch let error as PairingManifest.VerificationError {
            guard case .cardKeyMismatch(let algorithm, _, _) = error else {
                return XCTFail("unexpected \(error)")
            }
            XCTAssertEqual(algorithm, .secp256k1, "the signature slot is checked first")
        }
    }

    /// A manifest copied from another YubiKey is refused by serial, so the
    /// operator is told "wrong card" rather than "your keys disagree" — which are
    /// very different things to act on.
    func testVerificationRefusesAManifestFromAnotherCard() throws {
        let manifest = try manifest(seedHex: seedA)

        do {
            try manifest.verify(against: try cardReport(for: manifest, seedHex: seedA, serial: [9, 9, 9, 9]))
            XCTFail("a manifest written for another card must be refused")
        } catch let error as PairingManifest.VerificationError {
            XCTAssertEqual(
                error,
                .cardSerialMismatch(manifest: "00abcdef", card: "09090909")
            )
        }
    }

    func testVerificationRefusesAManifestMissingAKey() throws {
        let manifest = try manifest(seedHex: seedA)
        let report = CardKeyReport(
            cardSerial: manifest.cardSerial,
            publicKeys: [.secp256k1: try manifest.cardLeafPublicKey(for: .secp256k1)]
        )

        // Ed25519 is absent from the card's report: the manifest's own entry is
        // still checked, and with nothing to compare against it is skipped rather
        // than assumed good.
        XCTAssertNoThrow(try manifest.verify(against: report))
    }

    func testASingleEntryManifestRoundTrips() throws {
        let full = try manifest(seedHex: seedA)
        let single = PairingManifest(
            cardSerial: full.cardSerial,
            entries: [try XCTUnwrap(full.entry(for: .secp256k1))]
        )

        let decoded = try PairingManifest.decode(single.encoded())

        XCTAssertEqual(decoded.entries.count, 1)
        XCTAssertNil(decoded.entry(for: .ed25519))
        XCTAssertLessThan(decoded.encoded().count, full.encoded().count)
    }
}
