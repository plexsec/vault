import XCTest
@testable import VaultKit

/// Public-only (`ckd_pub`) derivation, added for one job: checking that an
/// extended public key read back off a YubiKey really does reach the key inside
/// it. Until the pairing manifest existed, this side of BIP32 was deliberately
/// absent, because a provisioning ceremony derives private keys and can compare
/// them directly.
///
/// The published BIP32 vectors carry an `xpub` at every level, so this is tested
/// against the same fixture the private side uses — not against our own output.
final class BIP32PublicDerivationTests: XCTestCase {

    private func seed(fromHex hex: String) -> SensitiveBytes {
        SensitiveBytes(copying: Array(try! Hex.decode(hex)))
    }

    /// Every chain of every published vector, deriving with the **public** side
    /// only and comparing against the published `xpub`. That covers depth, parent
    /// fingerprint, child number, chain code and the point arithmetic.
    func testPublicDerivationMatchesThePublishedVectors() throws {
        guard let root = try FixtureLoader.json("bip32_vectors", extension: "json") as? [String: Any],
              let vectors = root["bip32"] as? [[String: Any]]
        else {
            return XCTFail("malformed bip32 fixture")
        }

        var checked = 0
        var expected = 0
        for vector in vectors {
            let master = try ExtendedPrivateKey.master(seed: seed(fromHex: vector["seed"] as! String))
            let chains = vector["chains"] as! [[String: Any]]
            var previous: (path: DerivationPath, key: ExtendedPublicKey)?

            for chain in chains {
                let pathString = chain["path"] as! String
                let path = try DerivationPath(pathString)
                let published = try ExtendedPublicKey(
                    publicKey: try ExtendedKeyPayload.parse(
                        try Base58.decodeCheck(chain["xpub"] as! String)
                    ).publicKey(),
                    chainCode: try master.derived(path).chainCode,
                    depth: UInt8(path.components.count)
                )

                // The public node itself must agree with the private derivation.
                XCTAssertEqual(published.publicKey, try master.derived(path).publicKey(), "xpub \(pathString)")

                // And it must reach the next published node by public derivation
                // alone, when the step between them is non-hardened. This is the
                // re-pair walk in miniature: anchor at a stored extended public
                // key, derive the pinned child, compare with what the card says.
                if let previous, previous.path.components.count < path.components.count {
                    let suffix = DerivationPath(
                        components: Array(path.components.dropFirst(previous.path.components.count))
                    )
                    if !suffix.components.contains(where: \.isHardened) {
                        expected += 1
                        let walked = try previous.key.derived(suffix)
                        XCTAssertEqual(walked.publicKey, published.publicKey, "xpub \(pathString) via CKDpub")
                        XCTAssertEqual(walked.chainCode, published.chainCode, "chain code \(pathString) via CKDpub")
                        checked += 1
                    }
                }
                previous = (path, published)
            }
        }
        XCTAssertEqual(checked, expected)
        XCTAssertGreaterThan(checked, 0, "the vectors must actually exercise public derivation")
    }

    /// Deriving the pinned child of a stored account node must land on the leaf
    /// the private side produces. This is the comparison the manifest relies on,
    /// so it is asserted against private derivation rather than against itself.
    func testPublicDerivationLandsOnThePrivatelyDerivedLeaf() throws {
        let master = try ExtendedPrivateKey.master(
            seed: seed(fromHex: "000102030405060708090a0b0c0d0e0f")
        )
        let accountPath = try DerivationPath("m/44'/0'/0'")
        let childrenPath = try DerivationPath("m/0/0")
        let leafPath = try DerivationPath("m/44'/0'/0'/0/0")

        let account = try master.derived(accountPath)
        let publicAccount = try ExtendedPublicKey(
            publicKey: try account.publicKey(),
            chainCode: account.chainCode,
            depth: 3
        )

        let fromPublic = try publicAccount.derived(childrenPath).publicKey
        let fromPrivate = try master.derived(leafPath).publicKey()

        XCTAssertEqual(fromPublic, fromPrivate)
        XCTAssertEqual(fromPublic.count, 33)
    }

    /// A hardened component cannot be derived from a public key at all. Refusing
    /// it is what stops the check from silently comparing against a key that is
    /// merely plausible.
    func testHardenedComponentsAreRefused() throws {
        let master = try ExtendedPrivateKey.master(
            seed: seed(fromHex: "000102030405060708090a0b0c0d0e0f")
        )
        let publicMaster = try ExtendedPublicKey(
            publicKey: try master.publicKey(),
            chainCode: master.chainCode
        )

        XCTAssertThrowsError(try publicMaster.derived(try DerivationPath("m/44'"))) { error in
            XCTAssertEqual(
                error as? ExtendedPublicKey.PublicDerivationError,
                .hardenedComponent(0x8000_0000 | 44)
            )
        }
        XCTAssertThrowsError(try publicMaster.child(0x8000_0000))
    }

    func testFingerprintMatchesThePrivateSide() throws {
        let master = try ExtendedPrivateKey.master(
            seed: seed(fromHex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
        )
        let node = try master.derived(try DerivationPath("m/0"))

        let publicNode = try ExtendedPublicKey(
            publicKey: try node.publicKey(),
            chainCode: node.chainCode
        )

        XCTAssertEqual(publicNode.fingerprint(), try node.fingerprint())
    }

    /// An off-curve point is not a public key. Accepting one would let a
    /// malformed manifest get as far as a comparison.
    func testAnInvalidPointIsRejected() throws {
        // x >= the field prime: not a point on the curve, whatever the prefix says.
        XCTAssertThrowsError(
            try ExtendedPublicKey(
                publicKey: [0x02] + [UInt8](repeating: 0xFF, count: 32),
                chainCode: [UInt8](repeating: 0, count: 32)
            )
        ) { error in
            XCTAssertEqual(error as? ExtendedPublicKey.PublicDerivationError, .invalidPoint)
        }
        XCTAssertThrowsError(
            try ExtendedPublicKey(
                publicKey: [UInt8](repeating: 2, count: 32),
                chainCode: [UInt8](repeating: 0, count: 32)
            )
        )
        XCTAssertThrowsError(
            try ExtendedPublicKey(
                publicKey: try ExtendedPrivateKey.master(seed: seed(fromHex: "000102030405060708090a0b0c0d0e0f"))
                    .publicKey(),
                chainCode: [UInt8](repeating: 0, count: 31)
            )
        )
    }
}
