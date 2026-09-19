import XCTest
@testable import VaultKit

/// BIP32 conformance against the published test vectors, plus the differential
/// fixtures produced by `tools/derive` (an independent implementation).
final class BIP32Tests: XCTestCase {

    private func seed(fromHex hex: String) -> SensitiveBytes {
        SensitiveBytes(copying: Array(try! Hex.decode(hex)))
    }

    /// Vectors 1-4 from BIP-0032, including the leading-zero retention cases.
    /// Serialised xprv/xpub match byte-for-byte, so this covers depth, parent
    /// fingerprint, child number, chain code and key data all at once.
    func testPublishedBIP32Vectors() throws {
        guard let root = try FixtureLoader.json("bip32_vectors", extension: "json") as? [String: Any],
              let vectors = root["bip32"] as? [[String: Any]]
        else {
            return XCTFail("malformed bip32 fixture")
        }
        XCTAssertEqual(vectors.count, 4)

        var checked = 0
        for vector in vectors {
            let seedHex = vector["seed"] as! String
            let chains = vector["chains"] as! [[String: Any]]
            let master = try ExtendedPrivateKey.master(seed: seed(fromHex: seedHex))

            for chain in chains {
                let pathString = chain["path"] as! String
                let path = try DerivationPath(pathString)
                let node = try master.derived(path)

                XCTAssertEqual(
                    try node.serialized(version: .mainnet),
                    chain["xprv"] as? String,
                    "xprv \(pathString)"
                )
                XCTAssertEqual(
                    try node.serializedPublic(version: .mainnet),
                    chain["xpub"] as? String,
                    "xpub \(pathString)"
                )
                checked += 1
            }
        }
        XCTAssertEqual(checked, 17)
    }

    /// BIP32 test vector 5: every listed extended key must be rejected, with the
    /// published reason (unknown version, version/key-data mismatch, bad prefix,
    /// out-of-range scalar, unparseable point, zero depth with non-zero
    /// parent/index).
    func testPublishedInvalidExtendedKeysAreRejected() throws {
        guard let root = try FixtureLoader.json("bip32_invalid_keys", extension: "json") as? [String: Any],
              let keys = root["invalid_extended_keys"] as? [String]
        else {
            return XCTFail("malformed invalid-key fixture")
        }
        XCTAssertEqual(keys.count, 14)

        for key in keys {
            XCTAssertThrowsError(
                try ExtendedKeyPayload.decode(key),
                "invalid extended key was accepted: \(key.prefix(16))…"
            )
        }
    }

    /// The happy path of the same parser: every key we serialise must validate,
    /// and the parsed public key must match the key we started from.
    func testSerialisedKeysRoundTripThroughValidator() throws {
        let master = try ExtendedPrivateKey.master(seed: seed(fromHex: String(repeating: "5a", count: 64)))
        let node = try master.derived(.secp256k1Default)

        let xprv = try node.serialized(version: .mainnet)
        let parsedPrivate = try ExtendedKeyPayload.decode(xprv)
        XCTAssertTrue(parsedPrivate.isPrivate)
        XCTAssertEqual(parsedPrivate.version, .mainnet)
        XCTAssertEqual(parsedPrivate.depth, node.depth)
        XCTAssertEqual(parsedPrivate.childNumber, node.childNumber)
        XCTAssertEqual(parsedPrivate.parentFingerprint, node.parentFingerprint)
        XCTAssertEqual(parsedPrivate.chainCode, node.chainCode)
        XCTAssertEqual(try parsedPrivate.publicKey(), try node.publicKey())

        let xpub = try node.serializedPublic(version: .mainnet)
        let parsedPublic = try ExtendedKeyPayload.decode(xpub)
        XCTAssertFalse(parsedPublic.isPrivate)
        XCTAssertEqual(parsedPublic.childNumber, node.childNumber)
        XCTAssertEqual(try parsedPublic.publicKey(), try node.publicKey())

        // Testnet uses different version bytes and must be recognised.
        let tpub = try node.serializedPublic(version: .testnet)
        XCTAssertEqual(try ExtendedKeyPayload.decode(tpub).version, .testnet)
    }

    func testValidatorRejectsCorruptedSerialisations() throws {
        let master = try ExtendedPrivateKey.master(seed: seed(fromHex: String(repeating: "11", count: 64)))
        let valid = try master.serialized(version: .mainnet)
        let payload = try Base58.decodeCheck(valid)

        // depth 0 with a non-zero parent fingerprint
        var badParent = payload; badParent[8] = 0x01
        XCTAssertThrowsError(try ExtendedKeyPayload.parse(badParent))

        // depth 0 with a non-zero child number
        var badIndex = payload; badIndex[12] = 0x01
        XCTAssertThrowsError(try ExtendedKeyPayload.parse(badIndex))

        // unknown version bytes
        var badVersion = payload; badVersion[0] = 0x00; badVersion[1] = 0x00
        XCTAssertThrowsError(try ExtendedKeyPayload.parse(badVersion))

        // private version carrying a public key prefix
        var mismatch = payload; mismatch[45] = 0x02
        XCTAssertThrowsError(try ExtendedKeyPayload.parse(mismatch))

        // truncated payload
        XCTAssertThrowsError(try ExtendedKeyPayload.parse(Array(payload.dropLast(1))))
    }

    /// Differential agreement with the independent Python implementation.
    ///
    /// The fixture now carries both algorithms, so a Swift-side bug in the
    /// secp256k1 key, either of its two address encodings, or the Ed25519 key
    /// shows up as a disagreement with a separate implementation.
    func testDifferentialDerivationVectors() throws {
        guard let root = try FixtureLoader.json("derivation_vectors", extension: "json") as? [String: Any],
              let vectors = root["vectors"] as? [[String: Any]]
        else {
            return XCTFail("malformed derivation fixture")
        }
        XCTAssertEqual(vectors.count, 48)

        var checkedSecp256k1 = 0
        var checkedEd25519 = 0

        for vector in vectors {
            let seedHex = vector["seed"] as! String
            let pathString = vector["path"] as! String
            let algorithm = vector["algorithm"] as! String
            let path = try DerivationPath(pathString)
            let seed = seed(fromHex: seedHex)

            switch algorithm {
            case "secp256k1":
                let node = try ExtendedPrivateKey.master(seed: seed).derived(path)
                let publicKey = try node.publicKey()

                XCTAssertEqual(
                    publicKey.hexString,
                    vector["public_key"] as? String,
                    "pubkey \(pathString)"
                )
                XCTAssertEqual(
                    Hex.encode(node.chainCode),
                    vector["chain_code"] as? String,
                    "chain code \(pathString)"
                )
                XCTAssertEqual(
                    Hex.encode(node.parentFingerprint),
                    vector["parent_fingerprint"] as? String,
                    "parent fingerprint \(pathString)"
                )
                XCTAssertEqual(
                    Hex.encode(try node.fingerprint()),
                    vector["fingerprint"] as? String,
                    "fingerprint \(pathString)"
                )
                XCTAssertEqual(
                    try EVMAddress.checksummed(fromPublicKey: publicKey),
                    vector["evm_address"] as? String,
                    "evm address \(pathString)"
                )
                XCTAssertEqual(
                    try BitcoinAddress.p2wpkh(publicKeyCompressed: publicKey),
                    vector["bitcoin_address"] as? String,
                    "bitcoin address \(pathString)"
                )
                checkedSecp256k1 += 1

            case "ed25519":
                let node = try ExtendedPrivateKeyEd25519.master(seed: seed).derived(path)
                var raw = node.key.materializedCopy()
                defer { wipe(&raw) }

                XCTAssertEqual(
                    raw.hexString,
                    vector["private_key"] as? String,
                    "ed25519 seed \(pathString)"
                )
                XCTAssertEqual(
                    node.chainCode.hexString,
                    vector["chain_code"] as? String,
                    "ed25519 chain code \(pathString)"
                )
                XCTAssertEqual(
                    node.parentFingerprint.hexString,
                    vector["parent_fingerprint"] as? String,
                    "ed25519 parent fingerprint \(pathString)"
                )
                XCTAssertEqual(
                    try node.fingerprint().hexString,
                    vector["fingerprint"] as? String,
                    "ed25519 fingerprint \(pathString)"
                )
                XCTAssertEqual(
                    try node.publicKey().hexString,
                    vector["public_key"] as? String,
                    "ed25519 pubkey \(pathString)"
                )
                checkedEd25519 += 1

            default:
                XCTFail("unknown algorithm in fixture: \(algorithm)")
            }
        }

        XCTAssertEqual(checkedSecp256k1, 30)
        XCTAssertEqual(checkedEd25519, 18)
    }

    func testDerivationPathParsing() throws {
        XCTAssertEqual(try DerivationPath("m").components, [])
        XCTAssertEqual(try DerivationPath("m/0").components, [.normal(0)])
        XCTAssertEqual(try DerivationPath("m/0'").components, [.hardened(0)])
        XCTAssertEqual(try DerivationPath("m/0h").components, [.hardened(0)])
        XCTAssertEqual(try DerivationPath("m/0H").components, [.hardened(0)])
        XCTAssertEqual(
            try DerivationPath("m/44'/60'/0'/0/0").components,
            [.hardened(44), .hardened(60), .hardened(0), .normal(0), .normal(0)]
        )
        XCTAssertEqual(try DerivationPath("m/44'/60'/0'/0/0").description, "m/44'/60'/0'/0/0")
        XCTAssertEqual(DerivationPath.secp256k1Default.indices, [0x8000_002C, 0x8000_0000, 0x8000_0000, 0, 0])
        XCTAssertEqual(DerivationPath.secp256k1Default.description, "m/44'/0'/0'/0/0")
        XCTAssertEqual(DerivationPath.ed25519Default.description, "m/44'/501'/0'/0'")
        XCTAssertTrue(DerivationPath.ed25519Default.components.allSatisfy(\.isHardened))

        XCTAssertThrowsError(try DerivationPath("44'/60'"))
        XCTAssertThrowsError(try DerivationPath("m/2147483648"))   // >= 2^31
        XCTAssertThrowsError(try DerivationPath("m/notanumber"))
        XCTAssertThrowsError(try DerivationPath(""))
    }

    func testDerivationPathPrefixAndAccountLevel() throws {
        let path = try DerivationPath("m/44'/60'/0'/0/0")
        XCTAssertEqual(path.accountLevel.description, "m/44'/60'/0'")
        XCTAssertEqual(path.prefix(0).description, "m")
    }

    /// BIP32 allows 128-512 bit seeds, so the boundary is 16...64 bytes, not
    /// exactly 64. The official vector 1 (16-byte seed) depends on this.
    func testMasterKeySeedLengthBoundaries() throws {
        for length in [16, 32, 64] {
            XCTAssertNoThrow(
                try ExtendedPrivateKey.master(seed: SensitiveBytes(count: length)),
                "seed length \(length) must be accepted"
            )
        }
        for length in [1, 15, 65, 128] {
            XCTAssertThrowsError(
                try ExtendedPrivateKey.master(seed: SensitiveBytes(count: length)),
                "seed length \(length) must be rejected"
            ) { error in
                XCTAssertEqual(error as? BIP32Error, .invalidSeedLength(length))
            }
        }
    }

    /// Hardened and non-hardened derivations must differ for the same index.
    func testHardenedAndNormalDiffer() throws {
        let master = try ExtendedPrivateKey.master(seed: seed(fromHex: String(repeating: "42", count: 64)))
        let hardened = try master.child(0x8000_0000)
        let normal = try master.child(0)
        XCTAssertNotEqual(try hardened.publicKey(), try normal.publicKey())
        XCTAssertEqual(hardened.depth, 1)
        XCTAssertEqual(normal.depth, 1)
        XCTAssertEqual(normal.childNumber, 0)
        XCTAssertEqual(hardened.childNumber, 0x8000_0000)
    }
}
