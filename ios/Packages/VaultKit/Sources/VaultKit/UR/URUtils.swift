//
// Ported from Blockchain Commons URKit (Sources/URKit), commit ebba59b2e1538cb368d98147dd58c452e6d1dc47
// https://github.com/BlockchainCommons/URKit
// Licensed under the "BSD-2-Clause Plus Patent License"; see LICENSE-URKit.txt
//
// Adaptations for VaultKit (documented so the diff against upstream is auditable):
//   * `import DCBOR` removed; CBOR types now come from VaultKit/Encoding/CBOR.swift
//   * CryptoKit SHA-256 replaced with VaultKit's in-repo SHA256
//   * `UInt32.serialized` / `deserialize(_:_:)` live in VaultKit/Support/Bytes.swift
// The fountain/bytewords/UR algorithms themselves are unmodified.
//

import Foundation

extension Character {
    var isURType: Bool {
        if "a" <= self && self <= "z" { return true }
        if "0" <= self && self <= "9" { return true }
        if self == "-" { return true }
        return false
    }
}

extension String {
    var isURType: Bool { allSatisfy { $0.isURType } }
}
