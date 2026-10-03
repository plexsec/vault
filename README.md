# PlexVault — v0.2 (provisioning + EVM signing)

An offline iOS app that provisions a YubiKey 5 as a minimum-trust, air-gapped
signer, plus the supporting tooling to verify it. The design is in
[`design.md`](design.md); this file explains what actually exists.

**v0.1 was provisioning only. v0.2 signs EVM transactions.** Provisioning resets a
YubiKey, generates or restores a BIP39 mnemonic, derives **two** keys from it — ECDSA
secp256k1 and Ed25519 — imports them into the OpenPGP applet's signature and
authentication slots, verifies each import by reading the public key back, and exports
both public keys for a desktop wallet. One key per *algorithm* means every secp256k1
chain shares one key and every Ed25519 chain shares the other.

Signing reads an `eth-sign-request` from the wallet's animated QR code, decodes the
transaction (legacy, EIP-2930 or EIP-1559), checks it against the account the card holds,
shows what it actually does, signs it with one PIN and one touch, verifies the signature
against the card's own key, and shows the `eth-signature` back as a QR code. It works on
any EVM chain — the chain id comes from the request and is confirmed by the operator each
session, never from a stored list — and the screens name the chain and its coin
(`Polygon (chain id 137), native token POL`), falling back to the bare id and `<n> native`
for a chain the app does not know rather than assuming ETH. Nothing is
written to the card, and the mnemonic is never needed. Bitcoin PSBTs, EIP-712 and
`personal_sign` are refused with an explanation (§3.2, §10 item 9).

## What is here

```
design.md                     the design specification (amended; see docs/design-amendments.md)
ios/
  project.yml                 XcodeGen source of truth; PlexVault.xcodeproj is generated and committed
  PlexVault/                  the SwiftUI app
  Packages/VaultKit/          pure logic: crypto (secp256k1 + Ed25519), BIP39, BIP32, SLIP-0010, addresses, BC-UR, RLP,
                              EVM transactions, ECDSA signature handling, the provisioning ceremony, the pairing
                              manifest, the signing ceremony
  Packages/YubikeyKit/        ISO 7816 / OpenPGP APDU layer + NFC, USB-C and simulated transports, private-use data objects,
                              PSO:CDS signing
tools/
  derive/                     independent Python oracle for the differential-testing fixtures
  verify.sh                   every off-hardware check in one command
  audit-release.sh            mechanical release checks (no simulated card, no networking, no persistence)
  hash-app.sh                 unsigned reproducible-build hashing + toolchain record
  generate-bip39-wordlist.sh  regenerate the pinned wordlist (asserts its SHA-256)
docs/
  provisioning-checklist.md   the operator procedure, including Appendix B
                              (and the read-only re-pair route, design.md §4.2 step 7c)
  signing-checklist.md        the signing procedure: what to compare on screen (including the
                              chain name and the coin), and what to do when a signature does
                              not come through
  m0-hardware-verification.md the checks only real hardware can settle
  reproducible-build.md       what "reproducible" means here, and what it does not
  v1-threat-notes.md          v0.1 scope, deviations, and residual risk
```

## Build and test

```sh
# all off-hardware checks (packages, oracle, fixtures, app build, release audit)
tools/verify.sh

# individual pieces
cd ios/Packages/VaultKit  && swift test      # 247 tests: crypto, BIP39/BIP32 incl. ckd_pub, addresses, BC-UR, pairing manifest,
                                             #            ceremony, read-only re-pair, RLP, transactions, signatures,
                                             #            chain naming and asset labelling, scanner lifecycle,
                                             #            interoperability with the reference implementation
cd ios/Packages/YubikeyKit && swift test     # 78 tests: APDU codec, both OpenPGP slots, private-use data objects, PSO:CDS,
                                             #            transports, NFC session policy, end-to-end signing
cd ios && xcodebuild test -scheme PlexVault -destination 'platform=iOS Simulator,name=iPhone 17'  # 9 UI tests (~4 min each for the two that walk a whole flow)
cd tools/derive && python3 -m venv .venv && .venv/bin/pip install pycryptodome
cd tools/derive && .venv/bin/python derive.py selftest

# app
cd ios && xcodegen generate                  # only needed after editing project.yml
open PlexVault.xcodeproj
```

The app requires Xcode 26.6 / iOS 26 SDK, a physical iPhone (CoreNFC has no
simulator), and either a YubiKey 5 NFC (contactless) or a YubiKey 5C NFC
(iPhone 15+ for the wired path). A DEBUG-only simulated card lets the whole
ceremony be exercised with no hardware present.

## Where the confidence comes from

1. **Published test vectors.** BIP32 vectors 1–5 (including the invalid-key
   rejection vector), the official BIP39 Trezor vectors, the SLIP-0010 Ed25519
   vectors, RFC 8032 §7.1 Ed25519 vectors, EIP-55, BIP-173 bech32, SHA-2/HMAC RFC
   vectors, and the BCR-2020-007 `hdkey` CBOR+UR golden strings.
2. **Differential testing.** A second implementation in a different language with
   its own crypto (`tools/derive`) must agree on every derived value — EVM
   address, Bitcoin address and Ed25519 public key — and a committed fixture
   asserts it stays current.
3. **Differential hash fixtures.** 1,224 digests over 306 input lengths chosen to
   straddle every block boundary — this is what caught a Keccak padding bug.
4. **A release audit that is itself tested.** `tools/audit-release.sh` fails on a
   DEBUG bundle, because an audit that cannot fail is not an audit.
5. **Published vectors for the parts that decide what gets signed.** The RLP decoder is
   checked against the ethereum/tests suite — all 28 valid vectors and all 26 invalid ones,
   committed verbatim with their hashes — because "the bytes displayed are the bytes signed"
   depends on refusing every non-canonical encoding. The transaction decoder is checked
   against EIP-155's own example and against typed payloads whose digests come from an
   independent RLP encoder plus pycryptodome's Keccak. Signature handling is checked against
   EIP-155's published signature, whose sender an independently written pure-Python
   `ecrecover` confirms. The chain table is checked from both ends: Polygon's transaction
   signs end to end with a genuine fixture signature, and a chain id nobody has heard of
   signs too — so turning the table into a whitelist fails a test rather than quietly
   refusing a network. The Ethereum QR protocol has a fixture generated from
   `@keystonehq/bc-ur-registry-eth` — MetaMask's own library — and the app is checked against it
   in both directions, because every earlier fixture was the app's own output and a shared
   misunderstanding between a decoder and its matching encoder is invisible to that.
6. **A mock card that cannot cheat.** `MockSignerCard` signs with signatures generated by
   `tools/derive`, so the signing ceremony's verification, low-s normalisation and recovery
   value are exercised against real cryptography — and the DEBUG simulated card returns a
   real signature for the deterministic test key, which is why the UI test can drive the
   whole flow in a simulator and still fail if the verification is wrong.
7. **One door into the ceremony.** The camera and the DEBUG sample both enter through the
   scanner's own decoder, because for a while they did not: the sample called the ceremony
   directly, the camera's handoff was wired to nothing, and the UI test walked the whole flow
   green while a real scan stopped dead after "Read a eth-sign-request" (amendment 24).
8. **UI automation for the screens a user can get stuck on.**
   `ios/PlexVaultUITests` drives the real app in a simulator and found a genuine
   defect: an `.inline` picker rendering as a wheel, so tapping "Generate a new
   wallet" did nothing.

## Known gaps

* Not hardware-verified yet: the exact `PUT DATA 0x4D` key-import template, the
  `0xC4` length-field semantics, CryptoTokenKit slot enumeration on a directly
  attached key, and whether a free personal team can carry the NFC entitlement.
  All four are specified with resolution procedures in
  [`docs/m0-hardware-verification.md`](docs/m0-hardware-verification.md).
* No signing (v0.2), no Bitcoin PSBT (v0.3), no desktop client (v0.3).
* Dice entropy is non-authoritative in v0.1, but the 256-bit entropy is now the
  XOR of the YubiKey's hardware RNG (`GET CHALLENGE`) and the iOS CSPRNG, so a
  single backdoored RNG cannot determine the key — recorded as Low in §9.5 of the
  design and in [`docs/v1-threat-notes.md`](docs/v1-threat-notes.md).
* The Ed25519 key sits in the authentication slot, which has no hardware
  signature counter, so the counter audit covers secp256k1 chains only. PIN and
  touch still gate every Ed25519 signature; the trade is recorded in §4.3, §9.5
  and [`docs/v1-threat-notes.md`](docs/v1-threat-notes.md).
