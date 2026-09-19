# A Minimum-Trust Air-Gapped Cryptocurrency Wallet Based on YubiKey and iPhone

---

## 1. Abstract

This scheme combines three individually limited but complementary devices into an air-gapped signing system:

- A **YubiKey 5 series** device (OpenPGP applet) holds the secp256k1 private key. The key is non-exportable, every signature requires a PIN and a physical touch, and the device maintains a hardware signature counter;
- An **offline iPhone** runs the signing app, providing a screen, and NFC/USB-C connectivity. It acts as the YubiKey's "display and input terminal" and holds no secrets itself;
- An **online Desktop wallet** constructs transactions, broadcasts them, and independently verifies the signatures returned by the iPhone.

Compared with conventional hardware wallets, this scheme splits the "secure element" and the "trusted display" across two independent devices and adds cross-checking via cryptographic verification of signatures on the Desktop: **even if the iPhone app is tampered with, it cannot cause the Desktop to broadcast a transaction that differs from the one the Desktop itself constructed.** Private-key backup uses a BIP39 mnemonic; the YubiKey itself is merely a replaceable signer.

---

## 2. Background and Motivation

Existing cold-signing approaches each have shortcomings at one end or the other:

- **Dedicated hardware wallets** (Ledger, Trezor, Coldcard, Keystone): the secure element and trusted display are integrated into one device, but users must trust the vendor's firmware, supply chain, and screen; the screens are small and complex transactions are hard for humans to read.
- **General-purpose phones as cold wallets** (AirGap Vault, an old phone plus an open-source app): good screen and camera, but the private key resides in a general-purpose OS's storage, with no physical touch confirmation and no hardware counter to resist brute force.
- **YubiKey / smart card plugged directly into a computer for signing**: the private key is secure, but there is no independent display; what the user signs is entirely determined by the online host.

The starting point of this scheme is: the YubiKey offers a mature, mass-produced, auditable secp256k1 signing element; the iPhone offers a high-quality, offline-capable trusted display and camera; all that stands between them is a protocol and an app.

---

## 3. Design Goals and Non-Goals

### 3.1 Goals

1. The private key never touches an online device during its entire lifecycle.
2. Every signature requires the user to physically confirm **on the device holding the private key** (PIN + touch).
3. Signing requests and signing results are transported only over a one-way, visible QR channel.
4. Compromise of any single device is insufficient to cause loss of funds.
5. Mnemonic backup is decoupled from the YubiKey hardware: loss, damage, or replacement of the YubiKey does not affect asset recovery.
6. Interoperability with mainstream Desktop wallets (EVM: MetaMask; Bitcoin: Sparrow), as well as support for a custom Desktop client.
7. Coverage of the practical chain landscape from **two** keys on one YubiKey, by assigning one key per *algorithm* rather than one key per chain: ECDSA secp256k1 and Ed25519.

### 3.2 Non-Goals

- No in-hardware BIP32 derivation (the OpenPGP applet does not support it); one key slot on one YubiKey corresponds to one fixed key, so a ceremony provisions one fixed key per algorithm rather than a derive-on-demand account tree.
- No Bitcoin Taproot (BIP340 Schnorr) support; the OpenPGP applet only provides ECDSA. Ed25519 is supported, but as a separate key in the authentication slot (see §4.3).
- No reliance on trust in the iPhone hardware (Secure Enclave) itself; in this scheme the iPhone is treated as a "potentially tampered display terminal."
- Duress scenarios are not addressed.
- No Lightning / MFi accessory transport: the 5Ci path is dropped, so transports are NFC and USB-C CCID only (see §7.2).
- No in-app signing in v1: the app performs the provisioning ceremony of §4.2 and stops there.
- No chain-specific address derivation for Ed25519 in v1: the key's identity is the public key itself (see §6.4).

---

## 4. System Architecture

### 4.1 Components and Trust Boundaries

```
┌────────────────────┐   QR (UR)   ┌────────────────────┐ NFC / USB-C CCID ┌──────────────┐
│  Desktop wallet    │ ──────────▶ │  Offline iPhone    │ ────────────────▶ │  YubiKey 5   │
│  (online)          │             │  Signing app       │   ISO 7816 APDU   │  OpenPGP     │
│  - build tx A      │ ◀────────── │  - parse/show A    │ ◀──────────────── │  - key sk    │
│  - verify (P,H(A),σ)│  QR (UR)   │  - compute H(A)    │                   │  - PIN, touch│
│  - broadcast       │             │  - relay σ         │                   │  - sig counter│
└────────────────────┘             └────────────────────┘                   └──────────────┘
        ▲                                                                          │
        └──── periodic direct connection: read sig counter (no PIN), compare expected_counter ──┘
```

| Component | Secrets held | What it can do alone if compromised | What it cannot do |
|---|---|---|---|
| Desktop | None (public key / address only) | Construct a malicious transaction and send it to the iPhone for display | Bypass the user's human-readable confirmation on the iPhone; bypass the YubiKey touch |
| iPhone app | None (briefly holds the mnemonic during generation) | Display A but sign B (see §9; caught by Desktop verification); socially engineer the user into one extra touch | Export the private key; produce a signature without a touch |
| YubiKey | Private key `sk` | — | Display anything; judge what is being signed |

The trust relationship among the three is: **the user trusts what they read on the iPhone screen; the Desktop uses cryptographic verification to confirm the iPhone did not swap the content; the YubiKey uses physical touch to ensure no extra signatures occur.**

### 4.2 Provisioning (Initialization)

Prerequisites: a **brand-new or factory-reset** iPhone, no SIM, airplane mode; a YubiKey 5 (firmware ≥ 5.2.3, supporting secp256k1).

1. **Install the app.** Two options: (a) install from the App Store, then immediately disconnect and remain permanently offline; (b) sideload from audited source code via Xcode (reproducible build, hash verified). Option (b) is the recommended path.

   The reference build uses a **free personal team**. A free-team provisioning profile expires after 7 days, so the app must be re-signed and re-installed from Xcode weekly to keep launching — which means tethering the "offline" iPhone to a computer once a week (see §10). A paid developer account gives 1-year profiles. Re-installing over the same bundle identifier preserves the app's data container, and since the app persists no secrets at all, an accidental deletion costs only a re-pairing, not funds.
2. **Reset the YubiKey OpenPGP applet** (`ykman openpgp reset`; may be done on the Desktop, since the YubiKey holds no secrets yet).
3. **Configure YubiKey policies** (done on the iPhone via the app, or in advance on the Desktop):
   - Touch policy `UIF = 0x02` (Fixed: touch permanently required, cannot be disabled later) on **both** signing-capable slots — `0xD6` (signature) and `0xD8` (authentication);
   - `PW1 status (0xC4[0]) = 0x00`: PIN must be re-verified for every signature;
   - Set a User PIN (≥ 6 digits) and an Admin PIN (≥ 8 digits), different from each other.
4. **Generate entropy.** The app reads 256 bits from the YubiKey's hardware random-number generator (`GET CHALLENGE`, INS `0x84`) and 256 bits from the iOS system CSPRNG (`SecRandomCopyBytes`), then XORs the two into the **sole authoritative** entropy. Because either source being unpredictable keeps the XOR unpredictable, neither a backdoored card RNG nor a backdoored OS RNG alone can determine the mnemonic. Dice are optional and **non-authoritative**: if the user rolls, the app records and displays the rolls as a ceremony witness, but they do not feed the mnemonic, so a dice sequence cannot be used to reproduce it afterwards (see the amendment in §9.5). The app displays the first 8 hex digits of the SHA-256 of the entropy — the *entropy commitment* — as a ceremony witness for the record.
5. **Generate the mnemonic** (BIP39, 24 words), display it on screen, and have the user transcribe it onto a steel plate. The app requires the user to back-fill 3 randomly chosen words to confirm correct transcription. This one mnemonic is the backup of **both** keys below.
6. **Derive and import both keys.** From the BIP39 seed the app derives two keys at fixed paths and imports each into its slot via `PUT DATA 0x4D` (Extended Header List):
   - **secp256k1** at `m/44'/0'/0'/0/0` (BIP32) into the **signature** slot (CRT `0xB6`), with algorithm attributes `0xC1 = ECDSA secp256k1 (1.3.132.0.10)`, fingerprint `0xC7`, creation time;
   - **Ed25519** at `m/44'/501'/0'/0'` (SLIP-0010, all hardened) into the **authentication** slot (CRT `0xA4`), with algorithm attributes `0xC3 = EdDSA Ed25519 (1.3.6.1.4.1.11591.15.1)`, fingerprint `0xC9`, creation time.
   The paths are **not** chain-specific: the secp256k1 key serves every secp256k1 chain and the Ed25519 key serves every Ed25519 chain (see §4.3). After import, the app immediately wipes the mnemonic and both private keys from memory.
7. **Verify read-back (mandatory).** The app reads each public key back out of the YubiKey (`GENERATE ASYMMETRIC KEY PAIR`, `P1=0x81` with CRT `0xB6` and `0xA4` → `7F49` → `86`) and compares it byte-for-byte against the key it derived and imported. **If either differs, the entire procedure is void; restart from step 2.**
8. **Export the public keys.** The app encodes **each** public key as its own UR (`crypto-hdkey`/`hdkey`, see §6.4) and displays two QR codes; the Desktop scans both and imports them as hardware-signer accounts. The Desktop records each public key `P`, the associated address(es), and `expected_counter = 0`.
9. **Initial signature-counter baseline.** Read `0x93` from `GET DATA 0x7A` and confirm it is 0. This is an on-device action over NFC or USB-C: it requires no PIN and exposes no secrets, and no Desktop tether is required. This counter belongs to the **signature** slot; the Ed25519 key in the authentication slot has no counter (see §4.3 and §9.5), and the app records that on the provisioning report.
10. **Small-value test transaction.** The Desktop constructs a small transfer and runs the full §5 flow. Only after signature verification passes and the transaction confirms on-chain may large amounts be transferred in.

### 4.3 Key Model

- One OpenPGP signing-capable slot holds exactly one key, and a ceremony provisions **two**: the **signature** slot holds an ECDSA secp256k1 key, and the **authentication** slot holds an Ed25519 key. Both come from the one mnemonic, at the fixed paths `m/44'/0'/0'/0/0` and `m/44'/501'/0'/0'`.
- The slot assignment is by **algorithm, not by chain**. Every secp256k1 chain shares the one key — the app derives and displays both its EVM address and its native-segwit Bitcoin address — and every Ed25519 chain shares the other. Two keys therefore cover the practical chain landscape, where one key per chain would not.
- Because the path is shared, the same key appears at the same path on every chain of that algorithm. That is deliberate: address reuse and cross-chain linkability are accepted in exchange for covering many chains with one card, and it is the reason the pairing export omits a chain code (§6.4).
- **Accepted consequence: only the signature slot increments the hardware signature counter** (`GET DATA 0x7A` → `0x93`). The Ed25519 key sits in the authentication slot, and `INTERNAL AUTHENTICATE` is not counted, so the counter audit of §5.2 rules 3–4 covers secp256k1 chains only. PIN and touch authorization still gate both keys. This residual risk is recorded in §9.5 and in `docs/v1-threat-notes.md`; it is a deliberate trade of one control for broad chain coverage, not an oversight.
- The encryption slot (DEC) is not used.
- Multiple accounts beyond this are achieved with additional YubiKeys. Re-importing a key into a slot resets the counter and invalidates the old public key; re-pairing is required.
- The mnemonic is the sole backup of **both** keys. Recovery = repeat §4.2 steps 6–9 on a new YubiKey; recovered public keys identical to the originals prove successful recovery.

---

## 5. Signing Flow

### 5.1 Sequence

Using an EVM transaction as the example (PSBT differences are described in §6.3).

```
 Desktop                          iPhone app                        YubiKey
 ───────                          ──────────                        ───────
 1. User builds transaction A in the wallet
 2. Serialize A (unsigned RLP)
 3. Wrap as UR eth-sign-request
    (with requestId, chainId,
     derivationPath, address)
 4. Render as (animated) QR ─────▶ 5. Scan, CRC check, reassemble
                                  6. Parse A: type, chainId, to,
                                     value, gas, nonce, data
                                  7. If data non-empty, try to decode
                                     with built-in ABI library (ERC-20 etc.)
                                  8. Check that address in the request
                                     matches the locally paired address
                                  9. Full-screen human-readable summary of A;
                                     raw hex expandable
                                 10. User confirms → compute H(A)=keccak256
                                 11. Prompt "Bring YubiKey near / plug in,
                                     enter PIN"
                                 12. SELECT OpenPGP AID ─────────▶
                                 13. VERIFY PW1 (P2=0x81) ───────▶ Check PIN (locks after 3 failures)
                                 14. PSO:CDS (H(A)) ─────────────▶ LED blinks, awaits touch
                                                                   User touches ──▶ compute σ=Sign(sk,H(A))
                                                                   counter +1
                                 15. ◀──────────────────── (r,s)
                                 16. Normalize low-s; try v∈{0,1}
                                     such that ecrecover(H(A), σ) = address
                                 17. Wrap as UR eth-signature
                                     (requestId, r‖s‖v), show QR
 18. Scan ◀──────────────────────
 18.5 **Independent verification**:
      Verify(P, H(A), σ) and
      ecrecover(H(A), σ) == account address
      Any failure → do not broadcast, raise alarm (see below)
 19. expected_counter += 1
 20. Assemble signed transaction, broadcast
```

**Step 18.5 is a mandatory step of this scheme, not an optional optimization.** On failure, the Desktop must:

- Refuse to broadcast and discard this signature;
- Display "The signature returned by the signer does not match the request; the signing device may have been tampered with";
- Guide the user to immediately insert the YubiKey into the Desktop and read the signature counter, comparing it against `expected_counter`;
- Advise the user to stop using that iPhone until safety is confirmed, and to consider migrating assets.

### 5.2 Rules

1. **One transaction = one `PSO:CDS`.** At the specification level, the app is forbidden from retrying a signature for the same request. If the YubiKey returns any error (wrong PIN, touch timeout, NFC disconnect), the entire flow terminates and restarts from the Desktop (which generates a new `requestId`).
2. **Hard rule for users: any single transaction permits exactly one touch.** If the app says "Signing failed, please touch again," the user should treat the app as compromised and stop. This rule must be repeated on the app's first launch, on the Desktop wallet's pairing page, and in the printed quick-start guide.
3. **The counter is read by a party other than the one that displayed the transaction.** The Desktop, or the iPhone itself over NFC/USB-C, reads `0x93` via `GET DATA 0x7A` (no PIN required). What matters is that the comparison against `expected_counter` is made by something other than the signing screen; a count displayed by the signing app alone is not evidence.
4. **Counter audit frequency**: at least once at the end of every signing session; for large holdings, once per transaction is recommended. `actual_counter > expected_counter` means the YubiKey produced a signature the Desktop does not know about; migrate assets immediately.
5. **The iPhone app only displays parsed content and never performs "smart" rewriting.** Undecodable `data` must be shown as raw hex and explicitly labeled "Unable to parse — proceed with caution."
6. **Address binding.** The app refuses to sign any request whose `address` field does not match the locally paired address, preventing the Desktop from mistakenly sending another account's transaction.
7. **chainId allowlist.** The app maintains a user-configured list of permitted chains; a chainId not on the list requires a second confirmation.
8. **NFC session timeout** (about 60 seconds on iOS): if the touch is not completed within the session, it is treated as failure with no automatic retry.

---

## 6. Cryptography and Protocol Details

### 6.1 Curve and Algorithm

- Curves: **secp256k1** (OID `1.3.132.0.10`) in the signature slot and **Ed25519** (EdDSA, OID `1.3.6.1.4.1.11591.15.1`) in the authentication slot, both supported in the OpenPGP applet on YubiKey 5 firmware ≥ 5.2.3. (The exact EdDSA object identifiers and import encoding are M0 hardware-verification items; see `docs/m0-hardware-verification.md`.)
- Signature **over secp256k1**: ECDSA. The OpenPGP applet's `PSO:CDS` **signs the supplied 32-byte digest directly** without further internal hashing, so keccak256 / double-SHA256 can be computed by the app and passed in.
- Signature **over Ed25519**: EdDSA is **not hash-then-sign**. OpenPGP delivers the *message* to the card, which applies SHA-512 internally, so the v0.2 signing protocol cannot reuse the "compute a 32-byte digest in the app and pass it in" shape for Ed25519 chains. This is a v0.2 design input, not a v1 behaviour: v1 never signs. It is recorded now because a reader would otherwise assume the ECDSA flow generalises.
- Nonce k: generated internally by the YubiKey. The scheme does not assume RFC 6979 deterministic k; Desktop verification relies only on the validity of `(r, s)`, not on k's predictability.
- **Low-s normalization**: the YubiKey may return `s > n/2`. In step 16, the app replaces `s` with `n − s` (and flips v accordingly). This does not affect validity, but both Ethereum (EIP-2) and Bitcoin (BIP62 / standardness rules) require low-s.

### 6.2 EVM Signing

- Supported transaction types: Legacy (EIP-155), EIP-2930, EIP-1559.
- `H(A)`: keccak256 of the RLP encoding of the unsigned transaction; for EIP-2718 typed transactions, the type byte is prepended to the RLP.
- Message signing (EIP-191 personal_sign, EIP-712 typed data) uses the same channel and the same UR type, distinguished by the `dataType` field. The app shows parsed domain and fields for EIP-712, and UTF-8 text plus hex for personal_sign.
- Desktop verification: `ecrecover(H(A), r, s, v) == account.address`.

### 6.3 Bitcoin PSBT Signing

- Input: the Desktop produces a PSBT (BIP174); each input to be signed must carry `witness_utxo` (segwit v0) or `non_witness_utxo` (legacy), plus `bip32_derivation` pointing to this YubiKey's public key.
- App checks: every input's scriptPubKey is consistent with the locally derived public key; display each output's address and amount, change markers, fee, and total spend.
- For each input, compute the sighash (BIP143 for P2WPKH / P2SH-P2WPKH; traditional sighash for legacy) and call `PSO:CDS` one at a time. **Multi-input transactions require multiple touches**; the app states up front "This transaction has N inputs and will require N touches," and the Desktop does `expected_counter += N`. This is the only exception to §5.2 rule 1, and N is fixed and displayed before signing begins.
- Output: PSBT with `partial_sig` (DER encoding + sighash type).
- Desktop verification: verify each `partial_sig` against the sighash with the corresponding public key; Sparrow does this at finalize, and a custom Desktop must do it explicitly.
- Not supported: P2TR (Schnorr), MuSig within multisig; supported as one ECDSA participant in a multisig (P2WSH).

### 6.4 Data Encoding (UR / QR)

Uses the Blockchain Commons UR (BC-UR) standard, compatible with the Keystone / AirGap ecosystem:

| Direction | UR type | Content |
|---|---|---|
| iPhone → Desktop (pairing) | `crypto-hdkey` (v1 also offers the current `hdkey` naming) | One UR **per key** (secp256k1 and Ed25519): public key, derivation path, source fingerprint |
| Desktop → iPhone (EVM) | `eth-sign-request` | requestId (UUID), signData, dataType, chainId, derivationPath, address |
| iPhone → Desktop (EVM) | `eth-signature` | requestId, signature (65 bytes) |
| Desktop → iPhone (BTC) | `crypto-psbt` | PSBT bytes |
| iPhone → Desktop (BTC) | `crypto-psbt` | PSBT with partial_sig |

- Data exceeding a single frame uses UR animated QR (fountain-code fragments); the iPhone side supports out-of-order reception.
- **The Desktop must alarm on unknown UR fields rather than silently dropping them** (to prevent the iPhone from exfiltrating data via extra fields; see §9). The custom Desktop enforces this strictly; third-party wallet behavior is listed in §7.1.
- **The pairing export omits the chain code by default.** One YubiKey slot holds exactly one key (§4.3), so advertising a chain code would invite a wallet to derive child addresses that this card *cannot sign for*. Exporting a chain code is possible but requires an explicit acknowledgement in the app and is recorded in the provisioning report. For the same reason v1 does not emit `crypto-account` / `account-descriptor`: an account-level descriptor describes derivable children.
- **Two keys, two codes.** A ceremony produces two single-part-friendly `crypto-hdkey` URs, one per algorithm, and the wallet scans each. BCR-2020-007 defines no explicit curve field, so the curve is discriminated by the length of `key-data` (33 bytes = compressed secp256k1 point, 32 bytes = raw Ed25519 point), reinforced by `use-info` (SLIP-44 coin type 0 and 501). That convention is listed as an interoperability item in `docs/m0-hardware-verification.md`.
- **The Ed25519 identity is the public key.** With one key per algorithm and no chain-specific derivation in v1, there is no single Ed25519 address to display: the app shows the 32-byte public key and uses it for the read-back comparison.

### 6.5 YubiKey APDU Mapping

| Operation | APDU | Notes |
|---|---|---|
| Select applet | `00 A4 04 00 06 D2 76 00 01 24 01` | OpenPGP AID |
| Get challenge (entropy) | `00 84 00 00 20` | Hardware RNG; returns 32 random bytes, XORed with the iOS CSPRNG (§4.2 step 4) |
| Verify signing PIN | `00 20 00 81 Lc <PIN>` | PW1 mode 81 |
| Sign | `00 2A 9E 9A 20 <32-byte digest> 00` | PSO:COMPUTE DIGITAL SIGNATURE; returns r‖s (64 bytes) |
| Read public key | `00 47 81 00 01 B6 00` | GENERATE ASYMMETRIC KEY PAIR, P1=0x81 (read mode), signature slot |
| Read public key (auth slot) | `00 47 81 00 01 A4 00` | Same, addressed at the authentication slot |
| Read counter | `00 CA 00 7A 00` | Security Support Template, contains `93 03 <counter>` |
| Read application data | `00 CA 00 6E 00` | Includes fingerprints, algorithm attributes, PW status |
| Import private key | `00 DB 3F FF Lc 4D ...` | PUT DATA Extended Header List; requires Admin PIN |
| Set UIF | `00 DA 00 D6 02 02 20` | Signature slot touch policy Fixed |
| Set UIF (auth slot) | `00 DA 00 D8 02 02 20` | Authentication slot touch policy Fixed |
| Algorithm attributes (auth) | `00 DA 00 C3 Lc 16 … 00` | EdDSA Ed25519 attributes |
| Fingerprint (auth) | `00 DA 00 C9 14 …` | 20-byte fingerprint for the authentication slot |

On iOS, NFC uses CoreNFC `NFCISO7816Tag`, declaring `D27600012401` under `com.apple.developer.nfc.readersession.iso7816.select-identifiers` in Info.plist. The wired path is USB-C CCID through CryptoTokenKit (`TKSmartCard`), which presents the YubiKey as a smart-card slot. The APDUs are identical on both transports.

The CCID transport intentionally uses the low-level `TKSmartCard.transmit(_:)` rather than the high-level `send(ins:p1:p2:data:le:)`: the high-level call throws for any status word other than `0x9000`, which would discard the status-word semantics this scheme depends on (`63Cx` retries remaining, `6983` blocked, `6A88` no key present, `6Cxx` wrong Le).

---

## 7. Compatibility

### 7.1 Desktop Wallets

| Wallet | Integration | Explicitly verifies returned signature? | Alarms on extra UR fields? | Position of this scheme |
|---|---|---|---|---|
| Custom Desktop (reference implementation) | Native | **Yes (mandatory, §5.1 step 18.5)** | **Yes** | Recommended |
| MetaMask | "QR-based hardware wallet" (Keystone protocol) | Recovers `from` when assembling; mismatched transactions fail at broadcast/node side, but **cannot be considered reliable explicit verification** | No | Usable, but recommended to pair with the reference implementation for independent verification before broadcast |
| Sparrow | Camera → UR crypto-psbt | Verifies partial_sig at finalize; **effective** | Partial | Recommended |
| Other Keystone-UR wallets (Rabby, BlueWallet, etc.) | As above | Must be confirmed individually | Must be confirmed individually | Pending verification |

Specification requirement: **any Desktop client claiming compatibility with this scheme must implement §5.1 step 18.5.** Users of third-party wallets should treat §5.2 rule 2 (one touch per transaction) and rule 4 (counter audit) as compensating controls.

### 7.2 Hardware

- YubiKey: 5 NFC, 5C NFC (firmware ≥ 5.2.3). Two transports are supported: **NFC** (CoreNFC ISO 7816) and **USB-C CCID** (CryptoTokenKit). Touch behaviour over NFC must be verified per firmware version; the wired path is more reliable for touch confirmation.
- **Lightning / 5Ci is no longer supported.** The 5Ci required a vendor MFi accessory SDK that YubiKit 4.x dropped, which made it the project's only external SDK dependency and an availability risk. USB-C CCID replaces it using only Apple frameworks, so a YubiKey 5C NFC is the recommended wired key.
- iPhone: NFC requires any model supporting CoreNFC tag read/write (iPhone 7 and later). The **USB-C transport requires an iPhone 15 or later**, or a USB-C iPad. A dedicated device with the SIM removed and permanent airplane mode is recommended.
- Desktop: no longer required for provisioning. For the signing flow it still needs a USB port to read the counter (macOS / Linux / Windows via PC/SC).

---

## 8. Operations

### 8.1 Backup

- Engrave the 24-word mnemonic on steel plates, at least two copies, stored in separate locations.
- The YubiKey is **not** a backup. It can be re-created from the mnemonic at any time.
- Record the derivation path and the public-key fingerprint from provisioning (public information) to aid verification after recovery.

### 8.2 Recovery

Perform §4.2 steps 2–9 on a new YubiKey; compare the new public key against the recorded fingerprint. If the old YubiKey is still on hand, run `openpgp reset` and then destroy or reuse it.

### 8.3 Audit

- After every signing session: the Desktop reads the counter and compares against `expected_counter`.
- Quarterly: check that the steel-plate mnemonic is legible; perform one recovery drill (recover onto a spare YubiKey, compare public keys, then reset).
- App updates: update only after confirming the new version's reproducible-build hash; the update requires the iPhone to touch a computer and is treated as a "generation-phase-level" trust event (see §9). After updating, perform a small-value signature and verify it.

### 8.4 Decommissioning / Migration

- Retiring a YubiKey: `openpgp reset` (three Admin PIN failures also trigger lockout, after which terminate + activate resets the applet).
- Suspected compromise: migrate assets first, then investigate devices.

---

## 9. Threat Model

### 9.1 Assets and Security Properties

The system protects three assets:

| Asset | Held by | Consequence of compromise |
|---|---|---|
| Private key `sk` | YubiKey secure element (non-exportable); mnemonic as backup | Direct theft of all funds |
| Signature authorization | Distributed: YubiKey (PIN + touch) + iPhone (display) | Unauthorized transaction |
| Availability | Mnemonic plates; any BIP39-compatible tool | Locked funds |

The design targets three properties:

1. **Key confidentiality** — after provisioning, `sk` exists in plaintext only inside the YubiKey; the mnemonic is the sole backup and is handled exclusively in §4.2.
2. **Signing integrity** — the Desktop broadcasts only a transaction it constructed itself: any signature it accepts must verify against `(P, H(A))` for exactly the `A` it built.
3. **Signing authorization** — every signature is gated by a physical touch on the YubiKey and a human confirmation on the iPhone.

### 9.2 Adversary Model

| Capability | Assumption |
|---|---|
| Compromise the online Desktop | In scope — full control of its network, display, and stored data |
| Compromise the iPhone app | In scope — full control of app behavior, display, and computation |
| Extract `sk` from the YubiKey (physical / side-channel) | Out of scope — relies on Yubico's secure element |
| Observe the QR channel | In scope, low value — the channel carries only public data (unsigned tx, signature) |
| Steal the YubiKey and know the PIN | Mitigated, partially in scope — see §9.5 |
| Coerce the user (duress) | Out of scope |

The enabling constraint is that **the iPhone never holds the private key, and every signature it can induce consumes exactly one PIN entry and one physical touch, and increments a hardware counter.** The iPhone's power is therefore bounded: it can only produce signatures over *some* digest, each costing a user-visible, later-auditable gesture.

### 9.3 Core Argument: Why the Desktop Detects a Tampered iPhone

The Desktop holds the transaction bytes `A` it constructed and the paired public key `P`. On receiving `σ`, it computes `Verify(P, H(A), σ)` (equivalently `ecrecover(H(A), σ) == address`):

- **Honest iPhone**: relays the user's confirmed `A` to the YubiKey and returns `σ = Sign(sk, H(A))`; verification passes.
- **Tampered iPhone** that displays `A` but requests `B ≠ A` from the YubiKey obtains only `σ_B = Sign(sk, H(B))`. ECDSA verification binds `(r, s)` to the specific digest, so `σ_B` verifies against `H(B)` — not `H(A)` — and the Desktop's check fails; it refuses to broadcast.

The iPhone cannot forge a signature over `A` without `sk`, and cannot request a second signature without a second PIN entry and touch. A malicious app therefore cannot simultaneously satisfy Desktop verification and sign a different transaction.

**Consequence: compromising the iPhone app alone cannot steal funds.** To succeed, an attacker must additionally:

1. **Obtain one extra touch** — the first signs the honest `A` (satisfying the Desktop), the second signs the attacker's `B`. This is social engineering: the app must induce the user to touch once more than the transaction requires.
2. **Exfiltrate `B ‖ σ_B` off the offline iPhone** — via a second channel: an observing camera, a colluding Desktop, or physical contact during a future app update.

Condition 1 is necessarily discovered afterward: the extra touch increments the YubiKey's hardware signature counter, and the Desktop's direct read (`GET DATA 0x7A`) shows `actual_counter > expected_counter`. The overall bar is thus on the same order as "hardware-wallet firmware tampered ∧ host compromised."

### 9.4 Attack Tree

```
Asset theft
├── Private-key compromise
│   ├── Extract sk from YubiKey ── out of scope (secure element / side channel)
│   ├── Mnemonic leaked during generation (§4.2)
│   │   ├── App displays a mnemonic it did not actually write ── NOT mitigated in v0.1 (the independent cross-check was removed; see §9.5)
│   │   ├── Backdoored RNG ── both card and system RNG must fail: the entropy is
│   │   │   their XOR; dice do not feed the mnemonic (see §9.5)
│   │   ├── Steganography in exported pubkey QR ── fixed format + Desktop field alarm; no cameras at generation
│   │   └── Improper transcription / storage ── operational controls (§8.1)
│   └── iPhone not wiped after generation ── in-app memory wipe; dedicated offline device
├── Unauthorized signature
│   ├── Signing-phase app tampering (show A, sign B) ── Desktop independent verification (§5.1 18.5)
│   ├── Extra-touch social engineering ── one-touch-per-tx rule; counter audit (§5.2). **Covers secp256k1 chains only:** the Ed25519 key is in the authentication slot, which has no counter (§4.3, §9.5)
│   ├── PIN brute force ── 3-attempt lockout
│   └── Stolen YubiKey + known PIN ── no signature without touch; migrate on loss
├── User signs an unintended transaction
│   ├── Malicious Desktop builds a bad tx ── iPhone large-screen display; ABI decode; chainId allowlist
│   ├── Blind signing (unparseable data) ── explicit label + hex; reject large unparseable by default
│   └── Address substitution ── full-address display; out-of-band address verification
└── Loss of availability (funds locked)
    ├── YubiKey damaged / lost ── mnemonic recovery (§8.2)
    ├── Mnemonic lost ── two steel plates in separate locations (§8.1)
    └── App unavailable (delisting / iOS upgrade) ── mnemonic importable into any BIP39 wallet
```

### 9.5 Threat Table

Ratings are residual risk after the listed mitigations.

| Threat | Required capability | Primary mitigation | Residual risk |
|---|---|---|---|
| Malicious Desktop builds a transaction the user does not intend | Compromise of the online Desktop | iPhone full-screen human-readable display; ABI decoding; address + chainId binding | User misreads. **Medium** |
| Pairing-phase public-key / address substitution | Compromise of the Desktop during §4.2 step 8 | Character-by-character address comparison on both devices; small-value test transaction | **Low** |
| iPhone app tampered (signing phase) | Compromise of the iPhone app | Desktop independent verification (§5.1 18.5); one-touch-per-tx rule; Desktop counter audit | Needs an extra touch **and** a second exit channel, and is detectable afterward. **Low** |
| iPhone app tampered (generation phase) | Compromise of the iPhone app | Offline fresh device; reproducible-build verification; read-back confirms the card holds the key the app derived | Highest single point of app trust; the independent cross-check that bounded it was removed in v0.1. **Medium** |
| Backdoored or faulty entropy source | Compromise of the YubiKey secure element **and** the iPhone OS RNG | The 256-bit entropy is the XOR of the card's `GET CHALLENGE` and the iOS `SecRandomCopyBytes` (§4.2 step 4); either source alone cannot determine the mnemonic | **Low** — a single compromised RNG no longer yields the key; both independent RNGs must be backdoored, which requires compromising two vendors' stacks at once |
| Counterfeit YubiKey | Supply-chain substitution | Official channels; Yubico attestation; the read-back comparison fails if the card holds a different key | **Low** |
| Weak YubiKey internal RNG (nonce `k`) | — | `sk` is generated on the iPhone, not the YubiKey; no property of `k` is relied upon beyond secrecy | Leaked `k` ⇒ leaked `sk` (inherent ECDSA); depends on Yubico's secure element. **Low** |
| QR channel observed by a camera | Physical observation | Channel content is public (unsigned tx + signature) | **Low** |
| Extra touch on the **Ed25519** key goes unaudited | Compromise of the iPhone app plus one social-engineered touch | One-touch-per-transaction rule; PIN + touch still required; independent verification of what was signed (v0.2) | No hardware counter exists for the authentication slot, so the *detection* control that covers secp256k1 is absent here. **Medium**, accepted in exchange for chain coverage (see §4.3) |
| User under duress | Physical coercion | — (out of scope) | — |
| App delisting / iOS upgrade | — | Standard derivation paths; mnemonic recoverable in any BIP39/BIP44 wallet | **Low** |

---

## 10. Known Limitations

1. **Two fixed keys per YubiKey** — one per algorithm — with no in-hardware BIP32 derivation. Every chain of an algorithm shares the same key at the same path, so addresses are reused across chains and are linkable; multiple accounts require multiple YubiKeys or re-import.
2. **No Taproot / Schnorr support**, due to OpenPGP applet limitations. Ed25519 is supported as a second key, which is what makes the two-slot model cover the practical chain landscape.
2b. **The Ed25519 key has no hardware signature counter**, because it lives in the authentication slot (§4.3). The counter audit of §5.2 therefore covers secp256k1 chains only; this is an accepted limitation, not a defect that a future firmware fixes without moving the key.
3. **Multi-input PSBTs require multiple touches**, in tension with the "one touch per transaction" rule; mitigated by stating N up front, but this widens the social-engineering surface.
4. **NFC session time limit** (about 60 seconds). The USB-C CCID transport avoids this entirely and is preferred wherever an iPhone 15+ is available; over NFC, each step of a ceremony needs its own tap because the session cannot span the minutes a ceremony takes.
5. **App distribution conflicts with the offline requirement**: App Store installation requires connectivity; sideloading requires a computer. Both are one-time compromises to "permanently offline," classified as generation-phase-level trust events.
6. **The trusted display during the generation phase depends on the app itself; during the signing phase, the Desktop's independent verification provides a backstop.** Generation-phase trust rests on reproducible builds and the read-back comparison; the independent cross-check was removed in v0.1, so this trust cannot be eliminated entirely.
7. **Dependence on Yubico's closed-source firmware.** The OpenPGP applet's behavior can be black-box verified via APDUs, but the internal implementation is not auditable.
8. **Counter auditing requires the YubiKey to touch an online device.** Although reading the counter requires no PIN and exposes no secrets, this step runs counter to the intuition of a "cold" device and must be explicitly explained as safe in the documentation. During provisioning the read happens on the offline iPhone itself (§4.2 step 9).

9. **v1 is provisioning-only.** The app resets a card, generates or restores a mnemonic, derives both keys, imports them, verifies them by read-back and exports the public keys. It does **not** sign. The signing flow (§5), the `eth-sign-request`/`eth-signature` exchange, the counter-delta audit and therefore the small-value test transaction of §4.2 step 10 are v2 work. Everything in §5 should be read as design intent for v2, not as shipped behaviour.

10. **Dice entropy is non-authoritative in v1** (§4.2 step 4). A backdoored or faulty RNG is mitigated by construction — the entropy is the XOR of the card's hardware RNG and the iOS CSPRNG — so user dice are the one thing that is not fed into the mnemonic. Reproducible builds bound the residual risk further; the independent cross-check that previously provided an additional bound was removed in v0.1.

11. **One key per YubiKey limits desktop-wallet interoperability.** Wallets that expect an account-level extended public key *with a chain code* in order to enumerate accounts cannot be served without advertising child addresses this YubiKey cannot sign for. v1 therefore exports a single address-level key with no chain code by default (§6.4), and MetaMask's QR hardware flow — which keys off the Keystone UR family — may require manual confirmation rather than automatic account discovery. A custom Desktop client is the clean fix and is v2 work.

12. **Free-personal-team sideloading expires every 7 days** (§4.2 step 1), so the offline iPhone must be tethered to a computer weekly. The app stores no secrets, so this costs a re-pairing at worst, but it does periodically put the device in contact with an online machine and should be understood as part of the trust story.

---

## 11. Roadmap

- **v0.1 (implemented)**: iOS **provisioning app only** — §4.2 steps 2–9 over NFC and one wired transport (USB-C CCID), provisioning **both** algorithms (secp256k1 into the signature slot, Ed25519 into the authentication slot) from one mnemonic. Includes `tools/derive` as a differential-testing oracle (BIP32 + SLIP-0010 + Ed25519, cross-checked against the Swift implementation via committed fixtures), a scripted two-slot card for device-free testing, a mechanical release audit, and BIP39/BIP32/SLIP-0010/RFC 8032/BC-UR conformance tests against published vectors. No signing.
- **v0.2**: Signing flow (§5) — `PSO:CDS`, `eth-sign-request`/`eth-signature` URs, counter-delta auditing, and the small-value test transaction of §4.2 step 10.
- **v0.3**: Bitcoin PSBT signing (§6.3) and the custom Desktop client with the §5.1 step 18.5 verification and unknown-UR-field alarm.
- **v0.4**: Publish the reference implementation source (iOS app + Electron/Tauri Desktop); reproducible-build pipeline.
- **v0.5**: Third-party security audit (focus: §4.2 generation flow, §5.1 step 18.5, UR parser).
- **v0.6**: Multi-YubiKey Bitcoin P2WSH multisig workflow; Desktop-side multisig coordination.
- **Future exploration**: add Taproot when the YubiKey or other smart-card applets support BIP340 Schnorr; evaluate the PIV applet as an alternative.

---

## Appendix A: Glossary

| Term | Meaning |
|---|---|
| PSO:CDS | Perform Security Operation: Compute Digital Signature, the OpenPGP card signing command |
| UIF | User Interaction Flag, the YubiKey touch-policy DO |
| PW1 / PW3 | OpenPGP User PIN / Admin PIN |
| UR | Uniform Resources, Blockchain Commons' QR data encoding standard |
| PSBT | Partially Signed Bitcoin Transaction (BIP174) |
| expected_counter | The expected YubiKey signature count maintained by the Desktop |

## Appendix B: Provisioning Verification Checklist (Print Version)

- [ ] iPhone factory-reset, no SIM, airplane mode
- [ ] App hash matches the published reproducible-build hash (sideload method)
- [ ] YubiKey reset; UIF=Fixed; PW1 status=0x00; PINs set
- [ ] Entropy commitment (first 8 hex digits of SHA-256 of the entropy) shown by the app, recorded: `________`
- [ ] (Optional, non-authoritative) dice rolls ≥ 99 recorded as a ceremony witness: `________`
- [ ] Mnemonic transcribed twice; back-fill check passed
- [ ] Both public keys read back from the YubiKey and match the derived keys ✔
- [ ] Both pairing codes scanned; the Desktop shows the same values as the iPhone ✔
- [ ] Desktop reads YubiKey counter = 0 ✔
- [ ] Small-value test transaction: Desktop verification passed, confirmed on-chain ✔
- [ ] No other camera devices in the generation environment ✔
