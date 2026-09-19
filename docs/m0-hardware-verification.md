# Hardware verification (milestone M0)

Four things cannot be settled by reading specifications, and each one is written
into the code as an explicit, documented assumption rather than a guess. This is
the procedure to settle them. Nothing in v0.1 depends on getting these right for
its *security* argument, because a wrong assumption fails visibly — that is by
design; see "why each one is safe to be wrong" below.

## 1. The `PUT DATA 0x4D` key-import template layout

**Assumption in code** (`YubikeyKit/OpenPGPDataObjects.swift`,
`KeyImportTemplate.extendedHeaderList`):

```
PUT DATA   P1P2 = 3F FF, INS = 0xDB
data = 4D | B6 | 7F48 | 5F48 | 00 20 | <32-byte secp256k1 scalar>
```

i.e. the Extended Header List wraps the signature control reference template
(`B6`), which wraps the private key template (`7F48`), which wraps the private
key (`5F48`), whose single ECC component carries a 2-byte length prefix.

**How to verify.** On a desktop with the YubiKey attached, capture a known-good
import and diff it against ours:

```sh
# Option A: ykman prints APDUs at debug level
ykman --log-level DEBUG openpgp keys set-key ... 2>&1 | grep -A2 'DB 3F FF'

# Option B: GnuPG's keytocard, watched at the APDU layer
gpg --card-edit            # then: admin, key-attr, keytocard
# pair with an APDU logger (e.g. `pcscd` tracing, or a CCID shim)
```

Then compare with what we send:

```sh
cd ios/Packages/YubikeyKit && swift test --filter testKeyImportAPDUHeaderAndTemplateStructure
# prints/asserts: 4D 2A B6 28 7F 48 22 00 20 <scalar>
```

A quick end-to-end check that does not need a trace: `gpg --card-status` after
our import should show the key with our fingerprint, and `gpg --card-edit` →
`list` should show it as an ECC secp256k1 signing key.

**Why it is safe to be wrong.** The ceremony's next step reads the public key
back out of the card and compares it byte-for-byte with the locally derived key.
A wrong template either makes the card reject the import (`6A80`, surfaced as
`keyImportRejected`) or produces a key that does not match — in which case the
ceremony wipes everything and voids the procedure. It cannot silently provision a
different key.

**Fallback if in-app import proves unreliable.** Move the import to a desktop
`ykman` / `gpg` step over the same USB-C CCID path and have the app read the key
back and verify it. Every other behaviour in v0.1 is preserved; only the party
performing the write changes.

## 2. `0xC4` PW-status length fields

**Assumption in code** (`PWStatusBytes.encode`): seven bytes —
`PW1 status | max PW1 (2) | max PW2 (2) | max PW3 (2)` — with `PW1 status = 0x00`
and all maxima set to 127.

**How to verify.** After the policy step:

```sh
ykman openpgp info     # reports PIN policies: "PIN: verify each use" / retries / max length
gpg --card-status      # "PIN retry counter" and key attributes
```

Our app already reads the object back and records a warning if `0xC4[0]` is not
`0x00`; the report prints that warning, so a wrong write is visible without
hardware tooling. Confirm the maxima match what `ykman` reports and adjust
`PWStatusBytes.encode(maxLength:)` if the firmware uses a different maximum.

**Why it is safe to be wrong.** A rejected write surfaces as a status word; a
wrong maximum only affects the longest PIN the card will accept, and the PIN step
fails loudly if the PIN will not fit. The property that actually matters —
`PW1 status = 0x00`, so the PIN is required for every signature — is verified by
read-back.

## 3. `0xCE` as the creation-time object

**Assumption in code**: `OpenPGPDataObject.creationTimeSignature = 0x00CE`, taken
from design.md §4.2 step 6. The OpenPGP card 3.4 per-key timestamp object is
`0xCA`.

**How to verify.** Try both against the target firmware:

```sh
# after an import, check whether the timestamp landed
gpg --card-status | grep -i created
ykman openpgp info
```

If `0xCE` is rejected, the app already tolerates it: `importSignatureKey` catches
`unexpectedStatusWord` / `unsupportedFeature` for this object and continues,
because the timestamp is advisory metadata. The fix is to change the constant (or
write both), not to change any control flow.

**Why it is safe to be wrong.** The timestamp is descriptive. The fingerprint and
the public-key read-back are what the security argument uses, and both are
verified in-ceremony.

## 4. CryptoTokenKit enumeration of a directly attached CCID key

**Assumption in code** (`SmartCardTransport`): `TKSmartCardSlotManager` lists a
directly attached YubiKey 5C as a smart-card slot; `makeSmartCard()` and
`beginSession()` succeed with no additional entitlement; slot-state observation
is unavailable, so the transport polls `slotNames`.

**How to verify.**

1. Build to a physical iPhone 15 or later, plug in a YubiKey 5C NFC.
2. Launch the app, choose USB-C, and start the ceremony.
3. If discovery fails, the app prints the reason and
   `SmartCardTransport.describeAvailableSlots()` lists every slot with its state.
4. Cross-check the key's own configuration — CCID must be enabled:
   ```sh
   ykman config usb --list        # must include CCID
   ykman config usb --enable CCID # if it does not
   ```
5. Confirm whether an entitlement or a user-consent prompt appears. If one does,
   record it — it becomes part of the operator procedure. If `slotNames` never
   updates on plug-in, the existing polling loop is already the fallback and only
   the interval needs tuning.

**Why it is safe to be wrong.** This is a transport-discovery question, not a
cryptographic one. Failure to find the key is a visible error, and NFC remains a
fully functional alternative path.

## 5. Ed25519 support and the authentication-slot import template

**Assumption in code** (`YubikeyKit/OpenPGPDataObjects.swift`,
`KeyImportTemplate.eddsaEd25519AlgorithmAttributes` and
`KeySlotObjects.forSlot(.authentication)`):

- The applet supports Ed25519 (EdDSA) at all, and the applet version reported by
  `GET DATA 0x6E` distinguishes it.
- Algorithm attributes for the authentication slot (`0xC3`) are
  `16 | 2B 06 01 04 01 DA 47 0F 01 | 00`, i.e. EdDSA with the Ed25519 OID
  `1.3.6.1.4.1.11591.15.1` that GnuPG writes.
- Key import uses the same Extended Header List shape as secp256k1 but with CRT
  `0xA4`, and the 32-byte secret is the Ed25519 **seed** (not the clamped
  scalar).
- `GENERATE ASYMMETRIC KEY PAIR` with CRT `0xA4` returns the raw 32-byte point in
  `7F49`/`86`, with **no** `0x40` prefix.

**How to verify.** On a desktop with the key attached:

```sh
# 1. Does the applet accept Ed25519 at all? Does GnuPG agree on the OID?
gpg --card-edit            # admin, key-attr -> choose Ed25519 for the auth slot
gpg --card-status | grep -i curve

# 2. What does our import put on the wire, and what comes back?
cd ios/Packages/YubikeyKit && swift test --filter testAuthenticationSlotImportTemplateUsesCRT_A4
cd ios/Packages/YubikeyKit && swift test --filter testEd25519ImportIntoAuthenticationSlot

# 3. Read the public key back through our own APDU path and compare it with the
#    expected value from the independent oracle:
tools/derive/.venv/bin/python tools/derive/derive.py --algorithm ed25519 \
  --mnemonic "<the ceremony's 24 words>"
```

If the OID is wrong, the import fails visibly (`6A80` → `keyImportRejected`). If
the read-back encoding carries a `0x40` prefix, the read-back comparison fails
and the ceremony voids itself. If Ed25519 is unsupported entirely, the import is
rejected and the operator is told which algorithm failed.

**Fallback if the applet cannot hold Ed25519.** Provision secp256k1 only and use
a second YubiKey for Ed25519 — where, being that card's signature slot, the key
would also be counter-audited. Every other behaviour in v0.1 is preserved.

**Why it is safe to be wrong.** Every failure mode above is a visible rejection
or a read-back mismatch, never a silently different key: the same argument that
covers item 1 applies, and the read-back step compares *both* keys.

## 6. Ed25519 fingerprint object (0xC9)

**Assumption in code.** The 20-byte fingerprint written for the authentication
slot is the four-byte SLIP-0010 fingerprint (first four bytes of
`HASH160(0x00 || pubkey)`) zero-padded to 20, mirroring what is done for
secp256k1's `0xC7`.

**How to verify.** After an import: `gpg --card-status` and compare the reported
fingerprint against the value in the app's provisioning record.

**Why it is safe to be wrong.** The fingerprint is descriptive metadata here; the
security argument rests on the algorithm attributes and the public-key read-back,
both of which are verified in-ceremony.

## 7. Ed25519 in `crypto-hdkey`

**Assumption in code** (`VaultKit/UR/URTypes.swift`). A BCR-2020-007 `hdkey`
carries an Ed25519 key as 32 bytes of raw public key in `key-data`, with the
curve implied by that length plus `use-info` (SLIP-44 coin type 501). There is no
explicit curve field in the spec, so this is a convention.

**How to verify.** Scan the Ed25519 pairing code into the intended wallet and
confirm it imports a key matching the app's displayed public key.

**Why it is safe to be wrong.** A wallet that cannot interpret the code rejects
it; it cannot import a *different* key, because the key bytes are the payload and
the operator compares the resulting public key against the app's screen.

## 8. Free-personal-team NFC entitlement

**Assumption**: a free Apple personal team can sign an app carrying
`com.apple.developer.nfc.readersession.formats`. If it cannot:

1. The minimal test is a one-screen CoreNFC build; if it fails to install or the
   session never starts, the entitlement is the cause.
2. Escalation options, in order of preference:
   * a paid Apple Developer account (also removes the 7-day re-signing ritual and
     is the recommended fix);
   * the import fallback in item 1, which makes the app read-only against the
     card and removes the need for NFC entirely.

Record which path was taken in `docs/reproducible-build.md` alongside the hash
record, since it changes the trust story (see §10 of the design).
