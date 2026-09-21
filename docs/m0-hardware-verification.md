# Hardware verification (milestone M0)

Four things cannot be settled by reading specifications, and each one is written
into the code as an explicit, documented assumption rather than a guess. This is
the procedure to settle them. Nothing in v0.1 depends on getting these right for
its *security* argument, because a wrong assumption fails visibly — that is by
design; see "why each one is safe to be wrong" below.

## 1. The `PUT DATA 0x4D` key-import template layout

**Assumption in code, now resolved.** `KeyImportTemplate.extendedHeaderList`
previously produced:

```
PUT DATA   P1P2 = 3F FF, INS = 0xDB
data = 4D | B6 | 7F48 | 5F48 | 00 20 | <32-byte secret>
```

i.e. the control reference template (`B6`) wrapped the private-key template
(`7F48`), which wrapped the private key (`5F48`), whose single EC component
carried a 2-byte length prefix.

**Observed on hardware.** A YubiKey 5C Nano, firmware 5.4.3, OpenPGP applet 3.4
rejected that form with `6A80` (`keyImportRejected`). The accepted layout, matching
yubikit's `EcKeyTemplate` / `PrivateKeyTemplate.__bytes__` (OpenPGP card spec
4.4.3.9), is:

```
PUT DATA   P1P2 = 3F FF, INS = 0xDB
data = 4D | <CRT 00> | 7F48 | 92 20 | 5F48 | <32-byte secret>
```

* the CRT is an **empty-value** TLV (`B6 00` / `A4 00`), a sibling of the key
  objects rather than their wrapper;
* `7F48` carries the **tag and length** of the single EC private-key component
  (`92 20`);
* `5F48` carries the raw 32-byte value (secp256k1 scalar or Ed25519 seed), with
  no length prefix.

Full bytes for a 32-byte secret: `4D 2A B6 00 7F 48 02 92 20 5F 48 20 <secret>`.

**Change.** `KeyImportTemplate.extendedHeaderList` now emits the corrected form;
`testKeyImportAPDUHeaderAndTemplateStructure` and
`testAuthenticationSlotImportTemplateUsesCRT_A4` pin those bytes, and the mock's
`extractImport` parses the new structure.

**Two further findings, both resolved against the same card.**

1. *Algorithm attributes must be written before the key.* The card needs to know
   the curve to interpret the 32-byte key material. Importing first into a slot
   that still carries its default RSA attributes (`01 08 00 00 11 00`) is rejected
   with `6A80`. `OpenPGPCard.importKey` now writes `0xC1`/`0xC3` first, then the
   key (matching yubikit's `put_key`).
2. *The secp256k1 OID was wrong.* The code carried `13 2B 81 04 00 22 00`
   (`1.3.132.0.34` = secp384r1, plus a trailing format byte). The accepted value
   is `13 2B 81 04 00 0A` (6 bytes, `1.3.132.0.10` = secp256k1, no trailing
   byte), confirmed `9000` on hardware.

**Why it was safe to be wrong.** A wrong template is rejected outright (`6A80`) or
fails the read-back comparison — it cannot silently provision a different key. The
read-back step (§4.2 step 7) remains the final proof on the device.

## 2. `0xC4` PW-status bytes: write is a single byte, not seven

**Assumption in code, now resolved.** `PWStatusBytes.encode` produced seven bytes
(`PW1 status | 2-byte max PW1 | 2-byte max PW2 | 2-byte max PW3`) with all maxima
set to 127.

**Observed on hardware.** A YubiKey 5C Nano, firmware 5.4.3, OpenPGP applet 3.4:

* `PUT DATA 0xC4` with the seven-byte value is rejected with `6A80` (wrong data).
* On read, `GET DATA 0x006E` returns `C4 07 01 7F 7F 7F 03 00 03` — seven bytes, but
  laid out as `PW1 status | max PW1 | max PW2 | max PW3 | attempts PW1 | attempts PW2 | attempts PW3`
  (one byte each), not two-byte maxima.
* The write the card accepts is a **single byte**: the PW1 status (`0x00` = PIN
  required per signature, `0x01` = once per session). This matches yubikit's
  `set_signature_pin_policy`, which sends `struct.pack(">B", policy)`. Max lengths
  and retry counters are managed by the card (`CHANGE REFERENCE DATA` / `SET PIN
  RETRIES`), not by `PUT DATA 0xC4`.

**Change.** `PWStatusBytes.encode()` now returns the single PW1-status byte, and
the simulated card's stored `0xC4` value is one byte. The read-back check is
unchanged: the app still warns if `0xC4[0]` is not `0x00`.

**Why it was safe to be wrong.** The write is rejected outright (`6A80`), and the
only security-relevant bit — `PW1 status = 0x00`, so the PIN is required for every
signature — is the first byte, which the app reads back and warns on.

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

**Assumption in code, now resolved on a YubiKey 5C Nano, firmware 5.4.3, OpenPGP
applet 3.4** (`YubikeyKit/OpenPGPDataObjects.swift`,
`KeyImportTemplate.eddsaEd25519AlgorithmAttributes` and
`KeySlotObjects.forSlot(.authentication)`):

- The applet supports Ed25519 (EdDSA), confirmed by `GET DATA 0x6E` version 3.4.
- Algorithm attributes for the authentication slot (`0xC3`) are
  `16 | 2B 06 01 04 01 DA 47 0F 01` (10 bytes, **no** trailing format byte) — EdDSA
  with the Ed25519 OID `1.3.6.1.4.1.11591.15.1`. `PUT DATA 0xC3` with this value
  returns `9000`.
- Key import uses the same Extended Header List shape as secp256k1 but with CRT
  `0xA4`, and the 32-byte secret is the Ed25519 **seed** (not the clamped
  scalar). `PUT DATA 3F FF` returns `9000`.
- `GENERATE ASYMMETRIC KEY PAIR` with CRT `0xA4` returns the raw 32-byte point in
  `7F49`/`86`, with **no** `0x40` prefix. Confirmed: `7F 49 22 86 20 <32 bytes>`.

The trailing-format-byte `00` and a wrong length on the attributes were what made
an early manual probe desync the CCID channel; the code never shipped them.

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

## 9. `GET CHALLENGE` (INS 0x84) entropy length

**Assumption in code** (`OpenPGPCard.randomBytes`). The OpenPGP applet answers
`GET CHALLENGE` (`00 84 00 00 Le`) with exactly `Le` bytes of hardware-RNG output,
and `Le = 32` (256 bits) is supported in a single call. This is the entropy source
for mnemonic generation (design.md §4.2 step 4).

**How to verify.** On a desktop with the key attached, after selecting the OpenPGP
applet, issue `00 84 00 00 20` and confirm the response carries 32 bytes:

```sh
cd ios/Packages/YubikeyKit && swift test --filter testGetChallengeReturnsHardwareRandomBytes
# plus a hardware trace: ykman --log-level DEBUG / a CCID shim to observe the 0x84 exchange
```

If the card returns fewer than 32 bytes (or caps the response length regardless of
`Le`), the fix is to call `GET CHALLENGE` repeatedly and concatenate until 32 bytes
have been collected — a change confined to `OpenPGPCard.randomBytes`.

**Why it is safe to be wrong.** A short response is a visible, hard failure (the
app throws `CardError.malformedResponse`) before any mnemonic is derived; it cannot
silently produce short entropy. The fallback is a mechanical loop.

## 10. Reading an empty slot's public key returns `6581`, not `6A88`

**Assumption in code, now resolved.** `OpenPGPCard.inventory()` probes each slot
for occupancy with `GENERATE ASYMMETRIC KEY PAIR` in read mode
(`00 47 81 00 02 B6 00 00` and `00 47 81 00 02 A4 00 00`) and previously treated
only `6A88` ("referenced data not found") as "slot empty".

**Observed on hardware.** A YubiKey 5C Nano, firmware 5.4.3, OpenPGP applet 3.4,
factory-fresh (fingerprints `C5`/`C6` all zero, counter 0, default RSA attributes):

| APDU | Result |
|---|---|
| `00 47 81 00 02 B6 00 00` (read signature slot) | `6581` |
| `00 47 81 00 02 A4 00 00` (read authentication slot) | `6581` |
| bare-tag form `00 47 81 00 01 B6` | `6A80` (wrong data) |

The card reports `6581` ("memory failure") for a slot that holds no key; the
`6A88` the code expected was not produced. Both slots were empty, so `6581` is the
empty-slot answer on 5.4.x, not a memory fault — the same read against a slot that
*does* hold an EC key still returns `7F49`/`86`.

**Change.** `inventory()` now treats `6581` and `6A88` identically as "no key in
this slot". Any other unexpected status word is recorded as a `probeFailures`
warning rather than aborting the inventory, so the version and serial are still
reported. Pinned by `testInventoryTreatsRead6581AsEmptySlot`.

**Why it was safe to be wrong.** The failure was a hard crash at the inventory
screen, never a silently wrong key; the read-back comparison (§4.2 step 7) is
unaffected and still voids the ceremony on any mismatch. The fix only changes how
an empty slot is recognised before any key exists.

