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

## 5. Free-personal-team NFC entitlement

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
