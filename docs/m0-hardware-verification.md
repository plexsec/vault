# Hardware verification (milestone M0)

Some things cannot be settled by reading specifications, and each one is written
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

## 11. An interrupted NFC reset is recoverable, and back-to-back reader sessions survive

**Assumption in code** (`YubikeyKit/NFCSessionPolicy.swift`,
`YubikeyKitNFC/NFCTagTransport.swift`, `OpenPGPCard.select`). Three linked claims:

1. iOS refuses a reader session begun while the previous session's sheet is still
   being dismissed, reporting `NFCReaderError` 202; waiting
   `NFCSessionPolicy.cooldown` (2 s, matching Yubico's YubiKit) and retrying
   `begin()` absorbs it.
2. `ACTIVATE FILE` (`00 44 00 00`) reactivates an OpenPGP DF that `TERMINATE DF`
   left terminated, and `SELECT` answers `6985`/`6285` in that state.
3. A card terminated by an interrupted reset can therefore be provisioned by this
   app again, on the operator's next tap, with no GPG or `ykman` involved.

**How to verify.**

1. Build to a device. Use a YubiKey that **already holds a key**, which is the
   case that produced "The YubiKey could not be reached (Session invalidated
   unexpectedly)" at the reset step, and run the ceremony to the reset step.
2. Confirm the reset completes and the ceremony advances to the PIN step with no
   error banner. Probe the console (`[CoreNFC]`, `NFCError Code=202`) to see
   whether a 202 occurred at all: if it did, the retry must have absorbed it, and
   the ceremony must still have advanced.
3. Interrupt deliberately: from the reset confirmation, pull the key away so the
   session dies mid-reset. The app must return to *Inspect YubiKey* (the
   interruption rule, amendment 17), not sit on the reset screen.
4. Confirm the recovery of a terminated applet with an independent tool — on a
   desktop, `ykman openpgp info` will report the applet as inactive/unselectable
   while it is terminated. Re-tap in the app: the session must select (sending
   `ACTIVATE FILE` first) and the ceremony must continue. `ykman openpgp info`
   afterwards must report a factory-fresh applet.
5. Check the banner wording: every `NFCReaderError` code must produce a distinct,
   card-independent sentence. "Session invalidated unexpectedly" on its own is
   the string this item exists to remove.

**Why it is safe to be wrong.** The cooldown can only delay a session start, and
the retry budget is bounded (`maximumBeginAttempts`). The recovery path can only
send `ACTIVATE FILE` — a command every reset already sends — and it fires only
when `SELECT` answers `6985`/`6285`, status words that mean the applet is not
usable in that state anyway. Every one of these failures is visible rather than
silent: a wrong assumption here costs a re-tap, never a silently different key.

## 12. The private-use data objects hold a pairing manifest

**What M0 could not assume.** The four private-use data objects are *optional* in
the OpenPGP card spec and announced in Extended Capabilities, so that a
conforming applet may not implement them at all. Their access conditions also
differ per object, and the whole design depends on one of them being readable
with no PIN — a property that cannot be inferred from the spec table alone with
enough confidence to write 194 bytes of pairing material into an operator's card.

**Already verified, on a desk.** A YubiKey 5C NFC (firmware 5.8.0, OpenPGP 3.4,
serial 38531019) was driven directly with an independent tool (`scdaemon`, so the
check does not agree with our own code by construction). With **no PIN
presented**:

| APDU | answer | meaning |
|---|---|---|
| `GET DATA 0x0101` | `9000`, no data | implemented, readable without a PIN, empty |
| `GET DATA 0x0102` | `9000`, no data | implemented, readable without a PIN, empty |
| `GET DATA 0x0103` | `6982` | implemented, but a PIN is required to read it |
| `GET DATA 0x0104` | `6982` | implemented, but a PIN is required to read it |
| `GET DATA 0x00C0` | `6B00` | extended capabilities is not a standalone object on this applet |

So the objects exist, and `0x0102` is the one that is both readable with no PIN
and writable with PW3. That is the combination the feature stands on.

**And verified end to end.** With PW3 verified (`00 20 00 83 08 <PIN>`):

1. `PUT DATA 0x0102` with a **194-byte** manifest produced by this repository's
   own encoder answered `9000`; `GET DATA 0x0102` returned exactly those bytes,
   byte for byte. Re-measured at **198 bytes** after the layout gained a master
   fingerprint per entry (version 2, amendment 19): written, read back, identical.
2. A **254-byte** value was accepted; a **255-byte** value answered `6A80`. The
   applet enforces the spec's 254-byte limit, so `PairingManifest` must stay
   inside it (currently 198 bytes, asserted by a test).
3. The application data (`GET DATA 0x6E`) is **319 bytes and arrives chained**:
   the card answered `613F`, i.e. "63 more bytes available", and the full object
   only arrived after a `GET RESPONSE` (`00 C0 00 00 3F`). The shared
   `YubikeyTransport.exchange` loop handles this, which is worth knowing because
   the manifest read is of a similar size.
4. Parsed by this repository's own parser, that application data yielded applet
   3.4, serial `38531019` and PW status `00 7F 7F 7F 03 00 03`.
5. The binding check was run against the card's real keys: a manifest naming the
   card's own public keys was accepted, one with a single flipped bit in the
   secp256k1 key was refused (`.cardKeyMismatch`), and one written for a different
   serial was refused (`.cardSerialMismatch`).
6. The object was emptied afterwards with a zero-length `PUT DATA 0x0102`
   (`9000`, and a following read returns no data), so the card was left as found.

**Still to confirm on a card this app provisioned.** The chain codes in the
manifest above were synthetic: the test card was provisioned by something else, so
the *storage* and the *key binding* are verified, but not that a manifest written
by a full ceremony is accepted by a real wallet. That is what the small-value test
transaction of §4.2 step 10 covers, and it needs a card provisioned end to end by
this app — i.e. it is the same hardware gate the pairing export (items 1-8) is
already behind. Until then, treat "a wallet pairs from the stored manifest" as
unverified.

**Why it is safe to be wrong.** The write is 194 bytes into an object nothing else
uses, it happens after the keys are verified, and a failure is reported and
non-fatal: the ceremony still finishes, and the only consequence is that a later
re-pair needs the mnemonic. A `TERMINATE DF` clears the object, so a wrong
assumption cannot leave a card advertising keys it no longer holds.

**And the read side, on the same card.** The re-pair path (§4.2 step 7c) was
exercised against this card too, by reading the object with no PIN presented and
running this repository's own decoder over the bytes:

1. The card's reader session was dropped after the write (so no PW3 state
   survived in the daemon), and `GET DATA 0x0102` presented **no PIN of any kind**.
   It answered `9000` with the 198 bytes, byte for byte; in the same PIN-free
   session the control object `0x0103` answered `6982`. Those bytes — read off the
   card, not out of our encoder — were then handed to `PairingManifest.decode` and
   `verify(against:)`, which parsed them and accepted them against the card's real
   public keys and serial.
2. The same store with **one bit flipped** was written to the card, read back the
   same PIN-free way, and refused by the checksum before any field was trusted. A
   store naming a different serial is refused by `.cardSerialMismatch`, and one
   naming a different account key by `.cardKeyMismatch`.
3. Afterwards the object was emptied (zero-length `PUT DATA 0x0102` → `9000`, and a
   following read returns no data), so the card is as it was found.

**Still to confirm on a card this app provisioned.** As in item 12 above, and for
the same reason: the manifest was written by hand with synthetic chain codes
because the card was provisioned by something else. Storage, the binding check, the
refusal paths, and the read-back are measured; *whether a real wallet accepts a
code produced from a manifest this app wrote* is not, and needs a card provisioned
end to end by the app.

## 13. `PSO:CDS`: what the applet actually returns

Everything about signing that the app asserts but cannot prove off-hardware. The app
already treats both plausible answers correctly (it parses DER strictly and accepts a
bare 64-byte `r‖s` as well), so none of these can produce a wrong signature — but each
one decides whether a *real* card works at all.

- [ ] `VERIFY PW1` (`00 20 00 81 06 <PIN>`) then `PSO:CDS` (`00 2A 9E 9A 20 <digest> 00`)
      **in one session** → `9000` and a signature. Confirms that VERIFY state survives
      from the verify to the signature within a session, which the whole flow depends on.
- [ ] The same two commands in **two** sessions → expected `6982`. Confirms that the app's
      one-session design is necessary rather than merely cautious.
- [ ] The response body: DER `SEQUENCE { r, s }`, or a bare 64 bytes? Record the length
      and the first byte for a signature over a known digest.
- [ ] Is that `s` low (≤ n/2) or not? Sign the same digest several times and record whether
      the applet ever returns a high `s`; the app normalises, so this only decides whether
      the normalisation path is reached on hardware.
- [ ] An unanswered touch (pull the key away before touching): which status word? `6985`,
      `6400`, something else? The app maps `6985`/`6400`/`6600` to "the touch did not
      complete" and classifies it as *unknown* rather than as a refusal, because the card
      may have signed and moved its counter. Record whether the counter moved.
- [ ] Does a wrong PIN still decrement the PW1 retry counter when it is presented as part of
      `sign(digest:userPIN:)`, i.e. is the retry count in `63Cx` consistent with
      `VERIFY` alone?
- [ ] Order of checks: with no key in the signature slot *and* PW1 unverified, does the card
      answer `6982` (security status) or `6A88` (no key)? The simulated card answers `6982`
      first; record the hardware's order.
- [ ] Is `PSO:CDS` rejected with `6A80` (wrong data) if the digest is not exactly 32 bytes?
      The app never sends another length, so this is confirming the guard rather than
      relying on it.

## 14. A real wallet accepts a signature this app produced

The same shape as item 12, on the signing side, and the item that decides whether the
feature is usable at all.

- [ ] Provision a card with this app, pair it with MetaMask (QR), build a **small-value**
      transaction, scan it here, approve, sign, and scan the signature back. MetaMask must
      accept it and broadcast.
- [ ] Repeat for an **EIP-1559** transaction on mainnet: the recovery value is the y-parity
      (0 or 1) and the field is exactly 65 bytes.
- [ ] Repeat for an **EIP-1559** transaction on **Polygon (chain id 137)** — the ordinary
      POL case — and confirm the app's screens call the chain and the coin by name
      (`Polygon (chain id 137)`, `1.5 POL`) and that MetaMask's own screen agrees. Confirm
      the wallet accepts the signature and that the value moved is what both screens said.
- [ ] Repeat for a **legacy** transaction on a chain whose EIP-155 recovery value exceeds
      one byte. **Polygon 137 is the concrete case**: `137·2 + 35 + recid` is 309 or 310,
      the signature field grows to two bytes, and MetaMask reads everything from byte 64 as
      `v` (design.md §5.3). MetaMask sends EIP-1559 on Polygon by default, so this needs a
      wallet configured for legacy gas pricing (or a chain that has no 1559 support).
      This is the one deliberate deviation from the EIP's `bytes .size 65`, and only a real
      wallet can confirm it is tolerated — the unit tests only prove the bytes and the
      sender recovery are right, which is not the same as the wallet accepting them.
- [ ] Confirm MetaMask displays the same account address this app showed before signing.
- [ ] Confirm the counter moved by exactly one for one transaction (the app shows before and
      after; the wallet's own read is the independent one).
- [ ] A **wrong** PIN, then sign: the app must report the retry count the card gave, and the
      wallet must never receive a signature.

## 15. The camera comes back (lifecycle on a real device)

A simulator has no camera, so every path below needs the phone. The logic is unit-tested
(`QRScanSessionTests`); what a device adds is that `AVCaptureSession` really starts again,
which is the part no test can hold.

- [ ] Signing flow → *Read the YubiKey* → the camera opens. Tap **Cancel**, then *Read the
      YubiKey* again: the preview must come back. Repeat four or five times — this is the
      reported bug, and it was a state that outlived the camera rather than a one-off.
- [ ] While scanning (no code in view yet), send the app to the background and bring it back:
      the preview must restart on its own.
- [ ] Deny camera access, then re-enter the scanner: the reason must be shown again rather
      than a dark rectangle. Enable it in Settings, cancel out of the flow, come back: the
      camera must work.
- [ ] Interrupt mid-scan with an incoming call (or the Control Centre), then return: the
      preview must be live again, with no partial progress from before.
- [ ] Confirm that a request decoded in one visit is *not* still on screen after leaving the
      flow and coming back with a different (or no) request.

## 16. A scanned request reaches the ceremony (real camera)

The UI suite now covers the handoff itself, because the DEBUG sample enters through the
scanner's decoder (amendment 24). What a simulator cannot cover is the part that only exists on
a device: the metadata-output delegate firing, the hop to the main actor, and the callback.

- [ ] Read the YubiKey, build a real transaction in the wallet, and scan it: the screen must go
      from "Read a eth-sign-request" to the review screen on its own, with the recipient and
      value populated.
- [ ] Scan a request for a **sibling account** (select a different index in the wallet's account
      picker): the app must refuse it *and* leave the camera live so the next code can be
      scanned, with the reason still on screen.
- [ ] Point the camera at a QR code that is not `ur:` at all, then at a `ur:` code of the wrong
      type: the first must be ignored silently, the second must be refused with an explanation
      rather than half-fed to the ceremony.
- [ ] Scan a code while the app is on the scanner screen but *after* a previous refusal, to
      confirm the second code is read (the state machine's retry path).

## 17. A request from a real wallet reaches the signature

The request *format* is now covered off-hardware by a fixture from MetaMask's own library
(amendment 25), so what is left is the last hop: that the wallet accepts the signature this app
returns.

- [ ] Scan a real MetaMask `eth-sign-request` (Polygon, EIP-1559, small value): the review screen
      must show the recipient, the value in POL and the chain, and the digest must be the one the
      app signs.
- [ ] Scan the signature back: MetaMask must accept it (no "Signature request ID is missing", no
      recovery failure) and broadcast.
- [ ] Confirm the counter moved by exactly one, and that the wallet shows the same address the app
      displayed before signing.
- [ ] Repeat once with `personal_sign` from a dapp, to confirm the refusal reads as a *policy*
      refusal ("this app signs transactions only") rather than as a parse failure.

## 18. The touch policy survives provisioning — and how it was measured

**Resolved on hardware (YubiKey 5C NFC, firmware 5.8.0, applet 3.4).** Two behaviours of this
applet are now measured rather than assumed, and both had silently broken provisioning
(amendment 26).

* **Writing a slot's algorithm attributes discards that slot's touch policy.** Replaying the
  ceremony's own APDUs: `PUT DATA 0xD6 = 02 20` reads back `02 20`; the very next write of
  `0xC1 = ECDSA/secp256k1` makes it `00 20` — touch off — and the key upload, fingerprint and
  generation-time writes leave it there. Applying `02 20` *after* the import reads back `02 20`
  and survives every later write in the ceremony, including the manifest object and `0xC4`.
  Independently reported for `gpg keytocard` in yubikey-manager#693.
* **Ed25519 attributes: the OID matters.** `0xC3 = 16 || 2B 06 01 04 01 DA 47 0F 01` (GnuPG's
  OID) is refused with `6A80`; `0xC3 = 16 || 2B 65 70` (RFC 8410 `id-Ed25519`) is accepted and
  the key imports.
* **`YYYY` `0xC4` after a reset is `01`, not `00`.** A freshly terminated applet reads
  `01 7F 7F 7F 03 00 03`, so `0xC4[0] = 0x00` on a card is evidence that the policy step ran.
  That is what made the missing touch policy a contradiction rather than an unexplained state.
* **The UIF write is protected by PW3.** `PUT DATA 0xD6` without a verified Admin PIN answers
  `6982`.

- [ ] Run the app's own provisioning end to end against this card (not an APDU replay), then
      read the card back and confirm: `0xD6`/`0xD8` = `02 20`, `0xC4[0]` = `0x00`, both keys
      readable, manifest present, and both pairing codes reproduce the addresses the wallet
      shows.
- [ ] Confirm a signature attempt on the provisioned card actually waits for a touch, and that
      refusing to touch produces no signature and no counter increment.

### Probing trap: `gpg-connect-agent` caches the Admin PIN

`scdaemon` remembers a successful `VERIFY PW3` and silently re-sends it when a new card session
starts. A probe that sends `PUT DATA 0xD6` in a fresh session therefore appears to succeed
*without* any PIN, and looks like "these objects are not protected" — the opposite of the truth
(`6982` once `gpgconf --kill scdaemon` is run). Every conclusion in this document that depends
on an access condition was re-checked after killing the agent.

Note also that a long or repeated run of raw APDUs over CCID can wedge the reader:
`ERR 100663406 Card removed` from `scdaemon` while the card itself is fine. It recovers with
`gpgconf --kill scdaemon`; a Swift probe using the app's own transport (CryptoTokenKit) does not
show this at all, which is why item 18 asks for the app's path rather than more APDU replay.

## 19. `SET PIN RETRIES` on real hardware

**Resolved on hardware (YubiKey 5C NFC, firmware 5.8.0, applet 3.4).**

* The instruction exists and is protected: `00 F2 00 00 00` (no Admin PIN verified) answers
  `6982`, not `6D00`.
* A factory-fresh applet reports `C4 07 01 7F 7F 7F 03 00 03`: PW1 status `0x01` ("PIN once per
  session"), maximum lengths `7F`, and **3 / 0 / 3** remaining attempts, i.e. the resetting code
  this app never sets reports zero.
* Writing the PW1 status byte (`PUT DATA 0xC4` with one byte) is accepted; the seven-byte form is
  rejected (`6A80`, already recorded in item 2).

- [ ] After a provisioning run that chose a limit of, say, 5: read `C4` and confirm PW1 and PW3
      report 5, and that a wrong PIN decrements one and a correct PIN refills it to 5.
- [ ] Confirm the applet refuses 0 and 100 (`6A80`) — the app refuses them first, so this checks
      the applet's range rather than the app's.
- [ ] Confirm a run with a chosen limit survives to the end of the ceremony (the policy step
      re-reads the counters) and that the report records the number.

**Not implemented, deliberately.** Unblocking a blocked User PIN (`RESET RETRY COUNTER`, INS
`0x2C`, P1 `0x02` / P2 `0x83` with the Admin PIN) would make a low retry limit safe to choose and
is the honest answer to "I am afraid of typos". It is a signing-side feature — the operator has the
Admin PIN, the card is blocked, the PIN has to be replaced — and it is not in this version. Until
it is, the blocked-PIN message says what is actually true: the card has to be set up again from the
mnemonic.

## 20. The fixed sequence, run against the card (and what could not be run)

**Measured on the YubiKey 5C NFC in hand (firmware 5.8.0, applet 3.4)** by replaying the bytes the
app now sends, in the order the ceremony now uses. This is the evidence behind amendment 26 and
amendment 27; it is *not* the app's own run (see the bottom of this item).

* **A fresh applet reports `01 7F 7F 7F 03 00 03`** — PW1 status `0x01`, then 3/0/3 attempts for
  PW1 / resetting code / PW3. So `0xC4[0] = 0x00` on a card is evidence the policy step ran, and
  the "3 attempts" default is the card's, not ours.
* **`SET PIN RETRIES 5 5 5` works and reads back**: the write answers `9000` and `C4` then reads
  `00 7F 7F 7F 05 00 05`, i.e. PW1 and PW3 at 5 and the never-set resetting code at 0. The value
  survives later sessions, is visible in `0x6E`, and **survives the key import**.
* **Importing a key discards that slot's touch policy** — observed four separate times. Writing
  `D6 = 02 20` and then importing a secp256k1 key into that slot leaves `D6 = 00 20`; applying
  `02 20` after the import leaves `02 20` through the manifest write and every read that followed.
  This is the bug of amendment 26, reproduced on demand.
* **`TERMINATE DF` works while the Admin PIN is blocked.** The probe burned the admin attempts by
  accident (see the traps below), which put the card in exactly the state that clause is for:
  `C4 = 01 7F 7F 7F 03 00 00`, every VERIFY answering `63C0`/`6983`. `00 E6 00 00 00` +
  `00 44 00 00 00` **without any VERIFY** reset the applet and returned the PINs to their factory
  values. Spec 3.4.1 states the condition ("VERIFY of PW3 or Always if PW3 is blocked"), `ykman
  openpgp reset` takes no Admin PIN, and now this card has confirmed it.
* **The EC private-key template needs no public key.** yubikit's `EcKeyTemplate` optionally adds
  the public key as tag `0x99` next to the `0x92` scalar; this firmware accepts the
  private-key-only form our code sends (`4D .. B6 00 7F48(92 20) 5F48(<32-byte scalar>)`), which
  returned `9000` and produced a readable public key. Recorded so that nobody "fixes" it, and so
  the next person does not spend an hour on `0x99` as I did.

**Still not verified: the app's own provisioning on a pristine card.** Three attempts to drive the
*shipping* code from this Mac failed for transport reasons, every one of them worth knowing:

* `TKSmartCardSlotManager.default` is **nil** in a command-line binary, and still nil when the same
  binary is wrapped in a minimal `.app` bundle — even though `system_profiler SPSmartCardsDataType`
  lists the reader (`Yubico YubiKey FIDO+CCID`) and `scdaemon` talks to the card happily. So the
  CCID transport cannot be exercised from a plain macOS process here; the "directly attached CCID
  device without an additional entitlement" question of item 12 needs the iOS app, an entitled
  macOS app, or a reader-hosted card.
* The `PCSC` framework on this OS ships **no headers and no binary** (only `XPCServices`), so a
  PC/SC-based probe cannot be built against it either. `scdaemon` reaches the card through its own
  built-in CCID driver, not through that framework.
* Wrapping the certificate's own transport at least compiles now: `SmartCardTransport` is guarded by
  `canImport(CryptoTokenKit)` rather than `os(iOS)`, so the package build type-checks it on macOS
  instead of only during the iOS app build.

**Probe traps, all of which cost time and one of which cost the Admin PIN:**

1. **`scdaemon` caches a successful VERIFY PW3** and silently re-sends it in later sessions, so a
   protected write looks unprotected. Kill the agent before drawing conclusions about access
   conditions (already recorded in item 18).
2. **A burst of raw APDUs wedges the reader.** Sessions then return nothing at all
   (`ERR 100663406 Card removed`) while the card is fine; `gpgconf --kill scdaemon` recovers it.
   Multi-command bundles are the worst case, which is why the ceremony's own "one session per
   operation" shape is the right one for the app and the wrong one for a shell probe.
3. **A wedged or half-written slot answers `6A80` to a re-import and `6581` to a key read**, which
   is indistinguishable from a malformed template. I chased that as a missing-public-key bug until
   the same bytes succeeded on a clean slot. A probe must read the slot back before concluding
   anything about a rejected import.
4. **A probe that guesses PINs burns attempts.** One malformed `CHANGE REFERENCE DATA` (an `Lc`
   that was two bytes too large) left the Admin PIN unchanged while the script went on to verify
   with the new one — three times — and blocked it. The card was recoverable (trap 5's rule), but
   the script now aborts on the first failed VERIFY, and any future probe should.

**Consequence for the app: it cannot reset a card whose Admin PIN is blocked.** The applet allows
`TERMINATE DF` without PW3 in exactly that state, and `ykman openpgp reset` relies on it — but this
app's reset step verifies PW3 first, so as written it cannot rescue such a card and would report
`pinBlocked` instead. That is recorded rather than fixed: offering a no-PIN reset is a destructive
path (it erases both keys) and belongs with the unblock feature of item 19, in a version that can
also replace the PINs afterwards.

The card was left **factory-fresh**: reset, default PINs, no keys, `UIF = 00 20`, `C4 = 01 7F 7F 7F
03 00 03`. Nothing the probe wrote is still there, and the app's next provisioning run starts from
a reset in any case.

