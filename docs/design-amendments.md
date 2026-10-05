# Amendments applied to design.md

`design.md` is the specification this implementation is built against. Where the
implementation had to diverge, the specification was changed rather than left
silently inconsistent — a spec that disagrees with the code is worse than no spec,
because it makes the next reader trust the wrong document.

Each amendment below is applied in place in `design.md` and listed here so the
change is visible without diffing a 34 KB document.

## 1. Entropy: system CSPRNG is authoritative, dice are not

**Sections:** §4.2 step 4, §4.2 step 6b, Appendix B, §9.4, §9.5, §10 item 10.

*Before:* users were "strongly advised" to roll dice, and §4.2 step 6b and
Appendix B required confirming that the dice sequence mapped to the mnemonic.

*After:* `SecRandomCopyBytes` is the sole authoritative source. Dice are optional,
recorded as a ceremony witness, and explicitly non-authoritative. The
dice→mnemonic cross-check is removed, because it is unverifiable without a
published dice→entropy function.

*Why:* implementing dice as an entropy source requires specifying and publishing
the exact mapping so an independent tool can reproduce it. Claiming a check that
cannot be performed is worse than not claiming it.

*Consequence recorded in the spec:* the "backdoored RNG" node of the §9.4 attack
tree is no longer mitigated, and §9.5 records that residual risk as **Medium**
(raised from Low), with the path back to Low documented. This is an accepted
regression, not an oversight.

## 2. Lightning / 5Ci removed; USB-C CCID added

**Sections:** §3.2, §4.1 (diagram), §6.5, §7.2, §10 item 4.

*Before:* 5Ci over Lightning was a listed transport, "using the accessory channel
of Yubico's official iOS SDK".

*After:* transports are NFC (CoreNFC ISO 7816) and USB-C CCID (CryptoTokenKit).
Lightning/5Ci is explicitly not supported.

*Why:* the Lightning path depended on a vendor MFi accessory SDK that YubiKit 4.x
dropped, making it the project's only external SDK dependency and an availability
risk. USB-C CCID uses Apple frameworks only, so the project now ships with **no
third-party runtime dependency at all** — which also serves the reproducible-build
goal.

*Consequence:* the wired transport requires an iPhone 15 or later. NFC still
covers every CoreNFC-capable iPhone, so no ceremony capability is device-gated.

## 3. The signature counter is read on-device

**Sections:** §4.2 step 9, §5.2 rule 3, §10 item 8.

*Before:* §4.2 step 9 said to "insert the YubiKey into the Desktop" and §5.2
rule 3 made the Desktop the authoritative counter reader.

*After:* the counter is read over NFC or USB-C; §5.2 rule 3 is restated as "read
by a party other than the one that displayed the transaction", which is the
property that actually matters.

*Why:* reading `0x93` needs no PIN and exposes no secrets, so requiring a Desktop
tether during provisioning only adds friction and contradicts the cold-device
intuition the documentation has to fight anyway.

## 4. Pairing export omits the chain code

> **Superseded by amendment 14.** Omitting the chain code is not a compatibility
> trade-off: it is a hard decode failure in MetaMask. The export now always
> carries a chain code and pins `children` to the card's leaf.

**Sections:** §6.4 (table and bullets), §10 item 11.

*Before:* §6.4 listed `crypto-hdkey` / `crypto-account` as the pairing export.

*After:* v1 exports a single address-level `crypto-hdkey` (legacy naming by
default, current `hdkey` naming offered) with **no chain code**. Chain-code
export exists but requires an explicit acknowledgement that the derived addresses
cannot be signed for, and is recorded in the provisioning report.
`crypto-account` / `account-descriptor` is not emitted.

*Why:* one YubiKey signature slot holds exactly one key (§4.3). A chain code, or an
account-level descriptor, advertises child addresses that this card *cannot sign
for* — a wallet could derive them, the user could send funds to them, and the
funds would be unspendable from this device. Publishing capability the signer does
not have is a correctness bug in the export, so the safe default is no chain code.

*Consequence for interoperability:* wallets built around an account-level extended
public key (MetaMask's QR hardware flow keys off the Keystone UR family) may not
enumerate accounts automatically. The app therefore shows the address in large
monospace type and requires the operator to confirm the wallet displays the same
address. Recorded in §10 item 11 and in `docs/v1-threat-notes.md`.

## 5. Distribution is free-personal-team sideloading

**Sections:** §4.2 step 1, §10 item 12.

*Before:* App Store install or sideload, both described without discussing profile
lifetime.

*After:* the reference build uses a free personal team, which means a **7-day
profile expiry** and a weekly re-signing ritual; a paid account gives 1-year
profiles.

*Why:* it is what is actually available. The consequence — tethering the
"offline" iPhone to a computer weekly — is a real property of the trust story and
belongs in the spec rather than in someone's memory. Recorded that re-installing
over the same bundle preserves data and that no secret is stored, so the worst
case is a re-pairing.

## 6. v1 scope stated explicitly

**Sections:** §3.2 (non-goals), §11 (roadmap), §10 items 9–12.

*Before:* §5 (signing) read as though it described the shipped product.

*After:* §10 item 9 states that v1 is provisioning-only, §11 lists v0.1 (shipped,
provisioning only), v0.2 (signing flow and counter-delta auditing), v0.3 (PSBT and
the desktop client), and §3.2 lists the dropped transports and in-app signing as
non-goals.

*Why:* the scheme's central claim — that a tampered iPhone cannot cause the
Desktop to broadcast a different transaction — is only testable once both the
signing exchange and the Desktop verifier exist. Leaving that implicit invites a
reader to assume a control that is not there yet.

## 7. One key per algorithm instead of one key per chain

**Sections:** §3.1, §3.2, §4.2 steps 3–9, §4.3, §6.1, §6.4, §6.5, §9.4, §9.5,
§10, Appendix B, §11.

*Before:* a ceremony provisioned **one** key into the signature slot, targeting
one chain (EVM or Bitcoin), at that chain's default path. Serving a second chain
meant re-provisioning or a second YubiKey.

*After:* a ceremony provisions **two** keys from the one mnemonic, one per
algorithm: ECDSA secp256k1 in the signature slot at `m/44'/0'/0'/0/0`, and
Ed25519 in the authentication slot at `m/44'/501'/0'/0'` (SLIP-0010). The paths
are algorithm-scoped, not chain-scoped: every secp256k1 chain shares the one key
(the app derives both its EVM and its Bitcoin address) and every Ed25519 chain
shares the other.

*Why:* the OpenPGP applet exposes two signing-capable slots, so "one slot per
chain" scales to exactly two chains. "One slot per algorithm" covers the
practical chain landscape with the same hardware. The alternative — one key per
chain — needs a YubiKey per chain.

*Consequence recorded in the spec, and it is the important one:* only the
**signature** slot increments the hardware signature counter. Ed25519 must live
in the authentication slot (there is nowhere else for it), and
`INTERNAL AUTHENTICATE` is not counted. The counter audit of §5.2 rules 3–4
therefore covers secp256k1 chains only. PIN and touch authorization still apply
to both keys, and independent verification of what was signed is unaffected; what
is lost is the *detection* control for one social-engineered extra touch on the
Ed25519 key. §9.5 records this as **Medium** residual risk and §4.3 states it
plainly. This is an accepted trade, not an oversight.

*Interoperability consequence:* v1 does not derive chain-specific Ed25519
addresses. The Ed25519 identity is the 32-byte public key, and the pairing export
carries no chain code (amendment 4 stands, and now applies to two keys).

## 8. Independent cross-check removed from the ceremony

**Sections:** §4.2 step 7 (was "6b"), §6.4, §9.4, §9.5, §10 items 6, 9 and 10,
§11, Appendix B.

*Before:* §4.2 step 7 (labelled "6b") was a mandatory independent
cross-verification: on a separate device with a different implementation
(`tools/derive`), the operator entered the same mnemonic and compared three
derived values (EVM address, Bitcoin address, Ed25519 public key) against the
values the app read back from the YubiKey. A mismatch voided the ceremony.

*After:* the operator-facing independent cross-check is removed. The ceremony
still verifies read-back (§4.2 step 7, now a standalone step): the app reads each
public key back out of the YubiKey and compares it byte-for-byte against the key
it derived and imported. There is no longer a step that compares the app's output
against an external tool or wallet.

*Why:* the operator does not want the address to be verified from an external
tool or wallet after the keys are written to the YubiKey. The read-back check
remains the mandatory in-ceremony verification; the external-tool comparison is
dropped.

*Consequence recorded in the spec:* the read-back check (§4.2 step 7) now stands
alone. The "App displays a mnemonic it did not actually write" node of the §9.4
attack tree is no longer mitigated, and §9.5 records the generation-phase
tampering and backdoored-RNG residuals as no longer bounded by the cross-check.
`tools/derive` remains in the repository as a differential-testing oracle (its
fixtures still cross-check the Swift derivation against an independent Python
implementation at build/test time), but it is no longer part of the operator
procedure.

## 9. Entropy source: YubiKey hardware RNG XORed with the iOS CSPRNG

**Sections:** §4.2 step 4, §6.5, §9.4, §9.5, §10 item 10.

*Before:* §4.2 step 4 generated the 256-bit BIP39 entropy on the iPhone with
`SecRandomCopyBytes`, the iOS system CSPRNG.

*After:* the entropy is the XOR of the YubiKey's hardware random-number generator
(`GET CHALLENGE`, INS `0x84`) and the iOS system CSPRNG (`SecRandomCopyBytes`).
The mnemonic and both private keys are still derived on the iPhone from that
entropy, so the "mnemonic is the backup" model is unchanged; only the source of
the random bits changes.

*Why:* the operator wants the private key's randomness to come from the YubiKey's
secure-element RNG rather than the general-purpose iPhone OS RNG alone — and
mixing the two means neither a backdoored card RNG nor a backdoored OS RNG can
determine the key on its own.

*Consequence recorded in the spec:* the §9.5 "Backdoored or faulty entropy source"
residual risk drops from Medium to Low, because a single compromised RNG no longer
yields the key. The §9.4 attack tree's "Backdoored RNG" node is updated
accordingly. The exact per-call response length of `GET CHALLENGE` is an M0
hardware-verification item (see `docs/m0-hardware-verification.md`).

## 10. Read-back addresses the slot with a TLV CRT, not a bare tag

**Sections:** §6.5.

*Before:* `GENERATE ASYMMETRIC KEY PAIR` (read mode, P1=0x81) addressed the slot
by sending the Control Reference Template as a **bare tag** (`B6`, Lc=01).

*After:* the CRT is sent as a **TLV with an empty value** (`B6 00` / `A4 00`,
Lc=02). Real hardware rejected the bare-tag form with `6A80` (wrong data); the
TLV form reads the public key correctly.

*Why:* a Control Reference Template is a TLV structure, not a bare tag. The
codebase had assumed the compact form; the first real-device test disproved it.

*Consequence recorded in the spec:* §6.5's read-public-key APDUs now show
`00 47 81 00 02 B6 00 00` and `00 47 81 00 02 A4 00 00`. This was one of the M0
hardware-verification assumptions, now resolved in favour of the TLV form.

## 11. Read-back detects non-EC (RSA) keys; firmware floor confirmed

**Sections:** §6.5, §7.2.

*Finding:* a real YubiKey on firmware 5.1.3 (OpenPGP applet 3.3) returned
"7F49 had no EC point (86)" when the app read the signature slot, because the
slot held an RSA key — the older applet defaults to RSA and does not support
secp256k1/Ed25519 at all. This confirms the §4.2 prerequisite that firmware
5.2.3 (OpenPGP applet 3.4) or newer is required, and that YubiKey firmware is
not upgradeable.

*Change:* `readPublicKey` now distinguishes the two cases — an RSA key (modulus
`0x81` present) raises `CardError.unsupportedKeyType`, and the inventory counts
the slot as occupied so the destructive reset gate still applies. Any other
missing-EC-point response is reported with an explicit "firmware 5.2.3 or newer
required" message instead of the cryptic "no EC point (86)".

## 12. TERMINATE DF / ACTIVATE FILE are case-1 commands (no Le byte)

**Sections:** §6.5.

*Before:* `terminateDF()` and `activateFile()` sent `00 E6 00 00 00` and
`00 44 00 00 00` — a spurious Le byte (`expectedLength: 0`) on what are case-1
(no-data, no-response) commands.

*After:* both send the 4-byte case-1 form `00 E6 00 00` / `00 44 00 00`. Real
hardware rejected the 5-byte form with `6581` (card memory failure) during the
reset step.

*Why:* the OpenPGP card spec defines TERMINATE DF and ACTIVATE FILE as case-1
commands. The code had applied the "always include Le" convention where it does
not belong, and the golden test (`00e60000` / `00440000`) had drifted from the
actual method.

## 13. The ceremony hard-gates on an unsupported OpenPGP applet

**Sections:** §4.2 step 2, §7.2.

*Before:* a card whose OpenPGP applet was below 3.4 (firmware < 5.2.3) produced
only a warning on the inventory screen, and the ceremony would continue to the
reset step and then fail later with confusing errors (6A80, 7F49 without an EC
point, 6581 memory failure).

*After:* `CardInventory.isDefinitelyUnsupported` detects a parseable applet
version below 3.4, the inventory screen shows a red "too old to provision"
notice, and `advance()` from the inventory step throws
`unsupportedAppletVersion`, so the ceremony cannot proceed on hardware that
cannot hold secp256k1/Ed25519.

*Why:* real-device testing on firmware 5.1.2 (OpenPGP applet 2.1) confirmed the
applet only supports RSA. YubiKey firmware is not upgradeable, so no code change
can make such a card work; the app must refuse up front rather than fail later.

## 14. Pairing export carries a chain code and exports secp256k1 at the account level

**Sections:** §4.2 step 8, §4.3, §6.4, §7.1, §10 item 11. **Supersedes
amendment 4.**

*Before:* the pairing export omitted the chain code (CBOR field 4) and exported
the leaf key at its own path (`m/44'/0'/0'/0/0`).

*After:* every `crypto-hdkey` carries its chain code and a `name` (CBOR field 9,
`"PlexVault"`). The secp256k1 key is exported at its **BIP44 account level**
(`m/44'/0'/0'`) with the `children` keypath pinned to the fixed path that reaches
the card's leaf (`0/0`, no wildcard). Ed25519 is exported at its own path
(`m/44'/501'/0'/0'`) with its chain code and no `children` — SLIP-0010 is
all-hardened, so nothing is derivable from an extended public key there anyway.

*Why:* amendment 4 assumed a chain code was optional and that omitting it merely
limited account discovery. It is mandatory. `@keystonehq/bc-ur-registry`'s
`CryptoHDKey.getBip32Key()` concatenates the chain code unconditionally:

```ts
const chainCode = this.getChainCode();   // undefined when field 4 is absent
return encode(Buffer.concat([version, depthBuffer, parentFingerprint,
                             indexBuffer, chainCode, key]));
```

The browser `buffer` polyfill MetaMask bundles reads `.length` of each element in
`Buffer.concat`, so a `crypto-hdkey` without a chain code fails the scan with
`TypeError: Cannot read properties of undefined (reading 'length')`. The export
was therefore not "usable with manual confirmation" — MetaMask could not read it
at all.

*Consequence recorded in the spec:* the exported secp256k1 key is an **ancestor**
of the card's key, not the key itself. `children` is pinned to the card's leaf so
that a wallet which enumerates accounts (MetaMask derives `<origin>/0/*` by
default) presents the card's one address rather than siblings the card cannot
sign for. Verified against MetaMask's own `@keystonehq/*` packages: the QR no
longer throws, and account indices 0..4 all resolve to the card's EVM address.
Because a chain code is still mathematically present, a wallet that ignores the
pinned `children` path could derive siblings; the operator must therefore
acknowledge `PairingPolicy.chainCodeWarning` before the codes are built (a hard
gate on `buildPairingURs`), and the warning is recorded in the provisioning
report.

*Not changed:* `crypto-account` / `account-descriptor` is still not emitted, and
`children` is pinned rather than a wildcard.

### 14a. The `name` field is mandatory in practice, not decorative

Omitting `name` (field 9) is a second hard failure, independent of the chain code.
MetaMask keys the display name of the QR keyring off it:

* `@keystonehq/base-eth-keyring`'s `__readCryptoHDKey` is the **only** place that
  ever restores the keyring name:
  `const name = cryptoHDKey.getName(); if (name !== undefined && name !== "") { this.name = name; }`
* `BaseKeyring.deserialize()` unconditionally overwrites the `"QR Hardware"`
  default with the persisted value, which has no `name` for a QR keyring that was
  added but never paired (the failure mode MetaMask itself patched in
  metamask-extension#23903). After that, `this.name` is `undefined` unless the
  scanned `crypto-hdkey` restores it.
* On confirm, `metamask-controller.js`'s `getAccountLabel()` evaluates
  `` `${name[0].toUpperCase()}${name.slice(1)} …` `` — i.e. `undefined[0]` — and
  throws `TypeError: Cannot read properties of undefined (reading '0')` **after**
  the account list has already shown the correct address.
* `@metamask/eth-qr-keyring`'s `Device.getName()` (MetaMask Mobile) returns the
  field as-is, so without it the paired device reports no name at all.

Reproduced against MetaMask's own packages: with the pre-fix export the keyring
name is `undefined` and the confirm step throws exactly that `TypeError`; with
`name` present the keyring name is `"PlexVault"` and the label is
`"PlexVault 1"`. The export therefore always sets field 9
(`PairingPolicy.deviceName`).

### 14b. Consequence: a wallet enumerating accounts sees repeated addresses

Because `children` is pinned to `0/0`, MetaMask's index substitution is a no-op
and every page entry derives the same address: `getFirstPage()` returns five
entries with **one** distinct address. Every one of them is signable, which is
intentional — but two behaviours follow and must be explained to the operator:

* Re-adding an index adds the same address again (`BaseKeyring.addAccounts` does
  not deduplicate), so the wallet can end up listing it twice.
* MetaMask Mobile's `QrKeyring.createAccounts()` refuses a second index with
  `Failed to create new account`.

The alternative — the wildcard `children = "0/*"` MetaMask expects — would show
five *distinct* addresses of which only index 0 is signable, which is the
capability over-advertisement this design forbids (Known Limitations #11). The
pinned path is kept, and the UI requires the operator to acknowledge it.

## What was deliberately *not* changed

* **§5.2 rule 1 (one transaction, one `PSO:CDS`) and rule 2 (one touch)** are
  unchanged in the spec and are repeated in the app's UI and the printed
  checklist, even though v1 cannot yet sign. The habit and the user-facing warning
  belong to the workflow, not to the signing code.
* **The mandatory read-back (§4.2 step 7)** is unchanged and is additionally
  enforced by the state machine: the ceremony cannot reach pairing export
  without it.
* **§9.3's core argument** is unchanged. Nothing in v1 weakens it; v1 simply does
  not yet exercise it.

## 15. Consecutive NFC reader sessions need a cooldown, and a session loss is not a card error

**Sections:** §4.1, §4.2 step 2, §5.2 rules 1 and 8, §6.5.

*Before:* `NFCTagTransport.close()` invalidated the reader session and returned
immediately; the next `open()` created a new `NFCTagReaderSession` and began it
straight away. Every transport failure was reported through one string, so the
operator saw "The YubiKey could not be reached (Session invalidated
unexpectedly)" for two very different situations: a card that never answered, and
iOS refusing to start a session at all.

*After:* three rules the transport now follows:

1. `close()` waits for `didInvalidateWithError` to confirm the session is gone
   (bounded by a timeout, so a missing callback cannot wedge the ceremony);
2. a **2-second cooldown** is held after an invalidation before the next
   `begin()`;
3. `begin()` is retried, up to a small fixed budget, when the failure is one of
   the two session *races* — `NFCReaderError` 202 (session ended unexpectedly) or
   203 (system busy). Operator cancellation (200) and the system timeout (201) are
   decisions, not races, and are never retried: that is §5.2 rule 8, which still
   applies to any session in which an operation was already sent.

Each `NFCReaderError` code also gets its own operator-facing wording.

*Why:* the ceremony opens **one reader session per card operation**
(`TransportSessionCard`), and several steps perform two operations back to back
with no operator interaction between them — `reset` → `inventory`,
`applyPolicy` → `inventory`, and both keys' imports and read-backs. iOS fails a
session begun while the previous session's sheet is still being dismissed, and
reports that as `NFCReaderError` 202 "Session invalidated unexpectedly". The card
is not at fault and the previous operation succeeded; the next session simply
started too early. The reset step was where this surfaced first because it is the
first back-to-back pair in the ceremony, and because a card that already holds a
key makes the erase itself slower.

Yubico's own YubiKit hard-codes the same two seconds for the same reason
(`YubiKit/YubiKit/Connection/SmartCard/NFCSmartCardConnection.swift`):

> iOS fails a reader session begun while the previous session's sheet is still
> being dismissed (NFCReaderError 202, "Session invalidated unexpectedly"), so
> wait this long after an invalidation before beginning a new session.

*Consequence:* the policy is pure arithmetic and classification, so it lives in
`YubikeyKit/NFCSessionPolicy.swift` and is unit-tested on macOS — CoreNFC has no
simulator, and this is exactly the code that cannot be exercised on a desktop.
`M0` item 11 covers the on-device confirmation.

## 16. `SELECT` reactivates a terminated DF

**Sections:** §4.2 step 2, §6.5.

*Before:* `OpenPGPCard.select()` treated any non-`9000` answer as a hard error.

*After:* `6985` (`CONDITIONS OF USE NOT SATISFIED`) and `6285` (`NO INPUT DATA`)
on `SELECT` are handled as "the applet is not activated": the card sends
`ACTIVATE FILE` (`00 44 00 00`) and then re-selects.

*Why:* a reset is `TERMINATE DF` + `ACTIVATE FILE` + re-SELECT, and the reset
step sends all three inside one NFC session. If that session drops between the
first two, the card is left **terminated**: wiped, deactivated, and answering
`6985` to everything but `ACTIVATE FILE`. Without the recovery, that card could
not be provisioned by this app again — every later session failed at `SELECT` with
"preconditions were not met", and only GPG or `ykman` could reactivate it. The
recovery mirrors `yubikit`'s `OpenPgpSession.__init__`, which treats exactly those
two status words as "Not activated, activate" and re-selects.

*Consequence:* the simulated card models the terminated state
(`simulateInterruptedReset()`), so the recovery path — and the fact that a
completed reset never needs it — is pinned by tests rather than by a device
session.

## 17. A failed mutating step rewinds only when the card's state is unknown

**Sections:** §4.2 step 2, §5.2 rule 1.

*Before:* `withMutatingStep` cleared its "operation in flight" marker only on
success, so *every* failure during `reset`, `PIN provisioning`, `policy` or
`keyImport` was treated as an interruption. The UI, however, never called
`noteInterruption()` on a failure path at all — it only did so when the app was
backgrounded — so in practice the operator stayed on the failing screen with the
gate still armed, which invites the blind retry §5.2 rule 1 forbids.

*After:* two halves, both in the state machine rather than the view layer:

* `CardError.isDefinitiveCardRejection` separates a card that **answered no** —
  failed or blocked PIN, unmet preconditions, unsupported algorithm or object, a
  rejected key import — from an outcome that is genuinely unknown (a transport
  failure, an unparsed status word). Only the unknown kind leaves the marker set;
* the app's failure path calls `ceremony.noteInterruption()` on every error, and
  `noteInterruption` remains a no-op unless the marker is set.

*Why:* a wrong Admin PIN writes nothing, and rewinding to the inventory screen
over a typo costs the operator a card re-read and a second tap for no security
benefit. The opposite error is worse, which is why the classification defaults to
"unknown": an unrecognised status word must force a re-read, because a
half-written key is exactly what the re-inspection rule exists to catch.

*Consequence:* `CardErrorPolicyTests` pins the classification, and the ceremony
tests assert both directions — a dropped session rewinds, a refused PIN and a
rejected import do not.

## 18. The chain code is stored on the card, so a re-pair needs no reset

**Sections:** §4.2 (new step 7b), §6.5 (two rows), §10 (new item 13).

*Before:* a pairing code could only be produced during the ceremony that created
the keys. The chain code a wallet requires (amendment 14) is not in the YubiKey —
the OpenPGP applet stores a key, not a BIP32 node — so the only way to show the
codes again was to re-run §4.2 from the top, which resets the applet and destroys
the keys. An operator who lost the pairing codes, or wanted to pair a second
wallet, had to wipe a working card.

*After:* the ceremony writes the public material a wallet needs into the applet's
second private-use data object (`PUT DATA 0x0102`, 194 bytes), and reads it back
before the codes are shown (§4.2 step 7b). The app still persists nothing; the
card holds the manifest, so it survives reinstalls, the weekly profile expiry of
§10 item 12, and a new phone.

*Why this object.* The four private-use data objects (spec §4.3.1, optional, "can
be used to store any information") differ in access conditions by design, and the
difference decides which is usable:

| object | read | write | usable? |
|---|---|---|---|
| `0x0101` | no PIN | PW2 | no — PW2 is the resetting code, which this app never sets |
| **`0x0102`** | **no PIN** | **PW3** | **yes** — read free, and PW3 is already verified when the ceremony writes |
| `0x0103` | PW2 | PW2 | no — a re-pair must not need a PIN to read |
| `0x0104` | PW3 | PW3 | no — same reason |

Measured on a YubiKey 5C NFC (firmware 5.8.0, OpenPGP 3.4) with no PIN presented:
`GET DATA 0x0101` and `0x0102` answer `9000` (empty); `0x0103` and `0x0104` answer
`6982`. `PUT DATA 0x0102` accepts 254 bytes and refuses 255 with `6A80`. A
zero-length `PUT DATA` empties the object. Recorded in
`docs/m0-hardware-verification.md` item 12.

*Why it is written after the read-back check, and not before.* The manifest makes
the card advertise a key to a wallet. Writing it before the card has been shown to
hold that key would let a card that failed verification be paired anyway. It also
cannot be written before the reset, because `TERMINATE DF` wipes it: the object
lives inside the applet, so the manifest has the same lifetime as the keys.

*Why a plain byte comparison is not enough.* A manifest that is merely present
proves nothing — it can be stale, copied from another card, or corrupted. The app
therefore derives the pinned child of the stored account node and requires it to
equal the public key the card reports for its own signature slot. That is a
watch-only derivation, so `ExtendedPublicKey` (`ckd_pub`) is now implemented in
`VaultKit/BIP32`; until this change the source said in as many words that public
derivation was deliberately absent because the ceremony did not need it. It is
tested against the `xpub` values in the published BIP32 vectors, not against its
own output.

*Consequence for the threat model, and how it is bounded:* the manifest is public
data, so a card that is read by someone else discloses the account-level extended
public key — a watch-only capability, not a signing one. The marginal disclosure
over what the card already leaks is the chain code and the fingerprint: the public
key in the signature slot is readable without a PIN under any circumstances
(`GENERATE ASYMMETRIC KEY PAIR P1=0x81` is "read always"). Recorded in §10 item 13
rather than argued away.

*Read side:* delivered as §4.2 step 7c in amendment 19, which also corrects the
layout this amendment first wrote (198 bytes, version 2 — one master fingerprint
**per entry**).

## 19. Re-pair is a read-only mode, and a wallet has two master fingerprints

**Sections:** §4.2 (new step 7c, step 7b's format), §10 item 13. Supersedes the
"not yet done" note at the end of amendment 18.

*Before:* amendment 18 put the pairing material on the card, but the app could
only ever **write** it: the operator still had no way to get the codes back off a
card that was already provisioned. The one stored number that could not carry the
load turned out to be the master fingerprint.

*After — the read side.* A third `CeremonyMode` (`rePair`) with its own five-step
route (`cardInventory → rePairRead → pairingExport → counterBaseline → teardown`)
reads the manifest with `GET DATA 0x0102`, reads both public keys back out of the
card, and runs amendment 18's binding check before any code exists. No PIN is
presented, no mnemonic is entered, and nothing is written.

*Why "cannot write" is a property and not a promise.* Every mutating entry point in
`ProvisioningCeremony` already begins with `requireCurrent(<its own step>)`, and
this route never reaches those steps, so an accidental write would require a bug
in the step machine rather than a mistake at a call site. The route itself is data
(`CeremonyMode.path`) and a test asserts that **no step on it** is one of
`isMutatingCardState`'s. A separate test calls each mutating entry point during a
re-pair and requires `stepOutOfOrder`; another requires the destructive route to
still be the one a provisioning ceremony takes.

*The defect this work found.* Writing the read side meant comparing a re-pair's
printed record against the one the ceremony produced, and the comparison failed on
two fields — which is how a formatting assumption made in amendment 18 turned out
to be wrong.

A wallet has **two** master fingerprints, and they are different numbers:

| key | master | source |
|---|---|---|
| secp256k1 (`m/44'/0'/0'/0/0`) | `5436d724` | BIP32 master |
| Ed25519 (`m/44'/501'/0'/0'`) | `b2160abd` | SLIP-0010 master |

(Those two values are for the all-zero-entropy test mnemonic and were produced by
`tools/derive`, the independent Python oracle — not read off the app's output. The
oracle computes them in different functions to this day:
`describe_secp256k1` uses `fingerprint(master_key(seed))`, `describe_ed25519` uses
`slip10_fingerprint(slip10_master_key(seed))`.)

Version 1 of the manifest stored one fingerprint for the whole object, and the
re-pair rewrote the UR builder to take that single value from the first key. That
silently changed the **Ed25519** UR's `source-fingerprint` from the SLIP-0010
master to the BIP32 master: a code describing an origin that does not exist, with
no test failing, because the only place the value was asserted was the ceremony's
own output. The fix is per-entry fingerprints, which is what a *reader* needs:
without them a re-pair cannot reconstruct the Ed25519 code at all, since SLIP-0010
is all-hardened and no fingerprint can be derived upward from the stored child key.

So the format is version 2 — one master fingerprint inside each entry, 198 bytes
for two entries — and version 1 objects are **refused**, not read: a v1 object
cannot express the Ed25519 key's source fingerprint, so any code built from one
would be wrong. The two oracle values are now pinned as literals in the pairing
test, and the read-path test compares the whole record a re-pair prints against the
record the ceremony printed, field for field.

*Three smaller things the read side had to get right.*

1. **The record's `parentFingerprintHex` is the leaf's parent, not the origin's.**
   The UR field 8 and the printed record look like the same thing and are not: for
   the secp256k1 export the UR names the *account* path's parent, while the record
   names the parent of the key in the card (`…/0/0`). The second is recoverable
   from a public key only because the pinned path is non-hardened, so
   `cardLeafParentFingerprint(for:)` derives it rather than copying the entry's.
2. **A re-pair must not stop on a non-zero counter.** Step 9's zero check is a
   provisioning rule ("the card may already have signed"); a card that is in use is
   the normal case here, so the value is recorded and the operator is told to
   compare it against the wallet's `expected_counter`.
3. **A reset erases the manifest — including in the mock.** `MockSignerCard.reset`
   was not clearing the stored object, so a re-pair test could have passed on a card
   that in reality has nothing left. It now clears it (keeping the *capability*
   flag, since an applet without private-use objects still has none after a reset),
   and a test asserts that a reset card cannot be re-paired.

*Consequences.* An operator can pair a second wallet, or re-pair after losing the
codes, without touching a working card. The exposure is unchanged from amendment
18 and is recorded in §10 item 13. A card that was reset, or provisioned before
this feature existed, has no manifest and needs the mnemonic — the app says so
before the ceremony ends, and refuses rather than inventing codes.

## 20. The pairing screen renders from the record, and a ceremony inherits nothing

**Sections:** §5.2 (new rule 8).

*Reported:* after reading the manifest in re-pair mode, the pairing step showed no
QR code and no addresses — so there was nothing to import into a wallet and nothing
to check against it. The mode was useless in practice despite passing its unit
tests.

*Cause.* `PairingStepView` rendered its codes from `viewModel.derivedKeys`, which
exists only when a mnemonic was entered. A re-pair deliberately has none, so the
screen's entire code-and-address block was skipped and only the warnings remained.
The unit tests could not see this: they assert ceremony state, and the ceremony
state was correct — the *view* was reading the wrong source.

*Fix.* The pairing screen now renders from the ceremony **record**
(`CeremonyViewModel.keyRecord(for:)`), which both routes fill in: provisioning from
the derivation, re-pair from the card and the manifest on it. Renders-from-the-record
is the rule, because the record is the thing both routes are guaranteed to produce.

*Found while testing the fix, and fixed with it.* Driving a full ceremony and then a
re-pair in one app session exposed a second defect of the same family:
`resetTransientState()` did not clear the previous ceremony's results — `inventory`,
`pairingURStrings`, the manifest flags, the re-pair records, `report` and the
acknowledgement gates all survived "Provision another wallet". The second ceremony
therefore opened on the **previous card's inventory**, showing "Factory fresh / no
keys" for a card that had just been provisioned and offering "Continue" where it
must ask the operator to read the card; and its pairing step would have shown the
previous ceremony's codes. The state is now cleared on the way into a ceremony as
well as on the way out, and §5.2 rule 8 records the invariant.

*Evidence.* Both defects are covered by a UI test that provisions the simulated card
through the whole ceremony (previously no test walked past the mnemonic), returns to
setup, re-pairs read-only, and asserts that the codes and the **independently
derived EVM address** are on screen. It fails on both defects as they were, and on
the second one only because it drives two ceremonies in one session — which is why
the unit tests missed it.

*Cost.* That test runs a complete ceremony, so the UI suite went from ~40s to ~8
minutes. It is kept in the default (non-`QUICK`) run: it is the only coverage of the
ceremony's end-to-end behaviour in the real app, and both defects it catches were
invisible to every other kind of test.

*Also learned, and recorded because it wasted an afternoon:* the UI helpers' tappable
band is deliberately conservative — it reserves the area under the pinned footer, so a
step action that settles at the end of a tall page's content lands ~5pt below it and
the band-based helper refuses to tap a button that is plainly on screen. Step actions
are now tapped by label through `tapStepAction`, which scrolls until `isHittable`.
This is a test-harness lesson, not a product rule, but it is where a future reader
will look after watching the walk stall on the derivation step.

## 21. v0.2: the signing flow, and three places the specification was wrong

**Sections:** §3.2, §5.1, §5.2 (new rules 7b, 7c), new §5.3, §6.1, §6.5, §10 item 9, §11.

The signing flow was specified in §5 long before it existed, and implementing it against
the reference implementation (MetaMask's QR keyring and `@ethsign`/`bc-ur-registry-eth`)
showed the specification was wrong in three places. They are recorded here because each
one would have produced signatures that look fine and do not work.

**1. For transactions, the request carries no address.** §5.1 step 8 required the app to
check that the request's `address` matches the locally paired address. MetaMask's
`signTransaction` does not send that field — only the derivation path and the master
fingerprint — so the check as written could not exist. What binds the request to the card
is the path and the fingerprint, and what protects the operator is that the app shows the
address derived from **the card's own public key** so it can be compared with the wallet's
screen. The `address` field is still checked when a wallet does send it (messages do).

**2. The `data-type` field is a bare integer, not the tagged map the CDDL describes.**
ERC-4527 writes `data-type` as `#3.401(sign-data-type)`; `bc-ur-registry-eth` writes a
plain unsigned integer, which is what MetaMask's scanner has been tested against. The
decoder accepts the bare integer and refuses the tagged form rather than guessing.

**3. The recovery value has two conventions, and the wallet stores what it is given.**
For typed transactions the 65th byte is the y-parity; for legacy transactions it is the
full EIP-155 value `chainId·2 + 35 + recid`, because that is what the consumer writes into
the `v` slot and what the network recovers the sender from (ethereumjs's own validation
accepts `v = 27/28` or `v ≥ 37` for legacy, and its `_processSignature` adds
`chainId·2 + 8` only on the internal signing path). §5.1 said "try `v ∈ {0,1}`", which is
right for typed transactions and silently wrong for legacy ones. And for chain ids above
110 the EIP-155 value does not fit in one byte at all, so the signature field grows to
2–4 bytes rather than carrying a wrong `v`: the EIP's `bytes .size 65` is unsatisfiable
there. A real MetaMask on Polygon or Arbitrum is item 14 in
docs/m0-hardware-verification.md, because that deviation is the one thing here that only a
wallet can confirm.

**Decisions taken while implementing**

* **Transactions only.** `personal_sign` and EIP-712 are decoded and then refused with an
  explanation. EIP-712 needs the full structured-hashing encoder, and signing either with a
  transaction's `v` convention would produce a signature no wallet accepts.
* **Chain ids are confirmed per session.** §5.2 rule 7 asks for a remembered allowlist, and
  the app stores nothing (the release audit enforces it), so the list cannot exist. Every
  chain id is confirmed by name in the session that signs for it — stricter than the rule,
  and recorded in §5.3 rather than quietly relaxed.
* **The pairing manifest is required to sign.** A card provisioned before manifests existed
  cannot sign, because the app would have no way to tell which account it was paired with.
  Re-provisioning is the remedy, and the error says so.
* **`VERIFY PW1` and `PSO:CDS` are one operation.** VERIFY state belongs to a card session
  and an NFC session lasts about a minute. Exposing them as two `SignerCard` calls would
  pass against a card that keeps state in memory and fail on hardware with `6982`, so the
  protocol has `sign(digest:userPIN:)`, the simulated transport now *forgets* verification
  at a session boundary, and a test asserts both.
* **libsecp256k1's recovery module is compiled in.** Determining `v` requires recovering a
  public key from a signature, which the base module cannot do. One upstream file
  (`src/modules/recovery/main_impl.h`, byte-identical to v0.8.0, hash recorded in
  VENDORED.txt) is vendored and `ENABLE_MODULE_RECOVERY` is defined. The module also
  compiles a secret-key signing entry point; the Swift wrapper exposes no signing call, and
  `tools/audit-release.sh` now asserts that positively, alongside the assertion that
  recovery really is compiled in.
* **The DEBUG simulated card returns a real signature.** The app verifies what the card
  returns, so a fake signature cannot complete the flow — which is the point of the
  verification and also the reason the UI test needs a genuine one. `tools/derive` signs the
  digest with the key the *simulated* app is provisioned with (the 256-bit all-zero BIP39
  vector, whose key is secret to nobody) and generates
  `Sources/YubikeyKitMock/SimulatedSigningVectors.swift`, which `tools/verify.sh`
  regenerates and diffs. Writing that generator produced one of those silent mistakes worth
  recording: the twelve-word "abandon…about" vector is 128-bit entropy, while the UI tests
  pass **32** zero bytes, i.e. the twenty-four-word "abandon…art" vector — a different key.
  A unit test now asserts the generated key against the derivation the app performs, so the
  two cannot drift again.

**Also changed:** the app has a front door (`HomeView`) with two routes, because
provisioning and signing are separate flows with separate state; the camera became an input
channel (`NSCameraUsageDescription`), and the README's "air-gapped" claim is now
"air-gapped in the sense that matters: no network, no persistence, and the only inputs are
the camera and the card".

## 22. v0.2: the chain name is a label, not a gate — and Polygon is not Ethereum

**Sections:** §5.3 (new chain-naming paragraph), §5.2 rule 7.

**What was wrong.** Every value and every fee on the confirmation screen was formatted with
a literal `ETH`, and the record screen did the same. So a Polygon transaction was displayed
as `1.5 ETH` when the operator was approving 1.5 **POL**: every byte of the transaction was
correct, and the one number the screen exists to communicate was denominated in the wrong
asset. The chain itself was also only ever shown as a bare id, so the confirmation prompt
that §5.2 rule 7 makes the operator answer ("confirm the chain id explicitly") asked them to
remember what `137` means. Both are the same class of defect as the pairing-screen bug in
amendment 20: the machinery was right and the *screen* said something untrue.

There was nothing to add on the signing side. Polygon needed no protocol work — its id is
treated like any other, `chainId·2 + 35 + recid` already widens the recovery value for ids
above 110 (`testWideRecoveryValueOnPolygon`), and an EIP-1559 transaction on 137 is an
ordinary 65-byte signature. "Support for POL" was a statement about the screens.

**What changed.** A chain table (`VaultKit/Signing/EVMChain.swift`: id → name + native coin
ticker) and the screens read it:

* the summary's value and fee rows say `1.5 POL`, and the chain row says
  `Polygon (chain id 137)`;
* the chain confirmation prompt names the chain and its coin
  (`Polygon (chain id 137), native token POL`), and the refusal to sign until it is
  confirmed uses the same wording;
* the signing record's chain and value rows are composed **in the library**
  (`SigningReport.chainDisplay`, `nativeValueDisplay`) rather than by the view, because a
  view that appends its own unit is exactly what produced the bug. The record derives the
  name from `chainID`, so the two cannot drift.

**Two rules, and a test for each.**

1. **The table is a display convenience, never a gate.** Nothing on the signing path reads
   it. A chain id nobody has heard of is confirmed and signed exactly like a named one:
   `testAnUnknownChainIDIsStillSignable` signs a request on chain 424242 end to end, so
   turning the table into a whitelist fails a test rather than silently refusing a
   legitimate network. The number is always on screen, because the check that matters is
   the id against the wallet's own screen.
2. **An unknown chain gets no symbol rather than a default.** `EVMChain(id: 424242)` has no
   name and no ticker, its amounts read `2 native`, and its row reads
   `chain id 424242 (not a chain this app knows)`. Defaulting to ETH is the bug; the fix is
   to say less, which is the same principle as the card layer's "an unclassified failure is
   not a retry" (amendment 15).

**Evidence.** VaultKit 217 → 231: 12 tests in `EVMChainTests` (Polygon's name and ticker;
L2s that correctly say ETH; an unknown chain with no name, no symbol and no "ETH" anywhere
in its rows; a transaction with no chain id; the table's internal consistency, which catches
an entry filed under the wrong id; the record's two rows; the confirmation message), plus
`testSignsAPolygonTransactionEndToEnd` (a real EIP-1559 POL transaction through the whole
ceremony, with the card's genuine signature from `tools/derive`) and
`testAnUnknownChainIDIsStillSignable`.

**One thing that surfaced while writing those tests.** `tools/derive`'s fixture generator
emits `s` as the raw RFC6979 value and `high_s` as `n - s`, which are "this one" and "the
other one" rather than "low" and "high" — for some digests the raw value is already ≥ n/2.
Two of the new vectors are like that, so the *ordinary* Polygon path also exercises EIP-2
normalisation and exports the flipped recovery value. The assertion that caught this was
mine being wrong, not the app's; the vector is left uncanonicalised on purpose, because that
coverage is worth more than a tidier fixture, and the generator now says so.

## 23. v0.2: the scanner's state outlived its camera

**Sections:** §5.1 (new paragraph on the scanner's lifecycle), §5.2 rule 8 (applied to it).

**The report.** "Tap *Read the YubiKey*, the camera opens, tap *Cancel*, come back — and the
camera never comes back."

**The cause.** `QRScanModel.stop()` stopped the capture session but left `state == .scanning`,
and `start()` treated `scanning` as proof that the camera was already running:

```swift
switch state {
case .received, .failed, .scanning: return   // ← the second visit stopped here
case .idle: break
}
```

So the claim "the camera is on" outlived the camera. It was wrong in three separate paths,
all of which end in the same symptom, and all of which the operator can reach:

* **Cancel** — `SigningViewModel.abort()` called `scan.stop()`, which stopped the session and
  left the state claiming it was still on. The next visit did nothing at all.
* **Backgrounding** — `applicationDidBackground()` did the same, and nothing restarted the
  camera on the way back, so returning to the scanner showed a preview of nothing.
* **A stale request** — `abort()` never cleared what the decoder had read, so a request
  decoded during the previous visit stayed in `.received` and would have been carried into
  the next one (this is amendment 20's rule again, one layer out from the ceremony: a flow
  inherits nothing from the previous run).

A fourth, smaller contributor: `configureIfNeeded()` set `isConfigured = true` *before*
checking whether a camera existed, so a failed configuration was cached — the second attempt
would claim `scanning` with no input attached, i.e. a dark preview with no explanation, and
would not report the reason again.

**The fix.** The lifecycle rules moved into a pure type, `VaultKit.QRScanSession`, for the
same reason `NFCSessionPolicy` lives in YubikeyKit: a camera is needed to *see* this failure,
but not to notice it, and a rule that can only be checked while holding a phone is a rule
that breaks again. The type makes the invariant explicit — `scanning` *is* a claim that the
camera is on, so a cancel withdraws it (`suspend()` → `.idle`), while a result or a failure
stays on screen; `begin()` is what says whether a start is meaningful, and `reset()` is what
makes a second attempt possible at all. `QRScanModel` is now the AVFoundation shell:
capture session, fountain decoder, counters, plus the camera's transitions **serialised**
through one task chain, because a cancel immediately followed by re-entry could otherwise
interleave `stopRunning` with `startRunning` and have the second start skipped as "already
running" — the same dark preview, from a race rather than from a lie. Cancel now calls
`scan.reset()`, the app restarts the camera when it returns to the foreground with the
scanner on screen, and a failed configuration is no longer cached.

**Evidence.** `QRScanSessionTests` (8 tests): the reported sequence run five times over
(begin → suspend → begin), the background/foreground pair, that a second `begin()` while
scanning is refused, that a result and a failure each survive a cancel but not a reset, and
that a reset forgets the previous visit's request. The tests were confirmed to fail without
the rule — neutering `suspend()` produces 12 failures. VaultKit 231 → 239.

**What is *not* covered, and why.** The UI suite cannot see this bug: a simulator has no
camera, so the first visit already ends in `failed("No camera is available on this device.")`,
and with the bug the second visit shows the same stale banner. A UI test that passed either
way would be decoration, so none was added and the visible behaviour is a hardware item
instead — docs/m0-hardware-verification.md item 15.

**One line of honesty while in there.** The scanner's `.idle` label read "Starting the
camera…", which is not what `.idle` means (it means the camera is not running — it is also
the state of the screen *behind* the card-read step, which briefly shows the same view). It
now says "Camera is off".

## 24. v0.2: the scan was never handed to anything

**Sections:** §5.1 (new paragraph on the handoff).

**The report.** Scan a MetaMask QR code, the screen says "Read a eth-sign-request" — and then
nothing. No error, no next screen.

**The cause.** `SigningViewModel.acceptScannedRequest()` existed, was documented as "called by
the scanner", and **was called by nobody**. The scanner decoded the request and published
`.received`; `ScanningView` rendered that state ("Read a eth-sign-request"); and no code
anywhere subscribed to it, so the decoded request sat in the scanner's state while the flow
waited for something to happen. The camera path ended there.

**Why no test saw it.** The DEBUG sample button called `viewModel.accept(ur)` directly — a
second door into the ceremony that skipped the scanner entirely. The UI test drove that door,
so it walked the whole flow green while the door a real operator uses was wired to nothing.
This is amendment 20's lesson in its sharpest form: the test asserted the *ceremony's* state,
and what was broken was the path *into* it. The two doors are the defect; the missing
subscription is what they hid.

**The fix.** The scanner reports a decoded request through a callback
(`QRScanModel.onRequest`) that the signing flow installs in its `init`, so the handoff lives
where the decode happens and is set for the model's lifetime rather than depending on a view
being present and re-evaluated. `acceptScannedRequest()` is gone — there is now exactly one
entry point, `accept(_:)`, on both routes. The DEBUG button was changed to feed its sample
**through the scanner's decoder** (`scan.receive(payload)` as a UR string) instead of jumping
to the ceremony, so the sample now walks the same path as the camera and cannot bypass a step
again.

**A second dead end in the same path, fixed while there.** When the ceremony refused a request
before any approval (in practice: a sibling account's request, the one case §4.3 says will
happen), the error was reported but the scanner kept the refused request — and `.received` is
not a startable state, so the camera would not come back and the only way forward was Cancel,
which no message says. A refusal now resets the scanner and starts it again, leaving the error
on screen and the camera live for the next code.

**Evidence.** The UI test now fails without the handoff: with `onRequest?(ur)` removed it stops
at the assertion after the sample request (`SigningFlowUITests.swift:66`), where before this
change it passed with the handoff missing entirely. Both runs were performed: 191 s passing,
185 s failing. That is the regression test for this bug, and it only exists because the DEBUG
route was made to enter at the same door. The remaining camera-specific behaviour — that the
`AVCaptureMetadataOutput` delegate hop and the callback actually fire on a device — is item 16
in docs/m0-hardware-verification.md.

## 25. v0.2: nothing could read a real request, and the tests all passed

**Sections:** §5.3 (the wire format).

**The report.** Scan a MetaMask QR code and the app refuses it with a message about messages
and EIP-712: *"The request asks for the QR code carries the signing-request type name but the
CBOR tag 0, which is not the tag a wallet uses… This app signs transactions only; it does not
sign messages or EIP-712 typed data."* Every clause of that is wrong about what happened.

**Two defects, and the second is why the first was unreadable.**

1. **The decoder required an outer CBOR tag that no wallet emits.** `EthSignRequest.init(cbor:)`
   began `guard let tagged = cbor.taggedValue, tagged.tag == 401`, and threw
   `.wrongTag(found: 0)` for an untagged map — `0` being a hole where the tag would be, not a
   tag. ERC-4527 assigns these types tags, but the type name travels in the UR
   (`ur:eth-sign-request/…`) and the payload is a bare map. Measured against
   `@keystonehq/bc-ur-registry-eth` 0.22.1, `EthSignRequest.constructETHRequest(…).toUR().cbor`
   begins `0xa5`, and a signature's begins `0xa3`; `0xd9` (a CBOR tag header) never appears.
2. **A parse failure was reported as a policy refusal.** `SigningCeremony.accept` wrapped *any*
   `EthSignRequestError` into `SigningError.unsupportedDataType(...)`, whose text is about this
   app not signing messages or EIP-712. So the operator — and the person they reported it to —
   was told the request was the wrong *kind* when in fact it could not be *read*. There is now a
   separate case, `requestNotReadable`, carrying the parser's own words.

**Why no test noticed, which is the part worth keeping.** Both directions were wrong in the same
way: the app's encoder wrote tag 401/402, the app's decoder required it, and the round trip —
including the DEBUG sample that drives the whole UI suite — was perfectly self-consistent. Every
fixture was the app's own output. A second, independent implementation is the only thing that
finds this, which is what `tools/interop/gen-eth-ur-fixture.cjs` now provides: it encodes a
request and a signature with the library MetaMask itself uses, records the bytes and the library
versions, and both are committed. `EthURReferenceTests` then checks the app against them in both
directions:

* it decodes the reference's request UR (the reported bug, as a test) and a whole ceremony signs
  it — its payload hashes to the digest `tools/derive` signed for `fee_market_chain_137`, so this
  is a real signature over a wallet-shaped request;
* the app's encoder produces the reference's bytes exactly, for both the request and the
  signature, so the DEBUG sample can no longer exercise a shape no wallet sends;
* a wrong tag is still refused, and the expected tag is still tolerated.

While writing the fixture it caught its own first draft: the hand-written payload in the
generator said chain 1 and 1 ETH while the fixture claimed chain 137 and 1.5 POL, and the new
decode test failed on the inconsistency. That is the difference a fixture from somewhere else
makes.

**Evidence.** Restoring the tag requirement fails four tests, including
`testSignsARequestEncodedByTheReferenceImplementation` with the operator-visible string above —
the reported symptom reproduced in a test rather than described. VaultKit 239 → 247.

**What is still only a wallet's word.** That MetaMask accepts the signature the app produces. The
bytes now match its own library's, and the wallet's reader is quoted in the test
(`ETHSignature.fromCBOR`, which throws "Signature request ID is missing" without field 1), but a
real wallet is still docs/m0-hardware-verification.md item 14.

## 26. v0.2: the provisioning ceremony wrote a policy the applet threw away

**Sections:** §4.2 (steps 3 and 6), §5.2 (rule 7d), §6.5 (the UIF and Ed25519 rows).

**The report.** "This YubiKey was provisioned by the app, and the touch policy is wrong."
`ykman openpgp info`-equivalent reads of the card showed `UIF = 00 20` — **touch off** — on
both signing-capable slots, on a card whose private-use object held this app's 198-byte v2
pairing manifest and whose `0xC4[0]` was `0x00`. Three of those four facts are produced by the
ceremony; only the touch policy disagreed.

**Two defects, both in the same step, both silent.**

1. **The policy was applied before the key import, and the import discards it.** Writing a
   slot's algorithm attributes resets that slot, and the applet drops the slot's touch policy
   with it. Measured on the YubiKey 5C NFC in hand (firmware 5.8.0, applet 3.4), replaying the
   ceremony's own APDUs:

   | Step | `0xD6` (signature) after it |
   | --- | --- |
   | reset (`TERMINATE DF` + `ACTIVATE FILE`) | `00 20` (factory) |
   | `PUT DATA 0xD6 = 02 20` | `02 20` ✓ |
   | `PUT DATA 0xC1 = ECDSA/secp256k1` (algorithm attributes) | **`00 20`** |
   | key upload, fingerprint `0xC7`, generation time `0xCE` | `00 20` |
   | `PUT DATA 0xD6 = 02 20` **again**, after the import | `02 20` ✓, and it survives every later write (fingerprint, generation time, the manifest object, `0xC4`) |

   The same interaction is reported for `gpg keytocard` in Yubico's own tracker
   (yubikey-manager#693: "openpgp touch policy is reset to OFF" after `keytocard`). Note what
   did *not* move: the PW1 status byte (`0xC4[0] = 0x00`, written by the same step, moments
   earlier) survived the import — which is why the card looked configured and why the
   contradiction was invisible.
2. ~~**The Ed25519 algorithm attributes were the wrong OID.** The app wrote GnuPG's OID for
   Ed25519 (1.3.6.1.4.1.11591.15.1). This firmware rejects it with `6A80` and accepts RFC
   8410's `id-Ed25519` (1.3.101.112, `2B 65 70`). The authentication slot's key therefore
   could not be imported at all.~~ **RETRACTED — this was wrong, and acting on it shipped a
   regression. See amendment 29.** The GnuPG OID is the correct one (it is what `yubikit` sends
   and what this firmware accepts); RFC 8410's is refused with `6A80`. The "evidence" below was
   an APDU of mine that declared `Lc = 05` while carrying four bytes, whose `9000` was a
   truncated card session rather than an accepted write. Item 1 of this amendment — the touch
   policy — is unaffected and was reproduced repeatedly.

**Why no test noticed.** The simulated card stored whatever it was given and never modelled the
key-slot reset, so `applyPolicy` followed by `importKey` looked exactly like `importKey`
followed by `applyPolicy`. Every write answered `9000`. This is the same shape as amendment 25:
a self-consistent model (there, an encoder and a decoder; here, an applet model and the app)
agrees with itself while disagreeing with the device.

**The fixes.**

* The policy is applied **after** the key import (`CeremonyMode.path` puts `.policy` between
  `.readBackCheck` and `.pairingManifest`), because the algorithm attributes write is a
  key-slot reset and the policy must be the last thing that touches those slots.
* The policy step **reads both policies back** (`0x6E` carries `0xD6`/`0xD8`, with no extra
  round trip and no PIN) and fails the ceremony with `CeremonyError.policyNotApplied` unless the
  card reports `02 20` on both slots and `0xC4[0] = 0x00`. `CeremonyReport.touchPolicyVerified`
  records that it was checked, and is only ever set from the card's own answer.
* The Ed25519 attributes now carry RFC 8410's OID, which is also what the simulated card
  requires — the mock compares the attributes byte-for-byte, so writing the GnuPG OID fails a
  test instead of a provisioning run.
* The simulated card now models the key-slot reset (an algorithm-attributes write drops that
  slot's UIF) and a factory-fresh applet's `0xC4[0] = 0x01`, and can be told to answer `9000`
  to a UIF write while storing nothing (`uifWritesAreIgnored`), which is the failure the
  read-back exists to catch.

**Evidence.** Reordering the path back (policy before the import) fails
`testThePolicyStepComesAfterTheKeyImport`; removing the read-back fails
`testAPolicyTheCardDoesNotReportBackFailsTheCeremony` with "expected an error to be thrown" and
the step advanced to `pairingManifest` anyway. With the fixes, VaultKit 247 → 249 and YubikeyKit
78 → 81.

**What is still only a card's word.** Both fixes were found by replaying APDUs from a desktop
probe, not by the app driving the card over its own transport. The app must be run end to end
against the real YubiKey once and the card then read back
(docs/m0-hardware-verification.md item 18) — that is what turns "the APDUs are right" into "the
app provisions correctly".

## 27. v0.2: the PIN retry limit becomes a decision, not a default

**Sections:** §4.2 (step 3), §6.5, §9.

**What changed.** Provisioning left the card's factory retry limit in place — three wrong entries
per password — and never said so. The ceremony now has a step of its own for it: the operator
chooses between **3 and 10**, the app writes that limit for all three passwords with
`SET PIN RETRIES` (`00 F2 00 00 03 <PW1> <reset code> <PW3>`, PW3 verified in the same session,
firmware ≥ 4.3.1), reads the counters back out of `0xC4`, and refuses to continue unless the card
reports what it asked for. `CeremonyReport.pinRetryLimit` records the choice, and the policy step
re-reads the counters later, so a limit that something else resets during the run is caught before
any pairing code exists.

**Why it is a decision and not a default.** The same number is two opposite things. It is the
brute-force budget for a 6-digit PIN — the only thing standing between a stolen card and its key
(§9) — and it is how many typos stand between the operator and a blocked card. Leaving it
implicit meant the operator got whichever of those the factory chose without being told.

**What the number costs, stated on the step rather than in a footnote:**

* **Exhausting the User PIN** blocks every signature until the PIN is unblocked. Unblocking needs
  `RESET RETRY COUNTER` with the Admin PIN — which this version does not implement — so in
  practice the card is set up again from the 24 words, which erases both keys. (The old error text
  said "terminate and re-activate the OpenPGP applet to recover", which is not a recovery:
  `TERMINATE DF` destroys the keys, and the app now says so.)
* **Exhausting the Admin PIN** ends provisioning and re-pairing for that card. The card is not a
  brick: the applet permits `TERMINATE DF` when PW3 is blocked (spec 3.4.1, access conditions;
  `ykman openpgp reset` relies on the same path and takes no Admin PIN), so a full reset is still
  possible — and it erases both keys. The previous text claimed the card "can no longer be
  provisioned", which was wrong in the direction that matters least, but wrong.
* Either way the funds survive if the 24 words do; the *card* has to be set up again from them.

**Two facts measured on hardware, not assumed** (YubiKey 5C NFC, firmware 5.8.0):
`00 F2 00 00 00` answers `6982` — the instruction exists and waits for PW3, it is not `6D00`; and
`C4` reads seven bytes `00 7F 7F 7F 03 00 03` on a fresh card, i.e. the resetting code (never set
by this app) reports **0** attempts while PW1 and PW3 report 3. The read-back therefore asserts
PW1 and PW3 only, and the step says the resetting code is not set rather than implying it is.

**Why not let the app unblock a blocked PIN.** Because the honest fix for "I am afraid of typos"
is not a longer retry budget; it is the unblock path (`RESET RETRY COUNTER`). That is a signing-side
feature — the card is blocked, the operator has the Admin PIN, and the PIN has to be replaced — and
it is not in this version. Recorded here rather than half-built: docs/m0-hardware-verification.md
item 19.

**Evidence.** Reverting each part fails its test: dropping the read-back fails
`testRetryLimitsTheCardDoesNotApplyFailTheCeremony`, widening the offered range fails
`testARetryLimitOutsideTheOfferedRangeIsRefused`, and dropping the later re-check fails
`testTheReadBackStepRechecksTheRetryLimits`. The APDU itself is pinned byte-for-byte
(`00f2000003 040404 00`) and the UI walk now chooses 4 through the picker, so the number really
travels. VaultKit 249 → 253, YubikeyKit 81 → 83.

**Later (amendment 32).** The number became two — one per password, chosen independently — and the
read-back that re-checks them moved with the rest of the policy check into the read-back step. This
amendment's reasoning about the consequences is unchanged; only the count of numbers is.

## 28. v0.2: the app cannot reset a card whose Admin PIN is blocked

**Sections:** §4.2 (steps 2 and 3), §6.5. Measured on hardware, recorded in
docs/m0-hardware-verification.md item 20.

**What was measured.** The card's Admin PIN was blocked during hardware probing (a malformed
`CHANGE REFERENCE DATA` in a probe script, not the app — the script now aborts on the first failed
VERIFY, and the episode is written up as a trap). That state turned out to be useful: with
`C4 = 01 7F 7F 7F 03 00 00`, every `VERIFY PW3` answering `6983`, a bare
`TERMINATE DF` + `ACTIVATE FILE` **without any VERIFY** reset the applet and returned the PINs to
their factory values. Spec 3.4.1 says why ("TERMINATE DF: VERIFY of PW3 or Always if PW3 is
blocked"), and `ykman openpgp reset` is built on the same clause — it takes no Admin PIN at all.

**The gap this exposes.** The app's reset step is `SignerCard.reset(adminPIN:)`: it verifies PW3 and
then terminates. On a card whose Admin PIN is blocked that verification fails, the reset never
happens, and the operator is told `pinBlocked`. So the one state in which the applet deliberately
lowers the barrier is the one state in which this app cannot use it — and the app is the tool the
operator is holding when it happens.

**Not fixed here, deliberately.** Sending `TERMINATE DF` without a PIN is a destructive path that
erases both private keys, and it is only *safe* because the applet restricts it to the blocked-PW3
state. Offering it in the app means offering "erase this card" as a recovery, which belongs
together with the PIN-unblock feature of amendment 27: the pair is what turns a blocked PIN from a
re-provisioning into a repair. Both are recorded in m0 item 19 rather than half-built. What changed
now is only the wording:

* the blocked-Admin-PIN message no longer claims the card "can no longer be provisioned" — it says
  what is true, that the applet can still be reset (by a tool that does not need PW3) and that this
  erases both keys;
* the blocked-User-PIN message no longer recommends "terminate and re-activate", which destroys the
  keys rather than recovering them;
* the retry-limit step says the same thing in the operator's words before they choose a number.

**Fixed later.** Amendment 30 (§4.2 step 2) closes this gap by adopting the reference
implementation's route — block PW1 and PW3, then terminate — so the blocked-PW3 state is no longer
the state the app cannot use. The reasoning above about *where* a no-PIN reset belongs turned out to
be half right: it belongs with the PIN-unblock feature only if it is offered as a *recovery* for a
blocked PIN. As the reset step's own implementation it needs nothing else, because that step
already erases the keys and re-provisioning is what follows it.

**Also measured, and now recorded so nobody re-derives it:** a fresh applet reports
`01 7F 7F 7F 03 00 03`; `SET PIN RETRIES 5 5 5` reads back `05 00 05` and survives the key import;
importing a key clears that slot's touch policy (reproduced four times); and the EC private-key
template needs **no** public key — yubikit's optional `0x99` component is not required by this
firmware, which accepts the `92`-only form our code sends.

## 29. v0.2: a wrong Ed25519 OID shipped, on the strength of a broken probe

**Sections:** §4.2 (step 6), §6.5. Corrects amendment 26 item 2. Measured on the operator's own
YubiKey, in the app, which is how it was caught.

**What happened.** Amendment 26 claimed the app's Ed25519 algorithm attributes were wrong, and
changed them from GnuPG's OID (1.3.6.1.4.1.11591.15.1) to RFC 8410's `id-Ed25519` (1.3.101.112).
The operator then provisioned a real card and the app failed at **Import keys into YubiKey**:

> This YubiKey's OpenPGP applet does not support the requested algorithm. Firmware 5.2.3 or newer
> is required.

`ykman` showed the signature slot written and the authentication slot empty — and no touch policy,
because the ceremony had stopped *before* the policy step (which now runs after the import). One
wrong constant, three symptoms.

**The correct value is the one the app had all along.** `yubikit.openpgp` is what `ykman openpgp
keys import` uses on real YubiKeys:

```python
OID.Ed25519 = 1.3.6.1.4.1.11591.15.1          # GnuPG's OID, not RFC 8410's
if oid == OID.Ed25519: alg = 0x16             # EdDSA
__bytes__ = pack(">B", alg) + self.oid         # and no format byte: STANDARD means "not present"
```

Those are exactly the bytes amendment 26 removed. Reverted, and the bytes are now pinned by a test
to the reference implementation rather than to any measurement of mine.

**How the mistake got made, because the shape of it will recur.** The claim rested on two hand-typed
APDUs sent through `gpg-connect-agent`:

```
00 DA 00 C3 05 16 2B 65 70        <- declared Lc = 05, carried four bytes
00 DA 00 C3 09 16 2B 06 01 04 01 DA 47 0F 01
```

The first is malformed, and the `9000` it "returned" was not a card response at all: raw APDU bursts
wedge `scdaemon`, and a wedged session yields a *truncated* status-word list — here, the VERIFY's
`9000` with the write's answer missing. I read the first line as "RFC 8410 accepted", when the lines
together say "the second command never ran". The GnuPG OID's `6A80` in the same run was equally
untrustworthy, because the card had been left in an unknown state by the wedges (item 20 records
that a half-written slot answers `6A80` to a re-import).

**The rule this produced, now in docs/m0-hardware-verification.md item 20:** a bare status word is
not evidence. A write is verified by *reading the object back*, and a claim about a wire format is
preferred from the reference implementation over any probe of mine until the card itself contradicts
it with a read-back. Amendment 26's touch-policy finding passes that test (it was reproduced four
times, each time verified by reading `0xD6`/`0xD8` back); its Ed25519 finding did not.

**Two failures of the app's own making, fixed in the same change:**

* **The error blamed the firmware.** A refused attributes object was reported as "unsupported
  firmware… 5.2.3 or newer", which on a 5.8.0 card sends the operator looking for an upgrade they
  cannot install and hides the real cause. `CardError.algorithmAttributesRejected(algorithm:slot:)`
  now names what was refused and says that a newer card means an app bug.
* **A half-provisioned card invited a retry that cannot work.** Keys are imported one slot at a
  time, so a failure on the second leaves the first holding a key — and the applet refuses a key
  into an occupied slot. The ceremony now re-inspects the card, reports
  `importLeftTheCardPartlyProvisioned`, and sends the operator back to the inspection step with the
  reset named as the way forward. Before this, the same error repeated with no way out; the operator
  in this incident had to work out from `ykman` that the card needed a reset.

**Verified.** The mock refuses any attributes object that is not the exact one the firmware accepts,
so the reverted OID is a passing test and RFC 8410's is a failing one
(`testTheWrongEd25519AlgorithmAttributesAreRefused`); the named error and the partly-provisioned path
have their own tests (`testARefusedAttributesObjectNamesTheAlgorithmAndSlot`,
`testAFailedImportLeavesTheCardPartlyProvisionedAndSaysSo`,
`testAnImportThatWroteNothingReportsItsOwnError`). VaultKit 253 → 255, YubikeyKit 83 → 85.

**Still owed to hardware:** one provisioning run on the real card with the reverted OID, which the
operator can now do after resetting the applet. If `0xC3` is refused *again* with the GnuPG OID, then
the OID is not the whole story on this firmware and the next step is a read-back-verified probe of
the candidate forms (item 20), not another edit.

## 30. v0.2: the reset needs no Admin PIN, because the applet already offers that route

**Sections:** §4.2 (step 2), §6.5, §8.4. Supersedes the "not fixed, deliberately" half of amendment
28; the card behaviour behind it is recorded in docs/m0-hardware-verification.md item 20.

**What changed.** `SignerCard.reset(adminPIN:)` became `reset()`. The step no longer asks for the
Admin PIN; it mirrors `ykman openpgp reset` command for command — `GET DATA 0xC4`, then wrong
`VERIFY`s until PW1 and PW3 are blocked, `GET DATA 0xC4` again to confirm, `TERMINATE DF`,
`ACTIVATE FILE`, re-SELECT — and it refuses to continue if the counters read back non-zero rather
than terminating anyway. The sequence is pinned by `testResetBurnsBothPINCountersThenTerminates`,
`testResetWorksWhenTheAdminPINIsAlreadyBlocked` and `testResetReportsCountersThatWouldNotBlock`; the
mock now refuses `TERMINATE DF` unless PW3 is verified *or* its counter is spent, so the rule the
real card enforces is enforced in the tests too, and `CardError.pinBlockingIncomplete` names the
case where the burn silently did nothing.

**Why the PIN had to go.** The old step verified PW3 and then terminated. Because the applet's
access condition is "VERIFY of PW3, **or Always if PW3 is blocked**", that call could not reset the
one card that most needs resetting — the card whose Admin PIN is blocked or unknown — and the
operator holding the app was told `pinBlocked` and sent to a desktop tool. It also asked for a
credential the reset was about to destroy, which teaches the wrong thing: the Admin PIN is not what
authorises the erasure, and collecting it implies the erasure depends on it.

**What was rejected.** "Try `TERMINATE DF` first, fall back to the burn only on `6982`." It is fewer
APDUs on a card whose PW3 is already blocked, and it is the reading the spec's wording invites. It
was rejected because it splits one operation into two paths that differ in *what the card is left
in* when the session dies: the bare-terminate path can strand a terminated-but-unactivated applet
without having told the operator why the card is unusable, and the fallback's trigger (`6982`) is
the same status word an unverified *write* returns, so misreading it would turn a refusal into a
wipe. One path, the one the reference implementation uses on real cards, is the one that can be
reasoned about.

**What it costs, and where that is said.** The reset now *begins* by making the card unusable:
after the burn and before the terminate, both PINs are blocked and the keys are still there. A drop
in that window is recoverable — finishing needs no PIN, because a blocked PW3 is exactly what
`TERMINATE DF` wants — but it needs another tap, and the ceremony therefore returns to inspection on
**any** reset failure instead of treating one as impossible (`resetCard` no longer rewinds through
`withMutatingStep`). The reset step states the cost before the tap, the destructive-acknowledgement
toggle is unchanged, and the PIN step's warning now says what the consequence actually is: a blocked
Admin PIN no longer ends the card's life, it ends *this* provisioning run.

**What this does not fix.** A blocked **User PIN** is still unblockable only by re-provisioning from
the mnemonic: `RESET RETRY COUNTER` (INS `0x2C`) remains unimplemented, and it is the other half of
the repair story in m0 item 19. And the burn is only *safe* because the applet restricts a
no-VERIFY `TERMINATE DF` to the blocked-PW3 state; the app relies on that restriction rather than
re-checking it, which is why the `0xC4` read-back is part of the sequence and not a nicety.

**Verified off-hardware.** The APDU order, the blocked-PW3 path, the read-back failure and the
ceremony's reaction to a reset that fails are all tested; VaultKit 255 (unchanged), YubikeyKit
85 → 88. **Owed to hardware:** the four checks added to m0 item 20 — a reset on a card whose Admin
PIN works, one on a card whose Admin PIN is blocked, a reset interrupted between the burn and the
terminate and finished by a second tap, and the factory PINs and empty slots afterwards.

## 31. v0.2: the card connection is chosen once, and it is the one thing the app remembers

**Sections:** §4.2 (step 1), §5.2 (rule 7), §9.5. Changes check 3 of `tools/audit-release.sh` and the
persistence row of `docs/v1-threat-notes.md`.

**What changed.** NFC / USB-C / Simulated used to be offered *inside* each flow — a "Transport"
section on the provisioning setup screen, a "Card connection" section on the signing one — with the
value held by each view model. Both pickers are gone, and nothing inside either flow echoes the
choice: the connection is asked once, on a device screen that now stands in front of the app on
first launch, stored, and changed from a single place — a drawn YubiKey button in the home screen's
top-right corner, whose badge names the connection and whose colour reports whether the key is
plugged in. Picking a row on the device screen stores it immediately, so there is no save step that
can disagree with the row.

**The button says more than the old summary did.** Its body is the key (a rounded rectangle with
the touch button on it — there is no YubiKey symbol to borrow) and its corner badge is the
connection, so the app's reader is one glance away rather than one screen down. On USB-C the colour
becomes the presence signal: `TKSmartCardSlot.state == .validCard` means the key is in the slot, and
the icon goes green; `null` (NFC cannot be sensed passively, and the simulated card is always there)
leaves it in the normal tint rather than claiming to know. The poll is two seconds, opens no session,
and runs only while USB-C is the chosen connection and the home screen is in front — the same
polling, for the same reason, as the transport's own discovery (m0 item 4 now carries the hardware
check for it).

**Why the pickers had to go.** The connection is a property of the phone and its reader, not of a
ceremony: it does not change between provisioning and signing, or between two signatures. Two
pickers were therefore two sources of truth for one value — and the one place that value could be
changed *while a ceremony was running*, which is how a step ends up talking to a card the operator
is not holding. The value now has one owner, `DeviceChoiceStore`; both view models read it
(`transportChoice` is derived, not stored) and neither flow can write it.

**The persistence exception, stated rather than slipped in.** This is the first thing the app
stores. The audit used to fail the build on *any* persistence API in the app or the ceremony layer,
and the threat notes claimed the app writes nothing anywhere. Both are now narrowly different, and
the audit was tightened rather than loosened:

* the grep still fails on every persistence API except one named file, `Support/DeviceChoiceStore.swift`;
* that file is positively asserted to exist, to name the expected key, to touch no other key, and to
  reach for neither the keychain nor the filesystem — so deleting it turns the check red instead of
  green;
* the UI-test hooks (`-device-choice`, `-reset-device-choice`) exist only in DEBUG, in the same
  spirit as `-deterministic-entropy`.

**What is stored, and why it cannot weaken anything.** One key, one of three strings: the connection's
raw value. That selects a *channel*, not a policy — both real values reach the same card through the
same gates, and check 1 of the audit asserts a release build has no simulated transport to be pointed
at. A stored `"simulated"` (left by a debug build) is therefore not a value a release build
recognises: it is treated as no choice, and the app asks again rather than silently using a default.
A wrong or tampered value sends the operator to the wrong reader, which shows up at once as a card
that cannot be found. It is not secret, it is not key material, and deleting it costs one tap.

**What it deliberately still does not remember.** Not the card, not the wallet, not the pairing, not
a chain id, and nothing about any ceremony. `-deterministic-entropy`, the simulated card and every
other test hook remain DEBUG-only, and the app is still stateless in the sense §4.3 and §5.2 rule 8
mean: a fresh install can re-pair from the card alone.

**Verified.** `DeviceChoiceUITests` (5 tests): a first run asks and cannot be got past without an
answer, the choice survives a relaunch and a change *replaces* it, a choice made on that screen is
the one the ceremony then reads (behavioural proof, since no screen inside the flow echoes it), the
USB-C button reports the plug-in state, and the button is centred on the title line rather than
floating in a navigation bar above it. Every other UI test now seeds the connection at launch
(`launchApp(deviceChoice:)`) instead of tapping a picker, so the count went 9 → 15 and the walk
helpers no longer tap a transport at all. Packages unchanged (VaultKit 255, YubikeyKit 88). Release
build and `tools/audit-release.sh` pass with the narrowed check.


## 32. v0.2: the policy is written by the import, and the retry limits are two numbers

**Sections:** §4.2 (steps 3 and 7), §5.2 rule 7d, §6.5.

**What changed.**

* The **policy write moved into the key-import step.** There is no "apply policy" step any more:
  the import writes both keys and then the two UIF objects and the PW1 status, as the last write to
  those slots, and the read-back step confirms the keys **and** the policy in one pass.
* The **PIN retry limit became two independent numbers**, chosen per password on the retry step: the
  User PIN's limit and the Admin PIN's, both from the same offered range, both written and read back
  together.

**Why the policy step had to go rather than move.** It could not be *moved* where an operator asked
for it — before the PIN step, which is before the key import — because the applet discards a slot's
touch policy when that slot's algorithm attributes are written. That is not a theory: it was measured
on the card in hand, four times (amendment 26, m0 item 18). Moving the write earlier would have
produced a card that reports `9000` to every write and ends up with touch **off** while the operator
believes otherwise — the exact failure the read-back exists to catch — and moving the read-back with
it would have made the ceremony pass while the card stayed unprotected. What the operator actually
wanted was for the policy not to be its own movable screen, and that is what this does: with the
write inside the import, there is no ordering left to get wrong and no step to reorder. The
read-back step is now the single place where a provisioned card is admitted to be provisioned.

**Why two retry numbers.** The applet keeps one counter per password; the app was collapsing them
into one choice and telling the operator "this number is the brute-force budget for a 6-digit PIN".
That is only true of the User PIN. The Admin PIN is typed once per ceremony, not once per signature,
so the same number is not the right trade for both — and `ykman openpgp access set-retries` has taken
three numbers since it was written, for the same reason. The UI now asks twice.

`SET PIN RETRIES` takes all three counters in one command (`00 F2 00 00 03 <PW1> <reset code> <PW3>`),
so "separately" does not mean two commands: it means two inputs, one write, and a read-back that
asserts **both** counters. The resetting code's byte carries the User PIN's number and is inert —
this app never sets a resetting code, and the card reports 0 attempts for it whatever is sent
(measured: `03 00 03`).

The claim that `SET PIN RETRIES` leaves the PIN *values* alone on 4/5 came up while checking this, and
it is now sourced rather than asserted: Yubico's own library documents the PIN reset as NEO-only
(`yubikit.openpgp.set_pin_attempts`: "WARNING: On YubiKey NEO this will reset the PINs to their
default values"; the same sentence in YubiKit Android), and the ykneo-openpgp `PinRetries` page that
says otherwise is about applet 1.0.7 — the discontinued NEO applet, not the 3.4 applet on the cards
this app targets. m0 item 19 gained the check that would actually catch a difference on hardware:
re-verify PW3 with the operator's own Admin PIN *after* the retry write, which no probe has done,
because every probe so far used factory PINs — where a reset and a no-op are indistinguishable.

**The defect this uncovered, in a screen that has nothing to do with the YubiKey.** The report
screen's only way back to the home screen was the last item of a three-screen scroll, with the
"restart the app" note drawn *over it* as `.overlay(alignment: .bottom)`. Three extra rows of report
were enough to push the button under the note: the end-to-end re-pair UI test — which provisions a
card for real, then re-pairs it — reached the button, tapped it, and stayed on the screen, twice.
The fix is the pattern the rest of the app already uses: the action is pinned in a bottom bar
(`safeAreaInset`), with the note beneath it, so it is visible without scrolling and nothing overlaps
it. A primary action the operator has to scroll for is a primary action that can be missed.

**The same run also found a test that had been passing by luck.** That end-to-end test launched a
bare `XCUIApplication` with only `-deterministic-entropy`, so it inherited whichever connection the
previous test had left in the device-choice store — after `DeviceChoiceUITests`' USB-C case, a
ceremony pointed at a CCID reader that does not exist, and the inventory read produced nothing. It
was the one test not converted when the connection became a launch-time setting (amendment 31), and
the intermittent failure it produced had been recorded as flakiness; it is now seeded like its
sibling and deterministic.

**What did not change.** The policy itself: touch policy `Fixed` on both signing-capable slots, PW1
status `0x00`, both verified by read-back. The retry limits are still verified by read-back and
re-checked by the read-back step, which reports the card's own numbers. Nothing about the reset step,
the entropy, the mnemonic or the pairing path changed.

**Evidence.** Reverting each part fails its test. Dropping the policy write from the import fails
`testThePolicyIsWrittenAfterTheLastKeyImport` and the read-back's policy check
(`testAPolicyTheCardDoesNotReportBackFailsTheCeremony`, which now reaches the failure through
`verifyReadBack`); writing one number to both passwords fails
`testChosenRetryLimitsReachTheCardPerPIN` (it asserts the `F2` bytes are `04 04 06`) and
`testTheRetryLimitsAreChosenPerPINAndReadBack`; ignoring one of the two counters fails
`testTheReadBackStepRechecksTheRetryLimits`, which moves only the Admin PIN's counter and expects the
ceremony to stop. The UI walk raises the two pickers to different numbers, so a write that put one
number on both passwords fails the walk as well. VaultKit 255 (the count is unchanged: the tests were
reworked, not added to), YubikeyKit 88 → 88, UI 15. Release build and `tools/audit-release.sh` pass.

**Amendment 27's "the policy step re-reads the counters" is now "the read-back step re-reads them",
and its single number is now two.** Amendment 26's ordering rule is unchanged; where it used to say
"the policy step sits after the key import", it is now expressed by the import step itself writing
the policy last.

## 33. v0.2: the signing flow takes the request first, so it reads one key instead of two

**Sections:** §5.1 (sequence), `SigningStep`, `SignerCard`.

**What changed.** The signing flow's first step used to be reading the card, and the request was
scanned afterwards. It is now the other way round: the request is decoded first, and the card is read
second — **for the one slot the request names**.

**Why.** The old order read the card through `inventory()`, and an inventory probes *both* key slots:
detecting an occupied slot reliably means attempting a public-key read, because a fingerprint object
can be present and zero (that is the rule `OpenPGPCard.inventory()` documents, and the reason the
destructive reset is gated on its answer). So every signing session — for a transaction that can only
ever use one key — read both keys, plus the application data, the manifest and the counter, as four
separate `withSession` calls. On NFC each of those is a tap the operator pays for.

Scanning first removes the need. The request carries a derivation path, and this app provisions exactly
two fixed paths (`m/44'/0'/0'/0/0` → the signature slot, `m/44'/501'/0'/0'` → the authentication slot),
so the path says which key to read without asking the card anything:

* `SignerCard.readSigningIdentity(slot:)` is the new primitive: the serial, the manifest, **that slot's**
  public key and the signature counter, in **one** session. `inventory()` is untouched — it is the right
  answer to "what does this card hold", which is what provisioning and the destructive gate need.
* `SigningStep` is reordered to `requestDecoded → cardRead → requestVerified`, and the constructor
  `accept(requestUR:)` now runs before `readCard()`. The binding check (`verifyRequest`) still compares
  the request's path, master fingerprint and optional address against the card, and now runs after the
  card is read, which is where it always belonged.
* A request whose path is neither of the two this app provisions is refused **before the card is
  touched** (`SigningError.requestPathNotSignable`), so a request the app cannot serve costs no card
  operation at all. That includes this app's own Ed25519 path: the app reads and pairs that key but
  signs no Ed25519 request in this version, and the refusal now says so instead of reporting the card
  as lacking a key it actually holds.

**What was traded.** The account that will sign is no longer on screen *while* the request is decoded;
it appears one screen later, at the summary, which is where the operator has to compare it with the
wallet anyway. In exchange the read is one key and one session, and a request the app cannot serve is
refused without touching the card. The gates themselves are unchanged: the request is parsed and
re-encoded before any screen shows a number from it, the manifest must match the key the card reports,
and the binding check still runs before approval.

**Evidence.** `testTheSigningIdentityReadTouchesOneSlotOnly` (YubikeyKit, APDU-level) asserts the whole
pre-signing read is one session, with exactly one `GENERATE ASYMMETRIC KEY PAIR` and that it carries the
signature slot's control reference (`0xB6`) — with a key in the *other* slot, so a read of it would
succeed and leave no other trace. `testRequestForAnotherPathIsRefused` and
`testARequestForTheEd25519KeyIsRefusedBeforeTheCardIsRead` assert the refusals happen with
`card.calls.isEmpty`. The ceremony tests were reordered with the flow (`advanceToApproval` now accepts
before it reads), and the signing UI walk drives the real screens in the new order, asserting the card's
address is **not** on screen before the card read. VaultKit 255 → 256, YubikeyKit 88 → 89, UI 15
(the signing walk is one of them).

## 34. v0.2: the signing flow opens on the scanner

**Sections:** §5.1, `SigningViewModel.Phase`.

**What changed.** Tapping *Sign a transaction* on the home screen used to open a setup
screen whose only content was an explanation and a *Scan the request* button; the camera
started when that button was tapped. The setup screen is gone: entering the flow opens the
scanner.

**Why it was there, and why it is not needed.** The screen existed because the old flow
read the card first — the setup screen was where the operator acknowledged "this app reads
the key inside the YubiKey" before the card was touched. Once the request is taken first
(amendment 33), nothing has been read from the card at that point and nothing has to be
decided: the request is what names the key. A page whose only action opens the camera is a
button of ceremony between the operator and the work.

**What the flow looks like now.** Home screen → camera (toolbar: *Cancel*, because nothing
has been read and leaving drops nothing) → the request is decoded → *Read the YubiKey* for
the one slot the request named (toolbar: *Abort*, because a request is now in hand and
leaving abandons it) → summary → chain confirmation → PIN → signature → record. The camera
is tied to the view's lifetime: it starts from the view's `.task`, stops when the view goes
away, and `applicationDidForeground` still restarts it after a background trip.

**What was kept.** The explanation did not disappear with the screen: the scanner's own
copy now says that nothing is read from the YubiKey until the request is in, and that the
request names the one key that will be asked for. The toolbar's two words are the app's
statement about what leaving costs, and they follow the same rule as the rest of the app:
a cancel before anything is in hand, an abort afterwards.

**Evidence.** `SetupFlowUITests.testTheSigningFlowOpensOnTheScannerAndCancelsHome` asserts
the flow opens with the scanner's own control on screen and that Cancel returns to the home
screen (it replaced the test that asserted the same property on the setup screen, which no
longer exists). The signing walk in `SigningFlowUITests` no longer taps anything before the
sample request, and still asserts the card's address is absent from the screen until the
card has been read. VaultKit 256, YubikeyKit 89, UI 15.

## 35. v0.2: the camera is started late, and only where it can be displayed

**Sections:** §5.1 (the scanner), `QRScanModel`, `QRScannerView`.

**What was reported.** Opening the camera left the preview frozen on its first frame. Backgrounding
the app and bringing it back fixed it, which was the clue: a stop and a start of the same session is
what makes the preview display, and the app's first start did not have that property.

**Two defects, both about *when* the session is started.**

1. **It was started while the app was inactive.** A session started then reports `isRunning` and
   delivers nothing: the preview holds its last frame and no log line says why. The permission prompt
   is exactly that case — asking for the camera takes the app out of the foreground,
   `applicationDidBackground` suspends the scanner, and `start()` resumed after the operator answered
   with the app still on its way back. Starting there left the session "running" for good: the
   foreground edge asked to start it, the `isRunning` guard skipped it, and the preview never came
   alive. Fixed with one guard — configure, then start only if
   `UIApplication.shared.applicationState == .active`, otherwise withdraw the claim and let the
   foreground edge do it.

2. **It was started before the preview layer could display it.** The flow started the camera from
   `beginScanning()`, which runs as the view appears — and a `UIViewRepresentable` inside a
   `ScrollView` is created slightly later than an ancestor's `.task`. A session started before its
   preview layer is on screen shows one frame and then sits still, which is precisely why the
   background/foreground trip cured it: that trip stops and starts the session *after* the layer is
   up. Fixed by making the preview the trigger: `QRScannerView.PreviewView` reports when it is in a
   window with a non-zero size (`didMoveToWindow`/`layoutSubviews`, on change only), and
   `QRScanModel.previewDidAppear()` is what calls `start()`. `beginScanning()` now only opens the
   screen. The invariant afterwards is "`startRunning()` never happens before there is something to
   display it in", and the camera's lifetime follows the preview's (leaving the screen stops it).

**What the evidence looks like, and what it cannot.** A simulator has no camera — it answers
`AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)` with `nil` and the
app shows its own reason ("No camera is available on this device."), so neither defect could be seen
in CI. On the iPhone 17 in hand, a temporary probe (a second `AVCaptureVideoDataOutput` counting
frames, plus the session's notifications, printed once a second and read through `devicectl …
--console`) measured: **before** the fixes, `frames=1` with `didStart` and `didStop` in the same
second; **after** them, 23 → 606 frames in twenty seconds (~30 fps) with `running=true` throughout,
and the log shows the intended sequence — the launch's first `start()` sees the app inactive and
defers, then the foreground edge starts it. Background → foreground was measured the same way
(`didStop`, count frozen, `didStart`, count climbing again).

The second defect was found by the operator, on a device, after the first fix shipped — and it could
only be *confirmed* by eye: a UIKit render readback of the preview area returns the same bytes
whether the picture is live or frozen (the camera surface is not part of what `drawHierarchy`
composes), and `devicectl` has no screenshot verb. So the last check was done with the app launched
by hand (`-open-scanner`, which opens the scanner with no taps) and an on-screen frame counter: the
picture moved and the counter climbed. **A UI test on a phone cannot see any of this** — the test
runner takes the foreground while the test executes, so the system stops the app's session a
fraction of a second after it starts, and the count stays at 1. That is the harness, not the app,
and it is written down in `docs/m0-hardware-verification.md` item 15 and in the README so nobody
reads a frozen preview in a device test run as a regression.

**Still not covered.** A session the *system* stops while the app is active — an incoming call,
another app taking the camera — leaves the claim saying `scanning`, and the foreground edge then
declines to restart it. That case needs a frame watchdog rather than a flag, and it stays an m0 item
rather than a guess.

## 36. v0.2: the scanner's display is frosted

**Sections:** §5.1 (the scanner), `ScannerFrost` in `QRScannerView.swift`,
`docs/signing-checklist.md`.

**What changed.** A frosted-glass layer covers the camera preview. Through it the scanner shows
shapes and light — enough to centre a QR code in the frame — and no detail.

**Why it costs nothing.** Scanning does not read the screen. The request arrives as sample buffers
from the session's metadata output, so the display is not in the decoding path and can be obscured
without touching it. The same property is what makes the DEBUG sample equivalent to a real scan
(§5.1), and it leaves the preview exactly one job: aiming. Aiming needs edges, not detail.

**Why it is worth doing.** Without it the app is a viewfinder. It puts a live, legible picture of
whatever is in front of the phone onto a screen that other people can see, photograph, or record,
and the app cannot distinguish any of those from the operator looking at it. Two consequences are
covered: a bystander or a second camera gets the blur, and iOS's snapshot for the app switcher —
the one moment the preview is on screen while nobody is looking at the scanner — is redacted
(`privacySensitive()`) rather than left holding the last camera frame.

**Deliberately not a `blur` on the preview's own view.** The frost is a sibling drawn after the
preview in the same `ZStack`, and the preview's own modifiers are untouched: how that view renders
has already gone wrong once, in a way a simulator cannot show (amendment 35), and frosting it does
not require touching it.

**The strength is the material, and there is nothing below it.** The first version picked the
thinnest material, and the operator's verdict from the device was that it was too blurry to aim
through — so the next version diluted the material with `.opacity`, and that was wrong for a
documented reason. Apple's `UIVisualEffectView` documentation — the machinery under a SwiftUI
material — says to avoid alpha values below 1 on a visual effect view *or any of its superviews*,
because "many effects look incorrect or not show up at all". The operator then asked the question
that behaviour predicts: was the material doing anything at all? It was being flattened by the
opacity over it. Reverted to the material alone, at full strength, and the question is now the
documented one rather than an empirical puzzle.

That leaves a limitation worth stating rather than papering over: **the materials are not a dial
between blurry and clear.** They differ in thickness — how much of the background shows through —
and share the blur radius, so `.ultraThinMaterial` (already the most translucent of the five) is the
clearest this construction gets; every other choice only makes the picture greyer. A numerically
tunable radius would mean blurring the *frames* rather than the display: a `CIFilter` pipeline fed
by a video-data output, in place of the preview layer that took two rounds to stabilise (amendment
35). That is a different piece of work, and it has not been done. What the frost costs is therefore
paid in aiming: the code is framed by its shape, with the decode progress as feedback, and a clear
aperture in the middle of the frost is the obvious next step if that proves too coarse on a real
wallet.

**What it cannot do.** There is no public API to exclude an arbitrary view from a screen
recording, so a recording of the scanner holds the frosted image. That is the intent — what a
recording gets is what the operator saw — but it does mean the property is "nothing legible
reaches the screen", not "nothing reaches the recorder". And the frost is not a control on the
*request*: the QR code is shown in full, as parsed text, on the summary screen, deliberately,
because that is the screen the operator has to check. The frost protects the scene around the
operator, not the transaction.

**What is checked where.** A UI test asserts the part a simulator can see: the frost exists and
covers the preview's box exactly, with the stacking left to the `ZStack`'s source order. Whether the
picture is really obscured, and whether a real QR code still decodes behind it, needs the phone
(m0 items 15 and 16) — the display cannot be measured from inside the app (a render readback does
not include the camera surface), and the UI test harness stops the camera.

## 37. v0.2: the writes and their read-back are one step

**Sections:** §4.2 steps 6, 7 and 7b; `CeremonyStep` (`readBackCheck` and `pairingManifest` are gone
from `CeremonyMode.path`), `ProvisioningCeremony.importAndVerify`, `ImportStepView`,
`docs/provisioning-checklist.md`.

**What changed.** The ceremony used to visit three steps while writing the card: `keyImport` (both
private keys, then the policy), `readBackCheck` (both public keys and the policy read back off it)
and `pairingManifest` (the chain codes written into the card's private-use object). They are now
**one step**. `keyImport` writes keys → policy → manifest, then reads the keys, the policy, the
retry limits and the manifest's bytes and binding back off the card, and advances only once the card
has reported all of it. The two former steps have no screens of their own, and the window's step
counter counts one where it counted three.

**Why, in the order the reasons matter.**

1. **A step boundary is where an interruption happens.** The app does not control when the phone
   locks, when an NFC session ends, or when the operator switches away — and a screen boundary is
   the most likely moment for all three. The previous design put the gap between a write and its
   proof exactly there: a card holding keys the app had not yet read back, or a manifest no later
   re-pair could trust. A card written but unverified is the state this ceremony exists to refuse,
   and the cheapest way to refuse it is to have no place for it to happen.
2. **The ordering requirements were expressed as screen order.** Writing a slot's algorithm
   attributes resets that slot, and the applet discards that slot's touch policy with it, so the
   policy write must follow the last key write (amendment 26 measured the loss on hardware); and the
   manifest must follow the read-back, so that the card is never told to advertise a key that has not
   been verified to be in it. Amendment 32 folded the first two writes into one step; this folds in
   the manifest write and the read-back, so nothing about the order is a property of the view layer
   any more. The order now lives in one method (`importAndVerify`) and in the `CeremonyStep.keyImport`
   doc comment, which is where a future reader has to look anyway.
3. **The chain codes are written for the same reason the keys are.** A wallet needs the extended
   public keys, and the card is the only place they can be kept so that a later re-pair needs neither
   the mnemonic nor a reset. Treating them as a separate step made them a separate intention, which
   they are not.

**What it costs.** The read-back comparison is no longer its own screen the operator reads before
pressing Continue: it is on the same screen as the write, and Continue appears only once everything
has been verified. The information is the same, and it is still shown as the card reports it rather
than as the app asked for it. What is gone is a separate render pass — and with it the moment where
the operator was invited to look at a comparison the app had already made. The step also takes longer
in wall-clock time: four short card sessions for the writes and the reads, where the old import step
took two and the read-back step two. On NFC that is more time holding the key against the phone, and
that is the price the design accepts for not having a boundary in the middle.

**How a failure reads now, unchanged.** A key import that fails still leaves the card half provisioned
and says so, because the applet refuses to overwrite an occupied slot and "retry the import" can never
work; a public key that reads back different still voids the procedure, wipes every secret and sends
the operator back to the inspection step; a policy the card does not report still stops the step
without wiping, and the card is left for the reset because a second write is the blind retry §5.2
rule 1 forbids. A manifest the card cannot store, or that does not read back byte-for-byte and bind
to the card's own key, is still a warning and a degraded card in this version — the keys and the
mnemonic are unaffected — which §4.2 step 7b states as its "degradation, not failure" property.

**What is checked where.** `ProvisioningCeremonyTests` drives the step once and asserts the whole
outcome (the writes, the read-back, the policy, the manifest, the step it lands on), and the failure
tests inject at the operation they are about and assert the same errors as before. The ordering test
that used to compare the positions of `readBackCheck` and `pairingManifest` in the mode's path now
asserts what replaced it: the import step is followed directly by the export, and calling `advance()`
on the import step is refused — `importAndVerify` is the only way forward, and it ends with a card the
ceremony has read back. The UI test walk taps one action ("Write and verify the YubiKey") where it
tapped three, and asserts the stored-manifest line that only appears once the step has run.

## 38. v0.2: a card that cannot store the chain codes is not provisioned

**Sections:** §4.2 step 7b (its "four properties are normative" list), §10 item 13;
`CeremonyError.pairingManifestNotStored`, `ProvisioningCeremony.writePairingManifestAndCheck`,
`ImportStepView`, `docs/provisioning-checklist.md`, `docs/m0-hardware-verification.md` item 12.

**What changed.** The manifest write was the one write in the ceremony whose failure was
tolerated: a card whose applet has no private-use object, one that refused the write, and one
that handed back different bytes were all reported as a warning and the ceremony continued.
They now stop the ceremony, like every other write. `PairingManifestOutcome` and its `declined`
case are gone, `CeremonyReport.pairingManifestStored` is only ever true, and the step's gate is
"the manifest is on the card" rather than "the step ran" — so a report that exists at all means
the chain codes are in the card.

**Why.** The rule the rest of the ceremony already follows is that a value the card does not
report is not a value: §5.2 rule 7d states it for the touch policy, and the same reasoning
applies to the chain codes, which are part of what this ceremony writes. The old justification —
"the keys and the mnemonic are unaffected, so only the convenience of a later re-pair is lost" —
was true about the funds and wrong about the card. A card that finishes the ceremony without a
manifest is a card whose next re-pair silently costs the mnemonic, which is exactly the property
the operator believed the ceremony had bought. A ceremony that cannot deliver what it promises
says so and stops; it does not finish and leave a caveat in the record.

**What it costs.** A YubiKey whose applet has no private-use objects can no longer be provisioned
by this app (the objects are optional in the spec; they are present on YubiKey 5 firmware 5.8.0,
verified in m0 item 12). And a card that reaches this point has both keys in it already, so the
way out is the reset — the same position a policy that will not stick leaves the operator in, and
for the same reason: the card holds something the ceremony did not confirm, and a second write
would be the blind retry §5.2 rule 1 forbids. `pairingManifestNotStored` is the error, and its
message names both facts: what did not reach the card, and that a reset is the way forward.

**What is checked where.** The test that asserted the degradation
(`testACardWithoutThePrivateUseObjectWarnsAndContinues`) becomes
`testACardWithoutThePrivateUseObjectStopsTheCeremony`, and the two tests that asserted a warning
for a refused write and for storage that hands back different bytes now assert the throw. Each
checks three things: the error and its detail text, that the step stayed at `keyImport` and its
gate refuses to close, and that both keys are still in the card — because "the keys are fine, the
card is not" is the state the operator has to understand before resetting it.

## 39. v0.2: the signature counter is not read at all

**Sections:** §4.1 (diagram), §4.2 step 9 (deleted; the small-value test transaction is now step
9), §4.2 step 7c, §4.3, §5.1 (sequence steps 6, 13, 17), §5.2 rules 3–4 (rewritten in place) and
rule 8, §6.3, §6.5 (the `00 CA 00 7A 00` row is gone), §7.1, §7.2, §8.3, §9.3, §9.4, §9.5, §10
items 2b/8/9, §11, Appendix A and B; `SignerCard.signatureCounter`,
`SigningCardIdentity.signatureCounter`, `CardInventory.signatureCounter`, `CeremonyStep.counterBaseline`,
`CeremonyReport.counterBaseline`, `SigningReport.counterBeforeSigning/counterAfterSigning/counterDelta`,
`OpenPGPCard.signatureCounter`, and the `GET DATA 0x7A` read itself; `docs/provisioning-checklist.md`,
`docs/signing-checklist.md`, `docs/v1-threat-notes.md`, `docs/m0-hardware-verification.md`.

**What changed.** Everything that read, displayed, compared or verified the card's signature
counter is gone. The provisioning ceremony has no baseline step and records no baseline; the
signing flow does not read the counter before or after a signature, shows no before → after line,
and its record has no counter rows; the card inventory no longer reports the number; the app
issues no `GET DATA 0x7A` at all, so `YubikeyKit` no longer parses `0x93` and the simulated card
no longer answers for it. §4.2's step 9 is deleted, and the small-value test transaction becomes
step 9.

**Why.** The audit's premise is that a wallet knows how many signatures it asked for and can
compare that with the card's count. The premise fails the moment the card is shared: this YubiKey
is used with other applications, so its count moves for reasons this wallet cannot see, and
`actual > expected` stops meaning "a signature this wallet did not ask for". A control that fires
on other applications' signatures is worse than no control, because it teaches the operator to
ignore it. The rule it was built on also ruled out the alternative reading: §5.2 rule 3 required
the comparison to be made by a party *other* than the one that displayed the transaction, so the
app's own before/after numbers were never the control they looked like — the wallet's read was,
and the wallet's read has the same problem for the same reason.

**What replaces it.** The wallet's verification of the signature it asked for, against the digest
it sent and the account it holds (§5.1 step 16.5), plus the wallet's own record of what it
requested. That is the property rule 3 was reaching for — a party other than the signing screen
decides whether the signature is right — and it is stronger, because it names the digest rather
than counting events. §§5.2 rules 3 and 4 are rewritten in place rather than deleted, so the many
"rule 3" / "rules 3–4" references in the code and the other documents keep pointing at something;
and the threat-table row that recorded the Ed25519 gap as **Medium** (an extra touch on a key no
counter covered) becomes **Low**, because a signature the wallet did not ask for never reaches
verification at all — the separate existence of an authentication slot is no longer a detection
gap, since there is no detection control left for it to be a gap in.

**What is lost, stated plainly.** An extra touch — the social-engineering half of §9.3 — leaves no
card-side trace any more. What remains is the wallet's own check: a signature over a digest it did
not send fails verification, and the operator is told not to broadcast. An attacker who can also
make the wallet accept a substituted digest defeats any card-side count too, so the residual risk
is unchanged in kind; what changed is that the design no longer claims a detection control that a
shared card cannot provide. §10 item 8 is rewritten to say the card is shared, which is the
assumption the old counter rules silently depended on being false.

**What is checked where.** The remaining checks are structural rather than behavioural: the API is
gone (so nothing can call it), `CeremonyStep` has no counter step (so no screen can appear between
the pairing codes and the teardown), and `SigningReport` has no counter fields. The tests that
asserted a recorded baseline, a "must be zero" gate, a delta of one, or a counter read in the
signing session's APDU trace are deleted rather than rewritten, because they tested a feature that
no longer exists; the UI walk no longer taps a counter screen. A hardware trace that showed
`00 CA 00 7A 00` would now be a bug, and m0's counter lines are replaced by that
statement. This is a genuine reduction in what the off-hardware suite can prove — there is no
longer anything to assert about a number the app does not read — and it is recorded here rather
than left implicit.

## 40. v0.2: the keys come first, and one ceremony writes several YubiKeys

**Sections:** §4.2 (the order paragraph, steps 2, 3, the new 4b, 5 and 6), §4.3, §8.1;
`CeremonyStep.cardCount`, `CeremonyMode.path(cardCount:)`,
`ProvisioningCeremony.setCardCount` / `declineMnemonicBackup`, `CeremonyReport.cards` /
`mnemonicBackedUp`, `CardRecord`, `CardPolicy.cardCountRange`; `CardCountStepView`;
`docs/provisioning-checklist.md`; the UI test walk.

**What changed.** Three things, in one design, because each is what makes the next legible.

1. **The order.** A provisioning run generates the keys first — entropy, mnemonic, derivation —
   and only then touches a card. The per-card steps (inventory, reset, PINs, retry limits, write
   and read-back) follow, once per card. Re-pair is unchanged and still starts at the card: it
   reads one that is already provisioned.
2. **Several cards per run.** After the keys exist and before the first card is touched, the
   operator says how many YubiKeys this run will write (`4b`, 1–5). Each card is reset, given
   **its own User PIN and Admin PIN**, given the ceremony's retry limits, and written and verified
   in its own pass. Every card ends up holding the same two keys and the same pairing material;
   each stores its own manifest, because the manifest names the card's serial. The report names
   every card, in the order the operator presented them. A card this run has already written is
   refused at its inventory (`duplicateCard`) — the step after that inventory resets the card,
   which would erase the keys it now holds.
3. **The paper backup is optional.** The mnemonic step can be declined, and the choice is recorded
   (`mnemonicBackedUp`, and a line on the printable record) and said in the terms that matter:
   with one card and no backup, that card *is* the wallet. Restore mode cannot decline it, because
   those words came from a backup that exists and the back-fill there is a check on the typing.

**Why the keys go first.** The count is a decision about the operator's equipment, and it does not
exist until the keys do. It has to be known before the first card because the per-card block is
what the operator is about to repeat, and it has to be known *by the mnemonic step* because that
step's warning depends on it: "the words are the only copy" is true with one card and false with
three. The previous order — reset and configure a card, then generate the keys — could not ask the
question in either place, and it put a destructive operation before the only backup of the keys it
was about to write.

**Why several cards in one run.** A second YubiKey is the reason to have a mnemonic at all: the
same keys on two devices means one can be lost without losing the wallet. Doing it in one run is
what makes that practical — the keys are in memory once, the words are in front of the operator
once, and the pairing codes are produced once. The alternative (a second full ceremony in restore
mode) works, and remains the recovery path, but it re-derives the keys and re-runs the whole
per-card sequence anyway. What the single run costs is stated on the step: **every card must be to
hand**, because the ceremony cannot be paused between cards, and it cannot go back to one it has
already written.

**Why the backup is optional.** A compulsory backup is one an operator learns to click through,
and the honest reason it matters is the card count: with N cards the keys exist N times, with one
card they exist once. The app asks the count, says which case the operator is in, and records what
they chose. What it cannot do is make the record true: if the words are not written down and every
card is lost, reset or destroyed, the wallet is gone — and the record says exactly that.

**What is checked where.** `ProvisioningCeremonyTests` covers the count being chosen after the keys
and before the cards (and refused outside 1–5, leaving the step where it was), the same card
refused as a second card with the first card's keys untouched, the per-card PIN steps (the path has
one per card, so card 2's write cannot inherit card 1's PINs, which are wiped when card 1 is
written), the decline-and-record path for the mnemonic, and a restore that cannot decline. The
integration test `testTwoYubiKeysAreProvisionedInOneCeremony` swaps the transport underneath the
single `SignerCard` the ceremony holds — which is what "the card" means over NFC — and asserts that
both cards hold the keys, that each stores its own manifest, and that the report names both
serials. The UI walk provisions one card, which is what the simulator's one simulated card can be.

**What this does not do.** There is no resumption: a run that stops between cards starts again from
the keys. Per-card retry limits are deliberately not offered — the limits are one policy decision,
and the PINs are what differ per card. And nothing here changes what a single card *is*: the same
two keys, the same fixed paths, the same pairing material, whichever run wrote it.

## 41. v0.2: the second YubiKey was reset and never written

**Sections:** §4.2 step 4b; `ProvisioningCeremony.beginCardPass`,
`CeremonyViewModel.syncStepOutputs`, `ImportStepView`; `docs/m0-hardware-verification.md` item 20;
`SimulatedCardTransport` and the UI test walk.

**What was wrong.** With `card count = 2`, the first card was written and verified; the second card
was reset, given its PINs and its retry limits — and **never written**. The operator saw the second
card's write step already showing a **Continue** button and the *first* card's read-back, tapped it,
and the ceremony moved on to the pairing codes. The report named two cards; only one of them held
the keys.

**Why.** Two pieces of state were per-*run* while being about a *card*:

1. `ProvisioningCeremony` kept `readBackResults`, `pairingManifest` and the report's
   `readBackVerified` / `touchPolicyVerified` / `pairingManifestStored` flags after a card was
   written. `advance()` at the next card's write step is gated on exactly those flags, so it closed
   the step on the previous card's answers.
2. `CeremonyViewModel` cached `readBack` from that write, and `ImportStepView` decides what to show
   — and which action to offer — from `!readBack.isEmpty`. So the screen offered "Continue" instead
   of "Write and verify the YubiKey".

The model tests drove `importAndVerify()` directly and never asked whether the step *could* be closed
without one, so both defects passed every gate.

**The fix.** A card's pass is now a scope with a beginning. `beginCardPass()` runs when the next
card's inventory opens and clears the card reading, the read-back, the manifest, the policy flags,
the retry limits and the per-key `readBackVerified` marks; the view model re-reads those from the
ceremony on every step change instead of keeping a copy, and clears the inventory it holds and the
destructive-reset acknowledgement with them. `advance()` at a card's write step therefore refuses
until **that** card has been read back.

**A second defect the new test then found.** The first card's *inventory* survived into the second
card's pass on the screens, so the second card's inventory step showed the first card's reading and
offered Continue: the ceremony would have gone straight to the reset, never reading the second card,
which means the duplicate check could not run and the manifest would have been built with the first
card's serial. Clearing the model's inventory in `beginCardPass()` (and the view's copy with it, in
the same step-change branch) is what fixed it, and `advance()` now refuses a card step whose
inventory has not happened.

**How it was found, and how it was then checked on the card.** The operator reported it from a real
YubiKey with the card count at 2. After the fix, a scratch harness on the Mac drove the **app's own**
ceremony and transport against the attached key (5C NFC, firmware 5.8.0, applet 3.4) for a two-card
run, provisioning the same physical key twice — the harness reports a second serial for the second
pass, because that is what the duplicate check reads. After **each** pass the card was asked
directly, not through the ceremony: both slots occupied, UIF `02 20` on both, PW1 status `00`, the
198-byte manifest present, and both public keys byte-equal to the keys derived on the Mac. m0 item 20
records the run, and the entitlement that made it possible (a CLI signed ad-hoc with
`com.apple.security.smartcard`: `TKSmartCardSlotManager.default` is `nil` without it, which is what
had blocked this check before).

**What this says about the test suite.** The defect was in the *wiring* between the state machine and
the screens, which model tests cannot see: they call the method that does the work, so they never ask
whether the work could have been skipped. The guard is now a two-card UI walk, and the simulated
reader grew the smallest affordance that makes one possible — `-simulated-cards <n>`, plus an
explicit "the operator swapped the card" call from the view model at the moment a card's pass ends
(inferring the swap from what the card holds does not work: the write step reads its own manifest
back *after* writing it, so "this card looks written" is already true before the pass is over).

## 42. v0.2: the keys are wiped before the pairing codes, not after them

**Sections:** §4.2 (the order paragraph, the paragraph before step 8, step 6's last sentence);
`CeremonyStep.wipeSecrets`, `ProvisioningCeremony.wipeSecrets`/`wipeSecretMaterial`/`wipe`,
`CeremonyReport.secretsWipedBeforePairing`, `CeremonyViewModel.wipeSecrets`,
`WipeSecretsStepView`/`TeardownStepView`; `docs/provisioning-checklist.md` Part 3.

**What changed.** The wipe used to be the last thing the ceremony did: the operator scanned the two
pairing codes, compared the addresses with their wallet, and only then cleared the app's memory and
produced the record. It now runs **before the pairing step**, as a step of its own with its own
screen, its own Continue and a line in the record. The keys exist in memory until the last card has
been written and read back, and not one step longer.

**Why.** The pairing step is the worst place in the run to be holding private key material. It shows
two QR codes and lasts as long as the operator needs to scan them — the longest stretch of the
ceremony with the phone held up in front of a camera, and the one where the operator is looking at
another device rather than at the screen. And it needs nothing secret: the codes carry the public
keys, the chain codes, the paths and the fingerprints, all of which are also in the card's manifest.
Wiping first therefore costs the ceremony nothing:

* the codes stay reproducible from the card alone, which is what the manifest is for (§4.2 step 7c),
  so "wipe, then pair" cannot lose the ability to pair again;
* a run abandoned after the wipe has lost nothing the cards do not hold — the mnemonic is on the
  paper the operator was asked to write, and the keys are in every card this run wrote;
* the code that builds the codes now has no private key to reach even in principle.

**The wipe is derived, not asserted.** `secretsWiped` is computed from the secrets themselves
(`entropy == nil && seed == nil && privateKeys.isEmpty && mnemonicWords.isEmpty && sessionAdminPIN == nil`)
rather than set by the method that wipes, so the gate at `.wipeSecrets` cannot be satisfied by a call
that did not clear anything, and a later `wipe()` — or an abort — puts it back to false because the
secrets are gone and the ceremony is not in a position to pair. This is the same reasoning as §5.2
rule 5: a step is gated on what is true, not on what was asked for.

**What the step does and does not clear.** `wipeSecrets()` clears the mnemonic, the seed, both derived
private keys, the entropy and the per-card Admin PIN, and records `secretsWipedBeforePairing` in the
report. It deliberately keeps the public material the pairing step exists to show — the exports
(public keys and chain codes), the derived addresses, the read-back results, the inventory and the
record. "Wipe everything" is still `finish()`/`wipe()`, which runs at the end of the run and clears
the pairing material as well.

**Consequences for the operators' documents.** The record gains the line "secrets wiped from app
memory before pairing: yes", the teardown screen no longer wipes anything (its action is now "Finish
and show the record"), and the provisioning checklist gains a wipe item before the pairing item and
loses the teardown one. The app's step path for both provisioning modes gains the step; the re-pair
mode does not, because it never holds a secret in the first place — no mnemonic is entered and no
private key exists — and a test asserts that it stays that way.

**A note on the view-model bug this exposed.** The first version exposed `secretsWiped` as a computed
property over the ceremony, and the wipe appeared to do nothing on screen: the ceremony is a plain
class, so mutating it does not invalidate a SwiftUI view, and nothing else on that screen changed.
The view model now mirrors the flag and re-reads it from the ceremony on every step change — the same
shape as `readBack` and `pairingManifestStored`, and the same lesson as amendment 41: state that the
screens decide from is copied deliberately and re-synced, never assumed to follow along.
