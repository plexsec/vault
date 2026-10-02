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
