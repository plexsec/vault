# Threat notes, deviations and residual risk (v0.1 provisioning, v0.2 signing)

This complements §9 of `design.md`. It records what the app actually implements,
where it deviates from the design, and which risks are *accepted* rather than
mitigated — so that no reader mistakes a design intent for a shipped control.

## Scope actually shipped

| design.md section | v0.1 status |
|---|---|
| §4.2 steps 2–9 (provisioning) | implemented |
| §4.3 two-algorithm key model | implemented — secp256k1 (signature slot) + Ed25519 (authentication slot); see deviation 6 |
| §4.2 step 10 (small-value test transaction) | **not possible** — needs signing (v0.2) |
| §5 signing flow, `eth-sign-request`/`eth-signature` | **not implemented** (v0.2) |
| §5.2 rule 4 (counter-delta audit) | **not implemented** — the baseline is recorded, but nothing decrements it yet |
| §6.3 Bitcoin PSBT | **not implemented** (v0.3) |
| §7.1 Desktop reference client, §5.1 step 18.5 verification | **not implemented** (v0.3) |
| §8.2 recovery, §8.3 drill | implemented (restore mode) |

The consequence to be explicit about: **the scheme's central claim — that a
tampered iPhone cannot cause the Desktop to broadcast a different transaction — is
not yet testable with this code**, because neither the signing exchange nor the
Desktop verifier exists. What v0.1 does establish is that the key on the card is
the key derived from the mnemonic, verified by read-back.

## Deviations from the design, with rationale

### 1. Entropy: card RNG XORed with the iOS CSPRNG; dice non-authoritative

**Change.** §4.2 step 4 now builds the 256-bit entropy by XORing the YubiKey's
hardware random-number generator (`GET CHALLENGE`, INS `0x84`) with the iOS system
CSPRNG (`SecRandomCopyBytes`); dice are recorded as a witness only. The
dice→mnemonic cross-check in §4.2 step 6b and Appendix B is removed.

**Why.** This was an explicit product decision. Implementing dice as an entropy
source requires a specified, published dice→entropy function so that an
independent tool can reproduce the mapping; without one, the Appendix B check
would be unverifiable, which is worse than not claiming it.

**Consequence, stated plainly.** The "backdoored RNG" node of the §9.4 attack tree
is now mitigated by construction: the entropy is the XOR of two independent RNGs
(the card's secure element and the iOS CSPRNG), so a single backdoored source no
longer determines the key. What remains uncaught is a coordinated compromise of
*both* RNGs, and the independent cross-check that would have compared derived
addresses was removed (amendment 8). §9.5 records the residual risk as **Low**.

**Compensating controls that do exist.** Reproducible-build verification; the
entropy commitment (8 hex digits of SHA-256 of the entropy) which binds the
recorded mnemonic to the value the app says it generated; and a factory-reset,
airplane-mode device.

**Path back.** A future version can make dice authoritative by specifying the
function (for example Coldcard-style rejection sampling over rolls, or a tagged
KDF) and publishing it, and by making the app display either the raw entropy or
the rolls so an independent tool can reproduce the mnemonic.

### 2. Transport: Lightning/5Ci removed, USB-C CCID added

**Change.** §3.2, §4.1, §6.5, §7.2.

**Why.** The 5Ci path required a vendor MFi accessory SDK that YubiKit 4.x
dropped, making it the project's only external SDK dependency and a real
availability risk. USB-C CCID via CryptoTokenKit uses Apple frameworks only.

**Consequence.** The wired transport needs an iPhone 15 or later. NFC covers every
CoreNFC-capable iPhone, so no ceremony capability is device-gated.

### 3. Counter read on-device

**Change.** §4.2 step 9 and §5.2 rule 3.

**Why.** Reading `0x93` needs no PIN and exposes no secrets, and the iPhone can do
it over either transport. Requiring a Desktop tether for a provisioning-time read
contradicts the "cold device" intuition for no gain. §5.2 rule 3 is restated as
"read by a party other than the one that displayed the transaction", which is the
property that actually matters.

### 4. Pairing export carries a chain code; secp256k1 is account-level

**Change.** §6.4. Supersedes the earlier "no chain code" deviation
(amendment 14).

**Why.** A chain code is not optional for Keystone/MetaMask. Their
`CryptoHDKey.getBip32Key()` concatenates it unconditionally, so a `crypto-hdkey`
without one fails the scan with `TypeError: Cannot read properties of undefined
(reading 'length')` (the bundled `buffer` polyfill reads `.length` of `undefined`
in `Buffer.concat`). Omitting it therefore did not trade account discovery for
safety — it made the code unreadable. v0.1 now exports each key with its chain
code.

**The `name` field is also mandatory in practice.** MetaMask derives the keyring's
display name from `crypto-hdkey` field 9, and `BaseKeyring.deserialize()`
overwrites the `"QR Hardware"` default with the persisted value — which has no
`name` for a keyring that was added but never paired. The scanned key is the only
thing that can restore it, and on confirm `getAccountLabel()` evaluates
`name[0].toUpperCase()`. An export without field 9 therefore shows the right
address and then fails with `Cannot read properties of undefined (reading '0')`.
Reproduced against MetaMask's own packages; the export now always sets field 9.

**How the "unsignable children" hazard is handled.** One YubiKey slot holds one
key (§4.3), so the secp256k1 key is exported at its BIP44 **account** level
(`m/44'/0'/0'`) with `children` pinned to the fixed path that reaches the card's
leaf (`0/0`, no wildcard). MetaMask derives `<origin>/0/*`, which lands on the
card's key, and the pinned `children` makes every account index resolve to the
card's address rather than a sibling it cannot sign for. Verified against
MetaMask's own `@keystonehq/*` packages: the QR scans, and indices 0..4 all show
the card's EVM address. Because a chain code is still present, the operator must
acknowledge a warning before the codes are built, and the warning is recorded in
the report; a wallet that ignores the pinned path could still derive siblings.
`crypto-account` / `account-descriptor` is still not emitted.

**Consequence to state plainly.** With `children` pinned, MetaMask's index
substitution is a no-op, so its account picker shows the *same* address five
times (one distinct address; all signable). Re-adding an index duplicates the
address, and MetaMask Mobile's `createAccounts()` rejects a second index with
`Failed to create new account`. The wildcard MetaMask expects would instead show
five distinct addresses of which only index 0 is signable — the capability
over-advertisement this design forbids. The pinned path is kept deliberately.

### 5. Distribution: free personal team

**Change.** §4.2 step 1, §10 item 12.

**Why.** It is what is available. The honest consequences: profiles expire after
7 days, so the device must be re-tethered weekly, and `App Store` installs cannot
be hash-verified. The app persists no secrets, so the worst case of an expired or
deleted install is re-doing the pairing.

### 6. One key per algorithm; the counter covers secp256k1 only

**Change.** §4.3. A ceremony now writes two keys from one mnemonic: secp256k1
into the signature slot and Ed25519 into the authentication slot, at fixed
algorithm-scoped paths (`m/44'/0'/0'/0/0`, `m/44'/501'/0'/0'`).

**Why.** The applet has two signing-capable slots, so allocating slots per chain
would cover two chains; allocating per algorithm covers the practical chain
landscape with the same card. The user-visible cost is address reuse across
chains of the same algorithm, which is accepted and stated in §4.3.

**Consequence, stated plainly.** The OpenPGP signature counter belongs to the
**signature** slot. Ed25519 has to live in the authentication slot, whose
`INTERNAL AUTHENTICATE` does not increment it. So the §5.2 rule 3/4 audit — the
control that turns "extra touch" social engineering into a detectable event —
covers secp256k1 chains and **not** Ed25519 chains. PIN and touch still gate
every Ed25519 signature, and the tampered-display defence (§9.3) is unaffected,
because that rests on the Desktop verifying what it asked for, not on the
counter.

**Compensating controls that do exist.** Touch policy `Fixed` is written to the
authentication slot (UIF `0xD8`) as well as the signature slot, so an Ed25519
signature still requires a physical touch; PW1 status `0x00` still forces a PIN
per signature; the report states the limitation on every ceremony; and the
one-touch-per-transaction rule is unchanged.

**Path back.** There is none on this hardware: the counter is a property of the
slot, not of the algorithm. Restoring a counter-audited Ed25519 key means a
second YubiKey, where Ed25519 would occupy that card's signature slot. That
option is documented rather than implemented.

## Residual risk register for v0.1

| Risk | v0.1 mitigation | Residual |
|---|---|---|
| Backdoored/faulty entropy source | XOR of card RNG and iOS CSPRNG (see deviation 1); a single compromised source cannot determine the key | **Low** |
| Tampered app at generation time | Reproducible-build hash; read-back comparison; factory-reset offline device | **Medium** — the independent cross-check that bounded it was removed |
| Wrong key silently provisioned onto the card | Mandatory read-back comparison of the card's public key against the derived key, which voids and wipes on mismatch | **Low** |
| Malicious card (counterfeit) | Read-back mismatch; report records serial/applet and the operator writes down the fingerprint | **Low** |
| Fake card accepted by the app | Release build contains no simulation, asserted mechanically by `tools/audit-release.sh` on every verification run | **Low** |
| Mnemonic disclosed by screen capture | Mnemonic hidden unless pressed and hidden entirely while `UIScreen.isCaptured`; no pasteboard use; camera warning | **Low** |
| Mnemonic disclosed by the app writing it somewhere | No persistence API is referenced in the app or the ceremony layer, asserted by the release audit; secrets live in `SensitiveBytes` and are wiped on every exit path | **Low** |
| App update introduces a malicious card simulation | Simulation is DEBUG-only and compiled out of Release; the exclusion is a build setting, and the audit re-checks the built product | **Low** |
| User error: wrong PIN entered three times | PIN rules enforced before touching the card; the Admin-PIN lockout warning is shown on the reset and PIN screens | **Medium** — user error is not removable |
| Protocol assumption wrong (import template, `0xC4`, `0xCE`) | Fails visibly: rejection status words or a read-back mismatch; all four documented in `m0-hardware-verification.md` | **Low** |
| Extra touch on the **Ed25519** key is not detectable by a counter | PIN + touch still required; touch policy `Fixed` written to UIF `0xD8`; one-touch-per-transaction rule; Desktop verification of what was signed (v0.2) | **Medium** — accepted in exchange for chain coverage (deviation 6) |
| Loss of availability | Mnemonic recovery verified by the restore path; two steel plates | **Low** (operational) |

## UI defects found and fixed by automation

The setup screen originally used `Picker(.inline)` for the mode choice. On
iOS 26 that renders as a **wheel** — a 216pt control whose selected value is
already the default — so tapping "Generate a new wallet" did nothing and the
screen appeared broken. Beyond the picker itself:

* the primary action sat at the bottom of a very long scroll view and was
  disabled without saying why, so a tap near the top of the screen appeared to do
  nothing;
* the transport rows exposed accessibility labels of `"NFC, Hold the iPhone
  against the YubiKey…"` (title concatenated with description), which read badly
  in VoiceOver and could not be addressed by name.

Fixes: selection is now made with explicit tappable rows carrying a `selected`
trait and a title-only accessibility label; the primary action is pinned in a
bottom bar and states the reason when disabled; explanatory and reference
sections are collapsed so the controls fit on the first screen.

`ios/PlexVaultUITests` now drives the real app in a simulator and locks all of
this in, including an assertion that the mode rows are visible and unobscured on
launch. Running the audit's sibling check by hand would not have caught any of
it: the defect was only visible by tapping the actual screen.

## What would raise confidence most, in order

1. A third-party audit focused on the generation flow, the two import templates
   (secp256k1 and Ed25519) and the UR encoder (§11 v0.5 in the design).
2. The M0 hardware verification pass (`docs/m0-hardware-verification.md`).
3. Implementing the signing flow and the Desktop verifier, which is what makes the
   scheme's central claim testable at all.
4. Making dice authoritative again, which would add a third independent entropy
   source on top of the card-RNG-plus-iOS-CSPRNG XOR.

## v0.2: the risks signing introduces

Signing changes the app's role: it stops being a device that only ever writes keys and
becomes one that hands signatures out. The new surface, and what is accepted about it.

### The camera is now an input channel

The app's only inputs used to be the operator and the card (the transport is the same
channel). It now also reads QR codes, so a hostile QR code is a way to reach the parser.
Mitigations: the request is decoded strictly (unknown CBOR fields are refused, the payload
must match its declared `data-type`, the transaction must survive a decode/re-encode
equality check, and a signed or chain-id-less transaction is refused); nothing is acted on
until the operator approves a summary built from the *decoded* fields; and the bytes that
reach the card are recomputed from the approved transaction. What is accepted: a QR code
can still be a *social* attack vector — a request that is internally consistent and does
something the operator does not recognise. That is why the summary leads with the recipient,
the value and the decoded function, and why an unparsable call is labelled rather than
summarised.

### The display is still not trustworthy, and now it matters more

v0.1's threat model treats the phone as a possibly tampered display terminal, and that was
mostly about the mnemonic. During signing, a tampered phone could show one transaction and
sign another: the app's decode/re-encode check and digest binding make that harder inside
one app, but cannot survive a compromised app binary. The independent check is the wallet's
§5.1 step 16.5 verification — verify the signature against the account, and reject on
failure. The app may not be trusted to be the verifier of its own signature; it is trusted
only to display what it will sign, and the wallet is trusted to check the result.

### Interop depends on another implementation's conventions

The recovery value (`v`) follows MetaMask's own consumer code: y-parity for typed
transactions, the full EIP-155 value for legacy ones. For legacy transactions on chain ids
above 110 that value does not fit the 65-byte layout, so the app emits a wider field. This
is verified against the consumer's source and its own validation rules, but a *real* wallet
on such a chain is still an open hardware item (docs/m0-hardware-verification.md item 14).
Accepted: until that check is done, treat legacy signing on a chain id above 110 as
unverified.

### What the app does not sign, and why that is safe

`personal_sign`, EIP-712 and Bitcoin PSBTs are refused. Refusing is the conservative
choice: each has its own hashing and its own signature convention, and reusing the
transaction path for them would produce signatures that fail in ways that look like the
wallet's fault. Ed25519 signing is refused for a deeper reason — the applet hashes the
message itself for EdDSA, so the digest-in contract of §6.1 does not hold, and v0.2 does
not guess.

### The counter is evidence, not a gate

The app reads the card's signature counter before and after a signature, which is useful
evidence for the operator. It cannot be the control §5.2 rule 4 describes: the party that
displays the transaction must not be the party that reads the counter, and here it is the
same phone. The wallet's independent read remains the control; the app's numbers are a
convenience and a prompt to do it.

### Residual risks left over from v0.1 that signing inherits

- One key per algorithm, one account per card (§10 item 1, item 11): a wallet that
  enumerates sibling accounts will offer addresses this card cannot sign for. The app
  refuses those requests rather than signing the wrong account, and the pairing code pins
  the derivation path — but the wallet may still *show* a sibling before the refusal.
- The Ed25519 key has no counter (§10 item 2b), and v0.2 does not sign with it, which
  removes the question for now.
- Firmware is closed source (§10 item 7): the `PSO:CDS` behaviour the app relies on —
  DER output, touch semantics, status words — is black-box verified at best, and
  docs/m0-hardware-verification.md items 13–14 are what stands in for a firmware audit.
