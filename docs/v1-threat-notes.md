# v0.1 threat notes, deviations and residual risk

This complements §9 of `design.md`. It records what v0.1 actually implements,
where it deviates from the design, and which risks are *accepted* rather than
mitigated — so that no reader mistakes a v2 design intent for a shipped control.

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

### 1. Entropy: system CSPRNG authoritative, dice non-authoritative

**Change.** §4.2 step 4 now says `SecRandomCopyBytes` is the sole authoritative
source; dice are recorded as a witness only. The dice→mnemonic cross-check in
§4.2 step 6b and Appendix B is removed.

**Why.** This was an explicit product decision. Implementing dice as an entropy
source requires a specified, published dice→entropy function so that an
independent tool can reproduce the mapping; without one, the Appendix B check
would be unverifiable, which is worse than not claiming it.

**Consequence, stated plainly.** The "backdoored RNG" node of the §9.4 attack tree
is no longer mitigated. A tampered app or OS RNG could produce a mnemonic of its
own choosing, and nothing in v0.1 catches this: the independent cross-check that
would at least have compared addresses was removed (amendment 8). §9.5 records
this as **Medium** residual risk.

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

### 4. Pairing export omits the chain code; no `crypto-account`

**Change.** §6.4.

**Why.** One YubiKey signature slot holds one key (§4.3). Exporting a chain code
invites a wallet to derive child addresses that this card *cannot sign for*, which
would let a user send funds to an address they cannot spend from. Emitting
`crypto-account` / `account-descriptor` has the same problem: an account-level
descriptor describes derivable children. v0.1 therefore exports a single
address-level `crypto-hdkey` with no chain code, and offers chain-code export only
behind an explicit acknowledgement that is recorded in the report.

**Consequence for MetaMask.** MetaMask's QR hardware flow is built around the
Keystone UR family, which keys off an account-level extended public key. With one
key on the card, MetaMask may import the key but cannot enumerate further
accounts. The app therefore also shows the address in large monospace type and
requires the operator to confirm the wallet displays the same address. Automatic
account discovery is a v0.3 concern (custom Desktop client). This is a genuine
interoperability limitation, not a defect in the export.

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
| Backdoored/faulty entropy source | **None** (see deviation 1); the entropy commitment binds the record | **Medium** |
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
4. Making dice authoritative again, which returns the backdoored-RNG risk to Low.
