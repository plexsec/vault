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

## What was deliberately *not* changed

* **§5.2 rule 1 (one transaction, one `PSO:CDS`) and rule 2 (one touch)** are
  unchanged in the spec and are repeated in the app's UI and the printed
  checklist, even though v1 cannot yet sign. The habit and the user-facing warning
  belong to the workflow, not to the signing code.
* **The mandatory read-back (§4.2 step 7) and the independent cross-check
  (§4.2 step 6b)** are unchanged and are additionally enforced by the state
  machine: the ceremony cannot reach pairing export without them.
* **§9.3's core argument** is unchanged. Nothing in v1 weakens it; v1 simply does
  not yet exercise it.
