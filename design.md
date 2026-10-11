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
- **General-purpose phones as cold wallets** (AirGap Vault, an old phone plus an open-source app): good screen and camera, but the private key resides in a general-purpose OS's storage, with no physical touch confirmation.
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
- **No message signing.** The app signs *transactions*: `data-type` 1 (legacy) and 4 (EIP-2718 typed). `personal_sign` (EIP-191) and EIP-712 typed data are refused with an explanation rather than signed with a transaction's `v` convention, which would produce a signature no wallet accepts. EIP-712 in particular is not a small addition: it needs the full structured-hashing encoder.
- **No Bitcoin/PSBT signing yet** (§6.3), and no Ed25519 signing: the OpenPGP applet hashes the message itself for EdDSA (§6.1), so the "pass in a 32-byte digest" contract does not generalise.
- **No in-hardware BIP32 derivation** (§4.3), so the card signs for exactly one account. A request for any other path is refused rather than signed.
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
│  - broadcast       │             │  - relay σ         │                   │  - PIN, touch│
└────────────────────┘             └────────────────────┘                   └──────────────┘
```

| Component | Secrets held | What it can do alone if compromised | What it cannot do |
|---|---|---|---|
| Desktop | None (public key / address only) | Construct a malicious transaction and send it to the iPhone for display | Bypass the user's human-readable confirmation on the iPhone; bypass the YubiKey touch |
| iPhone app | None (holds the mnemonic and both private keys during generation, until the last card has been read back — §4.2) | Display A but sign B (see §9; caught by Desktop verification); socially engineer the user into one extra touch | Export the private key; produce a signature without a touch |
| YubiKey | Private key `sk` | — | Display anything; judge what is being signed |

The trust relationship among the three is: **the user trusts what they read on the iPhone screen; the Desktop uses cryptographic verification to confirm the iPhone did not swap the content; the YubiKey uses physical touch to ensure no extra signatures occur.**

### 4.2 Provisioning (Initialization)

Prerequisites: a **brand-new or factory-reset** iPhone, no SIM, airplane mode; a YubiKey 5 (firmware ≥ 5.2.3, supporting secp256k1).

**Order, and one card at a time.** The operator's run is 1 → 4 → 4b → 5 → 6/7/7b → 2/3 → the wipe → 8 → 9, and it is **two processes**: the first generates the keys, writes the cards, wipes its secrets and produces its record; the operator ends that process from the record screen ("Quit & Reopen App", behind a confirmation — amendment 45), and the second starts when they open the app again, reads the pairing codes back out of the card's manifest, shows them to the wallet and produces its own record. The keys are generated on the device first, then the count of YubiKeys is chosen, then **each card is reset, configured and written in its own pass** (steps 2 and 3, repeated once per card), then the secrets are wiped, and only then are the pairing codes produced — in the process that follows. The step numbers below are content markers, not the app's screen order — they are kept because the code and the other documents point at them. The wipe and the process boundary have no numbers of their own: they are the bold paragraphs before step 8, because they are ordering facts about the app rather than pieces of the procedure. Everything from step 2 to step 7b is per-card work except `4b` and the mnemonic: every card holds the same two keys and gets **its own User PIN and Admin PIN**, while the touch policy and the retry limits are **one decision per ceremony**, written to every card (amendment 40).

1. **Install the app.** Two options: (a) install the published App Store release, then immediately disconnect and remain permanently offline; (b) sideload from audited source code via Xcode (reproducible build, hash verified). The App Store release is the reference distribution; sideloading is what an operator chooses when the hash-verifiable build matters more than the convenience (amendment 50).

   The difference between the two is **one property**, and it is worth naming: a build compiled from published source can be hashed and compared against the output of `tools/hash-app.sh` before it is trusted, and an App Store install cannot — the binary on the phone is the one Apple signed, and the operator has no independent copy to compare it against. The app is the same code either way, and this design's argument does not rest on the phone being trustworthy (§9 rests it on the wallet verifying what it asked for). What the store route buys is a distribution a non-developer operator can perform, without the weekly re-tethering that a free-team profile forced (amendment 5, superseded). Re-installing over the same bundle identifier preserves the app's data container, and since the app persists no secrets at all, an accidental deletion costs only a re-pairing, not funds.
2. **Reset the YubiKey OpenPGP applet** — once per card, as the first step of that card's own pass (`ykman openpgp reset`; may be done on the Desktop in advance, since the YubiKey holds no secrets yet). The app can also do it, over whichever transport is in use, as `ykman openpgp reset` does it command for command: read `0xC4`, block **both** PINs by sending deliberately wrong `VERIFY`s, read `0xC4` back to confirm they are blocked, then `TERMINATE DF` + `ACTIVATE FILE` + re-SELECT (amendment 30). **No Admin PIN is asked for, and none is accepted.** The applet's access condition for `TERMINATE DF` is "VERIFY of PW3, or Always if PW3 is blocked" (spec 3.4.1), so blocking PW3 first is what makes the PIN-free route available on a card whose Admin PIN still works — and it is how a card whose Admin PIN is **blocked or unknown** becomes resettable in the app rather than only on the Desktop, which is the one state the applet deliberately lowers the barrier for and the one state the previous version could not use (amendment 28). Both keys are erased either way. `TERMINATE DF` leaves the applet *terminated* — wiped and deactivated — and only `ACTIVATE FILE` brings it back; a transport interruption between the two would therefore strand the card. Three consequences are normative: the reset **spends both PIN retry counters on purpose**, so a session that dies after the burn and before the terminate leaves the card with both PINs blocked and its keys still in place — it can neither sign nor be provisioned, and finishing needs no PIN (PW3 is blocked, which is exactly what `TERMINATE DF` wants), so the operator's next tap completes it, while any reset failure returns the ceremony to inspection rather than assuming the card was wiped; `SELECT` on a terminated applet (`6985`/`6285`) is answered by sending `ACTIVATE FILE` and re-selecting, so an interrupted reset heals on the operator's next tap; and because iOS refuses a reader session begun while the previous session's sheet is still being dismissed (CoreNFC error 202), consecutive reader sessions are separated by a cooldown (amendment 15).
3. **Configure YubiKey policies** (done on the iPhone via the app, or in advance on the Desktop) — once per card, in the same pass as its reset, which is what makes the numbers below the card's own:
   - Touch policy `UIF = 0x02` (Fixed: touch permanently required, cannot be disabled later) on **both** signing-capable slots — `0xD6` (signature) and `0xD8` (authentication);
   - `PW1 status (0xC4[0]) = 0x00`: PIN must be re-verified for every signature;
   - Set a User PIN (≥ 6 digits) and an Admin PIN (≥ 8 digits), different from each other. **Every card gets its own two PINs**: they are the card's secrets, not the ceremony's, and the app wipes its copy of a card's Admin PIN as soon as that card is written. The retry limits below are the opposite: one choice for the whole ceremony, written to each card (amendment 40).
   - Choose the **PIN retry limits**: how many wrong entries each password tolerates before the card blocks it (`SET PIN RETRIES`, INS `0xF2`, three bytes — PW1, the resetting code, PW3). The app offers **3 to 10 for each password separately** — the User PIN is typed on every signature and the Admin PIN almost never, so one number is not the right trade for both — and writes both choices in the one command the applet accepts, then reads both counters back out of `0xC4` and refuses to continue unless the card reports exactly those two numbers. The operator makes each choice on the step, with the consequences in front of them, because it cuts both ways: it is the brute-force budget for a 6-digit PIN (§9), and it is also how many typos stand between the operator and a blocked card. Exhausting the User PIN stops every signature until it is unblocked, which needs the Admin PIN (`RESET RETRY COUNTER`, not implemented in this version) or a re-provisioning from the mnemonic that erases both keys; exhausting the Admin PIN ends provisioning and re-pairing for that card, and the only way back is a full applet reset plus the mnemonic — the app's own reset step performs it without a PIN, because it blocks PW3 first and the applet then permits `TERMINATE DF` on its own (amendment 30). A limit that only *appears* to be set is worse than none, hence the read-back (amendment 27; the two independent numbers are amendment 32).

   **The touch policy is written by step 6's key import — after the last key — and read back by step 7.** Writing a slot's algorithm attributes resets that slot, and the applet discards the slot's touch policy with it. Measured on a YubiKey 5C NFC (firmware 5.8.0): `PUT DATA 0xD6 = 02 20` reads back as `02 20` on its own, and as `00 20` — touch **off** — after the key import that follows it in this procedure; the same interaction is reported for `gpg keytocard` in ykman#693. So the policy write is the **last** write that touches those slots, and it is verified rather than assumed: `0x6E` carries `0xD6`/`0xD8`, the app reads them back and fails the ceremony unless the card reports `02 20` on both slots *and* `0xC4[0] = 0x00`. The read-back is not decoration — without it this failure is invisible, because every write answers `9000` while the card ends up with touch disabled: a card the operator believes requires a touch, and which in fact signs without one (amendment 26). There is deliberately **no policy step of its own**: the write lives inside the import step, so the order the applet requires cannot be got wrong by reordering screens, and the read-back step is the single place that confirms the keys and the policy together (amendment 32).
4. **Generate entropy.** The app reads 256 bits from the YubiKey's hardware random-number generator (`GET CHALLENGE`, INS `0x84`) and 256 bits from the iOS system CSPRNG (`SecRandomCopyBytes`), then XORs the two into the **sole authoritative** entropy. Because either source being unpredictable keeps the XOR unpredictable, neither a backdoored card RNG nor a backdoored OS RNG alone can determine the mnemonic. Dice are optional and **non-authoritative**: if the user rolls, the app records and displays the rolls as a ceremony witness, but they do not feed the mnemonic, so a dice sequence cannot be used to reproduce it afterwards (see the amendment in §9.5). The app displays the first 8 hex digits of the SHA-256 of the entropy — the *entropy commitment* — as a ceremony witness for the record.
5. **Generate the mnemonic** (BIP39, 24 words), display it on screen, and offer to have the user transcribe it onto a steel plate. **The backup is the operator's choice, not a gate** (amendment 40): with the words written down and three of them back-filled, the ceremony records `mnemonicBackedUp: true` and the record proves the transcription; declining records `false`, warns in as many words that the cards then *are* the wallet, and carries on. What makes the choice legible is the count of cards, which is asked next (§4.2 step 4b): one card and no paper backup means one device holds everything. This one mnemonic is the backup of **both** keys below.
4b. **Choose how many YubiKeys.** After the keys exist and before any card is touched, the operator says how many cards this ceremony will write (1–5). Each card is then reset, configured, written and read back in its own pass (§4.2 steps 2, 3, 6, 7 and 7b), so the count is what the per-card block is repeated for; every card ends up holding the same two keys, and the report names every one of them. A card this run has already written is refused at its inventory rather than reset — resetting it would erase the keys it now holds.
6. **Derive and import both keys** — **once per card**. From the BIP39 seed the app derives two keys at fixed paths and imports each into its slot via `PUT DATA 0x4D` (Extended Header List):
   - **secp256k1** at `m/44'/0'/0'/0/0` (BIP32) into the **signature** slot (CRT `0xB6`), with algorithm attributes `0xC1 = ECDSA secp256k1 (1.3.132.0.10)`, fingerprint `0xC7`, creation time;
   - **Ed25519** at `m/44'/501'/0'/0'` (SLIP-0010, all hardened) into the **authentication** slot (CRT `0xA4`), with algorithm attributes `0xC3 = EdDSA Ed25519 (1.3.101.112, RFC 8410's `id-Ed25519`)`, fingerprint `0xC9`, creation time.

   The Ed25519 OID is not interchangeable, and it is **GnuPG's** 1.3.6.1.4.1.11591.15.1 — the value `yubikit` uses and `ykman openpgp keys import` sends. RFC 8410's `id-Ed25519` (1.3.101.112) is refused by this firmware with `6A80`; shipping it cost one provisioning run and a corrected amendment (amendment 29, which retracts amendment 26's claim to the contrary).

   If the import fails after one slot has been written, the ceremony says so explicitly and sends the operator back to the inspection step, naming the reset as the way forward: the applet refuses a key into an occupied slot, so "try the import again" can never work (amendment 29).
   The paths are **not** chain-specific: the secp256k1 key serves every secp256k1 chain and the Ed25519 key serves every Ed25519 chain (see §4.3). The app holds the mnemonic and both private keys across the per-card passes — every card is imported from the same two — and wipes them once the last card has been written and read back, before the codes are produced (the paragraph before step 8).
7. **Verify read-back (mandatory), inside the step that wrote the card.** The app reads each public key back out of the YubiKey (`GENERATE ASYMMETRIC KEY PAIR`, `P1=0x81` with CRT `0xB6` and `0xA4` → `7F49` → `86`) and compares it byte-for-byte against the key it derived and imported. **If either differs, the entire procedure is void; restart from step 2.** The same pass reads the policy back: the UIF objects on both signing-capable slots, the PW1 status and the PIN retry limits, each against what step 3 asked for — because every write that establishes a security property is verified rather than assumed, and a card the operator believes requires a touch, and which does not, is worse than an unprovisioned one.

   **Nothing advances between a write and its proof.** Steps 6, 7 and 7b are performed as **one step** in the app (amendment 37): the writes are ordered inside it (policy after the last key, manifest after the keys are verified), and the step completes only once the card has reported every value back. A card that does not report them back cannot reach step 8, and an interruption cannot leave a card holding something this procedure has not confirmed.
7b. **Store the pairing manifest on the card**, in the same step as the writes and the read-back (amendment 37). The app writes the public material a wallet needs — the secp256k1 **account** extended public key with its chain code, the Ed25519 key with its chain code, each key's own master fingerprint and the card serial — into the applet's second private-use data object (`PUT DATA 0x0102`; at most 254 bytes, 198 in the current format, version 2).

   The master fingerprint is stored **per key**, not once for the wallet, because a wallet has two masters and they are different numbers: secp256k1 keys are measured against the BIP32 master, Ed25519 keys against the SLIP-0010 master (`tools/derive` computes both, and both are pinned by tests). A UR that names the wrong one describes an origin that does not exist.

   The step exists because a chain code cannot be read out of a YubiKey: the OpenPGP applet stores a key, not a BIP32 node (§4.3), and the chain code lives only in the node derived from the mnemonic. Without it on the card, showing the pairing codes again means re-running this whole procedure, which resets the applet and destroys the keys. With it, the codes are reproducible from the card alone — and the app still **persists no wallet material**: the phone stays stateless, so a re-pair works on a fresh install, a new phone, or after the weekly profile expiry of §10 item 12.

   Which object it goes in is not a free choice; the four private-use objects differ in their access conditions by design. `0x0102` is readable with **no PIN** and writable with **PW3** — measured on a YubiKey 5C NFC, firmware 5.8.0: `0x0101` needs PW2 (the resetting code, which this app never sets), and `0x0103`/`0x0104` cannot be *read* without a PIN, which would defeat the purpose.

   Four properties are normative:
   - **Order.** Written inside the step that writes the keys, *after* the read-back that proves the keys and the policy, so the card is never told to advertise a key that has not been verified to be in it. It is in that step rather than one of its own so that an interruption cannot leave a card holding verified keys and no manifest without the ceremony knowing (amendment 37). `TERMINATE DF` wipes the object, so it can only be written after a reset.
   - **Read-back.** The app reads it straight back and requires the bytes to match what it wrote. Storage that answers with something else is reported and never trusted.
   - **The binding check.** The app derives the pinned child of the stored account node (BIP32 `ckd_pub`) and requires it to equal the public key the card reports for its own signature slot. This is what makes a manifest trustworthy rather than merely present: a stale, foreign or corrupted one cannot pair a wallet to addresses the card cannot sign for.
   - **Failure stops the ceremony.** The manifest is part of what this step writes, and the step's promise is that the card reports back everything it was told. A card whose applet has no private-use objects (they are optional in the spec), one that refuses the write, and one that hands back something other than what was written all stop the step, and the ceremony does not finish: the card has not been provisioned the way the operator was told it would be. The keys and the mnemonic are unaffected, which is why this is reported as itself rather than as a lost wallet, and why the way forward is the reset rather than a second write (amendment 38).

7c. **Re-pair mode (read-only).** Step 7b exists so that showing the pairing codes again does not require this procedure. The app therefore offers a second, read-only route to step 8 that an already-provisioned card can take at any later time: read the card (§4.2 step 2), read the manifest (`GET DATA 0x0102`, **no PIN**), read both public keys back out of the card, verify the manifest against them (§4.2 step 7b's binding check), and produce the codes.

   This mode is **structurally** incapable of writing: it visits only the five steps it needs, and every mutating entry point in §4.2 is gated on the step that puts it in the ceremony, which this route never reaches. No PIN is presented, no mnemonic is entered, and the applet is not reset — so the keys stay in the card, which is the entire point.

   Four properties are normative:
   - **The manifest is untrusted input.** Codes are produced only after the binding check of step 7b has passed. A manifest that is stale, foreign (a different serial), corrupted or written for another wallet produces a refusal, never a code: pairing a wallet to addresses the card cannot sign for is the failure this design exists to prevent.
   - **Read-only refusals are terminal for that card.** If there is nothing usable to read — the object is empty, or absent because the card was reset or was provisioned before the manifest existed — the app says so and names the way back (the ceremony with the mnemonic). It does not fabricate codes and does not offer to reset the card.
   - **A reset erases the manifest.** `TERMINATE DF` wipes the private-use objects with the keys, so a reset card has nothing left to re-pair from. "Forget the pairing" is therefore a reset, and a card that has been reset cannot be re-paired from stale material (§10 item 13).

**The wipe ends the first process, and the record of it is produced there.** The last card's read-back is the operator's last look at private key material: the mnemonic, the seed, both derived private keys, the entropy and the per-card Admin PIN are wiped from the app's memory, and the app then **produces the provisioning record** — the card serials, the read-back comparison, the policy, the retry limits, the backup choice, the entropy commitment. That process ends from the record screen: its "Quit & Reopen App" action, behind a confirmation, is the run's only way out (amendment 45). The record is produced at the wipe because the process that can testify to those facts is about to be gone: after the wipe, nothing in memory can say what was written to which card, and the operator's file is the artifact that has to carry it (amendment 43). The wipe is **derived rather than asserted**: the gate asks whether any secret is actually still in memory instead of trusting that a call happened (amendment 42).

**Pairing is a second process, with its own record.** The next launch goes straight into the pairing step (step 8) rather than to the home screen, because the wallet the run just wrote is not yet paired and nothing else on the phone knows that. That process is the read-only route of step 7c: it reads the manifest out of the card, checks it against the keys the card reports for its own slots, and shows the codes — no mnemonic, no PIN, no write, and no secret in memory at any point, which is why it does not carry the setup screen's posture gate (that gate exists for the process that generates keys and writes cards). The codes are not stored anywhere in between: the card is the source, which is what the manifest is for. It produces **its own** record — the public keys, paths, chain codes and the manifest it read them from — so a run's paper trail is two records, one per process, each saying which half of the run it is.

8. **Export the public keys.** The app encodes **each** public key as its own UR (`crypto-hdkey`/`hdkey`, see §6.4) and displays two QR codes; the Desktop scans both and imports them as hardware-signer accounts. Every code carries a chain code, and the secp256k1 key is exported at its BIP44 account level with `children` pinned to the card's leaf, so an account-enumerating wallet shows the card's address and no sibling it cannot sign for (amendment 14). The Desktop records each public key `P` and the associated address(es).
9. **Small-value test transaction.** The Desktop constructs a small transfer and runs the full §5 flow. Only after signature verification passes and the transaction confirms on-chain may large amounts be transferred in.

### 4.3 Key Model

- One OpenPGP signing-capable slot holds exactly one key, and a ceremony provisions **two**: the **signature** slot holds an ECDSA secp256k1 key, and the **authentication** slot holds an Ed25519 key. Both come from the one mnemonic, at the fixed paths `m/44'/0'/0'/0/0` and `m/44'/501'/0'/0'`.
- The slot assignment is by **algorithm, not by chain**. Every secp256k1 chain shares the one key — the app derives and displays both its EVM address and its native-segwit Bitcoin address — and every Ed25519 chain shares the other. Two keys therefore cover the practical chain landscape, where one key per chain would not.
- Because the path is shared, the same key appears at the same path on every chain of that algorithm. That is deliberate: address reuse and cross-chain linkability are accepted in exchange for covering many chains with one card, and it is why the pairing export pins the derived-child path to the card's single leaf key (§6.4).
- **The hardware signature counter is not read.** The applet counts `PSO:CDS` in `0x93` of `GET DATA 0x7A`, and that counter belongs to the **signature** slot; the Ed25519 key in the authentication slot is not counted at all (`INTERNAL AUTHENTICATE` is not a counted operation). The app does not read, display or compare it: a YubiKey is a shared device — this one is used with other applications, so a count of signatures says nothing about what *this wallet* asked for — and a count the signing app displays about itself is not evidence in any case (§5.2 rules 3–4, amendment 39). PIN and touch authorization still gate both keys, and what replaces the counter as the detection control is the wallet's own verification of the signature it asked for (§5.1 step 16.5).
- The encryption slot (DEC) is not used.
- Multiple accounts beyond this are achieved with additional YubiKeys. The ceremony asks how many cards to write (1–5, §4.2 step 4b) and provisions each one in its own pass, so a spare key can be created in the same run from the same mnemonic: every card holds the same two keys and the same pairing material, and each stores its own manifest (which names its own serial). The report names every card — serial and applet version — in the order they were presented, and the keys are recorded once, because they are the same on all of them (amendment 40). Re-importing a key into a slot resets that slot and invalidates the old public key; re-pairing is required.
- The mnemonic is the sole backup of **both** keys. Recovery = repeat §4.2 steps 6–9 on a new YubiKey; recovered public keys identical to the originals prove successful recovery.

---

## 5. Signing Flow

### 5.1 Sequence

The wallet is the watch-only side: it builds the unsigned transaction, shows it as an
animated QR code, and verifies what comes back. The app is the signer, and the YubiKey
holds the only copy of the key.

```
 Wallet                            iPhone app                        YubiKey
 ──────                            ──────────                        ───────
 1. Serialize the transaction
    unsigned, as sign-data
 2. Wrap as UR eth-sign-request ──▶ 3. Camera: fountain-decode the
    (requestId, data-type,              animated QR, reassemble
     chain-id, derivation-path,         the CBOR
     sign-data)
                                    4. Parse: legacy / EIP-2930 /
                                       EIP-1559, re-encode and
                                       require byte equality
                                    5. Which key this request needs:
                                       its path picks the slot this app
                                       signs with, and a path it cannot
                                       sign is refused **before** the
                                       card is touched
                                                                     6. Read **that slot's** public
                                                                        key, the manifest and the
                                                                        serial — one session, one
                                                                        key, no PIN, no writes
                                    7. Address derived from the
                                       card's own public key
                                    8. Bind to this card: path,
                                       master fingerprint, and the
                                       address if the wallet sent one
                                    9. Chain id: must be agreed by the
                                       request's field and the payload,
                                       and confirmed by the operator
                                   10. Summary on screen: recipient,
                                       value, function (ERC-20 etc.),
                                       raw hex; warnings unmissable
                                   11. Operator approves → the digest
                                       shown is the digest to be signed
                                   12. VERIFY PW1 (user PIN) ────────▶
                                   13. PSO:CDS(keccak256(sign-data)) ─▶ LED blinks, awaits touch
                                                                       User touches ──▶ σ = Sign(sk, H)
                                   14. ◀────────────────────────── DER (r, s)
                                   15. Normalise low-s (EIP-2), recover the
                                       key, require it to be this card's,
                                       and compute the recovery value
                                   16. Wrap as UR eth-signature
                                       (requestId echoed, r‖s‖v), show QR
 16. Scan ◀─────────────────────────
 16.5 **Independent verification** (the wallet, not this app):
      Verify(P, H, σ) and ecrecover(H, σ) == account address
      Any failure → do not broadcast, raise alarm (§5.2)
 17. Assemble the signed transaction, broadcast
```

The request is read **before** the card, because the request is what names the key: the app
takes the request, decides from its path which single slot it needs, and then reads that
slot. That is one key read and one session, where the previous order ran an inventory on the
way in — which probes *both* slots, because that is what an inventory is for — plus the
manifest, in four sessions, before it knew whether the request was one this
app could serve at all (amendment 33). The address that will sign is therefore derived one
step later than it used to be, and it is compared with the wallet where it always had to be
compared: on the summary screen, before approval. Steps 4–11 are gates in `SigningCeremony`;
the view layer only renders them.

What the app verifies itself, and why it is not optional:

* the request's `derivation-path` and `source-fingerprint` are the card's pinned path
  and its master fingerprint — a wallet paired to another wallet's key ring would
  otherwise get a signature from a key it is not watching;
* an `address` field, when the wallet sends one (it does not for transactions), is the
  address the card's key derives;
* the bytes hashed are the bytes displayed: the transaction is re-encoded from the
  decoded fields and must reproduce the input exactly, and the digest is recomputed
  from the approved transaction rather than taken from the screen;
* the signature recovers **this card's** key, by recovery and by libsecp256k1
  verification. A signature that does not produce no QR at all.

Step 16.5 stays where it is: the wallet is the independent party. The app's own check in
step 14 protects against a card that signs with another slot; it cannot protect against
the app itself.

**The handoff happens where the decode happens.** The scanner reports a complete request
through a callback the signing flow installs, and the flow is what gives it to the ceremony.
The camera and the DEBUG sample both enter through the scanner's own decoder, so a sample
cannot bypass a step the camera has to pass. The obvious alternative — a view observing the
scanner's state and reacting to it — is how v0.2 first shipped, and with the subscription
missing a real scan decoded the request, displayed it, and stopped dead: nothing was wired to
the state the screen was rendering (amendment 24). A callback fires with the value in hand and
cannot be forgotten by a view. A request the ceremony refuses *before* any approval returns
the scanner to a scanning state, so the operator can point it at another code — the practical
case being a wallet that sent a sibling account's request, which the operator fixes in the
wallet rather than by cancelling here.

**The scanner is stopped whenever the flow leaves it, and carries nothing across.** A
cancel and the app going to the background both stop the camera; returning starts it again,
because a capture session does not survive the background. A request decoded during a
previous visit is discarded rather than offered to the ceremony, for the same reason §5.2
rule 8 gives for ceremonies: a flow that inherits the last run's results shows the operator
something that is no longer true. The one thing that *does* stay on screen is a result or a
failure, since restarting over either would hide what the operator has to read. `scanning`
means the camera is on and nothing else — a state that outlives its camera is how a second
visit to the scanner came to show no picture at all (amendment 23).

**The display is frosted, and nothing depends on seeing it.** The request is decoded from the
session's sample buffers rather than from the screen, so the preview exists only to aim with — and
it can therefore be obscured at no cost: a frosted-glass layer covers it (amendment 36). What is
left visible is shapes and light, enough to centre a QR code. Without that layer the app is a
viewfinder: it holds a legible live picture of the scene in front of the phone on a screen that
other people can see, photograph, or record, and the app cannot tell any of those from the operator
looking at it. The one moment the preview is on screen with nobody watching it — the snapshot iOS
takes for the app switcher — is redacted rather than left holding the last camera frame.

### 5.2 Rules

1. **One transaction = one `PSO:CDS`.** At the specification level, the app is forbidden from retrying a signature for the same request. If the YubiKey returns any error (wrong PIN, touch timeout, NFC disconnect), the entire flow terminates and restarts from the Desktop (which generates a new `requestId`).
   - *Refined for provisioning* (§4.2, amendment 17): a failure splits into two kinds. A **definitive rejection** — the card answered, and answered no (wrong PIN, unmet preconditions, rejected import) — wrote nothing, so the operator may correct the cause and repeat the step. An **interruption** whose outcome is unknown (a session that ended mid-write) means the card's state is unknown, and the ceremony must return to card inspection before anything else happens. The distinction is enforced in the state machine, not in the view layer.
2. **Hard rule for users: any single transaction permits exactly one touch.** If the app says "Signing failed, please touch again," the user should treat the app as compromised and stop. This rule must be repeated on the app's first launch, on the Desktop wallet's pairing page, and in the printed quick-start guide.
3. **Nothing reads the card's signature counter any more.** The app does not read, display or
   compare `0x93`, and the provisioning ceremony does not record a baseline. The reason is the
   device's role rather than a defect in the applet: a YubiKey is used with other applications as
   well, so its count of signatures says nothing about what this wallet asked for, and a count the
   signing app displays about itself is not independent evidence in any case (amendment 39).
4. **What replaces it.** The wallet verifies the signature it asked for, against the digest it
   displayed and the account it holds (§5.1 step 16.5), and keeps its own record of what it sent.
   That check is the control: it is made by a party other than the signing screen, which is what
   the counter rule was for.
5. **The iPhone app only displays parsed content and never performs "smart" rewriting.** Undecodable `data` must be shown as raw hex and explicitly labeled "Unable to parse — proceed with caution."
6. **Address binding.** The app refuses to sign any request whose `address` field does not match the locally paired address, preventing the Desktop from mistakenly sending another account's transaction.
7. **chainId confirmation.** A chain id that has not been confirmed in this session requires an explicit, named confirmation before anything is signed for it (§5.3 records why this is per session rather than a remembered allowlist: the things a **release** build remembers between launches are which reader the YubiKey is on and whether a pairing is still pending — neither is a policy, amendments 31 and 43 — and a confirmed chain id is not one of them; the simulated card keeps its own state as well — a third store, which the released build carries now that the demo card ships in it, amendments 44 and 51). The confirmation names the id, so it cannot be a blanket "yes", and the request's `chain-id` field must agree with the chain id inside the transaction payload.
7b. **The signed bytes are the displayed bytes.** The app refuses any transaction whose re-encoded form differs from the bytes it received (a non-canonical encoding is a way to display one transaction and sign another), and the approval names the digest that was displayed, so an approval cannot be carried over to a different payload. What the card is asked to sign is recomputed from the approved transaction.
7c. **One session for PIN and signature.** VERIFY state belongs to a card session, and an NFC session lasts about a minute. `SignerCard.sign(digest:userPIN:)` therefore performs `VERIFY PW1` and `PSO:CDS` in one session; a design that verified in one session and signed in the next would work against a simulated card and fail on hardware with 6982.

7d. **A policy the card does not report is not a policy.** Every write that establishes a security property is verified by reading it back off the card, and a mismatch stops the ceremony rather than producing a card that only looks protected. This is how the touch policy is treated: it is written by the key import — as its last write, because the import itself discards it — and read back from `0x6E` by the read-back step, because an applet that answers `9000` and stores nothing is a real failure mode, not a theoretical one (amendment 26, amendment 32).

8. **A ceremony inherits nothing from the previous one.** Entering setup again — after finishing, aborting, or a re-pair — clears every result the last ceremony produced (inventory, derived keys, read-back, pairing codes, manifest state), and the ceremony screens render from the **current** ceremony's record rather than from whatever the view model happens to still hold. Anything less lets a stale value stand in for a fresh one: a second ceremony that opens on the previous card's inventory offers "Continue" where it must ask for a card read, and a pairing screen showing the previous ceremony's codes offers a wallet keys that may no longer be on the card (amendment 20).

9. **NFC session timeout** (about 60 seconds on iOS): if the touch is not completed within the session, it is treated as failure with no automatic retry. This governs a session in which an operation was **already sent**. Beginning a *new* reader session is a separate case: iOS can refuse one because the previous session has not finished shutting down (CoreNFC error 202), which is a transport race rather than a decision about the card, and the transport waits out a cooldown and retries it (amendment 15). Operator cancellation and the system timeout are never retried.

### 5.3 Wire Format

The two UR types are the Ethereum QR protocol (ERC-4527), as implemented by
`@keystonehq/bc-ur-registry-eth` — the library MetaMask's QR keyring uses. Where the
EIP's CDDL and that implementation disagree, the implementation wins, because it is
what a wallet actually sends.

**`eth-sign-request` (CBOR tag 401)**

| field | type | notes |
|---|---|---|
| 1 | `#6.37(bytes .size 16)` | request id, echoed in the signature |
| 2 | bytes | `sign-data`, at most 16 KiB here |
| 3 | **uint** | `data-type`: 1 legacy transaction, 2 EIP-712, 3 personal message, 4 typed transaction. The CDDL writes this as a tagged map; the implementation writes a bare integer, and a tagged one is refused rather than guessed at |
| 4 | uint | `chain-id`, omitted when 0 |
| 5 | `#6.304(crypto-keypath)` | full path from the master, with the master fingerprint |
| 6 | bytes .size 20 | `address`. **Absent for transactions**, present for messages, so the binding check cannot rely on it |
| 7 | text | `origin` (a dapp name, display only) |

Unknown fields are refused, not ignored: a field this app does not read could be one that
changes what gets signed.

**`sign-data`**

| tx | `data-type` | bytes | digest |
|---|---|---|---|
| legacy, pre-EIP-155 | 1 | `RLP([nonce, gasPrice, gas, to, value, data])` | keccak256 of those bytes |
| legacy, EIP-155 | 1 | `RLP([…, chainId, 0, 0])` | keccak256 of those bytes |
| EIP-2930 | 4 | `0x01 ‖ RLP([chainId, nonce, gasPrice, gas, to, value, data, accessList])` | keccak256 |
| EIP-1559 | 4 | `0x02 ‖ RLP([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList])` | keccak256 |

A legacy payload whose `r`/`s` slots are not empty is a *signed* transaction and is
refused. A transaction with no chain id at all is refused as well: it would be replayable
on every chain.

**`eth-signature`**: field 1 the request id (required — the wallet matches on it and throws
without it), field 2 `r ‖ s ‖ v`, field 3 `origin` (optional). MetaMask reads this with
`ETHSignature.fromCBOR` from the same reference library, and the app's bytes are compared
against that library's in `EthURReferenceTests`.

**The outer CBOR tag is nominal, and no wallet emits it.** ERC-4527 gives these types tags (401
for a request, 402 for a signature), but the type name travels in the UR
(`ur:eth-sign-request/…`) and the payload is a bare map. Measured against
`@keystonehq/bc-ur-registry-eth` 0.22.1 — the library `@metamask/eth-qr-keyring` uses — a
request's CBOR begins `0xa5` and a signature's begins `0xa3`; `0xd9`, which starts a CBOR tag,
never appears. The app therefore writes the untagged form and accepts either (a payload that
does carry the expected tag is read, since some encoders add it and MetaMask's decoder strips
it), refusing any *other* tag rather than guessing. This is not harmless strictness: requiring
the tag meant refusing **every** real signing request while the app's own encoder wrote the tag
too, so encode→decode agreed with itself through a whole test suite (amendment 25). The
reference implementation's bytes are committed as
`Fixtures/eth_ur_reference.json`, generated by `tools/interop/gen-eth-ur-fixture.cjs`, so the
comparison is against what a wallet sends rather than against the app's own output.

The recovery value in byte 64 is the part that is easy to get wrong, because two
conventions are in play and the wallet stores what it is given:

* **typed transactions** (EIP-2930/1559) carry the y-parity, `0` or `1`, because that is
  what the wallet writes into the signature's parity slot;
* **legacy transactions** carry the *EIP-155* value, `chainId·2 + 35 + recid`, because
  the wallet writes that into the `v` slot and the network recovers the sender from it.
  `chainId·2 + 35 + recid` exceeds one byte for chain ids above 110, and the 65-byte
  layout cannot express it, so the field grows to 2–4 bytes in that case rather than
  carrying a wrong value. A wallet reads everything from byte 64 as `v`, and the
  reference implementations' own validation accepts any `v ≥ 37` for a legacy
  transaction. This is the one place where the app deliberately emits something the
  EIP's `.size 65` annotation forbids, because the annotation is unsatisfiable there;
  docs/m0-hardware-verification.md carries the check against a real MetaMask.

**Chain ids are confirmed per session, not remembered.** §5.2 rule 7 asks for a
user-configured allowlist, and this app persists no wallet state (see the release audit: the values
a release build stores are the card connection and the pending-pairing flag, neither of which is a
policy — the third named persistence site is the DEBUG simulated card's own state, which is compiled
out of a release build, amendment 44), so the allowlist cannot exist. The implementation is therefore *stricter*: every chain id is
confirmed by the operator, by name, in the session that signs for it. A remembered list
would be more convenient and less safe.

**Chain names are labels, not a gate.** The screens name the chain and the coin the value
and the fees are denominated in — `Polygon (chain id 137), native token POL` — because
`chain id 137` on its own asks the operator to remember what 137 is, and because a value
row reading `ETH` on a Polygon transaction misnames the one number the operator is being
asked to approve. The table behind it (`VaultKit/Signing/EVMChain.swift`) is a **display
convenience only**: no signing decision consults it, and a chain id it has never seen is
confirmed and signed exactly like a named one — an app that signed only the chains its
author happened to list would refuse legitimate networks, and the check that matters is the
id against the wallet's own screen, which is why the number is always shown. An unknown
chain is displayed as `chain id 424242 (not a chain this app knows)` and its amounts as
`2 native`: it is never given a symbol, because defaulting to ETH is how the mislabelling
came about. Polygon's coin is spelled POL, the name the September 2024 migration gave it,
since that is what the operator will be comparing against on the wallet's screen. Because
Polygon's id is above 110, its *legacy* transactions are also the case that widens the
recovery value (above); its EIP-1559 transactions, which are what a wallet sends by
default, are ordinary 65-byte ones.

---

---

## 6. Cryptography and Protocol Details

### 6.1 Curve and Algorithm

- Curves: **secp256k1** (OID `1.3.132.0.10`) in the signature slot and **Ed25519** (EdDSA, OID `1.3.6.1.4.1.11591.15.1`) in the authentication slot, both supported in the OpenPGP applet on YubiKey 5 firmware ≥ 5.2.3. (The exact EdDSA object identifiers and import encoding are M0 hardware-verification items; see `docs/m0-hardware-verification.md`.)
- Signature **over secp256k1**: ECDSA. The OpenPGP applet's `PSO:CDS` **signs the supplied 32-byte digest directly** without further internal hashing, so keccak256 / double-SHA256 can be computed by the app and passed in. The card returns a DER-encoded `SEQUENCE { r, s }`; the app parses it strictly, normalises `s` to the low half of the curve order (EIP-2 requires it and a high-`s` signature is malleable), and recovers the key to determine the recovery value. Whether the applet itself ever returns a high `s`, and exactly which status word an unanswered touch produces, are hardware items (docs/m0-hardware-verification.md).
- Signature **over Ed25519**: EdDSA is **not hash-then-sign**. OpenPGP delivers the *message* to the card, which applies SHA-512 internally, so the v0.2 signing protocol cannot reuse the "compute a 32-byte digest in the app and pass it in" shape for Ed25519 chains. This is why v0.2 signs transactions only, and refuses Ed25519 signing requests rather than pretending the ECDSA flow generalises.
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
- For each input, compute the sighash (BIP143 for P2WPKH / P2SH-P2WPKH; traditional sighash for legacy) and call `PSO:CDS` one at a time. **Multi-input transactions require multiple touches**; the app states up front "This transaction has N inputs and will require N touches," and the wallet records the N touches it asked for, each as its own request and digest. This is the only exception to §5.2 rule 1, and N is fixed and displayed before signing begins.
- Output: PSBT with `partial_sig` (DER encoding + sighash type).
- Desktop verification: verify each `partial_sig` against the sighash with the corresponding public key; Sparrow does this at finalize, and a custom Desktop must do it explicitly.
- Not supported: P2TR (Schnorr), MuSig within multisig; supported as one ECDSA participant in a multisig (P2WSH).

### 6.4 Data Encoding (UR / QR)

Uses the Blockchain Commons UR (BC-UR) standard, compatible with the Keystone / AirGap ecosystem:

| Direction | UR type | Content |
|---|---|---|
| iPhone → Desktop (pairing) | `crypto-hdkey` (v1 also offers the current `hdkey` naming) | One UR **per key** (secp256k1 and Ed25519): public key, chain code, derivation path, source fingerprint |
| Desktop → iPhone (EVM) | `eth-sign-request` | requestId (UUID), signData, dataType, chainId, derivationPath, address |
| iPhone → Desktop (EVM) | `eth-signature` | requestId, signature (65 bytes) |
| Desktop → iPhone (BTC) | `crypto-psbt` | PSBT bytes |
| iPhone → Desktop (BTC) | `crypto-psbt` | PSBT with partial_sig |

- Data exceeding a single frame uses UR animated QR (fountain-code fragments); the iPhone side supports out-of-order reception.
- **The Desktop must alarm on unknown UR fields rather than silently dropping them** (to prevent the iPhone from exfiltrating data via extra fields; see §9). The custom Desktop enforces this strictly; third-party wallet behavior is listed in §7.1.
- **The pairing export always carries a chain code and a device name.** Keystone and MetaMask refuse a `crypto-hdkey` without a chain code: the JS decoder's `getBip32Key()` concatenates it unconditionally and MetaMask fails the scan with `Cannot read properties of undefined (reading 'length')` (amendment 14). MetaMask also derives the keyring name from field 9 (`name`), and its `getAccountLabel()` does `name[0].toUpperCase()` on confirm — an export without it shows the correct address and then fails with `Cannot read properties of undefined (reading '0')` (amendment 14a). One YubiKey slot holds exactly one key (§4.3), so the export must not invite a wallet to derive child addresses this card *cannot sign for*. The secp256k1 key is therefore exported at its BIP44 **account** level (`m/44'/0'/0'`) with `children` pinned to the fixed path that reaches the card's leaf (`0/0`, no wildcard): an account-enumerating wallet such as MetaMask presents the card's one address instead of siblings. Because a chain code is still present, the operator must acknowledge `PairingPolicy.chainCodeWarning` before the codes are built, and the acknowledgement is recorded in the provisioning report. For the same reason v1 does not emit `crypto-account` / `account-descriptor`.
- **Ed25519 has no derivable children.** SLIP-0010 derivation is all-hardened, so the Ed25519 key is exported at its own path with its chain code and no `children` keypath.
- **Two keys, two codes.** A ceremony produces two single-part-friendly `crypto-hdkey` URs, one per algorithm, and the wallet scans each. BCR-2020-007 defines no explicit curve field, so the curve is discriminated by the length of `key-data` (33 bytes = compressed secp256k1 point, 32 bytes = raw Ed25519 point), reinforced by `use-info` (SLIP-44 coin type 0 and 501). That convention is listed as an interoperability item in `docs/m0-hardware-verification.md`.
- **The Ed25519 identity is the public key.** With one key per algorithm and no chain-specific derivation in v1, there is no single Ed25519 address to display: the app shows the 32-byte public key and uses it for the read-back comparison.

### 6.5 YubiKey APDU Mapping

| Operation | APDU | Notes |
|---|---|---|
| Select applet | `00 A4 04 00 06 D2 76 00 01 24 01` | OpenPGP AID. A `6985`/`6285` answer means the DF is terminated (wiped, deactivated): send `ACTIVATE FILE` and re-select, which is what an interrupted reset leaves behind (amendment 16) |
| Terminate DF (reset) | `00 E6 00 00` | Case-1. Its access condition is "VERIFY of PW3, **or Always if PW3 is blocked**", so a reset blocks PW1 and PW3 first (wrong `VERIFY`s) and terminates afterwards — the Admin PIN is neither asked for nor accepted (amendment 30). Wipes the applet and leaves the DF terminated |
| Activate file (reset) | `00 44 00 00` | Case-1. The only command a terminated DF accepts besides a re-SELECT; the second half of a reset |
| Get challenge (entropy) | `00 84 00 00 20` | Hardware RNG; returns 32 random bytes, XORed with the iOS CSPRNG (§4.2 step 4) |
| Verify signing PIN | `00 20 00 81 Lc <PIN>` | PW1 mode 81. A *wrong* PIN is also sent on purpose: the reset spends both retry counters this way to reach the access condition above |
| Sign | `00 2A 9E 9A 20 <32-byte digest> 00` | PSO:COMPUTE DIGITAL SIGNATURE. Requires PW1 verified **in the same session**. The OpenPGP card specification has ECDSA signatures returned as a DER `SEQUENCE { INTEGER r, INTEGER s }`, and the app parses that strictly; a bare 64-byte `r‖s` is accepted too, since the two forms cannot be confused, and which one the firmware returns is an M0 item (docs/m0-hardware-verification.md) |
| Read public key | `00 47 81 00 02 B6 00 00` | GENERATE ASYMMETRIC KEY PAIR, P1=0x81 (read mode), signature slot |
| Read public key (auth slot) | `00 47 81 00 02 A4 00 00` | Same, addressed at the authentication slot |
| Read application data | `00 CA 00 6E 00` | Includes fingerprints, algorithm attributes, PW status **and the UIF objects `0xD6`–`0xD9`**, which is what the policy read-back reads — no extra round trip, and no PIN (§4.2 step 3) |
| Import private key | `00 DB 3F FF Lc 4D ...` | PUT DATA Extended Header List; requires Admin PIN |
| Write pairing manifest | `00 DA 01 02 Lc <bytes>` | Private-use data object 2. Requires PW3, holds at most 254 bytes (255 answers `6A80`), and is wiped by `TERMINATE DF` — hence written after both the reset and the read-back check |
| Read pairing manifest | `00 CA 01 02 00` | The same object, and the only thing §4.2 step 7c needs from the card. **Requires no PIN**, which is the property the other three objects lack. A never-written object answers `9000` with no data, not `6A88`; an empty answer is a refusal to re-pair, not an error to retry |
| Set PIN retry limits | `00 F2 00 00 03 <PW1> <reset code> <PW3>` | `SET PIN RETRIES`. Requires PW3 verified in the same session, needs firmware 4.3.1+, and takes one byte per password (1–99). The command carries all three counters at once, so the app writes the operator's **two** choices — `PW1` and `PW3`, independently chosen (amendment 32) — and sends the User PIN's number as the resetting code's byte, which is inert: this app never sets a resetting code and the card reports 0 attempts for it either way (measured: `03 00 03` on a fresh card). YubiKey 4/5 leave the PIN values alone — only the old NEO applet reset them — and the counters refill to the new maximum on the next successful VERIFY. Both counters are read back from `0xC4` (§4.2 step 3) |
| Set UIF | `00 DA 00 D6 02 02 20` | Signature slot touch policy Fixed. **Written by the key-import step, after the last key**: writing a slot's algorithm attributes resets that slot and the applet drops its touch policy with it, so the policy write is the last write to those slots and the read-back step is what confirms it (§4.2 steps 3 and 7, amendment 26, amendment 32) |
| Set UIF (auth slot) | `00 DA 00 D8 02 02 20` | Authentication slot touch policy Fixed, same rule |
| Algorithm attributes (auth) | `00 DA 00 C3 09 16 2B 06 01 04 01 DA 47 0F 01` | EdDSA Ed25519 attributes: algorithm `0x16` + GnuPG's OID 1.3.6.1.4.1.11591.15.1, no format byte — exactly `yubikit`'s `EcAttributes.create`. RFC 8410's `id-Ed25519` is refused with `6A80` (amendment 29) |
| Fingerprint (auth) | `00 DA 00 C9 14 …` | 20-byte fingerprint for the authentication slot |

On iOS, NFC uses CoreNFC `NFCISO7816Tag`, declaring `D27600012401` under `com.apple.developer.nfc.readersession.iso7816.select-identifiers` in Info.plist. The wired path is USB-C CCID through CryptoTokenKit (`TKSmartCard`), which presents the YubiKey as a smart-card slot. The APDUs are identical on both transports.

The CCID transport intentionally uses the low-level `TKSmartCard.transmit(_:)` rather than the high-level `send(ins:p1:p2:data:le:)`: the high-level call throws for any status word other than `0x9000`, which would discard the status-word semantics this scheme depends on (`63Cx` retries remaining, `6983` blocked, `6A88` no key present, `6Cxx` wrong Le).

Every transport failure is reported with the reason it failed, not as one generic string. `NFCReaderError` 200–203 (operator cancelled, session timed out, session ended unexpectedly, system busy) each get their own wording, because a session race that says "Session invalidated unexpectedly" is indistinguishable from a card problem to the operator reading it (amendment 15).

---

## 7. Compatibility

### 7.1 Desktop Wallets

| Wallet | Integration | Explicitly verifies returned signature? | Alarms on extra UR fields? | Position of this scheme |
|---|---|---|---|---|
| Custom Desktop (reference implementation) | Native | **Yes (mandatory, §5.1 step 18.5)** | **Yes** | Recommended |
| MetaMask | "QR-based hardware wallet" (Keystone protocol) | Recovers `from` when assembling; mismatched transactions fail at broadcast/node side, but **cannot be considered reliable explicit verification** | No | Usable: the pairing code is Keystone-compatible (account-level secp256k1 export, chain code present, `children` pinned), so MetaMask scans it and shows the card's address for every account index. Recommended to pair with the reference implementation for independent verification before broadcast |
| Sparrow | Camera → UR crypto-psbt | Verifies partial_sig at finalize; **effective** | Partial | Recommended |
| Other Keystone-UR wallets (Rabby, BlueWallet, etc.) | As above | Must be confirmed individually | Must be confirmed individually | Pending verification |

Specification requirement: **any Desktop client claiming compatibility with this scheme must implement §5.1 step 18.5.** Users of third-party wallets should treat §5.2 rule 2 (one touch per transaction) and their own verification of the signature they asked for (§5.1 step 16.5) as the compensating controls.

### 7.2 Hardware

- YubiKey: 5 NFC, 5C NFC (firmware ≥ 5.2.3). Two transports are supported: **NFC** (CoreNFC ISO 7816) and **USB-C CCID** (CryptoTokenKit). Touch behaviour over NFC must be verified per firmware version; the wired path is more reliable for touch confirmation.
- **USB-C and OTP:** the YubiKey's OTP interface registers as a HID keyboard; when it is enabled over USB-C it suppresses the iPhone's on-screen keyboard, so the PIN cannot be entered. Disable it once with `ykman config usb --disable OTP` (this leaves NFC OTP unaffected). The app cannot do this itself: the OTP configuration is managed over the HID interface, which iOS does not expose to apps.
- **Lightning / 5Ci is no longer supported.** The 5Ci required a vendor MFi accessory SDK that YubiKit 4.x dropped, which made it the project's only external SDK dependency and an availability risk. USB-C CCID replaces it using only Apple frameworks, so a YubiKey 5C NFC is the recommended wired key.
- iPhone: NFC requires any model supporting CoreNFC tag read/write (iPhone 7 and later). The **USB-C transport requires an iPhone 15 or later**, or a USB-C iPad. A dedicated device with the SIM removed and permanent airplane mode is recommended.
- Desktop: no longer required for provisioning, nor for anything in the signing flow — the QR channel carries everything: the app neither needs a wired reader nor asks for one.

---

## 8. Operations

### 8.1 Backup

- Engrave the 24-word mnemonic on steel plates, at least two copies, stored in separate locations.
- The YubiKey is **not** a backup. It can be re-created from the mnemonic at any time.
- **The app does not force this** (amendment 40). Provisioning can continue with the words unwritten; the record then says `mnemonic written down: NO`, and the cards it wrote are the wallet. That is a defensible choice when several cards hold the keys — losing one is not losing the wallet — and a poor one when only one does, which is what the card count is asked for and what the step's wording is keyed to. Neither the app nor the record pretends the choice was not made.
- Record the derivation path and the public-key fingerprint from provisioning (public information) to aid verification after recovery.

### 8.2 Recovery

Perform §4.2 steps 2–8 on a new YubiKey; compare the new public key against the recorded fingerprint. If the old YubiKey is still on hand, run `openpgp reset` and then destroy or reuse it.

### 8.3 Audit

- After every signing session: the wallet confirms that the signature it received verifies against the digest it sent and the account it holds (§5.1 step 16.5), and records what it asked for. This app keeps no such record and reads no card-side count (amendment 39).
- Quarterly: check that the steel-plate mnemonic is legible; perform one recovery drill (recover onto a spare YubiKey, compare public keys, then reset).
- App updates: update only after confirming the new version's reproducible-build hash; the update requires the iPhone to touch a computer and is treated as a "generation-phase-level" trust event (see §9). After updating, perform a small-value signature and verify it.

### 8.4 Decommissioning / Migration

- Retiring a YubiKey: reset the applet — the app's reset step or `ykman openpgp reset`, neither of which needs the Admin PIN, since both block PW1 and PW3 and then terminate + re-activate (amendment 30). Three wrong Admin PIN entries change nothing about whether the card can be reset, and the keys are erased either way.
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

1. **Key confidentiality** — after provisioning, `sk` exists in plaintext only inside the YubiKey; the app's own copies (the mnemonic, the seed and both private keys) are wiped when the last card has been read back and written down in its record, and the app is **closed from the record screen** at that point (§4.2) — the run's only way out, behind a confirmation — so no later screen — including the pairing step, which is a separate process — is ever shown with a private key in memory. The mnemonic is the sole backup, handled exclusively in §4.2.
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

The enabling constraint is that **the iPhone never holds the private key, and every signature it can induce consumes exactly one PIN entry and one physical touch.** The iPhone's power is therefore bounded: it can only produce signatures over *some* digest, each costing a user-visible gesture — and each one verifiable afterwards by the wallet that asked for it (§5.1 step 16.5).

### 9.3 Core Argument: Why the Desktop Detects a Tampered iPhone

The Desktop holds the transaction bytes `A` it constructed and the paired public key `P`. On receiving `σ`, it computes `Verify(P, H(A), σ)` (equivalently `ecrecover(H(A), σ) == address`):

- **Honest iPhone**: relays the user's confirmed `A` to the YubiKey and returns `σ = Sign(sk, H(A))`; verification passes.
- **Tampered iPhone** that displays `A` but requests `B ≠ A` from the YubiKey obtains only `σ_B = Sign(sk, H(B))`. ECDSA verification binds `(r, s)` to the specific digest, so `σ_B` verifies against `H(B)` — not `H(A)` — and the Desktop's check fails; it refuses to broadcast.

The iPhone cannot forge a signature over `A` without `sk`, and cannot request a second signature without a second PIN entry and touch. A malicious app therefore cannot simultaneously satisfy Desktop verification and sign a different transaction.

**Consequence: compromising the iPhone app alone cannot steal funds.** To succeed, an attacker must additionally:

1. **Obtain one extra touch** — the first signs the honest `A` (satisfying the Desktop), the second signs the attacker's `B`. This is social engineering: the app must induce the user to touch once more than the transaction requires.
2. **Exfiltrate `B ‖ σ_B` off the offline iPhone** — via a second channel: an observing camera, a colluding Desktop, or physical contact during a future app update.

Condition 1 has to be caught by the party that asked for the signature: the wallet verifies σ against `P` and `H(A)`, and a signature over `B` fails that check (§5.1 step 16.5). Nothing on the card reports it — this app does not read the signature counter, and a count would not name *which* signature was extra in any case (amendment 39). The overall bar is thus on the same order as "hardware-wallet firmware tampered ∧ host compromised ∧ the wallet's own verification bypassed."

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
│   ├── Extra-touch social engineering ── one-touch-per-tx rule; the wallet's own verification of the signature it asked for (§5.1 18.5)
│   ├── PIN brute force ── lockout after the operator-chosen number of attempts (3–10, §4.2 step 3)
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
| iPhone app tampered (signing phase) | Compromise of the iPhone app | Desktop independent verification (§5.1 18.5); one-touch-per-tx rule | Needs an extra touch **and** a second exit channel, and the extra signature fails the wallet's own verification. **Low** |
| iPhone app tampered (generation phase) | Compromise of the iPhone app | Offline fresh device; reproducible-build verification; read-back confirms the card holds the key the app derived | Highest single point of app trust; the independent cross-check that bounded it was removed in v0.1. **Medium** |
| Backdoored or faulty entropy source | Compromise of the YubiKey secure element **and** the iPhone OS RNG | The 256-bit entropy is the XOR of the card's `GET CHALLENGE` and the iOS `SecRandomCopyBytes` (§4.2 step 4); either source alone cannot determine the mnemonic | **Low** — a single compromised RNG no longer yields the key; both independent RNGs must be backdoored, which requires compromising two vendors' stacks at once |
| Counterfeit YubiKey | Supply-chain substitution | Official channels; Yubico attestation; the read-back comparison fails if the card holds a different key | **Low** |
| Weak YubiKey internal RNG (nonce `k`) | — | `sk` is generated on the iPhone, not the YubiKey; no property of `k` is relied upon beyond secrecy | Leaked `k` ⇒ leaked `sk` (inherent ECDSA); depends on Yubico's secure element. **Low** |
| QR channel observed by a camera | Physical observation | Channel content is public (unsigned tx + signature) | **Low** |
| Extra touch on the **Ed25519** key | Compromise of the iPhone app plus one social-engineered touch | One-touch-per-transaction rule; PIN + touch still required; independent verification of what was signed (v0.2) | The extra signature is a signature over *some* digest; the wallet that asked for that digest verifies it, and one it did not ask for never reaches verification (amendment 39). **Low** |
| User under duress | Physical coercion | — (out of scope) | — |
| App delisting / iOS upgrade | — | Standard derivation paths; mnemonic recoverable in any BIP39/BIP44 wallet | **Low** |

---

## 10. Known Limitations

1. **Two fixed keys per YubiKey** — one per algorithm — with no in-hardware BIP32 derivation. Every chain of an algorithm shares the same key at the same path, so addresses are reused across chains and are linkable; multiple accounts require multiple YubiKeys or re-import.
2. **No Taproot / Schnorr support**, due to OpenPGP applet limitations. Ed25519 is supported as a second key, which is what makes the two-slot model cover the practical chain landscape.
2b. **Nothing in this app reads the card's signature counter.** The applet counts `PSO:CDS` in `0x93` of `GET DATA 0x7A`, but a YubiKey is used with other applications too, so the number says nothing about what this wallet asked for — and a count shown by the signing app about itself is not independent evidence (amendment 39). Detection rests on the wallet verifying the signature it asked for (§5.1 step 16.5).
3. **Multi-input PSBTs require multiple touches**, in tension with the "one touch per transaction" rule; mitigated by stating N up front, but this widens the social-engineering surface.
4. **NFC session time limit** (about 60 seconds). The USB-C CCID transport avoids this entirely and is preferred wherever an iPhone 15+ is available; over NFC, each step of a ceremony needs its own tap because the session cannot span the minutes a ceremony takes.
5. **App distribution conflicts with the offline requirement**: App Store installation requires connectivity; sideloading requires a computer. Both are one-time compromises to "permanently offline," classified as generation-phase-level trust events. The published release is the App Store route (amendment 50), which also means the installed binary cannot be hashed against published source — the one property sideloading had and a store install cannot, and the reason §4.2 step 1 documents the sideloaded path rather than retiring it.
6. **The trusted display during the generation phase depends on the app itself; during the signing phase, the Desktop's independent verification provides a backstop.** Generation-phase trust rests on reproducible builds and the read-back comparison; the independent cross-check was removed in v0.1, so this trust cannot be eliminated entirely.
7. **Dependence on Yubico's closed-source firmware.** The OpenPGP applet's behavior can be black-box verified via APDUs, but the internal implementation is not auditable.
8. **The card is shared with other applications.** A YubiKey provisioned here can hold other keys and be used by other software, so nothing on the card identifies which application produced a given signature — which is why no card-side counter is treated as evidence about this wallet (amendment 39). The keys this ceremony writes are separate from every other slot the applet does not touch (the encryption slot is never used), but the *device* is not dedicated, and the design does not assume it is.

9. **Signing covers EVM transactions only** (v0.2). `personal_sign` (EIP-191), EIP-712 typed data, Bitcoin PSBTs (§6.3) and Ed25519 chains are refused with an explanation: the first two need their own hashing and their own `v` convention, the third a PSBT engine, and the fourth cannot use the digest-in contract at all (§6.1). Within EVM the chain set is *open*: any chain id in the request is signable once the operator confirms it, and the app's chain table only decides how the chain and its coin are *named* on screen (§5.3) — so the app cannot be the reason a network is unsupported, and equally cannot vouch for one it does not know. The wallet's verification of the signature it asked for (§5.1 step 16.5) is what bounds this: the app cannot make a signature verify against a digest the wallet did not send.

10. **Dice entropy is non-authoritative in v1** (§4.2 step 4). A backdoored or faulty RNG is mitigated by construction — the entropy is the XOR of the card's hardware RNG and the iOS CSPRNG — so user dice are the one thing that is not fed into the mnemonic. Reproducible builds bound the residual risk further; the independent cross-check that previously provided an additional bound was removed in v0.1.

11. **One key per YubiKey limits desktop-wallet interoperability.** A wallet that enumerates accounts expects an account-level extended public key with a chain code. v1 serves this by exporting the secp256k1 **account** node (`m/44'/0'/0'`) with its chain code and a `name`, and pinning `children` to the card's leaf (`0/0`), so MetaMask shows the card's address rather than a sibling it cannot sign for (§6.4, amendments 14/14a). Two consequences follow and are stated to the operator: every entry in MetaMask's account picker is the same (all signable) address, so re-adding an index duplicates it and MetaMask Mobile rejects a second index; and because the exported key is still an ancestor of the card's key, a wallet that ignores the pinned path can derive unsignable siblings. A custom Desktop client is the clean fix and is v2 work.

12. **The published release cannot be hash-verified, and a sideloaded profile is a yearly ritual** (§4.2 step 1, amendment 50). The App Store install is the reference distribution: it cannot be compared against published source, and it puts the "offline" iPhone in contact with Apple's servers once, at install. An operator who sideloads instead gets the hash-verifiable build and pays for it with a profile that expires — after a year on the paid organisation team this app is released under, rather than the 7 days a free personal team gave (amendment 5, superseded). The app stores no secrets either way, so the worst case of an expired or deleted install is a re-pairing, but the device does periodically come into contact with an online machine, and that belongs in the trust story rather than in someone's memory.

13. **The pairing manifest is public data on the card, and a reset erases it.** The object is also the *only* thing standing between an attacker with the card and a convincing re-pair, which is why §4.2 step 7c checks it against the keys the card reports: the manifest tells a wallet which addresses to display, and a wallet cannot tell a wrong manifest from a right one. What the object cannot do is sign, and what it cannot reveal is a private key — reading it needs no PIN, so a thief who takes the card learns nothing they could not already read out of the signature slot. The material written in §4.2 step 7b is not secret — the public key in the signature slot is already readable without a PIN, and the manifest is exactly what the desktop wallet is told anyway — but anyone who reads the object learns the account-level extended public key, i.e. a watch-only capability and the linkability that comes with it. It also lives inside the applet, so `TERMINATE DF` wipes it along with the keys: a reset is what "forget the pairing" means for this card. Where the applet has no private-use objects at all (they are optional in the spec; verified present on YubiKey 5 firmware 5.8.0), re-pairing falls back to re-running the ceremony with the mnemonic, and the app says so before the ceremony ends.

---

## 11. Roadmap

- **v0.1 (implemented)**: iOS **provisioning app only** — §4.2 steps 2–8 over NFC and one wired transport (USB-C CCID), provisioning **both** algorithms (secp256k1 into the signature slot, Ed25519 into the authentication slot) from one mnemonic. Includes `tools/derive` as a differential-testing oracle (BIP32 + SLIP-0010 + Ed25519, cross-checked against the Swift implementation via committed fixtures), a scripted two-slot card for device-free testing, a mechanical release audit, and BIP39/BIP32/SLIP-0010/RFC 8032/BC-UR conformance tests against published vectors. No signing.
- **v0.2 (implemented)**: EVM signing flow (§5) — read-only card inspection, `eth-sign-request`/`eth-signature` URs, camera scanning, the transaction summary, `VERIFY PW1` + `PSO:CDS` in one session, low-s normalisation and signature verification. The small-value test transaction of §4.2 step 9 is the operator's, and remains outstanding for a real wallet.
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

## Appendix B: Provisioning Verification Checklist (Print Version)

- [ ] iPhone factory-reset, no SIM, airplane mode
- [ ] App hash matches the published reproducible-build hash (sideload method)
- [ ] YubiKey reset; UIF=Fixed; PW1 status=0x00; PINs set
- [ ] Entropy commitment (first 8 hex digits of SHA-256 of the entropy) shown by the app, recorded: `________`
- [ ] (Optional, non-authoritative) dice rolls ≥ 99 recorded as a ceremony witness: `________`
- [ ] Mnemonic transcribed twice; back-fill check passed
- [ ] Both public keys read back from the YubiKey and match the derived keys ✔
- [ ] Both pairing codes scanned; the Desktop shows the same values as the iPhone ✔
- [ ] Small-value test transaction: Desktop verification passed, confirmed on-chain ✔
- [ ] No other camera devices in the generation environment ✔
