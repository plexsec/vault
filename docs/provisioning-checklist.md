# Operator procedure and checklist (v0.1)

Everything here happens on the **offline iPhone** unless a step says otherwise.
The app enforces the step order mechanically, so if it refuses to advance, do not
look for a way around it — the ordering gates are the security property.

**Print this and tick it off. Record the blanks on your steel-plate paperwork.**

The same procedure is in the app, under **How it works → Manual** (amendment 49); this file is
the full one, and is what the in-app copy is checked against.

---

## Part 1 — Prepare

- [ ] YubiKey 5 NFC or 5C NFC, firmware ≥ 5.2.3, from an official channel
- [ ] Tell the app how the YubiKey is connected — it asks once, on first launch (NFC, or USB-C
      with the key plugged in), and remembers it. The YubiKey button in the home screen's
      top-right corner shows the connection; change it there if it is wrong (on USB-C it turns
      green once the key is plugged in)
- [ ] (USB-C only) YubiKey OTP interface disabled over USB, or the iPhone
      keyboard will not appear for PIN entry: `ykman config usb --disable OTP`
- [ ] A second YubiKey (optional) for a recovery drill later
- [ ] Steel plate(s) for the mnemonic, plus a punch or engraver — two plates,
      two locations
- [ ] iPhone factory-reset, SIM removed, airplane mode on, no other apps
- [ ] Decide and record both PINs **before** starting: User PIN ≥ 6 digits,
      Admin PIN ≥ 8 digits, different from each other, in your password manager
- [ ] No cameras in the room; no screen recording or mirroring active

## Part 2 — Install

- [ ] Build or obtain the app; note the published main-executable hash
- [ ] `tools/hash-app.sh --no-build` (or the published record) reproduces that hash
- [ ] Install onto the iPhone (sideload via Xcode is recommended)
- [ ] Launch, and on the first screen confirm:
      - [ ] App binary SHA-256: `________________________________`
      - [ ] It matches the published hash ✔

> **Free personal team:** the profile expires after 7 days. Re-install from Xcode
> over the same bundle to continue; the app keeps no secrets, so nothing is lost.

## Part 3 — Ceremony

Follow the app. The checklist below is the same sequence, so you can confirm each
step completed rather than trusting the flow: the keys are generated first, then each
YubiKey is reset, configured and written in its own pass, then the secrets are wiped and the
app closes itself, and pairing the wallet is the second process that follows.

- [ ] **Posture + rules** acknowledged
- [ ] **Entropy commitment** (first 8 hex digits of SHA-256 of the entropy read
      from the YubiKey's hardware RNG):
      `________`
      - [ ] (Optional, non-authoritative) dice rolls ≥ 99 recorded:
            `________________________________________`
- [ ] **Mnemonic** — 24 words revealed by holding the screen
      - [ ] Transcribed onto steel, **twice**
      - [ ] Back-fill check passed
      - [ ] Or: the backup was **declined** on purpose, and the number of YubiKeys written in this
            run is what the keys now live in (write that number down)
- [ ] **Derivation** — both keys derived
      - secp256k1 path `m/44'/0'/0'/0/0`
        - EVM address from this device: `______________________________________`
        - Bitcoin address from this device: `__________________________________`
      - Ed25519 path `m/44'/501'/0'/0'`
        - Public key from this device: `______________________________________`
- [ ] **How many YubiKeys** — 1 to 5. Every card gets the same two keys; each gets **its own**
      User PIN and Admin PIN, and the retry limits below are one choice written to all of them.
      Number chosen: `______`
- [ ] **Repeat this block once per YubiKey**, in the order the app asks for it:
      - [ ] **Card inventory** read
            - Serial recorded: `________________`   Applet: `__________`
            - [ ] The serial is one you have not already written in this run (the app refuses a
                  card it has already provisioned, rather than resetting it)
      - [ ] **Reset** — **no PIN is asked for.** The app blocks both PINs and then terminates the
            applet, exactly as `ykman openpgp reset` does, so neither the factory default nor your
            own Admin PIN is relevant here
            - [ ] Warning understood: this erases every key on the applet, and the tap must **not**
                  be interrupted — if it is, the card is left with both PINs blocked and the old
                  keys still in place, and tapping reset again (still no PIN) is what finishes it
      - [ ] **PINs set for this card** — both recorded in the password manager, keyed by serial ✔
      - [ ] **PIN retry limits** — one number **per password** (User PIN / Admin PIN): `______` /
            `______`. The same numbers go on every card in the run
            - [ ] The report shows both, as the card reported them back
      - [ ] **The card, written and verified in one step** — keys, then the touch/PIN policy after
            the last key (writing a slot's algorithm attributes would otherwise discard it), then
            the pairing manifest, then all of it read back off the card. One action, one screen:
            the step shows "Continue" only once every value has come back
            - [ ] Both public keys read back and matching the derived keys ✔
            - [ ] The same screen reports the policy read back off the card: touch policy **Fixed**
                  on both slots, PW1 status `0x00`, and both PIN retry limits as chosen. Anything
                  else leaves the app on this step, and the card must be reset rather than used
            - [ ] Pairing manifest stored on the card, and read back byte-for-byte ✔ — a card that
                  cannot store it, or that hands back something else, stops the ceremony on this
                  step rather than finishing without it
            - [ ] No step asked for a second touch, and no screen was left between a write and its
                  proof
- [ ] **Wipe secrets** — the end of the **first process**: it clears the mnemonic, the seed and
      both private keys out of the app's memory and produces the provisioning record. The app does
      not close itself here
      - [ ] The record is on screen: **save it** (Save to Photos or Copy) — it says what was written to which
            card, and it is the only artifact that can say so
      - [ ] **Quit & Reopen App** ends this process — confirm the alert, which says the next launch
            goes straight to pairing. Nothing else closes the app, and the record is gone once you
            leave it
      - [ ] Understood: the words cannot be shown again after this. If the notes above record that
            you **declined** the paper backup, the YubiKey(s) just written are the only copy of both
            keys
- [ ] **Reopen the app to continue pairing** — this is the **second process**, and it is the reason
      the app closed: it opens straight on the pairing flow (no home screen, no setup screen)
      - [ ] Hold the YubiKey you just provisioned against the phone and tap **Read YubiKey**
      - [ ] **Read pairing manifest** — no PIN is needed. The app checks the stored manifest against
            the keys the card reports for its own slots and refuses if they disagree. A card that was
            reset, or provisioned before the manifest existed, has nothing to pair from: the way
            back is a full ceremony with the mnemonic
      - [ ] Nothing is written to the card in this process, and no mnemonic or PIN is entered
- [ ] **Pairing** — **two** QRs shown (secp256k1 and Ed25519) and scanned
      - [ ] The wallet shows the same EVM/Bitcoin addresses as the app ✔
      - [ ] The wallet shows the same Ed25519 public key as the app ✔
      - [ ] You have acknowledged that the pairing code carries a chain code
            (required by Keystone/MetaMask) and that only the address shown can
            be signed for
- [ ] **Finish** — the **pairing record** is on this step (public data only): the public keys,
      paths and chain codes, read back out of the card's manifest. Two records, one per process, each
      saying which half of the run it is
      - [ ] Save it (Save to Photos or Copy) before leaving: this step *is* the pairing process's record screen
      - [ ] **Finish** completes the ceremony and returns to the home screen — no restart is needed
            before another ceremony

## Part 3b — Re-pairing later (read-only, no reset)

Use this when the pairing codes are lost, or when a second desktop wallet has to
be paired, and the YubiKey is already provisioned. It is the mode to prefer over
re-running Part 3: **nothing is written and the card is not reset**, so the keys
stay in the card. It is also the recovery route when the app has been reinstalled
(the app stores nothing, so a fresh install can still re-pair).

- [ ] Confirm the card is the one you think it is (serial from Part 3:
      `________________`)
- [ ] Choose **Re-pair this YubiKey** in the app
- [ ] **Card inventory** read — the app must *not* warn about erasing a key; if it
      does, you are in the provisioning flow, not this one. Stop
- [ ] **Read pairing manifest** — no PIN is asked for. This is expected: the object
      is readable without one by design
      - [ ] The app shows *"The stored manifest matches the keys in this YubiKey"*.
            **If it refuses instead, do not proceed**: the manifest is stale, was
            written for another card, or the card was reset. Re-pairing means
            re-running Part 3 with the steel plate, which resets the card
      - [ ] The serial shown matches the card in your hand
- [ ] **Pairing** — the same acknowledgements as Part 3: two QRs, addresses
      compared against the wallet
- [ ] Nothing to restore afterwards: no secrets were entered, and the card was not
      modified

> A card that has been **reset** has no manifest — `TERMINATE DF` erases it with the
> keys — so it cannot be re-paired from old material. That is the intended way to
> "forget" a pairing.

## Part 4 — Afterwards

- [ ] Store the two steel plates in separate, secure locations
- [ ] Store the **provisioning record** with the plates (it holds no secrets), and the **pairing
      record** from the second process with it
- [ ] Store the record of which YubiKey serial holds which address
- [ ] If the app is reopened for any reason and opens straight on the pairing flow, that is the
      pending pairing from the run that just finished: pair it, or leave the flow (the app stops
      offering it after that)
- [ ] Run one **recovery drill** on the spare YubiKey (§8.3): repeat Part 3 from
      the mnemonic (Restore mode), confirm the public key matches, then reset the
      spare
- [ ] Re-check the steel plates quarterly for legibility

## Part 5 — Ongoing audit

- [ ] The wallet verifies every signature it receives, against the digest it sent and the
      account it holds, and keeps its own record of what it asked for. This app keeps no such
      record and reads no card-side count: a YubiKey is used with other applications too, so a
      signature count on the card says nothing about what this wallet asked for
- [ ] Exactly one touch per transaction. A second request for the same
      transaction means the display device is compromised — stop

---

## What "one touch per transaction" means in v0.1

There is no signing in v0.1, so the rule does not yet apply. It is still repeated
in the app because the habit matters, and because a v0.1 card is exactly the card
that v0.2 will sign with.

## PIN retry limits

The ceremony asks how many wrong PIN entries **each** password tolerates before the card blocks
it — two numbers, because the User PIN is typed on every signature and the Admin PIN almost never.
Choose each deliberately:

- **3** (the card's factory value) is the strictest sensible choice and the smallest brute-force
  budget for a 6-digit PIN.
- Higher numbers tolerate more typos, and also give an attacker with the card more guesses.
- A longer budget for the User PIN and a shorter one for the Admin PIN is a coherent choice: the
  Admin PIN is the one you rarely type, so typos are less likely and a lockout hurts more.
- Either way, the consequence of using them up is the same: a blocked **User PIN** stops every
  signature (unblocking needs the Admin PIN and a command this app does not implement yet, so plan
  on re-provisioning from the 24 words), and a blocked **Admin PIN** ends provisioning and
  re-pairing for that card — though the app's reset step can still clear it, without a PIN. Both
  paths end with the keys erased from the card and rebuilt from the mnemonic, so the 24 words are
  the only thing that has to survive.

