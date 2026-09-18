# Operator procedure and checklist (v0.1)

Everything here happens on the **offline iPhone** unless a step says otherwise.
The app enforces the step order mechanically, so if it refuses to advance, do not
look for a way around it — the ordering gates are the security property.

**Print this and tick it off. Record the blanks on your steel-plate paperwork.**

---

## Part 1 — Prepare

- [ ] YubiKey 5 NFC or 5C NFC, firmware ≥ 5.2.3, from an official channel
- [ ] A second YubiKey (optional) for a recovery drill later
- [ ] Steel plate(s) for the mnemonic, plus a punch or engraver — two plates,
      two locations
- [ ] A second, independent device for the address cross-check (laptop, tablet,
      or another hardware wallet), with `tools/derive` ready to run offline
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
step completed rather than trusting the flow.

- [ ] **Posture + rules** acknowledged
- [ ] **Card inventory** read
      - Serial recorded: `________________`   Applet: `__________`
- [ ] **Reset** (Admin PIN: factory default `12345678`)
      - [ ] Warning about irreversible Admin-PIN lockout understood
- [ ] **PINs set** — both recorded in the password manager ✔
- [ ] **Policy applied**
      - [ ] Touch policy reads **Fixed**
      - [ ] PW1 status reads `0x00`
- [ ] **Entropy commitment** (first 8 hex digits of SHA-256 of the entropy):
      `________`
      - [ ] (Optional, non-authoritative) dice rolls ≥ 99 recorded:
            `________________________________________`
- [ ] **Mnemonic** — 24 words revealed by holding the screen
      - [ ] Transcribed onto steel, **twice**
      - [ ] Back-fill check passed
- [ ] **Derivation** — chain and path confirmed
      - Path: `______________________`
      - Address from this device: `______________________________________`
- [ ] **Import** completed without a second touch request
- [ ] **Read-back** verified: the YubiKey's public key matches the derived key ✔
- [ ] **Independent cross-check** (§4.2 step 6b) — on the *other* device:
      ```
      tools/derive/.venv/bin/python derive.py --mnemonic "<your 24 words>" --coin eth
      ```
      - [ ] Address from the independent tool: `______________________________________`
      - [ ] Both addresses match character by character ✔
      - [ ] Tool and device recorded: `____________________________`
- [ ] **Pairing** — QR shown and scanned by the desktop wallet
      - [ ] The wallet shows the same address as the app ✔
      - [ ] (If you enabled chain-code export) you have accepted that child
            addresses cannot be signed for by this key
- [ ] **Counter baseline** reads **0** ✔
- [ ] **Teardown** — secrets wiped, provisioning record saved
- [ ] Restart the app before any further ceremony

## Part 4 — Afterwards

- [ ] Store the two steel plates in separate, secure locations
- [ ] Store the provisioning record with the plates (it holds no secrets)
- [ ] Store the record of which YubiKey serial holds which address
- [ ] Run one **recovery drill** on the spare YubiKey (§8.3): repeat Part 3 from
      the mnemonic (Restore mode), confirm the public key matches, then reset the
      spare
- [ ] Re-check the steel plates quarterly for legibility

## Part 5 — Ongoing audit (once signing ships in v0.2)

- [ ] After every signing session, read the YubiKey signature counter and compare
      with `expected_counter`
- [ ] `actual > expected` means the card signed something you did not ask for:
      migrate assets immediately
- [ ] Exactly one touch per transaction. A second request for the same
      transaction means the display device is compromised — stop

---

## What "one touch per transaction" means in v0.1

There is no signing in v0.1, so the rule does not yet apply. It is still repeated
in the app because the habit matters, and because a v0.1 card is exactly the card
that v0.2 will sign with.
