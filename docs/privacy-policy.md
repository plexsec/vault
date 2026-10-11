# PlexVault privacy policy

**PlexVault collects nothing.** It has no networking code at all — it cannot send anything
anywhere, because no network framework is linked into it, and the release audit asserts that
mechanically rather than promising it.

Contact for anything on this page: **privacy@plexsec.com**

## What the app does with your data

**Nothing leaves your device.** There is no account, no sign-in, no server, no analytics, no
crash reporting and no third-party SDK. There is nothing to opt out of.

**Nothing about you is collected, stored or shared** — not your wallet, not your addresses, not
your transactions, not your mnemonic or your PINs.

## What the app uses, and why

| Permission | Why | What happens to it |
|---|---|---|
| **NFC** | To talk to a YubiKey 5 over its OpenPGP applet, to write the keys to it and to ask it to sign | Read in the moment and discarded — the card's answers are not stored, logged or transmitted |
| **Camera** | To read the unsigned transaction your wallet shows as a QR code | Decoded frame by frame in memory and discarded. Nothing is recorded, and no image is written anywhere |
| **Add to Photos** | Only when you ask the app to save your provisioning record as an image | An explicit, add-only write of one image you asked for. The app never reads your photo library |

## What the app remembers on your phone

Three values, none of them secret, all of them in the app's own storage:

1. **Which connection the YubiKey is on** (NFC or USB-C) — a setting about the phone's reader,
   asked once.
2. **A flag** saying a provisioning run stopped between wiping its secrets and showing the
   pairing codes, so the next launch can continue with the pairing step.
3. **The demo card's state** — only if you chose the "Simulated card (demo)" connection, which is
   a card simulated inside the app for trying the app without hardware. Its keys are not real and
   are not on any YubiKey.

Your mnemonic, your PINs and your private keys are **never** written to the phone. They exist in
memory during provisioning only, and are wiped when the keys have been written to the card.

## Deleting everything

Deleting the app deletes all three values above. Nothing remains anywhere else, because nothing
was ever sent anywhere. The keys themselves live on your YubiKey; wiping the YubiKey (a full
OpenPGP applet reset) erases them.

## Where the keys are

After provisioning, the signing keys exist only inside your YubiKey. Your paper backup of the
mnemonic is yours, on paper, and the app neither needs it nor asks for it again in order to sign.

## Changes

If this policy ever changes, the app's listing and this page will both say so, and the app will
still collect nothing.
