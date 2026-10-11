# PlexVault support

Support for PlexVault is by email: **support@plexsec.com**

Please say which iPhone or iPad you are using, which YubiKey model and firmware version, and
which connection you chose (NFC, USB-C, or the Simulated card). A screenshot of the screen you
are on helps, and the app's own record screen can be saved as an image if the problem is about a
provisioning run.

**Never send your mnemonic, your PINs, or your private keys — to us or to anyone.** PlexVault
will never ask for them outside the provisioning ceremony, and no support request needs them.

## Before you write: the things that are not faults

* **Your wallet shows the same address for every account index.** This is intended. The app
  writes one key per algorithm to the card and exports the account-level key with the card's leaf
  pinned, so every entry in your wallet's account picker is the same address — the one on the
  card. Adding a second index duplicates it, and some wallets refuse it.
* **The app asks you to quit and reopen it in the middle of provisioning.** Provisioning is two
  processes by design: the first generates the keys, writes the cards and wipes its own copies;
  the second reads the pairing codes back out of the card. The keys are never in memory while the
  pairing codes are on screen.
* **A failed touch ends the signing attempt, and the app will not retry it.** One transaction
  permits exactly one touch. If an app ever asks you to touch twice for the same transaction,
  treat it as compromised and stop.
* **The card connection screen has no NFC option on an iPad.** No iPad has an NFC reader. Use a
  YubiKey 5C NFC over USB-C, or a phone.
* **The "Simulated card (demo)" produces no valid signature.** It is a card simulated inside the
  app, for walking the app without hardware. Its signatures are not real, and the app will tell
  you the signature did not verify. Do not use it for a wallet that matters.

## What you need

* A **YubiKey 5 NFC** or **YubiKey 5C NFC**, firmware **5.2.3 or later** (secp256k1 support).
* An iPhone with NFC for the contactless path, or an iPhone 15 or later for the USB-C path.
* For signing: a desktop wallet that supports QR-based hardware signers, such as MetaMask's
  QR hardware flow.

## Recovering

* **Lost or broken YubiKey:** restore from your paper mnemonic with a new YubiKey, using the same
  app, and re-pair your wallet.
* **Blocked User PIN:** unblocking needs the card's Admin PIN. Re-provisioning the card from the
  mnemonic also works and erases both keys on that card.
* **Card that will not pair:** the card connection screen can reset the applet; then re-pair from
  the wallet. You do not need the mnemonic for pairing.
