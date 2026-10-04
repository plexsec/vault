# Signing checklist

The operator procedure for signing a transaction with a YubiKey provisioned by this app.
Design.md §5 is the specification; this is what to do, and what to look at while doing it.

Provisioning is a separate procedure (`provisioning-checklist.md`). Signing never writes to
the card and never needs the mnemonic — if a screen asks for one, stop.

## What you need

- The iPhone with this app, **offline**.
- The YubiKey that was provisioned, and the **user PIN** (PW1) chosen then.
- The wallet (MetaMask or another Keystone-compatible QR wallet) with the account already
  paired from this card.

## Before the first signature

- [ ] The wallet shows the same address this app shows on the *Read the YubiKey* step. If
      it does not, the wallet is watching a different key: re-pair it (`provisioning-checklist.md`
      Appendix B) before signing anything.
- [ ] The wallet's account is the one holding the funds you intend to move. This app can only
      sign for the single account on this card.

## The procedure

1. **Build the transaction in the wallet** (as small a value as you can make it the first
   time), confirm it there, and choose the QR signing option. The wallet shows an animated QR.
2. **Scan the request.** Tap *Sign a transaction*: the camera opens directly. No card is needed
   for this step, and nothing has been read from the YubiKey yet.
3. **Read the YubiKey.** The request names the key it wants; the app reads **that one slot** and
   says so on screen. Card connection: NFC (hold the iPhone against the key when asked) or USB-C
   (plug it in and leave it). The connection was chosen once, on first launch, and is shown by the
   YubiKey button in the home screen's top-right corner — tap it if the card is not found. No PIN
   is needed to read, and nothing is written.
4. **Check the address on screen** against the account in your wallet. If a request names a key
   this app does not sign with, it is refused before the card is touched.
5. **Read the summary.** This is the screen that matters:
   - **To** — the recipient. If the transaction is a token call, the *Function* row names it
     (`transfer`, `approve`, …) and the amount.
   - **Value** — in ETH. A token transfer shows `0` here; the token amount is in the function's
     arguments, in **raw units**, because the token's decimals are not in the request.
   - **Warnings** — an unlimited approval, or `setApprovalForAll` (which hands over every token
     in the account), is called out. Read them before approving.
   - **Function: unrecognised** — the app could not parse the call. The raw hex is below it.
     Do not proceed on the basis of the summary alone; compare the raw data with what the
     wallet shows, or cancel and rebuild the transaction from a dapp you trust.
6. **Confirm the chain** if the app asks for it. It asks for every chain that has not been
   confirmed in this session, and it names it: `Polygon (chain id 137), native token POL`.
   Compare **both** against the network your wallet is on — the name is a convenience, the
   id is the fact. If the app shows `chain id 424242 (not a chain this app knows)`, it has
   never heard of that network: sign only if you know what that id is, because the app
   cannot help you check it. The value and the fees are denominated in the chain's own coin
   (`1.5 POL`), or as `<n> native` when the app cannot name the coin — never assume it is
   ETH.
7. **Approve and continue.** The app shows the digest (keccak-256) of the transaction.
8. **Read the one-touch rule and tick it**, then enter the user PIN and tap *Sign with the
   YubiKey*.
9. **Complete the touch.** Hold the iPhone against the key and touch the gold contact when
   the key blinks. The app shows the signature as soon as the card answers.
10. **Scan the signature back into the wallet** (the wallet's *Scan* button). The wallet
    verifies the signature against the account before broadcasting.
11. **Check the counter.** The app shows the card's signature counter before and after. One
    transaction must move it by exactly one. The wallet's own counter read is the independent
    one — do it at the end of a session for anything you care about (design.md §5.2 rules 3–4).

## When something goes wrong

- **"The YubiKey rejected the PIN."** Nothing was signed. The message says how many attempts
  are left. Check the PIN in the wallet's records; after three failures PW1 blocks and only a
  reset (which destroys the keys) clears it.
- **The touch did not come through** (a timeout, or the key moved away). The card may have
  produced a signature and counted it, so the app does **not** retry and does not offer a
  second attempt for that request. Read the card's counter, then start again **from the
  wallet** with a new request.
- **"The signature does not match this card's key."** No QR is shown, and nothing can be
  scanned. Do not retry; treat the app and the phone as suspect, check the counter, and
  consider migrating the funds (design.md §5.2).
- **"The request is for a path this YubiKey does not sign."** The wallet offered a sibling
  account from the same extended public key. This card holds one key: select the paired
  account in the wallet, or re-pair with that account.
- **"This YubiKey carries no pairing manifest."** The card was provisioned before the manifest
  existed, or it has been reset since. Provision it again (which resets it) before signing.
- **The app asks for a second touch.** It should not: an app that asks for a second touch for
  the same transaction is to be treated as compromised, and you should stop (design.md §5.2
  rule 2).

## What the app records

The signing record screen shows the transport, the card serial, the account, the pinned path,
the chain id, the transaction type, the recipient, the value, the decoded function, the
request id, the digest that was approved, how many signature attempts were made, whether the
signature verified, the recovery value, and the counter before and after. It contains no
secrets and nothing is stored on the device: close the screen and it is gone.
