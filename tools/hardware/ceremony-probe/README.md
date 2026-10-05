# ceremony-probe

A macOS-only probe that runs the app's **own** provisioning ceremony against a real YubiKey in the
reader, over the app's **own** USB-C CCID transport (`SmartCardTransport`).

```sh
cd tools/hardware/ceremony-probe
swift run ceremony-probe --cards 2      # provision two cards' worth of passes
swift run slot-probe                    # just: is the card reachable from here?
```

## What it is for

The ceremony is otherwise exercised by the simulator (which cannot reach a card at all) and by unit
tests (which cannot reach one either). That gap is where amendment 41 lived: with the card count at
2 the app reset the second card and then closed its write step on the first card's read-back, so the
second card was never written, and every test passed. `docs/m0-hardware-verification.md` item 20
records what this probe found and what it checks.

What it adds over an APDU replay is not more APDUs: it is the shipping state machine, the shipping
transport, and — after **each** pass — an independent read of the card that does not go through the
ceremony (both slots, the touch policy, the PW1 status, the manifest, and both public keys compared
byte-for-byte against the keys derived here).

## It is a probe, not a provisioning tool

It **resets the card**, sets its own PINs (printed), prints the generated mnemonic to the terminal,
and **declines** the paper backup — so the record it prints says, correctly, that no paper copy
exists. Use a card whose contents do not matter, and reset it afterwards:

```sh
ykman openpgp reset -f
```

With `--cards N` (default 1) the same physical card is reset and written N times. Only the **serial**
is faked for the passes after the first (`SerialSwappingCard`): the serial is all the ceremony uses
to tell one card from another — it is what the duplicate check compares and what each card's pairing
manifest carries — while everything else (reset, PINs, imports, policy, manifest) goes to the
hardware. A real reader has one card in it, and the app refuses a serial it has already written in
the same run; that refusal is covered by the unit tests rather than by this probe.

## The signing step

`TKSmartCardSlotManager.default` is `nil` in an unsigned command-line binary *and* in an
ad-hoc-signed `.app` bundle, so the probe has to be signed with one entitlement:

```sh
cat > /tmp/smartcard-entitlements.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.smartcard</key><true/>
</dict></plist>
PLIST

BIN="$(swift build --show-bin-path)/ceremony-probe"
codesign --force --sign - --entitlements /tmp/smartcard-entitlements.plist "$BIN"
"$BIN" --cards 2
```

No identity, no sandbox and no provisioning profile are needed — only that key. `system_profiler
SPSmartCardsDataType` should list the reader (`Yubico YubiKey FIDO+CCID`) whether or not the binary
is signed; if the probe says the subsystem is unavailable, the signature is why.

Two hardware rules the probe embodies, both learned the hard way:

* **One transport per session.** `TransportSessionCard`'s factory shape (a fresh transport per
  operation) is what the card needs; a shared `SmartCardTransport` that is opened again for the next
  operation hangs on the second `beginSession()` and looks like a wedged reader.
* **Kill the desktop smart-card agent first** if you are also using `gpg`/`ykman`:
  `gpgconf --kill scdaemon`. Otherwise a cached `VERIFY PW3` in another process makes protected
  writes look unprotected (m0 item 18), and two clients on one card is a race in any case.
