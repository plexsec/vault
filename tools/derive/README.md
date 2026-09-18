# tools/derive — independent derivation oracle

This directory holds the **second implementation** required by design.md §4.2
step 6b: an independent check that the address derived by the app is the address
the same mnemonic really produces.

## Why a second implementation

design.md §9.5 rates "iPhone app tampered (generation phase)" as the highest
single point of app trust. The mitigation is a derivation done by a different
codebase on a different device. `derive.py` is that second codebase, and it is
deliberately built differently from the app:

| | app (Swift) | oracle (Python) |
|---|---|---|
| SHA-256 / SHA-512 / HMAC / PBKDF2 | in-repo Swift | OpenSSL via `hashlib` |
| RIPEMD-160 / Keccak-256 | in-repo Swift | pycryptodome |
| secp256k1 point arithmetic | vendored libsecp256k1 (C) | from-scratch Python integers |
| bech32 | in-repo Swift | from-scratch Python |
| Base58Check | in-repo Swift | from-scratch Python |

If both agree on the same mnemonic, an error would have to be a shared
*misreading of the standards* rather than a coding mistake. `selftest` closes that
gap by checking the oracle against the published BIP32/BIP39 vectors, and the
Swift test target separately checks the app against the same published vectors.

## Usage

```sh
# one-time setup (Python 3.10+)
python3 -m venv .venv && .venv/bin/pip install pycryptodome

# verify the oracle itself against the published vectors
.venv/bin/python derive.py selftest

# derive an address from the mnemonic written on your steel plate
.venv/bin/python derive.py --mnemonic "word1 word2 … word24" --coin eth
.venv/bin/python derive.py --mnemonic "word1 …" --coin btc --path "m/84'/0'/0'/0/0"

# regenerate the fixtures the Swift tests consume
.venv/bin/python derive.py gen-fixtures ../../ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures
```

`english.txt` is a copy of the official BIP39 English wordlist with the same
SHA-256 the Swift side asserts
(`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`).

## Operational note

Run this on a **different device** from the one that showed you the mnemonic —
for example a laptop, with the mnemonic typed in by hand. Running it on the same
iPhone would not add any independence.

The app's step-11 screen asks you to type in the address this tool printed, and
compares it byte-for-byte.
