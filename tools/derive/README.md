# tools/derive — independent derivation oracle

This directory holds the **second implementation** of the derivation path — an
independent Python codebase whose derived values are checked against the Swift
app. Three values are cross-checked, because one secp256k1 key serves two address
formats and the Ed25519 key's identity is its public key: the EVM address, the
Bitcoin address, and the Ed25519 public key.

> The operator-facing independent cross-check that design.md §4.2 step 6b
> described was removed in v0.1 (see `docs/design-amendments.md`, amendment 8).
> This tool remains as a **differential-testing oracle**: `selftest` checks it
> against the published vectors, and `gen-fixtures` produces the committed
> fixtures the Swift tests assert against.

## Why a second implementation

design.md §9.5 rates "iPhone app tampered (generation phase)" as the highest
single point of app trust. `derive.py` is a second codebase, built differently
from the app, so that the two must agree on the same mnemonic. It is deliberately
constructed to share no code with the app:

| | app (Swift) | oracle (Python) |
|---|---|---|
| SHA-256 / SHA-512 / HMAC / PBKDF2 | in-repo Swift | OpenSSL via `hashlib` |
| RIPEMD-160 / Keccak-256 | in-repo Swift | pycryptodome |
| secp256k1 point arithmetic | vendored libsecp256k1 (C) | from-scratch Python integers |
| BIP32 derivation | in-repo Swift | from-scratch Python |
| SLIP-0010 derivation | in-repo Swift | from-scratch Python |
| Ed25519 key generation | vendored TweetNaCl (C) | pycryptodome |
| bech32 | in-repo Swift | from-scratch Python |
| Base58Check | in-repo Swift | from-scratch Python |

If both agree on the same mnemonic, an error would have to be a shared
*misreading of the standards* rather than a coding mistake. `selftest` closes that
gap by checking the oracle against the published BIP32, BIP39, SLIP-0010
Ed25519 and RFC 8032 §7.1 vectors, and the Swift test target separately checks
the app against the same published vectors.

## Usage

```sh
# one-time setup (Python 3.10+)
python3 -m venv .venv && .venv/bin/pip install pycryptodome

# verify the oracle itself against the published vectors
.venv/bin/python derive.py selftest

# derive the secp256k1 key and both of its addresses (EVM + Bitcoin)
.venv/bin/python derive.py --mnemonic "word1 word2 … word24"

# derive the Ed25519 key; its identity is the public key
.venv/bin/python derive.py --mnemonic "word1 …" --algorithm ed25519

# ad-hoc single-coin lookups are still available
.venv/bin/python derive.py --mnemonic "word1 …" --coin eth
.venv/bin/python derive.py --mnemonic "word1 …" --coin btc --path "m/84'/0'/0'/0/0"

# regenerate the fixtures the Swift tests consume
.venv/bin/python derive.py gen-fixtures ../../ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures
```

`english.txt` is a copy of the official BIP39 English wordlist with the same
SHA-256 the Swift side asserts
(`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`).

## Operational note

The app no longer asks the operator to cross-check addresses against this tool
during the ceremony — that independent cross-check was removed in v0.1. The
`--mnemonic` / `--algorithm` modes remain for ad-hoc verification and for the
hardware-verification procedures in `docs/m0-hardware-verification.md`, but the
in-ceremony check is gone.
