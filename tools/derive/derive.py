#!/usr/bin/env python3
"""Independent BIP39/BIP32/address reference used as the §4.2 step 6b oracle.

This file is intentionally NOT derived from the Swift implementation in
``ios/Packages/VaultKit``. It is a second, independent implementation of the
same standards, written in a different language, using:

  * ``hashlib`` (OpenSSL) for SHA-256 / SHA-512 / HMAC / PBKDF2,
  * ``pycryptodome`` for RIPEMD-160 and Keccak-256,
  * a from-scratch pure-Python secp256k1 (no libsecp256k1, no coincurve),
  * a from-scratch bech32 encoder.

That independence is the whole point: if the Swift code and this file agree on
the same mnemonic, the address is right, and a bug that exists in both would
have to be a shared *misreading* of the standards. The published BIP32/BIP39
test vectors (checked by ``selftest``) close that last gap.

Usage:
    derive.py --mnemonic "word1 ... word24" --coin eth [--path m/44'/60'/0'/0/0]
    derive.py --mnemonic "..." --coin eth --json
    derive.py --seed-hex 000102... --path m/0'/1 --coin btc
    derive.py selftest
    derive.py gen-fixtures <output-directory>

Exit codes: 0 success, 1 usage/validation error, 2 selftest failure.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys

from Crypto.Hash import RIPEMD160, keccak

# --------------------------------------------------------------------------
# secp256k1 (pure Python, affine coordinates)
# --------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k: int, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def ser_p(point) -> bytes:
    """SEC1 compressed serialisation."""
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


# --------------------------------------------------------------------------
# BIP39
# --------------------------------------------------------------------------

def _wordlist_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "english.txt"),
        os.path.join(here, "..", "..", "ios", "Packages", "VaultKit",
                     "Tests", "VaultKitTests", "Fixtures", "bip39_english.txt"),
        os.path.join(here, "..", "..", "ios", "Packages", "VaultKit",
                     "Sources", "VaultKit", "BIP39", "english.txt"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    raise SystemExit("english.txt wordlist not found next to derive.py")


def load_wordlist():
    with open(_wordlist_path(), encoding="utf-8") as handle:
        words = [w.strip() for w in handle if w.strip()]
    if len(words) != 2048:
        raise SystemExit(f"wordlist has {len(words)} words, expected 2048")
    return words


def mnemonic_to_entropy(words):
    wordlist = load_wordlist()
    index = {w: i for i, w in enumerate(wordlist)}
    if len(words) not in (12, 15, 18, 21, 24):
        raise SystemExit(f"invalid word count: {len(words)}")
    bits = ""
    for word in words:
        if word not in index:
            raise SystemExit(f"word not in wordlist: {word}")
        bits += f"{index[word]:011b}"
    checksum_bits = len(words) * 11 // 33
    entropy_bits = bits[: len(bits) - checksum_bits]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    expected = f"{hashlib.sha256(entropy).digest()[0]:08b}"[:checksum_bits]
    if bits[len(bits) - checksum_bits:] != expected:
        raise SystemExit("mnemonic checksum mismatch")
    return entropy


def mnemonic_to_seed(words, passphrase=""):
    mnemonic = " ".join(words)
    salt = "mnemonic" + passphrase
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"), salt.encode("utf-8"), 2048, 64
    )


# --------------------------------------------------------------------------
# BIP32
# --------------------------------------------------------------------------

HARDENED = 0x80000000


def master_key(seed: bytes):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    if not (0 < key < N):
        raise SystemExit("invalid master key")
    return {"key": key, "chain": digest[32:], "depth": 0, "parent": b"\x00" * 4, "index": 0}


def fingerprint(node) -> bytes:
    pub = ser_p(point_mul(node["key"]))
    ripemd = RIPEMD160.new()
    ripemd.update(hashlib.sha256(pub).digest())
    return ripemd.digest()[:4]


def ckd_priv(node, index: int):
    if index >= HARDENED:
        data = b"\x00" + node["key"].to_bytes(32, "big")
    else:
        data = ser_p(point_mul(node["key"]))
    data += index.to_bytes(4, "big")
    digest = hmac.new(node["chain"], data, hashlib.sha512).digest()
    il = int.from_bytes(digest[:32], "big")
    if il >= N:
        raise SystemExit("invalid child (IL >= n)")
    child = (il + node["key"]) % N
    if child == 0:
        raise SystemExit("invalid child (zero)")
    return {
        "key": child,
        "chain": digest[32:],
        "depth": node["depth"] + 1,
        "parent": fingerprint(node),
        "index": index,
    }


def parse_path(path: str):
    if not path.startswith("m"):
        raise SystemExit(f"path must start with m: {path}")
    parts = [p for p in path.split("/")[1:] if p != ""]
    out = []
    for part in parts:
        hardened = part.endswith("'") or part.endswith("h") or part.endswith("H")
        body = part[:-1] if hardened else part
        value = int(body)
        if value >= HARDENED:
            raise SystemExit(f"index out of range: {part}")
        out.append(value + HARDENED if hardened else value)
    return out


def derive(seed: bytes, path: str):
    node = master_key(seed)
    for index in parse_path(path):
        node = ckd_priv(node, index)
    return node


# --------------------------------------------------------------------------
# Addresses
# --------------------------------------------------------------------------

def evm_address(pub_compressed: bytes) -> str:
    point = None
    x = int.from_bytes(pub_compressed[1:], "big")
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if (y & 1) != (pub_compressed[0] & 1):
        y = P - y
    point = (x, y)
    uncompressed = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    digest = keccak.new(digest_bits=256)
    digest.update(uncompressed)
    raw = digest.digest()[-20:]
    lower = raw.hex()
    checksum = keccak.new(digest_bits=256)
    checksum.update(lower.encode("ascii"))
    hashed = checksum.digest()
    out = "0x"
    for i, character in enumerate(lower):
        nibble = (hashed[i // 2] >> 4) if i % 2 == 0 else (hashed[i // 2] & 0x0F)
        out += character.upper() if (character.isalpha() and nibble >= 8) else character
    return out


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


def _bech32_polymod(values):
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                checksum ^= BECH32_GENERATOR[i]
    return checksum


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def btc_p2wpkh(pub_compressed: bytes, hrp="bc") -> str:
    ripemd = RIPEMD160.new()
    ripemd.update(hashlib.sha256(pub_compressed).digest())
    program = ripemd.digest()
    data = _convertbits([0] + list(program), 8, 5)
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def address_for(coin: str, pub_compressed: bytes) -> str:
    if coin == "eth":
        return evm_address(pub_compressed)
    if coin == "btc":
        return btc_p2wpkh(pub_compressed)
    raise SystemExit(f"unknown coin: {coin}")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

COIN_PATHS = {"eth": "m/44'/60'/0'/0/0", "btc": "m/84'/0'/0'/0/0"}


def describe(seed: bytes, path: str, coin: str, source: str):
    node = derive(seed, path)
    pub = ser_p(point_mul(node["key"]))
    return {
        "source": source,
        "path": path,
        "coin": coin,
        "seed": seed.hex(),
        "chain_code": node["chain"].hex(),
        "private_key": f"{node['key']:064x}",
        "public_key_compressed": pub.hex(),
        "parent_fingerprint": node["parent"].hex(),
        "master_fingerprint": fingerprint(master_key(seed)).hex(),
        "address": address_for(coin, pub),
    }


def selftest() -> int:
    """Anchor this file to the published BIP32 and BIP39 vectors."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.normpath(os.path.join(here, "..", ".."))
    fixtures = os.path.join(root, "ios", "Packages", "VaultKit", "Tests",
                            "VaultKitTests", "Fixtures")
    failures = []

    with open(os.path.join(fixtures, "bip32_vectors.json"), encoding="utf-8") as handle:
        vectors = json.load(handle)["bip32"]
    checked = 0
    for vector in vectors:
        seed = bytes.fromhex(vector["seed"])
        for chain in vector["chains"]:
            node = derive(seed, chain["path"])
            pub = ser_p(point_mul(node["key"]))
            xprv = encode_extended(0x0488ADE4, node, b"\x00" + node["key"].to_bytes(32, "big"))
            xpub = encode_extended(0x0488B21E, node, pub)
            if chain["xprv"] and xprv != chain["xprv"]:
                failures.append(f"BIP32 v{vector['vector']} {chain['path']} xprv")
            if chain["xpub"] and xpub != chain["xpub"]:
                failures.append(f"BIP32 v{vector['vector']} {chain['path']} xpub")
            checked += 1

    with open(os.path.join(fixtures, "bip39_trezor_vectors.json"), encoding="utf-8") as handle:
        bip39 = json.load(handle)["english"]
    for entry in bip39:
        # Trezor vectors are [entropy, mnemonic, seed, xprv]
        entropy_hex, mnemonic, seed_hex = entry[0], entry[1], entry[2]
        seed = mnemonic_to_seed(mnemonic.split(), "TREZOR")
        if seed.hex() != seed_hex:
            failures.append(f"BIP39 seed for entropy {entropy_hex[:16]}")
        rebuilt = mnemonic_to_entropy(mnemonic.split())
        if rebuilt.hex() != entropy_hex:
            failures.append(f"BIP39 entropy for {mnemonic[:24]}")
        checked += 1

    if failures:
        print("SELFTEST FAILED:", file=sys.stderr)
        for failure in failures[:20]:
            print("  " + failure, file=sys.stderr)
        return 2
    print(f"selftest OK: {checked} published vectors reproduced by the independent implementation")
    return 0


def encode_extended(version: int, node, key_data: bytes) -> str:
    payload = version.to_bytes(4, "big")
    payload += bytes([node["depth"]])
    payload += node["parent"]
    payload += node["index"].to_bytes(4, "big")
    payload += node["chain"]
    payload += key_data
    payload += hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload)


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = B58_ALPHABET[remainder] + out
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def gen_fixtures(outdir: str) -> int:
    """Differential fixtures consumed by the Swift test target."""
    os.makedirs(outdir, exist_ok=True)
    mnemonics = [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "shield group erode awake lock sausage cash glare wave crew flame glove",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
    ]
    records = []
    for mnemonic in mnemonics:
        seed = mnemonic_to_seed(mnemonic.split(), "")
        for coin, default_path in COIN_PATHS.items():
            for path in (default_path, "m/44'/60'/0'/0/0" if coin == "eth" else "m/84'/0'/0'/0/0", "m/0'", "m"):
                record = describe(seed, path, coin, mnemonic[:24])
                records.append(record)
    with open(os.path.join(outdir, "derivation_vectors.json"), "w", encoding="utf-8") as handle:
        json.dump({"note": "generated by tools/derive/derive.py (independent implementation)",
                   "vectors": records}, handle, indent=1)
    print(f"wrote {len(records)} derivation vectors to {outdir}/derivation_vectors.json")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", help="selftest | gen-fixtures")
    parser.add_argument("outdir", nargs="?", help="output directory for gen-fixtures")
    parser.add_argument("--mnemonic")
    parser.add_argument("--seed-hex")
    parser.add_argument("--passphrase", default="")
    parser.add_argument("--coin", choices=["eth", "btc"])
    parser.add_argument("--path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "selftest":
        return selftest()
    if args.command == "gen-fixtures":
        if not args.outdir:
            parser.error("gen-fixtures requires an output directory")
        return gen_fixtures(args.outdir)

    if args.mnemonic:
        seed = mnemonic_to_seed(args.mnemonic.split(), args.passphrase)
        source = "mnemonic"
    elif args.seed_hex:
        seed = bytes.fromhex(args.seed_hex)
        source = "seed-hex"
    else:
        parser.error("provide --mnemonic or --seed-hex (or use selftest/gen-fixtures)")

    coin = args.coin or "eth"
    path = args.path or COIN_PATHS[coin]
    record = describe(seed, path, coin, source)
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"path    : {record['path']}")
        print(f"pubkey  : {record['public_key_compressed']}")
        print(f"address : {record['address']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
