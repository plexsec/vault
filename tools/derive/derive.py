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
    derive.py --mnemonic "word1 ... word24" [--path m/44'/0'/0'/0/0]
    derive.py --mnemonic "..." --algorithm ed25519
    derive.py --seed-hex 000102... --coin eth --path m/44'/60'/0'/0/0
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
from Crypto.PublicKey import ECC

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
# SLIP-0010 (Ed25519)
# --------------------------------------------------------------------------
#
# A separate section rather than a branch inside BIP32: SLIP-0010 uses a
# different master salt, treats the 32-byte seed itself as the private key, and
# does not define non-hardened derivation at all.

SLIP10_CURVE = b"ed25519 seed"


def slip10_master_key(seed: bytes):
    if not (16 <= len(seed) <= 64):
        raise SystemExit(f"invalid SLIP-0010 seed length: {len(seed)}")
    digest = hmac.new(SLIP10_CURVE, seed, hashlib.sha512).digest()
    return {
        "key": digest[:32],
        "chain": digest[32:],
        "depth": 0,
        "parent": b"\x00" * 4,
        "index": 0,
    }


def ed25519_public_key(seed32: bytes) -> bytes:
    """Raw 32-byte Ed25519 public key (RFC 8032 key generation)."""
    if len(seed32) != 32:
        raise SystemExit("Ed25519 seed must be 32 bytes")
    key = ECC.construct(curve="Ed25519", seed=seed32)
    return key.public_key().export_key(format="raw")


def slip10_fingerprint(node) -> bytes:
    """First four bytes of HASH160(0x00 || pubkey), matching SLIP-0010's own
    serialisation of an Ed25519 public key."""
    pub = ed25519_public_key(node["key"])
    ripemd = RIPEMD160.new()
    ripemd.update(hashlib.sha256(b"\x00" + pub).digest())
    return ripemd.digest()[:4]


def slip10_ckd_priv(node, index: int):
    if index < HARDENED:
        raise SystemExit(f"SLIP-0010 forbids non-hardened index {index}")
    data = b"\x00" + node["key"] + index.to_bytes(4, "big")
    digest = hmac.new(node["chain"], data, hashlib.sha512).digest()
    return {
        "key": digest[:32],
        "chain": digest[32:],
        "depth": node["depth"] + 1,
        "parent": slip10_fingerprint(node),
        "index": index,
    }


def slip10_derive(seed: bytes, path: str):
    node = slip10_master_key(seed)
    for index in parse_path(path):
        node = slip10_ckd_priv(node, index)
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

# One fixed path per algorithm, matching DerivationPath in the Swift library.
SECP256K1_PATH = "m/44'/0'/0'/0/0"
ED25519_PATH = "m/44'/501'/0'/0'"


def describe(seed: bytes, path: str, coin: str, source: str):
    """secp256k1 record for one coin (ad-hoc CLI use)."""
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


def describe_secp256k1(seed: bytes, path: str, source: str):
    """The single secp256k1 key and both addresses it serves."""
    node = derive(seed, path)
    pub = ser_p(point_mul(node["key"]))
    return {
        "source": source,
        "algorithm": "secp256k1",
        "path": path,
        "seed": seed.hex(),
        "chain_code": node["chain"].hex(),
        "private_key": f"{node['key']:064x}",
        "public_key": pub.hex(),
        "parent_fingerprint": node["parent"].hex(),
        "fingerprint": fingerprint(node).hex(),
        "master_fingerprint": fingerprint(master_key(seed)).hex(),
        "evm_address": evm_address(pub),
        "bitcoin_address": btc_p2wpkh(pub),
    }


def describe_ed25519(seed: bytes, path: str, source: str):
    """The single Ed25519 key; its identity is the raw public key."""
    node = slip10_derive(seed, path)
    pub = ed25519_public_key(node["key"])
    return {
        "source": source,
        "algorithm": "ed25519",
        "path": path,
        "seed": seed.hex(),
        "chain_code": node["chain"].hex(),
        "private_key": node["key"].hex(),
        "public_key": pub.hex(),
        "parent_fingerprint": node["parent"].hex(),
        "fingerprint": slip10_fingerprint(node).hex(),
        "master_fingerprint": slip10_fingerprint(slip10_master_key(seed)).hex(),
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

    # SLIP-0010 Ed25519 vector 1 (published in the SLIP-0010 spec).
    slip10_seed1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    slip10_v1 = [
        ("m", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
         "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
         "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
        ("m/0'", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
         "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
         "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
        ("m/0'/1'", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
         "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
         "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"),
        ("m/0'/1'/2'", "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
         "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
         "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"),
        ("m/0'/1'/2'/2'", "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
         "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
         "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"),
        ("m/0'/1'/2'/2'/1000000000'", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
         "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
         "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"),
    ]
    for slip_path, slip_chain, slip_priv, slip_pub in slip10_v1:
        node = slip10_derive(slip10_seed1, slip_path)
        if node["chain"].hex() != slip_chain:
            failures.append(f"SLIP-0010 v1 {slip_path} chain code")
        if node["key"].hex() != slip_priv:
            failures.append(f"SLIP-0010 v1 {slip_path} private key")
        if ed25519_public_key(node["key"]).hex() != slip_pub:
            failures.append(f"SLIP-0010 v1 {slip_path} public key")
        checked += 1

    # RFC 8032 7.1 TEST 1: Ed25519 public key from the published secret.
    rfc_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    if ed25519_public_key(rfc_seed).hex() != \
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a":
        failures.append("RFC 8032 TEST 1 public key")
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
    """Differential fixtures consumed by the Swift test target.

    Both algorithms are emitted, so the Swift tests compare against this
    implementation on the secp256k1 key, its two address encodings, and the
    Ed25519 key.
    """
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
        source = mnemonic[:24]
        for path in (SECP256K1_PATH, "m/44'/60'/0'/0/0", "m/84'/0'/0'/0/0", "m/0'", "m"):
            records.append(describe_secp256k1(seed, path, source))
        for path in (ED25519_PATH, "m/0'", "m"):
            records.append(describe_ed25519(seed, path, source))
    with open(os.path.join(outdir, "derivation_vectors.json"), "w", encoding="utf-8") as handle:
        json.dump({"note": "generated by tools/derive/derive.py (independent implementation)",
                   "vectors": records}, handle, indent=1)
    print(f"wrote {len(records)} derivation vectors to {outdir}/derivation_vectors.json")
    return 0



# ---------------------------------------------------------------------------
# Signing fixtures (v0.2)
# ---------------------------------------------------------------------------
#
# This is a *fixture generator*, not a signer: it exists so the Swift tests can
# exercise the real verification path (recovery, low-s normalisation, the
# recovery value) against signatures produced by an implementation that shares no
# code with libsecp256k1 or with VaultKit. The nonce is derived from a hash of the
# key and the message purely so the output is reproducible; nothing here is
# constant-time and nothing here should ever sign anything of value.

SIGNING_FIXTURE_KEY = hashlib.sha256(b"plexvault signing fixture key").digest()


def _deterministic_nonce(private_key: bytes, message: int) -> int:
    return int.from_bytes(
        hashlib.sha256(b"plexvault signing fixture nonce" + private_key + message.to_bytes(32, "big")).digest(),
        "big",
    ) % N


def ecdsa_sign(private_key: bytes, message: int) -> dict:
    """Deterministic ECDSA over secp256k1, returning both s forms."""
    secret = int.from_bytes(private_key, "big")
    k = _deterministic_nonce(private_key, message)
    point = point_mul(k)
    r = point[0] % N
    s = (_inv(k, N) * (message + r * secret)) % N
    recid = (2 if point[0] >= N else 0) | (point[1] & 1)
    high_s = N - s
    return {
        "r": r,
        "s": s,
        "high_s": high_s,
        "recid": recid,
        # Negating s recovers the same key under the other recovery id.
        "recid_high_s": recid ^ 1,
    }


def rlp_encode(value) -> bytes:
    """Minimal RLP encoder, enough for the fixture payloads."""
    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
        if len(payload) == 1 and payload[0] < 0x80:
            return payload
        return _rlp_length(len(payload), 0x80) + payload
    if isinstance(value, int):
        return rlp_encode(b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big"))
    if isinstance(value, (list, tuple)):
        body = b"".join(rlp_encode(item) for item in value)
        return _rlp_length(len(body), 0xC0) + body
    raise TypeError(value)


def _rlp_length(length: int, base: int) -> bytes:
    if length < 56:
        return bytes([base + length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(encoded)]) + encoded


def keccak_256(data: bytes) -> bytes:
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def _der(r: int, s: int) -> bytes:
    def integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def gen_signing_fixtures(outdir: str) -> int:
    """Signatures for the digests the Swift tests use, plus the key that made them.

    The digests are the three transaction shapes the app decodes (EIP-155 legacy,
    EIP-1559, EIP-2930) plus an arbitrary 32-byte value, so a test can drive the
    whole ceremony — manifest, approval, signature, verification, export — with a
    card that behaves like a real one.

    Note on the two `s` values: `s` is the raw RFC6979-form signature and `high_s` is
    `n - s`. They are "this one" and "the other one", not "low" and "high" — for some
    digests the raw value is already ≥ n/2 (chain 137's two extra vectors are), so the
    mock card returns a high-s signature on that path and the app has to normalise it.
    That is deliberate coverage of EIP-2 rather than an accident, which is why the
    vector is left as it is instead of being canonicalised.

    Two more exist so that chain handling is tested with real signatures rather than
    with a stub: the EIP-1559 shape on chain id 137 (Polygon, the ordinary case for
    POL) and on an id no chain list knows (424242), which keeps the chain *name* table
    a display convenience rather than a whitelist — a card that only signs the chains
    its author listed would be a different, worse product.
    """
    os.makedirs(outdir, exist_ok=True)
    public_key = ser_p(point_mul(int.from_bytes(SIGNING_FIXTURE_KEY, "big")))
    # The Polygon variant of the EIP-155 example, whose recovery value (309/310)
    # does not fit in the signature's one-byte v field.
    polygon_payload = rlp_encode([
        bytes([0x09]),
        bytes.fromhex("04a817c800"),
        bytes.fromhex("5208"),
        bytes.fromhex("35" * 20),
        bytes.fromhex("0de0b6b3a7640000"),
        b"",
        (137).to_bytes(1, "big"),
        b"",
        b"",
    ])
    # 0x02 ‖ RLP([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList]),
    # with the fields the Swift test helper builds: nonce 1, 1 gwei tip, 30 gwei cap,
    # 21000 gas, the 0x35…35 recipient, and an empty access list. `rlp_encode` minimises
    # integers the same way `EVMQuantity.bytes` does, so the two encoders agree.
    def fee_market(chain_id: int, value: int) -> bytes:
        return b"\x02" + rlp_encode([
            chain_id,
            1,
            1_000_000_000,
            30_000_000_000,
            bytes.fromhex("5208"),
            bytes.fromhex("35" * 20),
            value,
            b"",
            [],
        ])

    digests = {
        "eip155_legacy": "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53",
        "fee_market": "b28e48247c132650294459b31a5ad7e4e9ad187abb0f984388629b2c29e27e85",
        "access_list": "ffda134128f580ee2061c44fd17f6aac36bd2032386fd593de3900cb046dadd1",
        "legacy_chain_137": keccak_256(polygon_payload).hex(),
        "fee_market_chain_137": keccak_256(fee_market(137, 1_500_000_000_000_000_000)).hex(),
        "fee_market_chain_424242": keccak_256(fee_market(424242, 1)).hex(),
        "arbitrary": hashlib.sha256(b"plexvault signing fixture digest").hexdigest(),
    }
    signatures = []
    for name, digest_hex in digests.items():
        message = int.from_bytes(bytes.fromhex(digest_hex), "big")
        signature = ecdsa_sign(SIGNING_FIXTURE_KEY, message)
        signatures.append({
            "name": name,
            "digest": digest_hex,
            "r": f"{signature['r']:064x}",
            "s": f"{signature['s']:064x}",
            "high_s": f"{signature['high_s']:064x}",
            "recid": signature["recid"],
            "recid_high_s": signature["recid_high_s"],
            "der": _der(signature["r"], signature["s"]).hex(),
            "der_high_s": _der(signature["r"], signature["high_s"]).hex(),
            # The two recovery values a wallet expects, for chain id 1.
            "legacy_v_chain_1": 35 + 2 * 1 + signature["recid"],
            "typed_v": signature["recid"],
        })
    document = {
        "note": "generated by tools/derive/derive.py; a fixture generator, not a signer",
        "publicKeyCompressed": public_key.hex(),
        "address": evm_address(public_key),
        "signatures": signatures,
    }
    path = os.path.join(outdir, "signing_vectors.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)
    print(f"wrote {len(signatures)} signing vectors to {path}")
    return 0


def gen_simulated_card_vectors(outpath: str) -> int:
    """A real signature by the key the *simulated* card holds.

    The app's DEBUG simulated card is provisioned from the all-zero entropy the UI
    tests pass on the command line, so the key inside it is a published BIP39 test
    vector's key: derivable by anyone, and secret to nobody. Having this generator
    sign with it means the UI test can drive the whole signing flow — including the
    app's own recovery check, which a fake signature cannot satisfy — while the app
    still contains no signing code.

    The output is Swift source rather than JSON because only DEBUG builds may see
    it, and `#if DEBUG` is the mechanism the audit already checks.
    """
    # 32 zero bytes of entropy, which is what the UI tests pass on the command
    # line, so the mnemonic is the *256-bit* all-zero vector: twenty-three
    # "abandon" and a final "art". (The twelve-word "…about" vector is 128-bit
    # entropy and a different key — an easy and silent mistake, which is why
    # SigningEndToEndTests asserts this key against the derivation the app does.)
    mnemonic = " ".join(["abandon"] * 23 + ["art"])
    seed = mnemonic_to_seed(mnemonic.split(), "")
    node = derive(seed, SECP256K1_PATH)
    secret = node["key"].to_bytes(32, "big")
    public_key = ser_p(point_mul(node["key"]))
    digest_hex = hashlib.sha256(b"plexvault simulated card digest placeholder").hexdigest()
    # The digest the debug sample request carries (EIP-155's example transaction).
    digest_hex = "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    signature = ecdsa_sign(secret, int(digest_hex, 16))
    der = _der(signature["r"], signature["s"]).hex()
    # Recovery value for chain 1: what the wallet needs, and what the app verifies.
    legacy_v = 35 + 2 * 1 + signature["recid"]

    source = f'''// Generated by tools/derive/derive.py — do not edit by hand.
// Regenerate with: tools/derive/derive.py gen-signing-fixtures <dir>
//
// A real ECDSA signature by the key the app\'s DEBUG simulated card holds. That
// card is provisioned from the all-zero entropy the UI tests pass, so its key is
// the one from the published BIP39 test vector: secret to nobody, and enough for
// the UI test to exercise the app\'s own signature verification, which a fake
// signature cannot pass.

#if DEBUG
enum SimulatedSigningVectors {{
    /// The account the simulated card signs for (EIP-55).
    static let address = "{evm_address(public_key)}"
    /// The uncompressed/compressed key the card reports, for cross-checks in tests.
    static let publicKeyHex = "{public_key.hex()}"
    /// digest -> DER signature, for one signature per digest at most.
    static let signatures: [String: String] = [
        "{digest_hex}": "{der}",
    ]
    /// The recovery values a wallet expects for that digest on chain 1.
    static let legacyRecoveryValue: Int = {legacy_v}
}}
#endif
'''
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w", encoding="utf-8") as handle:
        handle.write(source)
    print(f"wrote the simulated-card signing vector to {outpath}")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", help="selftest | gen-fixtures | gen-signing-fixtures")
    parser.add_argument("outdir", nargs="?", help="output directory for gen-fixtures")
    parser.add_argument("--mnemonic")
    parser.add_argument("--seed-hex")
    parser.add_argument("--passphrase", default="")
    parser.add_argument("--coin", choices=["eth", "btc"])
    parser.add_argument("--algorithm", choices=["secp256k1", "ed25519"], default="secp256k1")
    parser.add_argument("--path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "selftest":
        return selftest()
    if args.command == "gen-fixtures":
        if not args.outdir:
            parser.error("gen-fixtures requires an output directory")
        gen_fixtures(args.outdir)
        gen_signing_fixtures(args.outdir)
        return gen_simulated_card_vectors(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "ios/Packages/YubikeyKit/Sources/YubikeyKitMock/SimulatedSigningVectors.swift",
            )
        )

    if args.command == "gen-signing-fixtures":
        if not args.outdir:
            parser.error("gen-signing-fixtures requires an output directory")
        return gen_signing_fixtures(args.outdir)

    if args.mnemonic:
        seed = mnemonic_to_seed(args.mnemonic.split(), args.passphrase)
        source = "mnemonic"
    elif args.seed_hex:
        seed = bytes.fromhex(args.seed_hex)
        source = "seed-hex"
    else:
        parser.error("provide --mnemonic or --seed-hex (or use selftest/gen-fixtures)")

    if args.algorithm == "ed25519":
        path = args.path or ED25519_PATH
        record = describe_ed25519(seed, path, source)
        if args.json:
            print(json.dumps(record, indent=2))
        else:
            print(f"path        : {record['path']}")
            print(f"public key  : {record['public_key']}")
            print(f"chain code  : {record['chain_code']}")
        return 0

    if args.coin:
        # Ad-hoc single-coin lookup, retained for convenience.
        path = args.path or COIN_PATHS[args.coin]
        record = describe(seed, path, args.coin, source)
        if args.json:
            print(json.dumps(record, indent=2))
        else:
            print(f"path    : {record['path']}")
            print(f"pubkey  : {record['public_key_compressed']}")
            print(f"address : {record['address']}")
        return 0

    path = args.path or SECP256K1_PATH
    record = describe_secp256k1(seed, path, source)
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print(f"path            : {record['path']}")
        print(f"public key      : {record['public_key']}")
        print(f"evm address     : {record['evm_address']}")
        print(f"bitcoin address : {record['bitcoin_address']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
