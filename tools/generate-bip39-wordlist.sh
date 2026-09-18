#!/usr/bin/env bash
#
# Regenerates VaultKit's BIP39 wordlist from the official source and asserts the
# hash, so the generated Swift file can never drift from the standard unnoticed.
#
# Usage: tools/generate-bip39-wordlist.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
EXPECTED_SHA256="2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -sSL --max-time 60 "$URL" -o "$TMP"

ACTUAL="$(shasum -a 256 "$TMP" | awk '{print $1}')"
if [[ "$ACTUAL" != "$EXPECTED_SHA256" ]]; then
  echo "error: english.txt hash mismatch" >&2
  echo "  expected $EXPECTED_SHA256" >&2
  echo "  actual   $ACTUAL" >&2
  echo "The upstream wordlist changed, or the download was corrupted. Investigate before regenerating." >&2
  exit 1
fi

OUT="$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/BIP39/BIP39Wordlist.swift"
FIXTURE="$REPO_ROOT/ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures/bip39_english.txt"
cp "$TMP" "$FIXTURE"

python3 - "$TMP" "$OUT" "$EXPECTED_SHA256" <<'PY'
import sys
src, out, sha = sys.argv[1], sys.argv[2], sys.argv[3]
words = [w for w in open(src).read().split('\n') if w]
assert len(words) == 2048, len(words)
L = []
L.append('// Generated from the official BIP39 English wordlist (bitcoin/bips, bip-0039/english.txt).')
L.append('// Do not edit by hand: regenerate with tools/generate-bip39-wordlist.sh, which also')
L.append('// asserts the SHA-256 recorded below. The test target recomputes that hash from the')
L.append('// in-repo fixture copy to prove the list was not altered in transit.')
L.append('//')
L.append('// Source file SHA-256: ' + sha)
L.append('public enum BIP39Wordlist {')
L.append('    /// SHA-256 of the canonical `english.txt` (2048 words joined by \\n plus trailing \\n).')
L.append('    public static let englishFileSHA256 = "%s"' % sha)
L.append('    public static let english: [String] = [')
for i in range(0, 2048, 8):
    L.append('        ' + ', '.join('"%s"' % w for w in words[i:i+8]) + ',')
L.append('    ]')
L.append('    public static let index: [String: Int] = {')
L.append('        var map = [String: Int](minimumCapacity: 2048)')
L.append('        for (i, w) in english.enumerated() { map[w] = i }')
L.append('        return map')
L.append('    }()')
L.append('}')
open(out, 'w').write('\n'.join(L) + '\n')
print(f"wrote {out} ({len(words)} words, sha256 {sha})")
PY
