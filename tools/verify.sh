#!/usr/bin/env bash
#
# Runs every check that can be run without a YubiKey or an iPhone.
#
# This is the gate for "the code is correct to the limit of what can be verified
# off-hardware". The remaining, hardware-only checks are listed in
# docs/m0-hardware-verification.md.
#
# Usage: tools/verify.sh [--quick]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAILED: %s\033[0m\n' "$1" >&2; exit 1; }

step "Independent oracle self-test (published BIP32/BIP39 vectors)"
PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
  for candidate in "$REPO_ROOT/tools/derive/.venv/bin/python" python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
  done
fi
[[ -n "$PYTHON" ]] || fail "no python3 found"
"$PYTHON" - <<'PY' || fail "pycryptodome is required for the oracle (pip install pycryptodome)"
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("Crypto") else 1)
PY
(cd "$REPO_ROOT/tools/derive" && "$PYTHON" derive.py selftest) || fail "oracle self-test"

step "Differential fixtures are current"
# Regenerate the derivation vectors and fail if they changed: a stale fixture
# would let the Swift tests pass against yesterday's truth.
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
(cd "$REPO_ROOT/tools/derive" && "$PYTHON" derive.py gen-fixtures "$tmpdir" >/dev/null) || fail "fixture generation"
if ! diff -q "$tmpdir/derivation_vectors.json" \
     "$REPO_ROOT/ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures/derivation_vectors.json" >/dev/null; then
  echo "derivation_vectors.json is stale; regenerate with:"
  echo "  tools/derive/derive.py gen-fixtures ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures"
  fail "differential fixtures out of date"
fi
echo "  ok: derivation fixtures match the independent implementation"

step "VaultKit tests (crypto, BIP39/BIP32, addresses, BC-UR, ceremony)"
(cd "$REPO_ROOT/ios/Packages/VaultKit" && swift test) || fail "VaultKit tests"

step "YubikeyKit tests (APDU codec, OpenPGP card, transports)"
(cd "$REPO_ROOT/ios/Packages/YubikeyKit" && swift test) || fail "YubikeyKit tests"

if [[ "$QUICK" == "0" ]]; then
  step "App builds (Release, unsigned)"
  (cd "$REPO_ROOT/ios" && xcodebuild \
      -project PlexVault.xcodeproj -scheme PlexVault \
      -configuration Release -sdk iphonesimulator \
      -destination 'generic/platform=iOS Simulator' \
      CODE_SIGNING_ALLOWED=NO build) >/dev/null || fail "app Release build"

  step "Release audit"
  APP="$(find "$HOME/Library/Developer/Xcode/DerivedData" -name 'PlexVault.app' \
        -path '*Release-iphonesimulator*' 2>/dev/null | head -1 || true)"
  [[ -n "$APP" ]] || fail "no Release app bundle found for the audit"
  "$REPO_ROOT/tools/audit-release.sh" "$APP" || fail "release audit"
fi

printf '\n\033[32mAll off-hardware checks passed.\033[0m\n'
echo "Hardware-only checks remaining: docs/m0-hardware-verification.md"
