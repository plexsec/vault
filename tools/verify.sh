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
stale=0
for fixture in derivation_vectors.json signing_vectors.json; do
  if ! diff -q "$tmpdir/$fixture" \
       "$REPO_ROOT/ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures/$fixture" >/dev/null; then
    echo "$fixture is stale; regenerate with:"
    echo "  tools/derive/derive.py gen-fixtures ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures"
    stale=1
  fi
done
if [[ "$stale" == "1" ]]; then
  fail "differential fixtures out of date"
fi
echo "  ok: derivation and signing fixtures match the independent implementation"

step "VaultKit tests (crypto, BIP39/BIP32, addresses, BC-UR, ceremony)"
(cd "$REPO_ROOT/ios/Packages/VaultKit" && swift test) || fail "VaultKit tests"

step "YubikeyKit tests (APDU codec, OpenPGP card, transports)"
(cd "$REPO_ROOT/ios/Packages/YubikeyKit" && swift test) || fail "YubikeyKit tests"

if [[ "$QUICK" == "0" ]]; then
  step "App UI tests (setup screen and ceremony entry)"
  # Finds an iOS 26 simulator; skips with a warning rather than failing when none
  # is installed, since these tests need a simulator runtime.
  SIM_ID="$(xcrun simctl list devices available --json 2>/dev/null | python3 -c '
import json, sys
data = json.load(sys.stdin).get("devices", {})
for runtime in sorted(data):
    if "iOS-26" not in runtime:
        continue
    for device in data[runtime]:
        if device.get("isAvailable") and device.get("name", "").startswith("iPhone"):
            print(device["udid"])
            raise SystemExit
' 2>/dev/null || true)"
  if [[ -n "$SIM_ID" ]]; then
    if ! (cd "$REPO_ROOT/ios" && xcodebuild test \
        -project PlexVault.xcodeproj -scheme PlexVault \
        -sdk iphonesimulator -destination "platform=iOS Simulator,id=$SIM_ID" \
        CODE_SIGNING_ALLOWED=NO) > /tmp/plexvault-uitests.log 2>&1; then
      echo "see /tmp/plexvault-uitests.log"
      fail "UI tests"
    fi
    echo "  ok: setup screen and ceremony entry behave as expected"
  else
    echo "  skipped: no iOS 26 iPhone simulator installed"
  fi


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
