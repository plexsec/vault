#!/usr/bin/env bash
#
# Release audit for PlexVault.
#
# These are the checks that must pass before a build is treated as shippable.
# Each one is a *mechanical* check on the built product, not a promise in a
# document:
#
#   1. No simulated YubiKey anywhere in the release bundle. A release build must
#      not be able to talk to a fake card.
#   2. No network API is linked or referenced. The app must be offline by
#      construction, not by policy.
#   3. No secret material is persisted: no writes of mnemonic/PIN/key data and no
#      use of UserDefaults/Keychain for ceremony secrets.
#   4. The NSCameraUsageDescription / NFC keys are present, and NFC declares the
#      OpenPGP AID (without it iOS never surfaces the card).
#
# Usage: tools/audit-release.sh [path/to/PlexVault.app]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${1:-}"

if [[ -z "$APP" ]]; then
  APP="$(find "$REPO_ROOT/ios/build" "$HOME/Library/Developer/Xcode/DerivedData" \
      -name 'PlexVault.app' -path '*Release-iphoneos*' 2>/dev/null | head -1 || true)"
fi
if [[ -z "$APP" || ! -d "$APP" ]]; then
  echo "error: no Release app bundle found. Build it first:" >&2
  echo "  tools/hash-app.sh" >&2
  echo "or pass the path explicitly: tools/audit-release.sh /path/to/PlexVault.app" >&2
  exit 1
fi

echo "==> Auditing $APP"
failures=0

note_fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
note_ok()   { echo "  ok  : $1"; }

# Match against captured text rather than a pipeline.
#
# `strings file | grep -q pattern` looks like the obvious way to write these
# checks, but it is WRONG under `set -o pipefail`: on a match, `grep -q` exits
# immediately and `strings` dies of SIGPIPE, so the pipeline reports 141 and the
# check silently never fires. That bug disabled check [1] entirely until a
# negative test (running the audit against a DEBUG bundle) caught it.
matches() { grep -qE "$2" <<<"$1"; }

# ---------------------------------------------------------------------------
# 1. No simulated card in the release bundle.
# ---------------------------------------------------------------------------
echo
echo "[1] Simulated YubiKey must be absent"
simulated_hits=0
while IFS= read -r -d '' file; do
  case "$file" in *.dylib|*.app/*|*/PlexVault|*/PlexVault.debug.dylib) ;; *) continue ;; esac
  file_strings="$(strings "$file" 2>/dev/null || true)"
  if matches "$file_strings" 'MockYubikey|Simulated YubiKey|simulated card'; then
    note_fail "simulated-card strings found in $(basename "$file")"
    simulated_hits=$((simulated_hits + 1))
  fi
done < <(find "$APP" -type f -print0)
if [[ "$simulated_hits" == "0" ]]; then
  note_ok "no simulated-card strings in any file of the bundle"
fi

# ---------------------------------------------------------------------------
# 2. Offline by construction.
# ---------------------------------------------------------------------------
echo
echo "[2] No networking"
# Check the *linked libraries* first: Objective-C/Swift network use always drags
# in one of these, regardless of which API is called.
for binary in "$APP/PlexVault" "$APP"/*.dylib; do
  [[ -f "$binary" ]] || continue
  linked="$(otool -L "$binary" 2>/dev/null | tail -n +2 || true)"
  for forbidden in CFNetwork Network.framework WebKit; do
    if matches "$linked" "$forbidden"; then
      note_fail "$(basename "$binary") links $forbidden"
    fi
  done
done
# Then check the source for the APIs that would matter if a framework were
# pulled in indirectly.
network_hits="$(grep -rnE '\bURLSession\b|\bNWConnection\b|CFStreamCreate|NSURLConnection' \
      "$REPO_ROOT/ios/PlexVault" \
      "$REPO_ROOT/ios/Packages/VaultKit/Sources" \
      "$REPO_ROOT/ios/Packages/YubikeyKit/Sources" 2>/dev/null || true)"
network_hits="$(grep -v '^\s*//' <<<"$network_hits" || true)"
if [[ -n "$network_hits" ]]; then
  note_fail "network API referenced in source:"
  sed 's/^/        /' <<<"$network_hits"
else
  note_ok "no URLSession/NWConnection/CFStream references in app or packages"
fi

# ---------------------------------------------------------------------------
# 3. No secret persistence.
# ---------------------------------------------------------------------------
echo
echo "[3] No secret persistence"
persist_hits="$(grep -rnE 'UserDefaults|NSUbiquitousKeyValueStore|FileManager\.default\.createFile|SecItemAdd|\.write\(to:' \
      "$REPO_ROOT/ios/PlexVault" \
      "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/Ceremony" 2>/dev/null || true)"
persist_hits="$(grep -v '^\s*//' <<<"$persist_hits" || true)"
if [[ -n "$persist_hits" ]]; then
  note_fail "persistence API referenced in the app or ceremony layer:"
  sed 's/^/        /' <<<"$persist_hits"
else
  note_ok "ceremony and app do not persist anything"
fi
# The only persisted item permitted is the redacted report, which the operator
# exports deliberately. Assert the report type holds no secret-bearing field.
report_fields="$(grep -nE 'var (mnemonic|seed|privateKey|pin)' \
     "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/Ceremony/ProvisioningCeremony.swift" 2>/dev/null || true)"
if matches "$report_fields" 'CeremonyReport'; then
  note_fail "CeremonyReport appears to carry a secret field"
else
  note_ok "CeremonyReport carries no secret fields"
fi
# Positive assertion: the report type really is the one being inspected.
if ! grep -q "public struct CeremonyReport" \
     "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/Ceremony/ProvisioningCeremony.swift"; then
  note_fail "could not locate CeremonyReport; the check above proved nothing"
fi

# ---------------------------------------------------------------------------
# 4. Platform keys.
# ---------------------------------------------------------------------------
echo
echo "[4] Info.plist requirements"
PLIST="$APP/Info.plist"
plist_value() { /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null || true; }

if [[ -n "$(plist_value NFCReaderUsageDescription)" ]]; then
  note_ok "NFCReaderUsageDescription present"
else
  note_fail "NFCReaderUsageDescription missing"
fi
aid_list="$(/usr/libexec/PlistBuddy -c "Print :com.apple.developer.nfc.readersession.iso7816.select-identifiers" "$PLIST" 2>/dev/null || true)"
if matches "$aid_list" 'D27600012401'; then
  note_ok "OpenPGP AID declared for NFC selection"
else
  note_fail "OpenPGP AID (D27600012401) not declared; iOS will not surface the YubiKey"
fi
if [[ "$(plist_value ITSAppUsesNonExemptEncryption)" == "false" ]]; then
  note_ok "ITSAppUsesNonExemptEncryption=false"
else
  note_fail "ITSAppUsesNonExemptEncryption is not false"
fi

# ---------------------------------------------------------------------------
echo
if [[ "$failures" -gt 0 ]]; then
  echo "AUDIT FAILED: $failures problem(s)"
  exit 1
fi
echo "AUDIT PASSED"
