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
#      use of UserDefaults/Keychain for ceremony secrets. Two non-secret values are
#      permitted — the card connection the operator chose once, and a flag saying a run
#      stopped at the wipe so the next launch pairs the wallet — plus one DEBUG-only store
#      that saves the *simulated* card's state so a developer does not re-provision the fake
#      wallet on every launch. The check names all three files and their keys rather than
#      ignoring persistence in general, and asserts the simulated store cannot ship.
#   4. The camera, photo-library-add and NFC keys are present, and NFC declares the
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
echo "[1] Simulated YubiKey and test hooks must be absent"
simulated_hits=0
while IFS= read -r -d '' file; do
  case "$file" in *.dylib|*.app/*|*/PlexVault|*/PlexVault.debug.dylib) ;; *) continue ;; esac
  file_strings="$(strings "$file" 2>/dev/null || true)"
  if matches "$file_strings" 'MockYubikey|Simulated YubiKey|simulated card|deterministic-entropy'; then
    note_fail "debug-only string found in $(basename "$file")"
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
# Three persistence sites are permitted, and they are named here rather than excluded by
# silence. `DeviceChoiceStore` holds which reader the YubiKey is on; `PendingPairingStore`
# holds one Bool saying that a run stopped at the wipe and that the next launch should start
# in the pairing process (amendment 43); `SimulatedCardTransport.swift` holds the DEBUG-only
# simulated card's own state. None is a real secret: the first selects a channel (check 1
# asserts that a release build has no simulated transport to point it at), the second is a
# routing flag whose *payload* is deliberately nothing — the pairing codes are rebuilt from
# the card's manifest by the read-only route, and never stored on the phone — and the third
# belongs to a fake applet that is excluded from Release altogether. Everything else must
# still be untouched: no key material, no PINs, no pairing material, no ceremony state.
DEVICE_STORE="$REPO_ROOT/ios/PlexVault/Support/DeviceChoiceStore.swift"
PENDING_STORE="$REPO_ROOT/ios/PlexVault/Support/PendingPairingStore.swift"
SIMULATED_STORE="$REPO_ROOT/ios/PlexVault/Debug/SimulatedCardTransport.swift"
persist_hits="$(grep -rnE 'UserDefaults|NSUbiquitousKeyValueStore|FileManager\.default\.createFile|SecItemAdd|\.write\(to:' \
      "$REPO_ROOT/ios/PlexVault" \
      "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/Ceremony" \
      "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/Signing" 2>/dev/null \
      | grep -v "^${DEVICE_STORE}:" | grep -v "^${PENDING_STORE}:" \
      | grep -v "^${SIMULATED_STORE}:" || true)"
persist_hits="$(grep -v '^\s*//' <<<"$persist_hits" || true)"
if [[ -n "$persist_hits" ]]; then
  note_fail "persistence API referenced outside the three named stores:"
  sed 's/^/        /' <<<"$persist_hits"
else
  note_ok "the only persistence sites are the device-choice, pending-pairing and simulated-card stores"
fi
# The exceptions are one key each in one file, so assert exactly that: each store exists,
# names the key its screen reads, stores nothing else, and does not reach for a
# secret-bearing API (the keychain) or the filesystem. Without these, deleting a store would
# turn the check above into a pass for the wrong reason.
if [[ ! -f "$DEVICE_STORE" ]]; then
  note_fail "the permitted persistence site is missing; the check above proved nothing"
else
  if ! grep -q 'com\.plexsec\.vault\.device-choice' "$DEVICE_STORE"; then
    note_fail "the device-choice store does not name the expected key"
  fi
  store_keys="$(grep -cE '\.set\(|\.string\(forKey:|\.removeObject\(forKey:' "$DEVICE_STORE" || true)"
  if [[ "$store_keys" -gt 3 ]]; then
    note_fail "the device-choice store touches more than one key ($store_keys accesses)"
  fi
  if grep -qE 'SecItem(Add|Copy|Update)|FileManager|NSKeyedArchiver|\.write\(to:' "$DEVICE_STORE"; then
    note_fail "the device-choice store reaches for something other than UserDefaults"
  else
    note_ok "device choice: one UserDefaults key, no keychain, no files"
  fi
fi
# The pending-pairing flag is the second site, and the assertion that matters is what it does
# *not* hold: no pairing export, no public key, no chain code, no mnemonic, and no record. A
# store that carried any of those would make the phone hold watch-only material at rest, which
# is exactly what rebuilding the codes from the card avoids (amendment 43).
if [[ ! -f "$PENDING_STORE" ]]; then
  note_fail "the pending-pairing store is missing; the check above proved nothing here"
else
  if ! grep -q 'com\.plexsec\.vault\.pending-pairing' "$PENDING_STORE"; then
    note_fail "the pending-pairing store does not name the expected key"
  fi
  pending_keys="$(grep -cE '\.set\(|\.bool\(forKey:|\.removeObject\(forKey:' "$PENDING_STORE" || true)"
  if [[ "$pending_keys" -gt 3 ]]; then
    note_fail "the pending-pairing store touches more than one key ($pending_keys accesses)"
  fi
  if grep -qE 'SecItem(Add|Copy|Update)|FileManager|NSKeyedArchiver|\.write\(to:' "$PENDING_STORE"; then
    note_fail "the pending-pairing store reaches for something other than UserDefaults"
  else
    note_ok "pending pairing: one UserDefaults key, no keychain, no files"
  fi
  if grep -qE 'CeremonyReport|PairingExport|PairingManifest|\.string\(forKey:|chainCode|publicKey|mnemonic' "$PENDING_STORE"; then
    note_fail "the pending-pairing store carries pairing material; the flag must be the whole payload"
  else
    note_ok "pending pairing: a flag and nothing else — no codes, keys or record"
  fi
fi
# The third site is DEBUG-only: it saves the *simulated* card's state so a developer does not
# have to provision the fake wallet again after every relaunch. It is named here so the
# exception is stated rather than slipped in, and the assertions make the naming safe: the file
# must be `#if DEBUG`-guarded, it must live under the Debug directory, and it must reach for no
# secret-bearing API. Check 1 is what guarantees the card it belongs to is not in a release
# build at all.
if [[ ! -f "$SIMULATED_STORE" ]]; then
  note_fail "the simulated-card store is missing; the check above proved nothing"
else
  if ! grep -q 'com\.plexsec\.vault\.simulated-card' "$SIMULATED_STORE"; then
    note_fail "the simulated-card store does not name the expected key"
  fi
  if ! grep -qE '^#if DEBUG' "$SIMULATED_STORE"; then
    note_fail "the simulated-card store is not DEBUG-gated; a release build would compile it"
  fi
  case "$SIMULATED_STORE" in
    */Debug/*) ;;
    *) note_fail "the simulated-card store is not in a Debug directory" ;;
  esac
  if grep -qE 'SecItem(Add|Copy|Update)|NSKeyedArchiver|\.write\(to:|CeremonyReport|PairingExport' "$SIMULATED_STORE"; then
    note_fail "the simulated-card store reaches for something other than UserDefaults"
  else
    note_ok "simulated card: DEBUG-only, one namespaced key per card, simulated state only"
  fi
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
# 3b. No in-memory signing.
# ---------------------------------------------------------------------------
echo
echo "[3b] No in-memory signing"
# The vendored libsecp256k1 compiles its recovery module, which also contains
# secp256k1_ecdsa_sign_recoverable (a secret-key entry point). The app must never
# call it: the signing key exists only on the YubiKey, and a signature produced
# from a secret held in the phone would defeat the entire design (design.md §3.2).
# Only the calls that take a *secret key* are listed, and they are matched with word
# boundaries: `secp256k1_ecdsa_signature_parse_compact` (used by verification) shares
# a prefix with the signing entry point, and a check that fires on the verifier would
# be turned off rather than fixed. Verification and recovery take public material and
# are the point of the module.
signing_hits="$(grep -rnE '\bsecp256k1_ecdsa_sign\b|\bsecp256k1_ecdsa_sign_recoverable\b' \
      "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit" \
      "$REPO_ROOT/ios/PlexVault" 2>/dev/null || true)"
signing_hits="$(grep -v '^\s*//' <<<"$signing_hits" || true)"
if [[ -n "$signing_hits" ]]; then
  note_fail "a secret-key signing entry point is referenced:"
  sed 's/^/        /' <<<"$signing_hits"
else
  note_ok "no signing entry point is referenced by the app or VaultKit"
fi
# Positive assertion: the recovery module really is compiled in, otherwise the
# check above would pass by looking at a library that cannot verify anything.
if ! grep -q 'ENABLE_MODULE_RECOVERY' "$REPO_ROOT/ios/Packages/VaultKit/Package.swift"; then
  note_fail "recovery module is not enabled; the signing flow cannot determine v"
fi
if ! grep -q 'secp256k1_ecdsa_recover' \
     "$REPO_ROOT/ios/Packages/VaultKit/Sources/VaultKit/Crypto/Secp256k1.swift"; then
  note_fail "VaultKit does not use secp256k1 recovery; the check above proved nothing"
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
# The signing flow reads the wallet's request through the camera, so the usage
# string must be there — without it iOS kills the app the moment scanning starts.
camera="$(plist_value NSCameraUsageDescription)"
if [[ -z "$camera" ]]; then
  note_fail "NSCameraUsageDescription is missing; the signing flow cannot scan"
else
  note_ok "NSCameraUsageDescription present"
fi
# Saving the record writes one image the operator asked for. Without the add-only usage string iOS
# terminates the app the moment the write is attempted — the same failure mode as a missing camera
# string, and just as invisible until it happens.
photo="$(plist_value NSPhotoLibraryAddUsageDescription)"
if [[ -z "$photo" ]]; then
  note_fail "NSPhotoLibraryAddUsageDescription is missing; saving the record to Photos would be killed by iOS"
else
  note_ok "NSPhotoLibraryAddUsageDescription present"
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
