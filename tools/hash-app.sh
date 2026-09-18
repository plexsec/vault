#!/usr/bin/env bash
#
# Reproducible artifact hashing for PlexVault.
#
# Purpose (design.md §4.2 step 1, Appendix B): the operator must be able to check
# that the app on the offline iPhone is the one built from the published source.
#
# What "reproducible" means here, stated honestly:
#
#   * The hash published for review is the SHA-256 of the *unsigned* app binary,
#     so it does not depend on any signing identity or provisioning profile.
#   * Bit-for-bit reproducibility is guaranteed only for a fixed toolchain. The
#     toolchain identity (Xcode build, Swift version, SDK build) is printed and
#     recorded so a mismatch can be detected rather than silently producing a
#     different hash.
#   * The build is deterministic in its inputs: no timestamps or random values are
#     embedded by this project, package dependencies are pinned local paths, and
#     no network fetch happens during the build.
#
# Usage:
#   tools/hash-app.sh                 # build Release and print hashes + record
#   tools/hash-app.sh --no-build      # just hash whatever is already built
#   tools/hash-app.sh --output FILE   # write the record to FILE
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$REPO_ROOT/ios"
SCHEME="PlexVault"
CONFIGURATION="Release"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/build}"

build=1
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) build=0; shift ;;
    --output) output="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ "$build" == "1" ]]; then
  echo "==> Building $SCHEME ($CONFIGURATION) for iphoneos"
  # A device build needs a signing identity to install, but hashing does not:
  # signing is disabled here on purpose so the hash is identity-independent.
  xcodebuild \
    -project "$PROJECT_DIR/$SCHEME.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" \
    build
fi

APP="$BUILD_DIR/DerivedData/Build/Products/$CONFIGURATION-iphoneos/$SCHEME.app"
if [[ ! -d "$APP" ]]; then
  echo "error: no built app at $APP" >&2
  echo "hint: run without --no-build first, or set BUILD_DIR" >&2
  exit 1
fi

echo
echo "==> Toolchain identity (record this; a different toolchain can produce a different hash)"
XCODE_VERSION="$(xcodebuild -version | tr '\n' ' ' | sed 's/  */ /g')"
SWIFT_VERSION="$(swift --version 2>&1 | head -1)"
SDK_VERSION="$(xcodebuild -showsdks 2>/dev/null | awk '/iphoneos/{print $2; exit}')"
echo "    xcodebuild : $XCODE_VERSION"
echo "    swift      : $SWIFT_VERSION"
echo "    iphoneos   : $SDK_VERSION"

echo
echo "==> Artifact hashes (unsigned)"
echo "    app bundle directory : $(shasum -a 256 <(find "$APP" -type f -print0 | sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}') | awk '{print $1}')  (hash of the sorted per-file hash list)"
MAIN_BINARY="$APP/$SCHEME"
MAIN_HASH="$(shasum -a 256 "$MAIN_BINARY" | awk '{print $1}')"
echo "    main executable      : $MAIN_HASH"
for dylib in "$APP"/*.dylib; do
  [[ -e "$dylib" ]] || continue
  echo "    $(basename "$dylib") : $(shasum -a 256 "$dylib" | awk '{print $1}')"
done

echo
echo "==> Mach-O UUIDs (expected to differ between builds; recorded for support)"
if command -v dwarfdump >/dev/null 2>&1; then
  dwarfdump --uuid "$MAIN_BINARY" | sed 's/^/    /'
fi

if [[ -n "$output" ]]; then
  {
    echo "# PlexVault release hash record"
    echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "toolchain.xcodebuild: $XCODE_VERSION"
    echo "toolchain.swift: $SWIFT_VERSION"
    echo "toolchain.iphoneos: $SDK_VERSION"
    echo "app.main_executable.sha256: $MAIN_HASH"
    if [[ -n "${GITHUB_SHA:-}" ]]; then echo "source.commit: $GITHUB_SHA"; fi
    echo "source.git_describe: $(git -C "$REPO_ROOT" describe --always --dirty --tags 2>/dev/null || echo unknown)"
  } > "$output"
  echo
  echo "==> Wrote $output"
fi

echo
echo "Publish the main-executable hash above next to the source release. Reproduce"
echo "it with: tools/hash-app.sh --no-build   (after building with the same toolchain)"
