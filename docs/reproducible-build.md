# Reproducible builds — scope and limits

design.md §4.2 step 1 requires the operator to verify that the app on the offline
iPhone was built from the published source. This document says exactly what can be
checked and what cannot, so nobody over-trusts it.

## What is published

`tools/hash-app.sh` builds Release for `iphoneos` with signing **disabled** and
prints:

* SHA-256 of the main executable,
* SHA-256 of each dylib in the bundle,
* a SHA-256 over the sorted per-file hash list of the whole bundle,
* the toolchain identity (Xcode build, Swift version, iphoneos SDK build),
* the source revision.

Signing is disabled deliberately: the hash must not depend on a signing identity
or provisioning profile, both of which are per-developer.

## What reproduction requires

Bit-for-bit reproduction is only claimed **for a fixed toolchain**. The record
includes it, and a mismatch invalidates the comparison. Reproduce with:

```sh
git checkout <revision from the record>
tools/hash-app.sh --no-build     # after building with the same toolchain
```

The reference toolchain for v0.1:

| Component | Version |
|---|---|
| Xcode | 26.6 (17F113) |
| Swift | 6.3.3 (swiftlang-6.3.3.1.3) |
| iphoneos SDK | 26.5 |

## What is deterministic in this project

* No network access during the build. All dependencies are local paths; there is
  no package resolution step that fetches anything.
* No generated source at build time. The BIP39 wordlist is committed as Swift
  source, regenerable and hash-checked (`tools/generate-bip39-wordlist.sh`).
* No timestamps, random values, or build counters injected by this project.
* libsecp256k1 is vendored at a pinned release (`v0.8.0`) with the tarball's
  SHA-256 recorded in `Sources/Csecp256k1/VENDORED.txt`, and no configuration
  header is generated.
* TweetNaCl is vendored at the pinned `20140427` release, byte-identical to
  upstream and recorded by MD5 in `Sources/Ced25519/VENDORED.txt`. The
  project's own `vault_ed25519.c` shim is the only additional source in that
  target, and `tweetnacl.c` is compiled exactly once (from the shim), so the
  vendored bytes stay verifiable.
* The BC-UR sources are ported at a pinned upstream commit, recorded in each
  file's header, with the licence alongside them.
* `PlexVault.xcodeproj` is committed, so a build never depends on the XcodeGen
  version used to generate it.

## What is NOT guaranteed

1. **Bit-identical output across toolchain versions.** Swift and Xcode change code
   generation; the record therefore pins the toolchain rather than pretending the
   hash is universal.
2. **Bit-identical output across architectures or optimisation settings.** Debug
   and Release differ, and the arm64 and simulator slices differ. Only the
   documented Release `iphoneos` configuration is comparable.
3. **Reproduction of the signature.** The published hash is of the unsigned
   binary. A signed, installed app has a different on-disk hash; compare the
   executable inside the bundle, not the bundle you installed.
4. **A verified chain from source to the installed app.** Nothing here prevents a
   developer from building modified source and installing it. The hash check
   detects that only if the operator compares against the published value — which
   is why Appendix B lists it as a manual step. It is a *detection* control, not a
   prevention control.
5. **Absence of a compiler-level backdoor.** Reproducibility is about matching a
   published artifact, not about proving the compiler is honest. The WYSINWYX
   problem is out of scope, as is a compromised Xcode.

## What has been verified by machine instead

Because "reproducible" is weaker than it sounds, the properties that matter most
are asserted mechanically by `tools/audit-release.sh`, which fails the build if:

* any simulated-card string appears anywhere in the Release bundle (a release
  build must not be able to talk to a fake card),
* a networking framework is linked or a networking API is referenced,
* the app or ceremony layer references a persistence API,
* the `CeremonyReport` type carries a secret-bearing field,
* the NFC usage string, the OpenPGP AID, or the encryption-declaration key is
  missing from `Info.plist`.

That audit is itself tested: running it against a DEBUG bundle must fail. An
audit that cannot fail is not an audit, and an early version of this one silently
never fired because `strings | grep -q` under `set -o pipefail` reports failure on
a *match* (SIGPIPE). The check is now written to match against captured text, and
`tools/verify.sh` runs the audit on every verification pass.
