/*
 * Project-owned shim over the vendored TweetNaCl source.
 *
 * Why this file #includes a .c file
 * ---------------------------------
 * TweetNaCl's seed-free keygen internals (`scalarbase`, `pack`, the `gf` field
 * type) are file-static, and the public API has no seed-based keypair entry
 * point. Patching tweetnacl.c would make the vendored artifact unverifiable by
 * hash, which is the property VENDORED.txt exists to preserve. Including the
 * vendored translation unit here is the only way to reach those statics while
 * leaving the vendored bytes untouched.
 *
 * Consequently `tweetnacl.c` is listed in this target's `exclude` in
 * Package.swift: it is compiled exactly once, right here.
 */

#include "vault_ed25519.h"

#include <stdlib.h>

/*
 * TweetNaCl's crypto_sign_keypair() calls this. It must be defined for the
 * translation unit to link. It traps rather than generating randomness: this
 * project has exactly one key-generation path (vault_ed25519_seed_keypair,
 * driven by a mnemonic-derived seed), and a second, silently-available RNG path
 * is precisely the kind of thing this codebase avoids.
 */
void randombytes(unsigned char *p, unsigned long long n)
{
    (void)p;
    (void)n;
    abort();
}

#include "tweetnacl.c"

int vault_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                               const unsigned char *seed)
{
    unsigned char d[64];
    gf p[4];
    int i;

    /* This is crypto_sign_keypair() with the randombytes() call replaced by the
     * caller-supplied seed; it must stay in step with the vendored version. */
    FOR(i, 32) sk[i] = seed[i];
    crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d);
    pack(pk, p);

    FOR(i, 32) sk[32 + i] = pk[i];
    return 0;
}

int vault_ed25519_sign(unsigned char *sm, unsigned long long *smlen,
                       const unsigned char *m, unsigned long long n,
                       const unsigned char *sk)
{
    return crypto_sign(sm, smlen, m, n, sk);
}

int vault_ed25519_sign_open(unsigned char *m, unsigned long long *mlen,
                            const unsigned char *sm, unsigned long long n,
                            const unsigned char *pk)
{
    return crypto_sign_open(m, mlen, sm, n, pk);
}
