#ifndef VAULT_ED25519_H
#define VAULT_ED25519_H

/*
 * Deterministic Ed25519 over the vendored, unmodified TweetNaCl (see
 * ../VENDORED.txt).
 *
 * TweetNaCl's public API exposes only crypto_sign_keypair(), which draws the
 * seed from randombytes(). This project derives the Ed25519 seed from a BIP39
 * mnemonic via SLIP-0010, so it needs a keypair from a caller-supplied seed.
 * These three entry points provide that without modifying the vendored source.
 */

/* pk[32] <- public key, sk[64] <- seed || pk, from seed[32]. Returns 0. */
int vault_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                               const unsigned char *seed);

/* Ed25519 over the message itself (NOT a precomputed digest).
 * sm must have room for n + 64 bytes. Returns 0. */
int vault_ed25519_sign(unsigned char *sm, unsigned long long *smlen,
                       const unsigned char *m, unsigned long long n,
                       const unsigned char *sk);

/* Returns 0 on a valid signature, -1 otherwise. m must have room for n bytes. */
int vault_ed25519_sign_open(unsigned char *m, unsigned long long *mlen,
                            const unsigned char *sm, unsigned long long n,
                            const unsigned char *pk);

#endif /* VAULT_ED25519_H */
