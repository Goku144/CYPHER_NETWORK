#include <stdint.h>
#include "cypher.h"

#if !defined(__CY_KEY__)
#define __CY_KEY__

/**
 * Expand an AES key into the full AES round-key schedule stored in `*w`.
 */
void cy_aes_key_expansion(const CY_AES_KEY key, CY_AES_EKEY *w);

/**
 * Generate a random AES key of the requested size into `*key`.
 */
void cy_aes_key_gen(const CY_AES_size size, CY_AES_KEY *key);

/**
 * Export an AES key into a CY_BUFF frame (sets key flags/type and length).
 */
void cy_aes_key_exp(const CY_AES_KEY key, CY_BUFF *buf);

/**
 * Import an AES key from a CY_BUFF frame into `*key` (expects key flag/type to be set).
 */
void cy_aes_key_imp(const CY_BUFF buf, CY_AES_KEY *key);

/**
 * Receive an AES key frame from `fd`, import it, and build the expanded key into `*ekey`.
 */
void cy_aes_get_key(int fd, CY_AES_EKEY *ekey);

/**
 * Generate an AES key, send it to `fd` as a key frame, and also build the expanded key into `*ekey`.
 */
void cy_aes_set_key(int fd, CY_AES_EKEY *ekey);

/**
 * Receive an RSA key frame from `fd` and import it into the already-initialized mpz_t key[2].
 */
void cy_rsa_get_key(int fd, mpz_t key[2]);

/**
 * Generate an RSA keypair, copy into `pub` and `prv`, and send either public or private key over `fd`
 * depending on `send_private`.
 */
void cy_rsa_set_key(int fd, mp_bitcnt_t bitsize, mpz_t pub[2], mpz_t prv[2], int send_private);

/**
 * Generate an RSA keypair of `bitsize` bits, returning allocated mpz_t[2] public and private keys.
 */
void cy_rsa_key_gen(const mp_bitcnt_t bitsize, mpz_t **pubkey, mpz_t **prvkey);

/**
 * Export an RSA key (two mpz values) into a CY_BUFF frame suitable for transport/storage.
 */
void cy_rsa_key_exp(const mpz_t key0, const mpz_t key1, CY_BUFF *buf);

/**
 * Import an RSA key (two mpz values) from a CY_BUFF frame into `key0` and `key1`.
 */
void cy_rsa_key_imp(const CY_BUFF buf, mpz_t key0, mpz_t key1);

#endif // __CY_KEY__
