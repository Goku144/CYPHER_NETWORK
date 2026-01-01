#include "cypher.h"

#if !defined(__CY_ALGO__)
#define __CY_ALGO__

/**
 * RSA-encrypt a single byte `c` using key[0]=exponent and key[1]=modulus (powm),
 * writing the ciphertext as a big integer into `cy_msg`.
 */
void cy_rsa_encrypt(const uint8_t c, const mpz_t *key, mpz_ptr cy_msg);

/**
 * RSA-decrypt a big-integer ciphertext `cy_msg` using key[0]=exponent and key[1]=modulus,
 * storing the recovered plaintext byte into `*c`.
 */
void cy_rsa_decrypt(const mpz_srcptr cy_msg, const mpz_t *key, uint8_t *c);

/**
 * AES key-schedule g() function: RotWord/SubWord + Rcon step applied to word `*w`
 * for round index `j`.
 */
void cy_aes_g_function(const uint8_t j, uint32_t *w);

/**
 * AES AddRoundKey: XOR the 4-word round key `rk` into the 16-byte `state`.
 */
void cy_aes_add_round_key(uint32_t *rk, uint8_t *state);

/**
 * AES SubBytes: substitute each byte of `state` using the provided 16x16 S-box table.
 */
void cy_aes_sub_bytes(const uint8_t stable[16][16], uint8_t *state);

/**
 * AES ShiftRows: perform the standard left row-rotations on the 16-byte `state`.
 */
void cy_aes_shift_rows(uint8_t *state);

/**
 * AES InvShiftRows: perform the standard inverse (right) row-rotations on `state`.
 */
void cy_aes_inv_shift_rows(uint8_t *state);

/**
 * AES MixColumns: mix each column of `state` in GF(2^8) using the standard matrix.
 */
void cy_aes_mix_columns(uint8_t *state);

/**
 * AES InvMixColumns: inverse mix of each column of `state` in GF(2^8).
 */
void cy_aes_inv_mix_columns(uint8_t *state);

/**
 * AES encrypt one 16-byte block: encrypt plaintext `pt` into ciphertext `ct`
 * using the expanded key `ek`.
 */
void cy_aes_encrypt(const CY_AES_EKEY ek, const uint8_t *pt, uint8_t *ct);

/**
 * AES decrypt one 16-byte block: decrypt ciphertext `ct` into plaintext `pt`
 * using the expanded key `ek`.
 */
void cy_aes_decrypt(const CY_AES_EKEY ek, const uint8_t *ct, uint8_t *pt);

#endif // __CY_ALGO__
