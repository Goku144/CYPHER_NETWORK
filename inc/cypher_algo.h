#include "cypher.h"

#if !defined(__CY_ALGO__)
#define __CY_ALGO__

void cy_rsa_encrypt(const uint8_t c, const mpz_t *key, mpz_ptr cy_msg);

void cy_rsa_decrypt(const mpz_srcptr cy_msg, const mpz_t *key, uint8_t *c);

void cy_aes_g_function(const uint8_t j, uint32_t *w);

void cy_aes_add_round_key(uint32_t *rk, uint8_t *state);

void cy_aes_sub_bytes(const uint8_t stable[16][16], uint8_t *state);

void cy_aes_shift_rows(uint8_t *state);

void cy_aes_inv_shift_rows(uint8_t *state);

void cy_aes_mix_columns(uint8_t *state);

void cy_aes_inv_mix_columns(uint8_t *state);

void cy_aes_encrypt(const CY_AES_EKEY ek, const uint8_t *pt, uint8_t *ct);

void cy_aes_decrypt(const CY_AES_EKEY ek, const uint8_t *ct, uint8_t *pt);

#endif // __CY_ALGO__
