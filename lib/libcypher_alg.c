#include "../inc/cypher_err.h"
#include "../inc/cypher_const.h"
#include "../inc/cypher_math.h"
#include "../inc/cypher_key.h"
#include "../inc/cypher_algo.h"
#include "../inc/cypher.h"

void cy_rsa_encrypt(const uint8_t c, const mpz_t *key, mpz_ptr cy_msg)
{
    mpz_set_ui(cy_msg, c);
    mpz_powm(cy_msg, cy_msg, key[0], key[1]);
}

void cy_rsa_decrypt(const mpz_srcptr cy_msg, const mpz_t *key, uint8_t *c)
{
    mpz_t out; mpz_init(out);
    mpz_powm(out, cy_msg, key[0], key[1]);
    *c = (uint8_t) mpz_get_ui(out);
    mpz_clear(out);
}

void cy_aes_g_function(const uint8_t j, uint32_t *w)
{
    *w = (*w << 0x08)|(*w >> 0x18);
    *w = (((uint32_t) CY_AES_SBOX[(*w >> 0x04) & 0xF][(*w >> 0x00) & 0xF]) << 0x00)| // b3
         (((uint32_t) CY_AES_SBOX[(*w >> 0x0C) & 0xF][(*w >> 0x08) & 0xF]) << 0x08)| // b2
         (((uint32_t) CY_AES_SBOX[(*w >> 0x14) & 0xF][(*w >> 0x10) & 0xF]) << 0x10)| // b1
         (((uint32_t) CY_AES_SBOX[(*w >> 0x1C) & 0xF][(*w >> 0x18) & 0xF]) << 0x18); // b0
    *w ^= ((uint32_t) CY_RC[j]) << 0x18;
}

void cy_aes_add_round_key(uint32_t *rk, uint8_t *state)
{
    for (size_t i = 0; i < 4; i++)
    {
        state[i]      ^= ((rk[i] >> 0x18) & 0xFF);
        state[i + 4]  ^= ((rk[i] >> 0x10) & 0xFF);
        state[i + 8]  ^= ((rk[i] >> 0x08) & 0xFF);
        state[i + 12] ^= ((rk[i] >> 0x00) & 0xFF);
    }
}

void cy_aes_sub_bytes(const uint8_t stable[16][16], uint8_t *state)
{
    for (size_t i = 0; i < 16; i++)
        state[i] = stable[(state[i] >> 0x04) & 0xF][(state[i] >> 0x00) & 0xF]; 
}

void cy_aes_shift_rows(uint8_t *state)
{
    uint8_t tmp[12];
    for (size_t i = 0; i < 12; i++) tmp[i] = state[i + 4];
    state[4]  = tmp[1];  state[5]  = tmp[2]; state[6]  = tmp[3]; state[7]  = tmp[0];
    state[8]  = tmp[6];  state[9]  = tmp[7]; state[10] = tmp[4]; state[11] = tmp[5];
    state[12] = tmp[11]; state[13] = tmp[8]; state[14] = tmp[9]; state[15] = tmp[10];
}

void cy_aes_inv_shift_rows(uint8_t *state)
{
    uint8_t tmp[12];

    for (size_t i = 0; i < 12; i++)
        tmp[i] = state[i + 4];

    state[4]  = tmp[3]; state[5]  = tmp[0]; state[6]   = tmp[1]; state[7]   = tmp[2];
    state[8]  = tmp[6]; state[9]  = tmp[7]; state[10]  = tmp[4]; state[11]  = tmp[5];
    state[12] = tmp[9]; state[13] = tmp[10]; state[14] = tmp[11]; state[15] = tmp[8];
}

void cy_aes_mix_columns(uint8_t *state)
{
    uint8_t tmp[4];
    for (size_t i = 0; i < 4; i++)
    {
        tmp[0] = state[i]; tmp[1] = state[i + 4]; tmp[2] = state[i + 8]; tmp[3] = state[i + 12];
        state[i]     = CY_AES_MUL2[tmp[0]] ^ CY_AES_MUL3[tmp[1]] ^ tmp[2] ^ tmp[3];
        state[i + 4] = tmp[0] ^ CY_AES_MUL2[tmp[1]] ^ CY_AES_MUL3[tmp[2]] ^ tmp[3];
        state[i + 8] = tmp[0] ^ tmp[1] ^ CY_AES_MUL2[tmp[2]] ^ CY_AES_MUL3[tmp[3]];
        state[i + 12] = CY_AES_MUL3[tmp[0]] ^ tmp[1] ^ tmp[2] ^ CY_AES_MUL2[tmp[3]];
    }
}

void cy_aes_inv_mix_columns(uint8_t *state)
{
    uint8_t tmp[4];

    for (size_t i = 0; i < 4; i++)
    {
        tmp[0] = state[i]; tmp[1] = state[i + 4]; tmp[2] = state[i + 8]; tmp[3] = state[i + 12];
        state[i]     = CY_AES_MUL14[tmp[0]] ^ CY_AES_MUL11[tmp[1]] ^ CY_AES_MUL13[tmp[2]] ^ CY_AES_MUL9[tmp[3]];
        state[i + 4] = CY_AES_MUL9[tmp[0]]  ^ CY_AES_MUL14[tmp[1]] ^ CY_AES_MUL11[tmp[2]] ^ CY_AES_MUL13[tmp[3]];
        state[i + 8] = CY_AES_MUL13[tmp[0]] ^ CY_AES_MUL9[tmp[1]]  ^ CY_AES_MUL14[tmp[2]] ^ CY_AES_MUL11[tmp[3]];
        state[i + 12] = CY_AES_MUL11[tmp[0]] ^ CY_AES_MUL13[tmp[1]] ^ CY_AES_MUL9[tmp[2]]  ^ CY_AES_MUL14[tmp[3]];
    }
}


void cy_aes_encrypt(const CY_AES_EKEY ek, const uint8_t *pt, uint8_t *ct)
{
    uint8_t state[16];
    for (size_t i = 0; i < 4; i++)
    {
        state[i]      = pt[i * 4];
        state[i + 4]  = pt[i * 4 + 1];
        state[i + 8]  = pt[i * 4 + 2];
        state[i + 12] = pt[i * 4 + 3];
    }
    cy_aes_add_round_key(ek.words, state);
    for (size_t i = 1; i < ek.nr; i++)
    {
        cy_aes_sub_bytes(CY_AES_SBOX, state);
        cy_aes_shift_rows(state);
        cy_aes_mix_columns(state);
        cy_aes_add_round_key(ek.words + i * 4, state);
    }
    cy_aes_sub_bytes(CY_AES_SBOX, state);
    cy_aes_shift_rows(state);
    cy_aes_add_round_key(ek.words + ek.nr * 4, state);
    for (size_t i = 0; i < 4; i++)
    {
        ct[i]      = state[i * 4];
        ct[i + 4]  = state[i * 4 + 1];
        ct[i + 8]  = state[i * 4 + 2];
        ct[i + 12] = state[i * 4 + 3];
    }
}

void cy_aes_decrypt(const CY_AES_EKEY ek, const uint8_t *ct, uint8_t *pt)
{
    uint8_t state[16];
    for (size_t i = 0; i < 4; i++)
    {
        state[i]      = ct[i * 4];
        state[i + 4]  = ct[i * 4 + 1];
        state[i + 8]  = ct[i * 4 + 2];
        state[i + 12] = ct[i * 4 + 3];
    }
    cy_aes_add_round_key(ek.words + ek.nr * 4, state);
    for (size_t i = 1; i < ek.nr; i++)
    {
        cy_aes_inv_shift_rows(state);
        cy_aes_sub_bytes(CY_AES_INV_SBOX, state);
        cy_aes_add_round_key(ek.words + (ek.nr - i) * 4, state);
        cy_aes_inv_mix_columns(state);
    }
    cy_aes_inv_shift_rows(state);
    cy_aes_sub_bytes(CY_AES_INV_SBOX, state);
    cy_aes_add_round_key(ek.words, state);
    for (size_t i = 0; i < 4; i++)
    {
        pt[i]      = state[i * 4];
        pt[i + 4]  = state[i * 4 + 1];
        pt[i + 8]  = state[i * 4 + 2];
        pt[i + 12] = state[i * 4 + 3];
    }
}