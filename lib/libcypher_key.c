#include "../inc/cypher_err.h"
#include "../inc/cypher_const.h"
#include "../inc/cypher_math.h"
#include "../inc/cypher_algo.h"
#include "../inc/cypher_rand.h"
#include "../inc/cypher_key.h"

void cy_aes_key_expansion(const CY_AES_KEY key, CY_AES_EKEY *w)
{
    if(!(key.size == CY_AES_128 || key.size == CY_AES_192 || key.size == CY_AES_256)) cy_state("cy_aes_key_expansion: invalid key size", -1);
    size_t nk = key.size / 4;
    size_t nr = nk + 6;
    size_t tw = (nr + 1) * 4;
    size_t ws = tw * sizeof(*(w->words));
    w->words = malloc(ws);
    if(!w) cy_state(__func__, -1);
    memset(w->words, 0, ws);
    for (size_t i = 0; i < nk; i++)
    {
        size_t j = 4 * i;
        w->words[i] = ((uint32_t) key.byte[j]     << 0x18)|
                      ((uint32_t) key.byte[j + 1] << 0x10)|
                      ((uint32_t) key.byte[j + 2] << 0x08)|
                      ((uint32_t) key.byte[j + 3] << 0x00);
    }
    for (size_t i = nk; i < tw; i++)
    {
        uint32_t tmp = w->words[i - 1];
        if (i % nk == 0) cy_aes_g_function((uint8_t)(i / nk - 1), &tmp);
        else if (nk > 6 && (i % nk) == 4)
        {
            uint32_t t = tmp;
            tmp = (((uint32_t) CY_AES_SBOX[(t >> 0x04) & 0xF][(t >> 0x00) & 0xF]) << 0x00)|
                  (((uint32_t) CY_AES_SBOX[(t >> 0x0C) & 0xF][(t >> 0x08) & 0xF]) << 0x08)|
                  (((uint32_t) CY_AES_SBOX[(t >> 0x14) & 0xF][(t >> 0x10) & 0xF]) << 0x10)|
                  (((uint32_t) CY_AES_SBOX[(t >> 0x1C) & 0xF][(t >> 0x18) & 0xF]) << 0x18);
        }
        w->words[i] = tmp ^ w->words[i - nk];
    }
    w->nr = nr;
}

void cy_aes_key_gen(const CY_AES_size size, CY_AES_KEY *key)
{   
    key->size = size;
    if(!(key->size == CY_AES_128 || key->size == CY_AES_192 || key->size == CY_AES_256)) cy_state("cy_aes_key_gen: invalid key size", -1);
    cy_getrand(key->size, &key->byte);
}

void cy_aes_key_exp(const CY_AES_KEY key, CY_BUFF *buf)
{
    buf->buffer = key.byte;
    buf->head.cy_len = key.size;
    buf->head.cy_key_flag = 1;
    buf->head.cy_key_type = CY_AES; 
}

void cy_aes_key_imp(const CY_BUFF buf, CY_AES_KEY *key)
{
    if(buf.head.cy_key_flag != 1) cy_state("cy_aes_key_imp: flag key not set", 0);
    key->byte = buf.buffer;
    key->size = buf.head.cy_len;
}

void cy_aes_get_key(int fd, CY_AES_EKEY *ekey)
{
    CY_AES_KEY key; CY_BUFF buf;
    cy_recv(fd, &buf);
    cy_aes_key_imp(buf, &key);
    cy_aes_key_expansion(key, ekey);
}

void cy_aes_set_key(int fd, CY_AES_EKEY *ekey)
{
    CY_AES_KEY key; CY_BUFF buf;
    cy_aes_key_gen(CY_AES_128, &key);
    cy_aes_key_exp(key, &buf);
    cy_send(fd, buf);
    cy_aes_key_expansion(key, ekey);
}

/* Receive RSA key (2 mpz: [0]=e or d, [1]=n) and import into already-inited mpz_t[2] */
void cy_rsa_get_key(int fd, mpz_t key[2])
{
    CY_BUFF buf;
    cy_recv(fd, &buf);
    if (buf.head.cy_len == 0) { free(buf.buffer); cy_state("cy_rsa_get_key: closed", 0); }

    cy_rsa_key_imp(buf, key[0], key[1]);

    free(buf.buffer);
}

/* Generate RSA keypair and send one key (pub or prv) over the socket.
   - If send_private == 0: sends public (e,n) into out_pub
   - If send_private != 0: sends private (d,n) into out_prv
   Caller must mpz_clear(out_pub/out_prv) if they keep them.
*/
void cy_rsa_set_key(int fd, mp_bitcnt_t bitsize, mpz_t pub[2], mpz_t prv[2], int send_private)
{
    mpz_t *pubp = NULL, *prvp = NULL;
    cy_rsa_key_gen(bitsize, &pubp, &prvp); /* your existing generator */

    /* copy into caller-provided mpz_t[2] (must be mpz_init'd by caller) */
    mpz_set(pub[0], pubp[0]); mpz_set(pub[1], pubp[1]);
    mpz_set(prv[0], prvp[0]); mpz_set(prv[1], prvp[1]);

    /* pack the selected key into CY_BUFF and send */
    CY_BUFF buf;
    if (send_private)
        cy_rsa_key_exp(prv[0], prv[1], &buf);  /* (d,n) */
    else
        cy_rsa_key_exp(pub[0], pub[1], &buf);  /* (e,n) */

    /* mark header as "key frame" */
    buf.head.cy_key_flag = 1;
    buf.head.cy_key_type = CY_RSA;

    cy_send(fd, buf);

    free(buf.buffer);

    /* cleanup temp mpz_t arrays allocated by cy_rsa_key_gen */
    mpz_clears(pubp[0], pubp[1], prvp[0], prvp[1], NULL);
    free(pubp);
    free(prvp);
}


void cy_rsa_key_gen(const mp_bitcnt_t bitsize, mpz_t **pubkey, mpz_t **prvkey)
{
    mpz_t n, p, q, phi_n, e, d;

    *pubkey = malloc(2 * sizeof((*pubkey)[0]));
    *prvkey = malloc(2 * sizeof((*prvkey)[0]));
    if (!*pubkey || !*prvkey) cy_state("malloc", -1);

    mpz_inits((*pubkey)[0], (*pubkey)[1], (*prvkey)[0], (*prvkey)[1],
              n, p, q, phi_n, e, d, NULL);

    cy_rsa_prime_prob_gen(bitsize, p);
    cy_rsa_prime_prob_gen(bitsize, q);

    mpz_mul(n, p, q);

    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_n, p, q);

    /* small-ish prime e*/
    cy_rsa_prime_prob_gen(bitsize / 10, e);

    /* must compute modular inverse: d = e^{-1} mod phi_n */
    EEA(e, phi_n, d);

    mpz_set((*pubkey)[0], e); mpz_set((*pubkey)[1], n);
    mpz_set((*prvkey)[0], d); mpz_set((*prvkey)[1], n);

    mpz_clears(e, d, n, p, q, phi_n, NULL);
}

void cy_rsa_key_exp(const mpz_t key0, const mpz_t key1, CY_BUFF *buf)
{
    if (!buf) cy_state("cy_rsa_key_exp: buf null", 0);

    size_t n0 = 0, n1 = 0;
    (void)mpz_export(NULL, &n0, 1, 1, 1, 0, key0);
    (void)mpz_export(NULL, &n1, 1, 1, 1, 0, key1);

    size_t total = 8 + n0 + 8 + n1;

    buf->buffer = (uint8_t*)malloc(total);
    if (!buf->buffer) cy_state("malloc", -1);

    for (int i = 0; i < 8; i++) buf->buffer[i] = (uint8_t)((n0 >> (56 - 8*i)) & 0xFF);
    mpz_export(buf->buffer + 8, &n0, 1, 1, 1, 0, key0);

    for (int i = 0; i < 8; i++) buf->buffer[i + 8 + n0] = (uint8_t)((n1 >> (56 - 8*i)) & 0xFF);
    mpz_export(buf->buffer + 8 + n0 + 8, &n1, 1, 1, 1, 0, key1);

    buf->head.cy_len = total;
}

void cy_rsa_key_imp(const CY_BUFF buf, mpz_t key0, mpz_t key1)
{
    if (!buf.buffer || buf.head.cy_len < 16) cy_state("cy_rsa_key_imp: short", 0);

    const uint8_t *p = buf.buffer;
    uint64_t n0 = 0;
    for (int i = 0; i < 8; i++) n0 = (n0 << 8) | (uint64_t)p[i];
    if (8 + (size_t)n0 + 8 > buf.head.cy_len) cy_state("cy_rsa_key_imp: bad len0", 0);

    mpz_import(key0, (size_t)n0, 1, 1, 1, 0, p + 8);

    const uint8_t *q = p + 8 + (size_t)n0;
    uint64_t n1 = 0;
    for (int i = 0; i < 8; i++) n1 = (n1 << 8) | (uint64_t)q[i];
    if (8 + (size_t)n0 + 8 + (size_t)n1 > buf.head.cy_len) cy_state("cy_rsa_key_imp: bad len1", 0);

    mpz_import(key1, (size_t)n1, 1, 1, 1, 0, q + 8);
}