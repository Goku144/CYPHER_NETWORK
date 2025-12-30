#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>



#if !defined (__CY_API__)
#define __CY_API__

#define CY_BUFF_SIZE 2048
#define CY_HEADER_SIZE 16
#define CY_AES_PAD_SIZE 16
#define CY_OK 0

typedef enum
{
    CY_AES = 0,
    CY_RSA,
} CY_ENC_TYPE;

typedef enum
{
    CY_AES_128 = 16,
    CY_AES_192 = 24,
    CY_AES_256 = 32
} CY_AES_size;

typedef struct
{
    uint8_t *byte;
    size_t size;
}CY_AES_KEY;

typedef struct
{
    uint32_t *words;
    size_t nr;
}CY_AES_EKEY;

typedef struct 
{
    size_t cy_len;
    uint8_t cy_pad_flag;
    uint8_t cy_pad_len;
    uint8_t cy_key_flag;
    uint8_t cy_key_type;
    uint8_t cy_enc_flag;
    uint8_t cy_enc_type;
    uint8_t cy_hash_flag;
    uint8_t cy_hash_type;
}CY_HEADER;

typedef struct
{
    CY_HEADER head;
    uint8_t *buffer;
}CY_BUFF;

void cy_getrand(const size_t len, uint8_t **buf);

void cy_aes_key_expansion(const CY_AES_KEY key, CY_AES_EKEY *w);

void cy_aes_key_gen(const CY_AES_size size, CY_AES_KEY *key);

void cy_aes_key_exp(const CY_AES_KEY key, CY_BUFF *buf);

void cy_aes_key_imp(const CY_BUFF buf, CY_AES_KEY *key);

void cy_rsa_key_gen(const mp_bitcnt_t bitsize, mpz_t **pubkey, mpz_t **prvkey);

void cy_rsa_key_exp(const mpz_t key0, const mpz_t key1, CY_BUFF *buf);

void cy_rsa_key_imp(const CY_BUFF buf, mpz_t key0, mpz_t key1);

void cy_read(int fd, CY_BUFF *buf);

void cy_write(int fd, const CY_BUFF buf);

void cy_recv(int fd, CY_BUFF *buf);

void cy_send(int fd, const CY_BUFF buf);

void cy_read_line(int fd, CY_BUFF *buf);

void cy_normal_full_duplex(int fd);

void cy_aes_full_duplex(int fd, const CY_AES_EKEY ekey);

void cy_rsa_full_duplex(int fd, const mpz_t *pubkey, const mpz_t *prvkey);

void cy_inet_server(const char *port, int *clsd);

void cy_inet_client(const char *ipv4, const char *port, int *servsd);

void cy_aes_get_key(int fd, CY_AES_EKEY *ekey);

void cy_aes_set_key(int fd, CY_AES_EKEY *ekey);

void cy_rsa_get_key(int fd, mpz_t key[2]);

void cy_rsa_set_key(int fd, mp_bitcnt_t bitsize, mpz_t pub[2], mpz_t prv[2], int send_private);

void cy_rsa_key_gen(const mp_bitcnt_t bitsize, mpz_t **pubkey, mpz_t **prvkey);

void cy_aes_send_encrypted(int fd, CY_BUFF buf, const CY_AES_EKEY ekey);

void cy_aes_recv_decrypted(int fd, CY_BUFF *buf, const CY_AES_EKEY ekey);

void cy_rsa_send_encrypted(int fd, CY_BUFF buf, const mpz_t *pubkey);

void cy_rsa_recv_decrypted(int fd, CY_BUFF *buf, const mpz_t *prvkey);

#endif //__CY_API__