#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <gmp.h> 

#if !defined (__CY_API__)
#define __CY_API__

#define cy_version "1.0.0" 
#define CY_HELLO_MAGIC 0x43594850u /* 'C''Y''H''P' */
#define CY_BUFF_SIZE 2048
#define CY_HEADER_SIZE 16
#define CY_AES_PAD_SIZE 16
#define CY_OK 0

typedef struct __attribute__((packed)) // eliminate padding mismatch caused by the compiler
{
    uint32_t magic;
    uint8_t  enc;
    uint8_t  _pad;
    uint16_t bits;
} cy_hello_t;

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

typedef enum 
{ 
    CY_MODE_NONE=0, 
    CY_MODE_SERVER, 
    CY_MODE_CLIENT 
} cy_mode_t;

typedef enum 
{ 
    CY_TARGET_NONE=0, 
    CY_TARGET_IPV4, 
    CY_TARGET_NAME 
} cy_target_t;

typedef enum
{
    CY_ENC_NONE = 0,
    CY_ENC_AES  = 1,
    CY_ENC_RSA  = 2
} cy_enc_t;

typedef struct
{
    cy_mode_t mode;

    cy_target_t target_kind;
    const char *target;
    const char *port;

    bool enc_enabled;
    cy_enc_t enc_type;
    int enc_bits;         /* AES bits if -e aes, RSA bits if -e rsa */

    bool kx_enabled;      /* true if -kx provided */
    int  kx_bits;         /* RSA bits for AES key exchange */
} cy_cli_t;

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

/* ---------------- usage helpers ---------------- */

/**
 * Print CLI usage/help text to stderr (modes, options, and examples).
 */
void cy_usage(const char *prog);

/**
 * Return non-zero if `s` is a non-empty string containing only ASCII digits [0-9].
 */
int is_all_digits(const char *s);

/**
 * Validate a TCP/UDP port string: numeric and in range [1..65535].
 * Returns non-zero if valid.
 */
int is_valid_port(const char *port);

/**
 * Validate an IPv4 address string using inet_pton(AF_INET, ...).
 * Returns non-zero if valid.
 */
int is_valid_ipv4(const char *ip);

/**
 * Parse a base-10 long from string `s`.
 * Sets `*ok` to true on success (entire string consumed), false otherwise.
 * Returns the parsed value (0 on failure).
 */
long parse_long(const char *s, bool *ok);

/**
 * Case-insensitive ASCII string equality check (A-Z/a-z only via tolower()).
 * Returns non-zero if strings are equal ignoring ASCII case.
 */
int streqi_ascii(const char *a, const char *b);

/**
 * Print a formatted CLI error message (optionally with `detail`), show usage, then exit(1).
 */
void die_arg(const char *prog, const char *msg, const char *detail);

/**
 * Parse command-line arguments into `*out` (server/client mode, target, port, -e, -kx).
 * Returns 0 on success, -1 if `out` is NULL.
 * Exits(1) on invalid arguments (via die_arg()).
 */
int cy_parse_args(const int argc, const char **argv, cy_cli_t *out);

/**
 * Convert AES key size in bits (128/192/256) into the internal CY_AES_size mode value.
 * Exits(1) if bits is invalid.
 */
int cy_aes_bits_to_mode(int bits);

/**
 * Default RSA key size policy (in bits) used for AES session-key exchange when `-kx` is not provided.
 * Exits(1) if `aes_bits` is invalid.
 */
int cy_rsa_bits_for_aes_exchange_default(const int aes_bits);

/**
 * Decide RSA key size (in bits) used for AES key exchange:
 * returns `cli->kx_bits` if -kx was provided, else the default policy for `cli->enc_bits`.
 */
int cy_rsa_bits_for_aes_exchange(const cy_cli_t *cli);

/**
 * Send a HELLO negotiation frame on `fd` containing {magic, enc, bits} in network byte order.
 * Used to detect encryption/size mismatches between peers.
 */
void cy_send_hello(int fd, uint8_t enc, uint16_t bits);

/**
 * Receive and validate a HELLO negotiation frame from `fd`, then output enc/bits.
 * Exits(1) on EOF, wrong size, or bad magic.
 */
void cy_recv_hello(int fd, uint8_t *enc, uint16_t *bits);

/**
 * Server-side negotiation: receive client HELLO, send server HELLO, then enforce exact match.
 * Exits(1) if client/server encryption settings differ.
 */
void cy_negotiate_or_die_server(int fd, const cy_cli_t *cli);

/**
 * Client-side negotiation: send client HELLO, receive server HELLO, then enforce exact match.
 * Exits(1) if client/server encryption settings differ.
 */
void cy_negotiate_or_die_client(int fd, const cy_cli_t *cli);

/**
 * Server-side AES mode negotiation + RSA key-exchange bits negotiation:
 *  - first enforce AES settings match
 *  - then negotiate RSA exchange bits (client proposes, server echoes expected)
 * Stores chosen RSA bits in `*rsa_kx_bits_out` if non-NULL.
 * Exits(1) on mismatch.
 */
void cy_negotiate_or_die_server_aes_kx(int fd, const cy_cli_t *cli, int *rsa_kx_bits_out);

/**
 * Client-side AES mode negotiation + RSA key-exchange bits negotiation:
 *  - first enforce AES settings match
 *  - then propose RSA exchange bits and require server to echo the same
 * Stores chosen RSA bits in `*rsa_kx_bits_out` if non-NULL.
 * Exits(1) on mismatch.
 */
void cy_negotiate_or_die_client_aes_kx(int fd, const cy_cli_t *cli, int *rsa_kx_bits_out);


#endif //__CY_API__