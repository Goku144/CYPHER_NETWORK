/*
 * cypher.c
 *
 * Modes:
 *   server: cypher -sp <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]
 *   client: cypher -i <IPV4> -p <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]
 *           cypher -n <NAME> -p <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]
 *
 * Handshake rules:
 *   -e aes <128|192|256>:
 *      0) negotiate enc+size (must match)
 *      0b) negotiate RSA exchange bits (must match)  => from -kx or default policy
 *      1) client generates RSA keypair (kx bits) -> sends client PUBLIC to server
 *      2) server generates AES session key (aes bits) -> RSA-encrypts it with client PUBLIC -> sends back
 *      3) client RSA-decrypts with client PRIVATE -> imports AES key -> both run AES full duplex
 *
 *   -e rsa <>=1024>:
 *      0) negotiate enc+size (must match)
 *      1) server generates RSA keypair -> sends server PUBLIC to client
 *      2) client generates RSA keypair -> sends client PUBLIC to server
 *      3) both run RSA full duplex (send with peer public, recv with own private)
 *
 *   no -e:
 *      0) negotiate enc+size (NONE/0 must match)
 *      1) run normal duplex (cy_normal_full_duplex)
 *
 * Notes:
 *   - -kx is ONLY meaningful with "-e aes ...".
 *   - If -kx is not provided, we use a default mapping based on AES size.
 *   - All fatal errors in this file end with exit(1); (as requested).
 *
 * IMPORTANT:
 *   - This file assumes you already fixed cy_recv() so it sets buf->head.cy_len=0
 *     and buf->buffer=NULL on peer close/truncation (so the other side exits).
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "../inc/cypher.h"

/* ---------------- CLI types ---------------- */

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

/* ---------------- usage helpers ---------------- */

static void cy_usage(const char *prog)
{
    fprintf(stderr,
        "usage:\n"
        "%s -sp <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]\n"
        "%s -i <IPV4> -p <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]\n"
        "%s -n <NAME> -p <PORT> [-e <aes|rsa> <SIZE>] [-kx <RSA_BITS>]\n"
        "\n"
        "Examples:\n"
        "  %s -sp 4444\n"
        "  %s -sp 4444 -e aes 256\n"
        "  %s -sp 4444 -e aes 256 -kx 1024\n"
        "  %s -i 192.168.1.10 -p 4444\n"
        "  %s -n example.com -p 4444 -e rsa 2048\n",
        prog, prog, prog, prog, prog, prog, prog, prog);
}

static int is_all_digits(const char *s)
{
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

static int is_valid_port(const char *port)
{
    if (!is_all_digits(port)) return 0;
    char *end = NULL;
    long v = strtol(port, &end, 10);
    if (!end || *end != '\0') return 0;
    return (v >= 1 && v <= 65535);
}

static int is_valid_ipv4(const char *ip)
{
    struct in_addr a;
    return (ip && inet_pton(AF_INET, ip, &a) == 1);
}

static long parse_long(const char *s, bool *ok)
{
    *ok = false;
    if (!s || !*s) return 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || *end != '\0') return 0;
    *ok = true;
    return v;
}

static int streqi_ascii(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (tolower(ca) != tolower(cb)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

static void die_arg(const char *prog, const char *msg, const char *detail)
{
    if (detail) fprintf(stderr, "error: %s: %s\n", msg, detail);
    else        fprintf(stderr, "error: %s\n", msg);
    cy_usage(prog);
    exit(1);
}

/* ---------------- CLI parser ---------------- */

int cy_parse_args(const int argc, const char **argv, cy_cli_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    const char *prog = (argc > 0 && argv && argv[0]) ? argv[0] : "cypher";

    bool seen_sp = false;
    bool seen_p  = false;
    bool seen_i  = false;
    bool seen_n  = false;
    bool seen_e  = false;
    bool seen_kx = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "-sp") == 0) {
            if (seen_sp) die_arg(prog, "duplicate option", "-sp");
            if (i + 1 >= argc) die_arg(prog, "missing value after", "-sp");

            const char *port = argv[++i];
            if (!is_valid_port(port)) die_arg(prog, "invalid port", port);

            seen_sp = true;
            out->mode = CY_MODE_SERVER;
            out->port = port;
            continue;
        }

        if (strcmp(a, "-p") == 0) {
            if (seen_p) die_arg(prog, "duplicate option", "-p");
            if (i + 1 >= argc) die_arg(prog, "missing value after", "-p");

            const char *port = argv[++i];
            if (!is_valid_port(port)) die_arg(prog, "invalid port", port);

            seen_p = true;
            out->port = port;
            continue;
        }

        if (strcmp(a, "-i") == 0) {
            if (seen_i) die_arg(prog, "duplicate option", "-i");
            if (i + 1 >= argc) die_arg(prog, "missing value after", "-i");

            const char *ip = argv[++i];
            if (!is_valid_ipv4(ip)) die_arg(prog, "invalid IPv4 for -i", ip);

            seen_i = true;
            out->mode = CY_MODE_CLIENT;
            out->target_kind = CY_TARGET_IPV4;
            out->target = ip;
            continue;
        }

        if (strcmp(a, "-n") == 0) {
            if (seen_n) die_arg(prog, "duplicate option", "-n");
            if (i + 1 >= argc) die_arg(prog, "missing value after", "-n");

            const char *name = argv[++i];
            if (!name || !*name) die_arg(prog, "empty name for -n", NULL);
            if (name[0] == '-') die_arg(prog, "name cannot start with '-'", name);

            seen_n = true;
            out->mode = CY_MODE_CLIENT;
            out->target_kind = CY_TARGET_NAME;
            out->target = name;
            continue;
        }

        if (strcmp(a, "-e") == 0) {
            if (seen_e) die_arg(prog, "duplicate option", "-e");
            if (i + 2 >= argc) die_arg(prog, "expected '-e <aes|rsa> <SIZE>'", NULL);

            const char *type = argv[++i];
            const char *size = argv[++i];

            bool ok = false;
            long bits = parse_long(size, &ok);
            if (!ok) die_arg(prog, "encryption size must be a number", size);

            if (streqi_ascii(type, "aes")) {
                if (!(bits == 128 || bits == 192 || bits == 256))
                    die_arg(prog, "AES size must be 128, 192, or 256", size);
                out->enc_enabled = true;
                out->enc_type = CY_ENC_AES;
                out->enc_bits = (int)bits;
            } else if (streqi_ascii(type, "rsa")) {
                if (bits < 1024) die_arg(prog, "RSA size must be >= 1024", size);
                out->enc_enabled = true;
                out->enc_type = CY_ENC_RSA;
                out->enc_bits = (int)bits;
            } else {
                die_arg(prog, "unknown encryption type (use aes or rsa)", type);
            }

            seen_e = true;
            continue;
        }

        if (strcmp(a, "-kx") == 0) {
            if (seen_kx) die_arg(prog, "duplicate option", "-kx");
            if (i + 1 >= argc) die_arg(prog, "missing value after", "-kx");

            const char *val = argv[++i];
            bool ok = false;
            long bits = parse_long(val, &ok);
            if (!ok) die_arg(prog, "kx size must be a number", val);
            if (bits < 1024) die_arg(prog, "kx RSA bits must be >= 1024", val);

            out->kx_enabled = true;
            out->kx_bits = (int)bits;
            seen_kx = true;
            continue;
        }

        die_arg(prog, "unknown argument", a);
    }

    if (seen_sp) {
        if (seen_p || seen_i || seen_n)
            die_arg(prog, "server mode (-sp) cannot be combined with -p/-i/-n", NULL);
        if (!out->port)
            die_arg(prog, "missing port for server mode", NULL);

        out->mode = CY_MODE_SERVER;
    } else {
        if (!seen_p) die_arg(prog, "client mode requires -p <PORT>", NULL);
        if (seen_i && seen_n) die_arg(prog, "choose only one target: -i <IPV4> OR -n <NAME>", NULL);
        if (!seen_i && !seen_n) die_arg(prog, "client mode requires a target: -i <IPV4> or -n <NAME>", NULL);
        out->mode = CY_MODE_CLIENT;
    }

    /* validate -kx usage */
    if (out->kx_enabled) {
        if (!out->enc_enabled || out->enc_type != CY_ENC_AES)
            die_arg(prog, "-kx is only allowed with '-e aes <SIZE>'", NULL);
    }

    return 0;
}

/* ---------------- helpers for AES bits ---------------- */

static int cy_aes_bits_to_mode(int bits)
{
    if (bits == 128) return CY_AES_128;
    if (bits == 192) return CY_AES_192;
    if (bits == 256) return CY_AES_256;

    fprintf(stderr, "invalid AES bits\n");
    exit(1);
}

/* default policy if -kx not given */
static int cy_rsa_bits_for_aes_exchange_default(const int aes_bits)
{
    /* You asked: allow overriding to 1024 even with AES-256 by using -kx 1024 */
    if (aes_bits == 128) return 2048;
    if (aes_bits == 192) return 3072;
    if (aes_bits == 256) return 4096;

    fprintf(stderr, "invalid AES bits for rsa exchange\n");
    exit(1);
}

static int cy_rsa_bits_for_aes_exchange(const cy_cli_t *cli)
{
    if (cli->kx_enabled) return cli->kx_bits;
    return cy_rsa_bits_for_aes_exchange_default(cli->enc_bits);
}

/* --------- HELLO / negotiation (detect mismatch) ---------- */

#define CY_HELLO_MAGIC 0x43594850u /* 'C''Y''H''P' */

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint8_t  enc;
    uint8_t  _pad;
    uint16_t bits;
} cy_hello_t;

static void cy_send_hello(int fd, uint8_t enc, uint16_t bits)
{
    CY_BUFF b = (CY_BUFF){0};
    b.head.cy_len = sizeof(cy_hello_t);
    b.buffer = malloc(b.head.cy_len);
    if (!b.buffer) { perror(__func__); exit(1); }

    cy_hello_t h;
    h.magic = htonl(CY_HELLO_MAGIC);
    h.enc   = enc;
    h._pad  = 0;
    h.bits  = htons(bits);

    memcpy(b.buffer, &h, sizeof(h));
    cy_send(fd, b);
    free(b.buffer);
}

static void cy_recv_hello(int fd, uint8_t *enc, uint16_t *bits)
{
    CY_BUFF b = (CY_BUFF){0};
    cy_recv(fd, &b);

    if (b.head.cy_len == 0) { free(b.buffer); fprintf(stderr, "peer closed during hello\n"); exit(1); }
    if (b.head.cy_len != sizeof(cy_hello_t)) { free(b.buffer); fprintf(stderr, "bad hello size\n"); exit(1); }

    cy_hello_t h;
    memcpy(&h, b.buffer, sizeof(h));
    free(b.buffer);

    if (ntohl(h.magic) != CY_HELLO_MAGIC) { fprintf(stderr, "bad hello magic\n"); exit(1); }

    if (enc)  *enc  = h.enc;
    if (bits) *bits = ntohs(h.bits);
}

static void cy_negotiate_or_die_server(int fd, const cy_cli_t *cli)
{
    uint8_t  c_enc = 0;
    uint16_t c_bits = 0;
    cy_recv_hello(fd, &c_enc, &c_bits);

    uint8_t  s_enc  = cli->enc_enabled ? (uint8_t)cli->enc_type : (uint8_t)CY_ENC_NONE;
    uint16_t s_bits = cli->enc_enabled ? (uint16_t)cli->enc_bits : (uint16_t)0;

    cy_send_hello(fd, s_enc, s_bits);

    if (c_enc != s_enc || c_bits != s_bits) {
        fprintf(stderr, "encryption mismatch (client != server)\n");
        exit(1);
    }
}

static void cy_negotiate_or_die_client(int fd, const cy_cli_t *cli)
{
    uint8_t  c_enc  = cli->enc_enabled ? (uint8_t)cli->enc_type : (uint8_t)CY_ENC_NONE;
    uint16_t c_bits = cli->enc_enabled ? (uint16_t)cli->enc_bits : (uint16_t)0;

    cy_send_hello(fd, c_enc, c_bits);

    uint8_t  s_enc = 0;
    uint16_t s_bits = 0;
    cy_recv_hello(fd, &s_enc, &s_bits);

    if (s_enc != c_enc || s_bits != c_bits) {
        fprintf(stderr, "encryption mismatch (server != client)\n");
        exit(1);
    }
}

/* Extra negotiation for AES mode: agree on RSA exchange bits */
static void cy_negotiate_or_die_server_aes_kx(int fd, const cy_cli_t *cli, int *rsa_kx_bits_out)
{
    /* 0) negotiate AES itself */
    cy_negotiate_or_die_server(fd, cli);

    int rsa_bits = cy_rsa_bits_for_aes_exchange(cli);
    if (rsa_kx_bits_out) *rsa_kx_bits_out = rsa_bits;

    /* 0b) negotiate RSA exchange bits (client proposes, server echoes) */
    uint8_t  c_enc = 0;
    uint16_t c_bits = 0;
    cy_recv_hello(fd, &c_enc, &c_bits);

    cy_send_hello(fd, CY_ENC_RSA, (uint16_t)rsa_bits);

    if (c_enc != CY_ENC_RSA || c_bits != (uint16_t)rsa_bits) {
        fprintf(stderr, "rsa-exchange mismatch for aes mode\n");
        exit(1);
    }
}

static void cy_negotiate_or_die_client_aes_kx(int fd, const cy_cli_t *cli, int *rsa_kx_bits_out)
{
    /* 0) negotiate AES itself */
    cy_negotiate_or_die_client(fd, cli);

    int rsa_bits = cy_rsa_bits_for_aes_exchange(cli);
    if (rsa_kx_bits_out) *rsa_kx_bits_out = rsa_bits;

    /* 0b) propose RSA exchange bits */
    cy_send_hello(fd, CY_ENC_RSA, (uint16_t)rsa_bits);

    uint8_t  s_enc = 0;
    uint16_t s_bits = 0;
    cy_recv_hello(fd, &s_enc, &s_bits);

    if (s_enc != CY_ENC_RSA || s_bits != (uint16_t)rsa_bits) {
        fprintf(stderr, "rsa-exchange mismatch for aes mode\n");
        exit(1);
    }
}

/* ---------------- main ---------------- */

int main(const int argc, const char **argv)
{
    cy_cli_t cli;
    if (cy_parse_args(argc, argv, &cli) != 0) return 1;

    if (cli.enc_enabled) {
        if (cli.enc_type == CY_ENC_AES) printf("[*] Encryption: AES-%d enabled\n", cli.enc_bits);
        else if (cli.enc_type == CY_ENC_RSA) printf("[*] Encryption: RSA-%d enabled\n", cli.enc_bits);
    } else {
        printf("[*] Encryption: disabled\n");
    }

    /* ---------------- SERVER ---------------- */
    if (cli.mode == CY_MODE_SERVER)
    {
        int clfd = -1;
        cy_inet_server(cli.port, &clfd);

        if (!cli.enc_enabled) {
            cy_negotiate_or_die_server(clfd, &cli);
            cy_normal_full_duplex(clfd);
            close(clfd);
            exit(0);
        }

        if (cli.enc_type == CY_ENC_RSA)
        {
            cy_negotiate_or_die_server(clfd, &cli);

            mpz_t pubS[2], prvS[2];
            mpz_inits(pubS[0], pubS[1], prvS[0], prvS[1], NULL);

            cy_rsa_set_key(clfd, cli.enc_bits, pubS, prvS, 0);

            mpz_t pubC[2];
            mpz_inits(pubC[0], pubC[1], NULL);
            cy_rsa_get_key(clfd, pubC);

            cy_rsa_full_duplex(clfd, pubC, prvS);

            mpz_clears(pubS[0], pubS[1], prvS[0], prvS[1], pubC[0], pubC[1], NULL);
            close(clfd);
            exit(0);
        }

        if (cli.enc_type == CY_ENC_AES)
        {
            int rsa_kx_bits = 0;
            cy_negotiate_or_die_server_aes_kx(clfd, &cli, &rsa_kx_bits);

            /* 1) receive client public key */
            mpz_t pubC[2];
            mpz_inits(pubC[0], pubC[1], NULL);
            cy_rsa_get_key(clfd, pubC);

            /* 2) generate AES key of requested size */
            CY_AES_KEY aes_key;
            cy_aes_key_gen(cy_aes_bits_to_mode(cli.enc_bits), &aes_key);

            /* 3) expand AES key */
            CY_AES_EKEY ekey;
            cy_aes_key_expansion(aes_key, &ekey);

            /* 4) export AES key into CY_BUFF (note: your cy_aes_key_exp does not allocate) */
            CY_BUFF plain_key;
            cy_aes_key_exp(aes_key, &plain_key);

            /* 5) RSA-encrypt AES key and send */
            (void)rsa_kx_bits; /* generated by client; server doesn't need to generate RSA here */
            cy_rsa_send_encrypted(clfd, plain_key, pubC);

            mpz_clears(pubC[0], pubC[1], NULL);

            /* 6) AES duplex */
            cy_aes_full_duplex(clfd, ekey);

            close(clfd);
            exit(0);
        }

        close(clfd);
        exit(0);
    }

    /* ---------------- CLIENT ---------------- */
    if (cli.mode == CY_MODE_CLIENT)
    {
        int fd = -1;
        cy_inet_client(cli.target, cli.port, &fd);

        if (!cli.enc_enabled) {
            cy_negotiate_or_die_client(fd, &cli);
            cy_normal_full_duplex(fd);
            close(fd);
            exit(0);
        }

        if (cli.enc_type == CY_ENC_RSA)
        {
            cy_negotiate_or_die_client(fd, &cli);

            mpz_t pubS[2];
            mpz_inits(pubS[0], pubS[1], NULL);
            cy_rsa_get_key(fd, pubS);

            mpz_t pubC[2], prvC[2];
            mpz_inits(pubC[0], pubC[1], prvC[0], prvC[1], NULL);

            cy_rsa_set_key(fd, cli.enc_bits, pubC, prvC, 0);

            cy_rsa_full_duplex(fd, pubS, prvC);

            mpz_clears(pubS[0], pubS[1], pubC[0], pubC[1], prvC[0], prvC[1], NULL);
            close(fd);
            exit(0);
        }

        if (cli.enc_type == CY_ENC_AES)
        {
            int rsa_kx_bits = 0;
            cy_negotiate_or_die_client_aes_kx(fd, &cli, &rsa_kx_bits);

            /* 1) client generates RSA keypair for key-exchange (rsa_kx_bits) */
            mpz_t pubC[2], prvC[2];
            mpz_inits(pubC[0], pubC[1], prvC[0], prvC[1], NULL);

            mpz_t *tp = NULL, *ts = NULL;
            cy_rsa_key_gen(rsa_kx_bits, &tp, &ts);

            mpz_set(pubC[0], tp[0]); mpz_set(pubC[1], tp[1]);
            mpz_set(prvC[0], ts[0]); mpz_set(prvC[1], ts[1]);

            mpz_clears(tp[0], tp[1], ts[0], ts[1], NULL);
            free(tp); free(ts);

            /* 2) send client public key to server */
            CY_BUFF pubbuf;
            cy_rsa_key_exp(pubC[0], pubC[1], &pubbuf);
            pubbuf.head.cy_key_flag = 1;
            pubbuf.head.cy_key_type = CY_RSA;
            cy_send(fd, pubbuf);
            free(pubbuf.buffer);

            /* 3) receive RSA-encrypted AES key + decrypt */
            CY_BUFF aes_plain;
            cy_rsa_recv_decrypted(fd, &aes_plain, prvC);

            /* FIX: RSA decrypt returns raw bytes without key flags */
            aes_plain.head.cy_key_flag = 1;
            aes_plain.head.cy_key_type = CY_AES;

            /* 4) import AES key and expand */
            CY_AES_KEY aes_key;
            cy_aes_key_imp(aes_plain, &aes_key);

            CY_AES_EKEY ekey;
            cy_aes_key_expansion(aes_key, &ekey);

            free(aes_plain.buffer);

            /* 5) AES duplex */
            cy_aes_full_duplex(fd, ekey);

            mpz_clears(pubC[0], pubC[1], prvC[0], prvC[1], NULL);
            close(fd);
            exit(0);
        }

        close(fd);
        exit(0);
    }

    fprintf(stderr, "internal error: no mode selected\n");
    exit(1);
}
