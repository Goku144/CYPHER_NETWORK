#include "../inc/cypher_err.h"
#include "../inc/cypher_const.h"
#include "../inc/cypher_math.h"
#include "../inc/cypher_key.h"
#include "../inc/cypher_algo.h"
#include "../inc/cypher.h"
#include "../inc/cypher_prot.h"
#include <unistd.h>

#define CY_BUFF_SIZE 2048

void cy_read(int fd, CY_BUFF *buf)
{
    size_t fs = CY_BUFF_SIZE; 
    buf->head.cy_len = 0;
    buf->buffer = malloc(fs);
    if(!buf->buffer) cy_state(__func__, -1); 
    while (1)
    {
        ssize_t n = read(fd, buf->buffer + buf->head.cy_len, fs - buf->head.cy_len);
        if(n == 0) break;
        if(n < 0) cy_state(__func__, -1);
        buf->head.cy_len += n;
        if(fs == buf->head.cy_len)
        {
            fs += CY_BUFF_SIZE;
            buf->buffer = realloc(buf->buffer, fs);
            if(!buf->buffer) cy_state(__func__, -1); 
        }
    }
}

void cy_write(int fd, const CY_BUFF buf)
{
    size_t fs = 0;
    if(!buf.buffer) cy_state(__func__, -1); 
    while (fs < buf.head.cy_len)
    {
        ssize_t n = write(fd, buf.buffer + fs, buf.head.cy_len - fs);
        if(n == 0) break;
        if(n < 0) cy_state(__func__, -1);
        fs += n;
    }
}

void cy_read_line(int fd, CY_BUFF *buf)
{
    size_t fs = CY_BUFF_SIZE; 
    buf->head.cy_len = 0;
    buf->buffer = malloc(fs);
    if(!buf->buffer) cy_state(__func__, -1); 
    while (1)
    {
        ssize_t n = read(fd, buf->buffer + buf->head.cy_len, fs - buf->head.cy_len);
        if(n == 0) break;
        if(n < 0) cy_state(__func__, -1);
        buf->head.cy_len += n;
        if((buf->buffer)[buf->head.cy_len - 1] == '\n') break;
        if(fs == buf->head.cy_len)
        {
            fs += CY_BUFF_SIZE;
            buf->buffer = realloc(buf->buffer, fs);
            if(!buf->buffer) cy_state(__func__, -1); 
        }
    }
}

void cy_recv(int fd, CY_BUFF *buf)
{
    buf->head.cy_len = 0;   /* IMPORTANT: default is "closed/empty" */
    buf->buffer = NULL;

    uint8_t hdr[CY_HEADER_SIZE];
    size_t nsize = 0;

    /* read header fully */
    while (nsize < CY_HEADER_SIZE)
    {
        ssize_t n = recv(fd, hdr + nsize, CY_HEADER_SIZE - nsize, 0);
        if (n == 0) return;                 /* peer closed => cy_len stays 0 */
        if (n < 0) cy_state(__func__, -1);
        nsize += (size_t)n;
    }

    /* parse header */
    cy_header_imp(hdr, buf);

    if (buf->head.cy_len == 0) return;      /* empty frame */

    buf->buffer = malloc(buf->head.cy_len);
    if (!buf->buffer) cy_state(__func__, -1);

    /* read payload fully */
    nsize = 0;
    while (nsize < buf->head.cy_len)
    {
        ssize_t n = recv(fd, buf->buffer + nsize, buf->head.cy_len - nsize, 0);
        if (n == 0) {                       /* peer closed mid-frame */
            free(buf->buffer);
            buf->buffer = NULL;
            buf->head.cy_len = 0;
            return;
        }
        if (n < 0) cy_state(__func__, -1);
        nsize += (size_t)n;
    }
}


void cy_send(int fd, const CY_BUFF buf)
{
    uint8_t *netbuf;
    size_t fullsize = buf.head.cy_len + CY_HEADER_SIZE;
    netbuf = malloc(CY_HEADER_SIZE);
    if(!netbuf) cy_state(__func__, -1);
    cy_header_exp(buf, netbuf);
    size_t nsize = 0;
    netbuf = realloc(netbuf, fullsize);
    if(!netbuf) cy_state(__func__, -1);
    memcpy(netbuf + CY_HEADER_SIZE, buf.buffer, buf.head.cy_len);
    while (nsize < fullsize)
    {
        ssize_t n = send(fd, netbuf + nsize, fullsize - nsize, 0);
        if(n == 0) break;
        if(n < 0) cy_state(__func__, -1);
        nsize += n;
    }
    
    free(netbuf);
}

void cy_normal_full_duplex(int fd)
{
    for (;;)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(fd, &rfds);

        int maxfd = (fd > STDIN_FILENO ? fd : STDIN_FILENO) + 1;
        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) cy_state("select", -1);

            /* stdin -> socket */
        if (FD_ISSET(STDIN_FILENO, &rfds))
        {
            CY_BUFF buf;
            cy_read_line(STDIN_FILENO, &buf);
            if (buf.head.cy_len == 8 && memcmp(buf.buffer, "exit();\n", 8) == 0) 
            { 
                free(buf.buffer);
                shutdown(fd, SHUT_RDWR);
                break;
            }
            cy_send(fd, buf);
            free(buf.buffer);
        }

            /* socket -> stdout */
        if (FD_ISSET(fd, &rfds))
        {
            CY_BUFF buf;
            cy_recv(fd, &buf);     // if your protocol is framed, replace with cy_recv()
            if (buf.head.cy_len == 0) { free(buf.buffer); break; }
            cy_write(STDOUT_FILENO, buf);
            free(buf.buffer);
        }
    }
}

void cy_aes_full_duplex(int fd, const CY_AES_EKEY ekey)
{
    for (;;)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(fd, &rfds);

        int maxfd = (fd > STDIN_FILENO ? fd : STDIN_FILENO) + 1;
        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) cy_state("select", -1);

            /* stdin -> socket */
        if (FD_ISSET(STDIN_FILENO, &rfds))
        {
            CY_BUFF buf;
            cy_read_line(STDIN_FILENO, &buf);
            if (buf.head.cy_len == 8 && memcmp(buf.buffer, "exit();\n", 8) == 0) 
            { 
                free(buf.buffer);
                shutdown(fd, SHUT_RDWR);
                break;
            }
            cy_aes_send_encrypted(fd, buf, ekey);
            free(buf.buffer);
        }

            /* socket -> stdout */
        if (FD_ISSET(fd, &rfds))
        {
            CY_BUFF buf;
            cy_aes_recv_decrypted(fd, &buf, ekey);         // if your protocol is framed, replace with cy_recv()
            if (buf.head.cy_len == 0) { free(buf.buffer); break; }
            cy_write(STDOUT_FILENO, buf);
            free(buf.buffer);
        }
    }
}

void cy_rsa_full_duplex(int fd, const mpz_t *pubkey, const mpz_t *prvkey)
{
    for (;;)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(fd, &rfds);

        int maxfd = (fd > STDIN_FILENO ? fd : STDIN_FILENO) + 1;
        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) cy_state("select", -1);

        /* stdin -> socket */
        if (FD_ISSET(STDIN_FILENO, &rfds))
        {
            CY_BUFF buf;
            cy_read_line(STDIN_FILENO, &buf);
            if (buf.head.cy_len == 8 && memcmp(buf.buffer, "exit();\n", 8) == 0) 
            { 
                free(buf.buffer);
                shutdown(fd, SHUT_RDWR);
                break;
            }
            cy_rsa_send_encrypted(fd, buf, pubkey);

            free(buf.buffer);
        }

        /* socket -> stdout */
        if (FD_ISSET(fd, &rfds))
        {
            CY_BUFF buf;
            cy_rsa_recv_decrypted(fd, &buf, prvkey);

            if (buf.head.cy_len == 0) { free(buf.buffer); break; }

            cy_write(STDOUT_FILENO, buf);
            free(buf.buffer);
        }
    }
}


void cy_aes_send_encrypted(int fd, CY_BUFF buf, const CY_AES_EKEY ekey)
{
    cy_pad_add(&buf);
    size_t len = buf.head.cy_len / 16;
    for (size_t i = 0; i < len; i++) cy_aes_encrypt(ekey, buf.buffer + 16 * i, buf.buffer + 16 * i);
    buf.head.cy_enc_flag = 1;
    buf.head.cy_enc_type = CY_AES;
    cy_send(fd, buf);
}

void cy_aes_recv_decrypted(int fd, CY_BUFF *buf, const CY_AES_EKEY ekey)
{
    cy_recv(fd, buf);
    size_t len = buf->head.cy_len / 16;
    for (size_t i = 0; i < len; i++) cy_aes_decrypt(ekey, buf->buffer + 16 * i, buf->buffer + 16 * i);
    buf->head.cy_enc_flag = 0;
    buf->head.cy_enc_type = 0;
    cy_pad_rmv(buf);
}

void cy_rsa_encrypted(const CY_BUFF in, const mpz_t *pubkey, CY_BUFF *out)
{
    if (!out || !in.buffer) cy_state(__func__, 0);

    /* 1st pass: compute total size */
    mpz_t c; mpz_init(c);
    size_t total = 0;

    for (size_t i = 0; i < in.head.cy_len; i++)
    {
        cy_rsa_encrypt(in.buffer[i], pubkey, c);

        size_t clen = 0;
        (void)mpz_export(NULL, &clen, 1, 1, 1, 0, c);

        total += 8 + clen;
    }

    /* allocate output */
    out->buffer = (uint8_t*)malloc(total);
    if (!out->buffer) cy_state(__func__, -1);
    out->head.cy_len = total;

    /* 2nd pass: fill buffer */
    size_t off = 0;
    for (size_t i = 0; i < in.head.cy_len; i++)
    {
        cy_rsa_encrypt(in.buffer[i], pubkey, c);

        size_t clen = 0;
        (void)mpz_export(NULL, &clen, 1, 1, 1, 0, c);

        for (int i = 0; i < 8; i++) out->buffer[i + off] = (uint8_t)((clen >> (56 - 8*i)) & 0xFF);

        off += 8;

        mpz_export(out->buffer + off, &clen, 1, 1, 1, 0, c);
        off += clen;
    }

    mpz_clear(c);
}

/* Decrypt RSA-packed buffer into plaintext bytes.
   Input format: [len:8][cipher:len] repeated.
   Output is raw plaintext bytes in out->buffer.
*/
void cy_rsa_decrypted(const CY_BUFF in, const mpz_t *prvkey, CY_BUFF *out)
{
    if (!out || !in.buffer) cy_state(__func__, 0);

    /* 1st pass: count blocks (plaintext length) */
    size_t off = 0;
    size_t nbytes = 0;

    while (off < in.head.cy_len)
    {
        if (in.head.cy_len - off < 8) cy_state("cy_rsa_decrypt: truncated len", 0);
        size_t clen = 0;
        for (int i = 0; i < 8; i++) clen = (clen << 8) | (size_t)in.buffer[i + off];
        off += 8;

        if (clen == 0) cy_state("cy_rsa_decrypt: zero cipher len", 0);
        if (in.head.cy_len - off < clen) cy_state("cy_rsa_decrypt: truncated cipher", 0);

        off += clen;
        nbytes++;
    }

    /* allocate plaintext */
    out->buffer = (uint8_t*)malloc(nbytes);
    if (!out->buffer) cy_state(__func__, -1);
    out->head.cy_len = nbytes;

    /* 2nd pass: decrypt blocks */
    mpz_t c; mpz_init(c);
    off = 0;

    for (size_t i = 0; i < nbytes; i++)
    {
        size_t clen = 0;
        for (int i = 0; i < 8; i++) clen = (clen << 8) | (size_t)in.buffer[i + off];
        off += 8;

        mpz_import(c, clen, 1, 1, 1, 0, in.buffer + off);
        off += clen;

        cy_rsa_decrypt(c, prvkey, out->buffer + i); /* writes one byte */
    }

    mpz_clear(c);
}

void cy_rsa_send_encrypted(int fd, CY_BUFF buf, const mpz_t *pubkey)
{
    /* encrypt buf -> enc */
    CY_BUFF enc = {0};
    cy_rsa_encrypted(buf, pubkey, &enc);

    /* mark header flags like AES does */
    enc.head.cy_enc_flag = 1;
    enc.head.cy_enc_type = CY_RSA;

    /* framed send */
    cy_send(fd, enc);

    free(enc.buffer);
}

/* RSA: recv decrypted (AES-style wrapper) */
void cy_rsa_recv_decrypted(int fd, CY_BUFF *buf, const mpz_t *prvkey)
{
    /* receive framed ciphertext */
    CY_BUFF enc = {0};
    cy_recv(fd, &enc);

    if (enc.head.cy_len == 0) {  /* closed */
        free(enc.buffer);
        buf->buffer = NULL;
        buf->head.cy_len = 0;
        return;
    }

    /* (optional but recommended) verify it is RSA */
    /* if (enc.head.cy_enc_flag != 1 || enc.head.cy_enc_type != CY_RSA)
         cy_state("protocol: expected RSA frame", 0); */

    /* decrypt enc -> plain (returned in *buf) */
    cy_rsa_decrypted(enc, prvkey, buf);

    /* clear flags on plaintext */
    buf->head.cy_enc_flag = 0;
    buf->head.cy_enc_type = 0;

    free(enc.buffer);
}